//! The provider-tier enforcement placement: [`govern_provider`] wraps a
//! [`TableProvider`] in a **secured view** at table-resolution time.
//!
//! Hosts with an async catalog resolver (one that resolves tables per query,
//! per principal) call [`govern_provider`] (or the config-driven
//! [`govern_provider_from_config`]) as they hand a provider back: the returned
//! provider carries the governed plan — the same
//! `Filter(row_filters, Projection(masks, scan))` shape the planner-tier
//! [`govern_plan`](crate::govern::govern_plan) produces — and DataFusion
//! inlines it wherever the table is referenced, before any planning happens.
//! The planner tier stays as the coarse gate (`is_allowed`), taint recording,
//! and the backstop for tables that never pass through a resolver; the
//! [`mark_governed`](crate::CatalogFactSink::mark_governed) marker keeps the
//! two tiers mutually exclusive per (table, query).

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::Session;
use datafusion::common::{Constraints, Result, Statistics, exec_err};
use datafusion::datasource::{TableProvider, provider_as_source};
use datafusion::logical_expr::dml::InsertOp;
use datafusion::logical_expr::{
    Expr, LogicalPlan, LogicalPlanBuilder, TableProviderFilterPushDown, TableType,
};
use datafusion::physical_plan::ExecutionPlan;
use datafusion::prelude::SessionConfig;
use datafusion::sql::TableReference;

use crate::engine::PolicyEngine;
use crate::facts::EvalContext;
use crate::govern::apply_table_policy;
use crate::principal::PrincipalIdentity;
use crate::session::{CatalogFactSinkExt, PolicyEngineExt, PrincipalExt};

/// Wrap `provider` in a secured view enforcing `policy.constrain(...)`.
///
/// Returns `provider` unchanged (the same `Arc`) when no constraints apply, so
/// ungoverned tables keep their concrete provider type (and any host
/// downcasts). When constraints apply, marks `table_ref` governed in
/// `eval.catalog_facts` so the planner-tier govern pass skips the wrapped
/// table's scan (taint recording still runs there). Errors from `constrain`
/// propagate — resolution fails closed rather than handing back an ungoverned
/// table.
///
/// The coarse `Deny` stays at the planner: `constrain` is read-shaped, and a
/// read-denied principal may still be allowed to INSERT; only `is_allowed`
/// sees the whole plan. Do not gate resolution on `is_allowed`.
pub async fn govern_provider(
    provider: Arc<dyn TableProvider>,
    table_ref: &TableReference,
    policy: &dyn PolicyEngine,
    principal: &PrincipalIdentity,
    eval: &EvalContext,
) -> Result<Arc<dyn TableProvider>> {
    let scan = LogicalPlanBuilder::scan(
        table_ref.clone(),
        provider_as_source(Arc::clone(&provider)),
        None,
    )?
    .build()?;

    let schema = Arc::clone(scan.schema());
    let table_policy = policy
        .constrain(table_ref, &schema, principal, eval)
        .await?;
    if table_policy.is_empty() {
        return Ok(provider);
    }

    let plan = apply_table_policy(scan, &schema, &table_policy)?;
    eval.catalog_facts.mark_governed(table_ref.clone());
    Ok(Arc::new(GovernedTableProvider::new(provider, plan)))
}

/// One-call host seam: assemble the engine ([`PolicyEngineExt`]), principal
/// ([`PrincipalExt`]), and eval context from `SessionConfig` extensions, then
/// delegate to [`govern_provider`].
///
/// Fails closed when no engine or no principal is bound to the config. The
/// eval context is assembled from the [`CatalogFactSinkExt`] (plus, under
/// `fgac`, [`FactStoreExt`](crate::FactStoreExt) /
/// [`FunctionResolverExt`](crate::FunctionResolverExt)) extensions; the host
/// must attach the *same* [`CatalogFactSinkExt`] the planner tier reads, or
/// the governed marker cannot coordinate the two tiers and the planner would
/// govern the inlined scan a second time.
pub async fn govern_provider_from_config(
    config: &SessionConfig,
    provider: Arc<dyn TableProvider>,
    table_ref: &TableReference,
) -> Result<Arc<dyn TableProvider>> {
    let Some(engine) = config.get_extension::<PolicyEngineExt>() else {
        return exec_err!("no policy engine bound to session config; cannot govern table");
    };
    let Some(principal) = config.get_extension::<PrincipalExt>() else {
        return exec_err!("no principal bound to session config; cannot govern table");
    };

    let eval = EvalContext {
        catalog_facts: config
            .get_extension::<CatalogFactSinkExt>()
            .map(|ext| ext.0.clone())
            .unwrap_or_default(),
        // The correlation id lives on the SessionState (its session id), not
        // the config; it only keys taint recording, which stays at the planner
        // tier.
        correlation_id: None,
        fact_store: config
            .get_extension::<crate::session::FactStoreExt>()
            .map(|ext| ext.0.clone()),
        function_resolver: config
            .get_extension::<crate::session::FunctionResolverExt>()
            .map(|ext| ext.0.clone()),
    };

    govern_provider(provider, table_ref, engine.0.as_ref(), &principal.0, &eval).await
}

/// A [`TableProvider`] that presents a governed (secured-view) plan over a
/// base provider.
///
/// The governed plan is exposed through [`get_logical_plan`], which DataFusion
/// inlines — wrapped in a `SubqueryAlias(table_name)` — at logical-plan build
/// time wherever the table is referenced, so qualified references stay stable
/// and every self-join occurrence inlines independently. Everything
/// non-read-shaped ([`table_type`], [`insert_into`], [`constraints`],
/// [`get_column_default`]) delegates to the base provider, so the wrapper is
/// indistinguishable from the base table to `SHOW TABLES`, `DESCRIBE`, and
/// INSERT.
///
/// [`get_logical_plan`]: TableProvider::get_logical_plan
/// [`table_type`]: TableProvider::table_type
/// [`insert_into`]: TableProvider::insert_into
/// [`constraints`]: TableProvider::constraints
/// [`get_column_default`]: TableProvider::get_column_default
#[derive(Debug)]
pub struct GovernedTableProvider {
    base: Arc<dyn TableProvider>,
    /// The governed plan: `Filter(row_filters, Projection(masks, scan))` over
    /// a scan of `base` (whose `get_logical_plan()` is `None`, so there is no
    /// recursive inlining).
    plan: LogicalPlan,
    /// The governed plan's schema. Masked columns keep the base column's name
    /// and `DataType` (see `apply_table_policy`), so this matches the base
    /// schema in names and types.
    schema: SchemaRef,
}

impl GovernedTableProvider {
    fn new(base: Arc<dyn TableProvider>, plan: LogicalPlan) -> Self {
        let schema = Arc::clone(plan.schema().inner());
        Self { base, plan, schema }
    }

    /// The wrapped base provider, for hosts that need to downcast to the
    /// concrete provider behind the secured view.
    pub fn base(&self) -> &Arc<dyn TableProvider> {
        &self.base
    }
}

#[async_trait]
impl TableProvider for GovernedTableProvider {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn constraints(&self) -> Option<&Constraints> {
        self.base.constraints()
    }

    fn table_type(&self) -> TableType {
        self.base.table_type()
    }

    fn get_logical_plan(&'_ self) -> Option<Cow<'_, LogicalPlan>> {
        Some(Cow::Borrowed(&self.plan))
    }

    fn get_column_default(&self, column: &str) -> Option<&Expr> {
        self.base.get_column_default(column)
    }

    /// Fallback for any path that bypasses `LogicalPlanBuilder`'s inlining
    /// (effectively unreachable through SQL). Plans the governed plan the way
    /// `ViewTable` does — note this **re-enters** `state.create_physical_plan`,
    /// i.e. the host's `QueryPlanner`; the governed marker makes that re-entry
    /// idempotent (the planner-tier govern pass skips the marked table).
    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let mut plan = LogicalPlanBuilder::from(self.plan.clone());

        if let Some(filter) = filters.iter().cloned().reduce(|acc, new| acc.and(new)) {
            plan = plan.filter(filter)?;
        }

        if let Some(projection) = projection {
            // Avoid a redundant identity projection (e.g. SELECT * FROM t).
            let identity = (0..plan.schema().fields().len()).collect::<Vec<usize>>();
            if projection != &identity {
                let fields: Vec<Expr> = projection
                    .iter()
                    .map(|i| {
                        Expr::Column(datafusion::common::Column::from(
                            self.plan.schema().qualified_field(*i),
                        ))
                    })
                    .collect();
                plan = plan.project(fields)?;
            }
        }

        if let Some(limit) = limit {
            plan = plan.limit(0, Some(limit))?;
        }

        state.create_physical_plan(&plan.build()?).await
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> Result<Vec<TableProviderFilterPushDown>> {
        // Mirrors `ViewTable`: only relevant on the `scan()` fallback path,
        // where the filter is applied onto the governed plan (above the mask
        // projection — a predicate on a masked column sees the masked value).
        Ok(vec![TableProviderFilterPushDown::Exact; filters.len()])
    }

    fn statistics(&self) -> Option<Statistics> {
        // The base provider's statistics describe pre-filter row counts;
        // returning them would both leak (row counts of rows the principal
        // cannot see) and mis-plan. No statistics is the safe answer.
        None
    }

    async fn insert_into(
        &self,
        state: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        insert_op: InsertOp,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        self.base.insert_into(state, input, insert_op).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::arrow::array::{Int64Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::common::DFSchema;
    use datafusion::datasource::MemTable;
    use datafusion::error::Result as DFResult;
    use datafusion::logical_expr::{col, lit};
    use datafusion::prelude::SessionContext;

    use super::*;
    use crate::govern::TablePolicy;
    use crate::types::Decision;

    /// A test engine returning a fixed [`TablePolicy`] for any table.
    #[derive(Debug)]
    struct FixedPolicy(TablePolicy);

    #[async_trait::async_trait]
    impl PolicyEngine for FixedPolicy {
        async fn is_allowed(
            &self,
            _plan: &LogicalPlan,
            _principal: &PrincipalIdentity,
            _eval: &EvalContext,
        ) -> DFResult<Decision> {
            Ok(Decision::Allow)
        }
        async fn constrain(
            &self,
            _table: &TableReference,
            _schema: &DFSchema,
            _principal: &PrincipalIdentity,
            _eval: &EvalContext,
        ) -> DFResult<TablePolicy> {
            Ok(self.0.clone())
        }
    }

    fn principal() -> PrincipalIdentity {
        PrincipalIdentity::new("User::\"alice\"")
    }

    fn base_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, true),
            Field::new("ssn", DataType::Utf8, true),
        ]))
    }

    /// A two-row MemTable: (1, "eu", "a") and (2, "us", "b").
    fn base_table() -> Arc<dyn TableProvider> {
        let schema = base_schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec!["eu", "us"])),
                Arc::new(StringArray::from(vec!["a", "b"])),
            ],
        )
        .unwrap();
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap())
    }

    /// Row filter `region = 'eu'` + mask `ssn -> '***'`.
    fn filter_and_mask() -> FixedPolicy {
        let mut masks = HashMap::new();
        masks.insert("ssn".to_string(), lit("***"));
        FixedPolicy(TablePolicy {
            row_filters: vec![col("region").eq(lit("eu"))],
            column_masks: masks,
        })
    }

    async fn governed(policy: &dyn PolicyEngine, eval: &EvalContext) -> Arc<dyn TableProvider> {
        govern_provider(
            base_table(),
            &TableReference::bare("t"),
            policy,
            &principal(),
            eval,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn select_through_registered_wrapper_is_masked_and_filtered() {
        let ctx = SessionContext::new();
        let eval = EvalContext::default();
        ctx.register_table("t", governed(&filter_and_mask(), &eval).await)
            .unwrap();

        let batches = ctx
            .sql("SELECT id, region, ssn FROM t ORDER BY id")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 1, "row filter must drop the non-eu row");
        let ssn = batches[0]
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(ssn.value(0), "***", "ssn must be masked");
    }

    #[tokio::test]
    async fn wrapper_schema_matches_base_names_and_types() {
        let eval = EvalContext::default();
        let provider = governed(&filter_and_mask(), &eval).await;
        let base = base_schema();
        let wrapped = provider.schema();
        assert_eq!(base.fields().len(), wrapped.fields().len());
        for (b, w) in base.fields().iter().zip(wrapped.fields().iter()) {
            assert_eq!(b.name(), w.name());
            assert_eq!(b.data_type(), w.data_type(), "field {}", b.name());
        }
    }

    #[tokio::test]
    async fn self_join_inlines_each_occurrence_independently() {
        let ctx = SessionContext::new();
        let eval = EvalContext::default();
        ctx.register_table("t", governed(&filter_and_mask(), &eval).await)
            .unwrap();

        let batches = ctx
            .sql("SELECT a.ssn, b.ssn FROM t a JOIN t b ON a.id = b.id")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        // Only the eu row survives on each side -> one joined row, both masked.
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 1);
        for col_idx in 0..2 {
            let ssn = batches[0]
                .column(col_idx)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            assert_eq!(ssn.value(0), "***");
        }
    }

    #[tokio::test]
    async fn insert_into_wrapper_appends_via_delegation() {
        let ctx = SessionContext::new();
        let eval = EvalContext::default();
        ctx.register_table("t", governed(&filter_and_mask(), &eval).await)
            .unwrap();

        ctx.sql("INSERT INTO t VALUES (3, 'eu', 'c')")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        // The appended eu row is visible (through the governed read: masked).
        let batches = ctx
            .sql("SELECT ssn FROM t WHERE id = 3")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 1, "insert must reach the base table by delegation");
        let ssn = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(ssn.value(0), "***");
    }

    #[tokio::test]
    async fn empty_policy_returns_same_arc_unwrapped() {
        let base = base_table();
        let eval = EvalContext::default();
        let out = govern_provider(
            Arc::clone(&base),
            &TableReference::bare("t"),
            &FixedPolicy(TablePolicy::default()),
            &principal(),
            &eval,
        )
        .await
        .unwrap();
        assert!(
            Arc::ptr_eq(&base, &out),
            "ungoverned table must keep its concrete provider"
        );
        // And the table is not marked governed — the planner backstop stays live.
        assert!(!eval.catalog_facts.is_governed(&TableReference::bare("t")));
    }

    #[tokio::test]
    async fn deny_all_rows_yields_empty_scan() {
        let ctx = SessionContext::new();
        let eval = EvalContext::default();
        let policy = FixedPolicy(TablePolicy {
            row_filters: vec![lit(false)],
            column_masks: Default::default(),
        });
        ctx.register_table("t", governed(&policy, &eval).await)
            .unwrap();
        let batches = ctx
            .sql("SELECT id FROM t")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 0);
    }

    /// The two tiers are mutually exclusive: `govern_plan` over a plan
    /// containing the inlined secured view adds nothing for the marked table,
    /// while an unmarked second table in the same query is still constrained.
    #[tokio::test]
    async fn planner_tier_respects_marker_but_constrains_unmarked_tables() {
        let ctx = SessionContext::new();
        let eval = EvalContext::default();
        ctx.register_table("t", governed(&filter_and_mask(), &eval).await)
            .unwrap();
        ctx.register_table("u", base_table()).unwrap();
        assert!(eval.catalog_facts.is_governed(&TableReference::bare("t")));

        let plan = ctx
            .sql("SELECT t.id FROM t JOIN u ON t.id = u.id")
            .await
            .unwrap()
            .into_unoptimized_plan();

        // The planner-tier engine hands out distinguishable filters.
        let planner_tier = FixedPolicy(TablePolicy {
            row_filters: vec![col("region").eq(lit("planner-marker"))],
            column_masks: Default::default(),
        });
        let governed_plan = crate::govern::govern_plan(&plan, &planner_tier, &principal(), &eval)
            .await
            .unwrap();
        let rendered = format!("{governed_plan:?}");
        assert_eq!(
            rendered.matches("planner-marker").count(),
            1,
            "exactly the unmarked table (u) gets the planner-tier filter: {rendered}"
        );
        // The provider-tier enforcement is present exactly once for t.
        assert_eq!(
            rendered.matches("***").count(),
            1,
            "the secured view's mask appears once, not twice: {rendered}"
        );
    }

    #[tokio::test]
    async fn from_config_governs_via_extensions_and_fails_closed() {
        // Fail closed: nothing bound.
        let bare = SessionConfig::new();
        let err = govern_provider_from_config(&bare, base_table(), &TableReference::bare("t"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no policy engine bound"));

        // Engine bound but no principal: still closed.
        let mut config = SessionConfig::new();
        config.set_extension(Arc::new(PolicyEngineExt(Arc::new(filter_and_mask()))));
        let err = govern_provider_from_config(&config, base_table(), &TableReference::bare("t"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no principal bound"));

        // Fully bound: the provider comes back wrapped and the shared sink is
        // marked.
        let sink_ext = Arc::new(CatalogFactSinkExt::default());
        config.set_extension(Arc::new(PrincipalExt(principal())));
        config.set_extension(sink_ext.clone());
        let out = govern_provider_from_config(&config, base_table(), &TableReference::bare("t"))
            .await
            .unwrap();
        assert!(
            (out.as_ref() as &dyn std::any::Any)
                .downcast_ref::<GovernedTableProvider>()
                .is_some(),
            "constrained table must come back as a GovernedTableProvider"
        );
        assert!(sink_ext.0.is_governed(&TableReference::bare("t")));
    }
}
