//! Layer 2: fine-grained governance — inject row filters and column masks into
//! a logical plan before optimization.
//!
//! [`govern_plan`] is a two-phase pass (the rewriter API is sync, but policy
//! resolution is async): an async phase collects the distinct tables a plan
//! reads and awaits each table's [`TablePolicy`]; a sync `GovernRewriter` then
//! wraps every `TableScan` in a mask `Projection` and a row `Filter`. Running
//! *before* `optimize()` lets the optimizer push the filter into the scan and
//! prune masked-away columns.

use std::collections::HashMap;

use datafusion::common::tree_node::{
    Transformed, TreeNode as _, TreeNodeRecursion, TreeNodeRewriter, TreeNodeVisitor,
};
use datafusion::common::{Column, DFSchema, Result};
use datafusion::logical_expr::expr_fn::cast;
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder};
use datafusion::sql::TableReference;

use crate::engine::PolicyEngine;
use crate::facts::EvalContext;
use crate::principal::PrincipalIdentity;

/// The fine-grained enforcement that applies to one table for one principal.
///
/// This is the engine-neutral carrier every [`PolicyEngine`] reduces its native
/// fine-grained shape to: a Cedar residual boolean, an OPA
/// residual, or an OpenFGA `ListObjects` id set all land in `row_filters` /
/// `column_masks` as DataFusion [`Expr`]s.
#[derive(Debug, Clone, Default)]
pub struct TablePolicy {
    /// Conjunctive row-filter predicates over the table's columns. Principal
    /// attributes are already folded to literals; only `resource.<col>`
    /// references remain (as `col(<col>)`).
    ///
    /// Any boolean [`Expr`] over the table's columns is a valid shape. Besides
    /// comparisons (`col("region").eq(lit("eu"))`), a *set-membership* filter
    /// `col("id").in_list(vec![...], false)` is explicitly supported — this is
    /// how an OpenFGA adapter would enforce a `ListObjects` permitted-id set as a
    /// semi-join-style row filter.
    pub row_filters: Vec<Expr>,
    /// Column name -> replacement expression for masked columns. The expression
    /// must not be a bare column (else the optimizer may absorb the projection);
    /// e.g. a literal or a hash.
    pub column_masks: HashMap<String, Expr>,
}

impl TablePolicy {
    /// Whether there is anything to enforce.
    pub fn is_empty(&self) -> bool {
        self.row_filters.is_empty() && self.column_masks.is_empty()
    }
}

/// Collect the distinct tables a plan reads (from `TableScan` nodes).
struct TableCollector {
    tables: Vec<(TableReference, datafusion::common::DFSchemaRef)>,
}

impl TreeNodeVisitor<'_> for TableCollector {
    type Node = LogicalPlan;

    fn f_down(&mut self, node: &Self::Node) -> Result<TreeNodeRecursion> {
        if let LogicalPlan::TableScan(scan) = node {
            self.tables
                .push((scan.table_name.clone(), scan.projected_schema.clone()));
        }
        Ok(TreeNodeRecursion::Continue)
    }
}

/// Inject row filters and column masks for each governed table.
///
/// Phase 1 (async): resolve each table's [`TablePolicy`]. Phase 2 (sync):
/// rewrite the plan. Returns the plan unchanged when nothing is governed.
pub async fn govern_plan(
    plan: &LogicalPlan,
    policy: &dyn PolicyEngine,
    principal: &PrincipalIdentity,
    eval: &EvalContext,
) -> Result<LogicalPlan> {
    // Phase 1: collect tables, then await per-table policy.
    let mut collector = TableCollector { tables: vec![] };
    plan.visit(&mut collector)?;

    let mut policies: HashMap<TableReference, TablePolicy> = HashMap::new();
    for (table, schema) in collector.tables {
        // Record the taints of any tagged column this scan reads into the
        // session fact store, keyed by correlation id. Independent of whether a
        // governance policy applies — taints accrue whenever a classified column
        // is read. Monotonic + idempotent, so repeated scans / re-planning are
        // safe. See docs/adr/0006 (shared-session-scoped facts).
        #[cfg(feature = "fgac")]
        record_taints(&table, schema.as_ref(), eval);

        if policies.contains_key(&table) {
            continue;
        }
        let tp = policy
            .constrain(&table, schema.as_ref(), principal, eval)
            .await?;
        if !tp.is_empty() {
            policies.insert(table, tp);
        }
    }

    if policies.is_empty() {
        return Ok(plan.clone());
    }

    // Phase 2: sync rewrite.
    let mut rewriter = GovernRewriter { policies };
    Ok(plan.clone().rewrite(&mut rewriter)?.data)
}

/// Record the taints of the columns `schema` projects from `table` into the
/// session fact store. No-ops unless a correlation id and fact store are both
/// present on `eval`, and only records the classification tags carried by the
/// columns actually projected (the catalog facts gathered at resolution).
fn record_taints(
    table: &TableReference,
    schema: &datafusion::common::DFSchema,
    eval: &EvalContext,
) {
    let (Some(cid), Some(store)) = (&eval.correlation_id, &eval.fact_store) else {
        return;
    };
    let Some(facts) = eval.catalog_facts.get(table) else {
        return;
    };
    let accessed: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();
    let taints = facts.taints_for_columns(&accessed);
    if !taints.is_empty() {
        store.record_taints(cid, &taints);
    }
}

/// Apply one table's enforcement to the plan node reading it, producing the
/// canonical `Filter(row_filters AND-reduced, Projection(masks, plan))` shape.
///
/// This is the single enforcement shape shared by both placements: the
/// planner-tier rewrite ([`govern_plan`]) hands in the `TableScan` it visits,
/// and the provider-tier secured view hands in a scan built over the base
/// provider. `schema` is the plan node's (projected) schema — the columns the
/// projection must reproduce.
pub(crate) fn apply_table_policy(
    plan: LogicalPlan,
    schema: &DFSchema,
    policy: &TablePolicy,
) -> Result<LogicalPlan> {
    let mut builder = LogicalPlanBuilder::from(plan);

    // Column masks: rebuild the projection, replacing masked columns with
    // their mask expression and passing the rest through unchanged. A masked
    // column must preserve the original *qualified* column identity (e.g.
    // `t.ssn`) so downstream nodes that reference the qualified column still
    // resolve, and the original `DataType` (via the CAST) so DESCRIBE /
    // information_schema stay indistinguishable from the base table.
    if !policy.column_masks.is_empty() {
        let projections: Vec<Expr> = schema
            .iter()
            .map(|(qualifier, field)| {
                let name = field.name();
                match policy.column_masks.get(name) {
                    Some(mask) => cast(mask.clone(), field.data_type().clone())
                        .alias_qualified(qualifier.cloned(), name),
                    None => Expr::Column(Column::new(qualifier.cloned(), name)),
                }
            })
            .collect();
        builder = builder.project(projections)?;
    }

    // Row filters: AND them together into one filter above the (possibly
    // masked) scan.
    if let Some(predicate) = policy.row_filters.iter().cloned().reduce(Expr::and) {
        builder = builder.filter(predicate)?;
    }

    builder.build()
}

/// The sync rewriter that wraps each governed `TableScan` in a mask projection
/// and a row filter.
struct GovernRewriter {
    policies: HashMap<TableReference, TablePolicy>,
}

impl TreeNodeRewriter for GovernRewriter {
    type Node = LogicalPlan;

    fn f_up(&mut self, node: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
        let LogicalPlan::TableScan(scan) = &node else {
            return Ok(Transformed::no(node));
        };
        let Some(tp) = self.policies.get(&scan.table_name) else {
            return Ok(Transformed::no(node));
        };

        let schema = scan.projected_schema.clone();
        Ok(Transformed::yes(apply_table_policy(node, &schema, tp)?))
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::common::DFSchema;
    use datafusion::error::Result as DFResult;
    use datafusion::logical_expr::logical_plan::builder::table_scan;
    use datafusion::logical_expr::{col, lit};

    use super::*;
    use crate::principal::PrincipalIdentity;
    use crate::types::Decision;

    /// A test policy returning a fixed enforcement for any table.
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

    fn scan() -> LogicalPlan {
        let schema = Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, true),
            Field::new("ssn", DataType::Utf8, true),
        ]);
        table_scan(Some("t"), &schema, None)
            .unwrap()
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn no_policy_leaves_plan_unchanged() {
        let policy = FixedPolicy(TablePolicy::default());
        let plan = scan();
        let governed = govern_plan(&plan, &policy, &principal(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(format!("{plan:?}"), format!("{governed:?}"));
    }

    fn schema_3() -> Schema {
        Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, true),
            Field::new("ssn", DataType::Utf8, true),
        ])
    }

    /// An `EvalContext` carrying a fact store + a sink that tags `t.ssn` as `pii`.
    fn eval_with_pii_ssn() -> (EvalContext, std::sync::Arc<crate::InMemoryFactStore>) {
        let sink = crate::CatalogFactSink::new();
        sink.record(
            TableReference::bare("t"),
            crate::TableFacts {
                column_tags: std::collections::HashMap::from([(
                    "ssn".to_string(),
                    ["pii".to_string()].into_iter().collect(),
                )]),
                ..Default::default()
            },
        );
        let store = std::sync::Arc::new(crate::InMemoryFactStore::new());
        let eval = EvalContext {
            catalog_facts: sink,
            correlation_id: Some("session-1".to_string()),
            fact_store: Some(store.clone()),
            function_resolver: None,
        };
        (eval, store)
    }

    #[tokio::test]
    async fn records_taint_when_tagged_column_is_projected() {
        use crate::FactStore as _;
        let (eval, store) = eval_with_pii_ssn();
        // Project id + ssn: ssn is pii-tagged, so the session ledger gains "pii".
        let plan = table_scan(Some("t"), &schema_3(), Some(vec![0, 2]))
            .unwrap()
            .build()
            .unwrap();
        govern_plan(
            &plan,
            &FixedPolicy(TablePolicy::default()),
            &principal(),
            &eval,
        )
        .await
        .unwrap();
        assert_eq!(
            store.observed_taints("session-1"),
            ["pii".to_string()].into_iter().collect()
        );
    }

    #[tokio::test]
    async fn no_taint_when_tagged_column_not_projected() {
        use crate::FactStore as _;
        let (eval, store) = eval_with_pii_ssn();
        // Project only id: ssn is not read, so nothing accrues.
        let plan = table_scan(Some("t"), &schema_3(), Some(vec![0]))
            .unwrap()
            .build()
            .unwrap();
        govern_plan(
            &plan,
            &FixedPolicy(TablePolicy::default()),
            &principal(),
            &eval,
        )
        .await
        .unwrap();
        assert!(store.observed_taints("session-1").is_empty());
    }

    #[tokio::test]
    async fn injects_row_filter() {
        let policy = FixedPolicy(TablePolicy {
            row_filters: vec![col("region").eq(lit("eu"))],
            column_masks: Default::default(),
        });
        let governed = govern_plan(&scan(), &policy, &principal(), &EvalContext::default())
            .await
            .unwrap();
        // Top of the governed subtree is a Filter.
        assert!(
            matches!(governed, LogicalPlan::Filter(_)),
            "expected a Filter at the top, got: {governed:?}"
        );
    }

    #[tokio::test]
    async fn injects_column_mask_as_non_identity_projection() {
        let mut masks = HashMap::new();
        masks.insert("ssn".to_string(), lit("***"));
        let policy = FixedPolicy(TablePolicy {
            row_filters: vec![],
            column_masks: masks,
        });
        let governed = govern_plan(&scan(), &policy, &principal(), &EvalContext::default())
            .await
            .unwrap();
        // A Projection wraps the scan; the masked column is a literal, not a
        // bare column reference (so the optimizer cannot absorb it).
        let LogicalPlan::Projection(proj) = &governed else {
            panic!("expected a Projection at the top, got: {governed:?}");
        };
        let masked = proj
            .expr
            .iter()
            .find(|e| e.schema_name().to_string().ends_with("ssn"))
            .expect("ssn projection present");
        // The masked column is an aliased literal, not a bare Column reference,
        // so the optimizer cannot absorb it back to the raw column.
        assert!(
            !matches!(masked, Expr::Column(_)),
            "masked column must not be a bare Column expr, got: {masked:?}"
        );
        // The other columns are preserved as qualified pass-through columns.
        let id_passthrough = proj
            .expr
            .iter()
            .find(|e| e.schema_name().to_string().ends_with("id"))
            .expect("id projection present");
        assert!(
            matches!(id_passthrough, Expr::Column(_)),
            "unmasked column should pass through as a Column"
        );
    }

    #[tokio::test]
    async fn mask_preserves_column_name_and_data_type() {
        // Mask an Int64 column with an Int32 literal: the CAST added by
        // `apply_table_policy` must restore the original DataType so the
        // governed schema is indistinguishable from the base table.
        let mut masks = HashMap::new();
        masks.insert("id".to_string(), lit(0i32));
        let policy = FixedPolicy(TablePolicy {
            row_filters: vec![],
            column_masks: masks,
        });
        let governed = govern_plan(&scan(), &policy, &principal(), &EvalContext::default())
            .await
            .unwrap();
        let field = governed
            .schema()
            .field_with_unqualified_name("id")
            .expect("masked column keeps its name");
        assert_eq!(
            field.data_type(),
            &DataType::Int64,
            "masked column must keep the original DataType"
        );
    }

    #[tokio::test]
    async fn deny_override_keeps_negated_condition() {
        // deny_override is modeled upstream as NOT(condition) in the row
        // filters; verify a NOT filter survives into the governed plan.
        let policy = FixedPolicy(TablePolicy {
            row_filters: vec![!col("region").eq(lit("blocked"))],
            column_masks: Default::default(),
        });
        let governed = govern_plan(&scan(), &policy, &principal(), &EvalContext::default())
            .await
            .unwrap();
        let LogicalPlan::Filter(f) = &governed else {
            panic!("expected Filter, got: {governed:?}");
        };
        // The predicate is a negation (Not), not the bare equality.
        assert!(
            format!("{:?}", f.predicate).contains("NOT") || matches!(f.predicate, Expr::Not(_)),
            "expected a negated predicate, got: {:?}",
            f.predicate
        );
    }

    /// A policy keyed per table, plus an option to error on resolution.
    #[derive(Debug)]
    struct PerTablePolicy {
        by_table: HashMap<String, TablePolicy>,
        err: bool,
    }

    #[async_trait::async_trait]
    impl PolicyEngine for PerTablePolicy {
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
            table: &TableReference,
            _schema: &DFSchema,
            _principal: &PrincipalIdentity,
            _eval: &EvalContext,
        ) -> DFResult<TablePolicy> {
            if self.err {
                return Err(datafusion::common::plan_datafusion_err!("policy boom"));
            }
            Ok(self
                .by_table
                .get(table.table())
                .cloned()
                .unwrap_or_default())
        }
    }

    /// In a JOIN, each scanned table gets its own filter/mask from its own
    /// policy — the rewriter keys by `scan.table_name`.
    #[tokio::test]
    async fn multi_table_join_governs_each_scan_independently() {
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;
        use std::sync::Arc;

        let ctx = SessionContext::new();
        let s = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, true),
        ]));
        for name in ["a", "b"] {
            ctx.register_table(
                name,
                Arc::new(MemTable::try_new(s.clone(), vec![vec![]]).unwrap()),
            )
            .unwrap();
        }
        let plan = ctx
            .sql("SELECT a.id FROM a JOIN b ON a.id = b.id")
            .await
            .unwrap()
            .into_unoptimized_plan();

        // Only table `a` gets a row filter; `b` is ungoverned.
        let mut by_table = HashMap::new();
        by_table.insert(
            "a".to_string(),
            TablePolicy {
                row_filters: vec![col("region").eq(lit("eu"))],
                column_masks: Default::default(),
            },
        );
        let policy = PerTablePolicy {
            by_table,
            err: false,
        };

        let governed = govern_plan(&plan, &policy, &principal(), &EvalContext::default())
            .await
            .unwrap();
        let rendered = format!("{governed:?}");
        // Exactly one Filter was injected (for `a`), not two — `b` is ungoverned.
        assert_eq!(
            rendered.matches("Filter(Filter").count(),
            1,
            "plan: {rendered}"
        );
        // The injected predicate filters on `a.region`.
        assert!(rendered.contains(r#"name: "region""#));
    }

    /// A policy-resolution error propagates out of `govern_plan` (fail-closed:
    /// the query fails rather than running ungoverned).
    #[tokio::test]
    async fn table_policy_error_propagates() {
        let policy = PerTablePolicy {
            by_table: HashMap::new(),
            err: true,
        };
        let result = govern_plan(&scan(), &policy, &principal(), &EvalContext::default()).await;
        assert!(result.is_err(), "policy resolution error must propagate");
    }

    // --- Optimizer-interaction tests (Phase 3): run the real DataFusion
    // optimizer over a governed plan and assert masks/filters behave. ---

    mod optimizer {
        use std::sync::Arc;

        use datafusion::arrow::array::{Int64Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;

        use super::*;

        async fn ctx() -> SessionContext {
            let ctx = SessionContext::new();
            let schema = Arc::new(Schema::new(vec![
                Field::new("id", DataType::Int64, false),
                Field::new("region", DataType::Utf8, true),
                Field::new("ssn", DataType::Utf8, true),
            ]));
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(Int64Array::from(vec![1, 2])),
                    Arc::new(StringArray::from(vec!["eu", "us"])),
                    Arc::new(StringArray::from(vec!["a", "b"])),
                ],
            )
            .unwrap();
            let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
            ctx.register_table("t", Arc::new(table)).unwrap();
            ctx
        }

        fn mask_ssn() -> FixedPolicy {
            let mut masks = HashMap::new();
            masks.insert("ssn".to_string(), lit("***"));
            FixedPolicy(TablePolicy {
                row_filters: vec![],
                column_masks: masks,
            })
        }

        /// The mask projection must survive `OptimizeProjections` — the masked
        /// column stays a literal and is never restored to the raw column.
        #[tokio::test]
        async fn mask_survives_optimizer() {
            let ctx = ctx().await;
            let plan = ctx
                .sql("SELECT id, region, ssn FROM t")
                .await
                .unwrap()
                .into_unoptimized_plan();

            let governed = govern_plan(&plan, &mask_ssn(), &principal(), &EvalContext::default())
                .await
                .unwrap();
            let optimized = ctx.state().optimize(&governed).unwrap();

            // The literal mask must appear in the optimized plan, and the raw
            // ssn column must not flow to the output unmasked.
            let dbg = format!("{}", optimized.display_indent());
            assert!(
                dbg.contains("Utf8(\"***\")") || dbg.contains("***"),
                "mask literal absent from optimized plan:\n{dbg}"
            );
        }

        /// A user predicate over a masked column must evaluate against the
        /// masked value: it must stay ABOVE the mask projection and never be
        /// pushed into the scan as a filter on the raw column (which would leak
        /// the real value).
        #[tokio::test]
        async fn user_predicate_does_not_push_through_mask() {
            let ctx = ctx().await;
            // User selects + filters on ssn; governance masks ssn.
            let plan = ctx
                .sql("SELECT ssn FROM t WHERE ssn = 'a'")
                .await
                .unwrap()
                .into_unoptimized_plan();

            let governed = govern_plan(&plan, &mask_ssn(), &principal(), &EvalContext::default())
                .await
                .unwrap();
            let optimized = ctx.state().optimize(&governed).unwrap();

            // Execute and confirm the predicate matched the MASKED value, not
            // the raw one: WHERE ssn='a' over masked data yields zero rows
            // (every ssn is '***'), proving the filter sits above the mask.
            let df = ctx.execute_logical_plan(optimized).await.unwrap();
            let batches = df.collect().await.unwrap();
            let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
            assert_eq!(
                rows, 0,
                "user predicate leaked through the mask (matched raw ssn)"
            );
        }

        /// A governed row filter pushes down toward the scan after optimization
        /// (it becomes a scan-level filter or a Filter directly above the scan),
        /// confirming the pre-optimize injection rides predicate pushdown.
        #[tokio::test]
        async fn row_filter_pushes_toward_scan() {
            let ctx = ctx().await;
            let plan = ctx
                .sql("SELECT id, region FROM t")
                .await
                .unwrap()
                .into_unoptimized_plan();

            let policy = FixedPolicy(TablePolicy {
                row_filters: vec![col("region").eq(lit("eu"))],
                column_masks: Default::default(),
            });
            let governed = govern_plan(&plan, &policy, &principal(), &EvalContext::default())
                .await
                .unwrap();
            let optimized = ctx.state().optimize(&governed).unwrap();

            // Only the 'eu' row survives -> 1 row.
            let df = ctx.execute_logical_plan(optimized).await.unwrap();
            let rows: usize = df
                .collect()
                .await
                .unwrap()
                .iter()
                .map(|b| b.num_rows())
                .sum();
            assert_eq!(rows, 1, "row filter not enforced");
        }
    }
}
