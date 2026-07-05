//! [`AbacPolicyEngine`]: a direct, data-driven [`PolicyEngine`] over the neutral
//! [`PolicyBinding`] model — the enforcement path for Databricks Unity Catalog
//! ABAC without a UC→Cedar compiler.
//!
//! UC ABAC policies are additive constraints with no deny verdicts, so Cedar
//! TPE's power (arbitrary residuals, forbid semantics) is unused. This engine is
//! instead a pure function `(bindings, facts, principal) → TablePolicy`: it
//! needs no catalog client and no Cedar — bindings are *facts* delivered on
//! [`TableFacts::policies`](crate::TableFacts::policies), and the only external
//! seam is the [`CatalogFunctionResolver`](crate::CatalogFunctionResolver) that
//! turns a policy's function name into a callable UDF (shared with the Cedar
//! path). This keeps the Cedar/OCI stack optional for UC-only deployments.
//!
//! # Coarse gate
//!
//! [`is_allowed`](AbacPolicyEngine::is_allowed) always returns
//! [`Decision::Allow`]: UC ABAC has no coarse allow/deny — that is Unity Catalog
//! *privileges'* job (or a composed Cedar engine's, in a later composite
//! engine). This engine only produces fine-grained row filters and column masks.

use datafusion::common::{DFSchema, Result};
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{Expr, col, lit};
use datafusion::sql::TableReference;

use crate::binding::{BindingKind, ColumnMatch, FunctionArg, PolicyBinding};
use crate::engine::PolicyEngine;
use crate::facts::{EvalContext, TableFacts};
use crate::govern::TablePolicy;
use crate::principal::PrincipalIdentity;
use crate::types::Decision;

/// The default column-mask replacement when a mask function cannot be resolved —
/// the same fail-closed literal the Cedar path emits.
const DEFAULT_MASK: &str = "***";

/// The `TO` sentinel that matches every principal (Databricks' "all users"
/// group). A binding listing this in `to_principals` applies to everyone (still
/// subject to `except_principals`).
const ALL_USERS: &str = "account users";

/// Decides whether a [`PolicyBinding`]'s principal lists match the querying
/// [`PrincipalIdentity`] — a small seam so a host can override the
/// name-normalization / all-users semantics its directory uses.
///
/// The [default implementation](DefaultPrincipalMatcher) normalizes an
/// `EntityType::"name"`-wrapped uid down to `name` (both directions) so a
/// Cedar-shaped `User::"alice"` matches a plain `alice` written in a UC policy,
/// treats the `account users` sentinel as matching everyone, and is
/// case-sensitive.
pub trait PrincipalMatcher: std::fmt::Debug + Send + Sync {
    /// Whether `name` (a `to`/`except` entry from a binding) refers to
    /// `principal` — by its uid or any of its groups.
    fn matches(&self, name: &str, principal: &PrincipalIdentity) -> bool;
}

/// The default [`PrincipalMatcher`]: strips an `EntityType::"..."` wrapper off
/// both the binding name and the principal's uid/groups before a case-sensitive
/// compare, and treats the `account users` sentinel as matching every principal.
#[derive(Debug, Clone, Default)]
pub struct DefaultPrincipalMatcher;

/// Strip a `EntityType::"inner"` Cedar-style wrapper down to `inner`; leave a
/// plain name untouched. `User::"alice"` → `alice`, `alice` → `alice`.
fn normalize_name(name: &str) -> &str {
    // Find the `::` type separator, then unwrap surrounding quotes on the tail.
    if let Some((_, tail)) = name.rsplit_once("::") {
        tail.strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .unwrap_or(tail)
    } else {
        name
    }
}

impl PrincipalMatcher for DefaultPrincipalMatcher {
    fn matches(&self, name: &str, principal: &PrincipalIdentity) -> bool {
        if name == ALL_USERS {
            return true;
        }
        let want = normalize_name(name);
        if normalize_name(&principal.uid) == want {
            return true;
        }
        principal.groups.iter().any(|g| normalize_name(g) == want)
    }
}

/// A [`PolicyEngine`] that enforces UC ABAC [`PolicyBinding`]s directly.
///
/// Construct with [`AbacPolicyEngine::new`] (default matcher) or
/// [`AbacPolicyEngine::with_matcher`] to override principal matching. The engine
/// holds no catalog handle: it reads bindings from `eval.catalog_facts` and
/// resolves functions through `eval.function_resolver`.
#[derive(Debug)]
pub struct AbacPolicyEngine {
    matcher: Box<dyn PrincipalMatcher>,
}

impl Default for AbacPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AbacPolicyEngine {
    /// A new engine using the [`DefaultPrincipalMatcher`].
    pub fn new() -> Self {
        Self {
            matcher: Box::new(DefaultPrincipalMatcher),
        }
    }

    /// A new engine using a custom [`PrincipalMatcher`].
    pub fn with_matcher(matcher: Box<dyn PrincipalMatcher>) -> Self {
        Self { matcher }
    }

    /// Whether `binding` applies to `principal`: matched by `to_principals`
    /// (uid, group, or the all-users sentinel) AND NOT matched by
    /// `except_principals`.
    fn principal_applies(&self, binding: &PolicyBinding, principal: &PrincipalIdentity) -> bool {
        let to = binding
            .to_principals
            .iter()
            .any(|n| self.matcher.matches(n, principal));
        if !to {
            return false;
        }
        !binding
            .except_principals
            .iter()
            .any(|n| self.matcher.matches(n, principal))
    }

    /// The columns of `facts` that satisfy `m.condition`, **intersected with**
    /// the columns actually present in `schema` (don't touch columns not in this
    /// scan), in `schema` order for determinism.
    fn matched_columns(m: &ColumnMatch, facts: &TableFacts, schema: &DFSchema) -> Vec<String> {
        schema
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .filter(|name| {
                facts
                    .governed_column_tags
                    .get(name)
                    .is_some_and(|tags| m.condition.matches(tags))
            })
            .collect()
    }

    /// Map a binding's `using_args` to call [`Expr`]s. An [`FunctionArg::Alias`]
    /// resolves to the (first) column matched by the [`ColumnMatch`] carrying
    /// that alias — `col(that_column)`; a [`FunctionArg::Constant`] becomes a
    /// literal. An alias with no matching column is dropped (nothing to bind).
    fn map_args(
        args: &[FunctionArg],
        binding: &PolicyBinding,
        facts: &TableFacts,
        schema: &DFSchema,
    ) -> Vec<Expr> {
        args.iter()
            .filter_map(|arg| match arg {
                FunctionArg::Constant(c) => Some(lit(c.clone())),
                FunctionArg::Alias(alias) => binding
                    .match_columns
                    .iter()
                    .find(|m| &m.alias == alias)
                    .and_then(|m| Self::matched_columns(m, facts, schema).into_iter().next())
                    .map(col),
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl PolicyEngine for AbacPolicyEngine {
    async fn is_allowed(
        &self,
        _logical_plan: &datafusion::logical_expr::LogicalPlan,
        _principal: &PrincipalIdentity,
        _eval: &EvalContext,
    ) -> Result<Decision> {
        // UC ABAC has no coarse gate; privileges (or a composed engine) own deny.
        Ok(Decision::Allow)
    }

    async fn constrain(
        &self,
        table: &TableReference,
        schema: &DFSchema,
        principal: &PrincipalIdentity,
        eval: &EvalContext,
    ) -> Result<TablePolicy> {
        let Some(facts) = eval.catalog_facts.get(table) else {
            return Ok(TablePolicy::default());
        };

        let mut policy = TablePolicy::default();
        for binding in &facts.policies {
            // (1) principal match, (2) table `WHEN` conjunction.
            if !self.principal_applies(binding, principal) {
                continue;
            }
            if !binding
                .when_condition
                .iter()
                .all(|c| c.matches(&facts.governed_tags))
            {
                continue;
            }

            match binding.kind {
                BindingKind::RowFilter => {
                    let expr = self.row_filter_expr(binding, &facts, schema, eval).await?;
                    policy.row_filters.push(expr);
                }
                BindingKind::ColumnMask => {
                    self.apply_mask(binding, &facts, schema, eval, &mut policy)
                        .await?;
                }
            }
        }
        Ok(policy)
    }
}

impl AbacPolicyEngine {
    /// Build the row-filter call `Expr` for a `RowFilter` binding. A row filter
    /// that cannot be built is an **`Err`** — a filter that can't be resolved
    /// must fail the query, not silently pass every row.
    async fn row_filter_expr(
        &self,
        binding: &PolicyBinding,
        facts: &TableFacts,
        schema: &DFSchema,
        eval: &EvalContext,
    ) -> Result<Expr> {
        let Some(resolver) = eval.function_resolver.as_deref() else {
            return Err(DataFusionError::Plan(format!(
                "row-filter policy {:?} names function {:?} but no CatalogFunctionResolver is wired; \
                 refusing to run the query unfiltered (fail-closed)",
                binding.name, binding.function
            )));
        };
        let udf = resolver.resolve(&binding.function).await?;
        let args = Self::map_args(&binding.using_args, binding, facts, schema);
        Ok(udf.call(args))
    }

    /// Apply a `ColumnMask` binding to `policy`: for each column matched by the
    /// binding's first [`ColumnMatch`] (the masked input column), install a mask
    /// expression. An unresolvable mask function falls back to the
    /// [`DEFAULT_MASK`] literal (same fail-closed contract as the Cedar path).
    /// First binding wins per column — UC applies one mask per column, so a
    /// column already masked by an earlier binding is left untouched.
    async fn apply_mask(
        &self,
        binding: &PolicyBinding,
        facts: &TableFacts,
        schema: &DFSchema,
        eval: &EvalContext,
        policy: &mut TablePolicy,
    ) -> Result<()> {
        let Some(first) = binding.match_columns.first() else {
            return Ok(());
        };
        let columns = Self::matched_columns(first, facts, schema);
        for column in columns {
            if policy.column_masks.contains_key(&column) {
                // First matching binding wins (binding order); UC masks a column once.
                continue;
            }
            let mask = self
                .mask_expr(binding, &column, facts, schema, eval)
                .await?;
            policy.column_masks.insert(column, mask);
        }
        Ok(())
    }

    /// The mask expression for one `column`: the resolved function called with
    /// `col(column)` as arg 0 plus any `using_args` extras. When no resolver is
    /// wired or the function is unresolvable, fall back to the [`DEFAULT_MASK`]
    /// literal (fail-closed — never leaves the column unmasked).
    async fn mask_expr(
        &self,
        binding: &PolicyBinding,
        column: &str,
        facts: &TableFacts,
        schema: &DFSchema,
        eval: &EvalContext,
    ) -> Result<Expr> {
        let Some(resolver) = eval.function_resolver.as_deref() else {
            return Ok(lit(DEFAULT_MASK));
        };
        // An unresolvable mask function fails closed to the default literal
        // (never leaves the column unmasked), matching the Cedar path.
        let Ok(udf) = resolver.resolve(&binding.function).await else {
            return Ok(lit(DEFAULT_MASK));
        };
        let mut args = vec![col(column)];
        args.extend(Self::map_args(&binding.using_args, binding, facts, schema));
        Ok(udf.call(args))
    }
}

/// Shared free helper for the coarse "does any binding match" question used in
/// tests. Not part of the public surface.
#[cfg(test)]
fn _assert_send_sync<T: Send + Sync>() {}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::logical_expr::{
        ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
    };

    use super::*;
    use crate::binding::TagCondition;
    use crate::facts::CatalogFactSink;
    use crate::function::CatalogFunctionResolver;

    // --- Test fixtures -----------------------------------------------------

    fn schema(cols: &[&str]) -> DFSchema {
        let fields: Vec<Field> = cols
            .iter()
            .map(|c| Field::new(*c, DataType::Utf8, true))
            .collect();
        DFSchema::try_from(Schema::new(fields)).unwrap()
    }

    fn principal(uid: &str, groups: &[&str]) -> PrincipalIdentity {
        let mut p = PrincipalIdentity::new(uid);
        p.groups = groups.iter().map(|g| g.to_string()).collect();
        p
    }

    /// A trivial UDF so `resolve` yields something callable. Its identity in
    /// tests is the fixed name `ident`, so a resolved call is recognizable.
    #[derive(Debug, PartialEq, Eq, Hash)]
    struct IdentUdf(Signature);
    impl IdentUdf {
        fn new() -> Self {
            Self(Signature::variadic_any(Volatility::Immutable))
        }
    }
    impl ScalarUDFImpl for IdentUdf {
        fn name(&self) -> &str {
            "ident"
        }
        fn signature(&self) -> &Signature {
            &self.0
        }
        fn return_type(&self, _args: &[DataType]) -> Result<DataType> {
            Ok(DataType::Utf8)
        }
        fn invoke_with_args(&self, args: ScalarFunctionArgs) -> Result<ColumnarValue> {
            Ok(args.args.into_iter().next().unwrap())
        }
    }

    /// A resolver that resolves any name to a fixed UDF, or (if `fail`) errors.
    #[derive(Debug)]
    struct StubResolver {
        fail: bool,
    }

    #[async_trait::async_trait]
    impl CatalogFunctionResolver for StubResolver {
        async fn resolve(&self, name: &str) -> Result<Arc<ScalarUDF>> {
            if self.fail {
                return Err(DataFusionError::Plan(format!("no such function {name}")));
            }
            Ok(Arc::new(ScalarUDF::from(IdentUdf::new())))
        }
    }

    fn eval_with(facts: TableFacts, resolver: Option<StubResolver>) -> EvalContext {
        let sink = CatalogFactSink::new();
        sink.record(TableReference::bare("t"), facts);
        EvalContext {
            catalog_facts: sink,
            correlation_id: None,
            fact_store: None,
            function_resolver: resolver.map(|r| Arc::new(r) as Arc<dyn CatalogFunctionResolver>),
        }
    }

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // --- Principal matching ------------------------------------------------

    #[test]
    fn matcher_uid_group_except_all_users_and_normalization() {
        let m = DefaultPrincipalMatcher;
        let alice = principal("User::\"alice\"", &["UserGroup::\"analysts\""]);

        // uid match, both directions of normalization.
        assert!(m.matches("alice", &alice));
        assert!(m.matches("User::\"alice\"", &alice));
        // group match.
        assert!(m.matches("analysts", &alice));
        assert!(m.matches("UserGroup::\"analysts\"", &alice));
        // all-users sentinel.
        assert!(m.matches("account users", &alice));
        // no match, case-sensitive.
        assert!(!m.matches("bob", &alice));
        assert!(!m.matches("Alice", &alice));
    }

    #[tokio::test]
    async fn except_overrides_to() {
        let engine = AbacPolicyEngine::new();
        let binding = PolicyBinding {
            name: "p".into(),
            kind: BindingKind::RowFilter,
            to_principals: vec!["account users".into()],
            except_principals: vec!["alice".into()],
            when_condition: vec![],
            match_columns: vec![],
            function: "f".into(),
            using_args: vec![],
        };
        assert!(!engine.principal_applies(&binding, &principal("alice", &[])));
        assert!(engine.principal_applies(&binding, &principal("bob", &[])));
    }

    // --- when_condition ----------------------------------------------------

    async fn constrain_rows(facts: TableFacts, binding: PolicyBinding) -> TablePolicy {
        let mut f = facts;
        f.policies = vec![binding];
        let engine = AbacPolicyEngine::new();
        let eval = eval_with(f, Some(StubResolver { fail: false }));
        engine
            .constrain(
                &TableReference::bare("t"),
                &schema(&["id", "ssn"]),
                &principal("alice", &[]),
                &eval,
            )
            .await
            .unwrap()
    }

    fn row_filter_binding(when: Vec<TagCondition>) -> PolicyBinding {
        PolicyBinding {
            name: "rf".into(),
            kind: BindingKind::RowFilter,
            to_principals: vec!["account users".into()],
            except_principals: vec![],
            when_condition: when,
            match_columns: vec![],
            function: "f".into(),
            using_args: vec![],
        }
    }

    #[tokio::test]
    async fn when_empty_always_applies() {
        let tp = constrain_rows(TableFacts::default(), row_filter_binding(vec![])).await;
        assert_eq!(tp.row_filters.len(), 1);
    }

    #[tokio::test]
    async fn when_key_only_and_key_value_and_missing() {
        let facts = TableFacts {
            governed_tags: tags(&[("classification", "regulated")]),
            ..Default::default()
        };
        // key-only present.
        let tp = constrain_rows(
            facts.clone(),
            row_filter_binding(vec![TagCondition {
                key: "classification".into(),
                value: None,
            }]),
        )
        .await;
        assert_eq!(tp.row_filters.len(), 1);

        // key+value equal.
        let tp = constrain_rows(
            facts.clone(),
            row_filter_binding(vec![TagCondition {
                key: "classification".into(),
                value: Some("regulated".into()),
            }]),
        )
        .await;
        assert_eq!(tp.row_filters.len(), 1);

        // missing key => does not apply.
        let tp = constrain_rows(
            facts.clone(),
            row_filter_binding(vec![TagCondition {
                key: "absent".into(),
                value: None,
            }]),
        )
        .await;
        assert!(tp.row_filters.is_empty());
    }

    #[tokio::test]
    async fn when_multi_condition_is_conjunction() {
        let facts = TableFacts {
            governed_tags: tags(&[("a", "1"), ("b", "2")]),
            ..Default::default()
        };
        // Both hold => applies.
        let tp = constrain_rows(
            facts.clone(),
            row_filter_binding(vec![
                TagCondition {
                    key: "a".into(),
                    value: Some("1".into()),
                },
                TagCondition {
                    key: "b".into(),
                    value: Some("2".into()),
                },
            ]),
        )
        .await;
        assert_eq!(tp.row_filters.len(), 1);

        // One fails => does not apply.
        let tp = constrain_rows(
            facts,
            row_filter_binding(vec![
                TagCondition {
                    key: "a".into(),
                    value: Some("1".into()),
                },
                TagCondition {
                    key: "b".into(),
                    value: Some("WRONG".into()),
                },
            ]),
        )
        .await;
        assert!(tp.row_filters.is_empty());
    }

    // --- Column matching ∩ schema ------------------------------------------

    #[test]
    fn matched_columns_intersects_schema() {
        // ssn + email are pii-tagged in facts, but only ssn is in this scan.
        let facts = TableFacts {
            governed_column_tags: HashMap::from([
                ("ssn".to_string(), tags(&[("pii", "ssn")])),
                ("email".to_string(), tags(&[("pii", "email")])),
            ]),
            ..Default::default()
        };
        let m = ColumnMatch {
            condition: TagCondition {
                key: "pii".into(),
                value: None,
            },
            alias: "c".into(),
        };
        let matched = AbacPolicyEngine::matched_columns(&m, &facts, &schema(&["id", "ssn"]));
        assert_eq!(matched, vec!["ssn".to_string()]);
    }

    // --- TablePolicy production --------------------------------------------

    fn mask_binding(function: &str, extra: Vec<FunctionArg>) -> PolicyBinding {
        PolicyBinding {
            name: "mask".into(),
            kind: BindingKind::ColumnMask,
            to_principals: vec!["account users".into()],
            except_principals: vec![],
            when_condition: vec![],
            match_columns: vec![ColumnMatch {
                condition: TagCondition {
                    key: "pii".into(),
                    value: None,
                },
                alias: "col".into(),
            }],
            function: function.into(),
            using_args: extra,
        }
    }

    fn pii_ssn_facts() -> TableFacts {
        TableFacts {
            governed_column_tags: HashMap::from([("ssn".to_string(), tags(&[("pii", "ssn")]))]),
            ..Default::default()
        }
    }

    async fn constrain_with(
        facts: TableFacts,
        resolver: Option<StubResolver>,
    ) -> Result<TablePolicy> {
        let engine = AbacPolicyEngine::new();
        let eval = eval_with(facts, resolver);
        engine
            .constrain(
                &TableReference::bare("t"),
                &schema(&["id", "ssn"]),
                &principal("alice", &[]),
                &eval,
            )
            .await
    }

    #[tokio::test]
    async fn mask_binding_produces_call_over_matched_column() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![mask_binding(
            "hr.mask",
            vec![FunctionArg::Constant("X".into())],
        )];
        let tp = constrain_with(facts, Some(StubResolver { fail: false }))
            .await
            .unwrap();
        let mask = tp.column_masks.get("ssn").expect("ssn masked");
        // arg 0 is the column; the constant extra rides along.
        assert!(
            matches!(mask, Expr::ScalarFunction(_)),
            "expected a UDF call, got: {mask:?}"
        );
        let rendered = format!("{mask:?}");
        assert!(
            rendered.contains("IdentUdf"),
            "expected UDF call: {rendered}"
        );
        assert!(rendered.contains("ssn"), "arg-0 column missing: {rendered}");
        assert!(
            rendered.contains("X"),
            "constant extra arg missing: {rendered}"
        );
    }

    #[tokio::test]
    async fn row_filter_maps_alias_and_constant_args() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![PolicyBinding {
            name: "rf".into(),
            kind: BindingKind::RowFilter,
            to_principals: vec!["account users".into()],
            except_principals: vec![],
            when_condition: vec![],
            match_columns: vec![ColumnMatch {
                condition: TagCondition {
                    key: "pii".into(),
                    value: None,
                },
                alias: "c".into(),
            }],
            function: "hr.rf".into(),
            using_args: vec![
                FunctionArg::Alias("c".into()),
                FunctionArg::Constant("eu".into()),
            ],
        }];
        let tp = constrain_with(facts, Some(StubResolver { fail: false }))
            .await
            .unwrap();
        assert_eq!(tp.row_filters.len(), 1);
        let rendered = format!("{:?}", tp.row_filters[0]);
        // Alias resolved to the ssn column; constant present.
        assert!(rendered.contains("ssn"), "alias arg missing: {rendered}");
        assert!(rendered.contains("eu"), "constant arg missing: {rendered}");
    }

    #[tokio::test]
    async fn unresolvable_filter_fn_errors() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![row_filter_binding(vec![])];
        // Resolver present but failing => Err (never run unfiltered).
        let err = constrain_with(facts, Some(StubResolver { fail: true }))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("no such function"));
    }

    #[tokio::test]
    async fn missing_resolver_for_filter_errors() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![row_filter_binding(vec![])];
        // No resolver at all => Err (fail-closed).
        let err = constrain_with(facts, None).await.unwrap_err();
        assert!(format!("{err}").contains("fail-closed"));
    }

    #[tokio::test]
    async fn unresolvable_mask_fn_falls_back_to_default() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![mask_binding("hr.mask", vec![])];
        let tp = constrain_with(facts, Some(StubResolver { fail: true }))
            .await
            .unwrap();
        let mask = tp.column_masks.get("ssn").expect("ssn masked");
        assert_eq!(mask, &lit(DEFAULT_MASK));
    }

    #[tokio::test]
    async fn missing_resolver_for_mask_falls_back_to_default() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![mask_binding("hr.mask", vec![])];
        let tp = constrain_with(facts, None).await.unwrap();
        assert_eq!(tp.column_masks.get("ssn"), Some(&lit(DEFAULT_MASK)));
    }

    #[tokio::test]
    async fn first_mask_binding_wins_per_column() {
        let mut facts = pii_ssn_facts();
        // Two mask bindings on ssn: the first names a resolvable fn, the second
        // would default-mask. The first must win.
        facts.policies = vec![
            mask_binding("hr.first", vec![]),
            mask_binding("hr.second", vec![]),
        ];
        let tp = constrain_with(facts, Some(StubResolver { fail: false }))
            .await
            .unwrap();
        let mask = tp.column_masks.get("ssn").expect("ssn masked");
        // A resolved UDF call, not the default literal.
        assert_ne!(mask, &lit(DEFAULT_MASK));
    }

    #[tokio::test]
    async fn non_matching_principal_gets_no_constraints() {
        let mut facts = pii_ssn_facts();
        facts.policies = vec![PolicyBinding {
            to_principals: vec!["bob".into()],
            ..mask_binding("hr.mask", vec![])
        }];
        let tp = constrain_with(facts, Some(StubResolver { fail: false }))
            .await
            .unwrap();
        assert!(tp.is_empty(), "alice is not bob; nothing should apply");
    }

    #[tokio::test]
    async fn no_facts_for_table_is_empty_policy() {
        let engine = AbacPolicyEngine::new();
        let eval = EvalContext::default();
        let tp = engine
            .constrain(
                &TableReference::bare("absent"),
                &schema(&["id"]),
                &principal("alice", &[]),
                &eval,
            )
            .await
            .unwrap();
        assert!(tp.is_empty());
    }

    #[tokio::test]
    async fn is_allowed_always_allows() {
        use datafusion::logical_expr::LogicalPlanBuilder;
        let engine = AbacPolicyEngine::new();
        let plan = LogicalPlanBuilder::empty(false).build().unwrap();
        let d = engine
            .is_allowed(&plan, &principal("alice", &[]), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn engine_is_send_sync() {
        _assert_send_sync::<AbacPolicyEngine>();
    }
}
