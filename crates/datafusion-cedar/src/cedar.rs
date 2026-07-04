use std::collections::HashMap;
use std::sync::Arc;

use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_local_agent::public::{SimpleEntityProvider, SimplePolicySetProvider};
use cedar_policy::{Entities, Entity, RestrictedExpression};
use datafusion::common::plan_datafusion_err;
use datafusion::error::Result;
use datafusion::logical_expr::LogicalPlan;
use datafusion::sql::TableReference;

use cedar_oci::OciPolicyProvider;

use crate::cedar_entity::principal_entities;
use crate::facts::{EvalContext, TableFacts};
use crate::policy::PolicyEngine;
use crate::principal::PrincipalIdentity;
use crate::types::Decision;
use crate::visitor::{PlanRequest, authorize_plan, table_resource_uid};

/// Map Cedar's native decision onto the neutral [`Decision`]. Cedar has exactly
/// two variants; anything that is not an explicit `Allow` is treated as `Deny`
/// (fail-closed).
fn neutral_decision(decision: cedar_policy::Decision) -> Decision {
    match decision {
        cedar_policy::Decision::Allow => Decision::Allow,
        cedar_policy::Decision::Deny => Decision::Deny,
    }
}

/// Build the request-time `Table` resource entity carrying the catalog facts,
/// so policies can resolve `resource.owner/readers/writers/tags/column_tags`.
///
/// The entity uid is exactly `table_resource_uid(table_ref)` — the same uid the
/// authorization request resolves against — so cedar-local-agent merges this
/// attributed entity onto the request's `resource`. Returns `None` when there
/// are no facts to fold (the resource then resolves from the provider's static
/// bundle alone, as before).
fn table_entity(table_ref: &TableReference, facts: &TableFacts) -> Option<Entity> {
    if facts.is_empty() {
        return None;
    }
    let set = |items: &std::collections::BTreeSet<String>| {
        RestrictedExpression::new_set(
            items
                .iter()
                .map(|s| RestrictedExpression::new_string(s.clone())),
        )
    };

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    if let Some(owner) = &facts.owner {
        attrs.insert(
            "owner".into(),
            RestrictedExpression::new_string(owner.clone()),
        );
    }
    attrs.insert("readers".into(), set(&facts.readers));
    attrs.insert("writers".into(), set(&facts.writers));
    attrs.insert("tags".into(), set(&facts.tags));
    // column_tags as a Cedar record { <col>: Set<String>, ... }.
    let column_tags = facts
        .column_tags
        .iter()
        .map(|(col, tags)| (col.clone(), set(tags)));
    if let Ok(rec) = RestrictedExpression::new_record(column_tags) {
        attrs.insert("column_tags".into(), rec);
    }

    // Parents (group hierarchy) are not a resource concept here; an attribute
    // failure falls back to no entity so authorization stays fail-closed
    // (resource attrs simply don't resolve) rather than erroring open.
    Entity::new(table_resource_uid(table_ref), attrs, Default::default()).ok()
}

#[cfg(feature = "governance")]
use {
    crate::govern::TablePolicy,
    crate::translate::{CedarResidualTranslator, ConstraintTranslator},
    cedar_policy::{EntityTypeName, Request, RequestBuilder},
    datafusion::common::DFSchema,
    datafusion::logical_expr::lit,
    std::str::FromStr as _,
};

/// A [`PolicyEngine`] backed by a Cedar [`Authorizer`].
///
/// Generic over any policy-set and entity provider (e.g. `cedar-oci`'s
/// [`OciPolicyProvider`]), so the policy source is pluggable.
#[derive(Debug)]
pub struct CedarPolicy<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    authorizer: Authorizer<P, E>,
}

impl<P, E> CedarPolicy<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    fn new(authorizer: Authorizer<P, E>) -> Self {
        Self { authorizer }
    }
}

impl CedarPolicy<OciPolicyProvider, OciPolicyProvider> {
    /// Build a Cedar policy that sources its policy set, schema, and entities
    /// from an OCI registry reference (e.g.
    /// `localhost:10100/hydrofoil/plan-policy:latest`).
    ///
    /// The same provider backs both the policy-set and entity providers.
    pub async fn from_oci(reference: &str) -> Result<Self> {
        let provider = Arc::new(OciPolicyProvider::from_reference(reference).await.map_err(
            |e| {
                plan_datafusion_err!(
                    "Failed to load Cedar policy from OCI reference '{reference}': {e}"
                )
            },
        )?);
        let config = AuthorizerConfigBuilder::default()
            .policy_set_provider(provider.clone())
            .entity_provider(provider)
            .build()
            .map_err(|e| plan_datafusion_err!("Failed to build Cedar authorizer: {e}"))?;
        Ok(Self::new(Authorizer::new(config)))
    }
}

#[async_trait::async_trait]
impl<P, E> PolicyEngine for CedarPolicy<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    async fn is_allowed(
        &self,
        logical_plan: &LogicalPlan,
        principal: &PrincipalIdentity,
        eval: &EvalContext,
    ) -> Result<Decision> {
        let requests = authorize_plan(logical_plan, principal)?;

        for PlanRequest { request, table } in requests {
            // Supply the principal (and its resolved group-entity closure) as
            // request-time entities so policies can resolve `principal.<attr>`
            // and `principal in <group>`, plus — when this request is over a
            // table with gathered catalog facts — the `Table` resource entity
            // carrying `resource.owner/readers/writers/tags/column_tags`.
            // cedar-local-agent merges these with the entities the provider vends.
            let mut entities = principal_entities(principal)?;
            if let Some(table_ref) = &table
                && let Some(facts) = eval.catalog_facts.get(table_ref)
                && let Some(entity) = table_entity(table_ref, &facts)
            {
                entities.push(entity);
            }
            let request_entities =
                Entities::from_entities(entities, None).unwrap_or_else(|_| Entities::empty());

            // Fail closed: any authorizer error denies the query rather than
            // letting it through.
            let decision = match self
                .authorizer
                .is_authorized(&request, &request_entities)
                .await
            {
                Ok(response) => neutral_decision(response.decision()),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Cedar authorization failed; denying (fail-closed)"
                    );
                    return Ok(Decision::Deny);
                }
            };
            if decision == Decision::Deny {
                return Ok(Decision::Deny);
            }
        }
        Ok(Decision::Allow)
    }

    #[cfg(feature = "governance")]
    async fn constrain(
        &self,
        table: &TableReference,
        _schema: &DFSchema,
        principal: &PrincipalIdentity,
        _eval: &EvalContext,
    ) -> Result<TablePolicy> {
        use cedar_oci::{EntityId, EntityUid};

        // Partial request: concrete principal + read_table action, but an
        // *unknown* resource of type `Table`. Policies that gate on
        // `resource.<attr>` come back as residuals over the row.
        let read_action = EntityUid::from_type_name_and_id(
            "Action".parse().unwrap(),
            EntityId::new("read_table"),
        );
        let table_type = EntityTypeName::from_str("Table")
            .map_err(|e| plan_datafusion_err!("invalid entity type name 'Table': {e}"))?;

        // Carry the table identity (catalog/schema/table) in the context so
        // row-filter policies can condition on `context.catalog/schema/table`,
        // matching the Layer-1 gate. The resource stays unknown so per-row
        // `resource.<col>` conditions come back as residuals. No columns are
        // listed (governance is per-table, not per-projection).
        let context = crate::visitor::table_context(table, &[])?;

        let request = RequestBuilder::default()
            .principal(crate::cedar_entity::parse_uid(&principal.uid)?)
            .action(read_action)
            .unknown_resource_with_type(table_type)
            .context(context)
            .build();

        let principal_entities = Entities::from_entities(principal_entities(principal)?, None)
            .unwrap_or_else(|_| Entities::empty());

        let response = match self
            .authorizer
            .is_authorized_partial(&request, &principal_entities)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Fail closed: if partial evaluation fails we cannot prove what
                // is safe, so deny all rows for this table.
                tracing::warn!(error = %e, table = %table, "partial authorization failed; masking all rows (fail-closed)");
                return Ok(TablePolicy {
                    row_filters: vec![lit(false)],
                    column_masks: Default::default(),
                });
            }
        };

        let translator = CedarResidualTranslator;
        let mut tp = TablePolicy::default();

        for residual in response.nontrivial_residuals() {
            // `Ok(Some(e))` -> predicate; `Ok(None)` -> trivially true (no
            // constraint); `Err` -> untranslatable, fail closed.
            let translated = translator.to_predicate(&residual);
            // A residual whose intent is unstated or unrecognized is an
            // undischarged condition we cannot enforce -> fail closed.
            match residual.annotation("filter_type") {
                Some("row_filter") => match translated {
                    Ok(Some(pred)) => tp.row_filters.push(pred),
                    Ok(None) => {} // trivially permitted; no filter needed
                    Err(e) => {
                        tracing::warn!(error = %e, table = %table, "untranslatable row filter; denying all rows (fail-closed)");
                        tp.row_filters.push(lit(false));
                    }
                },
                Some("deny_override") => match translated {
                    // Keep rows where the deny condition does NOT hold.
                    Ok(Some(pred)) => tp.row_filters.push(!pred),
                    Ok(None) => {} // deny condition trivially false; nothing denied
                    Err(e) => {
                        tracing::warn!(error = %e, table = %table, "untranslatable deny_override; denying all rows (fail-closed)");
                        tp.row_filters.push(lit(false));
                    }
                },
                Some("column_mask") => {
                    // A surviving residual means the mask's exemption condition
                    // is not fully discharged -> mask the column. A custom mask
                    // value may be supplied via `@mask_value`; default to "***".
                    if let Some(column) = residual.annotation("column") {
                        let mask = residual.annotation("mask_value").unwrap_or("***");
                        tp.column_masks.insert(column.to_string(), lit(mask));
                    } else {
                        // We cannot tell which column to mask, so we cannot
                        // prove the column is protected -> deny all rows.
                        tracing::warn!(table = %table, "column_mask residual without @column annotation; denying all rows (fail-closed; resolver should expand tags to concrete columns)");
                        tp.row_filters.push(lit(false));
                    }
                }
                other => {
                    // Missing (`None`) or unrecognized `filter_type`: the policy
                    // left a condition we cannot classify, so fail closed.
                    tracing::warn!(filter_type = ?other, table = %table, "missing or unknown filter_type annotation on surviving residual; denying all rows (fail-closed)");
                    tp.row_filters.push(lit(false));
                }
            }
        }

        Ok(tp)
    }

    #[cfg(feature = "governance")]
    async fn tool_policy(
        &self,
        action: &str,
        principal: &PrincipalIdentity,
        observed_taints: &std::collections::BTreeSet<String>,
    ) -> Result<Decision> {
        use cedar_oci::{EntityId, EntityUid};

        // A full request: principal + the tool `action` + a tool resource named
        // after the action, with the session's observed taints in the context.
        let action_uid =
            EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new(action));
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Tool")
                .map_err(|e| plan_datafusion_err!("invalid entity type name 'Tool': {e}"))?,
            EntityId::new(action),
        );
        let context = crate::visitor::tool_context(observed_taints)?;
        let request = Request::new(
            crate::cedar_entity::parse_uid(&principal.uid)?,
            action_uid,
            resource,
            context,
            None,
        )
        .map_err(|e| plan_datafusion_err!("Failed to create tool request: {e}"))?;

        let principal_entities = Entities::from_entities(principal_entities(principal)?, None)
            .unwrap_or_else(|_| Entities::empty());

        // Fail closed: an authorizer error denies the tool call.
        match self
            .authorizer
            .is_authorized(&request, &principal_entities)
            .await
        {
            Ok(response) => Ok(neutral_decision(response.decision())),
            Err(e) => {
                tracing::warn!(error = %e, action, "tool authorization failed; denying (fail-closed)");
                Ok(Decision::Deny)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;
    use std::sync::Arc;

    use async_trait::async_trait;
    use cedar_local_agent::public::{
        EntityProviderError, PolicySetProviderError, SimpleEntityProvider, SimplePolicySetProvider,
    };
    use cedar_policy::{Entities, PolicySet, Request};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::logical_expr::logical_plan::builder::table_scan;

    use super::*;
    use crate::principal::PrincipalIdentity;

    /// In-memory provider holding a fixed policy set + entities, for tests.
    #[derive(Debug)]
    struct InMemory {
        policies: Arc<PolicySet>,
    }

    impl InMemory {
        fn new(src: &str) -> Self {
            Self {
                policies: Arc::new(PolicySet::from_str(src).expect("valid policy set")),
            }
        }
    }

    #[async_trait]
    impl SimplePolicySetProvider for InMemory {
        async fn get_policy_set(
            &self,
            _: &Request,
        ) -> Result<Arc<PolicySet>, PolicySetProviderError> {
            Ok(self.policies.clone())
        }
    }

    #[async_trait]
    impl SimpleEntityProvider for InMemory {
        async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
            Ok(Arc::new(Entities::empty()))
        }
    }

    /// A policy-set provider that always errors, to exercise fail-closed.
    #[derive(Debug)]
    struct ErrProvider;

    #[async_trait]
    impl SimplePolicySetProvider for ErrProvider {
        async fn get_policy_set(
            &self,
            _: &Request,
        ) -> Result<Arc<PolicySet>, PolicySetProviderError> {
            Err(PolicySetProviderError::General("boom".into()))
        }
    }

    #[async_trait]
    impl SimpleEntityProvider for ErrProvider {
        async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
            Ok(Arc::new(Entities::empty()))
        }
    }

    fn policy<P, E>(p: P, e: E) -> CedarPolicy<P, E>
    where
        P: SimplePolicySetProvider + 'static,
        E: SimpleEntityProvider + 'static,
    {
        let config = AuthorizerConfigBuilder::default()
            .policy_set_provider(Arc::new(p))
            .entity_provider(Arc::new(e))
            .build()
            .unwrap();
        CedarPolicy::new(Authorizer::new(config))
    }

    fn alice() -> PrincipalIdentity {
        PrincipalIdentity::new("User::\"alice\"").with_attribute("region", "eu")
    }

    fn scan_plan() -> LogicalPlan {
        let schema = Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, true),
        ]);
        table_scan(Some("t"), &schema, None)
            .unwrap()
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn is_allowed_permits_matching_principal() {
        let pol = policy(
            InMemory::new(
                r#"permit(principal == User::"alice", action == Action::"read_table", resource);"#,
            ),
            InMemory::new(""),
        );
        let decision = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn is_allowed_denies_non_matching_principal() {
        // Policy only permits bob; alice is denied by default-deny.
        let pol = policy(
            InMemory::new(
                r#"permit(principal == User::"bob", action == Action::"read_table", resource);"#,
            ),
            InMemory::new(""),
        );
        let decision = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Deny);
    }

    #[tokio::test]
    async fn is_allowed_fails_closed_on_provider_error() {
        let pol = policy(ErrProvider, ErrProvider);
        let decision = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Deny);
    }

    // --- Resource entity folding (PR3): catalog facts gathered at resolution
    // are folded into the request-time `Table` resource entity, so a policy can
    // gate on `resource.<attr>` with no static-bundle entity for the table. ---

    /// An `EvalContext` whose sink records `facts` for the bare table `t` that
    /// `scan_plan()` reads.
    fn eval_with_table_facts(facts: crate::TableFacts) -> EvalContext {
        let sink = crate::CatalogFactSink::new();
        sink.record(TableReference::bare("t"), facts);
        EvalContext {
            catalog_facts: sink,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn is_allowed_resolves_resource_tags_from_folded_facts() {
        // The policy permits only when the table carries the `pii` tag — an
        // attribute that exists *only* in the gathered catalog facts (the entity
        // provider is empty, so without folding there is no `resource.tags`).
        let pol = policy(
            InMemory::new(
                r#"permit(principal, action == Action::"read_table", resource)
                   when { resource.tags.contains("pii") };"#,
            ),
            InMemory::new(""),
        );

        let facts = crate::TableFacts {
            tags: ["pii".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let allow = pol
            .is_allowed(&scan_plan(), &alice(), &eval_with_table_facts(facts))
            .await
            .unwrap();
        assert_eq!(allow, Decision::Allow, "pii-tagged table is permitted");

        // Without the fact (empty EvalContext) the attribute does not resolve,
        // so the `when` guard is unsatisfied and default-deny applies.
        let deny = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(deny, Decision::Deny, "untagged table falls to default-deny");
    }

    #[tokio::test]
    async fn is_allowed_resolves_resource_readers_from_folded_facts() {
        // Membership-style gate keyed on `resource.readers` carried by the facts.
        let pol = policy(
            InMemory::new(
                r#"permit(principal, action == Action::"read_table", resource)
                   when { resource.readers.contains("User::\"alice\"") };"#,
            ),
            InMemory::new(""),
        );
        let facts = crate::TableFacts {
            readers: ["User::\"alice\"".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let allow = pol
            .is_allowed(&scan_plan(), &alice(), &eval_with_table_facts(facts))
            .await
            .unwrap();
        assert_eq!(allow, Decision::Allow);
    }

    // --- Principal/identity PIP (PR4): group membership resolved dynamically
    // and folded via `to_entities()`, so a membership-gated permit fires with an
    // EMPTY static entity bundle — proving the bundle is no longer load-bearing
    // for membership. ---

    #[tokio::test]
    async fn is_allowed_resolves_group_membership_with_empty_bundle() {
        use crate::principal::Group;
        // The entity provider vends NO entities; alice's `readers` membership
        // exists only in the enrichment closure (alice ∈ privileged_readers ⊂
        // readers), supplied request-time via the neutral group hierarchy that
        // the adapter rebuilds into Cedar entities.
        let pol = policy(
            InMemory::new(
                r#"permit(principal in UserGroup::"readers", action == Action::"read_table", resource);"#,
            ),
            InMemory::new(""),
        );

        let enriched = alice().enriched(crate::PrincipalEnrichment {
            groups: vec!["UserGroup::\"privileged_readers\"".into()],
            group_hierarchy: vec![
                Group {
                    uid: "UserGroup::\"privileged_readers\"".into(),
                    parents: vec!["UserGroup::\"readers\"".into()],
                },
                Group {
                    uid: "UserGroup::\"readers\"".into(),
                    parents: vec![],
                },
            ],
            ..Default::default()
        });

        let allow = pol
            .is_allowed(&scan_plan(), &enriched, &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(
            allow,
            Decision::Allow,
            "membership resolves from the enrichment closure, not the bundle"
        );

        // Without enrichment the same principal is not in `readers`, so
        // default-deny applies — the membership came from the closure, nothing else.
        let deny = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(deny, Decision::Deny, "no membership without enrichment");
    }

    // A demo policy's Layer-1 gate: a principal with a `region` attribute is
    // permitted to read; one without is denied the whole query.
    const DEMO_POLICY: &str = include_str!("../tests/fixtures/demo.cedar");

    #[tokio::test]
    async fn demo_policy_gate_allows_principal_with_region() {
        let pol = policy(InMemory::new(DEMO_POLICY), InMemory::new(""));
        // alice() carries region=eu.
        let decision = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn demo_policy_gate_denies_principal_without_region() {
        let pol = policy(InMemory::new(DEMO_POLICY), InMemory::new(""));
        let carol = PrincipalIdentity::new("User::\"carol\"");
        let decision = pol
            .is_allowed(&scan_plan(), &carol, &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Deny);
    }

    /// Minimal extension node named after a Unity Catalog DDL command, used to
    /// build a UC-DDL logical plan without depending on the UC crate.
    #[derive(Debug, PartialEq, Eq, Hash, PartialOrd)]
    struct FakeDdlNode;

    impl datafusion::logical_expr::UserDefinedLogicalNodeCore for FakeDdlNode {
        fn name(&self) -> &str {
            "CreateCatalog"
        }
        fn inputs(&self) -> Vec<&LogicalPlan> {
            vec![]
        }
        fn schema(&self) -> &datafusion::common::DFSchemaRef {
            use std::sync::LazyLock;
            static EMPTY: LazyLock<datafusion::common::DFSchemaRef> =
                LazyLock::new(|| Arc::new(datafusion::common::DFSchema::empty()));
            &EMPTY
        }
        fn expressions(&self) -> Vec<datafusion::logical_expr::Expr> {
            vec![]
        }
        fn fmt_for_explain(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "CreateCatalog: name=demo")
        }
        fn with_exprs_and_inputs(
            &self,
            _exprs: Vec<datafusion::logical_expr::Expr>,
            _inputs: Vec<LogicalPlan>,
        ) -> Result<Self> {
            Ok(Self)
        }
    }

    fn create_catalog_plan() -> LogicalPlan {
        use datafusion::logical_expr::Extension;
        LogicalPlan::Extension(Extension {
            node: Arc::new(FakeDdlNode),
        })
    }

    #[tokio::test]
    async fn uc_ddl_denied_without_permit() {
        // No policy grants create_catalog -> Cedar default-deny (fail-closed).
        let pol = policy(
            InMemory::new(r#"permit(principal, action == Action::"read_table", resource);"#),
            InMemory::new(""),
        );
        let decision = pol
            .is_allowed(&create_catalog_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Deny);
    }

    #[tokio::test]
    async fn uc_ddl_allowed_with_permit() {
        let pol = policy(
            InMemory::new(
                r#"permit(principal == User::"alice", action == Action::"create_catalog", resource);"#,
            ),
            InMemory::new(""),
        );
        let decision = pol
            .is_allowed(&create_catalog_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Allow);
    }

    #[cfg(feature = "governance")]
    mod governance {
        use super::*;
        use datafusion::common::DFSchema;
        use datafusion::logical_expr::{col, lit};
        use datafusion::sql::TableReference;

        fn table() -> TableReference {
            TableReference::bare("t")
        }

        fn empty_schema() -> DFSchema {
            DFSchema::empty()
        }

        const GUARDRAIL: &str = r#"
            @id("no_external_send_with_pii")
            forbid (principal, action == Action::"send_external", resource)
            when { context.observed_taints.contains("pii") };
            permit (principal, action == Action::"send_external", resource);
        "#;

        #[tokio::test]
        async fn tool_policy_forbids_send_external_on_pii() {
            use std::collections::BTreeSet;
            let pol = policy(InMemory::new(GUARDRAIL), InMemory::new(""));

            // With "pii" observed, the forbid overrides the permit → Deny.
            let tainted: BTreeSet<String> = ["pii".to_string()].into_iter().collect();
            assert_eq!(
                pol.tool_policy("send_external", &alice(), &tainted)
                    .await
                    .unwrap(),
                Decision::Deny
            );

            // A clean session is permitted — the decision tracks the accrued
            // fact, not a hardcoded outcome.
            assert_eq!(
                pol.tool_policy("send_external", &alice(), &BTreeSet::new())
                    .await
                    .unwrap(),
                Decision::Allow
            );
        }

        #[tokio::test]
        async fn row_filter_residual_becomes_predicate() {
            // The exemption is `resource.region == principal.region`; with a
            // concrete principal (region=eu) and unknown resource, the residual
            // is `resource.region == "eu"` -> col("region") == "eu".
            let pol = policy(
                InMemory::new(
                    r#"@filter_type("row_filter")
                       permit(principal, action == Action::"read_table", resource)
                       when { resource.region == principal.region };"#,
                ),
                InMemory::new(""),
            );
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            assert_eq!(tp.row_filters, vec![col("region").eq(lit("eu"))]);
            assert!(tp.column_masks.is_empty());
        }

        #[tokio::test]
        async fn column_mask_with_column_masks_it() {
            let pol = policy(
                InMemory::new(
                    r#"@filter_type("column_mask")
                       @column("ssn")
                       permit(principal, action == Action::"read_table", resource)
                       when { resource.region == principal.region };"#,
                ),
                InMemory::new(""),
            );
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            assert_eq!(tp.column_masks.get("ssn"), Some(&lit("***")));
        }

        #[tokio::test]
        async fn column_mask_honors_mask_value() {
            let pol = policy(
                InMemory::new(
                    r#"@filter_type("column_mask")
                       @column("ssn")
                       @mask_value("REDACTED")
                       permit(principal, action == Action::"read_table", resource)
                       when { resource.region == principal.region };"#,
                ),
                InMemory::new(""),
            );
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            assert_eq!(tp.column_masks.get("ssn"), Some(&lit("REDACTED")));
        }

        #[tokio::test]
        async fn column_mask_without_column_denies_all_rows() {
            // A surviving column_mask residual with no @column cannot be applied,
            // so fail closed (deny all rows), not silently ignored.
            let pol = policy(
                InMemory::new(
                    r#"@filter_type("column_mask")
                       permit(principal, action == Action::"read_table", resource)
                       when { resource.region == principal.region };"#,
                ),
                InMemory::new(""),
            );
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            assert_eq!(tp.row_filters, vec![lit(false)]);
            assert!(tp.column_masks.is_empty());
        }

        #[tokio::test]
        async fn unknown_filter_type_denies_all_rows() {
            let pol = policy(
                InMemory::new(
                    r#"@filter_type("bogus")
                       permit(principal, action == Action::"read_table", resource)
                       when { resource.region == principal.region };"#,
                ),
                InMemory::new(""),
            );
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            assert_eq!(tp.row_filters, vec![lit(false)]);
        }

        #[tokio::test]
        async fn missing_filter_type_denies_all_rows() {
            // No @filter_type annotation on a surviving residual -> fail closed.
            let pol = policy(
                InMemory::new(
                    r#"permit(principal, action == Action::"read_table", resource)
                       when { resource.region == principal.region };"#,
                ),
                InMemory::new(""),
            );
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            assert_eq!(tp.row_filters, vec![lit(false)]);
        }

        // ---- Regression tests for the shipped demo policy --------------------
        // `config/policies/demo.cedar` backs `notebooks/policy_demo.py`. These
        // assert the policy still produces the governance the notebook narrates,
        // so the demo can't silently rot. (`DEMO_POLICY` comes from `super`.)

        fn bob() -> PrincipalIdentity {
            PrincipalIdentity::new("User::\"bob\"").with_attribute("region", "us")
        }

        #[tokio::test]
        async fn demo_policy_alice_eu_sees_eu_rows_ssn_masked() {
            let pol = policy(InMemory::new(DEMO_POLICY), InMemory::new(""));
            let tp = pol
                .constrain(&table(), &empty_schema(), &alice(), &EvalContext::default())
                .await
                .unwrap();
            // Row filter restricts to the principal's region (eu).
            assert_eq!(tp.row_filters, vec![col("region").eq(lit("eu"))]);
            // The column mask is over the unknown resource, so it always survives:
            // ssn is masked for every caller of the table.
            assert_eq!(tp.column_masks.get("ssn"), Some(&lit("***")));
        }

        #[tokio::test]
        async fn demo_policy_bob_us_sees_us_rows_ssn_masked() {
            let pol = policy(InMemory::new(DEMO_POLICY), InMemory::new(""));
            let tp = pol
                .constrain(&table(), &empty_schema(), &bob(), &EvalContext::default())
                .await
                .unwrap();
            // Row filter restricts to the principal's region (us) — the
            // per-principal axis differs from alice purely via the folded literal.
            assert_eq!(tp.row_filters, vec![col("region").eq(lit("us"))]);
            assert_eq!(tp.column_masks.get("ssn"), Some(&lit("***")));
        }
    }
}
