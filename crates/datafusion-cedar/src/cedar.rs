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

use datafusion_policy::{Decision, EvalContext, PolicyEngine, PrincipalIdentity, TableFacts};

use crate::cedar_entity::principal_entities;
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

#[cfg(feature = "fgac")]
use {
    crate::cedar_entity::parse_uid,
    crate::translate::CedarResidualTranslator,
    cedar_policy::{
        Context, EntityTypeName, PartialEntities, PartialEntity, PartialEntityUid, PartialRequest,
        Policy, Request, Schema,
    },
    datafusion::common::DFSchema,
    datafusion::logical_expr::{Expr, ScalarUDF, col, lit},
    datafusion_policy::{ConstraintTranslator, TablePolicy},
    smol_str::SmolStr,
    std::collections::BTreeMap,
    std::str::FromStr as _,
};

/// A [`PolicyEngine`] backed by a Cedar [`Authorizer`].
///
/// Generic over any policy-set and entity provider (e.g. `cedar-oci`'s
/// [`OciPolicyProvider`]), so the policy source is pluggable. The policy-set
/// provider and the (optional) Cedar [`Schema`] are retained alongside the
/// authorizer so the fine-grained governance path can run type-aware partial
/// evaluation (`PolicySet::tpe`), which needs the raw policy set and schema.
#[derive(Debug)]
pub struct CedarPolicyEngine<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    authorizer: Authorizer<P, E>,
    /// The policy-set provider, shared with the authorizer, used to fetch the
    /// `PolicySet` for TPE. Only read by the `fgac` governance path.
    #[cfg_attr(not(feature = "fgac"), allow(dead_code))]
    policy_provider: Arc<P>,
    /// The Cedar schema TPE validates residuals against. `None` disables the
    /// fine-grained (row-filter/column-mask) path — `constrain` then fails
    /// closed, since TPE cannot run without a schema. Only read by `fgac`.
    #[cfg_attr(not(feature = "fgac"), allow(dead_code))]
    schema: Option<Arc<cedar_policy::Schema>>,
}

impl<P, E> CedarPolicyEngine<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    /// Build from an already-configured authorizer, the shared policy-set
    /// provider, and an optional schema.
    fn new(
        authorizer: Authorizer<P, E>,
        policy_provider: Arc<P>,
        schema: Option<Arc<cedar_policy::Schema>>,
    ) -> Self {
        Self {
            authorizer,
            policy_provider,
            schema,
        }
    }
}

impl CedarPolicyEngine<OciPolicyProvider, OciPolicyProvider> {
    /// Build a Cedar policy that sources its policy set, schema, and entities
    /// from an OCI registry reference (e.g.
    /// `localhost:10100/hydrofoil/plan-policy:latest`).
    ///
    /// The same provider backs both the policy-set and entity providers; the
    /// schema pulled with the image (if any) is retained for TPE-based governance.
    pub async fn from_oci(reference: &str) -> Result<Self> {
        let provider = Arc::new(OciPolicyProvider::from_reference(reference).await.map_err(
            |e| {
                plan_datafusion_err!(
                    "Failed to load Cedar policy from OCI reference '{reference}': {e}"
                )
            },
        )?);
        let schema = provider.schema().await;
        let config = AuthorizerConfigBuilder::default()
            .policy_set_provider(provider.clone())
            .entity_provider(provider.clone())
            .build()
            .map_err(|e| plan_datafusion_err!("Failed to build Cedar authorizer: {e}"))?;
        Ok(Self::new(Authorizer::new(config), provider, schema))
    }
}

#[async_trait::async_trait]
impl<P, E> PolicyEngine for CedarPolicyEngine<P, E>
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

    #[cfg(feature = "fgac")]
    async fn constrain(
        &self,
        table: &TableReference,
        schema: &DFSchema,
        principal: &PrincipalIdentity,
        eval: &EvalContext,
    ) -> Result<TablePolicy> {
        // TPE needs a schema; without one we cannot prove any row/column safe.
        let Some(cedar_schema) = self.schema.as_deref() else {
            tracing::warn!(table = %table, "no Cedar schema available for TPE; masking all rows (fail-closed)");
            return Ok(deny_all_rows());
        };

        let policy_set = self
            .policy_provider
            .get_policy_set(&placeholder_request(&principal.uid)?)
            .await
            .map_err(|e| plan_datafusion_err!("failed to fetch policy set for TPE: {e}"))?;

        let facts = eval.catalog_facts.get(table);
        let mut tp = TablePolicy::default();

        // ---- Row filters: read_table over an unknown Table -----------------
        // A surviving *permit* residual over `resource.<col>` is a row filter; a
        // surviving *forbid* at table grain denies all rows.
        match self.table_residuals(&policy_set, cedar_schema, table, principal, facts.as_ref()) {
            Ok((permits, forbids)) => {
                if !forbids.is_empty() {
                    // An undischarged table-level forbid: deny all rows.
                    return Ok(deny_all_rows());
                }
                let translator = CedarResidualTranslator;
                for residual in permits {
                    match translator.to_predicate(&residual) {
                        Ok(Some(pred)) => tp.row_filters.push(pred),
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, table = %table, "untranslatable row-filter residual; denying all rows (fail-closed)");
                            tp.row_filters.push(lit(false));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, table = %table, "row-filter TPE failed; denying all rows (fail-closed)");
                tp.row_filters.push(lit(false));
            }
        }

        // ---- Column masks: read_column per tagged candidate column ----------
        // Only columns carrying governed tags can be masked; a surviving *forbid*
        // residual for a column means it is protected for this principal.
        let candidates = mask_candidate_columns(schema, facts.as_ref());
        for column in candidates {
            match self.column_is_masked(
                &policy_set,
                cedar_schema,
                table,
                &column,
                principal,
                facts.as_ref(),
            ) {
                Ok(Some(mask_policy)) => {
                    let mask = self
                        .resolve_mask_expr(&mask_policy, &column, eval)
                        .await
                        .unwrap_or_else(|e| {
                            tracing::warn!(error = %e, table = %table, column = %column, "mask function unresolved; using default mask (fail-closed)");
                            lit(DEFAULT_MASK)
                        });
                    tp.column_masks.insert(column, mask);
                }
                Ok(None) => {} // column is readable for this principal
                Err(e) => {
                    tracing::warn!(error = %e, table = %table, column = %column, "column-mask TPE failed; masking column (fail-closed)");
                    tp.column_masks.insert(column, lit(DEFAULT_MASK));
                }
            }
        }

        Ok(tp)
    }

    #[cfg(feature = "fgac")]
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

// ---------------------------------------------------------------------------
// Fine-grained governance helpers (TPE + three-level function resolution).
// ---------------------------------------------------------------------------

/// The default column-mask replacement when no catalog function is named
/// (resolution level 3).
#[cfg(feature = "fgac")]
const DEFAULT_MASK: &str = "***";

/// A `TablePolicy` that hides every row — the fail-closed governance outcome.
#[cfg(feature = "fgac")]
fn deny_all_rows() -> TablePolicy {
    TablePolicy {
        row_filters: vec![lit(false)],
        column_masks: Default::default(),
    }
}

/// Build a concrete request used only to fetch the policy set from the provider
/// (the provider ignores the request contents in practice, but the trait needs
/// one). Uses the principal uid, a `read_table` action, and a placeholder table.
#[cfg(feature = "fgac")]
fn placeholder_request(principal_uid: &str) -> Result<Request> {
    use cedar_oci::{EntityId, EntityUid};
    let action =
        EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new("read_table"));
    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Table")
            .map_err(|e| plan_datafusion_err!("invalid entity type name 'Table': {e}"))?,
        EntityId::new("_"),
    );
    Request::new(
        parse_uid(principal_uid)?,
        action,
        resource,
        Context::empty(),
        None,
    )
    .map_err(|e| plan_datafusion_err!("failed to build policy-fetch request: {e}"))
}

/// The columns eligible for masking: those the plan reads that carry governed
/// tags (only tagged columns can be governed by a `read_column` policy).
#[cfg(feature = "fgac")]
fn mask_candidate_columns(schema: &DFSchema, facts: Option<&TableFacts>) -> Vec<String> {
    let Some(facts) = facts else {
        return Vec::new();
    };
    schema
        .fields()
        .iter()
        .map(|f| f.name().to_string())
        .filter(|name| {
            facts
                .governed_column_tags
                .get(name)
                .is_some_and(|t| !t.is_empty())
        })
        .collect()
}

/// Lower governed key→value tags to the Cedar native-tags map for a
/// [`PartialEntity`].
#[cfg(feature = "fgac")]
fn native_tags(
    tags: &BTreeMap<String, String>,
) -> BTreeMap<SmolStr, cedar_policy::RestrictedExpression> {
    tags.iter()
        .map(|(k, v)| {
            (
                SmolStr::from(k.as_str()),
                cedar_policy::RestrictedExpression::new_string(v.clone()),
            )
        })
        .collect()
}

#[cfg(feature = "fgac")]
impl<P, E> CedarPolicyEngine<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    /// Build the concrete principal [`PartialEntity`] (attributes known) for TPE.
    fn principal_partial_entity(
        &self,
        principal: &PrincipalIdentity,
        schema: &Schema,
    ) -> Result<PartialEntity> {
        let uid = parse_uid(&principal.uid)?;
        let attrs: BTreeMap<SmolStr, cedar_policy::RestrictedExpression> = principal
            .attributes
            .iter()
            .map(|(k, v)| (SmolStr::from(k.as_str()), attr_to_restricted(v)))
            .collect();
        PartialEntity::new(uid, Some(attrs), Some(Default::default()), None, schema)
            .map_err(|e| plan_datafusion_err!("failed to build principal partial entity: {e}"))
    }

    /// Run TPE for a `read_table` request over an *unknown* `Table` resource and
    /// return the surviving (permit, forbid) residual policies.
    fn table_residuals(
        &self,
        policy_set: &cedar_policy::PolicySet,
        schema: &Schema,
        table: &TableReference,
        principal: &PrincipalIdentity,
        _facts: Option<&TableFacts>,
    ) -> Result<(Vec<Policy>, Vec<Policy>)> {
        use cedar_oci::{EntityId, EntityUid};
        let action = EntityUid::from_type_name_and_id(
            "Action".parse().unwrap(),
            EntityId::new("read_table"),
        );
        let principal_uid = PartialEntityUid::from_concrete(parse_uid(&principal.uid)?);
        let table_type = EntityTypeName::from_str("Table")
            .map_err(|e| plan_datafusion_err!("invalid entity type name 'Table': {e}"))?;
        let resource_uid = PartialEntityUid::new(table_type, None);
        let context = crate::visitor::table_context(table, &[])?;

        let request =
            PartialRequest::new(principal_uid, action, resource_uid, Some(context), schema)
                .map_err(|e| plan_datafusion_err!("failed to build partial request: {e}"))?;
        let entities = PartialEntities::from_partial_entities(
            [self.principal_partial_entity(principal, schema)?],
            schema,
        )
        .map_err(|e| plan_datafusion_err!("failed to build partial entities: {e}"))?;

        let response = policy_set
            .tpe(&request, &entities, schema)
            .map_err(|e| plan_datafusion_err!("TPE failed: {e}"))?;

        let mut permits = Vec::new();
        let mut forbids = Vec::new();
        for policy in response.nontrivial_residual_policies() {
            match policy.effect() {
                cedar_policy::Effect::Permit => permits.push(policy),
                cedar_policy::Effect::Forbid => forbids.push(policy),
            }
        }
        Ok((permits, forbids))
    }

    /// Determine whether `column` is masked for this principal. Returns the
    /// forbid policy that masks it (for function resolution) or `None` if the
    /// column is readable.
    ///
    /// The column is supplied as a *concrete* `Column` partial entity carrying
    /// its native tags, so a `read_column` forbid fully resolves. We test each
    /// `read_column` forbid policy in isolation so we can attribute the mask to a
    /// specific policy (and read its `@mask_fn`).
    fn column_is_masked(
        &self,
        policy_set: &cedar_policy::PolicySet,
        schema: &Schema,
        table: &TableReference,
        column: &str,
        principal: &PrincipalIdentity,
        facts: Option<&TableFacts>,
    ) -> Result<Option<Policy>> {
        use cedar_oci::{EntityId, EntityUid};
        let action = EntityUid::from_type_name_and_id(
            "Action".parse().unwrap(),
            EntityId::new("read_column"),
        );
        let column_type = EntityTypeName::from_str("Column")
            .map_err(|e| plan_datafusion_err!("invalid entity type name 'Column': {e}"))?;
        let column_uid = EntityUid::from_type_name_and_id(
            column_type.clone(),
            EntityId::new(format!("{table}.{column}")),
        );

        // The Column partial entity: name attr + native governed tags.
        let tags = facts
            .and_then(|f| f.governed_column_tags.get(column))
            .cloned()
            .unwrap_or_default();
        let mut attrs: BTreeMap<SmolStr, cedar_policy::RestrictedExpression> = BTreeMap::new();
        attrs.insert(
            "name".into(),
            cedar_policy::RestrictedExpression::new_string(column.to_string()),
        );
        let column_entity = PartialEntity::new(
            column_uid.clone(),
            Some(attrs),
            Some(Default::default()),
            Some(native_tags(&tags)),
            schema,
        )
        .map_err(|e| plan_datafusion_err!("failed to build column partial entity: {e}"))?;

        let principal_uid = PartialEntityUid::from_concrete(parse_uid(&principal.uid)?);
        let context = crate::visitor::table_context(table, &[])?;

        // Test each read_column forbid policy alone, paired with a blanket permit
        // so the decision reflects *only whether that forbid fires* (a forbid-only
        // set is default-deny regardless). The forbid that fires masks the column.
        let blanket_permit = cedar_policy::Policy::from_str(
            r#"permit(principal, action == Action::"read_column", resource);"#,
        )
        .map_err(|e| plan_datafusion_err!("failed to build blanket permit: {e}"))?;

        for policy in policy_set.policies() {
            if policy.effect() != cedar_policy::Effect::Forbid {
                continue;
            }
            let probe = cedar_policy::PolicySet::from_policies([
                policy.new_id("probe_forbid".parse().unwrap()),
                blanket_permit.new_id("probe_permit".parse().unwrap()),
            ])
            .map_err(|e| plan_datafusion_err!("failed to build probe policy set: {e}"))?;
            let request = PartialRequest::new(
                principal_uid.clone(),
                action.clone(),
                PartialEntityUid::from_concrete(column_uid.clone()),
                Some(context.clone()),
                schema,
            )
            .map_err(|e| plan_datafusion_err!("failed to build column partial request: {e}"))?;
            let entities = PartialEntities::from_partial_entities(
                [
                    self.principal_partial_entity(principal, schema)?,
                    column_entity.clone(),
                ],
                schema,
            )
            .map_err(|e| plan_datafusion_err!("failed to build column partial entities: {e}"))?;

            let response = probe
                .tpe(&request, &entities, schema)
                .map_err(|e| plan_datafusion_err!("column TPE failed: {e}"))?;
            // Deny => this forbid fired (overrides the blanket permit) => mask.
            if response.decision() == Some(cedar_policy::Decision::Deny) {
                return Ok(Some(policy.clone()));
            }
        }
        Ok(None)
    }

    /// Resolve the masking expression for a column using three-level resolution:
    /// (1) the policy's `@mask_fn`; (2) the matched `Tag`'s `default_mask_fn`;
    /// (3) the generated default literal.
    async fn resolve_mask_expr(
        &self,
        mask_policy: &Policy,
        column: &str,
        eval: &EvalContext,
    ) -> Result<Expr> {
        // Level 1: a function named on the policy.
        if let Some(name) = mask_policy.annotation("mask_fn") {
            return self.call_fn(name, column, mask_policy, eval).await;
        }
        // Level 2: a default function on a matched Tag entity, resolved from the
        // provider's entity bundle. (The Tag whose key the policy matches carries
        // `default_mask_fn`.) We look it up via the schema-less entity provider.
        if let Some(name) = self.tag_default_mask_fn(mask_policy).await {
            return self.call_fn(&name, column, mask_policy, eval).await;
        }
        // Level 3: generated default literal.
        Ok(lit(DEFAULT_MASK))
    }

    /// Best-effort read of a `default_mask_fn` from a `Tag` entity referenced by
    /// the policy. Returns `None` if no tag default is available (caller falls
    /// back to the generated default). Currently a placeholder hook: hosts wire
    /// `Tag` metadata through the entity provider; absent that, level 2 is a
    /// no-op and resolution falls through to level 3.
    async fn tag_default_mask_fn(&self, _mask_policy: &Policy) -> Option<String> {
        None
    }

    /// Build a `ScalarUDF` call over the masked column (arg 0) plus any
    /// `@using_columns` extra args, resolving the function name via the eval
    /// context's [`CatalogFunctionResolver`](datafusion_policy::CatalogFunctionResolver).
    async fn call_fn(
        &self,
        name: &str,
        column: &str,
        mask_policy: &Policy,
        eval: &EvalContext,
    ) -> Result<Expr> {
        let resolver = eval.function_resolver.as_ref().ok_or_else(|| {
            plan_datafusion_err!(
                "policy names function '{name}' but no CatalogFunctionResolver is wired"
            )
        })?;
        let udf: Arc<ScalarUDF> = resolver.resolve(name).await?;

        let mut args: Vec<Expr> = vec![col(column)];
        if let Some(using) = mask_policy.annotation("using_columns") {
            for extra in using.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                // A `@using_columns` entry is another column reference; a bare
                // numeric/literal is passed as a literal argument.
                if let Ok(n) = extra.parse::<i64>() {
                    args.push(lit(n));
                } else {
                    args.push(col(extra));
                }
            }
        }
        Ok(udf.call(args))
    }
}

/// Lower a neutral attribute value to a Cedar restricted expression (for the
/// principal partial entity).
#[cfg(feature = "fgac")]
fn attr_to_restricted(v: &datafusion_policy::AttrValue) -> cedar_policy::RestrictedExpression {
    use cedar_policy::RestrictedExpression as R;
    use datafusion_policy::AttrValue;
    match v {
        AttrValue::String(s) => R::new_string(s.clone()),
        AttrValue::Long(n) => R::new_long(*n),
        AttrValue::Bool(b) => R::new_bool(*b),
        AttrValue::Set(items) => R::new_set(items.iter().map(attr_to_restricted)),
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
    use datafusion_policy::PrincipalIdentity;

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

    fn policy<P, E>(p: P, e: E) -> CedarPolicyEngine<P, E>
    where
        P: SimplePolicySetProvider + 'static,
        E: SimpleEntityProvider + 'static,
    {
        policy_with_schema(p, e, None)
    }

    /// Build an engine from a policy-set provider, entity provider, and optional
    /// schema (the schema is required for the fine-grained TPE governance path).
    fn policy_with_schema<P, E>(
        p: P,
        e: E,
        schema: Option<Arc<cedar_policy::Schema>>,
    ) -> CedarPolicyEngine<P, E>
    where
        P: SimplePolicySetProvider + 'static,
        E: SimpleEntityProvider + 'static,
    {
        let provider = Arc::new(p);
        let config = AuthorizerConfigBuilder::default()
            .policy_set_provider(provider.clone())
            .entity_provider(Arc::new(e))
            .build()
            .unwrap();
        CedarPolicyEngine::new(Authorizer::new(config), provider, schema)
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
    fn eval_with_table_facts(facts: datafusion_policy::TableFacts) -> EvalContext {
        let sink = datafusion_policy::CatalogFactSink::new();
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

        let facts = datafusion_policy::TableFacts {
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
        let facts = datafusion_policy::TableFacts {
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
        use datafusion_policy::Group;
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

        let enriched = alice().enriched(datafusion_policy::PrincipalEnrichment {
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

    // The committed showcase policy's Layer-1 gate: a principal with a `region`
    // attribute is permitted to read; one without is denied the whole query.
    const LAKEHOUSE_POLICY: &str = include_str!("../../../config/policies/lakehouse.cedar");

    #[tokio::test]
    async fn lakehouse_gate_allows_principal_with_region() {
        let pol = policy(InMemory::new(LAKEHOUSE_POLICY), InMemory::new(""));
        // alice() carries region=eu.
        let decision = pol
            .is_allowed(&scan_plan(), &alice(), &EvalContext::default())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn lakehouse_gate_denies_principal_without_region() {
        let pol = policy(InMemory::new(LAKEHOUSE_POLICY), InMemory::new(""));
        let anon = PrincipalIdentity::new("User::\"anon\"");
        let decision = pol
            .is_allowed(&scan_plan(), &anon, &EvalContext::default())
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

    #[cfg(feature = "fgac")]
    mod governance {
        use std::collections::BTreeMap;

        use async_trait::async_trait;
        use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
        use datafusion::common::DFSchema;
        use datafusion::logical_expr::{
            ColumnarValue, ScalarUDF, ScalarUDFImpl, Signature, Volatility, col, lit,
        };
        use datafusion::sql::TableReference;

        use datafusion_policy::{CatalogFactSink, CatalogFunctionResolver, TableFacts};

        use super::*;

        /// The checked-in typed schema backs these tests, so the showcase can't
        /// silently rot. (`LAKEHOUSE_POLICY` comes from the parent `tests` module.)
        const LAKEHOUSE_SCHEMA: &str =
            include_str!("../../../config/policies/lakehouse.cedarschema");

        fn table() -> TableReference {
            TableReference::full("prod", "customers", "accounts")
        }

        /// The plan's schema: the columns a query over the table reads.
        fn df_schema() -> DFSchema {
            let arrow = ArrowSchema::new(vec![
                Field::new("region", DataType::Utf8, true),
                Field::new("ssn", DataType::Utf8, true),
                Field::new("salary", DataType::Int64, true),
            ]);
            DFSchema::try_from(arrow).unwrap()
        }

        fn cedar_schema() -> Arc<cedar_policy::Schema> {
            let (schema, _warnings) =
                cedar_policy::Schema::from_cedarschema_str(LAKEHOUSE_SCHEMA).expect("valid schema");
            Arc::new(schema)
        }

        /// Build an engine over the checked-in showcase policy + schema.
        fn lakehouse_engine() -> CedarPolicyEngine<InMemory, InMemory> {
            policy_with_schema(
                InMemory::new(LAKEHOUSE_POLICY),
                InMemory::new(""),
                Some(cedar_schema()),
            )
        }

        /// A no-op UDF standing in for a catalog masking function. Its identity in
        /// tests is its name, so a resolved call is recognizable.
        #[derive(Debug, PartialEq, Eq, Hash)]
        struct StubUdf {
            name: String,
            signature: Signature,
        }

        impl StubUdf {
            fn new(name: &str) -> Self {
                Self {
                    name: name.to_string(),
                    signature: Signature::variadic_any(Volatility::Immutable),
                }
            }
        }

        impl ScalarUDFImpl for StubUdf {
            fn name(&self) -> &str {
                &self.name
            }
            fn signature(&self) -> &Signature {
                &self.signature
            }
            fn return_type(&self, _: &[DataType]) -> Result<DataType> {
                Ok(DataType::Utf8)
            }
            fn invoke_with_args(
                &self,
                _: datafusion::logical_expr::ScalarFunctionArgs,
            ) -> Result<ColumnarValue> {
                Ok(ColumnarValue::Scalar(
                    datafusion::scalar::ScalarValue::Utf8(Some("masked".into())),
                ))
            }
        }

        /// A resolver that returns a `StubUdf` named after the requested function.
        #[derive(Debug)]
        struct StubResolver;

        #[async_trait]
        impl CatalogFunctionResolver for StubResolver {
            async fn resolve(&self, name: &str) -> Result<Arc<ScalarUDF>> {
                Ok(Arc::new(ScalarUDF::from(StubUdf::new(name))))
            }
        }

        /// The expected call expression for a resolved function over `ssn`
        /// (+ the `@using_columns("4")` literal argument on the showcase policy).
        fn ssn_mask_call(fn_name: &str) -> Expr {
            let udf = Arc::new(ScalarUDF::from(StubUdf::new(fn_name)));
            udf.call(vec![col("ssn"), lit(4i64)])
        }

        /// An `EvalContext` with governed column tags + a function resolver wired.
        fn eval_ctx(
            governed_column_tags: HashMap<String, BTreeMap<String, String>>,
        ) -> EvalContext {
            let sink = CatalogFactSink::new();
            sink.record(
                table(),
                TableFacts {
                    governed_column_tags,
                    ..Default::default()
                },
            );
            EvalContext {
                catalog_facts: sink,
                function_resolver: Some(Arc::new(StubResolver)),
                ..Default::default()
            }
        }

        fn col_tags(
            pairs: &[(&str, &[(&str, &str)])],
        ) -> HashMap<String, BTreeMap<String, String>> {
            pairs
                .iter()
                .map(|(col, kvs)| {
                    (
                        col.to_string(),
                        kvs.iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect(),
                    )
                })
                .collect()
        }

        fn alice_eu() -> PrincipalIdentity {
            PrincipalIdentity::new("User::\"alice\"")
                .with_attribute("region", "eu")
                .with_attribute("clearance", "standard")
        }

        fn carol_high() -> PrincipalIdentity {
            PrincipalIdentity::new("User::\"carol\"")
                .with_attribute("region", "eu")
                .with_attribute("clearance", "high")
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
                pol.tool_policy("send_external", &alice_eu(), &tainted)
                    .await
                    .unwrap(),
                Decision::Deny
            );

            // A clean session is permitted — the decision tracks the accrued
            // fact, not a hardcoded outcome.
            assert_eq!(
                pol.tool_policy("send_external", &alice_eu(), &BTreeSet::new())
                    .await
                    .unwrap(),
                Decision::Allow
            );
        }

        #[tokio::test]
        async fn row_filter_residual_becomes_predicate() {
            // Level-3 row filter: `resource.region == principal.region` folds (with
            // a concrete principal, region=eu) to `col("region") == "eu"`.
            let tp = lakehouse_engine()
                .constrain(
                    &table(),
                    &df_schema(),
                    &alice_eu(),
                    &eval_ctx(HashMap::new()),
                )
                .await
                .unwrap();
            assert_eq!(tp.row_filters, vec![col("region").eq(lit("eu"))]);
            assert!(tp.column_masks.is_empty());
        }

        #[tokio::test]
        async fn policy_named_fn_masks_tagged_column() {
            // Level-1: the ssn column is tagged pii=ssn, and the showcase forbid
            // names @mask_fn("hr.security.mask_ssn") + @using_columns("4").
            let tags = col_tags(&[("ssn", &[("pii", "ssn")])]);
            let tp = lakehouse_engine()
                .constrain(&table(), &df_schema(), &alice_eu(), &eval_ctx(tags))
                .await
                .unwrap();
            assert_eq!(
                tp.column_masks.get("ssn"),
                Some(&ssn_mask_call("hr.security.mask_ssn"))
            );
        }

        #[tokio::test]
        async fn high_clearance_principal_sees_unmasked() {
            // The forbid is discharged by `unless { principal.clearance == "high" }`,
            // so carol sees ssn unmasked.
            let tags = col_tags(&[("ssn", &[("pii", "ssn")])]);
            let tp = lakehouse_engine()
                .constrain(&table(), &df_schema(), &carol_high(), &eval_ctx(tags))
                .await
                .unwrap();
            assert!(!tp.column_masks.contains_key("ssn"));
        }

        #[tokio::test]
        async fn default_literal_masks_when_no_fn_named() {
            // Level-3: the `classification=secret` forbid names no function, so the
            // column is masked with the default literal.
            let tags = col_tags(&[("salary", &[("classification", "secret")])]);
            let tp = lakehouse_engine()
                .constrain(&table(), &df_schema(), &alice_eu(), &eval_ctx(tags))
                .await
                .unwrap();
            assert_eq!(tp.column_masks.get("salary"), Some(&lit(DEFAULT_MASK)));
        }

        #[tokio::test]
        async fn untagged_column_is_not_masked() {
            // A column carrying no governed tags is not a mask candidate.
            let tp = lakehouse_engine()
                .constrain(
                    &table(),
                    &df_schema(),
                    &alice_eu(),
                    &eval_ctx(HashMap::new()),
                )
                .await
                .unwrap();
            assert!(tp.column_masks.is_empty());
        }

        #[tokio::test]
        async fn no_schema_denies_all_rows() {
            // Without a schema TPE cannot run; fail closed.
            let pol = policy_with_schema(InMemory::new(LAKEHOUSE_POLICY), InMemory::new(""), None);
            let tp = pol
                .constrain(
                    &table(),
                    &df_schema(),
                    &alice_eu(),
                    &eval_ctx(HashMap::new()),
                )
                .await
                .unwrap();
            assert_eq!(tp.row_filters, vec![lit(false)]);
        }

        #[tokio::test]
        async fn named_fn_without_resolver_fails_closed_to_default() {
            // A policy names a function but no resolver is wired: fall back to the
            // default mask (fail-closed) rather than leaving the column exposed.
            let tags = col_tags(&[("ssn", &[("pii", "ssn")])]);
            let sink = CatalogFactSink::new();
            sink.record(
                table(),
                TableFacts {
                    governed_column_tags: tags,
                    ..Default::default()
                },
            );
            let eval = EvalContext {
                catalog_facts: sink,
                function_resolver: None,
                ..Default::default()
            };
            let tp = lakehouse_engine()
                .constrain(&table(), &df_schema(), &alice_eu(), &eval)
                .await
                .unwrap();
            assert_eq!(tp.column_masks.get("ssn"), Some(&lit(DEFAULT_MASK)));
        }
    }
}
