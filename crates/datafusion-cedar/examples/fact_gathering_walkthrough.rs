//! End-to-end **fact-gathering & policy-evaluation walkthrough** for the hybrid PDP.
//!
//! Companion to `docs/policy-fact-gathering.md` (the design ADRs on fact locality
//! and session state live in the hydrofoil repo). Running this example
//! *is* the walkthrough: it steps through the four (partial) decision points along
//! the catalog → engine → agent chain, supplies the facts available at each point
//! (labelling each fact's *locality + lifetime*), and runs **real** Cedar
//! evaluations — `is_authorized` for the coarse gates and `is_authorized_partial`
//! for the engine's row-filter / column-mask governance.
//!
//! The shared-session-scoped facts use the **real** `datafusion_cedar::InMemoryFactStore`
//! (not a mock), and the principal's group membership is supplied via the real
//! neutral `PrincipalEnrichment` / `Group` hierarchy the identity PIP produces
//! (lowered to Cedar entities by `principal_entities`) — the static entity
//! bundle no longer carries user→group edges. Only the
//! local-ephemeral facts (catalog identity, columns) are still constructed inline
//! to keep the example self-contained.
//!
//! Nothing here is hardcoded: each decision is the output of the Cedar authorizer
//! over the policy set + entities + the supplied facts. Flip a fact (drop the
//! taint, drop alice's group from the enrichment) and the printed decision changes.
//!
//! Run with:
//! ```text
//! cargo run -p datafusion-cedar --example fact_gathering_walkthrough --features governance
//! ```
//!
//! ## What it demonstrates
//!
//! * **① Catalog PEP** — coarse `read_table` allow/deny, facts bound from the
//!   request context (principal) and the catalog (resource entity attributes).
//! * **② Engine coarse gate** — the same shape, now also carrying the accessed
//!   columns in the Cedar `context`.
//! * **③ Engine governance** — a *partial* request (unknown resource) yields a
//!   residual that lowers to a concrete row-filter / column-mask `Expr`. The
//!   residual is the artifact a "carry-residual" (option B in the ADR) design
//!   would cache in the session store.
//! * **④ Agent-tool PEP** — a tool call gated on the **session fact store**: a
//!   taint accrued at ②/③ (`observed_taints` ∋ `"pii"`) flips a `forbid`
//!   guardrail from allow to deny.

use std::collections::BTreeSet;
use std::str::FromStr;

use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_local_agent::public::{
    EntityProviderError, PolicySetProviderError, SimpleEntityProvider, SimplePolicySetProvider,
};
use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, PolicySet, Request, RequestBuilder,
    RestrictedExpression, Schema,
};
use std::sync::Arc;

use cedar_policy::Entity;
use datafusion_cedar::{
    CedarResidualTranslator, Group, PrincipalEnrichment, PrincipalIdentity, ResidualTranslator,
    parse_uid, principal_entities,
};

// ----------------------------------------------------------------------------
// Policy model
//
// We reuse the *committed* coarse baseline (`config/policies/`) so the
// walkthrough validates the real model, then layer two minimal policies inline:
// a governance row-filter (so partial eval has a residual to return) and an
// agent `forbid` guardrail (so the tool-call PEP has something to enforce). The
// inline policies are kept here, not in `config/policies/`, so the committed
// bundle stays the coarse baseline rather than implying these are production.
// ----------------------------------------------------------------------------

/// Path to the committed Cedar config, resolved relative to the workspace root.
const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/policies");

/// Governance row-filter: a reader may only see rows whose `region` matches their
/// own. With a concrete principal (`region == "eu"`) and an *unknown* resource,
/// partial evaluation leaves the residual `resource.region == "eu"`, which lowers
/// to `col("region") = "eu"`.
const GOVERNANCE_POLICY: &str = r#"
@id("region_row_filter")
@filter_type("row_filter")
permit (
    principal,
    action == Action::"read_table",
    resource
)
when { resource.region == principal.region };
"#;

/// Agent guardrail: forbid the `send_external` tool when the session has observed
/// PII. This is the data-flow control that survives prompt-injection — it blocks
/// the *action*, not the prompt.
const AGENT_GUARDRAIL_POLICY: &str = r#"
@id("no_external_send_with_pii")
forbid (
    principal,
    action == Action::"send_external",
    resource
)
when { context.observed_taints.contains("pii") };

permit (
    principal,
    action == Action::"send_external",
    resource
);
"#;

// ----------------------------------------------------------------------------
// Session fact store (shared, session-scoped) — option-A model.
//
// Local-ephemeral facts (principal attrs, catalog entity attrs, accessed
// columns) are resolved at the point of use and never persisted. Only
// *shared-session-scoped* facts live here, keyed by correlation id, so a later
// PEP (the agent tool-call) can read what earlier PEPs accrued. This is the
// **real** `datafusion_cedar::InMemoryFactStore` (not a mock); production would
// swap a shared-KV backend behind the same `FactStore` trait (see the ADR).
// ----------------------------------------------------------------------------

use datafusion_cedar::{FactStore as _, InMemoryFactStore};

// ----------------------------------------------------------------------------
// In-memory Cedar provider (mirrors the test harness in `cedar.rs`).
// ----------------------------------------------------------------------------

#[derive(Debug)]
struct InMemory {
    policies: Arc<PolicySet>,
    entities: Arc<Entities>,
}

#[async_trait::async_trait]
impl SimplePolicySetProvider for InMemory {
    async fn get_policy_set(&self, _: &Request) -> Result<Arc<PolicySet>, PolicySetProviderError> {
        Ok(self.policies.clone())
    }
}

#[async_trait::async_trait]
impl SimpleEntityProvider for InMemory {
    async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
        Ok(self.entities.clone())
    }
}

fn authorizer(policies: PolicySet, entities: Entities) -> Authorizer<InMemory, InMemory> {
    let provider = Arc::new(InMemory {
        policies: Arc::new(policies),
        entities: Arc::new(entities),
    });
    let config = AuthorizerConfigBuilder::default()
        .policy_set_provider(provider.clone())
        .entity_provider(provider)
        .build()
        .expect("authorizer config");
    Authorizer::new(config)
}

// ----------------------------------------------------------------------------
// Small helpers mirroring `visitor.rs` (which is `pub(crate)`), so the example
// stays honest about how requests are built without reaching into crate
// internals.
// ----------------------------------------------------------------------------

fn action(id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new(id))
}

fn table_resource(name: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Table").unwrap(),
        EntityId::new(name),
    )
}

/// Build the table-identity context (`catalog`/`schema`/`table`/`columns`),
/// mirroring `visitor::table_context`.
fn table_context(catalog: &str, schema: &str, table: &str, columns: &[&str]) -> Context {
    let mut pairs: Vec<(String, RestrictedExpression)> = vec![
        (
            "catalog".into(),
            RestrictedExpression::new_string(catalog.into()),
        ),
        (
            "schema".into(),
            RestrictedExpression::new_string(schema.into()),
        ),
        (
            "table".into(),
            RestrictedExpression::new_string(table.into()),
        ),
    ];
    if !columns.is_empty() {
        pairs.push((
            "columns".into(),
            RestrictedExpression::new_set(
                columns
                    .iter()
                    .map(|c| RestrictedExpression::new_string((*c).into())),
            ),
        ));
    }
    Context::from_pairs(pairs).expect("context")
}

/// Build the tool-call context carrying the session's observed taints.
fn tool_context(observed_taints: &BTreeSet<String>) -> Context {
    let pairs = vec![(
        "observed_taints".to_string(),
        RestrictedExpression::new_set(
            observed_taints
                .iter()
                .map(|t| RestrictedExpression::new_string(t.clone())),
        ),
    )];
    Context::from_pairs(pairs).expect("tool context")
}

/// alice's group closure as the identity PIP would resolve it: alice ∈
/// privileged_readers ⊂ readers. This is the `PrincipalEnrichment` the hydrofoil
/// `IdentityProvider` returns; here it replaces the user→group edges that used
/// to live in the static entity bundle. The hierarchy is expressed in the
/// engine-neutral `Group` shape; the Cedar adapter rebuilds the entity graph.
fn alice_enrichment() -> PrincipalEnrichment {
    let group = |id: &str| format!(r#"UserGroup::"{id}""#);
    PrincipalEnrichment {
        groups: vec![group("privileged_readers")],
        group_hierarchy: vec![
            Group {
                uid: group("privileged_readers"),
                parents: vec![group("readers")],
            },
            Group {
                uid: group("readers"),
                parents: vec![],
            },
        ],
        ..Default::default()
    }
}

/// Merge extra request-time entities (the principal + its group closure) into a
/// copy of the static bundle, so one `Entities` carries both.
fn merge_entities(base: &Entities, extra: Vec<Entity>) -> Entities {
    base.clone()
        .add_entities(extra, None)
        .expect("merge entities")
}

fn divider(title: &str) {
    println!("\n{}", "─".repeat(78));
    println!("  {title}");
    println!("{}", "─".repeat(78));
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // The correlation id that ties the chain together (decision 3 in the platform
    // doc). In hydrofoil this is the session/trace id propagated across hops.
    let correlation_id = "session-demo-0001";

    // ── Load the committed coarse baseline + parse the schema. ───────────────
    let baseline_src = std::fs::read_to_string(format!("{POLICY_DIR}/lakehouse.cedar"))
        .expect("read lakehouse.cedar");
    let schema_src = std::fs::read_to_string(format!("{POLICY_DIR}/lakehouse.cedarschema"))
        .expect("read lakehouse.cedarschema");
    let entities_src = std::fs::read_to_string(format!("{POLICY_DIR}/lakhouse.entities.json"))
        .expect("read entities");

    let (schema, _) = Schema::from_cedarschema_str(&schema_src).expect("parse cedar schema");
    let entities = Entities::from_json_str(&entities_src, Some(&schema))
        .expect("parse entities against schema");

    println!("Fact-gathering & policy-evaluation walkthrough (hybrid PDP)");
    println!("correlation_id = {correlation_id}");
    println!(
        "Loaded committed model from config/policies/: {} entities, baseline policy set.",
        entities.iter().count()
    );

    // The session fact store — the shared, session-scoped state (the rest of the
    // facts in this walkthrough are local-ephemeral and built at each point).
    let facts = InMemoryFactStore::new();

    // ── Decision point ① — Catalog PEP. ─────────────────────────────────────
    //
    // Facts bound here:
    //   * principal `User::"alice"`           [request context → principal entity]   local-ephemeral
    //   * resource  `Table::"protected_table"`[catalog metadata → resource entity]   local-ephemeral
    //   * action    `read_table`              [the operation]
    // Decision is full (no unknowns): is_authorized.
    divider("① Catalog PEP — may alice read protected_table?");
    // alice's group membership is NOT in the static bundle (it was shrunk):
    // the identity PIP resolves her closure (alice ∈ privileged_readers ⊂
    // readers) and we fold it in via `principal_entities`. This is the real
    // `PrincipalEnrichment` shape the hydrofoil `IdentityProvider` returns.
    let alice = PrincipalIdentity::new(r#"User::"alice""#)
        .with_attribute("region", "eu")
        .enriched(alice_enrichment());
    // Lower the neutral principal to Cedar types at the boundary (the adapter
    // helpers the `CedarPolicy` engine uses internally, exposed for hosts that
    // build requests directly).
    let alice_uid = parse_uid(&alice.uid).expect("alice uid");
    // The request-time entity set = the static bundle (groups + resource) PLUS
    // alice's dynamically-resolved principal + group closure.
    let with_principal = merge_entities(&entities, principal_entities(&alice).expect("entities"));
    let baseline = authorizer(
        PolicySet::from_str(&baseline_src).expect("baseline policy set"),
        with_principal.clone(),
    );
    let req = Request::new(
        alice_uid.clone(),
        action("read_table"),
        table_resource("protected_table"),
        Context::empty(),
        None,
    )
    .expect("request");
    // `alice` resolves through the dynamically-folded hierarchy: alice ∈
    // privileged_readers ⊂ readers = protected_table.readers, so the coarse
    // `read_table` permit fires — with an empty user→group bundle.
    let decision = baseline
        .is_authorized(&req, &with_principal)
        .await
        .expect("authz")
        .decision();
    println!("  facts: principal=alice + groups (SHARED via identity PIP, not the bundle),");
    println!("         resource=protected_table.readers=readers (local-ephemeral, from catalog)");
    println!("  → Cedar is_authorized = {decision:?}   (expect Allow)");

    // ── Decision point ① (deny path) — prove fail-closed + hierarchy. ────────
    divider("① Catalog PEP (deny path) — may r2d2 *write* protected_table?");
    let r2d2 = PrincipalIdentity::new(r#"Agent::"r2d2""#);
    let r2d2_uid = parse_uid(&r2d2.uid).expect("r2d2 uid");
    let req = Request::new(
        r2d2_uid.clone(),
        action("write_table"),
        table_resource("protected_table"),
        Context::empty(),
        None,
    )
    .expect("request");
    // r2d2 ∈ readers, but protected_table.writers = lakhouse_admins, so no write
    // permit fires → default-deny.
    let decision = baseline
        .is_authorized(&req, &entities)
        .await
        .expect("authz")
        .decision();
    println!("  facts: principal=r2d2∈readers, resource.writers=lakhouse_admins");
    println!("  → Cedar is_authorized = {decision:?}   (expect Deny — default-deny, fail-closed)");

    // ── Decision point ② — Engine coarse gate. ──────────────────────────────
    //
    // Same shape as ①, now carrying the *accessed columns* in the Cedar context
    // (local-ephemeral, from the DFSchema / TableScan projection).
    divider("② Engine coarse gate — alice reads protected_table[id, region, ssn]");
    let req = Request::new(
        alice_uid.clone(),
        action("read_table"),
        table_resource("protected_table"),
        table_context("main", "sales", "protected_table", &["id", "region", "ssn"]),
        None,
    )
    .expect("request");
    let decision = baseline
        .is_authorized(&req, &with_principal)
        .await
        .expect("authz")
        .decision();
    println!("  facts: + columns=[id, region, ssn] in context (local-ephemeral, from DFSchema)");
    println!("  → Cedar is_authorized = {decision:?}   (expect Allow)");

    // ── Decision point ③ — Engine governance (partial eval). ────────────────
    //
    // The resource is left *unknown* so per-row `resource.<col>` conditions come
    // back as residuals. The principal (region=eu) is concrete, so the residual
    // collapses to `resource.region == "eu"` → col("region") = "eu".
    divider("③ Engine governance — partial eval → row filter / column mask");
    // The principal entity must carry `region` so partial eval can fold
    // `principal.region` to a literal, leaving only `resource.region == "eu"` as
    // the residual. We supply alice's *attributed* entity (the committed
    // `entities` carry a bare `User::"alice"` with no attributes) — exactly what
    // `cedar::table_policy` does with `principal.to_entity()`. The governance
    // policy references only principal/resource attributes, so no hierarchy is
    // needed here.
    let gov_entities =
        Entities::from_entities(principal_entities(&alice).expect("principal entity"), None)
            .expect("principal entity");
    let gov = authorizer(
        PolicySet::from_str(GOVERNANCE_POLICY).expect("governance policy set"),
        gov_entities.clone(),
    );
    let partial = RequestBuilder::default()
        .principal(alice_uid.clone())
        .action(action("read_table"))
        .unknown_resource_with_type(EntityTypeName::from_str("Table").unwrap())
        .context(table_context("main", "sales", "protected_table", &[]))
        .build();
    let response = gov
        .is_authorized_partial(&partial, &gov_entities)
        .await
        .expect("partial authz");
    let translator = CedarResidualTranslator;
    println!("  facts: principal.region=eu (bound) · resource=UNKNOWN (deferred → residual)");
    let mut produced_residual = false;
    for residual in response.nontrivial_residuals() {
        produced_residual = true;
        let filter_type = residual.annotation("filter_type").unwrap_or("<none>");
        match translator.to_predicate(&residual) {
            Ok(Some(expr)) => {
                println!("  residual @filter_type({filter_type}) → DataFusion Expr: {expr}");
                println!("    (this Expr is injected as a Filter/Projection before optimize;");
                println!("     it is also the artifact a 'carry-residual' design (ADR option B)");
                println!(
                    "     would cache in the session store keyed by (correlation_id, bundle_version))"
                );
            }
            Ok(None) => {
                println!("  residual @filter_type({filter_type}) → trivially true (no filter)")
            }
            Err(e) => println!("  residual untranslatable → fail closed (deny rows): {e}"),
        }
    }
    if !produced_residual {
        println!("  (no non-trivial residual — policy fully decided)");
    }

    // Model the taint accrual that the engine performs as it reads a tagged
    // column: `protected_table.ssn` is tagged `pii`, so the session ledger gains
    // "pii". This is the one *shared-session-scoped* fact in the walkthrough.
    facts.record_taint(correlation_id, "pii");
    println!(
        "  → engine read a pii-tagged column; session ledger now: {:?}  (SHARED, in fact store)",
        facts.observed_taints(correlation_id)
    );

    // ── Decision point ④ — Agent-tool PEP. ──────────────────────────────────
    //
    // The tool-call request's context carries the *shared* session taints read
    // back from the fact store. The `forbid` guardrail flips on their presence.
    let guardrail = authorizer(
        PolicySet::from_str(AGENT_GUARDRAIL_POLICY).expect("guardrail policy set"),
        entities.clone(),
    );

    divider("④ Agent-tool PEP — may the agent call send_external now?");
    let observed = facts.observed_taints(correlation_id);
    let req = RequestBuilder::default()
        .principal(alice_uid.clone())
        .action(action("send_external"))
        .resource(table_resource("export_sink"))
        .context(tool_context(&observed))
        .build();
    let decision = guardrail
        .is_authorized(&req, &entities)
        .await
        .expect("authz")
        .decision();
    println!("  facts: context.observed_taints={observed:?} (SHARED, read from fact store)");
    println!("  → Cedar is_authorized = {decision:?}   (expect Deny — forbid-overrides on pii)");

    // Counterfactual: a *fresh* session that never read pii is allowed — proving
    // the decision is driven by the accrued fact, not hardcoded.
    divider("④ Agent-tool PEP (counterfactual) — fresh session, no taints");
    let clean = BTreeSet::new();
    let req = RequestBuilder::default()
        .principal(alice_uid.clone())
        .action(action("send_external"))
        .resource(table_resource("export_sink"))
        .context(tool_context(&clean))
        .build();
    let decision = guardrail
        .is_authorized(&req, &entities)
        .await
        .expect("authz")
        .decision();
    println!("  facts: context.observed_taints={{}} (no pii accrued)");
    println!("  → Cedar is_authorized = {decision:?}   (expect Allow — guardrail not triggered)");

    println!("\nWalkthrough complete. Every decision above is a real Cedar evaluation;");
    println!("flipping a mocked fact (taint, group membership, region) changes the outcome.");
}
