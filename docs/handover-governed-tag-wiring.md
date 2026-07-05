# Handover: wire governed (key→value) tags end-to-end so the Cedar column-mask FGAC path fires

> **Status: RESOLVED (2026-07-05).** The host-side wiring landed in hydrofoil #65
> (2026-07-04): hydrofoil now populates the governed-tag fields on `TableFacts`,
> so the "inert in production" claim below is stale. The breakwater side
> (governed-tag folding for both column *and* table tags) is fully wired and
> tested — see PR #12 (table-tag folding) and `docs/typed-fgac-seams.md`. Kept
> for historical context; do not action.

Working document for the next session. Covers the current state of the typed-FGAC
governed-tag seam across breakwater + hydrofoil (+ mangrove UC client), the gaps, and a
scoped implementation plan. Written 2026-07-04 on branch `feat/typed-fgac-native-tags`.

## TL;DR

breakwater's Cedar column-mask path is fully built and unit-tested but **inert in
production**: the host (hydrofoil) never populates the governed-tag fields on
`TableFacts`, so every governed-tag policy silently no-ops. The fix is host-side
wiring, gated behind a hydrofoil compatibility pass (hydrofoil is stale after the
`datafusion-policy-cedar`/`datafusion-policy` split). Scope decisions are locked (below).

_(Superseded — see the RESOLVED note at the top.)_

## Context / why

`TableFacts` (breakwater `crates/datafusion-policy/src/facts.rs:47,52`) carries two typed
governed-tag fields — `governed_tags: BTreeMap<String,String>` (table) and
`governed_column_tags: HashMap<String,BTreeMap<String,String>>` (column) — that the
Cedar adapter folds into native entity tags so policies match
`resource.hasTag(k) && resource.getTag(k) == v` (the UC ABAC governed-tag model). The
column-mask path (`cedar.rs::column_is_masked`, `native_tags`, `mask_candidate_columns`)
already consumes `governed_column_tags` and passes unit tests that inject the facts.

But hydrofoil's `record_facts` (`crates/hydrofoil/src/catalog/unity.rs:56-90`) builds
`TableFacts` populating only the **opaque classification sets** (`tags`/`column_tags`,
which feed taints) from `ConventionTagProvider`, and leaves **both governed fields at
`Default` (empty)**. There is no key→value tag producer in hydrofoil at all.

The mismatch is semantic: the convention provider emits opaque `BTreeSet<String>` (e.g.
`{"pii","ssn"}`), but governed tags are key→value (e.g. `{"pii":"ssn"}`) because policies
match `getTag("pii") == "ssn"`.

**Outcome wanted:** a UC table's governed tags flow into `TableFacts`, the Cedar
column-mask path fires against real tags, and `@mask_fn`-named UC functions resolve to
real UDFs. Verified end-to-end.

## Key finding (drives the sourcing decision)

The mangrove UC **client** ships a first-class governed-tag API —
`EntityTagAssignmentClient::list_entity_tag_assignments(entity_type, entity_name)`
returning `Vec<EntityTagAssignment { entity_type, entity_name, tag_key, tag_value:
Option<String> }>` (`mangrove/crates/client/src/codegen/entity_tag_assignments/client.rs:24`;
model `mangrove/crates/common/src/models/_gen/unitycatalog.tags.v1.rs:12`; accessor
`UnityCatalogClient::entity_tag_assignments_client()` at `.../codegen/client.rs:95`).
`entity_type` supports `catalogs/schemas/tables/columns`. `LakehouseTableProviderBuilder`
**already holds a `UnityCatalogClient`** (`unity.rs:39`) — the real UC governed-tag source
is reachable at the exact site that builds `TableFacts`, no new plumbing. The portal
`EntityTagAssignment` store is serving-only (no reader client in the query path) and is
the wrong source; use the UC client.

## Decisions (confirmed with user)

- **Tag sourcing:** convention provider now, behind a new `GovernedTagProvider` trait,
  with a UC-`EntityTagAssignmentClient`-backed impl as the production backend.
- **Function resolver:** in scope — implement `CatalogFunctionResolver` over the UC
  Functions API so `@mask_fn` resolves to a real UDF.
- **Table-tag row filters:** deferred (explicit boundary). Blocked on a cedar-policy
  API limit (no concrete tags on a symbolic-uid resource). Sourcing `governed_tags` is
  cheap and in scope; *consumption* for row filters is deferred.

## Phase 0 (GATING) — hydrofoil compatibility pass

**hydrofoil has not been updated since breakwater split `datafusion-policy-cedar` from
`datafusion-policy` and renamed the policy types.** It likely does not build against
current breakwater HEAD, so this must land (hydrofoil building) *before* any
governed-tag work. Breakage is tightly scoped and mechanical — verified surface:

**Imports that still resolve (no change):** hydrofoil imports the whole policy surface
via `datafusion_policy_cedar::…` and has no `datafusion-policy` dep declared, but
`datafusion-policy-cedar/src/lib.rs` re-exports the neutral core — so `TableFacts`,
`CatalogFactSink`, `CatalogFactSinkExt`, `EvalContext`, `Decision`, `PrincipalIdentity`,
`IdentityProvider`, `IdentityError`, `PrincipalClaims`, `PrincipalEnrichment`,
`FactStore`/`FactStoreExt`/`InMemoryFactStore`, `TablePolicy`, `EntityUid`, the provider
traits, and `authorize_and_govern` all still resolve (name-by-name checked).

**Three renamed types break the build (the whole compat delta):**
- `StaticPolicy` → `StaticPolicyEngine`
- `CedarPolicy`  → `CedarPolicyEngine`
- `Policy` (trait) → `PolicyEngine`

**Fix (H0) — minimize churn via the existing shim.** `crates/hydrofoil/src/policy.rs` is
a thin re-export (`pub use datafusion_policy_cedar::{CedarPolicy, Policy, StaticPolicy};`).
Alias the new names locally:
```rust
pub use datafusion_policy_cedar::{
    CedarPolicyEngine as CedarPolicy,
    PolicyEngine as Policy,
    StaticPolicyEngine as StaticPolicy,
};
```
Then fix the two sites that bypass the shim: `session/mod.rs:606`
(`datafusion_policy_cedar::StaticPolicy::new` → `StaticPolicyEngine`, or route via
`crate::policy`) and `planner/governed_lineage.rs:30` (imports `Policy` straight from
`datafusion_policy_cedar` → `PolicyEngine as Policy`). `main.rs:57`
(`policy::CedarPolicy::from_oci`) resolves once the shim aliases `CedarPolicy`. Build +
run hydrofoil tests to confirm green before Phase 1.

### Pre-flight blockers (fold into Phase 0)

1. **Feature-name mismatch.** hydrofoil maps `governance = ["datafusion-policy-cedar/governance"]`
   (`crates/hydrofoil/Cargo.toml:74`) but breakwater's crate only defines `fgac`. So
   `cargo build -p hydrofoil --features governance` cannot resolve. **Fix:** add
   `governance = ["fgac"]` to breakwater's `datafusion-policy-cedar` `[features]` (commit B1).
2. **Local path-override typo (flag to user — do NOT auto-fix).** hydrofoil
   `Cargo.toml:103` overrides `datafusion-policy-cedar` to `package = "olai-cedar-oci"` pointing
   at the `.../datafusion-policy-cedar` dir — wrong package name (line 23 correctly uses
   `olai-datafusion-policy-cedar`; line 102 legitimately uses `olai-cedar-oci` for the cedar-oci
   dir). It's in the `LOCAL, UNCOMMITTED — do not commit` block, so it's the user's local
   wiring; likely should read `package = "olai-datafusion-policy-cedar"`. Must be corrected
   locally for hydrofoil to build at all — Phase 0 can't be verified until it is.

## In scope

| # | Repo | Change |
|---|------|--------|
| **H0** | **hydrofoil** | **compat pass: alias 3 renamed policy types in `policy.rs`; fix 2 bypass sites; get hydrofoil building (GATING)** |
| B1 | breakwater | `governance = ["fgac"]` feature alias (pre-flight #1) |
| B2 | breakwater | walkthrough example: populate `governed_column_tags` at decision ③ |
| H1 | hydrofoil | `GovernedTags` struct + `GovernedTagProvider` trait + `ConventionGovernedTagProvider` |
| H2 | hydrofoil | `record_facts` populates both governed fields; provider field + builder method |
| H3 | hydrofoil | `UnityGovernedTagProvider` over `entity_tag_assignments_client`; select in `build_unity_resolver` |
| H4 | hydrofoil | `UnityFunctionResolver` (`CatalogFunctionResolver`) + `FunctionResolverExt` wiring |
| H5 | hydrofoil | end-to-end session integration test |

## Deferred (documented boundary, not this plan)

- **Table-level governed-tag row filters** — blocked on cedar-policy: the `read_table`
  row-filter path leaves the resource uid symbolic (`cedar.rs:532`,
  `PartialEntityUid::new(table_type, None)`) so `resource.<col>` survives per-row, but a
  `PartialEntity` (only carrier of concrete tags) requires a concrete uid — no API
  supplies concrete tags on a symbolic-uid resource. Sourcing `governed_tags` (H1–H3) is
  done; folding them in `table_residuals` + adding `hasTag`/`getTag` to `translate.rs`
  is deferred. Keep the `cedar.rs:524` NOTE as the marker.
- **Level-2 tag-default function** (`cedar.rs:703` `tag_default_mask_fn` returns `None`)
  — breakwater-only follow-up; depends on H4. Level 1 (`@mask_fn`) + level 3 (default
  `"***"`) cover the showcase.
- **Executing real UC SQL UDF bodies** — H4's first cut resolves the function's
  *signature* (real arity/type binding) but its `invoke_with_args` is a fail-closed
  no-op returning the mask literal; executing the UC SQL `routine_definition` is a
  larger separate effort.

## Implementation

### breakwater

**B1 — feature alias.** `crates/datafusion-policy-cedar/Cargo.toml` `[features]`: add
`governance = ["fgac"]`.

**B2 — walkthrough.** `crates/datafusion-policy-cedar/examples/fact_gathering_walkthrough.rs`,
decision ③: construct the facts with a populated `governed_column_tags`
(`ssn → {pii: ssn}`) and print the resulting column mask, so flipping the tag flips
masked/unmasked. No production-code change.

### hydrofoil

All new fact-sourcing code in `crates/hydrofoil/src/catalog/tags.rs` (mirror the existing
`TagProvider`/`ConventionTagProvider` pattern — one trait per PIP, per ADR-0007). Do
**not** overload `TagProvider` (opaque sets, taint path) or reuse `TableClassification`;
governed tags are key→value, feed the mask/filter path, production backend is
async-network per table/column.

**H1 — trait + convention impl** (`catalog/tags.rs`, re-export via `catalog/mod.rs`):
```rust
#[derive(Debug, Clone, Default)]
pub struct GovernedTags {
    pub table_tags: BTreeMap<String, String>,
    pub column_tags: HashMap<String, BTreeMap<String, String>>,
}

#[async_trait::async_trait]
pub trait GovernedTagProvider: Send + Sync + std::fmt::Debug {
    /// Best-effort: an error means "no governed tags" and must not block resolution.
    async fn governed_tags(&self, table: &Table) -> Result<GovernedTags, DataFusionError>;
}

#[derive(Debug, Default)]
pub struct ConventionGovernedTagProvider; // v1, synchronous, zero network
```
Convention keys (add to the existing `keys` module): table-level
`properties["govtag.<key>"] = "<value>"` → `table_tags`; per-column
`properties["govtag.<col>.<key>"] = "<value>"` → `column_tags[col][key]`. Unit tests
mirror the existing `ConventionTagProvider` tests.

**H2 — populate in `record_facts`** (`catalog/unity.rs`):
- Add `governed_tag_provider: Arc<dyn GovernedTagProvider>` to
  `LakehouseTableProviderBuilder` (`unity.rs:33`), defaulted in `new` (`unity.rs:44`) to
  `Arc::new(ConventionGovernedTagProvider)`, mirroring `tag_provider`. Leave the existing
  `tag_provider` hardcoded.
- Add builder method `with_governed_tag_provider(self, Arc<dyn GovernedTagProvider>) ->
  Arc<Self>` so `build_unity_resolver` can select the UC-backed impl.
- In `record_facts` (`unity.rs:56-90`): call the provider and fill the two fields
  (currently absent from the struct literal at `unity.rs:82-89`):
  ```rust
  let governed = self.governed_tag_provider.governed_tags(table).await.unwrap_or_default();
  // in TableFacts { ... }:
  governed_tags: governed.table_tags,
  governed_column_tags: governed.column_tags,
  ```
- Test: a `Table` with `govtag.*` properties yields a `TableFacts` in the sink whose
  `governed_column_tags` is populated.

**H3 — UC-backed provider** (`catalog/tags.rs` or new `catalog/governed_tags.rs`):
- `UnityGovernedTagProvider { client: UnityCatalogClient }`. `governed_tags(table)` calls
  `entity_tag_assignments_client().list_entity_tag_assignments` once for the table
  (`entity_type="tables"`, `entity_name=table.full_name`) and once per column
  (`entity_type="columns"`, `entity_name="{full_name}.{col}"`), folding
  `tag_key`/`tag_value` into `GovernedTags`. `tag_value: None` → skip.
- Errors logged + treated as empty (fail-open on *sourcing*; the mask decision stays
  fail-closed at the Cedar layer, consistent with `record_facts`' `classify` handling).
- Select it in `build_unity_resolver` (`session/mod.rs:728`) — the client is in hand via
  `factory.unity_client().clone()`. Keep the convention provider as the default for
  offline/deterministic tests.
- Test with the mangrove mock-server (mockito) pattern (see mangrove
  `crates/client/src/delta_v1.rs` tests): stub the tables/columns assignment endpoints.

**H4 — function resolver** (new `catalog/functions.rs`), fgac/governance-gated:
- `UnityFunctionResolver { client: UnityCatalogClient }` impl
  `datafusion_policy::CatalogFunctionResolver::resolve(&self, name) -> Result<Arc<ScalarUDF>>`.
- `name` catalog-qualified (`"hr.security.mask_ssn"`). Call
  `functions_client().get_function(GetFunctionRequest{ name })`
  (`mangrove/crates/client/src/codegen/functions/client.rs:73`). Map
  `Function.input_params.parameters[].type_name` (`ColumnTypeName`) → Arrow `DataType`
  for `Signature::exact(types, Immutable)`; map `Function.data_type`/`type_name` → return
  type. Small `col_type_to_arrow` helper covers showcase types
  (BOOLEAN/INT/LONG/DOUBLE/STRING).
- **First cut:** UDF `invoke_with_args` is a fail-closed no-op returning the mask literal
  — real signature (arity/type binding + `@using_columns` args validate), no UC-SQL-body
  execution (deferred). Unresolvable name / catalog outage → `Err`, which `call_fn`
  (`cedar.rs:715`) propagates to a default-literal mask — the crate's existing fail-closed
  contract, no breakwater change needed.
- Attach alongside `CatalogFactSinkExt` (`session/mod.rs:653`), gated:
  `session_config.set_extension(Arc::new(datafusion_policy_cedar::FunctionResolverExt(
  Arc::new(UnityFunctionResolver::new(unity_factory.unity_client().clone())))))`.
  `SessionConfigEvalContextProvider` already reads `FunctionResolverExt` into
  `EvalContext.function_resolver` (breakwater `session.rs:124-127`) — no breakwater change.

**H5 — end-to-end session test** (`session/mod.rs` integration tests): a session over a
`Table` fixture carrying `govtag.ssn.pii = "ssn"`; run `SELECT ssn FROM <table>` as a
standard-clearance principal and assert the governed plan masks `ssn` (default literal,
or the resolved UDF once H4 lands), while a high-clearance principal sees it unmasked.
Proves resolution → `record_facts` → sink → `EvalContext` → `column_is_masked` →
`resolve_mask_expr` with **real** governed tags.

## Commit sequence (small, release-plz-friendly)

1. **B1** `feat(datafusion-policy-cedar): add governance feature alias for fgac`
2. **H0** `fix(hydrofoil): update policy imports for the cedar/policy split` — gating compat pass
3. **H1** `feat(hydrofoil): add GovernedTagProvider trait + convention impl`
4. **H2** `feat(hydrofoil): populate governed tags in record_facts`
5. **H3** `feat(hydrofoil): source governed tags from UC entity-tag-assignments`
6. **H4** `feat(hydrofoil): resolve @mask_fn to UC functions via CatalogFunctionResolver`
7. **H5** `test(hydrofoil): column mask fires end-to-end with governed tags`
8. **B2** `docs(datafusion-policy-cedar): show governed column tags in fact-gathering walkthrough`

breakwater (B1, B2) and hydrofoil (H0–H5) are separate branches/PRs. Order: B1 first
(adds the `governance` alias), then H0 (with the local Cargo path-override typo
corrected) so hydrofoil builds against current breakwater HEAD — H1+ can't be verified
until H0 is green.

## Verification

- **Phase 0 gate (must pass before anything else):** with B1 landed and the local Cargo
  path-override typo corrected, `cargo build -p hydrofoil --features governance` and
  `cargo test -p hydrofoil` are green. Proves H0 restored hydrofoil against current
  breakwater HEAD. Do not start H1 until green.
- **breakwater unit (already passing, no change):** the `governance` module in
  `crates/datafusion-policy-cedar/src/cedar.rs` (`policy_named_fn_masks_tagged_column`,
  `default_literal_masks_when_no_fn_named`, `high_clearance_principal_sees_unmasked`,
  `resolver_error_fails_closed_to_default_mask`, …) is the contract the hydrofoil side
  must feed. `cargo test -p olai-datafusion-policy-cedar --features fgac`.
- **hydrofoil unit:** `ConventionGovernedTagProvider` fold test (H1); `record_facts`
  populates `governed_column_tags` (H2); `UnityGovernedTagProvider` mockito test (H3).
  `cargo test -p hydrofoil --features governance`.
- **walkthrough (runnable proof):**
  `cargo run -p olai-datafusion-policy-cedar --example fact_gathering_walkthrough --features fgac`
  — flipping the governed tag flips masked/unmasked (B2).
- **end-to-end:** the H5 session integration test.
- **hygiene before commit (per CLAUDE.md):** `cargo fmt --all`;
  `cargo clippy --all-targets --all-features -- -D warnings` in each repo.

## Key files

breakwater:
- `crates/datafusion-policy/src/facts.rs` — `TableFacts` (governed fields at :47,:52)
- `crates/datafusion-policy-cedar/src/cedar.rs` — `column_is_masked`, `native_tags`,
  `mask_candidate_columns`, `resolve_mask_expr`, `table_residuals` (:524 NOTE),
  `tag_default_mask_fn` (:703 stub)
- `crates/datafusion-policy-cedar/src/translate.rs` — residual translator (no hasTag/getTag)
- `crates/datafusion-policy-cedar/src/lib.rs` — the re-export surface hydrofoil imports
- `crates/datafusion-policy/src/function.rs` — `CatalogFunctionResolver` trait
- `config/policies/lakehouse.{cedar,cedarschema,entities.json}` — showcase policy contract

hydrofoil:
- `crates/hydrofoil/src/policy.rs` — the shim to fix in H0
- `crates/hydrofoil/src/catalog/tags.rs` — `TagProvider`/`ConventionTagProvider`; add
  `GovernedTagProvider` here
- `crates/hydrofoil/src/catalog/unity.rs` — `LakehouseTableProviderBuilder`, `record_facts`
- `crates/hydrofoil/src/session/mod.rs` — session wiring (`CatalogFactSinkExt` :653,
  `build_unity_resolver` :723), `StaticPolicy` use at :606, integration tests
- `crates/hydrofoil/src/planner/governed_lineage.rs` — `Policy` import at :30
- `crates/hydrofoil/Cargo.toml` — `governance` feature map (:74); local path override (:103)

mangrove (UC client):
- `crates/client/src/codegen/entity_tag_assignments/client.rs` — governed-tag source
- `crates/client/src/codegen/functions/client.rs` — `get_function` for the resolver
- `crates/common/src/models/_gen/unitycatalog.tags.v1.rs` — `EntityTagAssignment` model
