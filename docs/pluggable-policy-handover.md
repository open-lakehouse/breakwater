# Handover: make the breakwater policy layer engine-agnostic & more composable

> **Purpose of this document.** This is a self-contained handover/prompt for a
> fresh session (or engineer) to pick up and execute. It carries its own context:
> the current architecture, the prior-art that informed it, the decisions already
> taken, and the concrete work to do. You should not need the originating
> conversation. Read top to bottom, then start at **Work plan**.

---

## 1. What breakwater is

`breakwater` (repo root: this workspace) was just migrated out of the `hydrofoil`
monorepo. It provides **policy/authorization/governance for Apache DataFusion
query sessions**. It is two crates:

- **`crates/cedar-oci`** — sources a [Cedar](https://www.cedarpolicy.com/) policy
  set / schema / entities from an OCI registry image (`OciPolicyProvider`, which
  implements both `SimplePolicySetProvider` and `SimpleEntityProvider` from
  `cedar-local-agent`). Also carries generated `hydrofoil.policy` gRPC types — an
  unused remote-PDP surface, not wired into enforcement.
- **`crates/datafusion-policy-cedar`** — the DataFusion-aware enforcement layer (the
  substance). Depends on `cedar-oci`.

Workspace: edition 2024, Rust 1.91, `datafusion 54`, `cedar-policy 4.8.2`,
`cedar-local-agent 3.0.0`. Governance is feature-gated (`fgac`, default
off). The reference *host* that composes these into a real engine is the external
`hydrofoil` repo; lineage lives in a separate sibling repo `headwaters`. In
hydrofoil, lineage + policy shared one DataFusion session by **chaining
`QueryPlanner`s** — a property we must preserve.

## 2. Two evaluations we run (must keep)

1. **Coarse allow/deny gate (Layer 1)** — does the principal have access to the
   tables/actions a query references? Walk the `LogicalPlan`, emit an
   authorization request per accessed securable, deny the query if any is denied.
2. **Fine-grained access control (Layer 2)** — row filters + column masks
   injected into the plan **before optimization** (so they ride
   predicate/projection pushdown). Implemented as a logical-plan rewrite, not an
   optimizer rule.

Plus two experimental themes to preserve:
- **Fact store** — a monotonic, session-scoped *taint ledger* keyed by a
  correlation id. As the engine reads classified columns it records taints; a
  later decision point (e.g. an agent-tool PEP) reads them back to gate an action
  (`forbid send_external when observed_taints.contains("pii")`). This is a
  data-flow control that survives prompt injection because it constrains the
  *action*, not the prompt.
- **Principal sourcing** — the authenticated principal + attributes + group
  membership, read from the session (or enriched from an IdP), never trusted from
  a bare client header.

## 3. Current architecture (the decide / enforce split)

The existing design is already a concrete instance of the **decide / enforce**
split that the whole ecosystem converges on. **Do not rebuild it — refine it.**
These seams are sound and stay:

| Concern | Type / file | Keep? |
| --- | --- | --- |
| **Decide** contract | `Policy` trait — `crates/datafusion-policy-cedar/src/policy.rs` | rename+neutralize (§5) |
| Cedar decide impl | `CedarPolicy<P,E>` — `src/cedar.rs` (generic over policy/entity providers) | becomes the adapter |
| **Enforce** hook | `PolicyQueryPlanner` — `src/rule.rs` | keep as-is |
| Row/mask rewrite | `GovernRewriter` (`TreeNodeRewriter`) — `src/govern.rs` | keep as-is |
| Residual → `Expr` | `ResidualTranslator` trait + `CedarResidualTranslator` — `src/translate.rs` | rename trait (§5) |
| Plan walk → actions | `AuthorizationVisitor` + `PlanAction` enum — `src/visitor.rs` | split (§5) |
| Session wiring | `PolicyExtension`/`PolicyBuilder`/`PolicySessionExt` + `SessionConfig` ext newtypes + provider traits — `src/session.rs` | keep as-is |
| Neutral facts | `TableFacts`/`CatalogFactSink`/`EvalContext` — `src/facts.rs` | keep (move to neutral crate) |
| Taint ledger | `FactStore`/`InMemoryFactStore` — `src/fact_store.rs` | keep (move to neutral crate) |
| Principal | `PrincipalIdentity`/`IdentityProvider` — `src/principal.rs` | neutralize (§4) |

### Why the enforce hook is a `QueryPlanner` wrapper (not an `AnalyzerRule`)

This is a deliberate, **correct** choice — do not "fix" it to an AnalyzerRule.
The DataFusion community's idiomatic RLS/CLS hook *is* an `AnalyzerRule` (see
`datafusion-examples/examples/query_planning/analyzer_rule.rs`, and the fact that
`OptimizerRule` is explicitly wrong because its contract is "same results"). But
`AnalyzerRule::analyze(&self, LogicalPlan, &ConfigOptions)` is **sync** and only
sees `ConfigOptions` — it cannot `await` an async policy decision, cannot read
`&SessionState` for per-request facts, and cannot call `state.optimize()`.
`QueryPlanner::create_physical_plan(&self, plan, &SessionState)` is the only
**async, `&SessionState`-bound** seam around planning. Wrapping it also lets the
policy planner *nest* with the lineage planner (each wrapper delegates
`create_physical_plan` to the inner planner). This mirrors `datafusion-openlineage`.
Tradeoff: a logical-only / optimize-only caller isn't governed by the wrapper —
which is why `authorize_and_govern` (in `session.rs`) is also exposed as a
standalone function for write paths that bypass physical planning.

### How enforcement flows today

`PolicyQueryPlanner::create_physical_plan` → resolves principal (via
`PrincipalProvider`; `None` ⇒ fail-closed `exec_err`) + `EvalContext` (via
`EvalContextProvider`) → `authorize_and_govern(state, plan, policy, principal,
eval)`:
1. `govern_plan` — collect `TableScan`s (`TreeNodeVisitor`), `await` each table's
   `TablePolicy`, record taints, then `GovernRewriter` wraps each governed scan in
   a mask `Projection` (aliased *non-identity* exprs so the optimizer can't absorb
   them) + a row `Filter`.
2. `state.optimize(governed)`.
3. `policy.is_allowed(optimized, …)`; `Deny` ⇒ authorization error.
Then delegate the optimized plan to the inner `QueryPlanner`.

Per-request state rides **`SessionConfig` typed extensions** the host attaches
(`PrincipalExt`, `CatalogFactSinkExt`, `FactStoreExt`), read back by provider
traits (`SessionConfigPrincipalProvider`, `SessionConfigEvalContextProvider`). The
crate never depends on host types. Keep this pattern wholesale — it is the
DataFusion-native way to transport per-request information the user asked us to
lean into.

Fail-closed is pervasive and must be preserved: missing principal, untranslatable
residual, unmodeled state-changing DDL, provider error, TPE error, an unresolvable
masking function → deny/mask, never open.

## 4. The core problem to fix — Cedar leaks through the "neutral" seam

The decide seam is *shaped* neutrally but **leaks Cedar types**, so it cannot host
OPA or OpenFGA:

- `Policy::is_allowed` returns `cedar_oci::Decision`.
- `PrincipalIdentity.uid: cedar_oci::EntityUid`;
  `PrincipalIdentity.attributes: HashMap<String, cedar_policy::RestrictedExpression>`;
  it also carries `group_entities: Vec<cedar_policy::Entity>`.
- `crates/datafusion-policy-cedar/src/lib.rs` re-exports
  `cedar_oci::{Decision, EntityId, EntityTypeName, EntityUid}` and
  `cedar_policy::{Entity, RestrictedExpression}` as the "single import surface" —
  so every consumer of the "neutral" trait imports Cedar.
- The crate is *named* `datafusion-policy-cedar`, structurally implying Cedar is the
  layer rather than one adapter behind it.

The `TablePolicy` carrier (`row_filters: Vec<Expr>`, `column_masks:
HashMap<String, Expr>`) is *already* genuinely neutral (`Expr`s) — that part is
right.

## 5. Prior art that informs the design (already researched)

The decide/enforce split is the industry-convergent pattern. Concrete references:

- **InfluxDB 3.0 / IOx** — coarse authz at the **RPC handler, before planning**
  (`authz` crate: `Authorizer` trait, `Permission { action, resource }`,
  `permissions(token, &[Permission])` returns the granted∩requested intersection;
  `IoxAuthorizer` is a gRPC client to an external service). Tenant isolation is
  **structural** (one namespace's `SchemaProvider` per session ⇒ a plan can't name
  another tenant's tables), not a row filter. Per-request state rides
  `SessionState` config extensions — same seam as our `PrincipalExt`. Takeaway:
  coarse decide as a pluggable trait is validated; prefer catalog isolation for
  *hard* tenant boundaries; convert `Expr` ⇄ a private predicate type at the
  boundary.
- **Spice.ai** — **no in-engine authz** (edge API-key only); governance = handing
  out narrowed datasets. Value is the provider-wrapping stack
  (`AcceleratedTable`→`FederatedTable`→source) and running a **custom analyzer
  rule before the default analyzer**. No prior art for the authz layer itself.
- **DataFusion RLS/CLS consensus** (tracking issue #15192): catalog/policy store
  **decides**, trusted engine **enforces via plan rewrite before optimization**.
  `AnalyzerRule` = the sanctioned hook (may change semantics, rides pushdown, sees
  whole plan); `OptimizerRule` = never (contract is "same results");
  `TableProvider` pushdown = defense-in-depth only (an optimization *offer*, not a
  security channel — `Inexact` is re-applied, only `Exact` trusted). Our
  `QueryPlanner` wrapper is a justified divergence for the async/`&SessionState`
  reasons in §3.
- **Cedar partial eval** — the residual over the *unknown* resource **is** a row
  predicate; this is what `cedar.rs::table_policy` does via
  `is_authorized_partial` + reading residual **EST JSON** (`Policy::to_json`) in
  `translate.rs`. There are now **two** partial-eval paths: the untyped
  `partial-eval` we use (leaves `true &&` guards, can emit ill-typed residuals —
  which our fail-closed arms handle), and the newer **type-aware `tpe`** (RFC 95,
  `PolicySet::tpe(&PartialRequest, &PartialEntities, &Schema)`), which guarantees
  well-typed residuals but requires the policy bundle to ship a validated `Schema`.
- **OPA** (Rego) — partial evaluation via `POST /v1/compile` with `unknowns`
  returns a residual (compilable to SQL `WHERE` / an IR called UCAST); embeddable
  in Rust via `regorus`. Direct analog of Cedar residuals, different language.
- **OpenFGA** (ReBAC/Zanzibar) — `Check` (bool) + **`ListObjects`** (returns the
  permitted object-id set → an `IN (…)` / semi-join filter — a *materialized* set,
  mind pagination/large sets). No mature first-party Rust SDK.

**Minimal common decide surface** — each engine returns a different fine-grained
shape, all reducible to our neutral `TablePolicy`:

| Engine | Coarse | Fine-grained → carrier |
| --- | --- | --- |
| Cedar (`partial-eval`/`tpe`) | `Decision` | residual boolean → predicate `Expr`s |
| OPA (`/v1/compile`) | bool | residual conditions → UCAST → predicate `Expr`s |
| OpenFGA | `Check` bool | id set from `ListObjects` → `col(id).in_list(...)` |

## 6. Decisions already made (do not re-litigate)

1. **Scope: prove the seam only.** Refactor to a neutral core + Cedar adapter so
   OPA/OpenFGA *could* plug in. **Do not** build or scaffold OPA/OpenFGA adapters
   this iteration. The neutrality grep-gate (below) is what proves the seam admits
   them.
2. **Crate split: full split now.** Create a new neutral `datafusion-policy` crate
   and slim `datafusion-policy-cedar` to just the adapter. Rename `Policy` →
   `PolicyEngine` and `ResidualTranslator` → `ConstraintTranslator`. Stop
   re-exporting Cedar types from the neutral surface.
3. **Cedar `tpe` migration: follow-up PR, not now.** Keep the untyped
   `partial-eval` path in this work; migrate to `tpe` separately afterward.

## 7. Work plan (small, well-scoped commits — release-plz reads them)

Do the neutralization *before* the physical crate move so the move is a pure
relocation.

1. **`refactor: introduce neutral Decision + AttrValue types`**
   Add a neutral `enum Decision { Allow, Deny }` and a neutral principal attribute
   value type in `datafusion-policy-cedar` (temporary home). Cedar adapter maps
   `cedar_policy::Decision` → neutral `Decision`.
   ```rust
   pub enum AttrValue { String(String), Long(i64), Bool(bool), Set(Vec<AttrValue>) }
   ```
2. **`refactor: engine-neutral PrincipalIdentity, move Cedar entity-building to adapter`**
   `PrincipalIdentity` becomes:
   ```rust
   pub struct PrincipalIdentity {
       pub uid: String,                            // opaque to the core, e.g. "User::\"alice\""
       pub attributes: HashMap<String, AttrValue>, // NOT RestrictedExpression
       pub groups: Vec<String>,                    // no cedar Entity closure here
   }
   ```
   Move `to_entities()` / group-closure / `RestrictedExpression`/`Entity`
   construction from `principal.rs` into `cedar.rs` (adapter builds Cedar entities
   from the neutral principal). `IdentityProvider`/`PrincipalEnrichment` stay
   neutral, returning `AttrValue`/group strings.
3. **`refactor: rename Policy → PolicyEngine, ResidualTranslator → ConstraintTranslator`**
   New trait shape (Layer 2 + tool behind `fgac` as today):
   ```rust
   #[async_trait]
   pub trait PolicyEngine: Debug + Send + Sync {
       async fn is_allowed(&self, plan: &LogicalPlan, principal: &PrincipalIdentity,
                           eval: &EvalContext) -> Result<Decision>;
       async fn constrain(&self, table: &TableReference, schema: &DFSchema,
                          principal: &PrincipalIdentity, eval: &EvalContext) -> Result<TablePolicy>;
       async fn tool_policy(&self, action: &str, principal: &PrincipalIdentity,
                            observed_taints: &BTreeSet<String>) -> Result<Decision>;
   }
   ```
   Keep `StaticPolicy` (rename to match) as the non-Cedar impl proving the trait
   needs no Cedar. `TablePolicy` carrier unchanged; document `col(id).in_list(...)`
   as a supported row-filter shape (for OpenFGA later).
4. **`refactor: split datafusion-policy (neutral) out of datafusion-policy-cedar`**
   Create `crates/datafusion-policy`. Move into it: `engine.rs` (ex-`policy.rs`),
   neutral `PrincipalIdentity`/`IdentityProvider`, `facts.rs`, `fact_store.rs`,
   `govern.rs`, `rule.rs`, `session.rs`, the `ConstraintTranslator` *trait*, and
   the **neutral half of `visitor.rs`** (`AuthorizationVisitor` + `PlanAction`
   enum — the "what does the plan touch" analysis every engine needs). Leave in
   `datafusion-policy-cedar`: `CedarPolicyEngine` (ex-`CedarPolicy`), Cedar
   request-building (`authorize_plan`, `table_context`, `tool_context`, action
   `EntityUid` statics, `PlanRequest`), the Cedar residual→`TablePolicy` mapping,
   and `CedarResidualTranslator`. Expose the neutral `PlanAction` list to the
   adapter via a small pub API. Update root `Cargo.toml` members + intra-workspace
   deps; `datafusion-policy-cedar` now depends on `datafusion-policy` + `cedar-oci`.
   Fix `lib.rs` re-exports so the neutral crate exports **no** Cedar types.
5. **`docs: document the pluggable decide/enforce architecture`**
   A short `docs/` page: the decide/enforce split, the `PolicyEngine` adapter
   contract, and where OPA/OpenFGA would plug in (from §5's table). This handover
   doc can seed it.

**Follow-up PR (separate, not part of the above):**
6. **`feat(cedar): migrate residual path to type-aware partial eval (tpe)`**
   Swap `is_authorized_partial` (`partial-eval`) for `PolicySet::tpe(…)` (`tpe`
   feature). Removes the `true &&`-guard folding and ill-typed-residual arms in
   `translate.rs`/`cedar.rs`. Requires the OCI bundle to ship a validated Cedar
   `Schema` — `cedar-oci` already parses a schema layer; wire it through.

### Representative files to touch (steps 1–4)
`crates/datafusion-policy-cedar/src/{lib,policy,principal,cedar,translate,visitor,facts,fact_store,govern,rule,session}.rs`,
root `Cargo.toml`, `crates/datafusion-policy-cedar/Cargo.toml`, new
`crates/datafusion-policy/Cargo.toml` + `src/lib.rs`.

## 8. Non-goals / out of scope

- **No** move to an `AnalyzerRule` — the `QueryPlanner` wrapper is the right hook
  (async + `&SessionState`); validated against DataFusion guidance and IOx/Spice.
- **No** custom `TableProvider`/`CatalogProvider` for enforcement — pushdown is an
  optimization channel, not a security boundary (defense-in-depth only).
- **No** OPA/OpenFGA adapters or stub crates this iteration (decided: prove the
  seam only).
- **No** wiring of the `hydrofoil.policy` gRPC remote-PDP path.
- **No** lineage code here (lives in `headwaters`); only preserve the
  planner-chain composability that lets lineage + policy share a session.

## 9. Verification

- `cargo build --workspace` **and** `cargo build --workspace --features fgac`
  — both crates must compile with governance on and off.
- `cargo test --workspace --all-features` — the existing suites (`cedar.rs`,
  `govern.rs`, `visitor.rs`, `translate.rs`, `fact_store.rs`, `facts.rs`,
  `rule.rs`) must pass unchanged after the move. They are the regression guard for
  the enforce mechanics and fail-closed behavior — treat any change to their
  *assertions* as a red flag.
- **Neutrality grep-gate** (the invariant that proves pluggability): after the
  split, `crates/datafusion-policy/src` must contain **zero** `cedar_policy::` or
  `cedar_oci::` imports. Worth encoding as a tiny CI check or a test.
- `cargo run -p olai-datafusion-policy-cedar --example fact_gathering_walkthrough --features fgac`
  still runs end-to-end. Caveat: it reads `config/policies/` fixtures that live in
  the host repo, so it may only run in a host checkout — confirm current behavior
  before and after so you know whether a break is real.
- `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`
  before committing (CI gates on these; MSRV/edition are in the workspace
  `Cargo.toml`).

## 10. House rules (from the repo/user conventions)

- Branch first; never work on `main`. Prep fully (commit → push → open PR)
  without waiting on commit signing; surface a single sign+force-push command at
  the end.
- Commit messages: `<type>: <subject>` + body + a required `AI-assisted-by: Isaac`
  trailer. Prefer several small well-scoped commits (matches the step list above)
  over one large one — release-plz derives the changelog from them.
- End PR bodies with: `This pull request was AI-assisted by Isaac.`
