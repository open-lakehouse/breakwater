# The pluggable decide / enforce architecture

`breakwater` provides policy/authorization/governance for Apache DataFusion
query sessions. Its design is a concrete instance of the **decide / enforce**
split the authorization ecosystem converges on: a policy engine *decides* what is
allowed, and a trusted engine *enforces* the decision. The two halves live in two
crates:

- **`datafusion-policy`** — the engine-agnostic core. It owns the decide contract
  and the enforcement machinery, expressed entirely in neutral types. It names no
  policy engine.
- **`datafusion-policy-cedar`** — a Cedar *adapter* behind that seam. It implements the
  decide contract with [Cedar](https://www.cedarpolicy.com/) and does all
  Cedar-specific lowering.

An OPA or OpenFGA adapter could sit alongside `datafusion-policy-cedar` without touching
the core. Proving that seam admits them — not building them — is the point of the
split.

## Decide: the `PolicyEngine` trait

`datafusion_policy::PolicyEngine` is the contract every engine implements. It is
expressed in neutral types only — `Decision`, `AttrValue`, `PrincipalIdentity`,
`TableFacts`, and DataFusion `Expr`s — so nothing about a specific engine leaks
to its callers.

```rust,ignore
#[async_trait]
pub trait PolicyEngine: Debug + Send + Sync {
    // Layer 1: coarse allow/deny over the tables/actions a query references.
    async fn is_allowed(&self, plan: &LogicalPlan, principal: &PrincipalIdentity,
                        eval: &EvalContext) -> Result<Decision>;

    // Layer 2 (feature `fgac`): the fine-grained constraints (row filters +
    // column masks) that apply when `principal` reads `table`.
    async fn constrain(&self, table: &TableReference, schema: &DFSchema,
                       principal: &PrincipalIdentity, eval: &EvalContext)
        -> Result<TablePolicy>;

    // Agent-tool PEP (feature `fgac`): gate an action on the session's
    // accrued taints — a data-flow control that survives prompt injection.
    async fn tool_policy(&self, action: &str, principal: &PrincipalIdentity,
                         observed_taints: &BTreeSet<String>) -> Result<Decision>;
}
```

`StaticPolicyEngine` (a fixed `Allow`/`Deny`) is the non-engine implementation
that proves the trait needs no policy engine at all. `AbacPolicyEngine`
(feature `fgac`) is a second neutral, engine-free implementation: it reads
attribute-based bindings (the UC-ABAC-shaped `PolicyBinding` model — governed
tags + `CREATE POLICY`-style row filters / column masks) straight from the
per-query catalog facts, with no external policy engine. Its `is_allowed` is
always `Allow` (ABAC has no coarse gate; privileges — or a composed engine —
own deny); its `constrain` derives the row filters and column masks from the
bindings that match the principal.

### The two evaluations

1. **Coarse allow/deny gate (Layer 1).** Does the principal have access to the
   tables/actions a query references? The neutral plan walk
   (`datafusion_policy::plan_actions`) classifies the `LogicalPlan` into a list of
   `PlanAction`s (read/write/create table, Unity DDL, an unmodeled-node deny
   sentinel); the adapter lowers each to an authorization request and denies the
   query if any is denied.
2. **Fine-grained access control (Layer 2).** Row filters + column masks injected
   into the plan **before optimization** (so they ride predicate/projection
   pushdown), via `govern_plan` — a logical-plan rewrite, not an optimizer rule.

## Enforce: the `QueryPlanner` wrapper

Enforcement lives in `PolicyQueryPlanner`, a wrapper around the session's
`QueryPlanner`. This is a deliberate choice. The DataFusion-idiomatic RLS/CLS hook
is an `AnalyzerRule`, but `AnalyzerRule::analyze` is **sync** and sees only
`ConfigOptions` — it cannot `await` an async policy decision, read `&SessionState`
for per-request facts, or call `state.optimize()`.
`QueryPlanner::create_physical_plan(&self, plan, &SessionState)` is the only
**async, `&SessionState`-bound** seam around planning. Wrapping it also lets the
policy planner *nest* with other planner-wrapping extensions (e.g. lineage): each
wrapper delegates `create_physical_plan` to the inner planner. (For write paths
that bypass physical planning, `authorize_and_govern` is exposed as a standalone
function.)

The flow per query: resolve the principal (fail-closed if unbound) and the
`EvalContext`, then `authorize_and_govern`:

1. `govern_plan` — collect `TableScan`s, `await` each table's constraints via
   `PolicyEngine::constrain`, record taints, and wrap each governed scan in a mask
   `Projection` (aliased non-identity exprs, so the optimizer can't absorb them)
   and a row `Filter`.
2. `state.optimize(governed)`.
3. `PolicyEngine::is_allowed(optimized, …)`; `Deny` ⇒ authorization error.

Then delegate the optimized plan to the inner planner.

Per-request state (principal, catalog facts, the taint ledger) rides
`SessionConfig` typed extensions the host attaches, read back by provider traits —
so neither crate depends on host types.

**Fail-closed is pervasive:** missing principal, untranslatable residual,
unmodeled state-changing DDL, provider error, a `column_mask` without a resolvable
column → deny/mask, never open.

### Two enforcement placements

Fine-grained governance can be applied at either of two points, and they are
mutually exclusive per `(table, query)` so nothing is ever double-masked:

1. **Resolver-time secured view** (`GovernedTableProvider`, feature `fgac`) — a
   host that resolves tables through the catalog can wrap a base `TableProvider`
   in a governed one at *resolution* time (`govern_provider` /
   `govern_provider_from_config`, the latter reading the engine back from the
   `PolicyEngineExt` on `SessionConfig`). The secured view carries the same
   `Filter(row_filters, Projection(masks, scan))` shape `govern_plan` produces,
   built over the base provider — so a table is governed the moment it is named,
   before any plan rewrite.
2. **Planner backstop** (`govern_plan` inside `PolicyQueryPlanner`) — the
   pre-optimize plan rewrite described above, for every `TableScan` the plan
   reads.

**The governed-set marker.** When the resolver tier secures a table it calls
`CatalogFactSink::mark_governed(table)`. `govern_plan` skips any table marked
governed (it was already secured upstream) while still recording its taints —
this is what keeps the two tiers mutually exclusive without losing the taint
ledger. A host uses whichever tier fits its resolution path; both read the same
`PolicyEngine` and produce the same enforcement shape.

## The neutral constraint carrier

Every engine returns a different fine-grained shape, all reducible to one neutral
carrier, `datafusion_policy::TablePolicy` (`row_filters: Vec<Expr>`,
`column_masks: HashMap<String, Expr>`). Any boolean `Expr` over the table's
columns is a valid row filter — including `col("id").in_list(...)` for a
set-membership filter (how an OpenFGA id set would enforce).

The residual → `Expr` translation is itself a seam: `ConstraintTranslator` (a
trait with an associated `Residual` type, so it too names no engine type). The
Cedar adapter's `CedarResidualTranslator` sets `Residual = cedar_policy::Policy`.

## Where each engine plugs in

The decide surface reduces every engine's coarse and fine-grained shapes to the
neutral contract:

| Engine | Coarse (`is_allowed`) | Fine-grained (`constrain` → `TablePolicy`) |
| --- | --- | --- |
| **Cedar** (`partial-eval` / `tpe`) | `Decision` from `is_authorized` | partial-eval residual boolean → predicate `Expr`s |
| **OPA** (Rego, `/v1/compile`) | `bool` | residual conditions → UCAST → predicate `Expr`s |
| **OpenFGA** (ReBAC / Zanzibar) | `Check` bool | `ListObjects` id set → `col(id).in_list(...)` row filter |

An adapter for OPA or OpenFGA would:

1. Implement `PolicyEngine`: map its native decision to `Decision`, and its
   fine-grained result to `TablePolicy`.
2. Lower the neutral `PrincipalIdentity` (opaque uid string, `AttrValue`
   attributes, `Group` hierarchy) to its own request shape — the analog of
   `datafusion-policy-cedar`'s `cedar_entity` module.
3. Optionally implement `ConstraintTranslator` for its residual type — the analog
   of `CedarResidualTranslator`.

Nothing in `datafusion-policy` changes. The invariant that keeps it that way is
enforced by a test: `crates/datafusion-policy/tests/neutrality.rs` fails if any
engine type is named in the neutral core.

## What stays in the adapter

`datafusion-policy-cedar` holds everything Cedar-specific: `CedarPolicyEngine`, the
Cedar request-building that lowers `PlanAction`s to Cedar requests, the neutral
principal → Cedar entity lowering (`cedar_entity`), the Cedar residual →
`TablePolicy` mapping, and `CedarResidualTranslator`. It re-exports the neutral
core's public surface so a Cedar host imports a single crate.

## The host recipe: `Governance` + `Posture`

Wiring the pieces by hand — bind the principal as a `PrincipalExt` *before*
installing the planner, populate a `CatalogFactSinkExt` per query, set the
`PolicyEngineExt`, the `FactStoreExt`, the `FunctionResolverExt`, and remember to
call `IdentityProvider::enrich` — is error-prone, and every omission fails
*open* (a forgotten engine silently degrades to `StaticPolicyEngine(Allow)`).
`datafusion_policy::Governance` is the one-obvious-way assembly that removes that
burden. It is built once per server:

```rust,ignore
let gov = Governance::builder()
    .posture(Posture::Enforcing)
    .engine(engine)                 // Arc<dyn PolicyEngine>
    .identity_provider(idp)         // optional
    .function_resolver(resolver)    // optional (fgac)
    .fact_store(store)              // optional (fgac); defaults to InMemoryFactStore
    .build()?;                      // Enforcing + no engine => Err at startup
```

Per session / per request:

- `gov.bind_principal(claims, base).await?` runs the identity-provider
  enrichment (fail-closed under `Enforcing`) and folds it onto the principal.
- `gov.attach(config, principal)` sets **all** the `SessionConfig` extensions in
  one call, taking the principal as a required argument — so a missing principal
  is unrepresentable at the call site.
- `gov.instrument(state)` wraps the planner at the profile's posture. A host that
  composes its own `QueryPlanner` (e.g. one sequencing policy + lineage) reads
  `gov.engine()` and the provider accessors and builds the composed planner
  itself instead.

### `Posture` — the enforcement stance

Ungoverned operation is never the accidental result of a forgotten wire-up; it
is one explicit, build-time choice:

| Posture | Coarse gate + constraints | On `Deny` | Masks/filters | Unbound principal |
| --- | --- | --- | --- | --- |
| `Disabled` | not evaluated (no planner installed) | — | — | — |
| `Permissive` | **evaluated**, logged (`decision`, `would_block`, `would_constrain`) | logs, does **not** error | **not applied** | passes through |
| `Enforcing` | evaluated | authorization error | applied | fails closed |

`Permissive` is the rollout / dry-run stance: it reuses the exact evaluation
path of `Enforcing`, so the decisions it *logs* are the ones enforcement *would*
have applied — you can watch what a policy will do before turning it on. The
posture is fixed inside `PolicyQueryPlanner` at construction, so a session's
stance cannot drift mid-flight. `build()` validates completeness at startup:
`Permissive`/`Enforcing` require an engine, and `Enforcing` warns when no
function resolver is configured (a policy naming a masking function would
otherwise fail closed at query time).

## Related

- [`docs/policy-fact-gathering.md`](policy-fact-gathering.md) — the fact-locality
  model (local-ephemeral catalog facts vs. shared-session-scoped taints) and the
  end-to-end walkthrough (`fact_gathering_walkthrough` example).
- [`docs/typed-fgac-seams.md`](typed-fgac-seams.md) — how governed tags, TPE
  residuals, and catalog functions become `TablePolicy` row filters / masks.
