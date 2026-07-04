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
that proves the trait needs no policy engine at all.

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

## Related

- [`docs/policy-fact-gathering.md`](policy-fact-gathering.md) — the fact-locality
  model (local-ephemeral catalog facts vs. shared-session-scoped taints) and the
  end-to-end walkthrough (`fact_gathering_walkthrough` example).
