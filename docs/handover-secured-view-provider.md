# Handover S1: secured-view provider seam (`GovernedTableProvider`)

| | |
|---|---|
| **Status** | DONE |
| **Repo / branch** | breakwater / `feat/secured-view-provider` (branch off `main`) |
| **Recommended model** | **Fable** — novel, correctness-critical TableProvider wrapper with several subtle hazards |
| **Depends on** | nothing (first session; S4 and S6 depend on this) |
| **Scope** | Plan steps W1, W2, W4, W5 |

## Context

Today FGAC enforcement lives only in a `QueryPlanner` wrapper (`PolicyQueryPlanner`,
`crates/datafusion-policy/src/rule.rs:63-97`): at physical-planning time, `govern_plan`
(`crates/datafusion-policy/src/govern.rs:76-114`) collects `TableScan`s, awaits
`PolicyEngine::constrain` per table, and rewrites each scan into
`Filter(row_filters, Projection(masks, TableScan))`.

We are adding a **second, primary placement**: hosts with an async catalog resolver (hydrofoil
resolves UC tables per query, per principal) should be able to hand back a **secured view** at
`TableProvider`-construction time — before any planning happens. The planner tier stays as coarse
gate (`is_allowed`) + taint recording + **backstop** for tables that never pass through a resolver
(locally registered tables). A per-table marker keeps the two tiers mutually exclusive so nothing
is double-masked and nothing slips through.

### Verified load-bearing facts (do not re-derive)

- **DataFusion 54 inlines `get_logical_plan()` at logical-plan *build* time** — not via an
  analyzer rule. `datafusion-expr-54/src/logical_plan/builder.rs:516-520`
  (`scan_with_filters_inner`): when `TableScan.filters` is empty (always true at SQL-build time)
  and the `TableSource` returns `Some(plan)`, the plan is inlined wrapped in
  `SubqueryAlias(table_name)`. Qualified references stay stable, so downstream column resolution
  and user aliases are untouched, and every self-join occurrence inlines independently.
- **`insert_to_plan` never consults `get_logical_plan`**
  (`datafusion-sql-54/src/statement.rs:2358` uses only `table_source.schema()`); the physical
  planner calls `provider.insert_into`, which we delegate. INSERT into a governed table works by
  delegation.
- The optimizer-interaction guarantees are already proven for this exact plan shape by
  `govern.rs` tests (`mask_survives_optimizer`, `user_predicate_does_not_push_through_mask`,
  `row_filter_pushes_toward_scan`, `govern.rs:504-633`): the governance row filter pushes into the
  scan, and a user predicate on a masked column is rewritten *through* the mask projection
  (`ssn = 'a'` becomes `'***' = 'a'`), never touching raw values.

## Steps (one conventional commit each)

### W1 — `feat(datafusion-policy)!: enable fgac by default` (or non-breaking if feasible)

Flip the `fgac` cargo feature to default-on in **both** `crates/datafusion-policy/Cargo.toml` and
`crates/datafusion-policy-cedar/Cargo.toml`. Keep the feature itself as an opt-out for minimal
builds (`default-features = false`). Runtime enable/disable becomes `Posture` in session S4 — this
commit only removes the compile-time footgun of two crates × one feature that hosts forget.

*Proof:* both crates and the sibling hydrofoil checkout (`../hydrofoil`, has path overrides) build
with no feature flags; existing suites green.

### W2 — `refactor(datafusion-policy): extract shared apply_table_policy`

Factor the mask-projection + row-filter assembly out of `GovernRewriter::f_up`
(`src/govern.rs:147-183`) into a shared helper:

```rust
pub(crate) fn apply_table_policy(
    plan: LogicalPlan,            // the TableScan (or scan built over a provider)
    schema: &DFSchema,
    policy: &TablePolicy,
) -> Result<LogicalPlan>;
```

Both tiers must produce the byte-identical `Filter(row_filters AND-reduced,
Projection(masks, scan))` shape — one enforcement shape, two placements. While here, add
**type preservation**: wrap each mask expression in `CAST(mask AS <original column type>)` so a
masked column keeps its name (`alias_qualified`, already done at `govern.rs:162-174`) *and* its
`DataType`. `DESCRIBE`/information_schema must be indistinguishable from the base table.

*Proof:* existing govern.rs unit + optimizer tests stay green; new test asserting the masked
field's `DataType` equals the original (e.g. mask over an `Int64` column).

### W4 — `feat(datafusion-policy): governed-set marker on CatalogFactSink`

Add `mark_governed(&self, table: TableReference)` / `is_governed(&self, table: &TableReference)`
to `CatalogFactSink` (`src/facts.rs:104-134`; reuse its `normalize()` keying). `govern_plan`
(`src/govern.rs:76-114`) skips constraining marked tables — **taint recording
(`record_taints`, `govern.rs:120-136`) still runs for them**. The marker is what makes the two
tiers mutually exclusive per (table, query): the sink is per-session/per-query scoped and
re-populated on every resolution, so staleness is not a concern.

*Proof:* unit — a marked table gets no second filter/mask from `govern_plan`; an unmarked table
in the same plan still does; taints recorded for both.

### W5 — `feat(datafusion-policy): GovernedTableProvider + govern_provider seam`

New module `src/provider.rs` (under the `fgac` feature), the headline API:

```rust
/// Wrap `provider` in a secured view enforcing `policy.constrain(...)`.
/// Returns `provider` unchanged (same Arc) when no constraints apply.
/// Marks `table_ref` governed in `eval.catalog_facts` so the planner-tier
/// govern pass skips it. Errors propagate (fail-closed resolution).
pub async fn govern_provider(
    provider: Arc<dyn TableProvider>,
    table_ref: &TableReference,
    policy: &dyn PolicyEngine,
    principal: &PrincipalIdentity,
    eval: &EvalContext,
) -> Result<Arc<dyn TableProvider>>;

/// One-call host seam: assembles engine (PolicyEngineExt), principal (PrincipalExt),
/// and eval context from SessionConfig extensions, then delegates to govern_provider.
pub async fn govern_provider_from_config(
    config: &SessionConfig,
    provider: Arc<dyn TableProvider>,
    table_ref: &TableReference,
) -> Result<Arc<dyn TableProvider>>;
```

`GovernedTableProvider` fields: `base: Arc<dyn TableProvider>`, governed `plan: LogicalPlan`,
`schema: SchemaRef`. The governed plan is built via
`LogicalPlanBuilder::scan(table_ref, provider_as_source(base), None)` + `apply_table_policy`
(W2). The base provider's `get_logical_plan()` is `None`, so there is no recursive inlining.

Trait impl decisions (each one is load-bearing):

- `get_logical_plan()` → `Some(&plan)` — the inlining mechanism (verified fact above).
- `schema()` → governed plan schema (masked columns keep name + type per W2).
- `table_type()`, `insert_into()`, `constraints()`, `get_column_default()` → **delegate to base**.
  This is why we do NOT use `ViewTable`: its `table_type()` is hardcoded `View` (breaks
  `SHOW TABLES`), it has no `insert_into`, and its `scan()` re-enters
  `state.create_physical_plan` (re-enters the host's QueryPlanner).
- `scan()` → ViewTable-style fallback (plan → `state.create_physical_plan`) for any path that
  bypasses `LogicalPlanBuilder`. Effectively unreachable in hydrofoil; document the re-entrancy
  caveat in the rustdoc. The W4 marker makes accidental re-entry idempotent.
- `supports_filters_pushdown()` → `Exact` for all (mirrors `ViewTable`; only relevant on the
  `scan()` fallback path — the inline branch fires when `TableScan.filters` is empty).
- `statistics()` → **`None`**. Base stats describe pre-filter row counts — returning them leaks
  and mis-plans.
- Also expose `fn base(&self) -> &Arc<dyn TableProvider>` for hosts that need downcasts.

Semantics:

- Empty `TablePolicy` ⇒ return the **same Arc** unwrapped (no downcast breakage for ungoverned
  tables; hydrofoil currently has no downcasts on governed paths, verified by grep, but don't
  make it worse).
- `constrain` error ⇒ propagate (resolution fails closed).
- `deny_all_rows` (`row_filters == vec![lit(false)]`, see `datafusion-policy-cedar/src/cedar.rs:475`)
  ⇒ ordinary filter; optimizes to an empty scan. Correct — no special case.
- **Coarse Deny stays at the planner.** `constrain` is read-shaped (`read_table`); a read-denied
  principal may still be allowed to INSERT, and only `is_allowed` sees the whole plan (writes, UC
  DDL extension nodes). Do not gate resolution on `is_allowed`.

Also in this commit: `PolicyEngineExt(pub Arc<dyn PolicyEngine>)` as a `SessionConfig` extension
in `src/session.rs`, set by `PolicyBuilder::instrument` (`session.rs:263-283`) too, so the engine
is discoverable from config on every host regardless of which tier fires first.

Nothing in this module may name Cedar — the neutrality test
(`crates/datafusion-policy/tests/neutrality.rs`) must stay green.

*Proof (unit tests over `MemTable`):*
- masked/filtered SELECT through a session that registers the wrapper;
- schema (names + types) identical to base;
- self-join of the governed table (two independent inlines, no alias collision);
- `INSERT INTO` the governed wrapper appends via delegation;
- empty policy returns the same `Arc` (pointer equality);
- `deny_all_rows` ⇒ 0 rows;
- `govern_plan` over a plan containing the inlined view adds nothing (W4 marker respected),
  while an unmarked second table in the same query is still constrained.

## Done criteria

- All four commits on `feat/secured-view-provider`, `cargo fmt --all` clean,
  `cargo clippy --all-targets --all-features -- -D warnings` clean, `cargo test` green
  (also with `--no-default-features` for the opt-out path).
- Sibling hydrofoil checkout still builds against the branch via its path overrides (do not
  commit anything in hydrofoil — that's session S6).
- PR opened; flip this doc's Status to DONE in the PR.

## Explicitly out of scope

Cedar table-tag folding (S2, `cedar.rs`), `PolicyBinding`/`AbacPolicyEngine` (S3), `Governance`
builder + `Posture` (S4), all hydrofoil wiring (S6/S7), `CompositePolicyEngine`, auth
interceptor, agent-tool PEP, `VERSION AS OF`.

## Workflow

Machine-wide conventions apply (`~/.claude/CLAUDE.md`): conventional commits with the
`AI-assisted-by: Isaac` trailer, commit unsigned (`git commit --no-gpg-sign`), push and open the
PR without waiting, then surface the single bulk sign + force-push command (rebase on
**origin/main**, not local main).
