# Handover S3: neutral `PolicyBinding` model + `AbacPolicyEngine`

| | |
|---|---|
| **Status** | DONE |
| **Repo / branch** | breakwater / `feat/abac-policy-engine` (branch off `main`) |
| **Recommended model** | **Opus** — new engine logic, but pure data-driven functions over plain structs; design fully specified below |
| **Depends on** | nothing (parallel to S1/S2/S5; S4 and S7 depend on this) |
| **Scope** | Plan steps W6, W7 |

## Context

Databricks Unity Catalog ABAC binds principals × tag-matched securables/columns → ROW FILTER /
COLUMN MASK UDFs (`CREATE POLICY ... TO principals EXCEPT ... WHEN has_tag_value(...) MATCH
COLUMNS has_tag_value(...) AS alias ... USING COLUMNS (...)`). Our UC server (sibling repo
mangrove) is gaining a `/policies` endpoint (session S5). We want hosts to enforce those
policies **without hand-authoring Cedar**.

**Confirmed decision: a direct data-driven engine, not a UC→Cedar compiler.** Rationale: UC ABAC
policies are additive constraints with no deny verdicts — Cedar TPE's power (arbitrary residuals,
forbid semantics) is unused, and a compiler would debug every issue through generated cedarschema
artifacts. The engine needs **no UC client**: policies are *facts*, fetched per-securable at
catalog-resolution time by the host (exactly like governed tags today) and delivered on
`TableFacts`. The engine is then a pure function `(bindings, facts, principal) → TablePolicy`,
with zero catalog and zero Cedar dependencies — it belongs in the neutral crate
`olai-datafusion-policy`, next to `StaticPolicyEngine`. This also makes the Cedar/OCI path
optional for UC-only deployments.

Key existing surfaces (all in `crates/datafusion-policy/src/`):

- `PolicyEngine` trait — `engine.rs:31-84`: `is_allowed(plan, principal, eval)` +
  `constrain(table, schema, principal, eval) -> TablePolicy` (fgac).
- `TablePolicy` — `govern.rs:30-46`: `row_filters: Vec<Expr>` (conjunctive),
  `column_masks: HashMap<String, Expr>` (mask expr must not be a bare column).
- `TableFacts` — `facts.rs:28-53`: has `governed_tags: BTreeMap<String,String>` and
  `governed_column_tags: HashMap<String, BTreeMap<String,String>>`.
- `EvalContext` — `facts.rs:144-163`: `catalog_facts: CatalogFactSink`, optional
  `function_resolver: Option<Arc<dyn CatalogFunctionResolver>>`.
- `CatalogFunctionResolver` — `function.rs:37-40`: `resolve(name) -> Arc<ScalarUDF>`.
- `PrincipalIdentity` — `principal.rs:31-44`: `uid: String` (opaque, e.g. `User::"alice"`),
  `groups: Vec<String>`.

The neutrality test (`tests/neutrality.rs`) must stay green — nothing here may name Cedar or UC.

## Steps (one conventional commit each)

### W6 — `feat(datafusion-policy): neutral PolicyBinding model on TableFacts`

New module `src/binding.rs` (fgac feature), strings only, `Clone + Debug + PartialEq + Eq`,
mirroring the Databricks Policies API shape without UC types:

```rust
pub enum BindingKind { RowFilter, ColumnMask }

/// hasTag(key) when value is None; hasTagValue(key, value) otherwise.
pub struct TagCondition { pub key: String, pub value: Option<String> }

/// A column-tag matcher: columns whose governed tags satisfy `condition`,
/// exposed to the function under `alias`.
pub struct ColumnMatch { pub condition: TagCondition, pub alias: String }

pub enum FunctionArg { Alias(String), Constant(String) }

pub struct PolicyBinding {
    pub name: String,
    pub kind: BindingKind,
    pub to_principals: Vec<String>,        // plain names (users/groups); "account users" == all
    pub except_principals: Vec<String>,
    pub when_condition: Vec<TagCondition>, // table-tag conjunction; empty = always applies
    pub match_columns: Vec<ColumnMatch>,   // for masks: first match is the masked input column
    pub function: String,                  // catalog-qualified UDF name
    pub using_args: Vec<FunctionArg>,
}
```

`TableFacts` gains `pub policies: Vec<PolicyBinding>` (`facts.rs`) — the
**already-inheritance-folded** set applying to this table (catalog → schema → table union is the
host's/UC-server's job, not the engine's). Extend `TableFacts::is_empty()` accordingly.

*Proof:* unit — `is_empty` semantics, Eq round-trip.

### W7 — `feat(datafusion-policy): AbacPolicyEngine`

New module `src/abac.rs` (fgac feature), `AbacPolicyEngine` implementing `PolicyEngine`:

- `is_allowed` → `Decision::Allow`. UC ABAC has no coarse gate; coarse deny is Unity Catalog
  privileges' job (or a composed Cedar engine's — composite engine is a later session).
- `constrain(table, schema, principal, eval) -> TablePolicy`:
  1. `eval.catalog_facts.get(table)` → iterate `facts.policies`.
  2. **Principal match** via a small `PrincipalMatcher` seam (trait with a default impl, so hosts
     can override): normalizes `User::"alice"` ↔ `alice` (strip an `EntityType::"..."` wrapper if
     present) for both `principal.uid` and each of `principal.groups`; binding applies iff
     (`to_principals` matches uid or any group, with a documented "all-users" sentinel) AND NOT
     (`except_principals` matches). Case-sensitive.
  3. **Table condition**: every `TagCondition` in `when_condition` must be satisfied by
     `facts.governed_tags` (key present; value equal when `Some`). Empty conjunction = always.
  4. **Column matching** (masks): for each `ColumnMatch`, candidate columns =
     `facts.governed_column_tags` entries satisfying the condition, **intersected with the
     `schema`'s columns** (don't mask columns not in this scan).
  5. **RowFilter binding** → resolve `binding.function` via `eval.function_resolver` and emit the
     call `Expr` into `row_filters`, args = `using_args` mapped (`Alias` → the column matched by
     the alias's `ColumnMatch` → `col(...)`; `Constant` → literal). **Missing resolver or
     unresolvable filter function ⇒ `Err`** — a row filter that can't be built must fail the
     query, not silently return all rows.
  6. **ColumnMask binding** → for each matched column: mask expr = resolved fn call with
     `col(column)` as arg 0 + `using_args` extras. **Unresolvable mask fn ⇒ the `"***"` literal
     fallback** — same fail-closed contract as the Cedar path
     (`datafusion-policy-cedar/src/cedar.rs:772-799`, `DEFAULT_MASK` at `cedar.rs:471`).
  7. Multiple matching row-filter bindings AND together (they land in `row_filters` — already
     conjunctive per `govern.rs:30-46`). Multiple mask bindings on the same column: first match
     wins, in binding order — document this; UC applies one mask per column.

Export both modules from `lib.rs`; re-export through `datafusion-policy-cedar/src/lib.rs:34-62`
like the rest of the neutral surface (hydrofoil imports through the cedar crate's re-exports).

*Proof (unit, plain structs — no mangrove, no Cedar):*
- principal matching: uid, group, except-overrides-to, all-users sentinel, `User::"..."`
  normalization both directions;
- when_condition: empty, key-only, key+value, multi-condition conjunction, missing tag;
- match_columns ∩ schema;
- TablePolicy production: filter binding → call Expr with mapped args; mask binding → arg-0
  column + extras; unresolvable filter fn ⇒ Err; unresolvable mask fn ⇒ `"***"`.

*Proof (integration, in `datafusion-policy` tests):* `govern_plan` end-to-end over a `MemTable`
with fixture `PolicyBinding`s in the sink and a stub `CatalogFunctionResolver` — masked and
filtered results, matching vs non-matching principal.

## Done criteria

Two commits on `feat/abac-policy-engine`; fmt/clippy (`--all-features -D warnings`)/test green,
including `--no-default-features`; neutrality test green; PR opened; Status flipped to DONE.

## Explicitly out of scope

Fetching policies from UC (host-side, session S7's `UnityPolicyBindingProvider`), the mangrove
`/policies` endpoint (S5), `when_condition` **string parsing** (S7 — the host parses
`hasTagValue('k','v')` strings into `TagCondition`s; this crate only defines the parsed model),
`CompositePolicyEngine` (deferred W9), `Governance` builder (S4), tag-default mask functions.

## Workflow

Machine-wide conventions apply (`~/.claude/CLAUDE.md`): conventional commits with
`AI-assisted-by: Isaac` trailer, commit unsigned, push + open PR, surface the bulk sign +
force-push command (rebase on **origin/main**).
