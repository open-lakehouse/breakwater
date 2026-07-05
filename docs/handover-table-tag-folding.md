# Handover S2: fold table-level governed tags into `read_table` TPE

| | |
|---|---|
| **Status** | DONE (PR pending) |
| **Repo / branch** | breakwater / `fix/table-tag-folding` (branch off `main`) |
| **Recommended model** | **Opus** — single-file change with an in-repo pattern to mirror; the tests are the substance |
| **Depends on** | nothing (parallel to S1/S3/S5; S6 depends on this) |
| **Scope** | Plan step W3 |

## Context

This fixes a **live correctness gap**: table-level `governed_tags` (`TableFacts.governed_tags`,
`crates/datafusion-policy/src/facts.rs:47-52` — the UC ABAC key→value tags) are never folded into
the `read_table` TPE request. `table_residuals`
(`crates/datafusion-policy-cedar/src/cedar.rs:606-660`) keeps the `Table` resource fully
**unknown** (`PartialEntityUid::new(table_type, None)` at `cedar.rs:635`), so a Cedar condition
like `resource.hasTag("classification")` / `resource.getTag(...) == "internal"` cannot fold and
the residual translator fails closed. Net effect: **UC-style tag-conditioned row filters deny all
rows even for permitted principals.** There is an explicit `NOTE` block admitting this at
`cedar.rs:627-634`, and a status note in `docs/typed-fgac-seams.md:54-59`.

The column-mask path already does the right thing and is the pattern to mirror:
`column_is_masked` (`cedar.rs:670-761`) builds a **concrete** `Column` partial entity carrying
native tags via `native_tags()` (`cedar.rs:527-539`).

### Verified load-bearing fact

cedar-policy resolves to **4.11.2** in the workspace lockfile (Cargo.toml requests 4.8.2; both
fine). `PartialEntity::new(uid, attrs, ancestors, tags, schema)` (cedar-policy
`src/api/tpe.rs:279`) accepts a *concrete uid* with `attrs: None` — attributes stay unknown, so
`resource.<col>` comparisons **survive as residuals** — while `tags: Some(...)` makes
`resource.hasTag/getTag` **fold concretely**.

**Two claims here turned out wrong during implementation** (both fixed in the PR):

1. *"No residual-translation changes are needed."* With a **concrete** resource uid, the
   surviving residual references the resource as an **entity-uid literal**
   (`Table::"prod.customers.accounts".region`), **not** the symbolic `resource` var / `Unknown`
   node the untyped path emitted. `CedarResidualTranslator::base_is_resource` only recognized the
   symbolic forms, so every folded row filter failed closed (deny-all). Fix: the translator now
   carries the resource uid (`CedarResidualTranslator::with_resource_uid`) and also treats an
   entity-uid literal equal to that uid as the resource base.
2. *A tag-conditioned **forbid** that folds `true` denies the whole table* — but a fully-satisfied
   (post-fold trivially-`true`) forbid is **not** a "nontrivial residual"; it is dropped from
   `nontrivial_residual_policies()` and shows up only in `TpeResponse::decision()`. Same for the
   default-deny case when every tag guard folds and no permit survives. Fix: `table_residuals` now
   also returns `response.decision()`, and `constrain` denies all rows on a fully-resolved `Deny`
   (in addition to a surviving forbid residual).

## The change (`cedar.rs`, `table_residuals`)

1. Replace the unknown resource with a concrete uid: `Table::"<catalog.schema.table>"` (use the
   same table-uid formatting the rest of `cedar.rs` uses — check how `Column` uids are built:
   `"{table}.{column}"` around `column_is_masked`).
2. Build a `PartialEntity` for it: `attrs: None`, `ancestors: None`,
   `tags: Some(facts.governed_tags as RestrictedExpressions)` — reuse/extend the `native_tags()`
   helper (`cedar.rs:527-539`).
3. **Untagged tables get `tags: Some(empty)`, not `None`** — so `hasTag(k)` folds to `false`
   instead of remaining unknown (which would keep the residual unfoldable and fail closed for
   everyone again). Add a test proving this either way before relying on it.
4. Add the entity to the `PartialEntities` set and switch the request to
   `PartialEntityUid::from_concrete` (or equivalent constructor in 4.11).
5. The `facts` parameter is already threaded into `table_residuals` (currently named `_facts` or
   partially used) — wire it through.
6. Delete the `NOTE` block at `cedar.rs:627-634`; update the status note in
   `docs/typed-fgac-seams.md:54-59` (table-tag folding now wired).

Semantics that must not regress (existing behavior, covered by existing tests around
`cedar.rs:318-416`):

- Surviving **permit** residuals are OR-combined into one row filter (`cedar.rs:344-373`) —
  Cedar permits are a union.
- A surviving table-level **forbid** ⇒ `deny_all_rows()` = `row_filters: vec![lit(false)]`
  (`cedar.rs:353-356, 475-480`).
- `resource.<attr>` comparisons still translate to `col(<attr>)` via the typed PST
  (`translate.rs:87-97`); anything untranslatable still fails closed.

Check the Cedar schema fixtures (`config/policies/lakehouse.cedarschema`) declare
`entity Table ... tags String` — if the schema has no tags declaration on `Table`, the TPE call
errors; extend the fixture schema as part of this change so tests exercise the real shape hosts
ship.

## Proof tests (new, in `datafusion-policy-cedar`)

- Policy `permit(...) when { resource.hasTagValue-style condition }` (Cedar native:
  `resource.hasTag("classification") && resource.getTag("classification") == "internal"`):
  - table whose `governed_tags` contains `classification=internal` ⇒ condition folds away ⇒
    permitted principal gets **no** row filter (or only the residual parts);
  - table without the tag ⇒ folds to false ⇒ `lit(false)` for everyone;
  - untagged table with `Some(empty)` tags ⇒ same as above, **not** fail-closed-by-unknown.
- Tag-conditioned **forbid** fires only on matching tables.
- Mixed policy: tag condition + `resource.<col>` comparison ⇒ tag part folds, column part
  survives as a translated row-filter `Expr`.
- Existing suite green (no behavior change for policies without tag conditions).

## Done criteria

- One commit (`fix(datafusion-policy-cedar): fold table governed tags into read_table TPE`) on
  `fix/table-tag-folding`; fmt/clippy/test green; PR opened; Status flipped to DONE.
- The e2e proof through the full stack (hydrofoil `governed_tag_row_filter_end_to_end`) is
  **session S6's** job — do not touch hydrofoil here.

## Explicitly out of scope

Provider seam (S1), `AbacPolicyEngine` (S3), `Governance` (S4), hydrofoil wiring (S6/S7),
tag-default mask functions (`tag_default_mask_fn` stub at `cedar.rs:806` stays a stub).

## Workflow

Machine-wide conventions apply (`~/.claude/CLAUDE.md`): conventional commit with
`AI-assisted-by: Isaac` trailer, commit unsigned, push + open PR, surface the bulk sign +
force-push command (rebase on **origin/main**).
