# Typed FGAC seams: governed tags, TPE residuals & catalog functions

This document describes how `breakwater` turns Cedar policy decisions into
DataFusion table constraints — row filters and column masks — for the fine-grained
access control (`fgac`) layer. The model deliberately tracks **Databricks Unity
Catalog ABAC** (governed tags + policies + UDFs) while expressing everything in
native Cedar and a narrow, engine-neutral seam.

See also [the decide/enforce architecture](pluggable-policy-architecture.md) and
[fact gathering](policy-fact-gathering.md).

## The narrow waist

Cedar decides allow/deny for one `(principal, action, resource, context)`. We map
its two residual shapes to the two DataFusion constraint kinds, using native
mechanics rather than custom annotations:

| Concept | Cedar-native modeling | Becomes (`TablePolicy`) |
|---|---|---|
| **Row filter** | `permit(action == Action::"read_table", resource)` over an *unknown* `Table`. A surviving **permit** residual over `resource.<col>`. | `row_filters: Vec<Expr>` |
| **Column mask** | `forbid(action == Action::"read_column", resource)` over a `Column` carrying governed tags. A firing **forbid** ⇒ the column is protected. | `column_masks: HashMap<String, Expr>` |

What used to be carried by out-of-band annotations (`@filter_type`, `@column`,
`@mask_value`) is now carried by native signals:

- **Constraint kind** — the **action** (`read_table` vs `read_column`).
- **Which column** — the **resource identity** of the `read_column` request.
- **Mask vs allow** — a firing **forbid** vs a surviving **permit**.
- **Which objects are governed** — native **governed tags** (`hasTag`/`getTag`),
  supplied from an external classification system (Lineage / Unity Catalog).

## Governed tags are native Cedar entity tags

Cedar 4.x has first-class entity tags — the `.hasTag(k)` / `.getTag(k)`
operators and a schema `tags` declaration. This *is* the UC governed key→value tag
model, with no string-encoding hack and no custom helper:

```cedarschema
entity Table  { region: String } tags String;   // governed key -> value tags
entity Column in [Table] { name: String } tags String;
```

```cedar
// UC: FOR TABLES WHEN has_tag_value('pii','ssn')  /  MATCH COLUMNS ... AS ssn
when { resource.hasTag("pii") && resource.getTag("pii") == "ssn" }
```

Tags flow in as `TableFacts.governed_tags` (table) and
`TableFacts.governed_column_tags` (column) — a host wires the real Lineage/UC tag
PIP behind those neutral facts. Tag inheritance (catalog→schema→table) is
pre-resolved by the host into these facts (column tags applied directly, matching
UC).

## Type-aware partial evaluation (TPE)

The `fgac` feature uses Cedar's **type-aware partial evaluation** (`PolicySet::tpe`,
RFC 0095), which requires a schema and produces **well-typed** residual policies:

- **Row filters** — `constrain` builds a partial `read_table` request with an
  *unknown* `Table` resource and the concrete principal. A surviving **permit**
  residual (`resource.region == "eu"`, principal folded to a literal) is lowered to
  a DataFusion predicate by the PST translator (`translate.rs`,
  `resource.<attr> → col(<attr>)`). A surviving table-grain **forbid** denies all
  rows.
- **Column masks** — for each plan column carrying governed tags, `constrain` builds
  a `read_column` request with the column supplied as a concrete partial entity
  carrying its native tags, and probes each `read_column` forbid (paired with a
  blanket permit so the decision reflects only whether that forbid fires). A firing
  forbid masks the column.

## Three-level function resolution (the tag → function binding)

Once a column must be masked / rows filtered, the *expression* is resolved in this
order (mirroring UC's `COLUMN MASK f … USING COLUMNS`):

1. **Policy-named function** — `@mask_fn("catalog.schema.fn")` /
   `@row_filter_fn(...)` (+ optional `@using_columns("a","4")`) on the policy. The
   masked column is argument 0; `@using_columns` entries become extra column
   references (or literal args for bare numerics). **Wins when present.**
2. **Tag-default function** — the matched `Tag` entity's `default_mask_fn` /
   `default_filter_fn` attribute (define once per governed tag). *(Currently a hook;
   populated by hosts through the entity provider.)*
3. **Generated expression** — the translator lowers a self-contained residual
   straight to native DataFusion (`col("region") == "eu"`, or the default mask
   literal `"***"`). No catalog round-trip, no UDF.

Levels 1–2 resolve the named function via a pluggable, engine-neutral seam:

```rust,ignore
#[async_trait]
pub trait CatalogFunctionResolver: Debug + Send + Sync {
    async fn resolve(&self, name: &str) -> Result<Arc<ScalarUDF>>;
}
```

The host (e.g. hydrofoil) implements this over its catalog's Functions API — for
Unity Catalog, `GET …/functions/{name}` yields `input_params` + `return_type`,
which the host wraps as a DataFusion `ScalarUDF`. `breakwater` depends only on the
trait, never on `unitycatalog-*` — the same catalog-neutrality rule as `TableFacts`.
The resolver is threaded through `EvalContext.function_resolver` (a
`SessionConfig` extension, `FunctionResolverExt`).

## Fail-closed contract

Every ambiguity denies rather than exposes data:

- No schema wired ⇒ TPE cannot run ⇒ deny all rows (`lit(false)`).
- TPE error / untranslatable residual ⇒ deny all rows.
- A policy names a function but no resolver is wired, or resolution fails ⇒ mask
  the column with the default literal (or deny the row filter).
- A residual that is not a per-row predicate (a surviving `hasTag`/`getTag`, a
  non-`resource` attribute) is untranslatable ⇒ fail closed.

## UC ABAC → Cedar parity

| UC `CREATE POLICY` clause | breakwater equivalent |
|---|---|
| `TO principal … EXCEPT …` | permit/forbid scope + `unless { principal.… }` |
| `FOR TABLES WHEN has_tag_value(k,v)` | `read_table` residual `when { resource.hasTag("k") && resource.getTag("k") == "v" }` |
| `MATCH COLUMNS has_tag_value(k,v) AS a` | `read_column` residual over a `Column` whose `getTag` matches |
| `ROW FILTER f` / `COLUMN MASK f` | `@row_filter_fn` / `@mask_fn` **or** `Tag.default_*_fn` → resolved `ScalarUDF` |
| matched column = fn's 1st arg | masked `col(name)` is argument 0 |
| `USING COLUMNS (…)` | `@using_columns("…")` |
| (no function named) | generated `Expr` (native predicate / default `lit("***")`) |

## Where the code lives

- Fixtures: `config/policies/lakehouse.{cedarschema,cedar,entities.json}` — the
  checked-in typed showcase (also backs the `fact_gathering_walkthrough` example).
- Neutral seam: `datafusion-policy` — `CatalogFunctionResolver` (`function.rs`),
  `TablePolicy` (`govern.rs`), governed tags on `TableFacts` (`facts.rs`),
  `EvalContext.function_resolver` + `FunctionResolverExt` (`session.rs`).
- Cedar adapter: `datafusion-cedar` — TPE `constrain` + three-level resolution
  (`cedar.rs`), the PST residual translator (`translate.rs`).
