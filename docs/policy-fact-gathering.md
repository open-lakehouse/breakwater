# Fact gathering & policy evaluation — operational design

> **Note:** this doc references companion docs and ADRs
> (`platform-policy-architecture.md`, `policy-enforcement-design.md`,
> `docs/adr/0005`–`0007`) that describe the enclosing platform's session
> integration and live in the [hydrofoil](https://github.com/open-lakehouse/hydrofoil)
> repo. The `datafusion-cedar` / `cedar-oci` crates here own the reusable
> mechanism; hydrofoil is the reference host that composes it.

> The operational companion to `docs/platform-policy-architecture.md`. That
> document settles *what* the policy decision points are and leans on a **hybrid
> PDP** (embedded Cedar on the hot path + a central session-state PDP for dynamic
> state). This one zooms into the half that was only sketched: **how the inputs
> (facts) for a Cedar decision are gathered, and how evaluation proceeds**, across
> the catalog → engine → agent-tool chain. It is validated by a runnable
> walkthrough — `crates/datafusion-cedar/examples/fact_gathering_walkthrough.rs` —
> that supplies facts at each decision point and runs real Cedar evaluations over
> the **real** `InMemoryFactStore` and the `PrincipalEnrichment`/`to_entities()`
> membership shape (not mocks). The
> locality/lifetime classification and the residual-caching decision are recorded
> in `docs/adr/0006-policy-fact-locality-and-session-state.md`.

## Why

A Cedar decision is a function of a `Request` — `(principal, action, resource,
context)` — plus an `Entities` store. *Every attribute a policy reads* must be
sourced from somewhere, and the sources differ in **where** and **when** they
become available, and in **whether they must be shared** with later decision
points:

- Some facts are **local-ephemeral**: resolved on the spot, used in one
  evaluation, never shared — the principal parsed from the request, a table's
  `readers`/`writers` resolved from the catalog, the columns a scan touches.
- Some facts are **shared-session-scoped**: they must persist so a *later* PEP
  (often in a different service) can read what an *earlier* one established — the
  taints a session has accumulated, prior decisions, consent flags. These live in
  a **session fact store**, keyed by a correlation id.

A query (and increasingly an agent turn) crosses several decision points, and at
each one a *different* subset of facts is known. When facts are missing, partial
evaluation lets us defer: the unknowns come back as a **residual** that a later
point — with more facts bound — refines. The open question this document closes:
**do we carry that residual across points as session state, or re-evaluate fully
from the accumulated facts?** (Decision: re-evaluate fully for v1; see the ADR.)

## Design principles

Continues the corpus (`policy-enforcement-design.md`,
`platform-policy-architecture.md`): plug in, don't fork; one source of truth for
*rules* (the OCI bundle) but *many* information points for inputs; **fail closed**
across the gather step (a missing PIP denies/masks, never opens); pluggable at the
edges (PIP sources, residual translation are traits), opinionated in the middle
(the request shape and the layering are fixed).

## The (partial) decision points along the chain

Each node is a PEP issuing a Cedar request. The annotation shows which request
slots are *bound* (known) at that point and which are *deferred* (unknown →
residual).

```
 ① Catalog PEP            ② Engine coarse gate       ③ Engine governance        ④ Agent-tool PEP
   authorize(table,         is_authorized(plan)        is_authorized_partial      is_authorized(tool_call)
   Read | Vend)             over optimized plan        (resource UNKNOWN)         forbid on observed taints
   ───────────────          ───────────────────        ────────────────────      ──────────────────────
   principal  ✓ (req ctx)   principal  ✓               principal  ✓              principal/agent ✓ (req ctx)
   action     ✓             action     ✓               action     ✓              action     ✓ (the tool)
   resource   ✓ (catalog)   resource   ✓ (catalog)     resource   ✗ → residual   resource   ✓ (the sink)
   context    coarse        context  + columns ✓       context  + table id ✓     context  + observed_taints ✓
                                                        └─► row filter / mask         (read from fact store)
   ── full decision ──      ── full decision ──         ── residual → Expr ──      ── full decision ──
```

The chain is held together by a **correlation id** (the session/trace id of
`platform-policy-architecture.md`, decision 3) — it is the key under which
shared-session-scoped facts are recorded at ②/③ and read back at ④.

## Fact taxonomy — by locality + lifetime

The organizing axis (per the ADR). Each fact is classified by **(a)
source/timing** and **(b) locality + lifetime**, and mapped to the **Cedar request
slot** it lands in — so this table doubles as a wiring map.

| Fact | Source / timing | Locality + lifetime | Cedar slot | Code seam (today) |
| --- | --- | --- | --- | --- |
| principal uid | request metadata, per connection | local-ephemeral | `principal` + entity | `identity.rs::principal_from_metadata`, `PrincipalExt` |
| principal attrs (`role`, `region`) | request metadata | local-ephemeral | principal entity attrs | `PrincipalIdentity::with_attribute` → `to_entity()` |
| agent identity (`agent_id`, `task`, `purpose`) | request metadata, per query | local-ephemeral | `context` / principal attrs | `agent.rs::AgentContext`, `AgentContextExt` |
| `in_trusted_environment` | request / network (Envoy) | local-ephemeral | `context` | network PIP (future) |
| table identity (`catalog.schema.table`) | catalog resolution / `TableScan` | local-ephemeral | `resource` uid + `context` | `visitor::table_context` (✓ free today) |
| accessed columns | `DFSchema` / scan projection | local-ephemeral | `context.columns` | `visitor::authorize_plan` (✓ free today) |
| table `owner`/`readers`/`writers` | catalog metadata (UC `Table`) | local-ephemeral | `resource` entity attrs | `build_delta` → `table_acl_facts` → `CatalogFactSink` (✓ built) |
| column tags / classification | catalog metadata (convention) | local-ephemeral | `resource.column_tags` | `build_delta` → `ConventionTagProvider` → `CatalogFactSink` (✓ built) |
| **observed taints** | accrued as engine reads tagged cols | **shared-session-scoped** | `context.observed_taints` | **(new) session fact store** |
| prior decisions / consent / step-up | accrued across the session | **shared-session-scoped** | `context` | **(new) session fact store** |
| carried residual (option B) | produced by a prior PEP's partial eval | **shared-session-scoped** | n/a (a cached partial decision) | **(deferred)** — see ADR |

The line that matters: **everything above `observed_taints` is local-ephemeral**
— resolved at the point of use, folded into the request or the `Entities`, and
discarded. **Only the shared-session-scoped rows need a store**, because only they
must outlive one evaluation and be read by a *different* decision point.

## How facts are gathered, per source

### Request context (local-ephemeral)
`principal_from_metadata` and `agent_context_from_metadata` parse gRPC headers
into typed `SessionConfig` extensions (`PrincipalExt`, `AgentContextExt`,
`LineageContextExt`), read back at planning via the provider traits
(`SessionConfigPrincipalProvider`, `HydrofoilContextProvider`). This is the
established pattern; the agent context is already wired (today only logged — the
seam for the agent PEP). `in_trusted_environment` is derivable from the
network/request edge (Envoy PIP). **Trust boundary:** the header is *transport*,
not *trust* — the principal/agent identity must be established by authentication
upstream (mTLS / bearer token), never trusted as a bare client-asserted header.

### Catalog & providers (local-ephemeral) — **built**
UC resolution runs **per query** before planning (`UnityCatalogProviderList::resolve`
via `resolve_table_references`; `create_logical_plan` re-resolves every query, so
upstream metadata is always fresh), and the full UC `Table` flows into
`TableProviderBuilder::build_delta(location, table: &Table)` — the gather seam.
There, `LakehouseTableProviderBuilder::record_facts` derives the neutral
`TableFacts` and records them into the per-session `CatalogFactSink` (read from the
`CatalogFactSinkExt` config extension, keyed by `TableReference`, overwritten on
re-resolution for per-query freshness):

- **owner / readers / writers** via `table_acl_facts` (`Table.owner` +
  `properties["readers"|"writers"]`);
- **tags / column tags** via the `TagProvider` trait. Because the UC fork has *no
  tags API*, the v1 `ConventionTagProvider` derives them by convention from
  `properties["tags"|"classification"]`, `properties["tag.<col>"]`, and `[tags: …]`
  markers in column comments. A future backend (external classification service) is
  the same trait.

The policy layer (`CedarPolicy::is_allowed`) folds these into a request-time `Table`
resource entity (`resource.owner/readers/writers/tags/column_tags`) and discards them
after the decision. See `docs/adr/0007-fact-gathering-pips.md`.

### Session fact store (shared-session-scoped) — **built**
The one piece that needs persistence. The `FactStore` trait (`datafusion-cedar`):
record a taint and query observed taints by correlation id; accrual is
**monotonic** per session. Written at ②/③ by the governance PEP (`govern_plan`)
as the engine reads tagged columns; read at ④ (`Policy::tool_policy` /
`Session::authorize_tool_call`) to populate `context.observed_taints`. v1 backing
is `InMemoryFactStore`, owned process-wide by the `Engine`; a shared KV / central
session-state PDP slots behind the same trait. See
`docs/adr/0007-fact-gathering-pips.md`.

## Carry-residual vs. re-evaluate-fully

When ③ produces a residual (`resource.region == "eu"` → `col("region") = "eu"`),
that residual *is* a partial decision. The open question: is it session state we
carry forward, or do we recompute at the next point?

**A. Re-evaluate fully at each PEP** with the accumulated facts from the store.
- *Pro:* simple; each hop is stateless-with-respect-to-prior-residuals; no
  residual lifecycle to manage; the fact store holds only facts, not policy
  fragments.
- *Con:* re-does policy-slice work; if a later PEP shares policy structure with an
  earlier one, the partial-eval cost is paid twice.

**B. Carry the residual** as session state alongside facts: each PEP loads the
prior residual, binds newly-available facts, and refines it.
- *Pro:* no re-evaluation of already-settled slices; matches the
  progressive-refinement ideal end-state.
- *Con:* residual **lifecycle** — it must be invalidated when the policy bundle
  version *or* the underlying facts change; **leakage** risk — a residual encodes
  *which attributes still matter*, so handing it to a less-trusted hop discloses
  policy structure; and it leans harder on `partial-eval`, a still-maturing Cedar
  feature.

**Decision (argued in the ADR): A for v1**, with the residual retained as an
*optional cache/optimization* (B) behind a feature seam, keyed by
`(correlation_id, bundle_version)` so a bundle bump invalidates it automatically.
The walkthrough demonstrates A end-to-end and prints the residual ③ produces,
noting it is exactly the artifact a B-mode design would cache.

## The walkthrough (what the example proves)

`cargo run -p olai-datafusion-cedar --example fact_gathering_walkthrough --features
governance` exercises **real** `is_authorized` / `is_authorized_partial` calls
over the committed `config/policies/` model (plus two minimal inline policies),
with facts supplied at each point:

1. **① Catalog** — `alice` ∈ `privileged_readers` ⊂ `readers` = `protected_table.readers`
   → **Allow**, where alice's membership is folded in via `PrincipalEnrichment` /
   `to_entities()` (the bundle no longer carries user→group edges — the
   static-bundle→dynamic-membership shift). Deny path: `r2d2` cannot *write*
   (writers = `lakhouse_admins`) → **Deny** (default-deny, fail-closed). Proves
   dynamic entity-hierarchy resolution.
2. **② Engine coarse gate** — same, with `columns=[id, region, ssn]` in the
   context → **Allow**.
3. **③ Engine governance** — partial request with **unknown resource**; the
   `region` row-filter policy folds `principal.region = "eu"` and returns the
   residual `resource.region == "eu"`, lowered by `CedarResidualTranslator` to the
   DataFusion `Expr` `region = Utf8("eu")`. The engine then records `pii` into the
   session ledger (the one shared fact).
4. **④ Agent-tool PEP** — a `send_external` tool call whose context carries
   `observed_taints` read back from the store. With `pii` present, the `forbid`
   guardrail fires → **Deny**; the counterfactual fresh session (no taints) →
   **Allow**. Proves the decision is driven by the *accrued, shared* fact, not
   hardcoded.

Every decision flips when a supplied fact flips — that is the point: the harness
demonstrates fact-gathering *and* evaluation, not a scripted output.

## Risks

- **Fail-closed across the gather step.** A PIP that can't be reached must deny or
  mask, never open. The example's fail-closed posture (deny on untranslatable
  residual, deny on TPE error, mask on an unresolvable function) mirrors
  `cedar::constrain`. See [typed FGAC seams](typed-fgac-seams.md).
- **Stale local catalog facts.** Baked-in entity attributes can lag the catalog;
  state a freshness posture per the platform doc's static-vs-live tradeoff.
- **Taint over-accrual.** A monotonic ledger that never clears locks a session
  down; needs declassification (the `masking` flag / Atlas-style blocked-tag set)
  and session scoping.
- **Residual cache invalidation (option B).** If B is later enabled, the
  `(correlation_id, bundle_version)` key must actually invalidate on a bundle bump
  *and* on fact change.
- **Residual leakage (option B).** A carried residual discloses which attributes
  still gate access; don't hand it to a less-trusted hop.
- **Correlation-id spoofing.** The id is transport, not trust; it must ride
  authenticated context (PoP/mTLS for the agent hop), per the platform doc.

## See also

- `docs/platform-policy-architecture.md` — the platform context (PDP topology,
  PIPs, correlation, taint model, agentic authorization).
- `docs/adr/0006-policy-fact-locality-and-session-state.md` — the locality/lifetime
  classification and the carry-residual vs. re-evaluate decision, with tradeoffs.
- `docs/typed-fgac-seams.md` — how typed residuals + governed tags + catalog
  functions lower to row filters and column masks (the two-layer enforcement this
  builds on).
- `crates/datafusion-cedar/examples/fact_gathering_walkthrough.rs` — the runnable
  validation of this design.
