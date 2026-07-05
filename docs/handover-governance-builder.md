# Handover S4: `Governance` builder + `Posture` (one-obvious-way setup)

| | |
|---|---|
| **Status** | DONE |
| **Repo / branch** | breakwater / `feat/governance-builder` (branch off `main`) |
| **Recommended model** | **Opus** — API assembly with the surface fully sketched; subtlety is posture threading + hydrofoil's composed-planner seam |
| **Depends on** | **S1 merged** (`PolicyEngineExt`, `docs/handover-secured-view-provider.md`) and **S3 merged** (`AbacPolicyEngine`, `docs/handover-abac-engine.md`) |
| **Scope** | Plan steps W8, W10 (+ optional W9 stub) |

## Context

Consuming the policy crates today requires wiring 7+ things by hand, in the right order, with
silent fail-open when any is forgotten:

1. principal bound as `PrincipalExt` SessionConfig extension *before* installing the planner,
   else every query fails closed (`rule.rs:76-78`);
2. `CatalogFactSinkExt` populated per query by the host (`session.rs:46`);
3. `fgac` feature on two crates (fixed by S1 — now default-on);
4. Cedar schema mandatory for the Cedar engine (`cedar.rs:326-329`);
5. `FunctionResolverExt` or `@mask_fn` silently falls back to `"***"`;
6. `FactStoreExt` + correlation id for taints (`session.rs:119`);
7. `IdentityProvider::enrich` never wired — hosts must remember to call it.

Reference host symptom (hydrofoil): forgetting `policy.oci_ref` silently yields
`StaticPolicy(Allow)` — governance off with no error.

This session replaces all of that with a single builder + explicit runtime posture.

Existing seams to build on (all `crates/datafusion-policy/src/`):
`PolicyBuilder::instrument` (`session.rs:263-283`) wraps the session's current `QueryPlanner`
with `PolicyQueryPlanner`; `PolicySessionExt::with_policy` (`session.rs:320-325`);
`SessionConfigPrincipalProvider` (`session.rs:87-97`); default eval-context provider
(`session.rs:119`); `authorize_and_govern` (`session.rs:178-194`);
`PolicyQueryPlanner::create_physical_plan` (`rule.rs:63-97`); `IdentityProvider` /
`PrincipalClaims` / `PrincipalEnrichment` (`principal.rs:107-172`); `PolicyEngineExt`
(added by S1 in `session.rs`).

## W8 — `feat(datafusion-policy): Governance profile + Posture` (may be split into 2–3 commits)

New module `src/governance.rs`, exported from `lib.rs` and re-exported through
`datafusion-policy-cedar`:

```rust
pub enum Posture { Disabled, Permissive, Enforcing }

let gov: Arc<Governance> = Governance::builder()
    .posture(Posture::Enforcing)
    .engine(engine)                 // Arc<dyn PolicyEngine>
    .identity_provider(idp)         // optional Arc<dyn IdentityProvider>
    .function_resolver(resolver)    // optional Arc<dyn CatalogFunctionResolver>
    .fact_store(store)              // optional; defaults to InMemoryFactStore
    .build()?;                      // Enforcing + no engine => Err at startup
```

Built once per server. Per-session/per-request surface:

- `async fn bind_principal(&self, claims: PrincipalClaims, base: PrincipalIdentity)
  -> Result<PrincipalIdentity>` — runs `IdentityProvider::enrich` (fail-closed on error when
  Enforcing) and applies the enrichment (`enriched()`, `principal.rs:96-101`). Kills burden (7):
  enrichment becomes part of session construction. No IdP configured ⇒ pass-through.
- `fn attach(&self, config: SessionConfig, principal: PrincipalIdentity) -> SessionConfig` —
  sets **all** extensions in one call: `PrincipalExt`, a **fresh** `CatalogFactSinkExt`,
  `FactStoreExt`, `FunctionResolverExt`, `PolicyEngineExt`. Taking `principal` as a required
  parameter makes "forgot to bind principal" unrepresentable at the call site. Under
  `Permissive`, an absent principal resolves to the host's anonymous convention; under
  `Enforcing` the planner still fails closed if it's somehow missing (defense in depth,
  `rule.rs:76` behavior preserved).
- `fn instrument(&self, state: SessionState) -> SessionState` — wraps the planner (delegates to
  `PolicyBuilder::instrument`). `Disabled` returns the state untouched. Expose `engine()` /
  `providers()` accessors so a host that composes its own planner (hydrofoil's
  `GovernedLineagePlanner` sequences policy + lineage in one `QueryPlanner`) can keep doing so
  without `instrument`.

**Posture threading**: carry the posture *inside* `PolicyQueryPlanner` / `authorize_and_govern`
(constructor parameter, not a config lookup at query time):

- `Disabled` — nothing installed; the only ungoverned mode, and it's spelled out at build time.
- `Permissive` — evaluate everything (both `is_allowed` and `constrain`), emit structured
  logs/metrics (`decision=deny would_block=true`, per-table constraint summaries), enforce
  nothing: Deny doesn't error, TablePolicy isn't applied. Rollout/dry-run mode.
- `Enforcing` — today's fail-closed behavior, unchanged. `build()` additionally validates
  completeness: engine present; warn (log, not error) if the engine is Cedar/ABAC but no function
  resolver is set.

*Proof (unit):* `attach` sets all five extensions; `Enforcing` + no engine ⇒ `build()` error;
`Permissive` logs-but-does-not-block (Deny decision executes; masks not applied); missing
principal under `Enforcing` still fails closed; `Disabled` leaves state/config untouched;
`bind_principal` applies enrichment and IdP-attributes-override-client-asserted semantics.

## Optional W9 stub — `feat(datafusion-policy): CompositePolicyEngine`

Only if time permits (it is otherwise deferred until a deployment layers
`sources = ["unity-abac", "cedar-oci"]`): `is_allowed` = deny-overrides across children;
`constrain` = per-table union (concat `row_filters`; masks merged, first engine wins per column).
*Proof:* unit — deny wins; constraints union.

## W10 — `docs: refresh governance docs`

- `docs/pluggable-policy-architecture.md` + `docs/typed-fgac-seams.md`: document the two
  enforcement placements (resolver-time secured view from S1, planner backstop), the governed-set
  marker contract, the `Governance`/`Posture` host recipe, and the `AbacPolicyEngine` (S3).
- Mark `docs/handover-governed-tag-wiring.md` RESOLVED — hydrofoil #65 (2026-07-04) landed that
  wiring; the doc's "inert in production" claim is stale.
- Fix the dangling ADR-0005–0007 references in `docs/policy-fact-gathering.md` — those ADRs live
  in the hydrofoil repo (`hydrofoil/docs/adr/`), say so explicitly.
- Flip S1/S2/S3 handover docs to DONE if their PRs merged and nobody did.

## Done criteria

Commits on `feat/governance-builder`; fmt/clippy/test green (incl. `--no-default-features`);
neutrality test green (`Governance` is neutral — engines are injected); PR opened; Status DONE.

## Explicitly out of scope

Hydrofoil adoption of `Governance` and its `[governance]` config file redesign (session S7),
the secured-view provider internals (S1), UC policy fetching, auth interceptor (`Authenticator`
trait consolidation is deferred entirely), agent-tool PEP.

## Workflow

Machine-wide conventions apply (`~/.claude/CLAUDE.md`): conventional commits with
`AI-assisted-by: Isaac` trailer, commit unsigned, push + open PR, surface the bulk sign +
force-push command (rebase on **origin/main**).
