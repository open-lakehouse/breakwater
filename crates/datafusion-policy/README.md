# datafusion-policy

Engine-neutral policy enforcement for
[Apache DataFusion](https://datafusion.apache.org/) sessions — a coarse access
gate plus optional row/column governance, attached to a session as a
query-planner extension.

This is the DataFusion-aware, **engine-agnostic** core of the policy stack. It
owns the decide/enforce split and names no policy engine, so a Cedar, OPA, or
OpenFGA adapter can plug in behind the same seam.

## Decide / enforce

- **Decide** — the `PolicyEngine` trait: the contract a policy engine implements
  to answer *what is allowed* (coarse gate) and *what constraints apply* (row
  filters + column masks, as the neutral `TablePolicy` carrier). It is expressed
  entirely in neutral types (`Decision`, `AttrValue`, `PrincipalIdentity`,
  `TableFacts`, DataFusion `Expr`s).
- **Enforce** — the `PolicyQueryPlanner` (a `QueryPlanner` wrapper, the only
  async / `&SessionState`-bound seam around planning) and the pre-optimize plan
  rewrite (`govern_plan`, under `fgac`) that apply the engine's answers.

## Two layers

- **Layer 1 — coarse access gate** (`PolicyEngine::is_allowed`): does the
  principal have access to the tables/actions a query references?
- **Layer 2 — fine-grained governance** (feature `fgac`, off by default):
  row filters and column masks the engine derives, rewritten into the plan
  before optimization so they ride predicate/projection pushdown.

## Adapters

An adapter crate implements `PolicyEngine` for a concrete engine. The reference
adapter is [`datafusion-cedar`](https://docs.rs/olai-datafusion-cedar) (Cedar). The
neutrality invariant — that this crate names no engine type — is enforced by a
test (`tests/neutrality.rs`).

## Attaching to a session

```rust,ignore
use datafusion_policy::{PolicyExtension, PolicySessionExt};

// Wrap the session's QueryPlanner with a PolicyQueryPlanner that resolves the
// principal, gathers facts, and runs the engine's decision per query.
let ctx = SessionContext::new().with_policy(PolicyExtension::builder().policy(engine));
```

Per-request context (the principal, catalog facts, the session fact store) flows
through typed `SessionConfig` extensions, so the host stays unaware of the
internals.

Part of [breakwater](https://github.com/open-lakehouse/breakwater). The
reference host that composes this into a query engine is
[hydrofoil](https://github.com/open-lakehouse/hydrofoil).

## License

[Apache-2.0](https://github.com/open-lakehouse/breakwater/blob/main/LICENSE).
