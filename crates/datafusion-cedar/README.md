# datafusion-cedar

[Cedar](https://www.cedarpolicy.com/) adapter for the engine-neutral
[`datafusion-policy`](https://docs.rs/olai-datafusion-policy) layer — Cedar-backed
policy enforcement for [Apache DataFusion](https://datafusion.apache.org/)
sessions.

The neutral crate owns the decide/enforce split (the `PolicyEngine` trait, the
query-planner enforcement hook, the plan rewrite, and all neutral types); this
crate is one **adapter** behind that seam. It implements `PolicyEngine` with
Cedar (`CedarPolicyEngine`), lowers the neutral principal to Cedar entities,
lowers the neutral plan-action list to Cedar authorization requests, and reads
Cedar partial-eval residuals into DataFusion predicates. The neutral core's
public surface is re-exported here so a Cedar host imports one crate.

## Two layers

- **Layer 1 — coarse access gate** (`PolicyEngine::is_allowed`): does the
  principal have access to the tables and actions a query references? The crate
  walks the `LogicalPlan` into a set of Cedar authorization requests and denies
  the query if any is not allowed.
- **Layer 2 — fine-grained governance** (feature `fgac`, off by default):
  row filters and column masks derived from Cedar partial-evaluation residuals,
  rewritten into the plan before it executes.

## Attaching to a session

`datafusion-cedar` exposes a session-extension seam symmetric with other
DataFusion cross-cutting concerns (e.g. `datafusion-openlineage`):

```rust,ignore
use datafusion_cedar::{PolicyExtension, PolicySessionExt};

// Wrap the session's QueryPlanner with a PolicyQueryPlanner that resolves the
// principal, gathers facts, and runs the Cedar decision per query.
let ctx = SessionContext::new().with_policy(PolicyExtension::builder().policy(policy));
```

Per-request context (the principal, catalog facts, the session fact store)
flows through typed `SessionConfig` extensions, so the host stays unaware of the
internals. Policy *sourcing* — pulling a policy set / schema / entities from an
OCI registry — lives in the companion [`cedar-oci`](https://docs.rs/olai-cedar-oci)
crate.

## Example

```sh
cargo run -p olai-datafusion-cedar --example fact_gathering_walkthrough --features fgac
```

steps through the catalog → engine → agent decision points, supplies the facts
available at each, and runs real Cedar evaluations. See
[`docs/policy-fact-gathering.md`](https://github.com/open-lakehouse/breakwater/blob/main/docs/policy-fact-gathering.md).

Part of [breakwater](https://github.com/open-lakehouse/breakwater). The
reference host that composes this into a query engine is
[hydrofoil](https://github.com/open-lakehouse/hydrofoil).

## License

[Apache-2.0](https://github.com/open-lakehouse/breakwater/blob/main/LICENSE).
