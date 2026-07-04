# Breakwater

Fine-grained access control for the open Lakehouse stack — [Cedar](https://www.cedarpolicy.com/)
policy enforcement wired into [Apache DataFusion](https://datafusion.apache.org/).

A breakwater is the barrier that decides what reaches the harbor. These crates
are that barrier for a DataFusion query engine: they answer *can this principal
take this action on this resource, in this context?* and, when allowed, govern
*what they may see* (row filters + column masks). They are a self-contained,
reusable pair — the reference host that composes them into a query session is
[hydrofoil](https://github.com/open-lakehouse/hydrofoil).

## Crates

| Crate | crates.io | Description |
| --- | --- | --- |
| [`datafusion-cedar`](crates/datafusion-cedar) | `datafusion-cedar` | Cedar policy enforcement for DataFusion sessions: a coarse access gate plus optional row/column governance, attached to a `SessionState` as a query-planner extension. |
| [`cedar-oci`](crates/cedar-oci) | `cedar-oci` | A Cedar policy provider backed by OCI-distributed policy bundles, with the generated `hydrofoil.policy` gRPC types. |

`datafusion-cedar` depends on `cedar-oci`.

## How it attaches to a session

`datafusion-cedar` exposes a session-extension seam symmetric with other
DataFusion cross-cutting concerns: `PolicyExtension::builder()…instrument(state)`
wraps the session's `QueryPlanner` with a `PolicyQueryPlanner` that, per query,
resolves the principal, gathers facts, runs the Cedar decision, and — when the
`governance` feature is on — rewrites the plan with row filters and column masks
before it executes. Per-request context flows through typed `SessionConfig`
extensions, so the host stays unaware of the internals.

See [`docs/policy-fact-gathering.md`](docs/policy-fact-gathering.md) and the
runnable [`fact_gathering_walkthrough`](crates/datafusion-cedar/examples/fact_gathering_walkthrough.rs)
example.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). In short:

```sh
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

Releases are automated with [release-plz](https://release-plz.dev); crate
versions and changelogs are derived from conventional-commit history.

## License

[Apache-2.0](LICENSE).
