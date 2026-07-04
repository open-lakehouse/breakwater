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

While we incubate ahead of community consensus, the published crates.io names
carry an `olai-` prefix (open lakehouse and ai). Add them under the short name so
your `use` paths stay idiomatic, e.g.
`datafusion-policy-cedar = { package = "olai-datafusion-policy-cedar", version = "0.0.1" }`.

| Crate | crates.io | Description |
| --- | --- | --- |
| [`datafusion-policy-cedar`](crates/datafusion-policy-cedar) | `olai-datafusion-policy-cedar` | Cedar policy enforcement for DataFusion sessions: a coarse access gate plus optional row/column governance, attached to a `SessionState` as a query-planner extension. |
| [`datafusion-policy`](crates/datafusion-policy) | `olai-datafusion-policy` | The engine-neutral policy core `datafusion-policy-cedar` builds on: the decide contract, session seam, and (behind `fgac`) the row-filter/column-mask rewrite — engine-agnostic, no Cedar dependency. |
| [`cedar-oci`](crates/cedar-oci) | `olai-cedar-oci` | A Cedar policy provider backed by OCI-distributed policy bundles, with the generated `hydrofoil.policy` gRPC types. |

`datafusion-policy-cedar` depends on `datafusion-policy` and `cedar-oci`.

## How it attaches to a session

`datafusion-policy-cedar` exposes a session-extension seam symmetric with other
DataFusion cross-cutting concerns: `PolicyExtension::builder()…instrument(state)`
wraps the session's `QueryPlanner` with a `PolicyQueryPlanner` that, per query,
resolves the principal, gathers facts, runs the Cedar decision, and — when the
`fgac` feature is on — rewrites the plan with row filters and column masks
before it executes. Per-request context flows through typed `SessionConfig`
extensions, so the host stays unaware of the internals.

See [`docs/policy-fact-gathering.md`](docs/policy-fact-gathering.md) and the
runnable [`fact_gathering_walkthrough`](crates/datafusion-policy-cedar/examples/fact_gathering_walkthrough.rs)
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
