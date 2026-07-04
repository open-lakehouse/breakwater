# Contributing to Breakwater

Thanks for your interest in contributing! This guide covers the local setup and
the conventions CI enforces.

## Prerequisites

- A Rust toolchain matching the workspace MSRV (`rust-version` in the root
  `Cargo.toml`; currently 1.91). Newer stable is fine for day-to-day work — the
  `msrv` CI job verifies the floor still builds.
- [`protoc`](https://protobuf.dev) — `cedar-policy` compiles its protobuf
  schemas during the build.
- [`buf`](https://buf.build), only if you regenerate the `cedar-oci` proto stubs.

## Build & test

```sh
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

`datafusion-policy-cedar`'s fine-grained governance (row filters + column masks) is
behind the `fgac` feature; `--all-features` exercises it.

## Before you push

CI gates on formatting, clippy (all warnings denied), tests, doc warnings, and
the MSRV build. Run the same checks locally:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo doc --no-deps                  # must be warning-free (both crates ship to docs.rs)
```

### Protobuf changes

The generated Rust under `crates/cedar-oci/src/gen/` is committed so the
workspace builds without a codegen step. If you edit anything under `proto/`,
regenerate and commit the output in the same change (the generated file is
`include!`d, so format it directly with rustfmt — `cargo fmt` won't reach it):

```sh
cd crates/cedar-oci
buf generate --template buf.gen.yaml
rustfmt --edition 2024 src/gen/hydrofoil/policy/hydrofoil.policy.rs
```

CI (`proto-check`) fails if the committed output drifts from the `.proto`
sources.

## Commit & PR conventions

- **Conventional commits.** PR titles must follow
  [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, …, with an optional
  `(scope)`); a CI check enforces this, and releases are derived from the
  history by [release-plz](https://release-plz.dev). Prefer several small,
  well-scoped commits over one large mixed one.
- **Branch from `main`** and open a pull request; do not push to `main`.
- **Releases are automated.** Don't bump crate versions or edit `CHANGELOG.md`
  by hand — release-plz maintains both from the merged commit history.

## crates.io authentication (OIDC trusted publishing)

All published crates authenticate to crates.io via **Trusted Publishing
(OIDC)** — the `release-plz.yml` release job runs with `id-token: write` in the
protected `release` environment and needs **no** registry token. All three
crates are bootstrapped and live on OIDC; nothing extra is required to cut a
release.

**Adding a brand-new publishable crate** needs a one-time bootstrap first
publish, because OIDC cannot create a crate name that has never existed (there
is no crate to attach a Trusted Publisher policy to) and a corporate proxy
blocks publishing from local machines. To onboard a new crate:

1. Ensure the `release` GitHub Environment holds a crates.io token
   (publish-new scope) as its `CARGO_REGISTRY_TOKEN` secret.
2. From CI (or, if the proxy allows, locally) run one token-authenticated
   `cargo publish -p <crate> --locked` to create the crate name. Publish in
   dependency order if the new crate depends on other not-yet-published crates.
3. On crates.io, register the Trusted Publisher for the new crate (repo
   `open-lakehouse/breakwater`, workflow `release-plz.yml`, environment
   `release`). Once its Trusted Publisher is live, release-plz publishes it via
   OIDC on every subsequent release.

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0](LICENSE) license.
