# syntax=docker/dockerfile:1
#
# The `pdp` binary: the Cedar policy decision point (crates/pdp) as a
# standalone service. Build from the REPO ROOT:
#
#   docker build -f crates/pdp/Dockerfile -t pdp .
#
# cargo-chef caches the dependency graph as its own layer, so a source edit
# doesn't rebuild every dependency. Base images are pinned by digest; refresh
# one with `docker buildx imagetools inspect <image:tag>`.

# rust:1.99-bookworm
FROM rust@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Only olai-pdp's graph (with `bin`): a workspace build would unify features
# across every crate and pull in protoc-generated code the PDP doesn't need.
RUN cargo chef cook --release --recipe-path recipe.json \
    -p olai-pdp --features bin --bin pdp
COPY . .
RUN cargo build --release -p olai-pdp --features bin --bin pdp

# distroless cc (glibc, CA certs), nonroot. No shell: the HEALTHCHECK runs the
# binary's own `healthcheck` subcommand.
# gcr.io/distroless/cc-debian12:nonroot
FROM gcr.io/distroless/cc-debian12@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985 AS runtime

LABEL org.opencontainers.image.title="pdp" \
      org.opencontainers.image.description="A Cedar policy decision point serving olai-auth's PDP wire API." \
      org.opencontainers.image.source="https://github.com/open-lakehouse/breakwater" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="open-lakehouse"

COPY --from=builder /app/target/release/pdp /usr/local/bin/pdp

# The built-in Lakehouse schema and baseline are compiled in. Mount the
# deployment's schema fragments and policies and point PDP_POLICY_DIRS at them
# (e.g. `-v ./policies:/etc/pdp/policies:ro -e PDP_POLICY_DIRS=/etc/pdp/policies`).
# The reference privilege-level namespace of the OPA route ships here, so UC's
# OPA clients work with `PDP_POLICY_DIRS=/usr/share/pdp/unitycatalog-opa`.
COPY crates/pdp/policies/unitycatalog-opa /usr/share/pdp/unitycatalog-opa
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/pdp", "healthcheck"]

USER nonroot

# `serve` never migrates: run `pdp migrate` once against a new database first.
ENTRYPOINT ["/usr/local/bin/pdp"]
CMD ["serve"]
