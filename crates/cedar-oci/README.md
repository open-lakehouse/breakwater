# cedar-oci

A [Cedar](https://www.cedarpolicy.com/) policy provider backed by
**OCI-distributed policy bundles**, plus the generated `hydrofoil.policy` gRPC
types.

Cedar answers the fundamental authorization question:

> Can this principal take this action on this resource in this context?

`cedar-oci` supplies the policy sets, schemas, and entities that decision from
an OCI registry — policy is distributed and versioned like any other OCI
artifact, fetched at runtime rather than vendored into the binary. It is the
policy-provider half of [`datafusion-cedar`](https://docs.rs/olai-datafusion-cedar),
which wires Cedar enforcement into an Apache DataFusion query session.

Part of [breakwater](https://github.com/open-lakehouse/breakwater).

## License

[Apache-2.0](https://github.com/open-lakehouse/breakwater/blob/main/LICENSE).
