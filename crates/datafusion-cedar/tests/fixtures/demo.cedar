// Demo policy set for `notebooks/policy_demo.py` (`just policy-demo`).
//
// Three policies exercise both enforcement layers hydrofoil applies to every
// query, keyed off attributes the client sends as gRPC metadata
// (`x-hydrofoil-principal`, `x-hydrofoil-region`):
//
//   Layer 1 — coarse access gate (`Policy::is_allowed`):
//     permit reads for principals that carry a `region` attribute. A caller with
//     no region (e.g. the default `User::"anonymous"`) is denied the table
//     outright — the whole query is rejected before execution.
//
//   Layer 2 — fine-grained governance (`Policy::table_policy`, `fgac`
//   feature):
//     - a row filter so each principal sees only rows in their own region
//       (`resource.region == principal.region`), and
//     - a column mask hiding `ssn` on this table.
//
// Run the server with the `fgac` feature to see Layer 2; without it the
// gate (Layer 1) still applies. See docs/policy-enforcement-design.md.
//
// Note on column masks: the engine derives masks from Cedar partial-evaluation
// residuals, which reference only the *unknown* resource. A mask condition must
// therefore be written over `resource.*` (so a residual survives and the column
// is flagged). A condition over the *concrete* principal alone (e.g.
// `principal.region == "eu"`) resolves fully and leaves no residual, so it never
// masks — masking is currently per-table, not per-principal at the column level.
// The per-principal axis the demo shows is the row filter.

// ---------------------------------------------------------------------------
// Layer 1 — access gate. Permit table reads for any principal that has a region
// attribute set. (A real deployment would gate on `principal in resource.readers`
// using catalog entities; here we key on a principal attribute so the demo needs
// no per-table entity wiring.)
// ---------------------------------------------------------------------------
permit (
    principal,
    action == Action::"read_table",
    resource
)
when { principal has region };

// ---------------------------------------------------------------------------
// Layer 2 — row filter. Only rows whose `region` column matches the principal's
// region survive. With principal region = "eu", the partial-eval residual folds
// to `col("region") == "eu"`, which the engine pushes into the scan.
// ---------------------------------------------------------------------------
@filter_type("row_filter")
permit (
    principal,
    action == Action::"read_table",
    resource
)
when { resource.region == principal.region };

// ---------------------------------------------------------------------------
// Layer 2 — column mask. Mask the `ssn` column on this table. The condition is
// written over the unknown `resource` so a residual survives partial evaluation
// and the column is flagged for masking (with the default "***"). The
// `resource.region == principal.region` form mirrors the row filter; because the
// resource is symbolic the residual always survives, so `ssn` is masked for
// every caller of the table.
// ---------------------------------------------------------------------------
@filter_type("column_mask")
@column("ssn")
permit (
    principal,
    action == Action::"read_table",
    resource
)
when { resource.region == principal.region };

// ---------------------------------------------------------------------------
// Layer 1 — Unity Catalog DDL gate. Permit catalog/schema create + drop only for
// principals carrying an `admin` attribute. A caller without it (e.g. a
// read-only analyst) is denied the DDL outright — the statement is rejected
// before execution (fail-closed). This keys on a principal attribute so the demo
// needs no per-securable entity wiring, mirroring the read gate above.
//
// Written as four per-action `==` permits (rather than one `action in [...]`)
// so each folds cleanly against a concrete request action under Cedar partial
// evaluation — the Layer-2 governance pass evaluates the whole policy set over a
// `read_table` request, and an unresolved `action in [...]` membership would
// otherwise survive as a residual and be (incorrectly) treated as a row filter.
// ---------------------------------------------------------------------------
permit (principal, action == Action::"create_catalog", resource)
when { principal has admin && principal.admin == "true" };

permit (principal, action == Action::"drop_catalog", resource)
when { principal has admin && principal.admin == "true" };

permit (principal, action == Action::"create_schema", resource)
when { principal has admin && principal.admin == "true" };

permit (principal, action == Action::"drop_schema", resource)
when { principal has admin && principal.admin == "true" };
