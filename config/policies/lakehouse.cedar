// Typed FGAC showcase policy (see docs/typed-fgac-seams.md).
//
// Every fine-grained decision is expressed in native Cedar and evaluated with
// type-aware partial evaluation (TPE) against lakehouse.cedarschema. Intent is
// carried by native mechanics, not by custom annotations:
//
//   - row filter vs column mask  -> the action (read_table vs read_column)
//   - which column               -> the read_column resource identity
//   - mask vs allow              -> a surviving forbid vs permit residual
//   - which objects are governed  -> native governed tags (hasTag / getTag)
//
// The only annotations are the tag->function binding (@mask_fn / @row_filter_fn /
// @using_columns), the direct analog of UC `COLUMN MASK f ... USING COLUMNS`.

// ---------------------------------------------------------------------------
// Layer 1 — coarse access gate. Permit table reads for any principal that has a
// region attribute. A caller with no region is denied the table outright.
// ---------------------------------------------------------------------------
permit (
    principal,
    action == Action::"read_table",
    resource
)
when { principal has region };

// ---------------------------------------------------------------------------
// ROW FILTER — resolution level 3 (generated expression, no UDF).
// The residual `resource.region == principal.region` folds (with a concrete
// principal) to `col("region") == "<region>"`, pushed into the scan as a filter.
// ---------------------------------------------------------------------------
permit (
    principal,
    action == Action::"read_table",
    resource
)
when { principal has region && resource.region == principal.region };

// ---------------------------------------------------------------------------
// COLUMN MASK — resolution level 1 (policy-named catalog function).
// UC analog:
//   COLUMN MASK hr.security.mask_ssn TO analysts EXCEPT high-clearance
//   MATCH COLUMNS has_tag_value('pii','ssn') USING COLUMNS(4)
// The surviving forbid marks the column protected; @mask_fn names the UDF and
// @using_columns supplies its extra (non-column) argument.
// ---------------------------------------------------------------------------
@mask_fn("hr.security.mask_ssn")
@using_columns("4")
forbid (
    principal,
    action == Action::"read_column",
    resource
)
when { resource.hasTag("pii") && resource.getTag("pii") == "ssn" }
unless { principal has clearance && principal.clearance == "high" };

// ---------------------------------------------------------------------------
// COLUMN MASK — resolution level 2 (tag-default function).
// No @mask_fn here; the matched Tag entity's `default_mask_fn` supplies the UDF.
// ---------------------------------------------------------------------------
forbid (
    principal,
    action == Action::"read_column",
    resource
)
when { resource.hasTag("classification") && resource.getTag("classification") == "restricted" };

// ---------------------------------------------------------------------------
// COLUMN MASK — resolution level 3 (generated default literal).
// No function named anywhere; the surviving forbid masks the column with the
// engine default ("***").
// ---------------------------------------------------------------------------
forbid (
    principal,
    action == Action::"read_column",
    resource
)
when { resource.hasTag("classification") && resource.getTag("classification") == "secret" };
