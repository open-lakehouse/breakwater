//! The **constraint-translation** seam: lower an engine's residual (the leftover
//! condition after partial evaluation) into a DataFusion predicate [`Expr`].
//!
//! A [`PolicyEngine`](crate::PolicyEngine) that supports fine-grained governance
//! resolves per-row/-column constraints by partially evaluating its policy over
//! an *unknown* resource; what survives is a residual referencing only
//! `resource.<attr>`. Translating that residual to a `col(<attr>)` predicate is
//! the same shape for every engine, but the residual *type* differs (a Cedar
//! `Policy`, an OPA UCAST tree, …). This trait captures the shape while leaving
//! the residual type to the implementation via an associated type — so the trait
//! itself names no engine type and lives in the neutral crate, while the Cedar
//! reader (`CedarResidualTranslator`) implements it in the Cedar adapter.

use datafusion::common::Result;
use datafusion::logical_expr::Expr;

/// Translates an engine's residual into a DataFusion row-filter predicate.
///
/// The residual type is the implementation's own (`type Residual`); the produced
/// [`Expr`] is engine-neutral. `Ok(None)` means the residual is trivially true
/// (no filter needed); an `Err` is an untranslatable residual the caller treats
/// fail-closed (deny the row / mask the column).
pub trait ConstraintTranslator: std::fmt::Debug + Send + Sync {
    /// The engine-specific residual this translator reads (e.g. a Cedar
    /// `cedar_policy::Policy`).
    type Residual;

    /// Translate the residual's condition into a row-filter predicate
    /// (`resource.<attr>` mapped to `col(<attr>)`). `None` means the residual is
    /// trivially true (no filter needed).
    fn to_predicate(&self, residual: &Self::Residual) -> Result<Option<Expr>>;
}
