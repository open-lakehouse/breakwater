//! The **catalog-function seam**: resolve a policy-referenced masking or
//! row-filter function (by name) into a DataFusion [`ScalarUDF`] the governance
//! layer can call.
//!
//! Databricks Unity Catalog ABAC binds a governed tag to a *function* — a SQL
//! UDF that masks a column value or filters a row (`COLUMN MASK f` /
//! `ROW FILTER f`). Breakwater mirrors that: a policy (or a governed tag) may
//! name a function, and the engine builds a call expression over the affected
//! column(s). Resolving that name — and the function's signature — is a catalog
//! concern, so it lives behind this trait. The neutral crate must not depend on
//! any concrete catalog (`unitycatalog-*`); the host (e.g. hydrofoil) implements
//! [`CatalogFunctionResolver`] over its catalog's Functions API and wraps the
//! returned UDF as a DataFusion [`ScalarUDF`].
//!
//! When no function is named, the governance layer generates the expression
//! itself (a native predicate or a default mask literal) — this seam is only for
//! the named-function case.

use std::fmt::Debug;
use std::sync::Arc;

use datafusion::error::Result;
use datafusion::logical_expr::ScalarUDF;

/// Resolves a catalog function name into a callable DataFusion [`ScalarUDF`].
///
/// The returned UDF carries its own signature (parameter and return types), which
/// the governance layer relies on to bind argument columns and to let DataFusion
/// validate arity/types when the call expression is planned.
///
/// `name` is a catalog-qualified function name as written in the policy (e.g.
/// `"hr.security.mask_ssn"`). Implementations resolve it against their catalog;
/// an unresolvable name is an `Err`, which the caller treats **fail-closed**
/// (deny the row / mask the column with the default literal) rather than skipping
/// the constraint.
#[async_trait::async_trait]
pub trait CatalogFunctionResolver: Debug + Send + Sync {
    /// Resolve `name` to a callable UDF, or `Err` if it cannot be resolved.
    async fn resolve(&self, name: &str) -> Result<Arc<ScalarUDF>>;
}
