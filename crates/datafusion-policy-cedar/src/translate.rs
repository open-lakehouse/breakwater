//! Translate a Cedar residual (the leftover condition from type-aware partial
//! evaluation) into a DataFusion [`Expr`].
//!
//! After TPE with a concrete principal/action/context and a resource left
//! symbolic in its attributes, a surviving residual's condition references only
//! the resource's attributes (`resource.<attr>`, or `<Table uid>.<attr>` when the
//! resource uid was pinned concrete to fold its tags). We map those attribute
//! accesses to `col(<attr>)` and Cedar operators to DataFusion
//! expression operators. The grammar is deliberately restricted (equality,
//! comparison, boolean combinators, `like`); anything outside it fails — and the
//! caller treats a failure as fail-closed (deny the row / mask the column).
//!
//! Unlike the earlier untyped path (which walked the residual's EST JSON), this
//! reads the **typed PST** (`Policy::to_pst()`), whose expression nodes are a
//! strongly-typed [`pst::Expr`] tree. TPE resolves `hasTag`/`getTag` and
//! principal references against the supplied entities, so a well-formed row-filter
//! residual is left as a boolean over `resource.<col>`; anything else that
//! survives (a bare tag op, a non-resource attribute) is not a per-row predicate
//! and fails closed.

use datafusion::common::{Result, plan_datafusion_err};
use datafusion::logical_expr::{Expr, col, lit};

use cedar_policy::Policy;
use cedar_policy::pst::{self, BinaryOp, Clause, Literal, PatternElem, UnaryOp, Var};

use cedar_oci::EntityUid;

use datafusion_policy::ConstraintTranslator;

/// Reads a Cedar residual's typed PST and lowers its condition to an [`Expr`].
///
/// The Cedar implementation of the neutral
/// [`ConstraintTranslator`](datafusion_policy::ConstraintTranslator) seam: its
/// `Residual` is a `cedar_policy::Policy`. A future translator for a different
/// engine's residual would implement the same trait with a different `Residual`
/// type, without touching the enforcement layer.
///
/// The residual's `resource` base can appear two ways depending on how the TPE
/// request modeled the resource:
///
/// - as the symbolic `resource` var / an `Unknown` node — when the resource uid
///   was left unknown (`resource.<attr>` in the source PST); or
/// - as a concrete **entity-uid literal** — when the TPE request pinned the
///   resource to a concrete uid (so its tags could fold) while leaving its
///   attributes unknown. `read_table` now does this to fold table governed tags,
///   so `resource.region` surfaces as `Table::"…".region`.
///
/// [`with_resource_uid`](Self::with_resource_uid) records the concrete uid so
/// the second form is recognized as a column reference; a bare [`Default`]
/// translator (no uid) recognizes only the symbolic form.
#[derive(Debug, Default)]
pub struct CedarResidualTranslator {
    /// The concrete resource uid the residual was evaluated against, when the
    /// TPE request used one. `None` for the unknown-resource path.
    resource_uid: Option<EntityUid>,
}

impl CedarResidualTranslator {
    /// A translator that also recognizes `<resource_uid>.<attr>` (a concrete
    /// resource entity literal) as a column reference, alongside the symbolic
    /// `resource.<attr>` form.
    pub fn with_resource_uid(resource_uid: EntityUid) -> Self {
        Self {
            resource_uid: Some(resource_uid),
        }
    }
}

impl ConstraintTranslator for CedarResidualTranslator {
    type Residual = Policy;

    fn to_predicate(&self, residual: &Policy) -> Result<Option<Expr>> {
        let policy = residual
            .to_pst()
            .map_err(|e| plan_datafusion_err!("failed to lower residual to PST: {e}"))?;

        // Conjoin the policy's clauses; `unless { c }` is `when { !c }`.
        let mut predicate: Option<Expr> = None;
        for clause in policy.body().clauses() {
            let (raw, negate) = match clause {
                Clause::When(expr) => (expr, false),
                Clause::Unless(expr) => (expr, true),
            };
            // A `when { true }` clause contributes nothing (TPE leaves discharged
            // guards as `true`); skip it rather than AND it in. But an
            // `unless { true }` clause is `when { false }` — it denies every row —
            // so it must fold to `false`, not be skipped. (TPE only ever emits
            // single `when` clauses, so this guards the public trait method
            // against a hand-authored `unless { true }` residual.)
            if is_true_literal(raw) {
                if negate {
                    return Ok(Some(lit(false)));
                }
                continue;
            }
            let mut expr = self.translate_expr(raw)?;
            if negate {
                expr = !expr;
            }
            predicate = Some(match predicate {
                Some(acc) => acc.and(expr),
                None => expr,
            });
        }
        Ok(predicate)
    }
}

/// Whether a PST node is the literal `true`.
fn is_true_literal(node: &pst::Expr) -> bool {
    matches!(node, pst::Expr::Literal(Literal::Bool(true)))
}

impl CedarResidualTranslator {
    /// Translate one PST expression node into a DataFusion [`Expr`].
    fn translate_expr(&self, node: &pst::Expr) -> Result<Expr> {
        match node {
            pst::Expr::Literal(lit_val) => translate_literal(lit_val),

            pst::Expr::GetAttr { expr, attr } => {
                if self.base_is_resource(expr) {
                    Ok(col(attr.as_str()))
                } else {
                    // principal.* should have been folded out by TPE; any remaining
                    // non-resource attribute access is not a column reference.
                    Err(plan_datafusion_err!(
                        "residual references a non-resource attribute '{attr}'; not a column"
                    ))
                }
            }

            pst::Expr::UnaryOp { op, expr } => match op {
                UnaryOp::Not => Ok(!self.translate_expr(expr)?),
                other => Err(plan_datafusion_err!(
                    "unsupported Cedar unary operator in residual: {other:?}"
                )),
            },

            pst::Expr::BinaryOp { op, left, right } => self.translate_binary(op, left, right),

            pst::Expr::Like { expr, pattern } => self.translate_like(expr, pattern),

            // A surviving `resource`/`unknown` base outside a `.` access, a set/record
            // literal, `if`/`is`/slots, or a TPE residual-error node is not a row
            // predicate — fail closed.
            other => Err(plan_datafusion_err!(
                "unsupported Cedar residual expression: {other:?}"
            )),
        }
    }

    /// Whether a PST node denotes the resource: the symbolic `resource` var, an
    /// `Unknown` node standing in for it, or — when the request pinned a concrete
    /// resource uid — an entity-uid literal equal to that uid.
    fn base_is_resource(&self, node: &pst::Expr) -> bool {
        match node {
            pst::Expr::Var(Var::Resource) => true,
            pst::Expr::Unknown { name } => name.as_str() == "resource",
            // A concrete resource entity literal. The pst `EntityUID` and the
            // public `EntityUid` are distinct types but share Cedar's canonical
            // `Type::"eid"` textual form, so compare by that.
            pst::Expr::Literal(Literal::EntityUID(uid)) => self
                .resource_uid
                .as_ref()
                .is_some_and(|res| uid.to_string() == res.to_string()),
            _ => false,
        }
    }

    /// Translate a binary-operator node. Comparison and boolean combinators map to
    /// DataFusion; tag ops (`hasTag`/`getTag`) and everything else fail closed —
    /// TPE resolves tag ops against the supplied entities, so one surviving here
    /// means the tag data was missing and we cannot prove the row/column is safe.
    fn translate_binary(&self, op: &BinaryOp, left: &pst::Expr, right: &pst::Expr) -> Result<Expr> {
        match op {
            BinaryOp::And => {
                // Fold `true &&` guards TPE may leave in place.
                let l = self.fold_true(left)?;
                let r = self.fold_true(right)?;
                Ok(match (l, r) {
                    (None, None) => lit(true),
                    (Some(e), None) | (None, Some(e)) => e,
                    (Some(l), Some(r)) => l.and(r),
                })
            }
            BinaryOp::Or => Ok(self.translate_expr(left)?.or(self.translate_expr(right)?)),
            BinaryOp::Eq => Ok(self.translate_expr(left)?.eq(self.translate_expr(right)?)),
            BinaryOp::NotEq => Ok(self
                .translate_expr(left)?
                .not_eq(self.translate_expr(right)?)),
            BinaryOp::Less => Ok(self.translate_expr(left)?.lt(self.translate_expr(right)?)),
            BinaryOp::LessEq => Ok(self
                .translate_expr(left)?
                .lt_eq(self.translate_expr(right)?)),
            BinaryOp::Greater => Ok(self.translate_expr(left)?.gt(self.translate_expr(right)?)),
            BinaryOp::GreaterEq => Ok(self
                .translate_expr(left)?
                .gt_eq(self.translate_expr(right)?)),
            other => Err(plan_datafusion_err!(
                "unsupported Cedar binary operator in residual: {other:?}"
            )),
        }
    }

    /// Translate a node, returning `None` if it is the literal `true` (an
    /// always-satisfied guard that contributes nothing to the predicate).
    fn fold_true(&self, node: &pst::Expr) -> Result<Option<Expr>> {
        if is_true_literal(node) {
            return Ok(None);
        }
        Ok(Some(self.translate_expr(node)?))
    }

    /// `resource.<attr> like <pattern>` -> SQL LIKE. Cedar's pattern is a sequence of
    /// wildcards and literal chars; we escape SQL LIKE metacharacters in literals.
    fn translate_like(&self, expr: &pst::Expr, pattern: &[PatternElem]) -> Result<Expr> {
        let mut sql = String::new();
        for elem in pattern {
            match elem {
                PatternElem::Wildcard => sql.push('%'),
                PatternElem::Char(c) => {
                    if *c == '%' || *c == '_' || *c == '\\' {
                        sql.push('\\');
                    }
                    sql.push(*c);
                }
            }
        }
        Ok(self.translate_expr(expr)?.like(lit(sql)))
    }
}

/// Translate a Cedar literal (string/long/bool) to a DataFusion literal. Entity
/// UID literals have no column-predicate meaning and fail closed.
fn translate_literal(value: &Literal) -> Result<Expr> {
    match value {
        Literal::String(s) => Ok(lit(s.to_string())),
        Literal::Bool(b) => Ok(lit(*b)),
        Literal::Long(n) => Ok(lit(*n)),
        Literal::EntityUID(uid) => Err(plan_datafusion_err!(
            "unsupported entity-uid literal in residual: {uid:?}"
        )),
        // `Literal` is non-exhaustive; an unrecognized literal fails closed.
        _ => Err(plan_datafusion_err!("unsupported literal in residual")),
    }
}

#[cfg(test)]
mod tests {
    use datafusion::logical_expr::{col, lit};

    use super::*;

    /// Parse a policy and translate its condition; residuals are ordinary
    /// policies, so a hand-written policy exercises the same PST path.
    fn predicate(src: &str) -> Result<Option<Expr>> {
        let policy = Policy::parse(None, src).expect("valid policy");
        CedarResidualTranslator::default().to_predicate(&policy)
    }

    #[test]
    fn resource_eq_literal_becomes_col_eq() {
        let expr =
            predicate(r#"permit(principal, action, resource) when { resource.region == "eu" };"#)
                .unwrap()
                .unwrap();
        assert_eq!(expr, col("region").eq(lit("eu")));
    }

    #[test]
    fn conjunction_of_resource_comparisons() {
        let expr = predicate(
            r#"permit(principal, action, resource) when { resource.a == 1 && resource.b == "x" };"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(expr, col("a").eq(lit(1i64)).and(col("b").eq(lit("x"))));
    }

    #[test]
    fn disjunction_and_comparisons() {
        let expr = predicate(
            r#"permit(principal, action, resource) when { resource.a < 1 || resource.b >= 2 };"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(expr, col("a").lt(lit(1i64)).or(col("b").gt_eq(lit(2i64))));
    }

    #[test]
    fn unless_clause_is_negated() {
        let expr = predicate(r#"permit(principal, action, resource) unless { resource.a == 1 };"#)
            .unwrap()
            .unwrap();
        assert_eq!(expr, !col("a").eq(lit(1i64)));
    }

    #[test]
    fn unless_true_denies_all_rows() {
        // `unless { true }` == `when { false }`: the residual must deny every row
        // (fold to `false`), not be skipped like a discharged `when { true }`.
        let expr = predicate(r#"permit(principal, action, resource) unless { true };"#)
            .unwrap()
            .unwrap();
        assert_eq!(expr, lit(false));
    }

    #[test]
    fn when_true_contributes_nothing() {
        // A discharged `when { true }` guard adds no restriction (no filter).
        let pred = predicate(r#"permit(principal, action, resource) when { true };"#).unwrap();
        assert_eq!(pred, None);
    }

    #[test]
    fn like_translates_to_sql_like() {
        let expr =
            predicate(r#"permit(principal, action, resource) when { resource.name like "a*c" };"#)
                .unwrap()
                .unwrap();
        assert_eq!(expr, col("name").like(lit("a%c")));
    }

    #[test]
    fn like_escapes_sql_metacharacters() {
        // A literal `_` in the Cedar pattern must be escaped for SQL LIKE.
        let expr =
            predicate(r#"permit(principal, action, resource) when { resource.name like "a_b" };"#)
                .unwrap()
                .unwrap();
        assert_eq!(expr, col("name").like(lit("a\\_b")));
    }

    #[test]
    fn non_resource_attribute_fails_closed() {
        // A surviving principal attribute is not a column reference.
        assert!(
            predicate(r#"permit(principal, action, resource) when { principal.role == "admin" };"#)
                .is_err()
        );
    }

    #[test]
    fn tag_op_is_not_a_row_predicate() {
        // hasTag/getTag resolve during TPE; if one survives into a row predicate
        // we cannot translate it and fail closed.
        assert!(
            predicate(r#"permit(principal, action, resource) when { resource.hasTag("pii") };"#)
                .is_err()
        );
    }

    #[test]
    fn trivially_true_clause_yields_no_predicate() {
        let pred = predicate(r#"permit(principal, action, resource) when { true };"#).unwrap();
        assert!(pred.is_none());
    }

    #[test]
    fn concrete_resource_uid_base_becomes_col() {
        // When the TPE request pins a concrete resource uid, the residual
        // references it as an entity literal (`Table::"…".region`) rather than the
        // symbolic `resource`. A translator carrying that uid recognizes it as the
        // resource base and maps the attribute to a column.
        let uid: EntityUid = r#"Table::"prod.customers.accounts""#.parse().unwrap();
        let policy = Policy::parse(
            None,
            r#"permit(principal, action, resource)
               when { Table::"prod.customers.accounts".region == "eu" };"#,
        )
        .expect("valid policy");
        let expr = CedarResidualTranslator::with_resource_uid(uid)
            .to_predicate(&policy)
            .unwrap()
            .unwrap();
        assert_eq!(expr, col("region").eq(lit("eu")));
    }

    #[test]
    fn other_entity_uid_base_fails_closed() {
        // An entity literal that is *not* the resource uid is not a column
        // reference; the default translator (no resource uid) rejects any entity
        // literal base outright.
        assert!(
            predicate(
                r#"permit(principal, action, resource)
                   when { Table::"other.tbl".region == "eu" };"#
            )
            .is_err()
        );
    }
}
