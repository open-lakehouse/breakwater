//! Engine-neutral value types that cross the decide/enforce seam.
//!
//! These carry no dependency on any policy engine (Cedar, OPA, OpenFGA) so the
//! [`PolicyEngine`](crate::PolicyEngine) trait — the decide contract every
//! adapter implements — can be expressed without leaking engine types into its
//! callers. A Cedar adapter maps `cedar_policy` types to and from these at its
//! boundary; an OPA or OpenFGA adapter would map its own.

/// The coarse allow/deny outcome of an authorization decision.
///
/// The neutral analog of Cedar's `cedar_policy::Decision` (and of OPA's `bool`,
/// OpenFGA's `Check` bool). An adapter maps its engine's native decision onto
/// this at the boundary so the enforcement layer never names an engine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The principal may perform the action.
    Allow,
    /// The principal may not — the query/action is rejected (fail-closed default).
    Deny,
}

/// An engine-neutral principal attribute value.
///
/// Policies condition on principal attributes (`principal.role == "analyst"`,
/// `principal.clearances.contains("pii")`). The host supplies them in this
/// neutral shape; the Cedar adapter lowers each to a
/// `cedar_policy::RestrictedExpression` when it builds the principal entity.
/// The variant set is the common denominator across engines — string, integer,
/// boolean, and homogeneous sets thereof.
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    /// A string attribute, e.g. `role = "analyst"`.
    String(String),
    /// A 64-bit signed integer attribute, e.g. `clearance_level = 3`.
    Long(i64),
    /// A boolean attribute, e.g. `is_admin = true`.
    Bool(bool),
    /// A set of values, e.g. `regions = ["eu", "us"]`.
    Set(Vec<AttrValue>),
}

impl From<&str> for AttrValue {
    fn from(s: &str) -> Self {
        AttrValue::String(s.to_string())
    }
}

impl From<String> for AttrValue {
    fn from(s: String) -> Self {
        AttrValue::String(s)
    }
}

impl From<i64> for AttrValue {
    fn from(n: i64) -> Self {
        AttrValue::Long(n)
    }
}

impl From<bool> for AttrValue {
    fn from(b: bool) -> Self {
        AttrValue::Bool(b)
    }
}
