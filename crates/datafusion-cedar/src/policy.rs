use datafusion::error::Result;
use datafusion::logical_expr::LogicalPlan;

use crate::facts::EvalContext;
use crate::principal::PrincipalIdentity;
use crate::types::Decision;

#[cfg(feature = "governance")]
use datafusion::common::DFSchema;
#[cfg(feature = "governance")]
use datafusion::sql::TableReference;

/// Access-control policy applied during query planning.
///
/// Layer 1 of the policy stack: a coarse allow/deny over the tables and actions
/// a query references. Implementations inspect the [`LogicalPlan`] and decide
/// whether `principal` may execute it. The principal is passed as a
/// [`PrincipalIdentity`] (uid + attributes) so attribute-based policies
/// (`principal.role == ...`) can be evaluated.
///
/// With the `governance` feature, the trait also exposes [`Policy::table_policy`]
/// (Layer 2): the per-table row filters and column masks that apply to a
/// principal's access.
#[async_trait::async_trait]
pub trait Policy: std::fmt::Debug + Send + Sync {
    /// Decide whether `principal` may execute `logical_plan`.
    ///
    /// `eval` carries the per-query facts gathered outside the plan — the
    /// catalog facts to fold into `resource` entities, the correlation id, and
    /// (with `governance`) the session fact store. Pass
    /// [`EvalContext::default()`] when no such facts are available.
    async fn is_allowed(
        &self,
        logical_plan: &LogicalPlan,
        principal: &PrincipalIdentity,
        eval: &EvalContext,
    ) -> Result<Decision>;

    /// Resolve the fine-grained enforcement (row filters + column masks) that
    /// apply when `principal` reads `table` with schema `schema`.
    ///
    /// Default: no fine-grained enforcement. The Cedar implementation derives
    /// filters and masks from policy residuals; see `crate::govern`.
    #[cfg(feature = "governance")]
    async fn table_policy(
        &self,
        _table: &TableReference,
        _schema: &DFSchema,
        _principal: &PrincipalIdentity,
        _eval: &EvalContext,
    ) -> Result<crate::govern::TablePolicy> {
        Ok(crate::govern::TablePolicy::default())
    }

    /// Decide whether `principal` may invoke the agent tool named `action`,
    /// given the classifications the session has already observed.
    ///
    /// This is the agent-tool PEP: the data-flow control that gates an *action*
    /// (export, send-email, call-external-API) on the session's accrued taints,
    /// so consuming sensitive data forecloses exfiltrating it — surviving prompt
    /// injection because it constrains the action, not the prompt. `observed_taints`
    /// is read from the session fact store by correlation id (the host wires this
    /// at the tool-call boundary). Default: `Allow` (no guardrail).
    #[cfg(feature = "governance")]
    async fn tool_policy(
        &self,
        _action: &str,
        _principal: &PrincipalIdentity,
        _observed_taints: &std::collections::BTreeSet<String>,
    ) -> Result<Decision> {
        Ok(Decision::Allow)
    }
}

/// A [`Policy`] that returns the same decision for every query.
///
/// Used as the default when no real policy engine is wired (e.g.
/// `StaticPolicy::new(Decision::Allow)` for an open, ungoverned server).
#[derive(Debug, Clone)]
pub struct StaticPolicy {
    decision: Decision,
}

impl StaticPolicy {
    pub fn new(decision: Decision) -> Self {
        Self { decision }
    }
}

#[async_trait::async_trait]
impl Policy for StaticPolicy {
    async fn is_allowed(
        &self,
        _logical_plan: &LogicalPlan,
        _principal: &PrincipalIdentity,
        _eval: &EvalContext,
    ) -> Result<Decision> {
        Ok(self.decision)
    }
}

#[cfg(test)]
mod tests {
    use datafusion::logical_expr::LogicalPlanBuilder;

    use super::*;

    fn principal() -> PrincipalIdentity {
        PrincipalIdentity::new("User::\"alice\"")
    }

    #[tokio::test]
    async fn static_policy_returns_its_decision() {
        let plan = LogicalPlanBuilder::empty(false).build().unwrap();
        let allow = StaticPolicy::new(Decision::Allow);
        let deny = StaticPolicy::new(Decision::Deny);
        assert_eq!(
            allow
                .is_allowed(&plan, &principal(), &EvalContext::default())
                .await
                .unwrap(),
            Decision::Allow
        );
        assert_eq!(
            deny.is_allowed(&plan, &principal(), &EvalContext::default())
                .await
                .unwrap(),
            Decision::Deny
        );
    }
}
