use datafusion::error::Result;
use datafusion::logical_expr::LogicalPlan;

use crate::facts::EvalContext;
use crate::principal::PrincipalIdentity;
use crate::types::Decision;

#[cfg(feature = "governance")]
use datafusion::common::DFSchema;
#[cfg(feature = "governance")]
use datafusion::sql::TableReference;

/// The **decide** contract every policy engine implements — the engine-agnostic
/// seam the enforcement layer talks to.
///
/// This is the "decide" half of the decide/enforce split: a
/// [`PolicyEngine`] answers *what is allowed* (coarse gate) and *what
/// constraints apply* (fine-grained row filters + column masks), and the
/// enforcement layer (the [`PolicyQueryPlanner`](crate::PolicyQueryPlanner)
/// wrapper + the plan rewrite) applies the answers. The trait names no engine
/// type — the `datafusion-cedar`
/// Cedar adapter implements it today, and an OPA or OpenFGA adapter could
/// implement it without touching enforcement.
///
/// Layer 1 is the coarse allow/deny of [`is_allowed`](PolicyEngine::is_allowed)
/// over the tables/actions a query references; the principal is passed as a
/// [`PrincipalIdentity`] (uid + attributes) so attribute-based policies
/// (`principal.role == ...`) can be evaluated. With the `governance` feature the
/// trait also exposes [`constrain`](PolicyEngine::constrain) (Layer 2) and
/// [`tool_policy`](PolicyEngine::tool_policy) (the agent-tool PEP).
#[async_trait::async_trait]
pub trait PolicyEngine: std::fmt::Debug + Send + Sync {
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

    /// Resolve the fine-grained constraints (row filters + column masks) that
    /// apply when `principal` reads `table` with schema `schema`, as a neutral
    /// [`TablePolicy`](crate::govern::TablePolicy) carrier.
    ///
    /// Every engine reduces its native fine-grained shape to this carrier: a
    /// Cedar partial-eval residual boolean, an OPA `/v1/compile` residual, or an
    /// OpenFGA `ListObjects` id set (as a `col(id).in_list(...)` row filter) all
    /// land here. Default: no constraints. The Cedar implementation derives
    /// filters and masks from policy residuals; see `crate::govern`.
    #[cfg(feature = "governance")]
    async fn constrain(
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

/// A [`PolicyEngine`] that returns the same decision for every query.
///
/// The non-engine implementation that proves the trait needs no policy engine:
/// used as the default when nothing real is wired (e.g.
/// `StaticPolicyEngine::new(Decision::Allow)` for an open, ungoverned server).
#[derive(Debug, Clone)]
pub struct StaticPolicyEngine {
    decision: Decision,
}

impl StaticPolicyEngine {
    pub fn new(decision: Decision) -> Self {
        Self { decision }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for StaticPolicyEngine {
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
    async fn static_engine_returns_its_decision() {
        let plan = LogicalPlanBuilder::empty(false).build().unwrap();
        let allow = StaticPolicyEngine::new(Decision::Allow);
        let deny = StaticPolicyEngine::new(Decision::Deny);
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
