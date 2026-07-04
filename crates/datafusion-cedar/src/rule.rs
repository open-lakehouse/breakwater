//! The query-planner seam: [`PolicyQueryPlanner`].
//!
//! Enforcement is `&SessionState`-bound and async (it optimizes the plan and
//! assembles the [`EvalContext`](crate::EvalContext) from session extensions),
//! so the [`QueryPlanner`] hook — the only async, state-bearing seam DataFusion
//! exposes around physical planning — is where it lives, exactly as for
//! `datafusion_openlineage`. Built by [`crate::session::PolicyBuilder::instrument`].

use std::sync::Arc;

use async_trait::async_trait;
use datafusion::execution::context::{QueryPlanner, SessionState};
use datafusion::logical_expr::LogicalPlan;
use datafusion::physical_plan::ExecutionPlan;

use datafusion_common::{Result, exec_err};

use crate::policy::Policy;
use crate::session::{EvalContextProvider, PrincipalProvider, authorize_and_govern};

/// A [`QueryPlanner`] that governs and gates a query before physical planning.
///
/// Its `create_physical_plan` resolves the principal and per-query eval context,
/// runs [`authorize_and_govern`] (row filters + column masks, then the coarse
/// access gate on the optimized plan; a denied query errors), and hands the
/// governed plan to the wrapped inner planner for the actual physical planning.
/// Wrapping an inner planner (rather than owning a `DefaultPhysicalPlanner`) is
/// what lets this compose with other query-planner-wrapping extensions.
pub struct PolicyQueryPlanner {
    policy: Arc<dyn Policy>,
    principal: Arc<dyn PrincipalProvider>,
    eval: Arc<dyn EvalContextProvider>,
    inner: Arc<dyn QueryPlanner + Send + Sync>,
}

impl std::fmt::Debug for PolicyQueryPlanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyQueryPlanner")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl PolicyQueryPlanner {
    /// Build a planner that enforces `policy` (resolving the principal / eval
    /// context via the providers) and delegates physical planning to `inner`.
    pub fn new(
        policy: Arc<dyn Policy>,
        principal: Arc<dyn PrincipalProvider>,
        eval: Arc<dyn EvalContextProvider>,
        inner: Arc<dyn QueryPlanner + Send + Sync>,
    ) -> Self {
        Self {
            policy,
            principal,
            eval,
            inner,
        }
    }
}

#[async_trait]
impl QueryPlanner for PolicyQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let eval = self.eval.eval_context(session_state).await;

        // The host binds the principal into the session (via `PrincipalExt`, or a
        // custom provider) before installing this planner; a `None` here means an
        // unbound session, which we fail closed on rather than authorizing against
        // an invented identity — a deny-by-default policy must not be bypassed by a
        // missing principal.
        let Some(principal) = self.principal.principal(session_state).await else {
            return exec_err!("no principal bound to session; cannot authorize query");
        };

        let governed = authorize_and_govern(
            session_state,
            logical_plan,
            self.policy.as_ref(),
            &principal,
            &eval,
        )
        .await?;

        // Match the plan handed to the inner planner byte-for-byte with what the
        // pre-refactor inline gate did: it optimized then planned the *optimized*
        // plan. `authorize_and_govern` returns the governed (un-optimized) plan;
        // optimize once more here so the inner planner receives the optimized form.
        let optimized = session_state.optimize(&governed)?;
        self.inner
            .create_physical_plan(&optimized, session_state)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::prelude::SessionContext;

    use cedar_oci::{Decision, EntityUid};

    use crate::policy::StaticPolicy;
    use crate::principal::PrincipalIdentity;
    use crate::session::{PolicyExtension, PolicySessionExt, PrincipalExt};

    /// Register a one-column in-memory table so a `SELECT` has something to plan.
    fn register_table(ctx: &SessionContext) {
        let schema =
            std::sync::Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
        ctx.register_batch("t", RecordBatch::new_empty(schema))
            .unwrap();
    }

    /// Build a context with the policy installed and (optionally) a principal
    /// bound, registering the table *last* so it lands on the final context's
    /// catalog (rebuilding state via `new_with_state` would otherwise drop it).
    fn instrumented_ctx(decision: Decision, bind_principal: bool) -> SessionContext {
        let mut state = SessionContext::new().state();
        if bind_principal {
            let principal = PrincipalIdentity::new(EntityUid::from_str("User::\"alice\"").unwrap());
            state
                .config_mut()
                .set_extension(std::sync::Arc::new(PrincipalExt(principal)));
        }
        let ctx = SessionContext::new_with_state(state).with_policy(
            PolicyExtension::builder().policy(std::sync::Arc::new(StaticPolicy::new(decision))),
        );
        register_table(&ctx);
        ctx
    }

    /// Drive a `SELECT id FROM t` through physical planning (the `QueryPlanner`
    /// hook where the gate runs), returning the planning result.
    async fn plan_select(ctx: &SessionContext) -> datafusion_common::Result<()> {
        let logical = ctx.state().create_logical_plan("SELECT id FROM t").await?;
        ctx.state().create_physical_plan(&logical).await.map(|_| ())
    }

    #[tokio::test]
    async fn instrumented_session_denies_on_deny_policy() {
        let ctx = instrumented_ctx(Decision::Deny, true);
        let err = plan_select(&ctx).await.unwrap_err();
        assert!(
            err.to_string().contains("not authorized"),
            "expected an authorization error, got: {err}"
        );
    }

    #[tokio::test]
    async fn instrumented_session_allows_on_allow_policy() {
        let ctx = instrumented_ctx(Decision::Allow, true);
        // Physical planning succeeds under an allow policy.
        plan_select(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn unbound_principal_fails_closed() {
        // No `PrincipalExt` attached: even an allow policy cannot authorize
        // without a principal, so planning fails closed rather than open.
        let ctx = instrumented_ctx(Decision::Allow, false);
        let err = plan_select(&ctx).await.unwrap_err();
        assert!(
            err.to_string().contains("no principal bound"),
            "expected a fail-closed principal error, got: {err}"
        );
    }
}
