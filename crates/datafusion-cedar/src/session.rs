//! The customer-facing entry point: [`PolicyExtension::builder`].
//!
//! One builder assembles the pieces a policy integration needs — a
//! [`PolicyEngine`], a [`PrincipalProvider`], and an [`EvalContextProvider`] — and
//! installs them on a `SessionState` by wrapping its [`QueryPlanner`] with a
//! [`PolicyQueryPlanner`]. This is the policy analog of
//! `datafusion_openlineage`'s `OpenLineage::builder(…).instrument(state)`: the
//! host composes it onto a session without knowing the enforcement internals,
//! and it nests with other query-planner-wrapping extensions (lineage) because
//! each wrapper delegates its physical phase to the next planner in the chain.
//!
//! Per-request state (the principal, the catalog facts / taint ledger) flows in
//! through `SessionConfig` typed extensions the host attaches, read back by the
//! provider traits — so the crate never depends on host types. The default
//! providers ([`SessionConfigPrincipalProvider`], [`SessionConfigEvalContextProvider`])
//! read the extension newtypes this crate owns ([`PrincipalExt`],
//! [`CatalogFactSinkExt`], and — under `governance` — [`FactStoreExt`]); the host
//! populates them.

use std::sync::Arc;

use async_trait::async_trait;
use datafusion::execution::SessionStateBuilder;
use datafusion::execution::context::{QueryPlanner, SessionContext, SessionState};
use datafusion::logical_expr::LogicalPlan;

use datafusion_common::{Result, exec_err};

use crate::facts::{CatalogFactSink, EvalContext};
use crate::policy::{PolicyEngine, StaticPolicyEngine};
use crate::principal::PrincipalIdentity;
use crate::rule::PolicyQueryPlanner;
use crate::types::Decision;

/// The `SessionConfig` extension carrying the per-request principal.
///
/// A distinct newtype so `SessionConfig::get_extension` (which keys by
/// `TypeId`) resolves it unambiguously. The host attaches it (see
/// `with_principal`); [`SessionConfigPrincipalProvider`] reads it back.
#[derive(Debug, Clone)]
pub struct PrincipalExt(pub PrincipalIdentity);

/// The `SessionConfig` extension carrying the per-query [`CatalogFactSink`] the
/// catalog writes resource facts into and the policy layer reads.
#[derive(Debug, Clone, Default)]
pub struct CatalogFactSinkExt(pub CatalogFactSink);

/// The `SessionConfig` extension carrying the session's taint ledger, attached
/// to the per-query state so the policy layer can build the [`EvalContext`].
#[cfg(feature = "governance")]
#[derive(Clone)]
pub struct FactStoreExt(pub Arc<dyn crate::FactStore>);

/// Resolves the principal a query runs as, from a [`SessionState`].
///
/// Mirrors `datafusion_openlineage`'s `LineageContextProvider`: the provider
/// only sees a `SessionState`, so per-request data reaches it through a typed
/// `SessionConfig` extension. The default [`SessionConfigPrincipalProvider`]
/// reads the [`PrincipalExt`] extension; a host can supply its own.
#[async_trait]
pub trait PrincipalProvider: std::fmt::Debug + Send + Sync {
    async fn principal(&self, state: &SessionState) -> Option<PrincipalIdentity>;
}

/// Assembles the per-query [`EvalContext`] from a [`SessionState`].
///
/// The policy layer needs the catalog facts, the correlation id, and (under
/// `governance`) the taint ledger — none of which live on the plan. This trait
/// is the seam that gathers them; the default
/// [`SessionConfigEvalContextProvider`] reads them from `SessionConfig`
/// extensions the host attached.
#[async_trait]
pub trait EvalContextProvider: std::fmt::Debug + Send + Sync {
    async fn eval_context(&self, state: &SessionState) -> EvalContext;
}

/// A [`PrincipalProvider`] that reads the [`PrincipalIdentity`] attached to the
/// session's `SessionConfig` as a [`PrincipalExt`] extension.
#[derive(Debug, Default)]
pub struct SessionConfigPrincipalProvider;

#[async_trait]
impl PrincipalProvider for SessionConfigPrincipalProvider {
    async fn principal(&self, state: &SessionState) -> Option<PrincipalIdentity> {
        state
            .config()
            .get_extension::<PrincipalExt>()
            .map(|ext| ext.0.clone())
    }
}

/// An [`EvalContextProvider`] that assembles the [`EvalContext`] from the
/// session's `SessionConfig` extensions: the catalog fact sink and (under
/// `governance`) the correlation id + taint ledger. The correlation id is the
/// session id, stable per connection.
#[derive(Debug, Default)]
pub struct SessionConfigEvalContextProvider;

#[async_trait]
impl EvalContextProvider for SessionConfigEvalContextProvider {
    async fn eval_context(&self, state: &SessionState) -> EvalContext {
        let catalog_facts = state
            .config()
            .get_extension::<CatalogFactSinkExt>()
            .map(|ext| ext.0.clone())
            .unwrap_or_default();

        #[cfg(feature = "governance")]
        {
            EvalContext {
                catalog_facts,
                correlation_id: Some(state.session_id().to_string()),
                fact_store: state
                    .config()
                    .get_extension::<FactStoreExt>()
                    .map(|ext| ext.0.clone()),
            }
        }
        #[cfg(not(feature = "governance"))]
        {
            EvalContext {
                catalog_facts,
                correlation_id: Some(state.session_id().to_string()),
            }
        }
    }
}

/// Inject fine-grained governance (row filters + column masks) into a plan
/// before optimization.
///
/// With the `governance` feature this delegates to [`crate::govern::govern_plan`];
/// without it (the default), it is a no-op that returns the plan unchanged — the
/// coarse access gate still applies.
#[cfg(feature = "governance")]
async fn govern_plan(
    plan: &LogicalPlan,
    policy: &dyn PolicyEngine,
    principal: &PrincipalIdentity,
    eval: &EvalContext,
) -> Result<LogicalPlan> {
    crate::govern::govern_plan(plan, policy, principal, eval).await
}

#[cfg(not(feature = "governance"))]
async fn govern_plan(
    plan: &LogicalPlan,
    _policy: &dyn PolicyEngine,
    _principal: &PrincipalIdentity,
    _eval: &EvalContext,
) -> Result<LogicalPlan> {
    Ok(plan.clone())
}

/// Govern `plan` (row filters + column masks), then gate the optimized plan on
/// the coarse access policy — the shared enforcement sequence.
///
/// Returns the *governed* logical plan on `Allow` (the caller may execute or
/// further plan it), or an authorization error on `Deny`. This is the single
/// code path used both by [`PolicyQueryPlanner`] (the statement path) and by
/// hosts enforcing on a write path that bypasses physical planning (e.g. a
/// managed-table bulk-ingest append): one policy, one implementation.
///
/// `state` is used to optimize the governed plan so the gate sees the
/// projections/filters pushed down to the table scan — authorizing against the
/// data actually accessed.
pub async fn authorize_and_govern(
    state: &SessionState,
    plan: &LogicalPlan,
    policy: &dyn PolicyEngine,
    principal: &PrincipalIdentity,
    eval: &EvalContext,
) -> Result<LogicalPlan> {
    let governed = govern_plan(plan, policy, principal, eval).await?;
    let optimized = state.optimize(&governed)?;
    if policy.is_allowed(&optimized, principal, eval).await? == Decision::Deny {
        return exec_err!(
            "Principal '{}' is not authorized to execute this query",
            principal.uid
        );
    }
    Ok(governed)
}

/// Entry point for instrumenting a DataFusion session with Cedar policy
/// enforcement.
///
/// Construct a [`PolicyBuilder`] with [`PolicyExtension::builder`].
#[derive(Debug)]
pub struct PolicyExtension;

impl PolicyExtension {
    /// Start configuring policy instrumentation.
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }
}

/// Builds and installs policy enforcement on a [`SessionState`].
///
/// Set a policy and, optionally, the principal / eval-context providers; then
/// call [`Self::instrument`]. The providers default to the `SessionConfig`
/// read-backs, and the policy defaults to `StaticPolicyEngine(Allow)` (an ungoverned
/// session).
#[derive(Default)]
pub struct PolicyBuilder {
    policy: Option<Arc<dyn PolicyEngine>>,
    principal: Option<Arc<dyn PrincipalProvider>>,
    eval: Option<Arc<dyn EvalContextProvider>>,
}

impl std::fmt::Debug for PolicyBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyBuilder")
            .field("has_policy", &self.policy.is_some())
            .field("has_principal", &self.principal.is_some())
            .field("has_eval", &self.eval.is_some())
            .finish()
    }
}

impl PolicyBuilder {
    /// Set the policy to enforce. Defaults to `StaticPolicyEngine(Allow)`.
    pub fn policy(mut self, policy: Arc<dyn PolicyEngine>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the per-request principal provider. Defaults to
    /// [`SessionConfigPrincipalProvider`].
    pub fn principal(mut self, principal: Arc<dyn PrincipalProvider>) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Set the per-query eval-context provider. Defaults to
    /// [`SessionConfigEvalContextProvider`].
    pub fn eval_context(mut self, eval: Arc<dyn EvalContextProvider>) -> Self {
        self.eval = Some(eval);
        self
    }

    /// Install the enforcement on `state`, returning the wired `SessionState`.
    ///
    /// Wraps the session's current [`QueryPlanner`] with a [`PolicyQueryPlanner`]
    /// that runs govern → optimize → gate before delegating physical planning to
    /// the wrapped planner — so a pre-existing custom planner (e.g. a Unity DDL
    /// planner, or a lineage planner) is preserved as the inner planner. Also
    /// stashes the planner as a typed `SessionConfig` extension so a host can
    /// recover it with `get_extension::<PolicyQueryPlanner>()` (the `QueryPlanner`
    /// trait isn't `Any`-downcastable). One `Arc`, two roles.
    pub fn instrument(self, state: SessionState) -> SessionState {
        let policy = self
            .policy
            .unwrap_or_else(|| Arc::new(StaticPolicyEngine::new(Decision::Allow)));
        let principal = self
            .principal
            .unwrap_or_else(|| Arc::new(SessionConfigPrincipalProvider));
        let eval = self
            .eval
            .unwrap_or_else(|| Arc::new(SessionConfigEvalContextProvider));

        let inner: Arc<dyn QueryPlanner + Send + Sync> = state.query_planner().clone();
        let planner = Arc::new(PolicyQueryPlanner::new(policy, principal, eval, inner));

        let mut session_config = state.config().clone();
        session_config.set_extension(planner.clone());
        SessionStateBuilder::from(state)
            .with_config(session_config)
            .with_query_planner(planner)
            .build()
    }
}

/// Instrument `state` with an explicit policy and providers.
///
/// A thin wrapper over [`PolicyExtension::builder`] for callers that already
/// hold the pieces. Prefer the builder for new code.
pub fn instrument_session_state(
    state: SessionState,
    policy: Arc<dyn PolicyEngine>,
    principal: Arc<dyn PrincipalProvider>,
    eval: Arc<dyn EvalContextProvider>,
) -> SessionState {
    PolicyExtension::builder()
        .policy(policy)
        .principal(principal)
        .eval_context(eval)
        .instrument(state)
}

/// `SessionContext` ergonomics for policy instrumentation.
///
/// [`with_policy`](Self::with_policy) installs the enforcement on a context in
/// one consume-and-return call, mirroring `datafusion_openlineage`'s
/// `OpenLineageSqlExt::with_lineage` and DataFusion's own
/// `SessionContext::enable_url_table(self) -> Self`. `None` uses defaults (a
/// `StaticPolicyEngine(Allow)` and the `SessionConfig` read-back providers).
pub trait PolicySessionExt: Sized {
    /// Instrument this context with policy enforcement and return it.
    ///
    /// Pass a configured [`PolicyBuilder`] to control the policy and providers,
    /// or `None` for defaults. Because the argument is
    /// `impl Into<Option<PolicyBuilder>>`, both `ctx.with_policy(None)` and
    /// `ctx.with_policy(PolicyExtension::builder()…)` are valid call sites.
    fn with_policy(self, builder: impl Into<Option<PolicyBuilder>>) -> Self;
}

impl PolicySessionExt for SessionContext {
    fn with_policy(self, builder: impl Into<Option<PolicyBuilder>>) -> Self {
        let builder = builder.into().unwrap_or_default();
        SessionContext::new_with_state(builder.instrument(self.state()))
    }
}
