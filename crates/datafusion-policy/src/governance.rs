//! The one-obvious-way host entry point: [`Governance`] + [`Posture`].
//!
//! Consuming the policy layer directly means wiring several `SessionConfig`
//! extensions in the right order, remembering to enrich the principal through an
//! [`IdentityProvider`], and choosing an enforcement stance — with silent
//! fail-*open* if any piece is forgotten (a missing engine degrades to
//! `StaticPolicyEngine(Allow)`; a forgotten principal binding, an un-set function
//! resolver, …). [`Governance`] replaces that with a single builder assembled
//! **once per server** and an explicit, spelled-out [`Posture`].
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use olai_datafusion_policy::{Governance, Posture, PolicyEngine};
//! # fn demo(engine: Arc<dyn PolicyEngine>) -> datafusion_common::Result<()> {
//! let gov = Governance::builder()
//!     .posture(Posture::Enforcing)
//!     .engine(engine)
//!     .build()?; // Enforcing + no engine => Err at startup
//! # let _ = gov;
//! # Ok(())
//! # }
//! ```
//!
//! Per session / per request:
//!
//! - [`Governance::bind_principal`] runs the [`IdentityProvider`] enrichment
//!   (fail-closed under [`Posture::Enforcing`]) and folds it onto the principal,
//!   so "forgot to enrich" is no longer possible.
//! - [`Governance::attach`] sets **all** the `SessionConfig` extensions the
//!   enforcement layer reads, in one call, taking the principal as a required
//!   argument — so "forgot to bind the principal" is unrepresentable at the call
//!   site.
//! - [`Governance::instrument`] wraps the session's planner (a no-op under
//!   [`Posture::Disabled`]). A host that composes its own planner instead reads
//!   [`Governance::engine`] / the provider accessors and sequences enforcement
//!   itself.

use std::sync::Arc;

use datafusion::execution::context::SessionState;
use datafusion::prelude::SessionConfig;

use datafusion_common::{Result, exec_err};

use crate::engine::PolicyEngine;
use crate::principal::{IdentityProvider, PrincipalClaims, PrincipalIdentity};
use crate::session::{CatalogFactSinkExt, PolicyBuilder, PolicyEngineExt, PrincipalExt};

#[cfg(feature = "fgac")]
use crate::fact_store::{FactStore, InMemoryFactStore};
#[cfg(feature = "fgac")]
use crate::function::CatalogFunctionResolver;
#[cfg(feature = "fgac")]
use crate::session::{FactStoreExt, FunctionResolverExt};

/// The runtime enforcement stance, chosen once at build time so an ungoverned
/// session is never the accidental result of a forgotten wire-up.
///
/// The three modes are the whole enforcement contract:
///
/// - [`Disabled`](Posture::Disabled) — no planner is installed; the *only*
///   ungoverned mode, and it must be named explicitly. Nothing evaluates.
/// - [`Permissive`](Posture::Permissive) — evaluate everything (the coarse gate
///   *and* the row/column constraints) and emit structured logs of what *would*
///   have been enforced (`decision`, `would_block`, `would_constrain`), but
///   enforce nothing: a `Deny` does not error and constraints are not applied.
///   The rollout / dry-run stance.
/// - [`Enforcing`](Posture::Enforcing) — fail-closed: deny errors, masks/filters
///   are applied, an unbound principal is rejected. The production stance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// No enforcement installed at all.
    Disabled,
    /// Evaluate + log, enforce nothing.
    Permissive,
    /// Fail-closed enforcement.
    Enforcing,
}

impl Posture {
    /// Whether a planner should be installed for this posture (everything except
    /// [`Disabled`](Posture::Disabled)).
    fn installs_planner(self) -> bool {
        !matches!(self, Posture::Disabled)
    }
}

/// A fully-assembled governance profile: the policy engine plus the optional
/// identity / function / fact-store providers, and the runtime [`Posture`].
///
/// Built once per server via [`Governance::builder`]; cheap to clone (`Arc`s
/// inside). See the [module docs](self) for the per-session recipe.
#[derive(Debug, Clone)]
pub struct Governance {
    posture: Posture,
    engine: Arc<dyn PolicyEngine>,
    identity_provider: Option<Arc<dyn IdentityProvider>>,
    #[cfg(feature = "fgac")]
    function_resolver: Option<Arc<dyn CatalogFunctionResolver>>,
    #[cfg(feature = "fgac")]
    fact_store: Arc<dyn FactStore>,
}

impl Governance {
    /// Start assembling a [`Governance`] profile.
    pub fn builder() -> GovernanceBuilder {
        GovernanceBuilder::default()
    }

    /// The runtime enforcement posture.
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// The policy engine, for a host composing its own planner instead of using
    /// [`instrument`](Self::instrument).
    pub fn engine(&self) -> &Arc<dyn PolicyEngine> {
        &self.engine
    }

    /// The configured identity provider, if any.
    pub fn identity_provider(&self) -> Option<&Arc<dyn IdentityProvider>> {
        self.identity_provider.as_ref()
    }

    /// The configured catalog function resolver, if any.
    #[cfg(feature = "fgac")]
    pub fn function_resolver(&self) -> Option<&Arc<dyn CatalogFunctionResolver>> {
        self.function_resolver.as_ref()
    }

    /// The session fact store (taint ledger). Defaults to an
    /// [`InMemoryFactStore`] when none was supplied.
    #[cfg(feature = "fgac")]
    pub fn fact_store(&self) -> &Arc<dyn FactStore> {
        &self.fact_store
    }

    /// Enrich `base` with identity facts and return the resolved principal.
    ///
    /// Runs [`IdentityProvider::enrich`] keyed on `base.uid` and folds the result
    /// onto the principal (IdP-sourced attributes override client-asserted ones;
    /// see [`PrincipalIdentity::enriched`]). With no identity provider configured
    /// this is a pass-through. An enrichment error is **fail-closed under
    /// [`Posture::Enforcing`]** (returns `Err`); under [`Posture::Permissive`] /
    /// [`Posture::Disabled`] it is logged and the un-enriched principal is
    /// returned so a dry run still proceeds.
    pub async fn bind_principal(
        &self,
        claims: PrincipalClaims,
        base: PrincipalIdentity,
    ) -> Result<PrincipalIdentity> {
        let Some(idp) = &self.identity_provider else {
            return Ok(base);
        };
        match idp.enrich(&base.uid, &claims).await {
            Ok(enrichment) => Ok(base.enriched(enrichment)),
            Err(e) => match self.posture {
                Posture::Enforcing => {
                    exec_err!("identity enrichment failed for '{}': {e}", base.uid)
                }
                _ => {
                    tracing::warn!(
                        target: "breakwater::governance",
                        posture = ?self.posture,
                        principal = %base.uid,
                        error = %e,
                        "identity enrichment failed; proceeding un-enriched (not enforcing)"
                    );
                    Ok(base)
                }
            },
        }
    }

    /// Attach **every** `SessionConfig` extension the enforcement layer reads, in
    /// one call: the principal ([`PrincipalExt`]), a **fresh**
    /// [`CatalogFactSinkExt`] (per-session, so facts don't leak across sessions),
    /// the [`PolicyEngineExt`], and — under `fgac` — the [`FactStoreExt`] and any
    /// [`FunctionResolverExt`].
    ///
    /// Taking `principal` as a required parameter makes "forgot to bind the
    /// principal" unrepresentable here. Under [`Posture::Enforcing`] the planner
    /// still fails closed if the principal is somehow absent downstream (defense
    /// in depth); this method simply guarantees it is present.
    pub fn attach(&self, config: SessionConfig, principal: PrincipalIdentity) -> SessionConfig {
        let mut config = config;
        config.set_extension(Arc::new(PrincipalExt(principal)));
        // A fresh sink per session: catalog facts are per-query-scoped and must
        // not bleed between sessions sharing this profile.
        config.set_extension(Arc::new(CatalogFactSinkExt::default()));
        config.set_extension(Arc::new(PolicyEngineExt(self.engine.clone())));

        #[cfg(feature = "fgac")]
        {
            config.set_extension(Arc::new(FactStoreExt(self.fact_store.clone())));
            if let Some(resolver) = &self.function_resolver {
                config.set_extension(Arc::new(FunctionResolverExt(resolver.clone())));
            }
        }

        config
    }

    /// Wrap the session's [`QueryPlanner`](datafusion::execution::context::QueryPlanner)
    /// with policy enforcement at this profile's posture.
    ///
    /// Under [`Posture::Disabled`] the state is returned untouched (no planner
    /// installed — the one ungoverned mode). Otherwise delegates to
    /// [`PolicyBuilder::instrument`], carrying the posture into the planner.
    ///
    /// A host that composes its own `QueryPlanner` (e.g. one sequencing policy +
    /// lineage) should not call this — read [`engine`](Self::engine) and the
    /// provider accessors and build the composed planner directly.
    pub fn instrument(&self, state: SessionState) -> SessionState {
        if !self.posture.installs_planner() {
            return state;
        }
        PolicyBuilder::default()
            .policy(self.engine.clone())
            .posture(self.posture)
            .instrument(state)
    }
}

/// Builder for [`Governance`]. See [`Governance::builder`].
#[derive(Default)]
pub struct GovernanceBuilder {
    posture: Option<Posture>,
    engine: Option<Arc<dyn PolicyEngine>>,
    identity_provider: Option<Arc<dyn IdentityProvider>>,
    #[cfg(feature = "fgac")]
    function_resolver: Option<Arc<dyn CatalogFunctionResolver>>,
    #[cfg(feature = "fgac")]
    fact_store: Option<Arc<dyn FactStore>>,
}

impl std::fmt::Debug for GovernanceBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("GovernanceBuilder");
        s.field("posture", &self.posture)
            .field("has_engine", &self.engine.is_some())
            .field("has_identity_provider", &self.identity_provider.is_some());
        #[cfg(feature = "fgac")]
        s.field("has_function_resolver", &self.function_resolver.is_some())
            .field("has_fact_store", &self.fact_store.is_some());
        s.finish()
    }
}

impl GovernanceBuilder {
    /// Set the runtime [`Posture`] (required in spirit; defaults to
    /// [`Posture::Enforcing`] if unset, the safe default).
    pub fn posture(mut self, posture: Posture) -> Self {
        self.posture = Some(posture);
        self
    }

    /// Set the policy engine. Required under [`Posture::Permissive`] /
    /// [`Posture::Enforcing`]; [`build`](Self::build) errors without one.
    pub fn engine(mut self, engine: Arc<dyn PolicyEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Set the identity provider used by [`Governance::bind_principal`].
    /// Optional — with none configured, `bind_principal` is a pass-through.
    pub fn identity_provider(mut self, idp: Arc<dyn IdentityProvider>) -> Self {
        self.identity_provider = Some(idp);
        self
    }

    /// Set the catalog function resolver (for policy-named masking / row-filter
    /// UDFs). Optional; without it a policy naming a function fails closed.
    #[cfg(feature = "fgac")]
    pub fn function_resolver(mut self, resolver: Arc<dyn CatalogFunctionResolver>) -> Self {
        self.function_resolver = Some(resolver);
        self
    }

    /// Set the session fact store (taint ledger). Optional; defaults to a
    /// process-wide [`InMemoryFactStore`].
    #[cfg(feature = "fgac")]
    pub fn fact_store(mut self, store: Arc<dyn FactStore>) -> Self {
        self.fact_store = Some(store);
        self
    }

    /// Validate and assemble the [`Governance`] profile.
    ///
    /// Fails at **startup** (not silently at query time) when the configuration
    /// cannot enforce what its posture promises:
    ///
    /// - [`Posture::Permissive`] / [`Posture::Enforcing`] require an engine;
    ///   without one, `build` errors rather than degrading to allow-all.
    /// - [`Posture::Disabled`] needs no engine — a `StaticPolicyEngine(Allow)`
    ///   stand-in is installed since none is used (the planner isn't installed).
    ///
    /// A completeness *warning* (logged, not an error) fires when an enforcing
    /// engine has no function resolver — a policy that names a masking function
    /// would then fail closed at query time.
    pub fn build(self) -> Result<Arc<Governance>> {
        let posture = self.posture.unwrap_or(Posture::Enforcing);

        let engine = match (self.engine, posture) {
            (Some(engine), _) => engine,
            (None, Posture::Disabled) => {
                // Never consulted (no planner installed), but the field is
                // non-optional so enforcement code needn't special-case it.
                Arc::new(crate::engine::StaticPolicyEngine::new(
                    crate::types::Decision::Allow,
                ))
            }
            (None, _) => {
                return exec_err!(
                    "Governance posture {posture:?} requires a policy engine; none was set"
                );
            }
        };

        #[cfg(feature = "fgac")]
        if posture == Posture::Enforcing && self.function_resolver.is_none() {
            tracing::warn!(
                target: "breakwater::governance",
                "Enforcing governance has no function resolver; policies that name a \
                 masking / row-filter function will fail closed at query time"
            );
        }

        Ok(Arc::new(Governance {
            posture,
            engine,
            identity_provider: self.identity_provider,
            #[cfg(feature = "fgac")]
            function_resolver: self.function_resolver,
            #[cfg(feature = "fgac")]
            fact_store: self
                .fact_store
                .unwrap_or_else(|| Arc::new(InMemoryFactStore::new())),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::prelude::SessionContext;

    use super::*;
    use crate::engine::StaticPolicyEngine;
    use crate::principal::{IdentityError, PrincipalEnrichment};
    use crate::types::{AttrValue, Decision};

    fn deny_engine() -> Arc<dyn PolicyEngine> {
        Arc::new(StaticPolicyEngine::new(Decision::Deny))
    }
    fn allow_engine() -> Arc<dyn PolicyEngine> {
        Arc::new(StaticPolicyEngine::new(Decision::Allow))
    }

    fn alice() -> PrincipalIdentity {
        PrincipalIdentity::new("User::\"alice\"")
    }

    /// Register a one-column in-memory table so a `SELECT` has something to plan.
    fn register_table(ctx: &SessionContext) {
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
        ctx.register_batch("t", RecordBatch::new_empty(schema))
            .unwrap();
    }

    async fn plan_select(ctx: &SessionContext) -> datafusion_common::Result<()> {
        let logical = ctx.state().create_logical_plan("SELECT id FROM t").await?;
        ctx.state().create_physical_plan(&logical).await.map(|_| ())
    }

    /// Build a `Governance`-instrumented context: attach the principal, then wrap
    /// the planner. Register the table last so it lands on the final catalog.
    fn governed_ctx(gov: &Governance, principal: Option<PrincipalIdentity>) -> SessionContext {
        let mut config = SessionConfig::new();
        if let Some(p) = principal {
            config = gov.attach(config, p);
        }
        let state = datafusion::execution::SessionStateBuilder::new()
            .with_config(config)
            .with_default_features()
            .build();
        let state = gov.instrument(state);
        let ctx = SessionContext::new_with_state(state);
        register_table(&ctx);
        ctx
    }

    #[test]
    fn enforcing_without_engine_errs_at_build() {
        let err = Governance::builder()
            .posture(Posture::Enforcing)
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("requires a policy engine"),
            "got: {err}"
        );
    }

    #[test]
    fn disabled_without_engine_builds() {
        // Disabled needs no engine — it installs nothing.
        Governance::builder()
            .posture(Posture::Disabled)
            .build()
            .expect("Disabled builds without an engine");
    }

    #[test]
    fn attach_sets_all_extensions() {
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(allow_engine())
            .build()
            .unwrap();
        let config = gov.attach(SessionConfig::new(), alice());

        assert!(
            config.get_extension::<PrincipalExt>().is_some(),
            "PrincipalExt"
        );
        assert!(
            config.get_extension::<CatalogFactSinkExt>().is_some(),
            "CatalogFactSinkExt"
        );
        assert!(
            config.get_extension::<PolicyEngineExt>().is_some(),
            "PolicyEngineExt"
        );
        #[cfg(feature = "fgac")]
        assert!(
            config.get_extension::<FactStoreExt>().is_some(),
            "FactStoreExt"
        );
    }

    #[cfg(feature = "fgac")]
    #[test]
    fn attach_sets_function_resolver_only_when_configured() {
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(allow_engine())
            .build()
            .unwrap();
        // No resolver configured => extension absent.
        let config = gov.attach(SessionConfig::new(), alice());
        assert!(config.get_extension::<FunctionResolverExt>().is_none());
    }

    #[tokio::test]
    async fn disabled_leaves_state_untouched() {
        // A Deny engine under Disabled installs no planner, so a query plans fine.
        let gov = Governance::builder()
            .posture(Posture::Disabled)
            .engine(deny_engine())
            .build()
            .unwrap();
        let ctx = governed_ctx(&gov, Some(alice()));
        plan_select(&ctx)
            .await
            .expect("Disabled must not enforce anything");
    }

    #[tokio::test]
    async fn permissive_logs_but_does_not_block() {
        // A Deny engine under Permissive must NOT error — the query still plans.
        let gov = Governance::builder()
            .posture(Posture::Permissive)
            .engine(deny_engine())
            .build()
            .unwrap();
        let ctx = governed_ctx(&gov, Some(alice()));
        plan_select(&ctx)
            .await
            .expect("Permissive must not block a Deny");
    }

    #[tokio::test]
    async fn enforcing_blocks_on_deny() {
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(deny_engine())
            .build()
            .unwrap();
        let ctx = governed_ctx(&gov, Some(alice()));
        let err = plan_select(&ctx).await.unwrap_err();
        assert!(err.to_string().contains("not authorized"), "got: {err}");
    }

    #[tokio::test]
    async fn missing_principal_under_enforcing_fails_closed() {
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(allow_engine())
            .build()
            .unwrap();
        // No principal attached.
        let ctx = governed_ctx(&gov, None);
        let err = plan_select(&ctx).await.unwrap_err();
        assert!(err.to_string().contains("no principal bound"), "got: {err}");
    }

    #[tokio::test]
    async fn missing_principal_under_permissive_passes_through() {
        let gov = Governance::builder()
            .posture(Posture::Permissive)
            .engine(deny_engine())
            .build()
            .unwrap();
        let ctx = governed_ctx(&gov, None);
        plan_select(&ctx)
            .await
            .expect("Permissive with no principal must pass through");
    }

    // --- bind_principal ---

    #[derive(Debug)]
    struct FixedIdp(PrincipalEnrichment);

    #[async_trait]
    impl IdentityProvider for FixedIdp {
        async fn enrich(
            &self,
            _uid: &str,
            _claims: &PrincipalClaims,
        ) -> std::result::Result<PrincipalEnrichment, IdentityError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct FailingIdp;

    #[async_trait]
    impl IdentityProvider for FailingIdp {
        async fn enrich(
            &self,
            _uid: &str,
            _claims: &PrincipalClaims,
        ) -> std::result::Result<PrincipalEnrichment, IdentityError> {
            Err(IdentityError::Provider("boom".into()))
        }
    }

    #[tokio::test]
    async fn bind_principal_no_idp_is_passthrough() {
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(allow_engine())
            .build()
            .unwrap();
        let bound = gov
            .bind_principal(PrincipalClaims::default(), alice())
            .await
            .unwrap();
        assert_eq!(bound.uid, "User::\"alice\"");
        assert!(bound.attributes.is_empty());
    }

    #[tokio::test]
    async fn bind_principal_applies_enrichment_and_idp_overrides() {
        let enrichment = PrincipalEnrichment {
            attributes: HashMap::from([(
                "role".to_string(),
                AttrValue::String("idp-authoritative".into()),
            )]),
            groups: vec!["UserGroup::\"readers\"".into()],
            ..Default::default()
        };
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(allow_engine())
            .identity_provider(Arc::new(FixedIdp(enrichment)))
            .build()
            .unwrap();
        // Client-asserted role should be overridden by the IdP's.
        let base = alice().with_attribute("role", "client-claimed");
        let bound = gov
            .bind_principal(PrincipalClaims::default(), base)
            .await
            .unwrap();
        assert_eq!(
            bound.attributes.get("role"),
            Some(&AttrValue::String("idp-authoritative".into()))
        );
        assert_eq!(bound.groups, vec!["UserGroup::\"readers\""]);
    }

    #[tokio::test]
    async fn bind_principal_enrichment_error_fails_closed_when_enforcing() {
        let gov = Governance::builder()
            .posture(Posture::Enforcing)
            .engine(allow_engine())
            .identity_provider(Arc::new(FailingIdp))
            .build()
            .unwrap();
        let err = gov
            .bind_principal(PrincipalClaims::default(), alice())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("enrichment failed"), "got: {err}");
    }

    #[tokio::test]
    async fn bind_principal_enrichment_error_tolerated_when_permissive() {
        let gov = Governance::builder()
            .posture(Posture::Permissive)
            .engine(allow_engine())
            .identity_provider(Arc::new(FailingIdp))
            .build()
            .unwrap();
        // Permissive: enrichment error is logged, un-enriched principal returned.
        let bound = gov
            .bind_principal(PrincipalClaims::default(), alice())
            .await
            .expect("permissive tolerates enrichment error");
        assert_eq!(bound.uid, "User::\"alice\"");
    }
}
