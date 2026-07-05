//! Engine-neutral policy enforcement for Apache DataFusion.
//!
//! This crate is the DataFusion-aware, **engine-agnostic** core of the policy
//! stack — the policy analog of `datafusion-openlineage`. It owns the
//! decide/enforce split:
//!
//! - **Decide** — the [`PolicyEngine`] trait: the contract a policy engine
//!   implements to answer *what is allowed* (coarse gate) and *what constraints
//!   apply* (row filters + column masks). It names no engine type; a Cedar
//!   adapter lives in [`datafusion-policy-cedar`](https://docs.rs/olai-datafusion-policy-cedar),
//!   and an OPA or OpenFGA adapter could implement the same trait.
//! - **Enforce** — the [`PolicyQueryPlanner`] (a `QueryPlanner` wrapper) and the
//!   pre-optimize plan rewrite ([`govern_plan`], under `fgac`) that apply
//!   the engine's answers to a session.
//!
//! Everything here is expressed in neutral types — [`Decision`], [`AttrValue`],
//! [`PrincipalIdentity`], [`TableFacts`], DataFusion [`Expr`]s — so no policy
//! engine leaks through the seam.
//!
//! Two layers:
//!
//! - **Layer 1 — coarse access gate** ([`PolicyEngine::is_allowed`]): does the
//!   principal have access to the tables/actions a query references?
//! - **Layer 2 — fine-grained governance** (feature `fgac`): row filters
//!   and column masks the engine derives, applied before optimization.
//!
//! [`Expr`]: datafusion::logical_expr::Expr

mod constraint;
mod engine;
mod facts;
mod plan_actions;
mod principal;
mod rule;
mod session;
mod types;

#[cfg(feature = "fgac")]
mod abac;
#[cfg(feature = "fgac")]
mod binding;
#[cfg(feature = "fgac")]
mod fact_store;
#[cfg(feature = "fgac")]
mod function;
#[cfg(feature = "fgac")]
pub mod govern;
#[cfg(feature = "fgac")]
mod provider;

pub use constraint::ConstraintTranslator;
pub use engine::{PolicyEngine, StaticPolicyEngine};
pub use facts::{CatalogFactSink, EvalContext, TableFacts, normalize};
pub use plan_actions::{PlanAction, plan_actions};
pub use principal::{
    AgentClaims, Group, IdentityError, IdentityProvider, PrincipalClaims, PrincipalEnrichment,
    PrincipalIdentity,
};
pub use rule::PolicyQueryPlanner;
pub use session::{
    CatalogFactSinkExt, EvalContextProvider, PolicyBuilder, PolicyEngineExt, PolicyExtension,
    PolicySessionExt, PrincipalExt, PrincipalProvider, SessionConfigEvalContextProvider,
    SessionConfigPrincipalProvider, authorize_and_govern, instrument_session_state,
};
pub use types::{AttrValue, Decision};

#[cfg(feature = "fgac")]
pub use abac::{AbacPolicyEngine, DefaultPrincipalMatcher, PrincipalMatcher};
#[cfg(feature = "fgac")]
pub use binding::{BindingKind, ColumnMatch, FunctionArg, PolicyBinding, TagCondition};
#[cfg(feature = "fgac")]
pub use fact_store::{FactStore, InMemoryFactStore};
#[cfg(feature = "fgac")]
pub use function::CatalogFunctionResolver;
#[cfg(feature = "fgac")]
pub use govern::{TablePolicy, govern_plan};
#[cfg(feature = "fgac")]
pub use provider::{GovernedTableProvider, govern_provider, govern_provider_from_config};
#[cfg(feature = "fgac")]
pub use session::{FactStoreExt, FunctionResolverExt};
