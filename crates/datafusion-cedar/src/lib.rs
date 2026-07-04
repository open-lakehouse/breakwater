//! Cedar policy enforcement for Apache DataFusion.
//!
//! This crate is the Cedar **adapter** for the engine-neutral policy layer: it
//! implements the [`PolicyEngine`] decide contract (owned by the neutral core)
//! with a Cedar-backed implementation ([`CedarPolicy`]), plus the
//! [`LogicalPlan`](datafusion::logical_expr::LogicalPlan) walk that turns a
//! query into a set of Cedar authorization requests. Policy *sourcing* (pulling
//! a policy set / schema / entities from an OCI registry) lives in the
//! [`cedar-oci`](https://docs.rs/cedar-oci) crate; engine-specific *glue*
//! (extracting the principal from a request, composing onto a session) lives in
//! the host — see [hydrofoil](https://github.com/open-lakehouse/hydrofoil) for a
//! reference host.
//!
//! Two layers:
//!
//! - **Layer 1 — coarse access gate** ([`PolicyEngine::is_allowed`]): does the
//!   principal have access to the tables/actions a query references?
//! - **Layer 2 — fine-grained governance** (feature `governance`): row filters
//!   and column masks derived from Cedar partial-evaluation residuals.

mod cedar;
mod cedar_entity;
mod facts;
mod policy;
mod principal;
mod rule;
mod session;
mod types;
mod visitor;

#[cfg(feature = "governance")]
mod fact_store;
#[cfg(feature = "governance")]
pub mod govern;
#[cfg(feature = "governance")]
mod translate;

pub use cedar::CedarPolicy;
pub use cedar_entity::{parse_uid, principal_entities};
pub use facts::{CatalogFactSink, EvalContext, TableFacts, normalize};
pub use policy::{PolicyEngine, StaticPolicyEngine};
pub use principal::{
    AgentClaims, Group, IdentityError, IdentityProvider, PrincipalClaims, PrincipalEnrichment,
    PrincipalIdentity,
};
pub use rule::PolicyQueryPlanner;
pub use session::{
    CatalogFactSinkExt, EvalContextProvider, PolicyBuilder, PolicyExtension, PolicySessionExt,
    PrincipalExt, PrincipalProvider, SessionConfigEvalContextProvider,
    SessionConfigPrincipalProvider, authorize_and_govern, instrument_session_state,
};
pub use types::{AttrValue, Decision};

#[cfg(feature = "governance")]
pub use fact_store::{FactStore, InMemoryFactStore};
#[cfg(feature = "governance")]
pub use govern::{TablePolicy, govern_plan};
#[cfg(feature = "governance")]
pub use session::FactStoreExt;
#[cfg(feature = "governance")]
pub use translate::{CedarResidualTranslator, ConstraintTranslator};

// Re-export the cedar identity types through this crate so consumers building
// Cedar-shaped principals have a single import surface (they originate in
// `cedar-oci`). The neutral [`Decision`] now comes from `types`.
pub use cedar_oci::{EntityId, EntityTypeName, EntityUid};

// Cedar value/entity types the host needs to build principal/resource
// attributes and the group-entity closure for identity enrichment.
pub use cedar_policy::{Entity, RestrictedExpression};

// Cedar provider traits a `CedarPolicy` is generic over, re-exported for
// consumers building an authorizer.
pub use cedar_local_agent::public::{SimpleEntityProvider, SimplePolicySetProvider};
