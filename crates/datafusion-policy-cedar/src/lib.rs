//! Cedar adapter for the engine-neutral policy layer ([`datafusion-policy`]).
//!
//! The neutral crate ([`datafusion_policy`]) owns the decide/enforce split — the
//! [`PolicyEngine`] trait, the [`PolicyQueryPlanner`] enforcement hook, the plan
//! rewrite, and all neutral types. This crate is one **adapter** behind that
//! seam: it implements [`PolicyEngine`] with Cedar
//! ([`CedarPolicyEngine`]), lowers the neutral principal to Cedar entities
//! ([`principal_entities`]), lowers the neutral plan-action list to Cedar
//! authorization requests, and reads Cedar partial-eval residuals into
//! DataFusion predicates ([`CedarResidualTranslator`]). Policy *sourcing*
//! (pulling a policy set / schema / entities from an OCI registry) lives in the
//! [`cedar-oci`](https://docs.rs/olai-cedar-oci) crate; engine-specific *glue*
//! (extracting the principal from a request, composing onto a session) lives in
//! the host — see [hydrofoil](https://github.com/open-lakehouse/hydrofoil) for a
//! reference host.
//!
//! The neutral core's public surface ([`PolicyEngine`], [`PrincipalIdentity`],
//! [`PolicyExtension`], …) is re-exported here so a Cedar host has a single
//! import surface.
//!
//! [`datafusion-policy`]: datafusion_policy

mod cedar;
mod cedar_entity;
mod visitor;

#[cfg(feature = "fgac")]
mod translate;

pub use cedar::{CedarPolicyEngine, InMemoryPolicyProvider};
pub use cedar_entity::{parse_uid, principal_entities};

// Re-export the neutral core's public surface so a Cedar host imports one crate.
pub use datafusion_policy::{
    AgentClaims, AttrValue, CatalogFactSink, CatalogFactSinkExt, ConstraintTranslator, Decision,
    EvalContext, EvalContextProvider, Group, IdentityError, IdentityProvider, PlanAction,
    PolicyBuilder, PolicyEngine, PolicyExtension, PolicyQueryPlanner, PolicySessionExt,
    PrincipalClaims, PrincipalEnrichment, PrincipalExt, PrincipalIdentity, PrincipalProvider,
    SessionConfigEvalContextProvider, SessionConfigPrincipalProvider, StaticPolicyEngine,
    TableFacts, authorize_and_govern, instrument_session_state, normalize, plan_actions,
};

#[cfg(feature = "fgac")]
pub use datafusion_policy::{
    AbacPolicyEngine, BindingKind, CatalogFunctionResolver, ColumnMatch, DefaultPrincipalMatcher,
    FactStore, FactStoreExt, FunctionArg, FunctionResolverExt, InMemoryFactStore, PolicyBinding,
    PrincipalMatcher, TablePolicy, TagCondition, govern_plan,
};
#[cfg(feature = "fgac")]
pub use translate::CedarResidualTranslator;

// Re-export the cedar identity types through this crate so consumers building
// Cedar-shaped principals/requests directly have a single import surface (they
// originate in `cedar-oci`).
pub use cedar_oci::{EntityId, EntityTypeName, EntityUid};

// Cedar value/entity types a host may need to build Cedar requests directly
// (the neutral principal is lowered via [`principal_entities`]).
pub use cedar_policy::{Entity, RestrictedExpression};

// Cedar provider traits a [`CedarPolicyEngine`] is generic over, re-exported for
// consumers building an authorizer.
pub use cedar_local_agent::public::{SimpleEntityProvider, SimplePolicySetProvider};
