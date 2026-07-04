//! The authenticated principal a query runs as, and the identity PIP that
//! enriches it with attributes + group membership from external systems.

use std::collections::HashMap;

use cedar_policy::{Entity, RestrictedExpression};

use cedar_oci::EntityUid;

/// The principal on whose behalf a query executes, plus the attributes policies
/// may condition on (e.g. `role`, `region`, `name`) and the group memberships
/// they resolve `in` against.
///
/// Carrying attributes alongside the `EntityUid` is why the [`Policy`](crate::Policy)
/// trait threads a `&PrincipalIdentity` rather than a bare `EntityUid`: Cedar
/// policies written against `principal.role` need the principal to exist as an
/// entity with those attributes at authorization time. The host (hydrofoil)
/// builds this from authenticated request metadata, then optionally enriches it
/// via an [`IdentityProvider`] (see [`PrincipalIdentity::enriched`]).
///
/// **Group membership.** `groups` are the principal's *direct* parents and
/// `group_entities` the transitive closure of those groups (each with their own
/// parents/attrs). Both come from the identity PIP and are folded into the
/// request-time entities by [`to_entities`](PrincipalIdentity::to_entities), so
/// `principal in UserGroup::"…"` resolves dynamically rather than from a static
/// entity bundle. See `docs/adr/0008-principal-identity-resolution.md`.
#[derive(Debug, Clone)]
pub struct PrincipalIdentity {
    /// The principal's Cedar entity uid, e.g. `User::"alice"`.
    pub uid: EntityUid,
    /// Principal attributes, as Cedar restricted expressions.
    pub attributes: HashMap<String, RestrictedExpression>,
    /// The principal's direct group memberships → this entity's Cedar parents.
    pub groups: Vec<EntityUid>,
    /// The transitive group entities to fold alongside the principal so the
    /// hierarchy resolves. Not part of the principal's identity per se; carried
    /// here so a single value reaches `Entities::from_entities`.
    group_entities: Vec<Entity>,
}

impl PrincipalIdentity {
    /// A principal with a uid and no attributes or groups.
    pub fn new(uid: EntityUid) -> Self {
        Self {
            uid,
            attributes: HashMap::new(),
            groups: Vec::new(),
            group_entities: Vec::new(),
        }
    }

    /// Set a string-valued attribute (e.g. `role`, `region`).
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes
            .insert(key.into(), RestrictedExpression::new_string(value.into()));
        self
    }

    /// Apply a [`PrincipalEnrichment`] resolved from an [`IdentityProvider`].
    ///
    /// IdP-sourced attributes **override** any client-asserted attribute of the
    /// same key (the IdP is authoritative; see the trust note on
    /// [`IdentityProvider`]). Groups become this principal's parents and the
    /// group-entity closure is carried for folding.
    pub fn enriched(mut self, enrichment: PrincipalEnrichment) -> Self {
        self.attributes.extend(enrichment.attributes);
        self.groups = enrichment.groups;
        self.group_entities = enrichment.group_entities;
        self
    }

    /// Build the Cedar [`Entity`] for this principal so an authorizer can
    /// resolve `principal.<attr>` references **and** `principal in <group>`
    /// membership. The groups are emitted as the entity's parents. Returns the
    /// bare uid entity (no attributes/parents) if attribute evaluation fails, so
    /// authorization stays fail-closed rather than erroring open.
    pub fn to_entity(&self) -> Entity {
        let parents: std::collections::HashSet<EntityUid> = self.groups.iter().cloned().collect();
        Entity::new(self.uid.clone(), self.attributes.clone(), parents)
            .unwrap_or_else(|_| Entity::new_no_attrs(self.uid.clone(), Default::default()))
    }

    /// The principal entity **plus** the transitive group entities — the full
    /// set to hand to `Entities::from_entities`. This is what makes group
    /// membership resolve without a static entity bundle.
    pub fn to_entities(&self) -> Vec<Entity> {
        let mut entities = Vec::with_capacity(1 + self.group_entities.len());
        entities.push(self.to_entity());
        entities.extend(self.group_entities.iter().cloned());
        entities
    }
}

/// The facts an [`IdentityProvider`] resolves for a principal: attributes to
/// fold onto the principal entity, the principal's direct group parents, and the
/// transitive group entities needed for Cedar's `in` to resolve the hierarchy.
#[derive(Debug, Clone, Default)]
pub struct PrincipalEnrichment {
    /// IdP-sourced attributes (role, region, …). These override client-asserted
    /// attributes of the same key when applied via [`PrincipalIdentity::enriched`].
    pub attributes: HashMap<String, RestrictedExpression>,
    /// The principal's direct group memberships → Cedar entity parents.
    pub groups: Vec<EntityUid>,
    /// The transitive group entities (groups + their ancestors, each with their
    /// own parents/attrs), so `privileged_readers ⊂ readers` resolves without
    /// the static bundle.
    pub group_entities: Vec<Entity>,
}

/// Neutral, transport-free claims the host passes to an [`IdentityProvider`].
///
/// The host fills this from validated token claims / request metadata. Keeping
/// it free of any transport type lets the trait live in this crate while the
/// HTTP/IdP detail stays in the host.
#[derive(Debug, Clone, Default)]
pub struct PrincipalClaims {
    /// Raw claim key/values (e.g. from a validated bearer token).
    pub claims: HashMap<String, String>,
    /// Agent identity claims, when the caller is an agent. The seam for OIDC-A
    /// principal enrichment; unused by the v1 provider.
    pub agent: Option<AgentClaims>,
}

/// Agent-identity claims (OIDC-A). A placeholder seam carried on
/// [`PrincipalClaims`]; agent principal-enrichment is deferred to the agent-PEP
/// work, so the v1 identity provider ignores it.
#[derive(Debug, Clone, Default)]
pub struct AgentClaims {
    pub agent_type: Option<String>,
    pub agent_model: Option<String>,
    pub delegator: Option<String>,
}

/// An error resolving identity facts. Small and crate-local so the host owns the
/// fail-closed decision (an `Err` should fail the session, not proceed
/// un-enriched).
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity provider error: {0}")]
    Provider(String),
}

/// The principal/identity PIP: given the **authenticated** principal uid (plus
/// any validated claims), pull the slice of identity facts policies condition
/// on — attributes and group membership.
///
/// **Trust.** Enrichment keys off the authenticated uid; the provider's facts
/// are authoritative and override self-asserted request attributes. Group
/// membership must come only from here, never from a client header. An `Err`
/// should be treated fail-closed by the host (fail the session). An unknown uid
/// returning an *empty* enrichment is a success, not an error.
///
/// The trait deals only in this crate's types so it can live here; concrete
/// IdP/directory-querying implementations live in the host.
#[async_trait::async_trait]
pub trait IdentityProvider: std::fmt::Debug + Send + Sync {
    async fn enrich(
        &self,
        uid: &EntityUid,
        claims: &PrincipalClaims,
    ) -> Result<PrincipalEnrichment, IdentityError>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    fn uid(s: &str) -> EntityUid {
        EntityUid::from_str(s).unwrap()
    }

    fn group(s: &str) -> EntityUid {
        EntityUid::from_str(s).unwrap()
    }

    #[test]
    fn carries_attributes_and_builds_entity() {
        let id = PrincipalIdentity::new(uid("User::\"alice\""))
            .with_attribute("role", "analyst")
            .with_attribute("region", "eu");
        assert_eq!(id.attributes.len(), 2);
        // Entity construction succeeds and preserves the uid.
        let entity = id.to_entity();
        assert_eq!(entity.uid(), id.uid);
    }

    #[test]
    fn entity_with_no_attributes() {
        let id = PrincipalIdentity::new(uid("User::\"bob\""));
        assert!(id.attributes.is_empty());
        assert_eq!(id.to_entity().uid().to_string(), "User::\"bob\"");
    }

    #[test]
    fn to_entity_with_groups_builds_successfully() {
        // The groups are emitted as the entity's parents (their effect on `in`
        // is exercised end-to-end by the Cedar evaluation test in `cedar.rs`,
        // `is_allowed_resolves_group_membership_with_empty_bundle`). Here we only
        // assert construction succeeds with parents and preserves the uid.
        let id = PrincipalIdentity::new(uid("User::\"alice\"")).enriched(PrincipalEnrichment {
            groups: vec![group("UserGroup::\"readers\"")],
            ..Default::default()
        });
        assert_eq!(id.to_entity().uid(), id.uid);
    }

    #[test]
    fn to_entities_includes_group_closure() {
        // alice ∈ privileged_readers ⊂ readers — supplied entirely by enrichment.
        let readers = Entity::new_no_attrs(group("UserGroup::\"readers\""), Default::default());
        let privileged = Entity::new(
            group("UserGroup::\"privileged_readers\""),
            HashMap::new(),
            [group("UserGroup::\"readers\"")].into_iter().collect(),
        )
        .unwrap();
        let id = PrincipalIdentity::new(uid("User::\"alice\"")).enriched(PrincipalEnrichment {
            groups: vec![group("UserGroup::\"privileged_readers\"")],
            group_entities: vec![privileged, readers],
            ..Default::default()
        });
        // principal + 2 group entities.
        assert_eq!(id.to_entities().len(), 3);
    }

    #[test]
    fn enriched_idp_attributes_override_client_asserted() {
        let id = PrincipalIdentity::new(uid("User::\"alice\""))
            .with_attribute("role", "client-claimed") // self-asserted
            .enriched(PrincipalEnrichment {
                attributes: HashMap::from([(
                    "role".to_string(),
                    RestrictedExpression::new_string("idp-authoritative".to_string()),
                )]),
                ..Default::default()
            });
        // IdP wins on key collision.
        let role = id.attributes.get("role").unwrap();
        assert_eq!(
            format!("{role:?}"),
            format!(
                "{:?}",
                RestrictedExpression::new_string("idp-authoritative".to_string())
            )
        );
    }
}
