//! The authenticated principal a query runs as, and the identity PIP that
//! enriches it with attributes + group membership from external systems.
//!
//! Everything here is **engine-neutral**: the principal is an opaque uid string,
//! attributes are [`AttrValue`]s, and group membership is expressed as uid
//! strings plus a neutral [`Group`] hierarchy. A policy-engine adapter (e.g.
//! `cedar.rs`) lowers these to its own entity/value types at authorization time.
//! No Cedar type appears in this module.

use std::collections::HashMap;

use crate::types::AttrValue;

/// The principal on whose behalf a query executes, plus the attributes policies
/// may condition on (e.g. `role`, `region`, `name`) and the group memberships
/// they resolve `in` against.
///
/// Carrying attributes alongside the uid is why the
/// [`PolicyEngine`](crate::PolicyEngine) trait threads a `&PrincipalIdentity`
/// rather than a bare uid string: attribute-based policies (`principal.role ==
/// ...`) need the principal's attributes at authorization time. The host builds
/// this from authenticated request metadata, then optionally enriches it via an
/// [`IdentityProvider`] (see [`PrincipalIdentity::enriched`]).
///
/// **Group membership.** `groups` are the principal's *direct* parents (uid
/// strings). The transitive closure of those groups — each group's own parents —
/// is carried on the [`PrincipalEnrichment`] as [`Group`]s, so an adapter can
/// rebuild the hierarchy and `principal in Group::"…"` resolves dynamically
/// rather than from a static entity bundle. The Cedar adapter folds both into
/// request-time entities.
#[derive(Debug, Clone)]
pub struct PrincipalIdentity {
    /// The principal's opaque uid, e.g. `User::"alice"`. Format is the engine's
    /// concern; the core treats it as a string.
    pub uid: String,
    /// Principal attributes, as engine-neutral [`AttrValue`]s.
    pub attributes: HashMap<String, AttrValue>,
    /// The principal's direct group memberships, as uid strings.
    pub groups: Vec<String>,
    /// The transitive group hierarchy to resolve membership against. Not part of
    /// the principal's identity per se; carried here so a single value reaches
    /// the adapter that rebuilds the engine's entity graph.
    pub(crate) group_hierarchy: Vec<Group>,
}

/// A node in the neutral group hierarchy: a group uid and its direct parent
/// group uids. The transitive closure of a principal's groups (each group plus
/// its ancestors) so `privileged_readers ⊂ readers` resolves without a static
/// entity bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group's uid, e.g. `UserGroup::"readers"`.
    pub uid: String,
    /// The group's direct parent group uids.
    pub parents: Vec<String>,
}

impl PrincipalIdentity {
    /// A principal with a uid and no attributes or groups.
    pub fn new(uid: impl Into<String>) -> Self {
        Self {
            uid: uid.into(),
            attributes: HashMap::new(),
            groups: Vec::new(),
            group_hierarchy: Vec::new(),
        }
    }

    /// Set a string-valued attribute (e.g. `role`, `region`).
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes
            .insert(key.into(), AttrValue::String(value.into()));
        self
    }

    /// Set an attribute of any [`AttrValue`] type (long, bool, set, …).
    pub fn with_attribute_value(mut self, key: impl Into<String>, value: AttrValue) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// The transitive group hierarchy carried for membership resolution.
    ///
    /// Public so an engine adapter can rebuild the group ancestry when it lowers
    /// the neutral principal to its own entity graph.
    pub fn group_hierarchy(&self) -> &[Group] {
        &self.group_hierarchy
    }

    /// Apply a [`PrincipalEnrichment`] resolved from an [`IdentityProvider`].
    ///
    /// IdP-sourced attributes **override** any client-asserted attribute of the
    /// same key (the IdP is authoritative; see the trust note on
    /// [`IdentityProvider`]). Groups become this principal's parents and the
    /// group hierarchy is carried for the adapter to fold.
    pub fn enriched(mut self, enrichment: PrincipalEnrichment) -> Self {
        self.attributes.extend(enrichment.attributes);
        self.groups = enrichment.groups;
        self.group_hierarchy = enrichment.group_hierarchy;
        self
    }
}

/// The facts an [`IdentityProvider`] resolves for a principal: attributes to
/// fold onto the principal, the principal's direct group parents, and the
/// transitive group hierarchy needed for `in` to resolve the ancestry.
#[derive(Debug, Clone, Default)]
pub struct PrincipalEnrichment {
    /// IdP-sourced attributes (role, region, …). These override client-asserted
    /// attributes of the same key when applied via [`PrincipalIdentity::enriched`].
    pub attributes: HashMap<String, AttrValue>,
    /// The principal's direct group memberships, as uid strings.
    pub groups: Vec<String>,
    /// The transitive group hierarchy (groups + their ancestors, each with its
    /// own parents), so `privileged_readers ⊂ readers` resolves without the
    /// static bundle.
    pub group_hierarchy: Vec<Group>,
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
/// The trait deals only in this crate's neutral types so it can live here;
/// concrete IdP/directory-querying implementations live in the host.
#[async_trait::async_trait]
pub trait IdentityProvider: std::fmt::Debug + Send + Sync {
    async fn enrich(
        &self,
        uid: &str,
        claims: &PrincipalClaims,
    ) -> Result<PrincipalEnrichment, IdentityError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_attributes() {
        let id = PrincipalIdentity::new("User::\"alice\"")
            .with_attribute("role", "analyst")
            .with_attribute("region", "eu");
        assert_eq!(id.attributes.len(), 2);
        assert_eq!(id.uid, "User::\"alice\"");
        assert_eq!(
            id.attributes.get("role"),
            Some(&AttrValue::String("analyst".into()))
        );
    }

    #[test]
    fn with_attribute_value_carries_non_string() {
        let id = PrincipalIdentity::new("User::\"alice\"")
            .with_attribute_value("clearance", AttrValue::Long(3))
            .with_attribute_value("admin", AttrValue::Bool(true));
        assert_eq!(id.attributes.get("clearance"), Some(&AttrValue::Long(3)));
        assert_eq!(id.attributes.get("admin"), Some(&AttrValue::Bool(true)));
    }

    #[test]
    fn no_attributes_by_default() {
        let id = PrincipalIdentity::new("User::\"bob\"");
        assert!(id.attributes.is_empty());
        assert!(id.groups.is_empty());
    }

    #[test]
    fn enriched_sets_groups_and_hierarchy() {
        // alice ∈ privileged_readers ⊂ readers — supplied entirely by enrichment.
        let id = PrincipalIdentity::new("User::\"alice\"").enriched(PrincipalEnrichment {
            groups: vec!["UserGroup::\"privileged_readers\"".into()],
            group_hierarchy: vec![
                Group {
                    uid: "UserGroup::\"privileged_readers\"".into(),
                    parents: vec!["UserGroup::\"readers\"".into()],
                },
                Group {
                    uid: "UserGroup::\"readers\"".into(),
                    parents: vec![],
                },
            ],
            ..Default::default()
        });
        assert_eq!(id.groups, vec!["UserGroup::\"privileged_readers\""]);
        assert_eq!(id.group_hierarchy().len(), 2);
    }

    #[test]
    fn enriched_idp_attributes_override_client_asserted() {
        let id = PrincipalIdentity::new("User::\"alice\"")
            .with_attribute("role", "client-claimed") // self-asserted
            .enriched(PrincipalEnrichment {
                attributes: HashMap::from([(
                    "role".to_string(),
                    AttrValue::String("idp-authoritative".to_string()),
                )]),
                ..Default::default()
            });
        // IdP wins on key collision.
        assert_eq!(
            id.attributes.get("role"),
            Some(&AttrValue::String("idp-authoritative".into()))
        );
    }
}
