//! Lower a neutral [`PrincipalIdentity`] to the Cedar entity/value types the
//! authorizer needs.
//!
//! The core's principal is engine-neutral (an opaque uid string, [`AttrValue`]
//! attributes, and a [`Group`] hierarchy). This adapter module rebuilds the
//! Cedar `EntityUid` / `Entity` / `RestrictedExpression` graph from it at
//! authorization time — the Cedar-specific construction that used to live on
//! `PrincipalIdentity` itself, moved here so `principal.rs` names no Cedar type.

use std::collections::HashSet;
use std::str::FromStr as _;

use cedar_policy::{Entity, EntityUid, RestrictedExpression};
use datafusion::common::plan_datafusion_err;
use datafusion::error::Result;

use crate::principal::{Group, PrincipalIdentity};
use crate::types::AttrValue;

/// Parse a neutral uid string (e.g. `User::"alice"`) into a Cedar [`EntityUid`].
///
/// Exposed so hosts and adapter code that build Cedar requests directly can turn
/// a neutral [`PrincipalIdentity::uid`] into the Cedar type at the boundary.
pub fn parse_uid(uid: &str) -> Result<EntityUid> {
    EntityUid::from_str(uid)
        .map_err(|e| plan_datafusion_err!("invalid principal/entity uid '{uid}': {e}"))
}

/// Lower a neutral [`AttrValue`] to a Cedar [`RestrictedExpression`].
fn to_restricted_expr(value: &AttrValue) -> RestrictedExpression {
    match value {
        AttrValue::String(s) => RestrictedExpression::new_string(s.clone()),
        AttrValue::Long(n) => RestrictedExpression::new_long(*n),
        AttrValue::Bool(b) => RestrictedExpression::new_bool(*b),
        AttrValue::Set(items) => {
            RestrictedExpression::new_set(items.iter().map(to_restricted_expr))
        }
    }
}

/// Build the Cedar [`Entity`] for the principal so an authorizer can resolve
/// `principal.<attr>` references **and** `principal in <group>` membership. The
/// direct groups are emitted as the entity's parents. Returns the bare uid
/// entity (no attributes/parents) if attribute evaluation fails, so
/// authorization stays fail-closed rather than erroring open.
fn principal_entity(principal: &PrincipalIdentity) -> Result<Entity> {
    let uid = parse_uid(&principal.uid)?;
    let attrs = principal
        .attributes
        .iter()
        .map(|(k, v)| (k.clone(), to_restricted_expr(v)))
        .collect();
    let parents: HashSet<EntityUid> = principal
        .groups
        .iter()
        .filter_map(|g| parse_uid(g).ok())
        .collect();
    Ok(Entity::new(uid.clone(), attrs, parents)
        .unwrap_or_else(|_| Entity::new_no_attrs(uid, Default::default())))
}

/// Build a Cedar [`Entity`] for a neutral [`Group`] (uid + parent uids). A group
/// carries no attributes; only its ancestry matters for `in` resolution.
/// Unparseable uids are dropped from the parent set (fail-closed: a membership
/// that cannot be expressed simply does not resolve).
fn group_entity(group: &Group) -> Result<Entity> {
    let uid = parse_uid(&group.uid)?;
    let parents: HashSet<EntityUid> = group
        .parents
        .iter()
        .filter_map(|p| parse_uid(p).ok())
        .collect();
    Ok(Entity::new_no_attrs(uid, parents))
}

/// The principal entity **plus** the transitive group entities rebuilt from the
/// neutral hierarchy — the full set to hand to `Entities::from_entities`. This is
/// what makes group membership resolve without a static entity bundle.
///
/// A group whose uid fails to parse is skipped rather than failing the whole
/// build, so a single malformed hierarchy node cannot error authorization open.
///
/// Exposed so hosts building Cedar requests directly (e.g. a write-path PEP) can
/// fold the neutral principal into the request-time entity set the same way the
/// [`CedarPolicy`](crate::CedarPolicy) adapter does.
pub fn principal_entities(principal: &PrincipalIdentity) -> Result<Vec<Entity>> {
    let mut entities = Vec::with_capacity(1 + principal.group_hierarchy().len());
    entities.push(principal_entity(principal)?);
    for group in principal.group_hierarchy() {
        if let Ok(entity) = group_entity(group) {
            entities.push(entity);
        }
    }
    Ok(entities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::PrincipalEnrichment;

    #[test]
    fn builds_principal_entity_with_attributes() {
        let id = PrincipalIdentity::new("User::\"alice\"")
            .with_attribute("region", "eu")
            .with_attribute_value("clearance", AttrValue::Long(3));
        let entities = principal_entities(&id).unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].uid(), parse_uid("User::\"alice\"").unwrap());
    }

    #[test]
    fn builds_group_closure_from_hierarchy() {
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
        // principal + 2 group entities.
        assert_eq!(principal_entities(&id).unwrap().len(), 3);
    }

    #[test]
    fn invalid_group_uid_is_skipped_not_fatal() {
        let id = PrincipalIdentity::new("User::\"alice\"").enriched(PrincipalEnrichment {
            group_hierarchy: vec![Group {
                uid: "not a valid uid".into(),
                parents: vec![],
            }],
            ..Default::default()
        });
        // Only the principal entity survives; the malformed group is dropped.
        assert_eq!(principal_entities(&id).unwrap().len(), 1);
    }

    #[test]
    fn invalid_principal_uid_errors() {
        let id = PrincipalIdentity::new("not a valid uid");
        assert!(principal_entities(&id).is_err());
    }

    #[test]
    fn set_attribute_lowers_to_cedar_set() {
        let id = PrincipalIdentity::new("User::\"alice\"").with_attribute_value(
            "regions",
            AttrValue::Set(vec![
                AttrValue::String("eu".into()),
                AttrValue::String("us".into()),
            ]),
        );
        // Construction succeeds (a Set attr is a valid Cedar record value).
        assert_eq!(principal_entities(&id).unwrap().len(), 1);
    }
}
