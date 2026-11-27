//! The OPA-compatible decision route's input, and how it maps into a Cedar
//! request of the caller's namespace.
//!
//! Unity Catalog's OPA authorizers (UC Java 0.8 `OpaInputBuilder`,
//! unitycatalog-rs `authz::opa`) send one leaf privilege check per request:
//!
//! ```json
//! {"input": {
//!   "principal": {"id": "…", "email": "alice@example.com", "external_id": "…"},
//!   "privilege": "SELECT",
//!   "resource": {"id": "…", "type": "TABLE", "name": "orders", "parents": [
//!     {"id": "…", "type": "SCHEMA", "name": "reports"},
//!     {"id": "…", "type": "CATALOG", "name": "analytics"}
//!   ]},
//!   "context": {"source_ip": "10.1.2.3"}
//! }}
//! ```
//!
//! and read `{"result": {"allow": bool}}`. In namespace `Ns` that is the
//! request `Ns::Action::"SELECT"` on `Ns::Table::"analytics.reports.orders"`,
//! with the schema and catalog as the caller-supplied ancestors
//! ([`to_authorize`]). The input's `context` is kept only where the schema
//! declares it ([`ContextShapes`]).

use std::collections::{BTreeMap, HashMap};

use olai_auth::wire::{AuthorizeRequest, EntityRef};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The context attribute the route sets to the input's `principal.email`.
pub(crate) const PRINCIPAL_EMAIL: &str = "principal_email";

/// The body of `POST /v1/data/{package}`.
#[derive(Debug, Deserialize)]
pub(crate) struct OpaRequest {
    pub(crate) input: OpaInput,
}

/// One privilege check. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
pub(crate) struct OpaInput {
    #[serde(default)]
    pub(crate) principal: OpaPrincipal,
    pub(crate) privilege: String,
    pub(crate) resource: OpaResource,
    #[serde(default)]
    pub(crate) context: Option<Map<String, Value>>,
}

/// The UC user asking. Its `id` is UC's own, which the PDP doesn't use.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct OpaPrincipal {
    /// UC's id of the user.
    #[serde(default)]
    pub id: Option<String>,
    /// The user's email.
    #[serde(default)]
    pub email: Option<String>,
    /// The user's id at the identity provider, when UC knows it.
    #[serde(default)]
    pub external_id: Option<String>,
}

impl OpaPrincipal {
    /// `email`, unless empty.
    pub fn email(&self) -> Option<&str> {
        non_empty(self.email.as_deref())
    }

    /// `external_id`, unless empty.
    pub fn external_id(&self) -> Option<&str> {
        non_empty(self.external_id.as_deref())
    }
}

/// A securable, with its containers nearest-first in `parents`.
#[derive(Debug, Deserialize)]
pub(crate) struct OpaResource {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    parents: Vec<OpaResource>,
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// `REGISTERED_MODEL` as a Cedar type name: `RegisteredModel`.
fn type_name(kind: &str) -> Result<String, String> {
    if kind.is_empty() || !kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("invalid resource type {kind:?}"));
    }
    Ok(kind
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            let mut chars = lower.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect())
}

/// The Cedar request of `input` in `namespace`, asked by `principal`, with
/// `context` (already projected) as its context.
///
/// The resource and each of its `parents` become entities `namespace::<Type>`,
/// each the Cedar parent of the one before. Ids are full names (the leaf
/// names, root first, joined by `.`), except the metastore's, which is its UC
/// id. Each entity carries `name`, `uc_id` and `owner` as far as the input has
/// them.
pub(crate) fn to_authorize(
    namespace: &str,
    input: &OpaInput,
    principal: EntityRef,
    context: Map<String, Value>,
) -> Result<AuthorizeRequest, String> {
    let privilege = input.privilege.as_str();
    if privilege.is_empty() {
        return Err("the input has no privilege".into());
    }
    // The resource, then its parents, nearest first.
    let chain: Vec<&OpaResource> = std::iter::once(&input.resource)
        .chain(input.resource.parents.iter())
        .collect();
    let mut refs = Vec::with_capacity(chain.len());
    for (at, securable) in chain.iter().enumerate() {
        let entity_type = format!("{namespace}::{}", type_name(&securable.kind)?);
        let id = if securable.kind == "METASTORE" {
            non_empty(securable.id.as_deref())
                .ok_or("the metastore has no id")?
                .to_string()
        } else {
            let mut names = Vec::with_capacity(chain.len() - at);
            for container in chain[at..].iter().rev() {
                names.push(
                    non_empty(container.name.as_deref())
                        .ok_or_else(|| format!("a {} in the input has no name", container.kind))?,
                );
            }
            names.join(".")
        };
        refs.push(EntityRef::new(entity_type, id));
    }
    let entities = chain.iter().enumerate().map(|(at, securable)| {
        let mut attrs = Map::new();
        if let Some(name) = non_empty(securable.name.as_deref()) {
            attrs.insert("name".into(), name.into());
        }
        if let Some(id) = non_empty(securable.id.as_deref()) {
            attrs.insert("uc_id".into(), id.into());
        }
        if let Some(owner) = non_empty(securable.owner.as_deref()) {
            attrs.insert("owner".into(), owner.into());
        }
        let parents: Vec<&EntityRef> = refs.get(at + 1).into_iter().collect();
        json!({ "uid": refs[at], "attrs": attrs, "parents": parents })
    });
    Ok(AuthorizeRequest::new(
        principal,
        EntityRef::new(format!("{namespace}::Action"), privilege),
        refs[0].clone(),
    )
    .with_context(context)
    .with_entities(entities.collect::<Vec<_>>()))
}

/// The type of a context value, as far as projecting it needs.
#[derive(Debug, Clone, PartialEq)]
enum Shape {
    /// A record: only its declared attributes are kept.
    Record(BTreeMap<String, Shape>),
    /// A set of values of one shape.
    Set(Box<Shape>),
    /// An extension type, constructed from a string by the Cedar function
    /// named here (`ip`, `datetime`, `decimal`, `duration`).
    Extension(&'static str),
    /// Anything else (a string, number, boolean or entity): kept as it is,
    /// and validated by Cedar.
    Value,
}

impl Shape {
    /// `value` with what `self` doesn't declare left out, or `None` when
    /// nothing of it is left.
    fn project(&self, value: &Value) -> Option<Value> {
        match (self, value) {
            (Shape::Record(attrs), Value::Object(object)) => Some(Value::Object(
                object
                    .iter()
                    .filter_map(|(key, value)| {
                        let shape = attrs.get(key)?;
                        shape.project(value).map(|v| (key.clone(), v))
                    })
                    .collect(),
            )),
            (Shape::Set(element), Value::Array(items)) => Some(Value::Array(
                items
                    .iter()
                    .filter_map(|item| element.project(item))
                    .collect(),
            )),
            (Shape::Extension(function), Value::String(arg)) => {
                Some(json!({ "__extn": { "fn": function, "arg": arg } }))
            }
            (_, Value::Null) => None,
            // A mismatch is left for Cedar to reject: a deny with the reason.
            (_, value) => Some(value.clone()),
        }
    }
}

/// The context record each action declares, by action uid (`Ns::Action`,
/// id), read from the composed schema once at start.
#[derive(Debug, Default)]
pub(crate) struct ContextShapes(HashMap<(String, String), Shape>);

impl ContextShapes {
    /// The context shapes of every action in `schema` (Cedar schema syntax).
    pub(crate) fn from_schema(schema: &str) -> Result<Self, String> {
        let (fragment, _) = cedar_policy::SchemaFragment::from_cedarschema_str(schema)
            .map_err(|e| e.to_string())?;
        let json = fragment.to_json_value().map_err(|e| e.to_string())?;
        let mut shapes = HashMap::new();
        let Value::Object(namespaces) = &json else {
            return Ok(Self(shapes));
        };
        for (namespace, body) in namespaces {
            let resolver = Resolver {
                namespace,
                namespaces,
            };
            let Some(actions) = body.get("actions").and_then(Value::as_object) else {
                continue;
            };
            for (action, decl) in actions {
                let shape = match decl.pointer("/appliesTo/context") {
                    Some(context) => resolver.shape(context, 0),
                    None => Shape::Record(BTreeMap::new()),
                };
                let action_type = if namespace.is_empty() {
                    "Action".to_string()
                } else {
                    format!("{namespace}::Action")
                };
                shapes.insert((action_type, action.clone()), shape);
            }
        }
        Ok(Self(shapes))
    }

    /// `context` as `action` declares it: undeclared attributes left out,
    /// extension values constructed from their strings. Nothing for an action
    /// the schema doesn't know (Cedar denies it).
    pub(crate) fn project(
        &self,
        action: &EntityRef,
        context: &Map<String, Value>,
    ) -> Map<String, Value> {
        let key = (action.entity_type.clone(), action.id.clone());
        let Some(shape) = self.0.get(&key) else {
            return Map::new();
        };
        let projected = match shape.project(&Value::Object(context.clone())) {
            Some(Value::Object(projected)) => projected,
            _ => Map::new(),
        };
        let dropped: Vec<&String> = context
            .keys()
            .filter(|k| !projected.contains_key(*k))
            .collect();
        if !dropped.is_empty() {
            tracing::debug!(action = %action, ?dropped, "context attributes not in the schema");
        }
        projected
    }
}

/// Resolves the types of a namespace's schema JSON, including its common types.
struct Resolver<'a> {
    namespace: &'a str,
    namespaces: &'a Map<String, Value>,
}

impl Resolver<'_> {
    const MAX_DEPTH: usize = 32;

    fn shape(&self, ty: &Value, depth: usize) -> Shape {
        if depth > Self::MAX_DEPTH {
            return Shape::Value;
        }
        let kind = ty.get("type").and_then(Value::as_str).unwrap_or_default();
        match kind {
            "Record" => Shape::Record(
                ty.get("attributes")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .map(|(name, attr)| (name.clone(), self.shape(attr, depth + 1)))
                    .collect(),
            ),
            "Set" => Shape::Set(Box::new(
                ty.get("element")
                    .map_or(Shape::Value, |element| self.shape(element, depth + 1)),
            )),
            "Extension" | "Entity" | "EntityOrCommon" => {
                let name = ty.get("name").and_then(Value::as_str).unwrap_or_default();
                self.named(name, depth)
            }
            other => self.named(other, depth),
        }
    }

    /// The type a name refers to: a common type, an extension type, or
    /// anything else.
    fn named(&self, name: &str, depth: usize) -> Shape {
        let name = name.strip_prefix("__cedar::").unwrap_or(name);
        match name {
            "ipaddr" => return Shape::Extension("ip"),
            "datetime" => return Shape::Extension("datetime"),
            "decimal" => return Shape::Extension("decimal"),
            "duration" => return Shape::Extension("duration"),
            _ => {}
        }
        let (namespace, local) = match name.rsplit_once("::") {
            Some((namespace, local)) => (namespace, local),
            None => (self.namespace, name),
        };
        let common = self
            .namespaces
            .get(namespace)
            .and_then(|body| body.get("commonTypes"))
            .and_then(|types| types.get(local));
        match common {
            Some(ty) => Resolver {
                namespace,
                namespaces: self.namespaces,
            }
            .shape(ty, depth + 1),
            None => Shape::Value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = include_str!("../policies/unitycatalog-opa/UnityCatalogOpa.cedarschema");

    fn schema() -> String {
        olai_auth::compose_schema(&[crate::policy::BUILTIN[0].1, SCHEMA]).unwrap()
    }

    #[test]
    fn type_names() {
        assert_eq!(type_name("TABLE").unwrap(), "Table");
        assert_eq!(type_name("REGISTERED_MODEL").unwrap(), "RegisteredModel");
        assert_eq!(type_name("EXTERNAL_LOCATION").unwrap(), "ExternalLocation");
        assert!(type_name("a::b").is_err());
        assert!(type_name("").is_err());
    }

    #[test]
    fn projects_onto_the_declared_context() {
        let shapes = ContextShapes::from_schema(&schema()).unwrap();
        let action = EntityRef::new("UnityCatalogOpa::Action", "SELECT");
        let context = json!({
            "source_ip": "10.1.2.3",
            "request_time": "2027-01-15T08:00:00Z",
            "auth_method": "jwt",
            "groups": ["analysts"],
            "undeclared": 1,
            "headers": { "x-tenant": "acme", "cookie": "secret" },
        });
        let projected = shapes.project(&action, context.as_object().unwrap());
        assert_eq!(
            Value::Object(projected),
            json!({
                "source_ip": { "__extn": { "fn": "ip", "arg": "10.1.2.3" } },
                "request_time": { "__extn": { "fn": "datetime", "arg": "2027-01-15T08:00:00Z" } },
                "auth_method": "jwt",
                "groups": ["analysts"],
                "headers": { "x-tenant": "acme" },
            })
        );
        let unknown = EntityRef::new("UnityCatalogOpa::Action", "NOPE");
        assert!(
            shapes
                .project(&unknown, context.as_object().unwrap())
                .is_empty()
        );
    }

    #[test]
    fn maps_a_table_with_its_parents() {
        let input: OpaRequest = serde_json::from_value(json!({ "input": {
            "principal": { "id": "u", "email": "alice@example.com" },
            "privilege": "SELECT",
            "resource": { "id": "t-1", "type": "TABLE", "name": "orders", "owner": "bob", "parents": [
                { "id": "s-1", "type": "SCHEMA", "name": "reports" },
                { "id": "c-1", "type": "CATALOG", "name": "analytics" },
            ]},
        }}))
        .unwrap();
        let request = to_authorize(
            "Uc",
            &input.input,
            EntityRef::new("Lakehouse::User", "alice"),
            Map::new(),
        )
        .unwrap();
        assert_eq!(request.action, EntityRef::new("Uc::Action", "SELECT"));
        assert_eq!(
            request.resource,
            EntityRef::new("Uc::Table", "analytics.reports.orders")
        );
        assert_eq!(
            Value::Array(request.entities),
            json!([
                { "uid": { "type": "Uc::Table", "id": "analytics.reports.orders" },
                  "attrs": { "name": "orders", "uc_id": "t-1", "owner": "bob" },
                  "parents": [{ "type": "Uc::Schema", "id": "analytics.reports" }] },
                { "uid": { "type": "Uc::Schema", "id": "analytics.reports" },
                  "attrs": { "name": "reports", "uc_id": "s-1" },
                  "parents": [{ "type": "Uc::Catalog", "id": "analytics" }] },
                { "uid": { "type": "Uc::Catalog", "id": "analytics" },
                  "attrs": { "name": "analytics", "uc_id": "c-1" },
                  "parents": [] },
            ])
        );
    }

    #[test]
    fn the_metastore_is_its_id_and_a_name_is_required() {
        let principal = EntityRef::new("Lakehouse::User", "alice");
        let metastore: OpaInput = serde_json::from_value(json!({
            "privilege": "CREATE_CATALOG",
            "resource": { "id": "m-1", "type": "METASTORE", "parents": [] },
        }))
        .unwrap();
        let request = to_authorize("Uc", &metastore, principal.clone(), Map::new()).unwrap();
        assert_eq!(request.resource, EntityRef::new("Uc::Metastore", "m-1"));

        let nameless: OpaInput = serde_json::from_value(json!({
            "privilege": "USE_CATALOG",
            "resource": { "id": "c-1", "type": "CATALOG", "parents": [] },
        }))
        .unwrap();
        assert!(to_authorize("Uc", &nameless, principal, Map::new()).is_err());
    }
}
