//! The schema and policies the PDP decides over: the built-in `Lakehouse`
//! fragment and baseline ([`BUILTIN`]), then every `*.cedarschema` and `*.cedar`
//! of the configured directories.

use std::path::Path;

use serde::Serialize;

use crate::Error;

/// The built-in sources, as `(name, text)`: the `Lakehouse` principals the
/// loader builds, and the policies that hold in every namespace (a banned user
/// or a disabled service account may do nothing).
pub const BUILTIN: &[(&str, &str)] = &[
    (
        "builtin:Lakehouse.cedarschema",
        include_str!("../policies/Lakehouse.cedarschema"),
    ),
    (
        "builtin:baseline.cedar",
        include_str!("../policies/baseline.cedar"),
    ),
];

/// An action of the schema, e.g. `UnityCatalog::Action` `select`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ActionRef {
    /// The action's entity type, e.g. `UnityCatalog::Action`.
    #[serde(rename = "type")]
    pub entity_type: String,
    /// The action's id, e.g. `select`.
    pub id: String,
}

/// The composed schema and the concatenated policies.
#[derive(Debug, Clone)]
pub struct PolicySet {
    /// One schema of every fragment ([`olai_auth::compose_schema`]).
    pub schema: String,
    /// Every policy file, each after a `// <name>` line.
    pub policies: String,
}

impl PolicySet {
    /// The built-in sources (when `builtin`), then those of each of `dirs` in
    /// file name order. Fails without at least one fragment and one policy, or
    /// when the fragments don't compose.
    pub fn load(builtin: bool, dirs: &[impl AsRef<Path>]) -> Result<Self, Error> {
        let mut sources: Vec<(String, String)> = Vec::new();
        if builtin {
            sources.extend(
                BUILTIN
                    .iter()
                    .map(|(name, text)| (name.to_string(), text.to_string())),
            );
        }
        for dir in dirs {
            sources.extend(read_dir(dir.as_ref())?);
        }
        Self::from_sources(&sources)
    }

    /// The set of `(name, text)` sources: `*.cedarschema` names are schema
    /// fragments, `*.cedar` names policies; others are skipped.
    pub fn from_sources(sources: &[(String, String)]) -> Result<Self, Error> {
        let (mut fragments, mut policies) = (Vec::new(), String::new());
        for (name, text) in sources {
            if name.ends_with(".cedarschema") {
                fragments.push((name.as_str(), text.as_str()));
            } else if name.ends_with(".cedar") {
                policies.push_str(&format!("// {name}\n{text}\n"));
            }
        }
        if fragments.is_empty() || policies.is_empty() {
            return Err(Error::Policy(
                "needs at least one *.cedarschema and one *.cedar source".into(),
            ));
        }
        Ok(Self {
            schema: compose_schema(&fragments)?,
            policies,
        })
    }

    /// The schema's actions, sorted.
    pub fn actions(&self) -> Result<Vec<ActionRef>, Error> {
        let (schema, _) = cedar_policy::Schema::from_cedarschema_str(&self.schema)
            .map_err(|e| Error::Policy(e.to_string()))?;
        let mut actions: Vec<ActionRef> = schema
            .actions()
            .map(|uid| ActionRef {
                entity_type: uid.type_name().to_string(),
                id: uid.id().unescaped().to_string(),
            })
            .collect();
        actions.sort();
        Ok(actions)
    }
}

/// The `*.cedarschema` and `*.cedar` files of `dir`, in file name order.
fn read_dir(dir: &Path) -> Result<Vec<(String, String)>, Error> {
    let read_error =
        |path: &Path, e: std::io::Error| Error::Policy(format!("reading {}: {e}", path.display()));
    let entries = std::fs::read_dir(dir).map_err(|e| read_error(dir, e))?;
    let mut paths: Vec<_> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("cedarschema" | "cedar")
            )
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).map_err(|e| read_error(&path, e))?;
            Ok((path.display().to_string(), text))
        })
        .collect()
}

/// One schema of the `(name, text)` fragments, merged namespace by namespace
/// by [`olai_auth::compose_schema`]: several may declare the same namespace,
/// which one concatenated text may not. A type or action declared twice is an
/// error.
fn compose_schema(fragments: &[(&str, &str)]) -> Result<String, Error> {
    let texts: Vec<&str> = fragments.iter().map(|(_, text)| *text).collect();
    olai_auth::compose_schema(&texts).map_err(|e| {
        let names: Vec<&str> = fragments.iter().map(|(name, _)| *name).collect();
        Error::Policy(format!("{e} (fragments, in order: {})", names.join(", ")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(n, t)| (n.to_string(), t.to_string()))
            .collect()
    }

    #[test]
    fn builtin_set_loads() {
        let set = PolicySet::load(true, &[] as &[&Path]).unwrap();
        assert!(set.schema.contains("Lakehouse"));
        assert!(set.policies.contains("@id(\"banned\")"));
    }

    #[test]
    fn composes_one_namespace_across_fragments() {
        let set = PolicySet::from_sources(&sources(&[
            ("a.cedarschema", "namespace Svc { entity Table; }"),
            (
                "b.cedarschema",
                "namespace Svc { action select appliesTo { principal: [Table], resource: [Table] }; }",
            ),
            ("p.cedar", "permit (principal, action, resource);"),
            ("README.md", "skipped"),
        ]))
        .unwrap();
        assert_eq!(
            set.actions().unwrap(),
            vec![ActionRef {
                entity_type: "Svc::Action".into(),
                id: "select".into()
            }]
        );
    }

    #[test]
    fn refuses_a_type_declared_twice() {
        let err = PolicySet::from_sources(&sources(&[
            ("a.cedarschema", "namespace Svc { entity Table; }"),
            ("b.cedarschema", "namespace Svc { entity Table; }"),
            ("p.cedar", "permit (principal, action, resource);"),
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("a.cedarschema, b.cedarschema"),
            "{err}"
        );
    }

    #[test]
    fn needs_a_schema_and_a_policy() {
        assert!(PolicySet::from_sources(&sources(&[("p.cedar", "")])).is_err());
        assert!(PolicySet::load(false, &[] as &[&Path]).is_err());
    }

    #[test]
    fn reads_directories_in_name_order() {
        let dir = std::env::temp_dir().join(format!("olai-pdp-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.cedar"), "// second\n").unwrap();
        std::fs::write(dir.join("a.cedar"), "// first\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "skipped").unwrap();
        let set = PolicySet::load(true, &[&dir]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let first = set.policies.find("// first").unwrap();
        let second = set.policies.find("// second").unwrap();
        let builtin = set.policies.find("@id(\"banned\")").unwrap();
        assert!(builtin < first && first < second);
        assert!(!set.policies.contains("skipped"));
    }
}
