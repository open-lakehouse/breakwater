//! The neutral **policy-binding model**: the parsed shape of a Databricks Unity
//! Catalog ABAC policy, expressed without any UC (or Cedar) type.
//!
//! UC ABAC binds principals × tag-matched securables/columns to a ROW FILTER or
//! COLUMN MASK function (`CREATE POLICY ... TO principals EXCEPT ... WHEN
//! has_tag_value(...) MATCH COLUMNS has_tag_value(...) AS alias ... USING
//! COLUMNS (...)`). A [`PolicyBinding`] is that statement reduced to plain
//! strings — the facts an [`AbacPolicyEngine`](crate::AbacPolicyEngine) turns
//! into a [`TablePolicy`](crate::TablePolicy) for one table and one principal.
//!
//! **Where bindings come from.** Bindings are catalog *facts*, fetched
//! per-securable at catalog-resolution time by the host (exactly like governed
//! tags) and delivered on [`TableFacts::policies`](crate::TableFacts::policies).
//! The set on `TableFacts` is the **already-inheritance-folded** union that
//! applies to this table (catalog → schema → table); folding the hierarchy and
//! parsing the `WHEN`/`MATCH COLUMNS` predicate strings into [`TagCondition`]s
//! is the host's job, not this crate's. The engine is then a pure function over
//! these structs with zero catalog and zero Cedar dependencies.

/// Whether a binding installs a row filter or a column mask — the two UC ABAC
/// policy kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingKind {
    /// `ROW FILTER`: a predicate function whose call lands in
    /// [`TablePolicy::row_filters`](crate::TablePolicy::row_filters).
    RowFilter,
    /// `COLUMN MASK`: a masking function applied to each matched column, landing
    /// in [`TablePolicy::column_masks`](crate::TablePolicy::column_masks).
    ColumnMask,
}

/// A governed-tag matcher: `hasTag(key)` when [`value`](Self::value) is `None`,
/// `hasTagValue(key, value)` otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCondition {
    /// The governed-tag key to test for.
    pub key: String,
    /// The required value; `None` matches on key presence alone.
    pub value: Option<String>,
}

impl TagCondition {
    /// Whether `tags` (a securable's governed key→value tags) satisfies this
    /// condition: the key must be present, and — when [`value`](Self::value) is
    /// `Some` — its value must be equal. Case-sensitive.
    pub fn matches(&self, tags: &std::collections::BTreeMap<String, String>) -> bool {
        match (&self.value, tags.get(&self.key)) {
            (None, Some(_)) => true,
            (Some(want), Some(have)) => want == have,
            (_, None) => false,
        }
    }
}

/// A `MATCH COLUMNS` matcher: the columns whose governed tags satisfy
/// [`condition`](Self::condition) are exposed to the function under
/// [`alias`](Self::alias).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnMatch {
    /// The tag condition a column's governed tags must satisfy to be matched.
    pub condition: TagCondition,
    /// The alias the matched column(s) are bound to in [`FunctionArg::Alias`].
    pub alias: String,
}

/// One argument to a binding's function: either a column bound by a
/// [`ColumnMatch`] alias, or a constant passed through as a literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionArg {
    /// The column matched by the [`ColumnMatch`] with this alias.
    Alias(String),
    /// A constant string argument, passed as a literal.
    Constant(String),
}

/// One parsed UC ABAC policy: principals × tag-matched securable/columns → a
/// row-filter or column-mask function call.
///
/// These are catalog *facts*, fetched per-securable at catalog-resolution time
/// by the host (like governed tags) and delivered on
/// [`TableFacts::policies`](crate::TableFacts::policies) as the
/// already-inheritance-folded set applying to a table — the engine does not
/// fold the catalog → schema → table hierarchy or parse predicate strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBinding {
    /// The policy name (for diagnostics / mask-precedence ordering).
    pub name: String,
    /// Whether this is a row filter or a column mask.
    pub kind: BindingKind,
    /// Plain principal names (users/groups) the policy applies `TO`. The
    /// sentinel `"account users"` matches every principal.
    pub to_principals: Vec<String>,
    /// Plain principal names the policy is `EXCEPT`ed for (overrides
    /// [`to_principals`](Self::to_principals)).
    pub except_principals: Vec<String>,
    /// The `WHEN` table-tag conjunction; **every** condition must hold on the
    /// table's governed tags for the binding to apply. Empty = always applies.
    pub when_condition: Vec<TagCondition>,
    /// The `MATCH COLUMNS` matchers. For a mask, the first match names the
    /// masked input column; unused by a row filter unless referenced via an
    /// [`FunctionArg::Alias`].
    pub match_columns: Vec<ColumnMatch>,
    /// The catalog-qualified function name to call (e.g. `"hr.security.mask_ssn"`).
    pub function: String,
    /// The `USING COLUMNS (...)` arguments, mapped in order.
    pub using_args: Vec<FunctionArg>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn tag_condition_key_presence_and_value() {
        let key_only = TagCondition {
            key: "pii".into(),
            value: None,
        };
        let key_value = TagCondition {
            key: "pii".into(),
            value: Some("ssn".into()),
        };

        // key-only: present key satisfies regardless of value.
        assert!(key_only.matches(&tags(&[("pii", "anything")])));
        assert!(!key_only.matches(&tags(&[("other", "x")])));

        // key+value: value must be equal (case-sensitive).
        assert!(key_value.matches(&tags(&[("pii", "ssn")])));
        assert!(!key_value.matches(&tags(&[("pii", "SSN")])));
        assert!(!key_value.matches(&tags(&[("pii", "email")])));
        assert!(!key_value.matches(&tags(&[("nope", "ssn")])));
    }

    #[test]
    fn binding_eq_round_trip() {
        let b = PolicyBinding {
            name: "mask_ssn".into(),
            kind: BindingKind::ColumnMask,
            to_principals: vec!["account users".into()],
            except_principals: vec!["User::\"admin\"".into()],
            when_condition: vec![TagCondition {
                key: "classification".into(),
                value: Some("regulated".into()),
            }],
            match_columns: vec![ColumnMatch {
                condition: TagCondition {
                    key: "pii".into(),
                    value: Some("ssn".into()),
                },
                alias: "col".into(),
            }],
            function: "hr.security.mask_ssn".into(),
            using_args: vec![
                FunctionArg::Alias("col".into()),
                FunctionArg::Constant("X".into()),
            ],
        };
        assert_eq!(b.clone(), b);
    }
}
