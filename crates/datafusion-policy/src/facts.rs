//! Neutral, catalog-agnostic fact types that cross into the policy layer.
//!
//! These are the carriers for the **resource/catalog PIP** (see
//! `docs/adr/0007-fact-gathering-pips.md`): facts gathered at catalog resolution
//! time — a table's `owner`/`readers`/`writers` and its column classification
//! tags — that the Cedar layer folds into the `resource` entity at evaluation.
//!
//! The layering rule this module exists to enforce: `datafusion-policy-cedar` must not
//! depend on `unitycatalog-*` (or any concrete catalog), so the host (hydrofoil)
//! translates its catalog's `Table` into these neutral types and hands them
//! across. Everything here is expressed in [`TableReference`], [`String`], and
//! Cedar types only.
//!
//! Facts here are **local-ephemeral** (ADR-0006): resolved per query, folded
//! into one evaluation, never persisted. Shared-session-scoped facts (the taint
//! ledger) live behind the [`FactStore`](crate::FactStore), not here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use dashmap::{DashMap, DashSet};
use datafusion::sql::TableReference;

/// Catalog-derived attributes of one table, gathered at resolution time and
/// folded into the Cedar `Table` resource entity. The host builds this from its
/// catalog metadata (UC `Table.owner`/`properties`/`comment`); the Cedar layer
/// reads only this neutral shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableFacts {
    /// `Table.owner` → `resource.owner` (a principal uid string).
    pub owner: Option<String>,
    /// Group/principal uids permitted to read → `resource.readers` (`Set<String>`).
    pub readers: BTreeSet<String>,
    /// Group/principal uids permitted to write → `resource.writers` (`Set<String>`).
    pub writers: BTreeSet<String>,
    /// Table-level classification tags → `resource.tags` (`Set<String>`).
    pub tags: BTreeSet<String>,
    /// Column name → its classification tags → `resource.column_tags`
    /// (`Record` of `Set<String>`), and the source of the taints recorded at
    /// the governance PEP when those columns are read.
    pub column_tags: HashMap<String, BTreeSet<String>>,
    /// Governed **key→value** tags on the table itself (the Databricks UC ABAC
    /// governed-tag model), folded into the Cedar `Table` entity's native tags so
    /// policies can read `resource.hasTag(k)` / `resource.getTag(k)`. Distinct
    /// from [`tags`](Self::tags) (an opaque classification set feeding taints):
    /// these carry the key→value pairs governance policies match on.
    pub governed_tags: BTreeMap<String, String>,
    /// Column name → its governed **key→value** tags, folded into each `Column`
    /// entity's native tags for `resource.hasTag`/`getTag` matching. The
    /// per-column analog of [`governed_tags`](Self::governed_tags); column tags
    /// are applied directly (UC semantics: they do not inherit from the table).
    pub governed_column_tags: HashMap<String, BTreeMap<String, String>>,
}

impl TableFacts {
    /// Whether this carries no facts at all (nothing to fold).
    pub fn is_empty(&self) -> bool {
        self.owner.is_none()
            && self.readers.is_empty()
            && self.writers.is_empty()
            && self.tags.is_empty()
            && self.column_tags.is_empty()
            && self.governed_tags.is_empty()
            && self.governed_column_tags.is_empty()
    }

    /// The union of the classification tags of any column in `accessed` — the
    /// taints to record when those columns are read at the governance PEP.
    pub fn taints_for_columns(&self, accessed: &[String]) -> BTreeSet<String> {
        accessed
            .iter()
            .filter_map(|c| self.column_tags.get(c))
            .flatten()
            .cloned()
            .collect()
    }
}

/// Normalize a [`TableReference`] to its fully-qualified form so the key the
/// catalog writes (`catalog.schema.table`, built from UC metadata) matches the
/// key the plan's `TableScan` carries (which may be bare/partial before
/// resolution). Both the [`record`](CatalogFactSink::record) and
/// [`get`](CatalogFactSink::get) sides normalize, so a `bare("t")` and a
/// `full("c","s","t")` referring to the same table resolve to one entry only
/// when they share the same qualified name; refs that genuinely differ stay
/// distinct.
pub fn normalize(table: &TableReference) -> TableReference {
    TableReference::full(
        table.catalog().unwrap_or("").to_string(),
        table.schema().unwrap_or("").to_string(),
        table.table().to_string(),
    )
}

/// A per-query sink the catalog writes [`TableFacts`] into and the Cedar policy
/// reads. Interior-mutable and cheap to clone (`Arc<DashMap>`), so the same
/// instance reaches both `build_delta` (during resolution) and the policy layer
/// (during evaluation) through a `SessionConfig` extension.
///
/// Keyed by the *normalized* [`TableReference`]; a re-resolved table overwrites
/// its prior entry, which is how per-query freshness is achieved even though the
/// sink may be session-owned (a table not in the current plan is simply never
/// read).
#[derive(Debug, Clone, Default)]
pub struct CatalogFactSink {
    by_table: Arc<DashMap<TableReference, TableFacts>>,
    /// Tables whose enforcement was already applied at provider-resolution
    /// time (the secured-view tier). The planner-tier govern pass skips
    /// constraining these, keeping the two tiers mutually exclusive per
    /// (table, query). Like `by_table`, entries are re-populated on every
    /// resolution of a per-session/per-query sink, so staleness is not a
    /// concern.
    governed: Arc<DashSet<TableReference>>,
}

impl CatalogFactSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (overwriting any prior entry) the facts for `table`.
    pub fn record(&self, table: TableReference, facts: TableFacts) {
        self.by_table.insert(normalize(&table), facts);
    }

    /// The facts recorded for `table`, if any.
    pub fn get(&self, table: &TableReference) -> Option<TableFacts> {
        self.by_table.get(&normalize(table)).map(|r| r.clone())
    }

    /// Mark `table` as governed at provider-resolution time: its enforcement
    /// (row filters + column masks) is already baked into a secured-view
    /// provider, so the planner-tier govern pass must not constrain it again.
    /// Taint recording is unaffected — taints accrue regardless of which tier
    /// enforces.
    pub fn mark_governed(&self, table: TableReference) {
        self.governed.insert(normalize(&table));
    }

    /// Whether `table` was [marked governed](Self::mark_governed) at
    /// provider-resolution time.
    pub fn is_governed(&self, table: &TableReference) -> bool {
        self.governed.contains(&normalize(table))
    }

    /// Number of tables with recorded facts (for tests/diagnostics).
    pub fn len(&self) -> usize {
        self.by_table.len()
    }

    /// Whether any facts have been recorded.
    pub fn is_empty(&self) -> bool {
        self.by_table.is_empty()
    }
}

/// Per-query, non-plan facts threaded into the [`PolicyEngine`](crate::PolicyEngine) layer.
///
/// This is the single seam carrying everything a Cedar evaluation needs beyond
/// the plan and principal: the catalog facts gathered this query, the
/// correlation id that keys session-scoped state, and (with `fgac`) the
/// session fact store the governance PEP records taints into. Keeping it in one
/// struct means future fact sources grow here rather than in the trait
/// signature.
#[derive(Clone, Default)]
pub struct EvalContext {
    /// Catalog facts gathered during this query's resolution.
    pub catalog_facts: CatalogFactSink,
    /// The session/trace id that keys shared-session-scoped facts (the taint
    /// ledger). `None` when no session correlation is available.
    pub correlation_id: Option<String>,
    /// The session fact store taints are recorded into (at the governance PEP)
    /// and read back from (at a later PEP). `None` when no store is wired —
    /// taint recording then no-ops. Behind `fgac`, alongside the PEP that
    /// consumes it.
    #[cfg(feature = "fgac")]
    pub fact_store: Option<Arc<dyn crate::FactStore>>,
    /// Resolves policy-referenced masking / row-filter functions (by name) into
    /// callable [`ScalarUDF`](datafusion::logical_expr::ScalarUDF)s at the
    /// governance PEP. `None` when no catalog function resolver is wired — a
    /// policy that names a function then fails closed. Behind `fgac`.
    #[cfg(feature = "fgac")]
    pub function_resolver: Option<Arc<dyn crate::CatalogFunctionResolver>>,
}

impl std::fmt::Debug for EvalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("EvalContext");
        s.field("catalog_facts", &self.catalog_facts)
            .field("correlation_id", &self.correlation_id);
        #[cfg(feature = "fgac")]
        s.field("fact_store", &self.fact_store.is_some());
        #[cfg(feature = "fgac")]
        s.field("function_resolver", &self.function_resolver.is_some());
        s.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn taints_for_columns_unions_accessed_column_tags() {
        let mut column_tags = HashMap::new();
        column_tags.insert("ssn".to_string(), tags(&["pii", "regulated"]));
        column_tags.insert("email".to_string(), tags(&["pii"]));
        column_tags.insert("notes".to_string(), tags(&["internal"]));
        let facts = TableFacts {
            column_tags,
            ..Default::default()
        };

        // Union across accessed columns, deduped.
        let observed = facts.taints_for_columns(&["ssn".into(), "email".into()]);
        assert_eq!(observed, tags(&["pii", "regulated"]));

        // A column with no tags contributes nothing; an untagged-only access is empty.
        assert!(facts.taints_for_columns(&["id".into()]).is_empty());

        // An unaccessed tagged column does not leak in.
        let observed = facts.taints_for_columns(&["notes".into()]);
        assert_eq!(observed, tags(&["internal"]));
    }

    #[test]
    fn is_empty_reflects_all_fields() {
        assert!(TableFacts::default().is_empty());
        assert!(
            !TableFacts {
                owner: Some("User::\"alice\"".into()),
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !TableFacts {
                tags: tags(&["pii"]),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn normalize_collapses_equivalent_refs() {
        // A bare/partial/full ref naming the same qualified table normalize to
        // one key only when their qualified names actually match.
        let full = TableReference::full("c", "s", "t");
        assert_eq!(
            normalize(&full),
            normalize(&TableReference::full("c", "s", "t"))
        );

        // A bare ref has empty catalog/schema, so it is a *distinct* normalized
        // key from a fully-qualified one — they are not the same table.
        let bare = TableReference::bare("t");
        assert_ne!(normalize(&bare), normalize(&full));
        // ...but two bare refs to the same name collapse.
        assert_eq!(normalize(&bare), normalize(&TableReference::bare("t")));
    }

    #[test]
    fn sink_records_and_reads_by_normalized_key() {
        let sink = CatalogFactSink::new();
        assert!(sink.is_empty());

        let facts = TableFacts {
            owner: Some("User::\"alice\"".into()),
            tags: tags(&["pii"]),
            ..Default::default()
        };
        // Record under a full ref; read back under an equivalent full ref.
        sink.record(TableReference::full("c", "s", "t"), facts.clone());
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.get(&TableReference::full("c", "s", "t")), Some(facts));

        // A different table is absent.
        assert!(sink.get(&TableReference::full("c", "s", "other")).is_none());
    }

    #[test]
    fn governed_marker_keys_by_normalized_ref() {
        let sink = CatalogFactSink::new();
        assert!(!sink.is_governed(&TableReference::bare("t")));

        sink.mark_governed(TableReference::bare("t"));
        assert!(sink.is_governed(&TableReference::bare("t")));

        // A fully-qualified ref is a distinct normalized key from a bare one.
        let full = TableReference::full("c", "s", "t");
        assert!(!sink.is_governed(&full));
        sink.mark_governed(full.clone());
        assert!(sink.is_governed(&full));
    }

    #[test]
    fn sink_record_overwrites_for_per_query_freshness() {
        let sink = CatalogFactSink::new();
        let t = TableReference::full("c", "s", "t");
        sink.record(
            t.clone(),
            TableFacts {
                tags: tags(&["pii"]),
                ..Default::default()
            },
        );
        // A later resolution of the same table replaces the prior facts.
        sink.record(
            t.clone(),
            TableFacts {
                tags: tags(&["public"]),
                ..Default::default()
            },
        );
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.get(&t).unwrap().tags, tags(&["public"]));
    }
}
