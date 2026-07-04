//! The session fact store: shared, session-scoped facts keyed by correlation id.
//!
//! Where [`TableFacts`](crate::TableFacts) are *local-ephemeral* (gathered per
//! query, folded into one evaluation, discarded), the facts here are
//! *shared-session-scoped* (ADR-0006): established at one PEP and read at a
//! *later* one — typically the engine governance PEP records the taints a
//! session has observed, and the (future) agent-tool PEP reads them back to gate
//! tool calls.
//!
//! v1 holds only the monotonic taint ledger and backs it with an in-memory
//! [`DashMap`]. A future Redis / central session-state PDP backend slots behind
//! the same [`FactStore`] trait without touching the policy layer
//! (see `docs/adr/0007-fact-gathering-pips.md`).

use std::collections::BTreeSet;

use dashmap::DashMap;

/// Shared, session-scoped facts keyed by a correlation id (the session/trace
/// id). v1 exposes only the monotonic taint ledger.
///
/// The store is consulted at operation boundaries: the governance PEP
/// [`record_taints`](FactStore::record_taints) as it reads tagged columns, and a
/// later PEP reads [`observed_taints`](FactStore::observed_taints). Taint accrual
/// is monotonic — a session's observed set only grows — so recording is
/// idempotent and safe to repeat (e.g. on query re-planning).
pub trait FactStore: Send + Sync + std::fmt::Debug {
    /// Monotonically add one observed classification to a session's ledger.
    fn record_taint(&self, correlation_id: &str, taint: &str);

    /// Add several taints at once — the common case when a single scan reads a
    /// column carrying multiple classifications.
    fn record_taints(&self, correlation_id: &str, taints: &BTreeSet<String>) {
        for t in taints {
            self.record_taint(correlation_id, t);
        }
    }

    /// All classifications the session has observed so far.
    fn observed_taints(&self, correlation_id: &str) -> BTreeSet<String>;
}

/// In-memory [`FactStore`] backed by a [`DashMap`] keyed by correlation id.
///
/// The v1 implementation, and the real version of the mock the
/// `fact_gathering_walkthrough` example used. Process-wide (owned by the
/// `Engine`): one map serves all sessions, keyed by correlation id, exactly as a
/// future shared-KV backend would be.
#[derive(Debug, Default)]
pub struct InMemoryFactStore {
    by_session: DashMap<String, BTreeSet<String>>,
}

impl InMemoryFactStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl FactStore for InMemoryFactStore {
    fn record_taint(&self, correlation_id: &str, taint: &str) {
        self.by_session
            .entry(correlation_id.to_string())
            .or_default()
            .insert(taint.to_string());
    }

    fn observed_taints(&self, correlation_id: &str) -> BTreeSet<String> {
        self.by_session
            .get(correlation_id)
            .map(|s| s.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taints(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accrual_is_monotonic_and_idempotent() {
        let store = InMemoryFactStore::new();
        store.record_taint("s1", "pii");
        store.record_taint("s1", "pii"); // idempotent
        store.record_taint("s1", "regulated");
        assert_eq!(store.observed_taints("s1"), taints(&["pii", "regulated"]));
    }

    #[test]
    fn record_taints_adds_a_set() {
        let store = InMemoryFactStore::new();
        store.record_taints("s1", &taints(&["pii", "regulated"]));
        store.record_taints("s1", &taints(&["pii", "internal"])); // overlap is fine
        assert_eq!(
            store.observed_taints("s1"),
            taints(&["internal", "pii", "regulated"])
        );
    }

    #[test]
    fn sessions_are_isolated_by_correlation_id() {
        let store = InMemoryFactStore::new();
        store.record_taint("s1", "pii");
        assert_eq!(store.observed_taints("s1"), taints(&["pii"]));
        // A different session has its own (empty) ledger.
        assert!(store.observed_taints("s2").is_empty());
    }

    #[test]
    fn unknown_session_is_empty() {
        let store = InMemoryFactStore::new();
        assert!(store.observed_taints("never-seen").is_empty());
    }
}
