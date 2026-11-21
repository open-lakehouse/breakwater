//! The Cedar entities of a request, from Postgres.
//!
//! olai-auth's [`GrantsEntityLoader`] over the `authz` grants
//! ([`PgGrantStore`]) builds them, and [`Principals`] adds what the database
//! knows about the principal:
//!
//! - The principal, never cached, so a change (a ban, "Make admin" in the Neon
//!   Console, a disabled service account) counts from the next request:
//!   - `Lakehouse::ServiceAccount` from `authz.service_accounts` (`name`,
//!     `disabled`);
//!   - with [`Config::neon_auth`](crate::Config::neon_auth), `Lakehouse::User`
//!     from Neon Auth's `neon_auth."user"` (`neon_role`, `banned`,
//!     `email_verified`), never from token claims, with its role as a
//!     `Lakehouse::Role` parent. Without it a user is a deny.
//! - Its groups (`authz.memberships`, transitively) as `Lakehouse::Group`
//!   parents, by name.
//! - On the resource and every entity the caller sent with it (a securable's
//!   ancestors), `privileges` (what the principal holds on that entity, itself
//!   or through a group) and `inherited_privileges` (on it or an ancestor).
//!   Cedar can't quantify over a set of grants, so the loader resolves them for
//!   the request at hand.
//!
//! Groups and grants are cached for a short TTL ([`CachedFacts`]). Any error,
//! and running past [`LOAD_TIMEOUT`], is a deny.
//!
//! It reads only what olai-auth's `authz_reader` role may read.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use olai_auth::grants::{
    Grant, GrantChange, GrantError, GrantStore, GroupMembership, ObjectRef, Subject, SubjectFacts,
    SubjectKind,
};
use olai_auth::wire::{AuthorizeRequest, EntityRef};
use olai_auth::{
    BoxError, EntityLoader, GrantsEntityLoader, PgGrantStore, PrincipalAttrs, PrincipalFacts,
    SubjectTypes, async_trait,
};
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

use crate::Error;

pub const USER: &str = "Lakehouse::User";
pub const SERVICE_ACCOUNT: &str = "Lakehouse::ServiceAccount";
pub const GROUP: &str = "Lakehouse::Group";
pub const ROLE: &str = "Lakehouse::Role";

/// Well under the 2 s a caller's `HttpAuthorizer` waits for a decision.
pub const LOAD_TIMEOUT: Duration = Duration::from_millis(1500);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CONNECTIONS: u32 = 4;
/// The most cached facts before the cache is dropped.
const MAX_CACHED: usize = 10_000;

/// The loader of the PDP: grants and groups from `authz`, the principal from
/// [`Principals`], under a deadline.
pub struct PgEntityLoader {
    inner: GrantsEntityLoader<CachedFacts<PgGrantStore>, Principals>,
}

impl PgEntityLoader {
    /// A loader over `database_url`, connected on first use, that reuses
    /// groups and grants for `ttl` (never when zero), and loads users from
    /// `neon_auth."user"` when `neon_auth`.
    pub fn new(database_url: &str, ttl: Duration, neon_auth: bool) -> Result<Self, Error> {
        let options: PgConnectOptions = database_url
            .parse()
            .map_err(|e| Error::Config(format!("invalid database url: {e}")))?;
        let pool = PgPoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect_lazy_with(options);
        let store = CachedFacts::new(PgGrantStore::new(pool.clone()), ttl);
        let inner = GrantsEntityLoader::new(store, SubjectTypes::new(USER, SERVICE_ACCOUNT, GROUP))
            .with_principal_attrs(Principals { pool, neon_auth });
        Ok(Self { inner })
    }
}

#[async_trait]
impl EntityLoader for PgEntityLoader {
    async fn load(&self, request: &AuthorizeRequest) -> Result<Value, BoxError> {
        match tokio::time::timeout(LOAD_TIMEOUT, self.inner.load(request)).await {
            Ok(entities) => entities,
            Err(_) => Err(format!("loading entities timed out after {LOAD_TIMEOUT:?}").into()),
        }
    }

    async fn load_batch(&self, requests: &[AuthorizeRequest]) -> Vec<Result<Value, BoxError>> {
        match tokio::time::timeout(LOAD_TIMEOUT, self.inner.load_batch(requests)).await {
            Ok(entities) => entities,
            Err(_) => requests
                .iter()
                .map(|_| Err(format!("loading entities timed out after {LOAD_TIMEOUT:?}").into()))
                .collect(),
        }
    }
}

/// The facts about a principal: a service account's name and whether it is
/// disabled, or (with `neon_auth`) a Neon Auth user's role and ban.
pub struct Principals {
    pool: PgPool,
    neon_auth: bool,
}

#[async_trait]
impl PrincipalAttrs for Principals {
    async fn principal(
        &self,
        principal: &EntityRef,
        subject: &Subject,
    ) -> Result<PrincipalFacts, BoxError> {
        let id = Uuid::parse_str(&subject.id)
            .map_err(|_| format!("{principal} is not a known principal"))?;
        match subject.kind {
            SubjectKind::User if !self.neon_auth => {
                Err(format!("{principal}: no user source is configured").into())
            }
            SubjectKind::User => {
                let row: Option<(Option<String>, bool, bool)> = sqlx::query_as(
                    r#"SELECT role,
                              coalesce(banned, false) AND ("banExpires" IS NULL OR "banExpires" > now()),
                              coalesce("emailVerified", false)
                       FROM neon_auth."user" WHERE id = $1"#,
                )
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
                let (role, banned, email_verified) =
                    row.ok_or_else(|| format!("no Neon Auth user {:?}", subject.id))?;
                let role = role
                    .filter(|r| !r.is_empty())
                    .unwrap_or_else(|| "user".into());
                let role_ref = EntityRef::new(ROLE, role.clone());
                Ok(PrincipalFacts {
                    attrs: attrs(
                        json!({ "neon_role": role, "banned": banned, "email_verified": email_verified }),
                    ),
                    parents: vec![role_ref.clone()],
                    entities: vec![json!({ "uid": role_ref, "attrs": {}, "parents": [] })],
                })
            }
            SubjectKind::ServiceAccount => {
                let row: Option<(String, bool)> = sqlx::query_as(
                    "SELECT name, disabled_at IS NOT NULL FROM authz.service_accounts WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
                let (name, disabled) =
                    row.ok_or_else(|| format!("no service account {:?}", subject.id))?;
                Ok(PrincipalFacts {
                    attrs: attrs(json!({ "name": name, "disabled": disabled })),
                    ..PrincipalFacts::default()
                })
            }
            SubjectKind::Group => Err(format!("{principal} is a group, not a principal").into()),
        }
    }
}

fn attrs(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The cached facts of a subject on a set of entities, with when they were loaded.
type FactsCache = HashMap<(Subject, Vec<ObjectRef>), (Instant, SubjectFacts)>;

/// A [`GrantStore`] that reuses a subject's [`facts`](GrantStore::facts) on the
/// same entities for a TTL. Everything else goes to the store.
pub struct CachedFacts<S> {
    store: S,
    ttl: Duration,
    cache: Mutex<FactsCache>,
}

impl<S> CachedFacts<S> {
    /// `store`, reusing facts for `ttl` (never when zero).
    pub fn new(store: S, ttl: Duration) -> Self {
        Self {
            store,
            ttl,
            cache: Mutex::default(),
        }
    }
}

#[async_trait]
impl<S: GrantStore> GrantStore for CachedFacts<S> {
    async fn list(&self, object: &ObjectRef) -> Result<Vec<Grant>, GrantError> {
        self.store.list(object).await
    }

    async fn apply(
        &self,
        object: &ObjectRef,
        changes: &[GrantChange],
    ) -> Result<Vec<Grant>, GrantError> {
        self.store.apply(object, changes).await
    }

    async fn delete_object(
        &self,
        object: &ObjectRef,
        descendant_types: &[&str],
    ) -> Result<u64, GrantError> {
        self.store.delete_object(object, descendant_types).await
    }

    async fn rename(
        &self,
        object: &ObjectRef,
        new_id: &str,
        descendant_types: &[&str],
    ) -> Result<u64, GrantError> {
        self.store.rename(object, new_id, descendant_types).await
    }

    async fn groups(&self, subject: &Subject) -> Result<Vec<GroupMembership>, GrantError> {
        self.store.groups(subject).await
    }

    async fn effective(
        &self,
        subject: &Subject,
        objects: &[ObjectRef],
    ) -> Result<Vec<Grant>, GrantError> {
        self.store.effective(subject, objects).await
    }

    async fn facts(
        &self,
        subject: &Subject,
        objects: &[ObjectRef],
    ) -> Result<SubjectFacts, GrantError> {
        if self.ttl.is_zero() {
            return self.store.facts(subject, objects).await;
        }
        let mut sorted = objects.to_vec();
        sorted.sort();
        let key = (subject.clone(), sorted);
        if let Ok(cache) = self.cache.lock()
            && let Some((at, facts)) = cache.get(&key)
            && at.elapsed() < self.ttl
        {
            return Ok(facts.clone());
        }
        let facts = self.store.facts(subject, objects).await?;
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= MAX_CACHED {
                cache.clear();
            }
            cache.insert(key, (Instant::now(), facts.clone()));
        }
        Ok(facts)
    }
}
