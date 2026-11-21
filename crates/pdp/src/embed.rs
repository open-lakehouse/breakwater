//! The PDP as a service a host embeds: [`start`] builds the router a host
//! serves (`pdp serve`, or a host that drives it in-process, such as a Neon
//! Function), [`migrate`] applies the `authz` schema it reads.

use std::sync::Arc;

use axum::Router;
use olai_auth::wire::AuthorizeRequest;
use olai_auth::{BoxError, CedarAuthorizer, EntityLoader, async_trait};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::http::{AppState, Callers};
use crate::loader::PgEntityLoader;
use crate::policy::{ActionRef, PolicySet};
use crate::{Config, Error};

/// The schema `migrate` applies olai-auth's migrations to.
pub const AUTHZ_SCHEMA: &str = "authz";

/// A started PDP: its router and the actions of its schema.
#[derive(Clone)]
pub struct Service {
    router: Router,
    actions: Arc<Vec<ActionRef>>,
}

impl Service {
    /// The router: `GET /health`, `POST /v1/authorize`, `POST /v1/authorize/batch`.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// The actions of the composed schema, sorted.
    pub fn actions(&self) -> &[ActionRef] {
        &self.actions
    }
}

/// Load and validate the policies (strict mode, so a bad policy never serves),
/// read the callers' secrets from the environment and prepare the connection
/// pool (connected on first use). Never migrates.
pub async fn start(config: &Config) -> Result<Service, Error> {
    // Collected first: `std::env::Vars` isn't `Send`, and the future must be.
    let vars: Vec<String> = std::env::vars().map(|(key, _)| key).collect();
    start_with_secrets(config, vars, |key| std::env::var(key).ok()).await
}

/// [`start`] with the callers' secrets from `secret` instead of the process
/// environment; `vars` are the names a misnamed secret is looked for in.
pub async fn start_with_secrets(
    config: &Config,
    vars: impl IntoIterator<Item = String>,
    secret: impl Fn(&str) -> Option<String>,
) -> Result<Service, Error> {
    let set = PolicySet::load(config.builtin_policies, &config.policy_dirs)?;
    let actions = set.actions()?;
    let database_url = config
        .database_url
        .as_deref()
        .ok_or_else(|| Error::Config("set PDP_DATABASE_URL or DATABASE_URL".into()))?;
    let loader = PgEntityLoader::new(database_url, config.entity_ttl, config.neon_auth)?;
    let callers = Callers::new(&config.callers, &config.token_prefix, vars, secret);
    service(&set, loader, callers, actions)
}

/// Validate the policies without a database: the actions of the schema, or why
/// the set would not serve.
pub fn check(config: &Config) -> Result<Vec<ActionRef>, Error> {
    let set = PolicySet::load(config.builtin_policies, &config.policy_dirs)?;
    let actions = set.actions()?;
    CedarAuthorizer::new(&set.schema, &set.policies, NoEntities)
        .map_err(|e| Error::Policy(e.to_string()))?;
    Ok(actions)
}

pub(crate) fn service(
    set: &PolicySet,
    loader: impl EntityLoader,
    callers: Callers,
    actions: Vec<ActionRef>,
) -> Result<Service, Error> {
    let authorizer = CedarAuthorizer::new(&set.schema, &set.policies, loader)
        .map_err(|e| Error::Policy(e.to_string()))?;
    if callers.is_empty() {
        tracing::warn!("no caller has a secret: every authorization request is a 401");
    }
    let router = crate::http::router(Arc::new(AppState {
        authorizer,
        callers,
    }));
    Ok(Service {
        router,
        actions: Arc::new(actions),
    })
}

/// Apply olai-auth's `authz` migrations (service accounts, API keys, groups,
/// memberships, grants, the `authz_reader` role) to the database at
/// `database_url`. Use a direct connection: the migrator holds a session
/// advisory lock.
pub async fn migrate(database_url: &str) -> Result<(), Error> {
    let options: PgConnectOptions = database_url
        .parse()
        .map_err(|e| Error::Config(format!("invalid database url: {e}")))?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;
    let migrated = olai_auth::migrate(&pool, AUTHZ_SCHEMA)
        .await
        .map_err(|e| Error::Database(e.to_string()));
    pool.close().await;
    migrated
}

/// The loader of [`check`], which never decides.
struct NoEntities;

#[async_trait]
impl EntityLoader for NoEntities {
    async fn load(&self, _: &AuthorizeRequest) -> Result<Value, BoxError> {
        Err("no entities".into())
    }
}
