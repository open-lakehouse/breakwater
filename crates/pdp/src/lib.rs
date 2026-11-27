//! A Cedar policy decision point (PDP) serving olai-auth's PDP wire API.
//!
//! Services ask it whether a principal may perform an action on a resource,
//! over [`olai_auth::wire`] (their `olai_auth::HttpAuthorizer` is the
//! client): `POST /v1/authorize` and `POST /v1/authorize/batch`, authenticated
//! with a per-caller bearer secret, and `GET /health`, open. A caller asks only
//! about the actions of its own Cedar namespace.
//!
//! Unity Catalog's OPA authorizers (UC Java 0.8, unitycatalog-rs) call the
//! OPA-compatible `POST /v1/data/{package}` instead: `{"input": …}` in,
//! `{"result": {"allow": …}}` out, one privilege check per request, decided
//! in the caller's namespace (see `policies/unitycatalog-opa`). A client that
//! sends no `Authorization` header (UC Java) puts its secret in the path,
//! `POST /opa/{secret}/v1/data/{package}`, if its caller is opted in with
//! [`Config::path_token_callers`].
//!
//! Decisions are [`olai_auth::CedarAuthorizer`]'s, over the built-in
//! `Lakehouse` schema and baseline ([`policy::BUILTIN`]) plus the schema
//! fragments and policies of the configured directories, validated in strict
//! mode at start. The entities come from Postgres ([`loader::PgEntityLoader`]):
//! the principal and its groups and grants from olai-auth's `authz` schema,
//! users from Neon Auth's `neon_auth."user"` when enabled. Any error is a deny.
//!
//! Run it as `pdp serve` (feature `bin`, or the container image), or embed it:
//!
//! ```no_run
//! # async fn run() -> Result<(), olai_pdp::Error> {
//! let mut config = olai_pdp::Config::from_env()?;
//! config.callers.push(olai_pdp::Caller::new("UNITYCATALOG", "UnityCatalog"));
//! let service = olai_pdp::embed::start(&config).await?;
//! let router = service.router(); // serve it, or drive it with `oneshot`
//! # let _ = router; Ok(()) }
//! ```

mod config;
pub mod embed;
mod http;
pub mod loader;
mod opa;
pub mod policy;

pub use config::{Caller, Config, DEFAULT_ENTITY_TTL, DEFAULT_PORT, DEFAULT_TOKEN_PREFIX};
pub use opa::OpaPrincipal;
pub use policy::ActionRef;

/// Why the PDP can't start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The configuration is invalid.
    #[error("{0}")]
    Config(String),
    /// The schema or the policies don't load or validate.
    #[error("{0}")]
    Policy(String),
    /// The database refused a migration.
    #[error("{0}")]
    Database(String),
}

#[cfg(test)]
mod opa_tests;
#[cfg(test)]
mod tests;
