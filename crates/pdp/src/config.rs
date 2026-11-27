//! The PDP's configuration, from the environment ([`Config::from_env`]) or
//! built by an embedding host.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use crate::Error;

/// The prefix of a caller's secret: `AUTHZ_TOKEN_<NAME>` holds the bearer
/// token of the caller `<NAME>`.
pub const DEFAULT_TOKEN_PREFIX: &str = "AUTHZ_TOKEN_";

/// How long the loader reuses a principal's groups and grants.
pub const DEFAULT_ENTITY_TTL: Duration = Duration::from_secs(2);

/// The port `pdp serve` listens on.
pub const DEFAULT_PORT: u16 = 8080;

/// A service that may ask for decisions: its name, which names its secret
/// (`<token_prefix><name>`), and the Cedar namespace it may ask about. A caller
/// asks only about actions of its own namespace (`UnityCatalog::Action::"select"`
/// for `UNITYCATALOG=UnityCatalog`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The caller's name, e.g. `UNITYCATALOG`.
    pub name: String,
    /// Its Cedar namespace, e.g. `UnityCatalog`.
    pub namespace: String,
}

impl Caller {
    /// The caller `name`, asking about `namespace`.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
        }
    }
}

/// What the PDP decides over, and where it reads its entities.
///
/// Holds no secrets: the callers' tokens are read from the environment when
/// the service starts.
#[derive(Debug, Clone)]
pub struct Config {
    /// The Postgres holding the `authz` schema (and `neon_auth`, with
    /// [`neon_auth`](Self::neon_auth)).
    pub database_url: Option<String>,
    /// Directories of `*.cedarschema` fragments and `*.cedar` policies, read
    /// in file name order after the built-in ones.
    pub policy_dirs: Vec<PathBuf>,
    /// Include the built-in `Lakehouse` schema and its baseline policies
    /// ([`crate::policy::BUILTIN`]). The loader builds `Lakehouse::*`
    /// principals, so turn this off only to supply that schema yourself.
    pub builtin_policies: bool,
    /// The services that may call.
    pub callers: Vec<Caller>,
    /// The caller of the trusted listener: one of [`callers`](Self::callers),
    /// as which every request there is decided, with no credential. For a
    /// client that sends none (UC Java 0.8). It needs no secret, and has the
    /// trusted listener only (`POST /v1/data/{package}`) unless it has one.
    ///
    /// The network is what authenticates it: serve the trusted listener only
    /// where nothing but that client can reach it.
    pub trusted_caller: Option<String>,
    /// The address `pdp serve` binds the trusted listener on.
    pub trusted_host: IpAddr,
    /// The port of `pdp serve`'s trusted listener. Required with a
    /// [`trusted_caller`](Self::trusted_caller), for `pdp serve`.
    pub trusted_port: Option<u16>,
    /// The prefix of the callers' secrets in the environment.
    pub token_prefix: String,
    /// How long the loader reuses a principal's groups and grants (never when
    /// zero). The principal itself is never cached.
    pub entity_ttl: Duration,
    /// Load `Lakehouse::User` principals from Neon Auth's `neon_auth."user"`.
    /// Without it, a user principal is a deny.
    pub neon_auth: bool,
    /// The address `pdp serve` binds.
    pub host: IpAddr,
    /// The port `pdp serve` listens on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: None,
            policy_dirs: Vec::new(),
            builtin_policies: true,
            callers: Vec::new(),
            trusted_caller: None,
            trusted_host: IpAddr::from([127, 0, 0, 1]),
            trusted_port: None,
            token_prefix: DEFAULT_TOKEN_PREFIX.into(),
            entity_ttl: DEFAULT_ENTITY_TTL,
            neon_auth: false,
            host: IpAddr::from([0, 0, 0, 0]),
            port: DEFAULT_PORT,
        }
    }
}

impl Config {
    /// The configuration in the environment:
    ///
    /// | Variable | Field | Default |
    /// |---|---|---|
    /// | `PDP_DATABASE_URL`, else `DATABASE_URL` | [`database_url`](Self::database_url) | none |
    /// | `PDP_POLICY_DIRS` (`:`-separated) | [`policy_dirs`](Self::policy_dirs) | none |
    /// | `PDP_BUILTIN_POLICIES` | [`builtin_policies`](Self::builtin_policies) | `true` |
    /// | `PDP_CALLERS` (`NAME=Namespace,…`) | [`callers`](Self::callers) | none |
    /// | `PDP_TRUSTED_CALLER` (`NAME`) | [`trusted_caller`](Self::trusted_caller) | none |
    /// | `PDP_TRUSTED_HOST` | [`trusted_host`](Self::trusted_host) | `127.0.0.1` |
    /// | `PDP_TRUSTED_PORT` | [`trusted_port`](Self::trusted_port) | none |
    /// | `PDP_TOKEN_PREFIX` | [`token_prefix`](Self::token_prefix) | `AUTHZ_TOKEN_` |
    /// | `AUTHZ_ENTITY_TTL_MS` | [`entity_ttl`](Self::entity_ttl) | `2000` |
    /// | `PDP_NEON_AUTH` | [`neon_auth`](Self::neon_auth) | `false` |
    /// | `PDP_HOST` | [`host`](Self::host) | `0.0.0.0` |
    /// | `PDP_PORT` | [`port`](Self::port) | `8080` |
    ///
    /// An empty variable is unset.
    pub fn from_env() -> Result<Self, Error> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// [`from_env`](Self::from_env) over `lookup` instead of the process
    /// environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let get = |key: &str| lookup(key).filter(|value| !value.is_empty());
        let mut config = Self {
            database_url: get("PDP_DATABASE_URL").or_else(|| get("DATABASE_URL")),
            ..Self::default()
        };
        if let Some(dirs) = get("PDP_POLICY_DIRS") {
            config.policy_dirs = dirs
                .split(':')
                .filter(|dir| !dir.is_empty())
                .map(PathBuf::from)
                .collect();
        }
        if let Some(value) = get("PDP_BUILTIN_POLICIES") {
            config.builtin_policies = parse_bool("PDP_BUILTIN_POLICIES", &value)?;
        }
        if let Some(value) = get("PDP_CALLERS") {
            config.callers = parse_callers(&value)?;
        }
        config.trusted_caller = get("PDP_TRUSTED_CALLER").map(|name| name.trim().to_string());
        if let Some(host) = get("PDP_TRUSTED_HOST") {
            config.trusted_host = host
                .parse()
                .map_err(|e| Error::Config(format!("invalid PDP_TRUSTED_HOST {host:?}: {e}")))?;
        }
        if let Some(port) = get("PDP_TRUSTED_PORT") {
            config.trusted_port =
                Some(port.parse().map_err(|e| {
                    Error::Config(format!("invalid PDP_TRUSTED_PORT {port:?}: {e}"))
                })?);
        }
        if let Some(prefix) = get("PDP_TOKEN_PREFIX") {
            config.token_prefix = prefix;
        }
        if let Some(ms) = get("AUTHZ_ENTITY_TTL_MS") {
            config.entity_ttl = u64::from_str(&ms)
                .map(Duration::from_millis)
                .map_err(|e| Error::Config(format!("invalid AUTHZ_ENTITY_TTL_MS {ms:?}: {e}")))?;
        }
        if let Some(value) = get("PDP_NEON_AUTH") {
            config.neon_auth = parse_bool("PDP_NEON_AUTH", &value)?;
        }
        if let Some(host) = get("PDP_HOST") {
            config.host = host
                .parse()
                .map_err(|e| Error::Config(format!("invalid PDP_HOST {host:?}: {e}")))?;
        }
        if let Some(port) = get("PDP_PORT") {
            config.port = port
                .parse()
                .map_err(|e| Error::Config(format!("invalid PDP_PORT {port:?}: {e}")))?;
        }
        config.check()?;
        Ok(config)
    }

    /// Fails when the [`trusted_caller`](Self::trusted_caller) isn't one of
    /// the [`callers`](Self::callers), or a trusted port is set without one or
    /// is the main port.
    pub fn check(&self) -> Result<(), Error> {
        if let Some(name) = &self.trusted_caller
            && !self.callers.iter().any(|c| &c.name == name)
        {
            return Err(Error::Config(format!(
                "PDP_TRUSTED_CALLER names {name:?}, which is not in PDP_CALLERS"
            )));
        }
        match self.trusted_port {
            Some(_) if self.trusted_caller.is_none() => Err(Error::Config(
                "PDP_TRUSTED_PORT is set without PDP_TRUSTED_CALLER".into(),
            )),
            Some(port) if port == self.port => Err(Error::Config(format!(
                "PDP_TRUSTED_PORT {port} is PDP_PORT: the trusted listener needs its own"
            ))),
            _ => Ok(()),
        }
    }
}

/// `NAME=Namespace,…`, e.g. `UNITYCATALOG=UnityCatalog,HEADWATERS=Headwaters`.
fn parse_callers(value: &str) -> Result<Vec<Caller>, Error> {
    let mut callers: Vec<Caller> = Vec::new();
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (name, namespace) = entry
            .split_once('=')
            .map(|(n, ns)| (n.trim(), ns.trim()))
            .filter(|(n, ns)| !n.is_empty() && !ns.is_empty())
            .ok_or_else(|| {
                Error::Config(format!(
                    "invalid PDP_CALLERS entry {entry:?}: expected NAME=Namespace"
                ))
            })?;
        if callers.iter().any(|c| c.name == name) {
            return Err(Error::Config(format!("PDP_CALLERS names {name:?} twice")));
        }
        callers.push(Caller::new(name, namespace));
    }
    Ok(callers)
}

fn parse_bool(key: &str, value: &str) -> Result<bool, Error> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(Error::Config(format!(
            "invalid {key} {value:?}: expected true or false"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, Error> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|key| vars.get(key).cloned())
    }

    #[test]
    fn defaults() {
        let config = config(&[]).unwrap();
        assert_eq!(config.database_url, None);
        assert!(config.builtin_policies);
        assert!(config.callers.is_empty());
        assert_eq!(config.token_prefix, "AUTHZ_TOKEN_");
        assert_eq!(config.entity_ttl, Duration::from_secs(2));
        assert!(!config.neon_auth);
        assert_eq!(config.port, 8080);
        assert_eq!(config.trusted_caller, None);
        assert_eq!(config.trusted_host, IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn reads_every_variable() {
        let config = config(&[
            ("DATABASE_URL", "postgres://fallback"),
            ("PDP_DATABASE_URL", "postgres://pdp"),
            ("PDP_POLICY_DIRS", "/a:/b:"),
            ("PDP_BUILTIN_POLICIES", "false"),
            (
                "PDP_CALLERS",
                " UNITYCATALOG=UnityCatalog , HEADWATERS=Headwaters",
            ),
            ("PDP_TRUSTED_CALLER", "UNITYCATALOG"),
            ("PDP_TRUSTED_HOST", "10.0.0.2"),
            ("PDP_TRUSTED_PORT", "8181"),
            ("PDP_TOKEN_PREFIX", "PDP_TOKEN_"),
            ("AUTHZ_ENTITY_TTL_MS", "0"),
            ("PDP_NEON_AUTH", "yes"),
            ("PDP_HOST", "127.0.0.1"),
            ("PDP_PORT", "9000"),
        ])
        .unwrap();
        assert_eq!(config.database_url.as_deref(), Some("postgres://pdp"));
        assert_eq!(
            config.policy_dirs,
            vec![PathBuf::from("/a"), PathBuf::from("/b")]
        );
        assert!(!config.builtin_policies);
        assert_eq!(
            config.callers,
            vec![
                Caller::new("UNITYCATALOG", "UnityCatalog"),
                Caller::new("HEADWATERS", "Headwaters"),
            ]
        );
        assert_eq!(config.trusted_caller.as_deref(), Some("UNITYCATALOG"));
        assert_eq!(config.trusted_host, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(config.trusted_port, Some(8181));
        assert_eq!(config.token_prefix, "PDP_TOKEN_");
        assert!(config.entity_ttl.is_zero());
        assert!(config.neon_auth);
        assert_eq!(config.host, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(config.port, 9000);
    }

    #[test]
    fn database_url_falls_back() {
        let config =
            config(&[("DATABASE_URL", "postgres://db"), ("PDP_DATABASE_URL", "")]).unwrap();
        assert_eq!(config.database_url.as_deref(), Some("postgres://db"));
    }

    #[test]
    fn refuses_bad_values() {
        for vars in [
            [("PDP_CALLERS", "UNITYCATALOG")],
            [("PDP_CALLERS", "=UnityCatalog")],
            [("PDP_CALLERS", "A=X,A=Y")],
            [("PDP_NEON_AUTH", "maybe")],
            [("AUTHZ_ENTITY_TTL_MS", "-1")],
            [("PDP_PORT", "http")],
            [("PDP_TRUSTED_CALLER", "NOBODY")],
            [("PDP_TRUSTED_PORT", "8181")],
        ] {
            assert!(config(&vars).is_err(), "{vars:?}");
        }
        let same_port = config(&[
            ("PDP_CALLERS", "UC=UnityCatalogOpa"),
            ("PDP_TRUSTED_CALLER", "UC"),
            ("PDP_TRUSTED_PORT", "8080"),
        ]);
        assert!(same_port.is_err());
    }
}
