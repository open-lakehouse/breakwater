//! The PDP's HTTP surface: `GET /health` (open), and `POST /v1/authorize` and
//! `POST /v1/authorize/batch` (`olai_auth::wire`) for the configured callers,
//! each holding its `<token_prefix><NAME>` secret.

use std::fmt;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use olai_auth::wire::{
    AUTHORIZE_BATCH_PATH, AUTHORIZE_PATH, AuthorizeRequest, AuthorizeResponse,
    BatchAuthorizeRequest, BatchAuthorizeResponse, EntityRef,
};
use olai_auth::{Authorizer, CedarAuthorizer};
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config;

/// The most requests one batch may carry.
const MAX_BATCH: usize = 1000;

/// A service holding a secret: its name, its namespace's action type, and the
/// SHA-256 of its secret.
struct Caller {
    service: String,
    action_type: String,
    digest: [u8; 32],
}

/// The callers configured in the environment.
pub(crate) struct Callers(Vec<Caller>);

impl Callers {
    /// Every one of `configured` whose secret (`<prefix><NAME>`, from
    /// `secret`) is set and non-empty. `vars` are the names in the
    /// environment: one with the prefix that names no caller is reported.
    pub(crate) fn new(
        configured: &[config::Caller],
        prefix: &str,
        vars: impl IntoIterator<Item = String>,
        secret: impl Fn(&str) -> Option<String>,
    ) -> Self {
        for key in vars {
            if let Some(name) = key.strip_prefix(prefix)
                && !configured.iter().any(|c| c.name == name)
            {
                tracing::warn!(%key, "ignored: not a configured caller");
            }
        }
        let mut callers = Vec::new();
        for caller in configured {
            let key = format!("{prefix}{}", caller.name);
            match secret(&key).filter(|value| !value.is_empty()) {
                Some(value) => {
                    callers.push(Caller {
                        service: caller.name.clone(),
                        action_type: format!("{}::Action", caller.namespace),
                        digest: Sha256::digest(value.as_bytes()).into(),
                    });
                    tracing::info!(caller = %caller.name, namespace = %caller.namespace, "caller configured");
                }
                None => tracing::warn!(%key, "caller not configured: no secret"),
            }
        }
        Self(callers)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The caller whose secret is the request's bearer token. Every configured
    /// secret is compared, in constant time.
    fn identify(&self, headers: &HeaderMap) -> Option<&Caller> {
        let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        let mut found = None;
        for caller in &self.0 {
            if bool::from(caller.digest.ct_eq(&digest)) {
                found = Some(caller);
            }
        }
        found
    }
}

pub(crate) struct AppState {
    pub(crate) authorizer: CedarAuthorizer,
    pub(crate) callers: Callers,
}

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(AUTHORIZE_PATH, post(authorize))
        .route(AUTHORIZE_BATCH_PATH, post(authorize_batch))
        .with_state(state)
}

/// A request refused before it is decided: an HTTP error with a JSON body.
struct Refusal {
    status: StatusCode,
    message: String,
}

impl Refusal {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut response =
            (self.status, axum::Json(json!({ "error": self.message }))).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().expect("static"));
        }
        response
    }
}

/// The caller and the parsed body.
fn accept<'a, T: DeserializeOwned>(
    state: &'a AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(&'a Caller, T), Refusal> {
    let caller = state.callers.identify(headers).ok_or_else(|| {
        Refusal::new(
            StatusCode::UNAUTHORIZED,
            "missing or unknown service secret",
        )
    })?;
    let parsed = serde_json::from_slice(body)
        .map_err(|e| Refusal::new(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    Ok((caller, parsed))
}

/// A request for an action outside the caller's namespace is refused outright.
fn check_namespace(caller: &Caller, request: &AuthorizeRequest) -> Result<(), Refusal> {
    if request.action.entity_type == caller.action_type {
        return Ok(());
    }
    tracing::warn!(
        caller = %caller.service,
        action = %Uid(&request.action),
        "refused: action outside the caller's namespace"
    );
    Err(Refusal::new(
        StatusCode::FORBIDDEN,
        format!(
            "{} may only ask about {} actions, not {}",
            caller.service,
            caller.action_type,
            Uid(&request.action)
        ),
    ))
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<AuthorizeResponse>, Refusal> {
    let (caller, request) = accept::<AuthorizeRequest>(&state, &headers, &body)?;
    check_namespace(caller, &request)?;
    let response = state.authorizer.authorize(&request).await;
    log(caller, &request, &response);
    Ok(axum::Json(response))
}

async fn authorize_batch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<BatchAuthorizeResponse>, Refusal> {
    let (caller, batch) = accept::<BatchAuthorizeRequest>(&state, &headers, &body)?;
    if batch.requests.len() > MAX_BATCH {
        return Err(Refusal::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("at most {MAX_BATCH} requests per batch"),
        ));
    }
    for request in &batch.requests {
        check_namespace(caller, request)?;
    }
    let responses = state.authorizer.authorize_batch(&batch.requests).await;
    for (request, response) in batch.requests.iter().zip(&responses) {
        log(caller, request, response);
    }
    Ok(axum::Json(BatchAuthorizeResponse { responses }))
}

/// The decision log: one line per decision.
fn log(caller: &Caller, request: &AuthorizeRequest, response: &AuthorizeResponse) {
    tracing::info!(
        target: "olai_pdp::decision",
        caller = %caller.service,
        principal = %Uid(&request.principal),
        action = %Uid(&request.action),
        resource = %Uid(&request.resource),
        decision = ?response.decision,
        policies = ?response.policies,
        errors = ?response.errors,
        "decision"
    );
}

/// An entity uid as Cedar writes it: `Ns::Type::"id"`.
struct Uid<'a>(&'a EntityRef);

impl fmt::Display for Uid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{:?}", self.0.entity_type, self.0.id)
    }
}
