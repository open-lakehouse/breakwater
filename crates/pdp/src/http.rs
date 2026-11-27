//! The PDP's HTTP surface: `GET /health` (open), `POST /v1/authorize` and
//! `POST /v1/authorize/batch` (`olai_auth::wire`), and the OPA-compatible
//! `POST /v1/data/{package}` for the configured callers, each holding its
//! `<token_prefix><NAME>` secret as a bearer token. A caller opted in to path
//! tokens may instead call `POST /opa/{secret}/v1/data/{package}`.

use std::fmt;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
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
use crate::loader::{LOAD_TIMEOUT, PrincipalResolver};
use crate::opa::{self, ContextShapes, OpaRequest};

/// The most requests one batch may carry.
const MAX_BATCH: usize = 1000;

/// A service holding a secret: its name, its namespace's action type, and the
/// SHA-256 of its secret.
struct Caller {
    service: String,
    namespace: String,
    action_type: String,
    digest: [u8; 32],
    /// May present its secret in the OPA route's path.
    path_token: bool,
}

/// The callers configured in the environment.
pub(crate) struct Callers(Vec<Caller>);

impl Callers {
    /// Every one of `configured` whose secret (`<prefix><NAME>`, from
    /// `secret`) is set and non-empty, those named in `path_token` allowed to
    /// present it in the OPA route's path. `vars` are the names in the
    /// environment: one with the prefix that names no caller is reported.
    pub(crate) fn new(
        configured: &[config::Caller],
        path_token: &[String],
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
                    let path_token = path_token.contains(&caller.name);
                    callers.push(Caller {
                        service: caller.name.clone(),
                        namespace: caller.namespace.clone(),
                        action_type: format!("{}::Action", caller.namespace),
                        digest: Sha256::digest(value.as_bytes()).into(),
                        path_token,
                    });
                    tracing::info!(caller = %caller.name, namespace = %caller.namespace, path_token, "caller configured");
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
        self.by_secret(token.trim())
    }

    /// The caller whose secret is `token`, comparing every configured secret
    /// in constant time.
    fn by_secret(&self, token: &str) -> Option<&Caller> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
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
    /// Who an OPA input's principal is.
    pub(crate) resolver: Box<dyn PrincipalResolver>,
    /// The context each action declares, for the OPA route.
    pub(crate) contexts: ContextShapes,
}

/// The OPA route, under its bearer form. Clients append nothing to their
/// configured URL, so any package path works: it is logged, not decided on.
pub(crate) const OPA_DATA_PATH: &str = "/v1/data/{*package}";
/// The OPA route with the caller's secret in the path.
pub(crate) const OPA_TOKEN_PATH: &str = "/opa/{token}/v1/data/{*package}";

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(AUTHORIZE_PATH, post(authorize))
        .route(AUTHORIZE_BATCH_PATH, post(authorize_batch))
        .route(OPA_DATA_PATH, post(opa_bearer))
        .route(OPA_TOKEN_PATH, post(opa_path_token))
        .with_state(state)
}

/// A request refused before it is decided: an HTTP error with a JSON body.
struct Refusal {
    status: StatusCode,
    message: String,
    /// Whether a 401 asks for a bearer token (`WWW-Authenticate: Bearer`).
    challenge: bool,
}

impl Refusal {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            challenge: true,
        }
    }

    /// A 401 of the path-token route, which takes no bearer.
    fn unknown_path_token() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unknown path token".into(),
            challenge: false,
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut response =
            (self.status, axum::Json(json!({ "error": self.message }))).into_response();
        if self.status == StatusCode::UNAUTHORIZED && self.challenge {
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
    log(caller, &request, &response, None);
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
        log(caller, request, response, None);
    }
    Ok(axum::Json(BatchAuthorizeResponse { responses }))
}

/// `POST /v1/data/{package}`, the caller identified by its bearer token.
async fn opa_bearer(
    State(state): State<Arc<AppState>>,
    Path(package): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<serde_json::Value>, Refusal> {
    let (caller, request) = accept::<OpaRequest>(&state, &headers, &body)?;
    Ok(opa_decide(&state, caller, &package, request).await)
}

/// `POST /opa/{token}/v1/data/{package}`, the caller identified by the secret
/// in its path. Only callers opted in to path tokens.
async fn opa_path_token(
    State(state): State<Arc<AppState>>,
    Path((token, package)): Path<(String, String)>,
    body: Bytes,
) -> Result<axum::Json<serde_json::Value>, Refusal> {
    let caller = state
        .callers
        .by_secret(&token)
        .filter(|caller| caller.path_token)
        .ok_or_else(Refusal::unknown_path_token)?;
    let request: OpaRequest = serde_json::from_slice(&body)
        .map_err(|e| Refusal::new(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    Ok(opa_decide(&state, caller, &package, request).await)
}

/// Decide an OPA input in the caller's namespace and answer
/// `{"result": {"allow": …}}`, the only shape UC's clients accept. A principal
/// that doesn't resolve, or an input that doesn't map, is a deny.
async fn opa_decide(
    state: &AppState,
    caller: &Caller,
    package: &str,
    request: OpaRequest,
) -> axum::Json<serde_json::Value> {
    let input = request.input;
    let resolved =
        match tokio::time::timeout(LOAD_TIMEOUT, state.resolver.resolve(&input.principal)).await {
            Ok(resolved) => resolved.map_err(|e| format!("resolving the principal: {e}")),
            Err(_) => Err(format!(
                "resolving the principal timed out after {LOAD_TIMEOUT:?}"
            )),
        };
    let action =
        olai_auth::wire::EntityRef::new(caller.action_type.clone(), input.privilege.clone());
    let mut context = input.context.clone().unwrap_or_default();
    // Ours, whatever the client put there.
    context.remove(opa::PRINCIPAL_EMAIL);
    if let Some(email) = input.principal.email() {
        context.insert(opa::PRINCIPAL_EMAIL.into(), email.into());
    }
    let context = state.contexts.project(&action, &context);
    let mapped = resolved
        .and_then(|principal| opa::to_authorize(&caller.namespace, &input, principal, context));
    let allow = match mapped {
        Ok(request) => {
            let response = state.authorizer.authorize(&request).await;
            log(caller, &request, &response, Some(package));
            response.is_allowed()
        }
        Err(error) => {
            tracing::info!(
                target: "olai_pdp::decision",
                caller = %caller.service,
                package,
                principal = ?input.principal,
                action = %Uid(&action),
                decision = "deny",
                errors = ?[&error],
                "decision"
            );
            false
        }
    };
    axum::Json(json!({ "result": { "allow": allow } }))
}

/// The decision log: one line per decision.
fn log(
    caller: &Caller,
    request: &AuthorizeRequest,
    response: &AuthorizeResponse,
    package: Option<&str>,
) {
    tracing::info!(
        target: "olai_pdp::decision",
        caller = %caller.service,
        package,
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
