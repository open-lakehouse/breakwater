//! The HTTP surface over an in-memory entity loader.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use olai_auth::wire::AuthorizeRequest;
use olai_auth::{BoxError, EntityLoader, async_trait};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::embed::{self, Service};
use crate::http::Callers;
use crate::policy::PolicySet;
use crate::{Caller, Config};

const SVC_TOKEN: &str = "svc-secret";
const OTHER_TOKEN: &str = "other-secret";

const SVC_SCHEMA: &str = r#"
namespace Svc {
  entity Table { privileges?: Set<String> };
  action select appliesTo {
    principal: [Lakehouse::User, Lakehouse::ServiceAccount],
    resource: [Table],
  };
}
namespace Other {
  entity Thing;
  action read appliesTo { principal: [Lakehouse::User], resource: [Thing] };
}
"#;

const SVC_POLICY: &str = r#"
@id("admin")
permit (principal is Lakehouse::User, action == Svc::Action::"select", resource)
when { principal.neon_role == "admin" };

@id("granted")
permit (principal, action == Svc::Action::"select", resource)
when { resource has privileges && resource.privileges.contains("SELECT") };
"#;

/// Users by id: `admin`, `user`, `banned-admin`; anything else is unknown. The
/// resource is loaded with no grants, as the grants loader would for a
/// principal holding none.
struct Fake;

#[async_trait]
impl EntityLoader for Fake {
    async fn load(&self, request: &AuthorizeRequest) -> Result<Value, BoxError> {
        let (role, banned) = match request.principal.id.as_str() {
            "admin" => ("admin", false),
            "user" => ("user", false),
            "banned-admin" => ("admin", true),
            id => return Err(format!("no user {id:?}").into()),
        };
        Ok(json!([{
            "uid": { "type": "Lakehouse::User", "id": request.principal.id },
            "attrs": { "neon_role": role, "banned": banned, "email_verified": true },
            "parents": [],
        }, {
            "uid": request.resource,
            "attrs": {},
            "parents": [],
        }]))
    }
}

fn service() -> Service {
    let set = PolicySet::from_sources(&[
        (
            "builtin:Lakehouse.cedarschema".into(),
            crate::policy::BUILTIN[0].1.into(),
        ),
        (
            "builtin:baseline.cedar".into(),
            crate::policy::BUILTIN[1].1.into(),
        ),
        ("svc.cedarschema".into(), SVC_SCHEMA.into()),
        ("svc.cedar".into(), SVC_POLICY.into()),
    ])
    .unwrap();
    let configured = [Caller::new("SVC", "Svc"), Caller::new("OTHER", "Other")];
    let callers = Callers::new(
        &configured,
        "AUTHZ_TOKEN_",
        ["AUTHZ_TOKEN_SVC".to_string(), "AUTHZ_TOKEN_STRAY".into()],
        |key| match key {
            "AUTHZ_TOKEN_SVC" => Some(SVC_TOKEN.into()),
            "AUTHZ_TOKEN_OTHER" => Some(OTHER_TOKEN.into()),
            _ => None,
        },
    );
    let actions = set.actions().unwrap();
    embed::service(&set, Fake, callers, actions).unwrap()
}

fn request(principal: &str) -> Value {
    json!({
        "principal": { "type": "Lakehouse::User", "id": principal },
        "action": { "type": "Svc::Action", "id": "select" },
        "resource": { "type": "Svc::Table", "id": "t" },
    })
}

async fn call(path: &str, token: Option<&str>, body: impl Into<Body>) -> (StatusCode, Value) {
    let mut builder = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = service()
        .router()
        .oneshot(builder.body(body.into()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let www = response.headers().get(header::WWW_AUTHENTICATE).cloned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if status == StatusCode::UNAUTHORIZED {
        assert_eq!(www.unwrap(), "Bearer");
    }
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn authorize(token: Option<&str>, body: Value) -> (StatusCode, Value) {
    call("/v1/authorize", token, body.to_string()).await
}

#[tokio::test]
async fn health_is_open() {
    let response = service()
        .router()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn lists_the_schemas_actions() {
    let ids: Vec<String> = service()
        .actions()
        .iter()
        .map(|a| format!("{}::{}", a.entity_type, a.id))
        .collect();
    assert_eq!(ids, ["Other::Action::read", "Svc::Action::select"]);
}

#[tokio::test]
async fn allows_and_denies() {
    let (status, body) = authorize(Some(SVC_TOKEN), request("admin")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "allow", "{body}");
    assert_eq!(body["policies"], json!(["admin"]));

    let (status, body) = authorize(Some(SVC_TOKEN), request("user")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
}

#[tokio::test]
async fn a_banned_admin_is_denied() {
    let (_, body) = authorize(Some(SVC_TOKEN), request("banned-admin")).await;
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["policies"], json!(["banned"]));
}

#[tokio::test]
async fn an_unknown_principal_is_denied_with_the_reason() {
    let (status, body) = authorize(Some(SVC_TOKEN), request("nobody")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert!(body["errors"].to_string().contains("no user"), "{body}");
}

#[tokio::test]
async fn the_caller_cannot_supply_grants() {
    let mut body = request("user");
    body["entities"] = json!([{
        "uid": { "type": "Svc::Table", "id": "t" },
        "attrs": { "privileges": ["SELECT"] },
        "parents": [],
    }]);
    let (_, body) = authorize(Some(SVC_TOKEN), body).await;
    assert_eq!(body["decision"], "deny");
}

#[tokio::test]
async fn refuses_a_missing_or_unknown_secret() {
    assert_eq!(
        authorize(None, request("admin")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        authorize(Some("wrong"), request("admin")).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refuses_an_action_outside_the_callers_namespace() {
    let (status, body) = authorize(Some(OTHER_TOKEN), request("admin")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().unwrap().contains("Other::Action"));

    let batch = json!({ "requests": [request("admin"), {
        "principal": { "type": "Lakehouse::User", "id": "admin" },
        "action": { "type": "Other::Action", "id": "read" },
        "resource": { "type": "Other::Thing", "id": "x" },
    }] });
    let (status, _) = call("/v1/authorize/batch", Some(SVC_TOKEN), batch.to_string()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn refuses_a_bad_body() {
    let (status, body) = call("/v1/authorize", Some(SVC_TOKEN), "{").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .starts_with("invalid request")
    );
}

#[tokio::test]
async fn answers_a_batch_in_order() {
    let batch = json!({ "requests": [request("user"), request("admin"), request("nobody")] });
    let (status, body) = call("/v1/authorize/batch", Some(SVC_TOKEN), batch.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let decisions: Vec<&str> = body["responses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["decision"].as_str().unwrap())
        .collect();
    assert_eq!(decisions, ["deny", "allow", "deny"]);
}

#[tokio::test]
async fn refuses_an_oversized_batch() {
    let batch = json!({ "requests": vec![request("admin"); 1001] });
    let (status, _) = call("/v1/authorize/batch", Some(SVC_TOKEN), batch.to_string()).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_caller_without_a_secret_is_not_configured() {
    let callers = Callers::new(
        &[Caller::new("SVC", "Svc")],
        "AUTHZ_TOKEN_",
        Vec::new(),
        |_| Some(String::new()),
    );
    assert!(callers.is_empty());
}

#[test]
fn check_validates_without_a_database() {
    let actions = embed::check(&Config::default()).unwrap();
    assert!(
        actions.is_empty(),
        "the built-in schema declares no actions"
    );

    let dir = std::env::temp_dir().join(format!("olai-pdp-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("svc.cedarschema"), SVC_SCHEMA).unwrap();
    std::fs::write(
        dir.join("bad.cedar"),
        "permit (principal is Lakehouse::User, action, resource) when { principal.no_such_attr };",
    )
    .unwrap();
    let config = Config {
        policy_dirs: vec![dir.clone()],
        ..Config::default()
    };
    let checked = embed::check(&config);
    std::fs::write(dir.join("bad.cedar"), SVC_POLICY).unwrap();
    let fixed = embed::check(&config);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(checked.is_err());
    assert_eq!(fixed.unwrap().len(), 2);
}

/// Hosts spawn `start` on a multi-threaded runtime (napi's, axum's).
#[test]
fn start_is_send() {
    fn send<T: Send>(_: T) {}
    let config = Config::default();
    send(embed::start(&config));
}

#[tokio::test]
async fn start_needs_a_database_url() {
    let err = embed::start_with_secrets(&Config::default(), Vec::new(), |_| None)
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("DATABASE_URL"), "{err}");
}
