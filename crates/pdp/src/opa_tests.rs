//! The OPA route: recorded UC Java and unitycatalog-rs inputs
//! (`tests/fixtures/opa`), replayed over the reference `UnityCatalogOpa`
//! policies, olai-auth's grants loader over an in-memory store, and fake
//! users.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use olai_auth::wire::EntityRef;
use olai_auth::{
    BoxError, GrantChange, GrantStore, GrantsEntityLoader, MemoryGrantStore, PrincipalAttrs,
    PrincipalFacts, Subject, SubjectTypes, async_trait,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::Caller;
use crate::embed::{self, Service};
use crate::http::Callers;
use crate::loader::{GROUP, PrincipalResolver, SERVICE_ACCOUNT, USER};
use crate::opa::OpaPrincipal;
use crate::policy::PolicySet;

const UCRS_TOKEN: &str = "uc-rs-secret";
const NS: &str = "UnityCatalogOpa";

/// Neon Auth users: `(id, email, email verified, banned)`.
const USERS: &[(&str, &str, bool, bool)] = &[
    (
        "0f9e8d7c-0000-4000-8000-00000000a11c",
        "Alice@Example.com",
        true,
        false,
    ),
    (
        "0f9e8d7c-0000-4000-8000-000000000b0b",
        "bob@example.com",
        true,
        false,
    ),
    (
        "0f9e8d7c-0000-4000-8000-00000000ca01",
        "carol@example.com",
        true,
        true,
    ),
    (
        "0f9e8d7c-0000-4000-8000-00000000bad0",
        "mallory@example.com",
        false,
        false,
    ),
];
const ALICE: &str = USERS[0].0;
const CAROL: &str = USERS[2].0;

/// The metastore id of the UC Java fixtures.
const UC_JAVA_METASTORE: &str = "11111111-2222-4333-8444-555555555555";

/// Context policy of the test deployment: a request a trusted proxy marked
/// with another tenant is denied.
const TENANT_POLICY: &str = r#"
@id("other-tenant")
forbid (principal, action, resource)
when {
  context has headers && context.headers has "x-tenant" &&
  context.headers["x-tenant"] != "acme"
};
"#;

/// Resolves like `PgPrincipalResolver`: a user's id as `external_id`, else a
/// verified email, case-insensitive.
struct FakeResolver;

#[async_trait]
impl PrincipalResolver for FakeResolver {
    async fn resolve(&self, principal: &OpaPrincipal) -> Result<EntityRef, BoxError> {
        let by_id = principal
            .external_id()
            .and_then(|id| USERS.iter().find(|u| u.0 == id));
        let by_email = || {
            principal.email().and_then(|email| {
                USERS
                    .iter()
                    .find(|u| u.2 && u.1.eq_ignore_ascii_case(email))
            })
        };
        by_id
            .or_else(by_email)
            .map(|u| EntityRef::new(USER, u.0))
            .ok_or_else(|| "no such user".into())
    }
}

/// The users' Neon Auth attributes.
struct FakeUsers;

#[async_trait]
impl PrincipalAttrs for FakeUsers {
    async fn principal(
        &self,
        principal: &EntityRef,
        _: &Subject,
    ) -> Result<PrincipalFacts, BoxError> {
        let user = USERS
            .iter()
            .find(|u| u.0 == principal.id)
            .ok_or("no such user")?;
        let attrs = json!({ "neon_role": "user", "banned": user.3, "email_verified": user.2 });
        Ok(PrincipalFacts {
            attrs: attrs.as_object().unwrap().clone(),
            ..PrincipalFacts::default()
        })
    }
}

fn object(kind: &str, id: &str) -> EntityRef {
    EntityRef::new(format!("{NS}::{kind}"), id)
}

async fn grant(store: &MemoryGrantStore, subject: Subject, privilege: &str, on: EntityRef) {
    store
        .apply(
            &on,
            &[GrantChange {
                subject,
                add: vec![privilege.into()],
                remove: vec![],
            }],
        )
        .await
        .unwrap();
}

/// The grants the fixtures are decided against.
async fn store() -> MemoryGrantStore {
    let store = MemoryGrantStore::new();
    let alice = || Subject::user(ALICE);
    // UC Java's catalog `analytics`.
    grant(&store, alice(), "SELECT", object("Catalog", "analytics")).await;
    grant(
        &store,
        alice(),
        "USE_CATALOG",
        object("Catalog", "analytics"),
    )
    .await;
    grant(&store, alice(), "OWNER", object("Catalog", "analytics")).await;
    store.add_group("g-1", "analysts");
    store.add_member("g-1", alice());
    grant(
        &store,
        Subject::group("g-1"),
        "USE_SCHEMA",
        object("Schema", "analytics.reports"),
    )
    .await;
    grant(
        &store,
        alice(),
        "ALL_PRIVILEGES",
        object("Volume", "analytics.reports.landing"),
    )
    .await;
    grant(
        &store,
        alice(),
        "CREATE_CATALOG",
        object("Metastore", UC_JAVA_METASTORE),
    )
    .await;
    // unitycatalog-rs's catalog `main`.
    grant(&store, alice(), "SELECT", object("Catalog", "main")).await;
    grant(&store, alice(), "USE_CATALOG", object("Catalog", "main")).await;
    // Bob holds what alice lacks on the location and on unitycatalog-rs's
    // metastore, so those denies are decisions, not inputs that didn't map.
    let bob = || Subject::user(USERS[1].0);
    grant(
        &store,
        bob(),
        "CREATE_EXTERNAL_TABLE",
        object("ExternalLocation", "location"),
    )
    .await;
    grant(&store, bob(), "CREATE_CATALOG", object("Metastore", "m-1")).await;
    // Carol, banned, holds SELECT too.
    grant(
        &store,
        Subject::user(CAROL),
        "SELECT",
        object("Catalog", "analytics"),
    )
    .await;
    store
}

async fn service() -> Service {
    let set = PolicySet::from_sources(&[
        (
            "builtin:Lakehouse.cedarschema".into(),
            crate::policy::BUILTIN[0].1.into(),
        ),
        (
            "builtin:baseline.cedar".into(),
            crate::policy::BUILTIN[1].1.into(),
        ),
        (
            "UnityCatalogOpa.cedarschema".into(),
            include_str!("../policies/unitycatalog-opa/UnityCatalogOpa.cedarschema").into(),
        ),
        (
            "unitycatalog-opa.cedar".into(),
            include_str!("../policies/unitycatalog-opa/unitycatalog-opa.cedar").into(),
        ),
        ("tenant.cedar".into(), TENANT_POLICY.into()),
    ])
    .unwrap();
    let loader = GrantsEntityLoader::new(
        store().await,
        SubjectTypes::new(USER, SERVICE_ACCOUNT, GROUP),
    )
    .with_principal_attrs(FakeUsers);
    // UC Java is the trusted listener's caller and has no secret.
    let callers = Callers::new(
        &[Caller::new("UCJAVA", NS), Caller::new("UCRS", NS)],
        Some("UCJAVA"),
        "AUTHZ_TOKEN_",
        Vec::new(),
        |key| (key == "AUTHZ_TOKEN_UCRS").then(|| UCRS_TOKEN.into()),
    );
    let actions = set.actions().unwrap();
    embed::service(&set, loader, FakeResolver, callers, actions).unwrap()
}

/// Which of the service's listeners a request goes to.
#[derive(Clone, Copy)]
enum Listener {
    Main,
    Trusted,
}

/// POST `body` to `path` on the main listener, with `bearer` if any: the
/// status, the `WWW-Authenticate` header and the JSON body.
async fn post(
    path: &str,
    bearer: Option<&str>,
    body: String,
) -> (StatusCode, Option<String>, Value) {
    post_to(Listener::Main, path, bearer, body).await
}

/// [`post`] to `listener`.
async fn post_to(
    listener: Listener,
    path: &str,
    bearer: Option<&str>,
    body: String,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let service = service().await;
    let router = match listener {
        Listener::Main => service.router(),
        Listener::Trusted => service.trusted_router().unwrap(),
    };
    let response = router
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let www = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        www,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// UC Java's configured decision URL, on the trusted listener.
const UC_JAVA_PATH: &str = "/v1/data/uc/authz";

/// What UC Java would read from the answer to `body`, sent without a
/// credential to the trusted listener.
async fn uc_java(body: &Value) -> bool {
    let (status, _, answer) =
        post_to(Listener::Trusted, UC_JAVA_PATH, None, body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    allow(&answer)
}

/// What unitycatalog-rs would read from the answer to `body`.
async fn uc_rs(body: &Value) -> bool {
    let (status, _, answer) = post("/v1/data/uc/authz", Some(UCRS_TOKEN), body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    allow(&answer)
}

/// `result.allow`, checking the answer has exactly UC's shape.
fn allow(answer: &Value) -> bool {
    let allow = answer
        .pointer("/result/allow")
        .and_then(Value::as_bool)
        .unwrap();
    assert_eq!(answer, &json!({ "result": { "allow": allow } }));
    allow
}

fn fixture(name: &str) -> Value {
    let text = match name {
        "uc-java/select-table" => include_str!("../tests/fixtures/opa/uc-java/select-table.json"),
        "uc-java/modify-table" => include_str!("../tests/fixtures/opa/uc-java/modify-table.json"),
        "uc-java/owner-table" => include_str!("../tests/fixtures/opa/uc-java/owner-table.json"),
        "uc-java/use-catalog" => include_str!("../tests/fixtures/opa/uc-java/use-catalog.json"),
        "uc-java/use-schema" => include_str!("../tests/fixtures/opa/uc-java/use-schema.json"),
        "uc-java/create-catalog" => {
            include_str!("../tests/fixtures/opa/uc-java/create-catalog.json")
        }
        "uc-java/read-volume" => include_str!("../tests/fixtures/opa/uc-java/read-volume.json"),
        "uc-java/create-external-table" => {
            include_str!("../tests/fixtures/opa/uc-java/create-external-table.json")
        }
        "uc-java/select-table-bob" => {
            include_str!("../tests/fixtures/opa/uc-java/select-table-bob.json")
        }
        "unitycatalog-rs/select-table" => {
            include_str!("../tests/fixtures/opa/unitycatalog-rs/select-table.json")
        }
        "unitycatalog-rs/owner-table-bob" => {
            include_str!("../tests/fixtures/opa/unitycatalog-rs/owner-table-bob.json")
        }
        "unitycatalog-rs/use-catalog-server-token" => {
            include_str!("../tests/fixtures/opa/unitycatalog-rs/use-catalog-server-token.json")
        }
        "unitycatalog-rs/create-catalog-metastore" => {
            include_str!("../tests/fixtures/opa/unitycatalog-rs/create-catalog-metastore.json")
        }
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn replays_uc_java_inputs() {
    for (name, expected, why) in [
        (
            "uc-java/select-table",
            true,
            "SELECT on the catalog covers its tables",
        ),
        ("uc-java/modify-table", false, "nothing grants MODIFY"),
        (
            "uc-java/owner-table",
            false,
            "owning the catalog doesn't own its tables",
        ),
        (
            "uc-java/use-catalog",
            true,
            "USE_CATALOG granted on the catalog",
        ),
        (
            "uc-java/use-schema",
            true,
            "USE_SCHEMA granted to alice's group",
        ),
        (
            "uc-java/create-catalog",
            true,
            "CREATE_CATALOG on the metastore, by its id",
        ),
        ("uc-java/read-volume", true, "ALL_PRIVILEGES on the volume"),
        (
            "uc-java/create-external-table",
            false,
            "nothing granted on the location",
        ),
        ("uc-java/select-table-bob", false, "bob holds nothing"),
    ] {
        assert_eq!(uc_java(&fixture(name)).await, expected, "{name}: {why}");
    }
}

#[tokio::test]
async fn replays_unitycatalog_rs_inputs() {
    for (name, expected, why) in [
        (
            "unitycatalog-rs/select-table",
            true,
            "SELECT on `main`, the context accepted",
        ),
        (
            "unitycatalog-rs/owner-table-bob",
            true,
            "bob is the owner the client sends",
        ),
        (
            "unitycatalog-rs/use-catalog-server-token",
            true,
            "every context key the server sets, request_time as a datetime",
        ),
        (
            "unitycatalog-rs/create-catalog-metastore",
            false,
            "nothing granted on m-1",
        ),
    ] {
        assert_eq!(uc_rs(&fixture(name)).await, expected, "{name}: {why}");
    }
}

#[tokio::test]
async fn the_denied_fixtures_allow_a_holder() {
    let bob = json!({ "id": "x", "email": "bob@example.com" });
    let mut body = fixture("uc-java/create-external-table");
    body["input"]["principal"] = bob.clone();
    assert!(uc_java(&body).await);
    let mut body = fixture("unitycatalog-rs/create-catalog-metastore");
    body["input"]["principal"] = bob;
    assert!(uc_rs(&body).await);
    // The table fixtures' shape decides too: SELECT allows, MODIFY doesn't.
    assert!(uc_java(&fixture("uc-java/select-table")).await);
}

#[tokio::test]
async fn maps_principals() {
    let mut body = fixture("uc-java/select-table");
    // `external_id` naming a Neon Auth user wins over the email.
    body["input"]["principal"] =
        json!({ "id": "x", "email": "bob@example.com", "external_id": ALICE });
    assert!(uc_java(&body).await);
    // An unverified email resolves to nobody.
    body["input"]["principal"] = json!({ "id": "x", "email": "mallory@example.com" });
    assert!(!uc_java(&body).await);
    // Neither id nor email.
    body["input"]["principal"] = json!({ "id": "x" });
    assert!(!uc_java(&body).await);
    // A banned user is denied, whatever it holds.
    body["input"]["principal"] = json!({ "id": "x", "email": "carol@example.com" });
    assert!(!uc_java(&body).await);
}

#[tokio::test]
async fn context_is_projected_onto_the_schema() {
    let base = fixture("unitycatalog-rs/select-table");
    let with = |context: Value| {
        let mut body = base.clone();
        body["input"]["context"] = context;
        body
    };
    // Undeclared attributes are dropped, not a validation failure.
    assert!(uc_rs(&with(json!({ "source_ip": "10.1.2.3", "trace_id": "abc" }))).await);
    // A header the schema declares reaches the policies.
    assert!(
        uc_rs(&with(
            json!({ "headers": { "x-tenant": "acme", "cookie": "c" } })
        ))
        .await
    );
    assert!(!uc_rs(&with(json!({ "headers": { "x-tenant": "globex" } }))).await);
    // A value of the wrong type is a deny.
    assert!(!uc_rs(&with(json!({ "source_ip": "not an ip" }))).await);
}

#[tokio::test]
async fn the_client_cannot_assert_the_principal_email() {
    let mut body = fixture("unitycatalog-rs/owner-table-bob");
    body["input"]["principal"] = json!({ "id": "u-1", "email": "alice@example.com" });
    body["input"]["context"]["principal_email"] = json!("bob@example.com");
    assert!(!uc_rs(&body).await, "alice isn't the owner");
}

#[tokio::test]
async fn an_input_that_does_not_map_is_a_deny() {
    let mut body = fixture("uc-java/select-table");
    body["input"]["privilege"] = json!("FLY");
    assert!(!uc_java(&body).await);
    let mut body = fixture("uc-java/select-table");
    body["input"]["resource"]["type"] = json!("SHARE");
    assert!(!uc_java(&body).await);
    let mut body = fixture("uc-java/select-table");
    body["input"]["resource"]["parents"][1]["name"] = json!(null);
    assert!(!uc_java(&body).await);
}

#[tokio::test]
async fn authenticates_callers() {
    let body = fixture("uc-java/select-table").to_string();
    // The main listener needs a bearer, also on the OPA route.
    let (status, www, _) = post(UC_JAVA_PATH, None, body.clone()).await;
    assert_eq!(
        (status, www.as_deref()),
        (StatusCode::UNAUTHORIZED, Some("Bearer"))
    );
    let (status, _, _) = post(UC_JAVA_PATH, Some("wrong"), body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The trusted caller has no secret, so nothing reaches it there.
    let (status, _, _) = post(UC_JAVA_PATH, Some(""), body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Any package path works.
    let (status, _, answer) = post("/v1/data/any/package", Some(UCRS_TOKEN), body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(allow(&answer));
}

#[tokio::test]
async fn the_trusted_listener_serves_only_the_opa_route() {
    let decision = json!({
        "principal": { "type": "Lakehouse::User", "id": ALICE },
        "action": { "type": "UnityCatalogOpa::Action", "id": "SELECT" },
        "resource": { "type": "UnityCatalogOpa::Catalog", "id": "analytics" },
    });
    for path in ["/v1/authorize", "/v1/authorize/batch"] {
        let (status, _, _) = post_to(Listener::Trusted, path, None, decision.to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    // A bearer changes nothing there: every request is the trusted caller's.
    let body = fixture("uc-java/select-table").to_string();
    let (status, _, answer) =
        post_to(Listener::Trusted, UC_JAVA_PATH, Some(UCRS_TOKEN), body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(allow(&answer));
}

#[tokio::test]
async fn no_trusted_caller_no_trusted_listener() {
    let set = PolicySet::from_sources(&[
        (
            "builtin:Lakehouse.cedarschema".into(),
            crate::policy::BUILTIN[0].1.into(),
        ),
        (
            "builtin:baseline.cedar".into(),
            crate::policy::BUILTIN[1].1.into(),
        ),
    ])
    .unwrap();
    let callers = Callers::new(
        &[Caller::new("UCRS", NS)],
        None,
        "AUTHZ_TOKEN_",
        Vec::new(),
        |_| Some(UCRS_TOKEN.into()),
    );
    let loader = GrantsEntityLoader::new(
        MemoryGrantStore::new(),
        SubjectTypes::new(USER, SERVICE_ACCOUNT, GROUP),
    );
    let service = embed::service(&set, loader, FakeResolver, callers, Vec::new()).unwrap();
    assert!(service.trusted_router().is_none());
}

#[tokio::test]
async fn refuses_a_bad_body() {
    for body in [
        "{",
        r#"{"principal": {}}"#,
        r#"{"input": {"privilege": "SELECT"}}"#,
    ] {
        let (status, _, answer) = post_to(Listener::Trusted, UC_JAVA_PATH, None, body.into()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            answer["error"]
                .as_str()
                .unwrap()
                .starts_with("invalid request")
        );
    }
}

#[test]
fn the_reference_policies_check() {
    let config = crate::Config {
        policy_dirs: vec![concat!(env!("CARGO_MANIFEST_DIR"), "/policies/unitycatalog-opa").into()],
        ..crate::Config::default()
    };
    let actions = embed::check(&config).unwrap();
    assert_eq!(actions.len(), 26);
    assert!(
        actions
            .iter()
            .all(|a| a.entity_type == "UnityCatalogOpa::Action")
    );
}
