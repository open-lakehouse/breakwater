//! The PDP against a real Postgres: `pdp migrate`'s schema, entities from
//! `authz.*` and a stand-in for Neon Auth's `neon_auth."user"`.
//!
//! `PDP_TEST_DATABASE_URL` points at a server the tests may create databases
//! on; each test gets its own. Unset, those tests skip.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, header};
use http_body_util::BodyExt;
use olai_pdp::embed::{self, Service};
use olai_pdp::{Caller, Config};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "svc-secret";

const ADMIN: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const GRANTEE: &str = "aaaaaaaa-0000-0000-0000-000000000002";
const MEMBER: &str = "aaaaaaaa-0000-0000-0000-000000000003";
const STRANGER: &str = "aaaaaaaa-0000-0000-0000-000000000099";
const ROBOT: &str = "bbbbbbbb-0000-0000-0000-000000000001";
const DISABLED_ROBOT: &str = "bbbbbbbb-0000-0000-0000-000000000002";

const SCHEMA: &str = r#"
namespace Svc {
  entity Table {
    privileges?: Set<String>,
    inherited_privileges?: Set<String>,
  };
  action select appliesTo {
    principal: [Lakehouse::User, Lakehouse::ServiceAccount],
    resource: [Table],
  };
}
"#;

const POLICIES: &str = r#"
@id("admin")
permit (principal is Lakehouse::User, action, resource)
when { principal.neon_role == "admin" };

@id("select")
permit (principal, action == Svc::Action::"select", resource)
when { resource has privileges && resource.privileges.contains("SELECT") };
"#;

const FIXTURES: &str = r#"
CREATE SCHEMA neon_auth;
CREATE TABLE neon_auth."user" (
    id              uuid PRIMARY KEY,
    "emailVerified" bool,
    role            text,
    banned          bool,
    "banExpires"    timestamptz
);
INSERT INTO neon_auth."user" (id, "emailVerified", role, banned) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', true, 'admin', false),
    ('aaaaaaaa-0000-0000-0000-000000000002', true, NULL, false),
    ('aaaaaaaa-0000-0000-0000-000000000003', true, 'user', false);
INSERT INTO authz.service_accounts (id, name, disabled_at) VALUES
    ('bbbbbbbb-0000-0000-0000-000000000001', 'robot', NULL),
    ('bbbbbbbb-0000-0000-0000-000000000002', 'disabled-robot', now());
INSERT INTO authz.groups (id, name) VALUES
    ('cccccccc-0000-0000-0000-000000000001', 'analysts');
INSERT INTO authz.memberships (group_id, principal_type, principal_id) VALUES
    ('cccccccc-0000-0000-0000-000000000001', 'user', 'aaaaaaaa-0000-0000-0000-000000000003');
INSERT INTO authz.grants (subject_type, subject_id, privilege, object_type, object_id) VALUES
    ('user', 'aaaaaaaa-0000-0000-0000-000000000002', 'SELECT', 'Svc::Table', 't'),
    ('group', 'cccccccc-0000-0000-0000-000000000001', 'SELECT', 'Svc::Table', 't'),
    ('service_account', 'bbbbbbbb-0000-0000-0000-000000000001', 'SELECT', 'Svc::Table', 't'),
    ('service_account', 'bbbbbbbb-0000-0000-0000-000000000002', 'SELECT', 'Svc::Table', 't');
"#;

/// A fresh database on the test server, migrated and seeded.
async fn fresh_db() -> Option<(String, PgPool)> {
    let Ok(base) = std::env::var("PDP_TEST_DATABASE_URL") else {
        eprintln!("PDP_TEST_DATABASE_URL is not set; skipping");
        return None;
    };
    let server = PgPoolOptions::new().connect(&base).await.unwrap();
    let name = format!("pdp_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&server)
        .await
        .unwrap();
    server.close().await;
    let url = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    embed::migrate(&url).await.unwrap();
    embed::migrate(&url)
        .await
        .expect("migrating again is a no-op");
    let pool = PgPoolOptions::new().connect(&url).await.unwrap();
    sqlx::raw_sql(FIXTURES).execute(&pool).await.unwrap();
    Some((url, pool))
}

/// A directory with the `Svc` schema and policies, removed on drop.
struct PolicyDir(PathBuf);

impl PolicyDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("olai-pdp-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("svc.cedarschema"), SCHEMA).unwrap();
        std::fs::write(dir.join("svc.cedar"), POLICIES).unwrap();
        Self(dir)
    }
}

impl Drop for PolicyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start(url: &str, dir: &PolicyDir, neon_auth: bool) -> Service {
    let config = Config {
        database_url: Some(url.into()),
        policy_dirs: vec![dir.0.clone()],
        callers: vec![Caller::new("SVC", "Svc")],
        entity_ttl: Duration::ZERO,
        neon_auth,
        ..Config::default()
    };
    embed::start_with_secrets(&config, Vec::new(), |key| {
        (key == "AUTHZ_TOKEN_SVC").then(|| TOKEN.to_string())
    })
    .await
    .unwrap()
}

async fn decide(service: &Service, principal_type: &str, principal: &str) -> Value {
    let body = json!({
        "principal": { "type": principal_type, "id": principal },
        "action": { "type": "Svc::Action", "id": "select" },
        "resource": { "type": "Svc::Table", "id": "t" },
    });
    let request = Request::post("/v1/authorize")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = service.router().oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn user(service: &Service, id: &str) -> Value {
    decide(service, "Lakehouse::User", id).await
}

#[tokio::test]
async fn decides_over_the_databases_entities() {
    let Some((url, pool)) = fresh_db().await else {
        return;
    };
    let dir = PolicyDir::new();
    let service = start(&url, &dir, true).await;

    let admin = user(&service, ADMIN).await;
    assert_eq!(admin["decision"], "allow", "{admin}");
    assert_eq!(admin["policies"], json!(["admin"]));
    for id in [GRANTEE, MEMBER] {
        let body = user(&service, id).await;
        assert_eq!(body["decision"], "allow", "{id}: {body}");
        assert_eq!(body["policies"], json!(["select"]));
    }
    let stranger = user(&service, STRANGER).await;
    assert_eq!(stranger["decision"], "deny");
    assert!(
        stranger["errors"].to_string().contains("no Neon Auth user"),
        "{stranger}"
    );

    let robot = decide(&service, "Lakehouse::ServiceAccount", ROBOT).await;
    assert_eq!(robot["decision"], "allow", "{robot}");
    let disabled = decide(&service, "Lakehouse::ServiceAccount", DISABLED_ROBOT).await;
    assert_eq!(disabled["decision"], "deny");
    assert_eq!(disabled["policies"], json!(["disabled"]));

    // A ban counts from the next request: the principal is never cached.
    sqlx::query(r#"UPDATE neon_auth."user" SET banned = true WHERE id = $1::uuid"#)
        .bind(ADMIN)
        .execute(&pool)
        .await
        .unwrap();
    let banned = user(&service, ADMIN).await;
    assert_eq!(banned["decision"], "deny");
    assert_eq!(banned["policies"], json!(["banned"]));
    // An expired ban doesn't.
    sqlx::query(
        r#"UPDATE neon_auth."user" SET "banExpires" = now() - interval '1 minute' WHERE id = $1::uuid"#,
    )
    .bind(ADMIN)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(user(&service, ADMIN).await["decision"], "allow");
    pool.close().await;
}

#[tokio::test]
async fn without_neon_auth_a_user_is_denied() {
    let Some((url, pool)) = fresh_db().await else {
        return;
    };
    pool.close().await;
    let dir = PolicyDir::new();
    let service = start(&url, &dir, false).await;
    let admin = user(&service, ADMIN).await;
    assert_eq!(admin["decision"], "deny");
    assert!(
        admin["errors"].to_string().contains("no user source"),
        "{admin}"
    );
    let robot = decide(&service, "Lakehouse::ServiceAccount", ROBOT).await;
    assert_eq!(robot["decision"], "allow", "{robot}");
}

/// Needs no server: nothing listens on the port.
#[tokio::test]
async fn an_unreachable_database_is_a_quick_deny() {
    let dir = PolicyDir::new();
    let service = start("postgres://127.0.0.1:1/pdp", &dir, true).await;
    let started = Instant::now();
    let body = user(&service, ADMIN).await;
    assert_eq!(body["decision"], "deny");
    assert!(
        body["errors"].to_string().contains("loading entities"),
        "{body}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}
