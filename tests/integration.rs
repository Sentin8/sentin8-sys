// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Sys tests — TEST-SYS-1/2/3 (per `sentin8-testing-strategy.md`).

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use sentin8::auth::client::{Client as AuthClient, ClientOptions};
use sentin8_sys_server::handlers::AppState;
use sentin8_sys_server::server::routes;
use tower::ServiceExt;
use uuid::Uuid;

// ── Local JWT issuer (mock discovery + JWKS) ────────────────────────────

struct TestIssuer {
    base_url: String,
    signing_key: jsonwebtoken::EncodingKey,
    kid: String,
}

impl TestIssuer {
    async fn start() -> Self {
        use base64::Engine;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let mut rng = rand::thread_rng();
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let n = pub_key.n().to_bytes_be();
        let e = pub_key.e().to_bytes_be();
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e);
        let kid = "sys-test-key".to_string();
        let pem = priv_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pem");
        let signing_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("key");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();

        let discovery = serde_json::json!({
            "issuer": format!("http://{addr}"),
            "jwks_uri": format!("http://{addr}/.well-known/jwks.json"),
            "authorization_endpoint": format!("http://{addr}/authorize"),
            "token_endpoint": format!("http://{addr}/token"),
            "response_types_supported": ["code"],
        });
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "alg": "RS256",
                "use": "sig",
                "n": n_b64,
                "e": e_b64,
            }]
        });

        // /oauth/userinfo — the live-identity endpoint the policy engine's
        // RoleResolver calls (mirrors production Sentin8:Auth). Echoes the
        // token's own `scope` claim as the effective scope set.
        let app = axum::Router::new()
            .route(
                "/oauth/userinfo",
                axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    let scopes = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.strip_prefix("Bearer "))
                        .and_then(|t| {
                            use base64::Engine as _;
                            let seg = t.split('.').nth(1)?;
                            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(seg)
                                .ok()?;
                            let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                            v.get("scope").and_then(|s| s.as_str()).map(str::to_string)
                        })
                        .unwrap_or_default();
                    let list: Vec<String> = scopes.split_whitespace().map(str::to_string).collect();
                    axum::Json(serde_json::json!({
                        "sub": "test-subject",
                        "roles": [],
                        "groups": [],
                        "scopes": list,
                    }))
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || {
                    let d = discovery.clone();
                    async move { axum::Json(d) }
                }),
            )
            .route(
                "/.well-known/jwks.json",
                axum::routing::get(move || {
                    let j = jwks.clone();
                    async move { axum::Json(j) }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            base_url: format!("http://{addr}"),
            signing_key,
            kid,
        }
    }

    fn token(&self, sub: &str, env_id: &str, scope: &str, ttl_secs: i64) -> String {
        self.token_with_email(sub, env_id, scope, ttl_secs, None)
    }

    fn token_with_email(
        &self,
        sub: &str,
        env_id: &str,
        scope: &str,
        ttl_secs: i64,
        email: Option<&str>,
    ) -> String {
        use jsonwebtoken::Algorithm;
        let now = chrono::Utc::now().timestamp();
        let mut claims = serde_json::json!({
            "sub": sub,
            "iss": self.base_url,
            "aud": "sentin8",
            "jti": uuid::Uuid::new_v4().to_string(),
            "iat": now,
            "exp": now + ttl_secs,
            "token_tp": "access",
            "scope": scope,
            "env_id": env_id,
        });
        if let Some(email) = email {
            claims["email"] = serde_json::json!(email);
        }
        let header = jsonwebtoken::Header {
            alg: Algorithm::RS256,
            kid: Some(self.kid.clone()),
            ..Default::default()
        };
        jsonwebtoken::encode(&header, &claims, &self.signing_key).expect("sign jwt")
    }
}

fn install_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
    });
}

// ── Harness ─────────────────────────────────────────────────────────────

const ENV_A: &str = "11111111-1111-1111-1111-111111111111";

async fn spawn_app() -> Option<(Router, TestIssuer)> {
    install_provider();
    let issuer = TestIssuer::start().await;
    let auth_client = AuthClient::new(ClientOptions {
        base_url: issuer.base_url.clone(),
        ..Default::default()
    });

    // The service's own NOBYPASSRLS role — REQUIRED for schema resolution
    // under DBX: the sys role's search_path (`sys, auth, public`) resolves
    // unqualified `outbox` to sys.outbox. The superuser DSN searches auth
    // FIRST, so handler outbox writes would land in auth.outbox and the
    // RLS assertions would see superuser-bypassed rows. `SENTIN8_SYS_DB_DSN`
    // wins; DATABASE_URL (superuser, e.g. for sqlx macro fixtures) is only
    // used for the SEEDING pool (spawn_pool), never for the app.
    let database_url = std::env::var("SENTIN8_SYS_DB_DSN")
        .unwrap_or_else(|_| "postgres://sentin8_sys_service@localhost:5432/sentin8".to_string());
    let pool = match sqlx::PgPool::connect(&database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping DB-backed sys handler tests — PostgreSQL unreachable: {e}");
            return None;
        }
    };

    let config = sentin8_sys_server::config::SysConfig {
        port: 0,
        auth_client,
    };
    // Live-identity resolution points at the test issuer (its userinfo
    // endpoint echoes the token's scope claim — mirrors production Auth).
    sentin8::shield::runtime::init_shared_deps(&issuer.base_url, pool.clone());
    let state = AppState {
        config: Arc::new(config),
        pool: pool.clone(),
        // Enforced scope-mirror seeded for the SYSTEM env — mirrors
        // production (enroll seeds the enforced set; the fail-closed
        // empty-env deny would otherwise reject every request). These tests
        // exercise sys domain flows, not the policy surface.
        policy: seeded_sys_engine(),
        workload_registry: sentin8::auth::workload_registry::WorkloadMap::boot_load_empty(
            "sentin8:sys",
        ),
        admin: sentin8::shield::admin::SharedAdminState::test("sentin8:sys", pool),
    };
    let app = routes(axum::Router::new()).with_state(state);
    Some((app, issuer))
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

// ── TEST-SYS-2: oneshot handler tests — scope negation ──────────────────

#[tokio::test]
async fn no_scope_rejected_on_all_protected_routes() {
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        ENV_A,
        "ledger:products:read",
        300,
    );
    // Bodies must be schema-valid for the route — otherwise axum's
    // deserializer rejects with 422 BEFORE the scope check runs.
    let bodies: &[(&str, &str, &str)] = &[
        ("POST", "/v1/o", r#"{"slug":"scopetest-org","display_name":"Scope Test"}"#),
        (
            "PUT",
            "/v1/org/00000000-0000-0000-0000-000000000001",
            r#"{"display_name":"x"}"#,
        ),
        (
            "POST",
            "/v1/e",
            r#"{"org_id":"00000000-0000-0000-0000-000000000009","slug":"scopetest","display_name":"Scope Test"}"#,
        ),
        (
            "PUT",
            "/v1/env/00000000-0000-0000-0000-000000000002/services",
            r#"{"service":"ledger","enabled":true}"#,
        ),
        (
            "POST",
            "/v1/env/00000000-0000-0000-0000-000000000002/applications",
            r#"{"name":"app","slug":"app","app_type":"oauth_client"}"#,
        ),
        (
            "POST",
            "/v1/env/00000000-0000-0000-0000-000000000002/bindings",
            r#"{"application_id":"00000000-0000-0000-0000-000000000008","name":"b","slug":"b","app_type":"oauth_client"}"#,
        ),
        (
            "DELETE",
            "/v1/org/00000000-0000-0000-0000-000000000001/memberships?user_id=00000000-0000-0000-0000-000000000003",
            "",
        ),
        (
            "POST",
            "/v1/org/00000000-0000-0000-0000-000000000001/invitations",
            r#"{"email":"scopetest@example.test","role":"member"}"#,
        ),
        ("GET", "/v1/audit", ""),
    ];
    for (method, uri, body) in bodies {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*uri)
                    .header("authorization", format!("Bearer {tok}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let resp_body = body_string(resp).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "route {method} {uri} must be scope-gated (403), got {status}: {resp_body}"
        );
    }
}

#[tokio::test]
async fn tenant_resolution_endpoints_require_token() {
    let Some((app, _issuer)) = spawn_app().await else {
        return;
    };
    for uri in [
        "/v1/app-instance/scopes?hostname=bff.ebank.prod.example",
        "/v1/app-instance/auth-mode?hostname=bff.ebank.prod.example",
        "/v1/env/00000000-0000-0000-0000-000000000002/auth-domain",
        "/v1/env/00000000-0000-0000-0000-000000000002/app-custom-domain",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "resolution endpoint {uri} must reject anonymous callers (401), got {status}"
        );
    }
}

#[tokio::test]
async fn tenant_resolution_endpoints_reject_wrong_scope() {
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        ENV_A,
        "ledger:products:read",
        300,
    );
    for uri in [
        "/v1/app-instance/scopes?hostname=bff.ebank.prod.example",
        "/v1/app-instance/auth-mode?hostname=bff.ebank.prod.example",
        "/v1/env/00000000-0000-0000-0000-000000000002/auth-domain",
        "/v1/env/00000000-0000-0000-0000-000000000002/app-custom-domain",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "resolution endpoint {uri} must require a sys scope (403), got {status}"
        );
    }
}

/// SEC-SYS-7 — the granular `sentin8:sys:instances:read` scope (the BFF delegator's
/// DCR scope) must satisfy the BFF-only tenant-resolution endpoints. Without
/// this, the BFF's instance lookup at `/auth/callback` 403s, sessions are
/// created unbound, and the D2 fail-closed check rejects every request
/// (2026-09-05 e2e incident). All four endpoints return 200 (unknown hosts
/// yield the empty-instance shape, not an error).
#[tokio::test]
async fn tenant_resolution_endpoints_accept_instances_read_scope() {
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token("bff-delegator", ENV_A, "sentin8:sys:instances:read", 300);
    for uri in [
        "/v1/app-instance/scopes?hostname=bff.ebank.prod.example",
        "/v1/app-instance/auth-mode?hostname=bff.ebank.prod.example",
        "/v1/env/00000000-0000-0000-0000-000000000002/auth-domain",
        "/v1/env/00000000-0000-0000-0000-000000000002/app-custom-domain",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        assert_eq!(
            status,
            StatusCode::OK,
            "resolution endpoint {uri} must accept sys:instances:read (200), got {status}"
        );
    }
}

// ── TEST-SYS-1: unit tests — branding merge logic ────────────────────────

mod unit {
    #[test]
    fn branding_merge_env_overrides_org_per_field() {
        let pick =
            |env_v: Option<String>, org_v: Option<String>| -> Option<String> { env_v.or(org_v) };
        assert_eq!(
            pick(Some("env".into()), Some("org".into())),
            Some("env".into())
        );
        assert_eq!(pick(None, Some("org".into())), Some("org".into()));
        assert_eq!(pick(None, None), None);
    }
}

// ── TEST-SYS-3: DB-backed tests (runtime-skip) ──────────────────────────

#[tokio::test]
async fn invitation_acceptance_scopes_to_per_org_group() {
    // Live-DCR gate (see org_access_provisioning test): skip without the
    // platform CA.
    if std::env::var("SENTIN8_TLS_CA_PEM")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        eprintln!("skipping — SENTIN8_TLS_CA_PEM not set (M2M DCR untestable)");
        return;
    }
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let email = format!("{org_id}@invite.test");
    let invited_sub = Uuid::new_v4().to_string();

    let pool = spawn_pool().await;

    // The invited user must exist in users — accepting an invitation
    // adds the user to a per-org group, and group_members carries an
    // FK to users(id). In the real flow the user signs up first.
    sqlx::query(
        r#"INSERT INTO users (id, env_id, email, status)
           VALUES ($1, $2, $3, 'active')"#,
    )
    .bind(Uuid::parse_str(&invited_sub).unwrap())
    .bind(sentin8::config::SYSTEM_ENV_ID)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("seed invited user");

    sqlx::query(
        r#"INSERT INTO organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $3, $4) ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(format!("it-{org_id}"))
    .bind("Invite Test Org")
    .bind(format!("{org_id}.test"))
    .execute(&pool)
    .await
    .expect("seed org");

    // Mirror production: the create-org Flow saga provisions the per-org
    // groups (sentin8:org:{org_id}:owners/admins/viewers — §6.0c id-based
    // names) — accept_invitation adds the user to
    // `sentin8:org:{org_id}:admins`, so the access model must exist first.
    sentin8_sys_server::handlers::provision_org_access_tx(
        &mut pool.acquire().await.expect("prov conn"),
        org_id,
        Uuid::parse_str(&invited_sub).unwrap(),
        sentin8::config::SYSTEM_ENV_ID,
    )
    .await
    .expect("provision org access");

    sqlx::query(
        r#"INSERT INTO invitations (id, org_id, email, role, status, token, expires_at)
           VALUES ($1, $2, $3, 'admin', 'pending', $4, now() + interval '7 days')"#,
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(&email)
    .bind(Uuid::new_v4().to_string())
    .execute(&pool)
    .await
    .expect("seed invitation");

    let invitation_id: Uuid =
        sqlx::query_scalar("SELECT id FROM invitations WHERE org_id = $1 LIMIT 1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("fetch invitation");

    let tok = issuer.token_with_email(
        &invited_sub,
        ENV_A,
        "sentin8:sys:memberships:admin",
        300,
        Some(&email),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/org/{org_id}/invitations/{invitation_id}/accept"
                ))
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let stbody = body_string(resp).await;
    assert_eq!(
        st,
        StatusCode::NO_CONTENT,
        "accept_invitation failed: {st}: {stbody}"
    );

    let in_group: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
             SELECT 1 FROM group_members gm
             JOIN groups g ON g.id = gm.group_id
             WHERE gm.user_id = $1 AND g.name = $2)"#,
    )
    .bind(Uuid::parse_str(&invited_sub).unwrap())
    .bind(format!("sentin8:org:{org_id}:admins"))
    .fetch_one(&pool)
    .await
    .expect("group check");
    assert!(in_group, "user must be in the per-org admins group");

    let _ = sqlx::query("DELETE FROM invitations WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
    cleanup_org_access(&pool, org_id, Some(Uuid::parse_str(&invited_sub).unwrap())).await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
}

/// FIX-SYS-1 — acceptance against an org whose access model was never
/// provisioned must fail with 409 (not silently 204 without a membership).
#[tokio::test]
async fn invitation_acceptance_unprovisioned_org_conflicts() {
    // Live-DCR gate (see org_access_provisioning test): skip without the
    // platform CA.
    if std::env::var("SENTIN8_TLS_CA_PEM")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        eprintln!("skipping — SENTIN8_TLS_CA_PEM not set (M2M DCR untestable)");
        return;
    }
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let email = format!("{org_id}@invite.test");
    let invited_sub = Uuid::new_v4().to_string();

    let pool = spawn_pool().await;

    sqlx::query(
        r#"INSERT INTO users (id, env_id, email, status)
           VALUES ($1, $2, $3, 'active')"#,
    )
    .bind(Uuid::parse_str(&invited_sub).unwrap())
    .bind(sentin8::config::SYSTEM_ENV_ID)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("seed invited user");

    // Seed the org but deliberately SKIP provision_org_access_tx: the
    // per-org group does not exist.
    sqlx::query(
        r#"INSERT INTO organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $3, $4) ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(format!("it-{org_id}"))
    .bind("Unprovisioned Invite Org")
    .bind(format!("{org_id}.test"))
    .execute(&pool)
    .await
    .expect("seed org");

    sqlx::query(
        r#"INSERT INTO invitations (id, org_id, email, role, status, token, expires_at)
           VALUES ($1, $2, $3, 'admin', 'pending', $4, now() + interval '7 days')"#,
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(&email)
    .bind(Uuid::new_v4().to_string())
    .execute(&pool)
    .await
    .expect("seed invitation");
    let invitation_id: Uuid =
        sqlx::query_scalar("SELECT id FROM invitations WHERE org_id = $1 LIMIT 1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("fetch invitation");

    let tok = issuer.token_with_email(
        &invited_sub,
        ENV_A,
        "sentin8:sys:memberships:admin",
        300,
        Some(&email),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/org/{org_id}/invitations/{invitation_id}/accept"
                ))
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let stbody = body_string(resp).await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "unprovisioned org acceptance must 409: {st}: {stbody}"
    );

    // No membership row may exist for the unprovisioned org.
    let in_group: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
             SELECT 1 FROM group_members gm
             JOIN groups g ON g.id = gm.group_id
             WHERE gm.user_id = $1 AND g.name = $2)"#,
    )
    .bind(Uuid::parse_str(&invited_sub).unwrap())
    .bind(format!("sentin8:org:{org_id}:admins"))
    .fetch_one(&pool)
    .await
    .expect("group check");
    assert!(!in_group, "no membership must be granted on 409");

    let _ = sqlx::query("DELETE FROM invitations WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&invited_sub).unwrap())
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn invitation_email_binding_is_enforced() {
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let email = format!("{org_id}@invite.test");

    let pool = spawn_pool().await;

    sqlx::query(
        r#"INSERT INTO organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $3, $4) ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(format!("ie-{org_id}"))
    .bind("Email Binding Org")
    .bind(format!("{org_id}.test"))
    .execute(&pool)
    .await
    .expect("seed org");
    sqlx::query(
        r#"INSERT INTO invitations (id, org_id, email, role, status, token, expires_at)
           VALUES ($1, $2, $3, 'admin', 'pending', $4, now() + interval '7 days')"#,
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(&email)
    .bind(Uuid::new_v4().to_string())
    .execute(&pool)
    .await
    .expect("seed invitation");
    let invitation_id: Uuid =
        sqlx::query_scalar("SELECT id FROM invitations WHERE org_id = $1 LIMIT 1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("fetch invitation");

    let invited_sub = Uuid::new_v4().to_string();

    let tok_no_email = issuer.token(&invited_sub, ENV_A, "sentin8:sys:memberships:admin", 300);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/org/{org_id}/invitations/{invitation_id}/accept"
                ))
                .header("authorization", format!("Bearer {tok_no_email}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let tok_wrong = issuer.token_with_email(
        &invited_sub,
        ENV_A,
        "sentin8:sys:memberships:admin",
        300,
        Some("someone-else@test"),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/org/{org_id}/invitations/{invitation_id}/accept"
                ))
                .header("authorization", format!("Bearer {tok_wrong}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let _ = sqlx::query("DELETE FROM invitations WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn set_service_writes_event_in_same_transaction() {
    let Some((app, issuer)) = spawn_app().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();

    let pool = spawn_pool().await;

    sqlx::query(
        r#"INSERT INTO organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $3, $4) ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(format!("svc-{org_id}"))
    .bind("Service Tx Org")
    .bind(format!("{org_id}.test"))
    .execute(&pool)
    .await
    .expect("seed org");
    sqlx::query(
        r#"INSERT INTO environments (id, org_id, slug, display_name)
           VALUES ($1, $2, 'prod', 'Prod') ON CONFLICT (org_id, slug) DO NOTHING"#,
    )
    .bind(env_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("seed env");

    let admin_tok = issuer.token(
        &format!("admin-{}", uuid::Uuid::new_v4()),
        ENV_A,
        "sentin8:sys:admin",
        300,
    );
    let body = serde_json::json!({ "service": "ledger", "enabled": true });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/env/{env_id}/services"))
                .header("authorization", format!("Bearer {admin_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_body = body_string(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "set_service must succeed: {resp_body}"
    );

    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sys.outbox WHERE event_type = 'sentin8:sys:service:updated' AND payload->>'env_id' = $1",
    )
    .bind(env_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("event count");
    assert!(
        event_count >= 1,
        "sys:service:updated must be in the local outbox"
    );

    let _ = sqlx::query("DELETE FROM sys.services WHERE env_id = $1")
        .bind(env_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM sys.environments WHERE id = $1")
        .bind(env_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM sys.organizations WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn org_access_provisioning_creates_groups_and_nesting() {
    // The provisioning path DCRs via Sentin8:Auth's mTLS M2M channel —
    // runtime-skip when the platform CA is not configured (plain `make test`
    // without the fleet env; CI with the CA runs them).
    if std::env::var("SENTIN8_TLS_CA_PEM")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        eprintln!("skipping — SENTIN8_TLS_CA_PEM not set (M2M DCR untestable)");
        return;
    }
    let Some((_app, _issuer)) = spawn_app().await else {
        return;
    };

    let pool = spawn_pool().await;

    let org_id = Uuid::new_v4();
    let creator = Uuid::new_v4();
    // Seed the creator user first — group_members has an FK to
    // users(id), and provisioning adds the creator to the owners group.
    sqlx::query(
        r#"INSERT INTO users (id, env_id, email, status)
           VALUES ($1, $2, $3, 'active')"#,
    )
    .bind(creator)
    .bind(sentin8::config::SYSTEM_ENV_ID)
    .bind(format!("{creator}@prov-test.local"))
    .execute(&pool)
    .await
    .expect("seed creator user");
    let mut prov_tx = pool.begin().await.expect("prov tx");
    sentin8_sys_server::handlers::provision_org_access_tx(
        &mut prov_tx,
        org_id,
        creator,
        sentin8::config::SYSTEM_ENV_ID,
    )
    .await
    .expect("provision");
    prov_tx.commit().await.expect("prov commit");

    for suffix in ["owners", "admins", "viewers"] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM groups WHERE env_id = $1 AND name = $2)",
        )
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .bind(format!("sentin8:org:{org_id}:{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("group exists check");
        assert!(exists, "group sentin8:org:{org_id}:{suffix} must exist");
    }

    let in_owners: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
             SELECT 1 FROM group_members gm
             JOIN groups g ON g.id = gm.group_id
             WHERE gm.user_id = $1 AND g.name = $2)"#,
    )
    .bind(creator)
    .bind(format!("sentin8:org:{org_id}:owners"))
    .fetch_one(&pool)
    .await
    .expect("creator membership check");
    assert!(in_owners, "creator must be in the owners group");

    cleanup_org_access(&pool, org_id, Some(creator)).await;
}

/// Fixture pool: the platform superuser DSN (DDL/fixture role — service
/// roles are NOBYPASSRLS and would reject seeding without tenant context).
/// FIX-SYS-3 — reverse-order cleanup of the artifacts
/// `provision_org_access_tx` creates for one org (design §12 rule 8):
/// memberships → group-role assignments → groups → role nesting → roles →
/// seeded user. Roles/nesting are SHARED per-env rows (sentin8:org:owner/admin/viewer
/// upserted with ON CONFLICT by every provisioning call) — they are removed
/// only when no other provisioning test can be running, i.e. from the caller's
/// own teardown; the ON CONFLICT upsert makes re-creation deterministic for
/// concurrent workers. Group names embed the org UUID (§6.0c) — cleanup is
/// keyed by the org's own id prefix (no slug patterns).
async fn cleanup_org_access(pool: &sqlx::PgPool, org_id: uuid::Uuid, user_id: Option<uuid::Uuid>) {
    // Shared roles may be referenced by another worker's groups mid-cleanup;
    // delete only this org's group bindings first, then leave the shared
    // roles themselves in place (they are idempotent upserts, recreated on
    // demand — deleting them here would race a parallel provisioning test).
    let _ = sqlx::query(
        "DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE name LIKE $1)",
    )
    .bind(format!("sentin8:org:{org_id}:%"))
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "DELETE FROM group_roles WHERE group_id IN (SELECT id FROM groups WHERE name LIKE $1)",
    )
    .bind(format!("sentin8:org:{org_id}:%"))
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM groups WHERE name LIKE $1")
        .bind(format!("sentin8:org:{org_id}:%"))
        .execute(pool)
        .await;
    if let Some(u) = user_id {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(pool)
            .await;
    }
}

async fn spawn_pool() -> sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::superuser_database_url().to_string());
    sqlx::PgPool::connect(&database_url).await.expect("db pool")
}

/// Seed the enforced scope-mirror set for sentin8:sys under the SYSTEM env
/// (mirrors the enroll path's production seeding). Permits grant each sys
/// action to holders of that same scope, plus the platform-admin breadth
/// (`sentin8:sys:admin`) the sys realm's role nesting provides.
fn seeded_sys_engine() -> std::sync::Arc<sentin8_sys_server::policy::Engine> {
    let engine = sentin8_sys_server::policy::Engine::new("sentin8:sys");
    // The tests evaluate under the SYSTEM env (platform-admin surfaces) AND
    // under ENV_A (tenant surfaces) — seed both (per-env sets, same permits).
    let envs = [
        sentin8::config::SYSTEM_ENV_ID,
        uuid::Uuid::parse_str(ENV_A).expect("static ENV_A"),
    ];
    let _ = &envs;
    let actions = [
        (
            "sentin8:sys:org:admin",
            vec![
                "sentin8:sys:org:admin",
                "sentin8:dash:org:create",
                "sentin8:dash:org:update",
                "sentin8:dash:org:delete",
                "sentin8:dash:org:archive",
            ],
        ),
        (
            "sentin8:sys:env:admin",
            vec![
                "sentin8:sys:env:admin",
                "sentin8:dash:env:create",
                "sentin8:dash:env:update",
                "sentin8:dash:env:delete",
                "sentin8:dash:env:archive",
            ],
        ),
        ("sentin8:sys:app:admin", vec!["sentin8:sys:app:admin"]),
        ("sentin8:sys:audit:read", vec!["sentin8:sys:audit:read"]),
        (
            "sentin8:sys:instances:read",
            vec![
                "sentin8:sys:instances:read",
                "sentin8:sys:admin",
                "sentin8:sys:env:admin",
                "sentin8:sys:org:admin",
            ],
        ),
        (
            "sentin8:sys:memberships:admin",
            vec!["sentin8:sys:memberships:admin", "sentin8:dash:admin"],
        ),
        (
            "sentin8:sys:services:admin",
            vec![
                "sentin8:sys:services:admin",
                "sentin8:sys:admin",
                "sentin8:sys:env:admin",
                "sentin8:sys:org:admin",
            ],
        ),
        (
            "sentin8:sys:read",
            vec![
                "sentin8:sys:admin",
                "sentin8:sys:org:admin",
                "sentin8:sys:env:admin",
                "sentin8:sys:org:view",
                "sentin8:sys:env:view",
                "sentin8:sys:view",
            ],
        ),
    ];
    let mut stmts: Vec<String> = Vec::new();
    for (action, scopes) in actions {
        for s in scopes {
            stmts.push(format!(
                "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"{s}\") }};",
                a = action, s = s
            ));
        }
    }
    for env in [
        sentin8::config::SYSTEM_ENV_ID,
        uuid::Uuid::parse_str(ENV_A).expect("static ENV_A"),
    ] {
        engine
            .upsert(sentin8::shield::PolicySetRecord {
                id: uuid::Uuid::nil(),
                env_id: env,
                service: "sentin8:sys".into(),
                policy_set_name: "scope-mirror".into(),
                description: String::new(),
                policies: stmts.join("\n"),
                schema: None,
                origin: sentin8::shield::PolicyOrigin::Platform,
                mode: sentin8::shield::PolicyMode::Enforced,
                version: 1,
                enabled: true,
            })
            .expect("seed sys scope-mirror set");
    }
    std::sync::Arc::new(engine)
}
