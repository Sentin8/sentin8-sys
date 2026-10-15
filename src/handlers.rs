// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Sys HTTP handlers — org/env/feature/application/binding/membership/audit.
//!
//! Stories.
//!
//! Sys owns the `sentin8_sys_*` tables directly (it is the control plane). Saga
//! orchestration spans Sys's own tables plus best-effort calls to Auth,
//! DB, Ledger, Buck, and TLS. External service calls are made when the
//! corresponding base URL is configured; failures are logged and surfaced in
//! the saga outcome but do not block the local record creation (the local
//! record is the source of truth for Sys-owned state).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{self, AuthContext};
use crate::config::SysConfig;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<SysConfig>,
    /// The pool.
    pub pool: PgPool,
    /// Shield engine ( — ): additional gate after scope.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// The  workload registry map (boot-loaded + TTL-cached):
    /// the authorization record for certificate-only platform-workload
    /// calls (scopes + vertical + enabled, auth DESIGN §4.3f).
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,
    /// Shared Sentin8:Policy admin surface.
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Insert an audit row on an ALREADY-OPEN connection/transaction (same
/// transaction as the domain change — sys design ). Failures are
/// logged at error level with never silently discarded.
///
/// RLS: the audit row's env IS the caller's env (`auth.claims.env_uuid()`),
/// while the surrounding handler transaction often runs under the TARGET
/// env's context (path-parameter `env_id` — the caller may be a platform
/// admin acting on another tenant). The FORCE-RLS insert policy requires
/// `env_id = sentin8_current_env_id()` (or NULL), so the context is set to
/// the audit row's own env immediately before the INSERT. `set_config(…,
/// true)` is transaction-local, so this also RE-SCOPES the caller's
/// remaining statements in the transaction: every `audit_tx` call site is
/// the LAST domain write before the emit block, which re-sets its own
/// context (the system env) anyway — the swap is safe for both.
async fn audit_tx(
    conn: &mut sqlx::PgConnection,
    auth: &AuthContext,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) {
    // DBX : Sys's own orchestration audit writes go to the canonical
    // `sys.audit_events` (service stamped `sentin8:sys`).
    set_rls_context(conn, auth.claims.env_uuid()).await;
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_events
           (env_id, service, actor_user_id, actor_subject_type,
            correlation_id, action, target_resource_type, target_resource_id,
            before_state, after_state)
           VALUES ($1, 'sentin8:sys', $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(auth.claims.env_uuid())
    .bind(&auth.claims.sub)
    .bind(&auth.claims.token_tp)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(before)
    .bind(after)
    .execute(&mut *conn)
    .await
    {
        tracing::error!(error = %e, action, resource_type, resource_id, "sys: failed to write audit event");
        return;
    }
    // Fan-out: `sentin8:sys:audit:recorded` on the local outbox, SAME
    // transaction (sys DESIGN §4 — `audit:recorded` is a family-sys event;
    // Stat's audit-volume consumer aggregates every row, whether it
    // entered through `POST /v1/audit` or an internal `audit_tx` write).
    //
    // ENV CONTRACT: the outbox row carries SYSTEM_ENV_ID — the shell's
    // relay produces with sys's M2M token, which is bound to the system
    // env; a caller-env row makes Bus reject the produce with 403
    // (cross-tenant) and the relay would hot-loop it forever. The target
    // env rides the payload (`env_id`) — payload completeness for Stat's
    // consumer. The nil→system context swap is safe here: this is the
    // LAST write in the transaction and no further statement reads
    // tenant-filtered rows. Best-effort: a failed emission degrades to a
    // missing analytics sample, never blocks the domain change.
    set_rls_context(conn, sentin8::config::SYSTEM_ENV_ID).await;
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row(
        conn,
        sentin8::config::SYSTEM_ENV_ID,
        "sys",
        "sentin8:sys:audit:recorded",
        &serde_json::json!({
            "service": "sentin8:sys",
            "env_id": auth.claims.env_uuid(),
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "actor": auth.claims.sub,
            "severity": "info",
        }),
    )
    .await
    {
        tracing::error!(error = %e, action, resource_type, resource_id, "sys: failed to emit audit:recorded fan-out");
    }
}

/// Insert an audit row on a pool connection (best-effort). Prefer
/// `audit_tx` inside a handler transaction.
async fn audit(
    pool: &PgPool,
    auth: &AuthContext,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) {
    // No connection acquisition needed — the transaction below comes from
    // the pool directly (the acquire+drop pattern wasted a connection slot).
    // Same-connection tenant context in an EXPLICIT transaction :
    // `audit_tx` writes to the FORCE-RLS'd `sys.audit_events` whose INSERT
    // policy requires `sentin8_context_initialized` — set_config(..., true)
    // is TRANSACTION-local, so the context set + INSERT must share one
    // transaction; on a bare autocommit connection the context evaporates
    // between statements ("new row violates row-level security policy",
    // : every audit call after org creation failed).
    // The audit row's env IS the caller's env.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, action, "sys: audit tx begin failed");
            return;
        }
    };
    set_rls_context(&mut tx, auth.claims.env_uuid()).await;
    audit_tx(
        &mut tx,
        auth,
        action,
        resource_type,
        resource_id,
        before,
        after,
    )
    .await;
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, action, "sys: audit tx commit failed");
    }
}

fn not_found() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "not found".into())
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"))
}

/// Resolve `org_id` from `env_id` via `sentin8_sys_environments`.
/// Used by env-scoped handlers that no longer receive `org_id` as a path
/// parameter — `env_id` is globally unique and sufficient to identify the
/// owning organization.
async fn resolve_org_id(pool: &PgPool, env_id: Uuid) -> Result<Uuid, (StatusCode, String)> {
    // Same-connection tenant-context rule (sys design ): the context
    // must be set on the connection that runs the query, and it must be the
    // TARGET env — sys_environments_select admits `id = app.env_id` only.
    // The context is transaction-local (`set_config(..., true)`), so both
    // statements run inside one explicit transaction ( rule 2).
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let org_id = sqlx::query_scalar("SELECT org_id FROM environments WHERE id = $1")
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?
        .ok_or((StatusCode::NOT_FOUND, "environment not found".into()))?;
    tx.commit().await.map_err(err_db)?;
    Ok(org_id)
}

/// Set the RLS tenant context to the system org/env for platform-wide lookups.
/// Used by hostname-based resolution endpoints that query across all tenants.
/// Set tenant context for RLS on a connection. Used before querying
/// sentin8_sys_* tables that have RLS policies.
async fn set_rls_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(conn)
        .await;
}

/// Insert a `inbox` row on an ALREADY-OPEN connection/transaction.
///
/// The inbox-first rule (sys design ) requires the event row to be
/// written in the SAME transaction as the domain change — an event written
/// on a separate autocommit connection after the domain transaction commits
/// is silently lost if the process dies between the two statements. The
/// caller must have set the tenant context on this same connection.
async fn emit_sentin8_sys_event_tx(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row(&mut *conn, env_id, "sys", event_type, &payload)
            .await
    {
        tracing::error!(error = %e, event_type = %event_type, %env_id, "sys: failed to emit inbox event");
    }
}

/// Emit an identity-invalidation event on the `policy` stream (policy design
/// -1). DBX : producers never touch bus.inbox — the row lands in
/// sys's LOCAL outbox (family `policy`); the shell-spawned relay pushes it to
/// Bus `POST /v1/produce`. Best-effort: a failed emission degrades to the
/// 30s resolver TTL (the contract's backstop), never blocks the provisioning
/// transaction.
async fn emit_policy_identity_event_tx(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row(&mut *conn, env_id, "policy", event_type, &payload)
            .await
    {
        tracing::error!(error = %e, event_type = %event_type, %env_id,
            "sys: failed to emit policy identity event (invalidation degrades to 30s TTL)");
    }
}

/// Enqueue a notification on sys's LOCAL `post_outbox` (DBX-POST-3,
/// sys DESIGN §10): the sys-post pusher drains it to Post
/// `POST /v1/send` (M2M, `sentin8:post:write`). Must run on the SAME
/// transaction/connection as the domain change (exactly-once coupling);
/// the row's `env_id` is the ORG's env and `sys.post_outbox`'s RLS policy
/// matches on it — the helper re-sets the tenant context to `env_id` on
/// THIS transaction (transaction-local; the preceding platform-plane
/// outbox emit needs SYSTEM, so the caller's context can't be assumed).
/// Best-effort: a failed enqueue logs and continues (the invitation
/// itself still commits — mail is a best-effort side channel, never a
/// gate).
async fn emit_post_notification_tx(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    recipient_user_id: Option<Uuid>,
    recipient_email: Option<&str>,
    message_type: &str,
    subject: &str,
    body: &str,
    metadata: serde_json::Value,
) {
    set_rls_context(conn, env_id).await;
    if let Err(e) = sqlx::query(
        r#"INSERT INTO post_outbox (env_id, message_type, category, priority,
           recipient_user_id, recipient_email, subject, body, metadata)
           VALUES ($1, $2, 'system', 'normal', $3, $4, $5, $6, $7)"#,
    )
    .bind(env_id)
    .bind(message_type)
    .bind(recipient_user_id)
    .bind(recipient_email)
    .bind(subject)
    .bind(body)
    .bind(&metadata)
    .execute(&mut *conn)
    .await
    {
        tracing::error!(error = %e, message_type = %message_type, "sys: failed to enqueue post notification");
    }
}

// ── Operational (Stories) ───────────────────────────────────

/// `GET /v1/health` — liveness probe.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses((status = 200, description = "Service is healthy", body = serde_json::Value)),
    tag = "sys",
)]
/// Handle health.
pub async fn health(State(_state): State<AppState>) -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({ "status": "ok", "service": "sys", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash() });
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

/// `GET /v1/readiness` — readiness probe.
#[utoipa::path(
    get,
    operation_id = "readiness.get",
    path = "/v1/readiness",
    responses(
        (status = 200, description = "Service is ready", body = serde_json::Value),
        (status = 503, description = "Database unavailable"),
    ),
    tag = "sys",
)]
/// Handle readiness.
pub async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let pg_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    let status = if pg_ok { "ready" } else { "degraded" };
    let code = if pg_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if !pg_ok {
        return Err((code, "database unavailable".into()));
    }
    Ok(Json(serde_json::json!({
        "status": status,
        "checks": { "postgres": "ok" },
    })))
}

/// `GET /v1/verticals/services?orgId={uuid}&envId={uuid}` — discover registered
/// vertical services and their admin_ui entries, filtered by feature enablement
/// for the given org/env.
///
/// Used by Sentin8:Dash at boot to build the dynamic sidebar. Returns an array
/// of vertical descriptors, each containing:
/// - `service` — the service type (e.g. `bank8-ledger`, `bank8-payments`)
/// - `label` — display label (e.g. "Ledger")
/// - `icon` — material icon name
/// - `service_flag` — the service that must be enabled (e.g. "ledger")
/// - `enabled` — whether the feature is enabled for this org/env
/// - `pages` — array of admin_ui page definitions (route, label, ui_endpoint, data_endpoint)
/// See `sentin8-.md` for the Remote UI architecture.
/// `GET /v1/verticals/services` — discover registered vertical services.
#[utoipa::path(
    get,
    path = "/v1/verticals/services",
    params(("org_id" = Option<Uuid>, Query, description = "Filter by org"), ("env_id" = Option<Uuid>, Query, description = "Filter by env")),
    responses(
        (status = 200, description = "Vertical services", body = [VerticalServiceResponse]),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List vertical services.
pub async fn list_vertical_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<VerticalServicesQuery>,
) -> Result<Json<Vec<VerticalServiceResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;

    let org_id = params.org_id;
    let env_id = params.env_id;

    // Validate org membership if org_id is provided. Skip the check for
    // the system org — the vertical services list is UI metadata (not
    // tenant data) and any staff user with sys:*:admin scopes needs to
    // see the sidebar. authorize_org blocks non-platform-admins from
    // accessing the system org, but vertical services is a discovery
    // endpoint, not a tenant-scoped data query.
    if let Some(org_id) = org_id {
        if org_id != sentin8::config::SYSTEM_ORG_ID {
            authorize_org(&a, org_id, &state.pool).await?;
        }
    }

    // Fetch registered vertical services with their admin_ui metadata.
    // The admin_ui JSON was populated by `sentin8-cli vertical enroll`.
    let rows = sqlx::query(
        r#"SELECT service_type, admin_ui FROM vertical_services
           WHERE admin_ui IS NOT NULL AND admin_ui != 'null'::jsonb
           ORDER BY service_type"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;

    // Fetch service states for this org/env (if provided).
    let service_map: std::collections::HashMap<String, bool> =
        if let (Some(org_id), Some(env_id)) = (org_id, env_id) {
            let svc_rows = sqlx::query(
                r#"SELECT service, enabled FROM services
               WHERE org_id = $1 AND env_id = $2"#,
            )
            .bind(org_id)
            .bind(env_id)
            .fetch_all(&state.pool)
            .await
            .map_err(err_db)?;
            svc_rows
                .into_iter()
                .map(|r| (r.get::<String, _>("service"), r.get::<bool, _>("enabled")))
                .collect()
        } else {
            std::collections::HashMap::new()
        };

    let verticals: Vec<VerticalServiceResponse> = rows
        .into_iter()
        .filter_map(|r| {
            let service_type: String = r.get("service_type");
            let admin_ui: serde_json::Value = r.get("admin_ui");

            // admin_ui can be either a single service descriptor (object)
            // or an array of service descriptors. Normalize to a list.
            let services: Vec<&serde_json::Value> = if let Some(arr) = admin_ui.as_array() {
                arr.iter().collect()
            } else if admin_ui.is_object() {
                vec![&admin_ui]
            } else {
                vec![]
            };

            let entries: Vec<VerticalServiceResponse> = services
                .iter()
                .filter_map(|svc| {
                    let service_flag = svc.get("service_flag")?.as_str()?.to_string();

                    // Core services (auth, app) are always enabled regardless
                    // of feature toggle state. Platform engines (func, cron,
                    // flow, stat, log, post, bus) default to enabled when no
                    // explicit feature row exists.
                    let enabled = if matches!(service_flag.as_str(), "auth" | "app") {
                        true
                    } else if matches!(
                        service_flag.as_str(),
                        "func"
                            | "cron"
                            | "flow"
                            | "stat"
                            | "log"
                            | "post"
                            | "bus"
                            | "db"
                            | "storage"
                    ) {
                        service_map.get(&service_flag).copied().unwrap_or(true)
                    } else {
                        service_map.get(&service_flag).copied().unwrap_or(false)
                    };

                    Some(VerticalServiceResponse {
                        service: svc
                            .get("service")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&service_type)
                            .to_string(),
                        label: svc
                            .get("label")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&service_type)
                            .to_string(),
                        icon: svc
                            .get("icon")
                            .and_then(|v| v.as_str())
                            .unwrap_or("extension")
                            .to_string(),
                        service_flag,
                        enabled,
                        pages: svc
                            .get("pages")
                            .cloned()
                            .unwrap_or(serde_json::Value::Array(vec![])),
                    })
                })
                .collect();

            if entries.is_empty() {
                None
            } else {
                Some(entries)
            }
        })
        .flatten()
        .collect();

    Ok(Json(verticals))
}

#[derive(Debug, serde::Deserialize, ToSchema)]
/// The verticalservicesquery type.
pub struct VerticalServicesQuery {
    /// org identifier.
    pub org_id: Option<Uuid>,
    /// env identifier.
    pub env_id: Option<Uuid>,
}

#[derive(Debug, serde::Serialize, ToSchema)]
/// Response payload for verticalservice.
pub struct VerticalServiceResponse {
    /// The service.
    pub service: String,
    /// The label.
    pub label: String,
    /// The icon.
    pub icon: String,
    /// The service flag.
    pub service_flag: String,
    /// The enabled.
    pub enabled: bool,
    /// The pages.
    pub pages: serde_json::Value,
}

/// Platform-only OAuth scope catalog returned by `GET /v1/scopes/catalog`.
///
/// Kept in lock-step with `_kDefaultScopeSuggestions` in
/// `apps/dash/lib/widgets/scope_selector.dart` — the Dart widget falls
/// back to that hardcoded list when the catalog endpoint is unreachable
/// (offline mode, no auth, etc.), so the two lists should be the same
/// set. We sort alphabetically for stable output (and so the autocomplete
/// ordering is predictable in tests).
///
/// Domain-specific scopes (fdx, ledger, payments, etc.) are loaded at
/// runtime from the `sentin8_vertical_error_codes` / vertical registry tables,
/// not hardcoded here.
/// The platform scope catalog constant.
pub const PLATFORM_SCOPE_CATALOG: &[&str] = &[
    // App
    "sentin8:app:installs:read",
    "sentin8:app:installs:write",
    "sentin8:app:listings:read",
    "sentin8:app:listings:write",
    // Auth (identity / access)
    "sentin8:auth:actor:issue",
    "sentin8:auth:admin:read",
    "sentin8:auth:admin:write",
    // Policy-admin surface — one scope pair per platform service (policy
    // design ; naming). Vertical pairs arrive via enroll.
    "sentin8:acme:policy:read",
    "sentin8:acme:policy:write",
    "sentin8:app:policy:read",
    "sentin8:app:policy:write",
    "sentin8:auth:policy:read",
    "sentin8:auth:policy:write",
    "sentin8:bus:policy:read",
    "sentin8:bus:policy:write",
    "sentin8:cron:policy:read",
    "sentin8:cron:policy:write",
    "sentin8:db:policy:read",
    "sentin8:db:policy:write",
    "sentin8:flow:policy:read",
    "sentin8:flow:policy:write",
    "sentin8:func:policy:read",
    "sentin8:func:policy:write",
    "sentin8:post:policy:read",
    "sentin8:post:policy:write",
    "sentin8:stat:policy:read",
    "sentin8:stat:policy:write",
    "sentin8:storage:policy:read",
    "sentin8:storage:policy:write",
    "sentin8:sys:policy:read",
    "sentin8:sys:policy:write",
    // Sys (BFF-only tenant resolution + Flow proxy-back)
    "sentin8:sys:instances:read",
    "sentin8:sys:steps:execute",
    // Storage
    "sentin8:storage:buckets:read",
    "sentin8:storage:buckets:write",
    "sentin8:storage:objects:read",
    "sentin8:storage:objects:write",
    // DB
    "sentin8:db:schemas:read",
    "sentin8:db:schemas:write",
    "sentin8:db:tables:read",
    "sentin8:db:tables:write",
];

/// `GET /v1/scopes/catalog` — returns the platform's well-known OAuth
/// scope catalog as a flat list. Used by Dash's `ScopeSelector`
/// widget to populate its autocomplete suggestions without
/// duplicating the list on the client side.
///
/// Open endpoint (no auth): the catalog is the same for every caller
/// and contains no org/env-specific data. Allowing anonymous access
/// keeps the suggestions available even before sign-in (e.g. on a
/// public marketing page that links to a sign-up form with scope
/// hints).
/// `GET /v1/scopes/catalog` — platform OAuth scope catalog.
#[utoipa::path(
    get,
    path = "/v1/scopes/catalog",
    responses((status = 200, description = "Scope catalog", body = serde_json::Value)),
    tag = "sys",
)]
/// Fetch scope catalog.
pub async fn get_scope_catalog(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut scopes: Vec<String> = PLATFORM_SCOPE_CATALOG
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Load vertical-specific scopes from the registry. Vertical scopes are
    // stored as role names in sentin8_vertical_services (registered by
    // `sentin8-cli vertical enroll`). The scope catalog merges platform
    // + all registered module scopes.
    let domain_scopes: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT scope FROM service_actions
            UNION
           SELECT DISTINCT scope FROM consent_providers"#,
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    scopes.extend(domain_scopes);

    scopes.sort();
    scopes.dedup();
    Json(serde_json::json!({ "scopes": scopes }))
}

// ── Organization API (Stories) ────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createorg.
pub struct CreateOrgRequest {
    /// The slug.
    pub slug: String,
    /// The display name.
    pub display_name: String,
    /// Optional domain for the org (e.g. "ibank.local").
    /// If not provided, defaults to {slug}.o.{sentin8_domain}.
    /// Serialized as `custom_domain` for API compatibility with the frontend.
    #[serde(default, rename = "custom_domain")]
    /// The domain.
    pub domain: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for org.
pub struct OrgResponse {
    /// Identifier.
    pub id: Uuid,
    /// The slug.
    pub slug: String,
    /// The display name.
    pub display_name: String,
    /// The status.
    pub status: String,
    /// Serialized as `custom_domain` for API compatibility with the frontend.
    #[serde(rename = "custom_domain")]
    /// The domain.
    pub domain: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for updateorg.
pub struct UpdateOrgRequest {
    /// The display name.
    pub display_name: Option<String>,
    /// The status.
    pub status: Option<String>,
    /// Optional domain update — triggers domain chaining via TLS.
    /// `None` or empty = no change; `Some(val)` = update.
    /// Serialized as `custom_domain` for API compatibility with the frontend.
    #[serde(default, rename = "custom_domain")]
    /// The domain.
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The listquery type.
pub struct ListQuery {
    #[serde(default)]
    /// The limit.
    pub limit: i64,
    #[serde(default)]
    /// The offset.
    pub offset: i64,
}

impl Default for ListQuery {
    fn default() -> Self {
        Self {
            limit: 50,
            offset: 0,
        }
    }
}

/// `POST /v1/o` — create organization.
#[utoipa::path(
    post,
    operation_id = "org.create",
    path = "/v1/o",
    request_body = CreateOrgRequest,
    responses(
        (status = 200, description = "Organization created", body = OrgResponse),
        (status = 403, description = "Missing sys:org:admin scope"),
        (status = 409, description = "Org slug already exists"),
    ),
    security(("sentin8:sys:org:admin" = [])),
    tag = "sys",
)]
/// Create org.
pub async fn create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:org:admin"),
    )
    .await?;
    if req.slug.trim().is_empty() || req.display_name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "slug and display_name are required".into(),
        ));
    }

    let slug = req.slug.clone();
    let display_name = req.display_name.clone();
    let cfg = sentin8::config::Sentin8Config::from_env();
    // The org domain is required (NOT NULL). If the caller didn't provide one,
    // default to the platform pattern `{slug}.o.{sentin8_domain}`.
    let domain = req
        .domain
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| cfg.org_domain(&req.slug));

    // Create the org record in a transaction with the tenant context set on
    // the same connection (sys design ). The org.created event joins
    // this same transaction (inbox-first).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let org_id = match sqlx::query_as::<_, OrgRow>(
        r#"INSERT INTO organizations (slug, display_name, domain)
               VALUES ($1, $2, $3)
               RETURNING id, slug, display_name, status, domain, created_at"#,
    )
    .bind(&slug)
    .bind(&display_name)
    .bind(&domain)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
                return Err((
                    StatusCode::CONFLICT,
                    format!("org slug already exists: {e}"),
                ));
            }
            return Err(err_db(e));
        }
    };
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // VDC-3 (design/sentin8-vertical-data-plane-contract.md §VDC.4): the
    // org lifecycle envelope is a payload-complete tenant snapshot —
    // consumers (vertical env-init, caches) act without a lookup.
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:org:created",
        serde_json::json!({
            "org_id": org_id.id,
            "org_slug": org_id.slug,
            "org_display_name": org_id.display_name,
            "org_domain": org_id.domain,
        }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(
        &state,
        "org",
        &org_id.domain,
        Some(org_id.id),
        None,
    )
    .await;

    // Resolve the caller's user id BEFORE provisioning — the provisioning
    // path adds the creator to the org's owners GROUP (auth DESIGN §4.3a).
    let user_id = match Uuid::parse_str(&a.claims.sub) {
        Ok(u) => u,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "subject is not a user uuid; cannot assign owner".into(),
            ))
        }
    };

    // Synchronous access-model provisioning (sys DESIGN §2 "Org creation
    // lifecycle"): the record tx committed above; provisioning rides
    // auth's membership API (idempotent ON CONFLICT upserts) directly in
    // the handler. The compensation on failure deletes the just-created
    // record (500) — a caller retry starts clean; nothing half-created
    // survives. No workflow engine on the fundamental path.
    if let Err(e) = provision_org_access(&state.pool, org_id.id, user_id).await {
        tracing::error!(org_id = %org_id.id, error = %e, "sys: create-org provisioning FAILED — compensating (org row deleted)");
        let mut cx = state.pool.begin().await.map_err(err_db)?;
        set_rls_context(&mut cx, sentin8::config::SYSTEM_ENV_ID).await;
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id.id)
            .execute(&mut *cx)
            .await;
        let _ = cx.commit().await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("org provisioning failed: {e} — the org was not created; retry"),
        ));
    }

    audit(
        &state.pool,
        &a,
        "create",
        "organization",
        &org_id.id.to_string(),
        None,
        Some(serde_json::json!({
            "slug": org_id.slug,
            "display_name": org_id.display_name,
        })),
    )
    .await;

    Ok(Json(OrgResponse {
        id: org_id.id,
        slug: org_id.slug,
        display_name: org_id.display_name,
        status: org_id.status,
        domain: org_id.domain,
        created_at: org_id.created_at,
    }))
}

/// `GET /v1/o` — list organizations.
#[utoipa::path(
    get,
    operation_id = "org.list",
    path = "/v1/o",
    params(("limit" = Option<i64>, Query, description = "Page size"), ("offset" = Option<i64>, Query, description = "Page offset")),
    responses((status = 200, description = "List of organizations", body = [OrgResponse])),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List orgs.
pub async fn list_orgs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<OrgResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let limit = if q.limit > 0 { q.limit } else { 50 };
    let offset = q.offset.max(0);

    // (PG18 GUC rule): `sys.organizations` is FORCE-RLS'd on
    // `sentin8_context_initialized` — both branches read inside a
    // transaction whose context covers the catalog view.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, a.claims.env_uuid()).await;
    let rows = if a.is_platform_admin() {
        sqlx::query_as::<_, OrgRow>(
            r#"SELECT id, slug, display_name, status, domain, created_at
               FROM organizations
               WHERE status <> 'archived'
               ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await
    } else {
        let user_id = Uuid::parse_str(&a.claims.sub).unwrap_or(Uuid::nil());
 // : membership rides auth's owner API — the same
 // id-embedded group-name resolution as `bootstrap` ( names).
        let member_org_ids = member_org_ids_via_auth(user_id).await?;
        sqlx::query_as::<_, OrgRow>(
            r#"SELECT DISTINCT o.id, o.slug, o.display_name, o.status, o.domain, o.created_at
               FROM organizations o
               WHERE o.status <> 'archived'
                 AND o.id <> $3  -- exclude System Org (platform-level roles are not org memberships)
                 AND o.id = ANY($4)
               ORDER BY o.created_at DESC LIMIT $2 OFFSET $1"#,
        )
        .bind(limit)
        .bind(sentin8::config::SYSTEM_ORG_ID)
        .bind(offset)
        .bind(member_org_ids)
        .fetch_all(&mut *tx)
        .await
    }
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| OrgResponse {
                id: r.id,
                slug: r.slug,
                display_name: r.display_name,
                status: r.status,
                domain: r.domain,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

/// `GET /v1/org/{id}` — organization detail.
#[utoipa::path(
    get,
    operation_id = "org.get",
    path = "/v1/org/{id}",
    params(("id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 200, description = "Organization", body = OrgResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Fetch org.
pub async fn get_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    // — the organizations table is FORCE-RLS'd; a bare-pool SELECT
    // silently returns 0 rows (: org GET returned 404
    // for an existing org once policy allowed the request). The caller's
    // token env is the tenant context; the policy's SYSTEM-env blanket
    // clause makes every org visible under it.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, a.claims.env_uuid()).await;
    let row = sqlx::query_as::<_, OrgRow>(
        "SELECT id, slug, display_name, status, domain, created_at FROM organizations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    let row = row.ok_or_else(not_found)?;

    authorize_org(&a, row.id, &state.pool).await?;
    Ok(Json(OrgResponse {
        id: row.id,
        slug: row.slug,
        display_name: row.display_name,
        status: row.status,
        domain: row.domain,
        created_at: row.created_at,
    }))
}

/// `PUT /v1/org/{id}` — update organization.
#[utoipa::path(
    put,
    operation_id = "org.update",
    path = "/v1/org/{id}",
    params(("id" = Uuid, Path, description = "Organization ID")),
    request_body = UpdateOrgRequest,
    responses(
        (status = 200, description = "Organization updated", body = OrgResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:org:admin scope"),
    ),
    security(("sentin8:sys:org:admin" = [])),
    tag = "sys",
)]
/// Update org.
pub async fn update_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOrgRequest>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:org:admin"),
    )
    .await?;
    authorize_org(&a, id, &state.pool).await?;

    let before = sqlx::query_as::<_, OrgRow>(
        "SELECT id, slug, display_name, status, domain, created_at FROM organizations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err_db)?
    .ok_or_else(not_found)?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let row = sqlx::query_as::<_, OrgRow>(
        r#"UPDATE organizations
           SET display_name = COALESCE($2, display_name),
               status = COALESCE($3, status),
               domain = COALESCE($4, domain),
               updated_at = now()
           WHERE id = $1
           RETURNING id, slug, display_name, status, domain, created_at"#,
    )
    .bind(id)
    .bind(req.display_name.as_deref())
    .bind(req.status.as_deref())
    .bind(req.domain.as_deref().filter(|d| !d.is_empty()))
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;

    audit_tx(
        &mut tx,
        &a,
        "update",
        "organization",
        &id.to_string(),
        Some(serde_json::json!({ "display_name": before.display_name, "status": before.status })),
        Some(serde_json::json!({ "display_name": row.display_name, "status": row.status })),
    )
    .await;

    // Stories — emit sys.org.updated to system org/env, same tx.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // VDC-3: payload-complete org snapshot (see the org:created emit).
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:org:updated",
        serde_json::json!({
            "org_id": id,
            "org_slug": row.slug,
            "org_display_name": row.display_name,
            "org_domain": row.domain,
            "status": row.status,
        }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "org", "", Some(id), None).await;

    Ok(Json(OrgResponse {
        id: row.id,
        slug: row.slug,
        display_name: row.display_name,
        status: row.status,
        domain: row.domain,
        created_at: row.created_at,
    }))
}

/// `POST /v1/org/{id}/archive` — archive organization.
#[utoipa::path(
    post,
    operation_id = "org.archive",
    path = "/v1/org/{id}/archive",
    params(("id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 204, description = "Organization archived"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:org:admin scope"),
    ),
    security(("sentin8:sys:org:admin" = [])),
    tag = "sys",
)]
/// Archive org.
pub async fn archive_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:org:admin"),
    )
    .await?;
    authorize_org(&a, id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let res = sqlx::query("UPDATE organizations SET status = 'archived', updated_at = now() WHERE id = $1 AND status <> 'archived'")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err(not_found());
    }
    audit_tx(
        &mut tx,
        &a,
        "archive",
        "organization",
        &id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.org.archived, same tx.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:org:archived",
        serde_json::json!({ "org_id": id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "org", "", Some(id), None).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/org/{id}` — cascade-delete org and all related records.
#[utoipa::path(
    delete,
    path = "/v1/org/{id}",
    params(("id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 204, description = "Organization deleted"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:org:admin scope"),
    ),
    security(("sentin8:sys:org:admin" = [])),
    tag = "sys",
)]
/// Delete org.
pub async fn delete_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:org:admin"),
    )
    .await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // Cascade children.
    sqlx::query("DELETE FROM branding WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;

    sqlx::query("DELETE FROM sys_audit_events WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM services WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM app_environment_bindings WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM app_instances WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM invitations WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    // Delete env-scoped audit/outbox/branding for this org's envs.

    sqlx::query("DELETE FROM sys_audit_events WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1)").bind(id).execute(&mut *tx).await.map_err(err_db)?;
    // Delete env-scoped auth roles/groups BEFORE deleting the envs (the
    // env_id subquery needs the env rows to still exist).
    sqlx::query("DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1))").bind(id).execute(&mut *tx).await.map_err(err_db)?;
    sqlx::query("DELETE FROM role_nesting WHERE parent_role_id IN (SELECT id FROM roles WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1)) OR child_role_id IN (SELECT id FROM roles WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1))").bind(id).execute(&mut *tx).await.map_err(err_db)?;
    sqlx::query(
        "DELETE FROM roles WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    sqlx::query("DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1))").bind(id).execute(&mut *tx).await.map_err(err_db)?;
    sqlx::query("DELETE FROM group_roles WHERE group_id IN (SELECT id FROM groups WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1))").bind(id).execute(&mut *tx).await.map_err(err_db)?;
    sqlx::query(
        "DELETE FROM groups WHERE env_id IN (SELECT id FROM environments WHERE org_id = $1)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    // Delete the org's groups at SYSTEM_ENV_ID ( — names embed the
    // tenant UUID, so no user-influenced LIKE pattern is needed):
    // - org-realm groups: `sentin8:org:{org_id}:%` (prefix on the org's
    // own UUID — owners/admins/viewers)
    // - env-realm org-scoped groups: `sentin8:env:{env_id}:%` for every env
    // of this org (previously pattern-matched with the ORG slug, which
    // orphaned rows for envs whose slug differed — defect 3).
    let org_pattern = format!("sentin8:org:{id}:%");
    sqlx::query("DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE env_id = $1 AND name LIKE $2)")
        .bind(sentin8::config::SYSTEM_ENV_ID).bind(&org_pattern).execute(&mut *tx).await.map_err(err_db)?;
    sqlx::query("DELETE FROM group_roles WHERE group_id IN (SELECT id FROM groups WHERE env_id = $1 AND name LIKE $2)")
        .bind(sentin8::config::SYSTEM_ENV_ID).bind(&org_pattern).execute(&mut *tx).await.map_err(err_db)?;
    sqlx::query("DELETE FROM groups WHERE env_id = $1 AND name LIKE $2")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .bind(&org_pattern)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    // Env-realm org-scoped groups (`sentin8:env:{env_id}:admins/viewers` at
    // SYSTEM_ENV_ID) — one exact-pattern sweep per env id.
    let env_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM environments WHERE org_id = $1")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(err_db)?;
    for env_id in &env_ids {
        let env_pattern = format!("sentin8:env:{env_id}:%");
        sqlx::query("DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE env_id = $1 AND name LIKE $2)")
            .bind(sentin8::config::SYSTEM_ENV_ID).bind(&env_pattern).execute(&mut *tx).await.map_err(err_db)?;
        sqlx::query("DELETE FROM group_roles WHERE group_id IN (SELECT id FROM groups WHERE env_id = $1 AND name LIKE $2)")
            .bind(sentin8::config::SYSTEM_ENV_ID).bind(&env_pattern).execute(&mut *tx).await.map_err(err_db)?;
        sqlx::query("DELETE FROM groups WHERE env_id = $1 AND name LIKE $2")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .bind(&env_pattern)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
    }
    sqlx::query("DELETE FROM environments WHERE org_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    let res = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err(not_found());
    }
    audit_tx(
        &mut tx,
        &a,
        "delete",
        "organization",
        &id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.org.deleted, same tx.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:org:deleted",
        serde_json::json!({ "org_id": id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "org", "", Some(id), None).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Environment API (Stories) ───────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createenv.
pub struct CreateEnvRequest {
    /// org identifier.
    pub org_id: Uuid,
    /// The slug.
    pub slug: String,
    /// The display name.
    pub display_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for env.
pub struct EnvResponse {
    /// Identifier.
    pub id: Uuid,
    /// org identifier.
    pub org_id: Uuid,
    /// The slug.
    pub slug: String,
    /// The display name.
    pub display_name: String,
    /// The status.
    pub status: String,
    /// The auth domain.
    pub auth_domain: Option<String>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Service enablement states for this env (service key → enabled).
    /// The services.
    pub services: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for updateenv.
pub struct UpdateEnvRequest {
    /// The display name.
    pub display_name: Option<String>,
    /// The status.
    pub status: Option<String>,
    /// The auth domain.
    pub auth_domain: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The listenvsquery type.
pub struct ListEnvsQuery {
    #[serde(default)]
    /// org identifier.
    pub org_id: Option<Uuid>,
}

/// `POST /v1/e` — create environment.
#[utoipa::path(
    post,
    operation_id = "env.create",
    path = "/v1/e",
    request_body = CreateEnvRequest,
    responses(
        (status = 200, description = "Environment created", body = EnvResponse),
        (status = 403, description = "Missing sys:env:admin scope"),
        (status = 409, description = "Env slug already exists"),
    ),
    security(("sentin8:sys:env:admin" = [])),
    tag = "sys",
)]
/// Create env.
pub async fn create_env(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateEnvRequest>,
) -> Result<Json<EnvResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:env:admin"),
    )
    .await?;
    let org_id = req.org_id;
    authorize_org(&a, org_id, &state.pool).await?;

    // Create the env record in a transaction with the tenant context set on
    // the same connection (sys design ). The env.created event joins
    // this same transaction (inbox-first).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let row = match sqlx::query_as::<_, EnvRow>(
        r#"INSERT INTO environments (org_id, slug, display_name)
           VALUES ($1, $2, $3)
           RETURNING id, org_id, slug, display_name, status, auth_domain, created_at"#,
    )
    .bind(org_id)
    .bind(&req.slug)
    .bind(&req.display_name)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
                return Err((
                    StatusCode::CONFLICT,
                    format!("env slug already exists: {e}"),
                ));
            }
            return Err(err_db(e));
        }
    };
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // VDC-3 (design/sentin8-vertical-data-plane-contract.md §VDC.4): the
    // env lifecycle envelope is a payload-complete tenant snapshot —
    // org + env identity so consumers (fdx provider-profile derivation,
    // caches) act without a lookup.
    let org_snapshot: Option<(String, String, String)> =
        sqlx::query_as(r#"SELECT slug, display_name, domain FROM organizations WHERE id = $1"#)
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
    let (org_slug, org_name, org_domain) = org_snapshot
        .map(|(s, n, d)| (Some(s), Some(n), Some(d)))
        .unwrap_or((None, None, None));
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:env:created",
        serde_json::json!({
            "env_id": row.id,
            "env_slug": row.slug,
            "env_display_name": row.display_name,
            "org_id": row.org_id,
            "org_slug": org_slug,
            "org_display_name": org_name,
            "org_domain": org_domain,
            "auth_domain": row.auth_domain,
            "status": row.status,
        }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "env", "", Some(org_id), Some(row.id))
        .await;

    // Synchronous access-model provisioning (sys DESIGN §2 "Org creation
    // lifecycle" — env family): the record tx committed above; the
    // provisioning helper seeds the env's policy template, provisions the
    // env realm + org-scoped access through auth's API (idempotent), and
    // commits the identity-invalidation event. A provisioning failure
    // compensates by deleting the env record (500) — a caller retry
    // starts clean. No workflow engine on the fundamental path.
    let user_id = Uuid::parse_str(&a.claims.sub).unwrap_or(Uuid::nil());
    if let Err(e) = provision_env_access(&state.pool, org_id, row.id, user_id).await {
        tracing::error!(env_id = %row.id, error = %e, "sys: create-env provisioning FAILED — compensating (env row deleted)");
        let mut cx = state.pool.begin().await.map_err(err_db)?;
        set_rls_context(&mut cx, sentin8::config::SYSTEM_ENV_ID).await;
        let _ = sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(row.id)
            .execute(&mut *cx)
            .await;
        let _ = cx.commit().await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("env provisioning failed: {e} — the env was not created; retry"),
        ));
    }

    audit(
        &state.pool,
        &a,
        "create",
        "environment",
        &row.id.to_string(),
        None,
        Some(serde_json::json!({ "slug": row.slug })),
    )
    .await;

    Ok(Json(EnvResponse {
        id: row.id,
        org_id: row.org_id,
        slug: row.slug,
        display_name: row.display_name,
        status: row.status,
        auth_domain: row.auth_domain,
        created_at: row.created_at,
        services: serde_json::Value::Object(serde_json::Map::new()),
    }))
}

/// `GET /v1/e` — list environments.
#[utoipa::path(
    get,
    operation_id = "env.list",
    path = "/v1/e",
    params(("org_id" = Option<Uuid>, Query, description = "Filter by org")),
    responses((status = 200, description = "List of environments", body = [EnvResponse])),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List envs.
pub async fn list_envs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListEnvsQuery>,
) -> Result<Json<Vec<EnvResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    if let Some(org_id) = params.org_id {
        authorize_org(&a, org_id, &state.pool).await?;

        // (PG18 GUC rule): the env read rides a context transaction.
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_rls_context(&mut tx, a.claims.env_uuid()).await;
        let rows = sqlx::query_as::<_, EnvRow>(
            r#"SELECT id, org_id, slug, display_name, status, auth_domain, created_at
               FROM environments
               WHERE org_id = $1 AND status <> 'archived'
               ORDER BY created_at DESC"#,
        )
        .bind(org_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;

        return Ok(Json(
            rows.into_iter()
                .map(|r| EnvResponse {
                    id: r.id,
                    org_id: r.org_id,
                    slug: r.slug,
                    display_name: r.display_name,
                    status: r.status,
                    auth_domain: r.auth_domain,
                    created_at: r.created_at,
                    services: serde_json::Value::Object(serde_json::Map::new()),
                })
                .collect(),
        ));
    }

    // No org_id filter — list all envs the caller has access to via RBAC.
    // (PG18 GUC rule): both branches read inside a context transaction
    // (sys.environments is FORCE-RLS'd on sentin8_context_initialized).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, a.claims.env_uuid()).await;
    let rows = if a.is_platform_admin() {
        sqlx::query_as::<_, EnvRow>(
            r#"SELECT id, org_id, slug, display_name, status, auth_domain, created_at
               FROM environments
               WHERE status <> 'archived'
               ORDER BY created_at DESC"#,
        )
        .fetch_all(&mut *tx)
        .await
    } else {
        let user_id = Uuid::parse_str(&a.claims.sub).unwrap_or(Uuid::nil());
 // : env visibility follows org membership — the
 // user's member-org ids ride auth's owner API (same resolution as
 // `bootstrap`); their envs are the visible env list. Env-realm
 // role grants ( provisioning) always ride an org the user is
 // a member of (env creation assigns the creator), so the org-set
 // is the faithful visibility boundary.
        let member_org_ids = member_org_ids_via_auth(user_id).await?;
        sqlx::query_as::<_, EnvRow>(
            r#"SELECT DISTINCT e.id, e.org_id, e.slug, e.display_name, e.status, e.auth_domain, e.created_at
               FROM environments e
               WHERE e.status <> 'archived'
                 AND e.org_id = ANY($2)
               ORDER BY e.created_at DESC"#,
        )
        .bind(user_id)
        .bind(member_org_ids)
        .fetch_all(&mut *tx)
        .await
    }
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| EnvResponse {
                id: r.id,
                org_id: r.org_id,
                slug: r.slug,
                display_name: r.display_name,
                status: r.status,
                auth_domain: r.auth_domain,
                created_at: r.created_at,
                services: serde_json::Value::Object(serde_json::Map::new()),
            })
            .collect(),
    ))
}

/// `GET /v1/env/{env_id}` — environment detail.
#[utoipa::path(
    get,
    operation_id = "env.get",
    path = "/v1/env/{env_id}",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "Environment", body = EnvResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Fetch env.
pub async fn get_env(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<EnvResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    // (PG18 GUC rule): the row + services
    // reads ride ONE context transaction keyed on the TARGET env —
    // sys_environments_select admits `id = app.env_id`, and a bare-pool read
    // (context evaporated with resolve_org_id's tx) sees zero rows → 404.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query_as::<_, EnvRow>(
        r#"SELECT id, org_id, slug, display_name, status, auth_domain, created_at
           FROM environments WHERE id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or_else(not_found)?;

    // Fetch service states for this env.
    let service_rows = sqlx::query(
        r#"SELECT service, enabled FROM services
           WHERE org_id = $1 AND env_id = $2"#,
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    let services: serde_json::Map<String, serde_json::Value> = service_rows
        .into_iter()
        .map(|r| {
            let service: String = r.get("service");
            let enabled: bool = r.get("enabled");
            (service, serde_json::Value::Bool(enabled))
        })
        .collect();

    Ok(Json(EnvResponse {
        id: row.id,
        org_id: row.org_id,
        slug: row.slug,
        display_name: row.display_name,
        status: row.status,
        auth_domain: row.auth_domain,
        created_at: row.created_at,
        services: serde_json::Value::Object(services),
    }))
}

/// `PUT /v1/env/{env_id}` — update environment.
#[utoipa::path(
    put,
    operation_id = "env.update",
    path = "/v1/env/{env_id}",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    request_body = UpdateEnvRequest,
    responses(
        (status = 200, description = "Environment updated", body = EnvResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:env:admin scope"),
    ),
    security(("sentin8:sys:env:admin" = [])),
    tag = "sys",
)]
/// Update env.
pub async fn update_env(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
    Json(req): Json<UpdateEnvRequest>,
) -> Result<Json<EnvResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:env:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    // Strip the auth_domain to just the subdomain prefix before storing.
    // The full domain is constructed at read time (get_env_auth_domain).
    let auth_subdomain = req.auth_domain.as_ref().map(|d| {
        d.trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .split('.')
            .next()
            .unwrap_or("")
            .to_string()
    });
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query_as::<_, EnvRow>(
        r#"UPDATE environments
           SET display_name = COALESCE($2, display_name),
               status = COALESCE($3, status),
               auth_domain = COALESCE($4, auth_domain),
               updated_at = now()
           WHERE id = $1
           RETURNING id, org_id, slug, display_name, status, auth_domain, created_at"#,
    )
    .bind(env_id)
    .bind(req.display_name.as_deref())
    .bind(req.status.as_deref())
    .bind(auth_subdomain.as_deref())
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or_else(not_found)?;

    audit_tx(
        &mut tx,
        &a,
        "update",
        "environment",
        &env_id.to_string(),
        None,
        None,
    )
    .await;

    // Stories — emit sys.env.updated, same tx.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // VDC-3: payload-complete env snapshot (see the env:created emit).
    let org_snapshot: Option<(String, String, String)> =
        sqlx::query_as(r#"SELECT slug, display_name, domain FROM organizations WHERE id = $1"#)
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
    let (org_slug, org_name, org_domain) = org_snapshot
        .map(|(s, n, d)| (Some(s), Some(n), Some(d)))
        .unwrap_or((None, None, None));
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:env:updated",
        serde_json::json!({
            "env_id": env_id,
            "env_slug": row.slug,
            "env_display_name": row.display_name,
            "org_id": org_id,
            "org_slug": org_slug,
            "org_display_name": org_name,
            "org_domain": org_domain,
            "auth_domain": row.auth_domain,
            "status": row.status,
        }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "env", "", None, Some(env_id)).await;

    // Fetch service states for this env.
    let service_rows = sqlx::query(
        r#"SELECT service, enabled FROM services
           WHERE org_id = $1 AND env_id = $2"#,
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;
    let services: serde_json::Map<String, serde_json::Value> = service_rows
        .into_iter()
        .map(|r| {
            let service: String = r.get("service");
            let enabled: bool = r.get("enabled");
            (service, serde_json::Value::Bool(enabled))
        })
        .collect();

    Ok(Json(EnvResponse {
        id: row.id,
        org_id: row.org_id,
        slug: row.slug,
        display_name: row.display_name,
        status: row.status,
        auth_domain: row.auth_domain,
        created_at: row.created_at,
        services: serde_json::Value::Object(services),
    }))
}

/// `POST /v1/env/{env_id}/archive` — archive environment.
#[utoipa::path(
    post,
    operation_id = "env.archive",
    path = "/v1/env/{env_id}/archive",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 204, description = "Environment archived"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:env:admin scope"),
    ),
    security(("sentin8:sys:env:admin" = [])),
    tag = "sys",
)]
/// Archive env.
pub async fn archive_env(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:env:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let res = sqlx::query(
        "UPDATE environments SET status = 'archived', updated_at = now() WHERE id = $1 AND status <> 'archived'",
    )
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err(not_found());
    }
    audit_tx(
        &mut tx,
        &a,
        "archive",
        "environment",
        &env_id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.env.archived, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:env:archived",
        serde_json::json!({ "env_id": env_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "env", "", None, Some(env_id)).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/env/{env_id}` — cascade-delete environment.
#[utoipa::path(
    delete,
    path = "/v1/env/{env_id}",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 204, description = "Environment deleted"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:env:admin scope"),
    ),
    security(("sentin8:sys:env:admin" = [])),
    tag = "sys",
)]
/// Delete env.
pub async fn delete_env(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:env:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    sqlx::query("DELETE FROM branding WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;

    sqlx::query("DELETE FROM sys_audit_events WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM services WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM app_environment_bindings WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM app_instances WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    // Delete env-scoped auth roles/groups BEFORE deleting the env (the
    // env_id subquery needs the env row to still exist).
    sqlx::query("DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE env_id = $1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM role_nesting WHERE parent_role_id IN (SELECT id FROM roles WHERE env_id = $1) OR child_role_id IN (SELECT id FROM roles WHERE env_id = $1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query("DELETE FROM roles WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    sqlx::query(
        "DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE env_id = $1)",
    )
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    sqlx::query(
        "DELETE FROM group_roles WHERE group_id IN (SELECT id FROM groups WHERE env_id = $1)",
    )
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    sqlx::query("DELETE FROM groups WHERE env_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    let res = sqlx::query("DELETE FROM environments WHERE id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err(not_found());
    }
    audit_tx(
        &mut tx,
        &a,
        "delete",
        "environment",
        &env_id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.env.deleted, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:env:deleted",
        serde_json::json!({ "env_id": env_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "env", "", None, Some(env_id)).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Service enablement ────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for service.
pub struct ServiceResponse {
    /// Identifier.
    pub id: Uuid,
    /// The service.
    pub service: String,
    /// The enabled.
    pub enabled: bool,
    /// The config.
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for setservice.
pub struct SetServiceRequest {
    /// The service.
    pub service: String,
    /// The enabled.
    pub enabled: bool,
    #[serde(default)]
    /// The config.
    pub config: serde_json::Value,
}

/// `GET /v1/env/{env_id}/services` — list service states.
#[utoipa::path(
    get,
    operation_id = "service.list",
    path = "/v1/env/{env_id}/services",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "Service states", body = [ServiceResponse]),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List services.
pub async fn list_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<Vec<ServiceResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    // (PG18 GUC rule): the services read rides a context transaction —
    // sys.services is FORCE-RLS'd on sentin8_context_initialized; a
    // bare-pool read (context evaporated with resolve_org_id's tx) sees zero
    // rows.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let rows = sqlx::query(
        r#"SELECT id, service, enabled, config FROM services
           WHERE org_id = $1 AND env_id = $2 ORDER BY service"#,
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ServiceResponse {
                id: r.get("id"),
                service: r.get("service"),
                enabled: r.get("enabled"),
                config: r.get("config"),
            })
            .collect(),
    ))
}

/// `PUT /v1/env/{env_id}/services` — enable/disable service.
#[utoipa::path(
    put,
    operation_id = "service.disable",
    path = "/v1/env/{env_id}/services",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    request_body = SetServiceRequest,
    responses(
        (status = 200, description = "Service state updated", body = ServiceResponse),
        (status = 403, description = "Missing sys:services:admin scope"),
    ),
    security(("sentin8:sys:services:admin" = [])),
    tag = "sys",
)]
/// Handle set service.
pub async fn set_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
    Json(req): Json<SetServiceRequest>,
) -> Result<Json<ServiceResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:services:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query(
        r#"INSERT INTO services (org_id, env_id, service, enabled, config)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (org_id, env_id, service)
           DO UPDATE SET enabled = EXCLUDED.enabled, config = EXCLUDED.config, updated_at = now()
           RETURNING id, service, enabled, config"#,
    )
    .bind(org_id)
    .bind(env_id)
    .bind(&req.service)
    .bind(req.enabled)
    .bind(&req.config)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;

    audit_tx(
        &mut tx,
        &a,
        "update",
        "service",
        &req.service,
        None,
        Some(serde_json::json!({ "enabled": req.enabled })),
    )
    .await;

    // Stories — emit sys.service.updated to the system org/env stream,
    // same tx. Downstream services (e.g. bank8-ledger) consume this
    // event via Sentin8:Bus SSE on the system stream family `sys` and run
    // their env-init reaction asynchronously. The payload carries the target
    // env_id so the consumer knows which tenant to seed. sentin8-sys does
    // NOT call the service's env-init endpoint directly — env-init is
    // event-driven. The event row lives in the system env, and the
    // inbox INSERT policy requires row env_id = app.env_id, so re-set
    // the context to the system env for this emit (it is the last write
    // in the transaction).
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:service:updated",
        serde_json::json!({
            "env_id": env_id,
            "service": req.service,
            "enabled": req.enabled,
            "config": req.config,
        }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;

    Ok(Json(ServiceResponse {
        id: row.get("id"),
        service: row.get("service"),
        enabled: row.get("enabled"),
        config: row.get("config"),
    }))
}

// ── Application lifecycle ─────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createapplication.
pub struct CreateApplicationRequest {
    /// The name.
    pub name: String,
    /// The slug.
    pub slug: String,
    #[serde(default = "default_app_type")]
    /// The app type.
    pub app_type: String,
}

fn default_app_type() -> String {
    "oauth_client".into()
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for application.
pub struct ApplicationResponse {
    /// Identifier.
    pub id: Uuid,
    /// The name.
    pub name: String,
    /// The slug.
    pub slug: String,
    #[serde(rename = "type")]
    /// The app type.
    pub app_type: String,
    /// The status.
    pub status: String,
}

/// `POST /v1/env/{env_id}/applications` — create application.
#[utoipa::path(
    post,
    operation_id = "app.create",
    path = "/v1/env/{env_id}/applications",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    request_body = CreateApplicationRequest,
    responses(
        (status = 200, description = "Application created", body = ApplicationResponse),
        (status = 403, description = "Missing sys:app:admin scope"),
        (status = 409, description = "Application slug already exists"),
    ),
    security(("sentin8:sys:app:admin" = [])),
    tag = "sys",
)]
/// Create application.
pub async fn create_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
    Json(req): Json<CreateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:app:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;
    if !matches!(req.app_type.as_str(), "oauth_client" | "api_client" | "m2m") {
        return Err((
            StatusCode::BAD_REQUEST,
            "type must be oauth_client|api_client|m2m".into(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query(
        r#"INSERT INTO app_environment_bindings (org_id, env_id, application_id, name, slug, type)
           VALUES ($1, $2, gen_random_uuid(), $3, $4, $5)
           RETURNING id, application_id, name, slug, type, status"#,
    )
    .bind(org_id)
    .bind(env_id)
    .bind(&req.name)
    .bind(&req.slug)
    .bind(&req.app_type)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
            (
                StatusCode::CONFLICT,
                format!("application slug already exists: {e}"),
            )
        } else {
            err_db(e)
        }
    })?;

    let id: Uuid = row.get("application_id");
    audit_tx(
        &mut tx,
        &a,
        "create",
        "application",
        &id.to_string(),
        None,
        Some(serde_json::json!({ "name": req.name })),
    )
    .await;
    // Stories — emit sys.app.created, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:app:created",
        serde_json::json!({ "env_id": env_id, "application_id": id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "app", "", None, Some(env_id)).await;

    Ok(Json(ApplicationResponse {
        id,
        name: row.get("name"),
        slug: row.get("slug"),
        app_type: row.get("type"),
        status: row.get("status"),
    }))
}

/// `GET /v1/env/{env_id}/applications` — list applications.
#[utoipa::path(
    get,
    operation_id = "app.list",
    path = "/v1/env/{env_id}/applications",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "List of applications", body = [ApplicationResponse]),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List applications.
pub async fn list_applications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<Vec<ApplicationResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let rows = sqlx::query(
        r#"SELECT application_id AS id, name, slug, type, status
           FROM app_environment_bindings
           WHERE org_id = $1 AND env_id = $2 ORDER BY created_at DESC"#,
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ApplicationResponse {
                id: r.get("id"),
                name: r.get("name"),
                slug: r.get("slug"),
                app_type: r.get("type"),
                status: r.get("status"),
            })
            .collect(),
    ))
}

/// `GET /v1/env/{env_id}/applications/{app_id}` — application detail.
#[utoipa::path(
    get,
    operation_id = "app.get",
    path = "/v1/env/{env_id}/applications/{app_id}",
    params(("env_id" = Uuid, Path, description = "Environment ID"), ("app_id" = Uuid, Path, description = "Application ID")),
    responses(
        (status = 200, description = "Application", body = ApplicationResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Fetch application.
pub async fn get_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((env_id, app_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApplicationResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let row = sqlx::query(
        r#"SELECT application_id AS id, name, slug, type, status
           FROM app_environment_bindings
           WHERE env_id = $1 AND application_id = $2"#,
    )
    .bind(env_id)
    .bind(app_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err_db)?
    .ok_or_else(not_found)?;

    Ok(Json(ApplicationResponse {
        id: row.get("id"),
        name: row.get("name"),
        slug: row.get("slug"),
        app_type: row.get("type"),
        status: row.get("status"),
    }))
}

/// `PUT /v1/env/{env_id}/applications/{app_id}` — update application.
#[utoipa::path(
    put,
    operation_id = "app.update",
    path = "/v1/env/{env_id}/applications/{app_id}",
    params(("env_id" = Uuid, Path, description = "Environment ID"), ("app_id" = Uuid, Path, description = "Application ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Application updated", body = ApplicationResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:app:admin scope"),
    ),
    security(("sentin8:sys:app:admin" = [])),
    tag = "sys",
)]
/// Update application.
pub async fn update_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((env_id, app_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ApplicationResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:app:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let name: Option<String> = req.get("name").and_then(|v| v.as_str()).map(String::from);
    let status: Option<String> = req.get("status").and_then(|v| v.as_str()).map(String::from);

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query(
        r#"UPDATE app_environment_bindings
           SET name = COALESCE($3, name),
               status = COALESCE($4, status),
               updated_at = now()
           WHERE env_id = $1 AND application_id = $2
           RETURNING application_id AS id, name, slug, type, status"#,
    )
    .bind(env_id)
    .bind(app_id)
    .bind(name.as_deref())
    .bind(status.as_deref())
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or_else(not_found)?;

    audit_tx(
        &mut tx,
        &a,
        "update",
        "application",
        &app_id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.app.updated, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:app:updated",
        serde_json::json!({ "env_id": env_id, "application_id": app_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "app", "", None, Some(env_id)).await;

    Ok(Json(ApplicationResponse {
        id: row.get("id"),
        name: row.get("name"),
        slug: row.get("slug"),
        app_type: row.get("type"),
        status: row.get("status"),
    }))
}

/// `POST /v1/env/{env_id}/applications/{app_id}/archive` — archive application.
#[utoipa::path(
    post,
    operation_id = "app.archive",
    path = "/v1/env/{env_id}/applications/{app_id}/archive",
    params(("env_id" = Uuid, Path, description = "Environment ID"), ("app_id" = Uuid, Path, description = "Application ID")),
    responses(
        (status = 204, description = "Application archived"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:app:admin scope"),
    ),
    security(("sentin8:sys:app:admin" = [])),
    tag = "sys",
)]
/// Archive application.
pub async fn archive_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((env_id, app_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:app:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let res = sqlx::query(
        "UPDATE app_environment_bindings SET status = 'archived', updated_at = now() WHERE env_id = $1 AND application_id = $2",
    )
    .bind(env_id)
    .bind(app_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err(not_found());
    }
    audit_tx(
        &mut tx,
        &a,
        "archive",
        "application",
        &app_id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.app.archived, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:app:archived",
        serde_json::json!({ "env_id": env_id, "application_id": app_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "app", "", None, Some(env_id)).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── App-environment bindings ──────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createbinding.
pub struct CreateBindingRequest {
    /// application identifier.
    pub application_id: Uuid,
    /// The name.
    pub name: String,
    /// The slug.
    pub slug: String,
    #[serde(default = "default_app_type")]
    /// The app type.
    pub app_type: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for binding.
pub struct BindingResponse {
    /// Identifier.
    pub id: Uuid,
    /// application identifier.
    pub application_id: Uuid,
    /// The name.
    pub name: String,
    /// The slug.
    pub slug: String,
    #[serde(rename = "type")]
    /// The app type.
    pub app_type: String,
    /// The status.
    pub status: String,
}

/// `POST /v1/env/{env_id}/bindings` — create app-environment binding.
#[utoipa::path(
    post,
    operation_id = "binding.create",
    path = "/v1/env/{env_id}/bindings",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    request_body = CreateBindingRequest,
    responses(
        (status = 200, description = "Binding created", body = BindingResponse),
        (status = 403, description = "Missing sys:app:admin scope"),
        (status = 409, description = "Binding slug already exists"),
    ),
    security(("sentin8:sys:app:admin" = [])),
    tag = "sys",
)]
/// Create binding.
pub async fn create_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
    Json(req): Json<CreateBindingRequest>,
) -> Result<Json<BindingResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:app:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query(
        r#"INSERT INTO app_environment_bindings (org_id, env_id, application_id, name, slug, type)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, application_id, name, slug, type, status"#,
    )
    .bind(org_id)
    .bind(env_id)
    .bind(req.application_id)
    .bind(&req.name)
    .bind(&req.slug)
    .bind(&req.app_type)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
            (
                StatusCode::CONFLICT,
                format!("binding slug already exists: {e}"),
            )
        } else {
            err_db(e)
        }
    })?;

    audit_tx(
        &mut tx,
        &a,
        "create",
        "binding",
        &row.get::<Uuid, _>("id").to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.binding.created, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:binding:created",
        serde_json::json!({ "env_id": env_id, "binding_id": row.get::<Uuid, _>("id") }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "app", "", None, Some(env_id)).await;

    Ok(Json(BindingResponse {
        id: row.get("id"),
        application_id: row.get("application_id"),
        name: row.get("name"),
        slug: row.get("slug"),
        app_type: row.get("type"),
        status: row.get("status"),
    }))
}

/// `GET /v1/env/{env_id}/bindings` — list bindings.
#[utoipa::path(
    get,
    operation_id = "binding.list",
    path = "/v1/env/{env_id}/bindings",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "List of bindings", body = [BindingResponse]),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List bindings.
pub async fn list_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<Vec<BindingResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let rows = sqlx::query(
        r#"SELECT id, application_id, name, slug, type, status
           FROM app_environment_bindings
           WHERE org_id = $1 AND env_id = $2 ORDER BY created_at DESC"#,
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BindingResponse {
                id: r.get("id"),
                application_id: r.get("application_id"),
                name: r.get("name"),
                slug: r.get("slug"),
                app_type: r.get("type"),
                status: r.get("status"),
            })
            .collect(),
    ))
}

/// `DELETE /v1/env/{env_id}/bindings/{binding_id}` — remove binding.
#[utoipa::path(
    delete,
    operation_id = "binding.delete",
    path = "/v1/env/{env_id}/bindings/{binding_id}",
    params(("env_id" = Uuid, Path, description = "Environment ID"), ("binding_id" = Uuid, Path, description = "Binding ID")),
    responses(
        (status = 204, description = "Binding deleted"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing sys:app:admin scope"),
    ),
    security(("sentin8:sys:app:admin" = [])),
    tag = "sys",
)]
/// Delete binding.
pub async fn delete_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((env_id, binding_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:app:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let res = sqlx::query("DELETE FROM app_environment_bindings WHERE id = $1 AND env_id = $2")
        .bind(binding_id)
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err(not_found());
    }
    audit_tx(
        &mut tx,
        &a,
        "delete",
        "binding",
        &binding_id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.binding.deleted, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:binding:deleted",
        serde_json::json!({ "env_id": env_id, "binding_id": binding_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "app", "", None, Some(env_id)).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Memberships & invitations ──────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for membership.
pub struct MembershipResponse {
    /// Identifier.
    pub id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// org identifier.
    pub org_id: Uuid,
    /// The role.
    pub role: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for invitation.
pub struct InvitationRequest {
    /// The email.
    pub email: String,
    #[serde(default = "default_role")]
    /// The role.
    pub role: String,
}

fn default_role() -> String {
    "member".into()
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for invitation.
pub struct InvitationResponse {
    /// Identifier.
    pub id: Uuid,
    /// org identifier.
    pub org_id: Uuid,
    /// The email.
    pub email: String,
    /// The role.
    pub role: String,
    /// The status.
    pub status: String,
    /// The token.
    pub token: String,
    /// expires time.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/org/{org_id}/memberships` — list members.
#[utoipa::path(
    get,
    operation_id = "membership.list",
    path = "/v1/org/{org_id}/memberships",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 200, description = "List of memberships", body = [MembershipResponse]),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// List memberships.
pub async fn list_memberships(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<MembershipResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    authorize_org(&a, org_id, &state.pool).await?;

    // Resolve members from RBAC: users with direct roles or group memberships
    // in this org.
    let sys_env_id = sentin8::config::SYSTEM_ENV_ID;
    let rows = sqlx::query(
        r#"SELECT DISTINCT u.id AS user_id, u.email, u.first_name, u.last_name
           FROM users u
           WHERE EXISTS (
               SELECT 1 FROM user_roles ur
               JOIN roles r ON r.id = ur.role_id
               WHERE ur.user_id = u.id AND r.env_id IN (SELECT id FROM environments WHERE org_id = $1)
               UNION
               SELECT 1 FROM group_members gm
               JOIN groups g ON g.id = gm.group_id
               WHERE gm.user_id = u.id AND g.env_id IN (SELECT id FROM environments WHERE org_id = $1)
               UNION
               -- Per-org groups at SYSTEM_ENV_ID ( — names embed the org UUID)
               SELECT 1 FROM group_members gm
               JOIN groups g ON g.id = gm.group_id
               WHERE gm.user_id = u.id AND g.env_id = $2
                 AND g.name LIKE 'sentin8:org:' || $1::text || ':%'
           )
           ORDER BY u.email"#,
    )
    .bind(org_id)
    .bind(sys_env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| MembershipResponse {
                id: r.get("user_id"),
                user_id: r.get("user_id"),
                org_id,
                role: "member".into(), // role details are in RBAC, not a flat table
                created_at: chrono::Utc::now(), // approximate — RBAC doesn't track join time here
            })
            .collect(),
    ))
}

/// `DELETE /v1/org/{org_id}/memberships` — remove member.
#[utoipa::path(
    delete,
    operation_id = "membership.remove",
    path = "/v1/org/{org_id}/memberships",
    params(("org_id" = Uuid, Path, description = "Organization ID"), ("user_id" = String, Query, description = "User ID to remove")),
    responses(
        (status = 204, description = "Membership removed"),
        (status = 400, description = "user_id query param required"),
        (status = 403, description = "Missing sys:memberships:admin scope"),
    ),
    security(("sentin8:sys:memberships:admin" = [])),
    tag = "sys",
)]
/// Remove membership.
pub async fn remove_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Query(params): Query<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:memberships:admin"),
    )
    .await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let user_id: Uuid = params
        .get("user_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "user_id query param required".into(),
        ))?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // Remove all role assignments for this user in envs that belong to the target org.
    let _ = sqlx::query(
        r#"DELETE FROM user_roles
           WHERE user_id = $1
             AND role_id IN (SELECT id FROM roles WHERE env_id IN (SELECT id FROM environments WHERE org_id = $2))"#,
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;

    // Remove all group memberships for this user in envs that belong to the target org.
    let _ = sqlx::query(
        r#"DELETE FROM group_members
           WHERE user_id = $1
             AND group_id IN (SELECT id FROM groups WHERE env_id IN (SELECT id FROM environments WHERE org_id = $2))"#,
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;

    // Also remove per-org group memberships at SYSTEM_ENV_ID ( — names
    // embed the org UUID, prefix matches this org's own id only).
    let _ = sqlx::query(
        r#"DELETE FROM group_members
           WHERE user_id = $1
             AND group_id IN (
               SELECT id FROM groups
               WHERE env_id = $3
                 AND name LIKE 'sentin8:org:' || $2::text || ':%'
             )"#,
    )
    .bind(user_id)
    .bind(org_id)
    .bind(sentin8::config::SYSTEM_ENV_ID)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;

    audit_tx(
        &mut tx,
        &a,
        "delete",
        "membership",
        &user_id.to_string(),
        None,
        None,
    )
    .await;
    // Stories — emit sys.membership.removed, same tx.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:membership:removed",
        serde_json::json!({ "org_id": org_id, "user_id": user_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/org/{org_id}/invitations` — list invitations (: the
/// lifecycle owner's read surface; auth's admin UI proxies here).
#[utoipa::path(
    get,
    operation_id = "invitation.list",
    path = "/v1/org/{org_id}/invitations",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 200, description = "List of invitations", body = [InvitationResponse]),
        (status = 403, description = "Missing sys:memberships:admin scope"),
    ),
    security(("sentin8:sys:memberships:admin" = [])),
    tag = "sys",
)]
/// List invitations.
pub async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<InvitationResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:memberships:admin"),
    )
    .await?;
    authorize_org(&a, org_id, &state.pool).await?;

    // RLS context is transaction-local (set_config(..., true)) — it must
    // be set inside an explicit transaction; on an autocommit connection
    // it evaporates before the query runs.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut conn, sentin8::config::SYSTEM_ENV_ID).await;
    let rows = sqlx::query(
        r#"SELECT id, org_id, email, role, status, token, expires_at
           FROM invitations WHERE org_id = $1
           ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| InvitationResponse {
                id: r.get("id"),
                org_id: r.get("org_id"),
                email: r.get("email"),
                role: r.get("role"),
                status: r.get("status"),
                token: r.get("token"),
                expires_at: r.get("expires_at"),
            })
            .collect(),
    ))
}

/// `POST /v1/invitations/{id}/revoke` — revoke an invitation (:
/// lifecycle owner surface; auth's admin UI proxies here).
#[utoipa::path(
    post,
    operation_id = "invitation.revoke",
    path = "/v1/invitations/{id}/revoke",
    params(("id" = Uuid, Path, description = "Invitation ID")),
    responses(
        (status = 204, description = "Invitation revoked"),
        (status = 403, description = "Missing sys:memberships:admin scope"),
        (status = 404, description = "Invitation not found"),
    ),
    security(("sentin8:sys:memberships:admin" = [])),
    tag = "sys",
)]
/// Revoke invitation.
pub async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:memberships:admin"),
    )
    .await?;

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let res = sqlx::query(
        "UPDATE invitations SET status = 'revoked' WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("invitation {id} not found or not pending"),
        ));
    }
    audit_tx(
        &mut tx,
        &a,
        "revoke",
        "invitation",
        &id.to_string(),
        None,
        None,
    )
    .await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:invitation:revoked",
        serde_json::json!({ "invitation_id": id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/org/{org_id}/invitations` — send invitation.
#[utoipa::path(
    post,
    operation_id = "invitation.send",
    path = "/v1/org/{org_id}/invitations",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = InvitationRequest,
    responses(
        (status = 200, description = "Invitation sent", body = InvitationResponse),
        (status = 403, description = "Missing sys:memberships:admin scope"),
    ),
    security(("sentin8:sys:memberships:admin" = [])),
    tag = "sys",
)]
/// Send invitation.
pub async fn send_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(req): Json<InvitationRequest>,
) -> Result<Json<InvitationResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:memberships:admin"),
    )
    .await?;
    authorize_org(&a, org_id, &state.pool).await?;

    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let row = sqlx::query(
        r#"INSERT INTO invitations (org_id, email, role, token, expires_at)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, org_id, email, role, status, token, expires_at"#,
    )
    .bind(org_id)
    .bind(req.email.to_lowercase())
    .bind(&req.role)
    .bind(&token)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;

    audit_tx(
        &mut tx,
        &a,
        "create",
        "invitation",
        &row.get::<Uuid, _>("id").to_string(),
        None,
        None,
    )
    .await;
    // DBX (SYS-3, sys DESIGN §10): emit sys.invitation.sent + enqueue the
    // post-mail notification row in the SAME domain transaction. The
    // post_outbox row carries the ORG's env under the caller's (already
    // set) context — same-context INSERT passes RLS; the sys-post pusher
    // relays it to Post POST /v1/send afterwards.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:invitation:sent",
        serde_json::json!({ "org_id": org_id, "invitation_id": row.get::<Uuid, _>("id") }),
    )
    .await;
    emit_post_notification_tx(
        &mut tx,
        org_id,
        None,
        Some(row.get::<String, _>("email").as_str()),
        "sentin8:sys:invitation:sent",
        "You're invited to join Sentin8",
        "You have been invited to join an organization on Sentin8. Please check your email for the invitation link.",
        serde_json::json!({"org_id": org_id}),
    )
    .await;
    tx.commit().await.map_err(err_db)?;

    Ok(Json(InvitationResponse {
        id: row.get("id"),
        org_id: row.get("org_id"),
        email: row.get("email"),
        role: row.get("role"),
        status: row.get("status"),
        token: row.get("token"),
        expires_at: row.get("expires_at"),
    }))
}

/// `POST /v1/org/{org_id}/invitations/{invitation_id}/accept` — accept invitation.
#[utoipa::path(
    post,
    operation_id = "invitation.accept",
    path = "/v1/org/{org_id}/invitations/{invitation_id}/accept",
    params(("org_id" = Uuid, Path, description = "Organization ID"), ("invitation_id" = Uuid, Path, description = "Invitation ID")),
    responses(
        (status = 204, description = "Invitation accepted"),
        (status = 404, description = "Invitation not found"),
        (status = 409, description = "Invitation is not pending"),
        (status = 410, description = "Invitation expired"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Handle accept invitation.
pub async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((org_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:memberships:admin"),
    )
    .await?;
    let user_id = Uuid::parse_str(&a.claims.sub)
        .map_err(|_| (StatusCode::BAD_REQUEST, "subject is not a user uuid".into()))?;

    // Same-transaction tenant-context rule (sys design ): the
    // invitation read, org-slug resolution, status update, group assignment,
    // audit row, and event all run on ONE connection under the caller's
    // context. sys_invitations_select is context-initialized only.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, a.claims.env_uuid()).await;

    let row = sqlx::query(
        r#"SELECT email, role, status, expires_at FROM invitations WHERE id = $1 AND org_id = $2"#,
    )
    .bind(invitation_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or_else(not_found)?;

    let status: String = row.get("status");
    if status != "pending" {
        return Err((StatusCode::CONFLICT, format!("invitation is {status}")));
    }
    let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
    if expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "invitation expired".into()));
    }

    // Verify the accepting user's email matches the invitation's email.
    // The email match is the invitation's proof-of-possession — when the
    // token carries no email claim the check cannot pass, so reject.
    let invited_email: String = row.get("email");
    let user_email = a.claims.email.as_deref().unwrap_or("");
    if user_email.is_empty() || user_email.to_lowercase() != invited_email.to_lowercase() {
        return Err((
            StatusCode::FORBIDDEN,
            "invitation email does not match the authenticated user".into(),
        ));
    }

    // sys_organizations_select admits `id = sentin8_current_org_id` — the
    // org-slug lookup is platform-level data resolution, so re-set the
    // context to the system env for this read (same tx, still same-connection).
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // Restore the caller's context for the remaining tenant-scoped writes.
    set_rls_context(&mut tx, a.claims.env_uuid()).await;
    sqlx::query("UPDATE invitations SET status = 'accepted' WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;

    // Add the user to the per-org admins group at SYSTEM_ENV_ID. That group
    // carries the org-scoped sentin8:org:admin role for THIS org only. Never insert
    // into a shared role row at SYSTEM_ENV_ID — those rows are reused across
    // orgs, so a direct assignment would grant visibility into every org.
    // The membership row lives in the system env, so the context must be the
    // system env for this write (RLS env match). The group is created by the
    // create-org Flow saga — acceptance does not create the access model; a
    // missing group fails the write. The group name
    // embeds the org UUID — the handler already holds org_id, so no
    // slug round-trip is needed.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    // : the membership write rides AUTH's provisioning API (the
    // owner of auth.group_members); sys holds no auth.* DML grants.
    let provisioner = crate::auth_provision::AuthProvisioner::connect()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("auth provisioner: {e}"),
            )
        })?;
    let written = provisioner
        .group_member(
            sentin8::config::SYSTEM_ENV_ID,
            &format!("sentin8:org:{org_id}:admins"),
            user_id,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if written == 0 {
        // The INSERT … SELECT matched no group row — acceptance must not
        // report success without granting access.
        return Err((
            StatusCode::CONFLICT,
            "org access model not provisioned".into(),
        ));
    }

    audit_tx(
        &mut tx,
        &a,
        "accept",
        "invitation",
        &invitation_id.to_string(),
        None,
        None,
    )
    .await;
    // DBX (SYS-3, sys DESIGN §10): emit sys.invitation.accepted + enqueue
    // the accepted-notification row in the SAME domain transaction. The
    // post_outbox row carries the ORG's env under the caller's (already
    // set) context — same-context INSERT passes RLS; the sys-post pusher
    // relays it to Post POST /v1/send afterwards.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:invitation:accepted",
        serde_json::json!({ "org_id": org_id, "invitation_id": invitation_id }),
    )
    .await;
    emit_post_notification_tx(
        &mut tx,
        org_id,
        Some(user_id),
        None,
        "sentin8:sys:invitation:accepted",
        "Invitation accepted",
        "Your invitation has been accepted. Welcome to the organization!",
        serde_json::json!({"org_id": org_id, "invitation_id": invitation_id}),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    // Read-your-writes (sys DESIGN §2, backlog RYW-1): acceptance just
    // granted org-scoped membership in the SYSTEM env realm — sweep
    // THIS process's resolver so the member's next request (same
    // process) sees the grant without waiting for the async bus event.
    crate::policy::invalidate_local_identity_caches([sentin8::config::SYSTEM_ENV_ID]);

    Ok(StatusCode::NO_CONTENT)
}

// ── Branding ───────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for branding.
pub struct BrandingResponse {
    /// The logo URL.
    pub logo_url: Option<String>,
    /// The logo icon URL.
    pub logo_icon_url: Option<String>,
    /// The primary color.
    pub primary_color: Option<String>,
    /// The accent color.
    pub accent_color: Option<String>,
    /// The font family.
    pub font_family: Option<String>,
    /// The theme mode.
    pub theme_mode: String,
    /// The custom css.
    pub custom_css: Option<String>,
    /// The sign in text.
    pub sign_in_text: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for setbranding.
pub struct SetBrandingRequest {
    /// The logo URL.
    pub logo_url: Option<String>,
    /// The logo icon URL.
    pub logo_icon_url: Option<String>,
    /// The primary color.
    pub primary_color: Option<String>,
    /// The accent color.
    pub accent_color: Option<String>,
    /// The font family.
    pub font_family: Option<String>,
    /// The theme mode.
    pub theme_mode: Option<String>,
    /// The custom css.
    pub custom_css: Option<String>,
    /// The sign in text.
    pub sign_in_text: Option<String>,
}

fn row_to_branding(row: &sqlx::postgres::PgRow) -> BrandingResponse {
    BrandingResponse {
        logo_url: row.get("logo_url"),
        logo_icon_url: row.get("logo_icon_url"),
        primary_color: row.get("primary_color"),
        accent_color: row.get("accent_color"),
        font_family: row.get("font_family"),
        theme_mode: row.get("theme_mode"),
        custom_css: row.get("custom_css"),
        sign_in_text: row.get("sign_in_text"),
    }
}

/// `GET /v1/org/{org_id}/branding` — get org-level branding.
#[utoipa::path(
    get,
    operation_id = "branding.get",
    path = "/v1/org/{org_id}/branding",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 200, description = "Org branding", body = BrandingResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Fetch org branding.
pub async fn get_org_branding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Result<Json<BrandingResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    authorize_org(&a, org_id, &state.pool).await?;
    let row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
           FROM branding WHERE org_id = $1 AND env_id IS NULL AND scope = 'org'"#,
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err_db)?;
    Ok(Json(row.as_ref().map(row_to_branding).unwrap_or(
        BrandingResponse {
            logo_url: None,
            logo_icon_url: None,
            primary_color: None,
            accent_color: None,
            font_family: None,
            theme_mode: String::new(),
            custom_css: None,
            sign_in_text: None,
        },
    )))
}

/// `PUT /v1/org/{org_id}/branding` — set org-level branding.
#[utoipa::path(
    put,
    operation_id = "branding.set",
    path = "/v1/org/{org_id}/branding",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = SetBrandingRequest,
    responses(
        (status = 200, description = "Org branding updated", body = BrandingResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Handle set org branding.
pub async fn set_org_branding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(req): Json<SetBrandingRequest>,
) -> Result<Json<BrandingResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    // Incident (policy design ): this was gated with the
    // coarse `sentin8:sys:write` action, which NO scope-mirror set permits
    // (not a registered scope, not a mirrored action) — the endpoint denied
    // for every principal. Use the mirrored granular action; the org-admin
    // entitlement rides authorize_org below.
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:org:admin"),
    )
    .await?;
    authorize_org(&a, org_id, &state.pool).await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    let row = sqlx::query(
        r#"INSERT INTO branding (org_id, env_id, scope, logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text)
           VALUES ($1, NULL, 'org', $2, $3, $4, $5, $6, COALESCE($7, ''), $8, $9)
           ON CONFLICT (org_id, env_id, scope)
           DO UPDATE SET logo_url = EXCLUDED.logo_url, logo_icon_url = EXCLUDED.logo_icon_url,
              primary_color = EXCLUDED.primary_color, accent_color = EXCLUDED.accent_color,
              font_family = EXCLUDED.font_family, theme_mode = EXCLUDED.theme_mode,
              custom_css = EXCLUDED.custom_css, sign_in_text = EXCLUDED.sign_in_text, updated_at = now()
           RETURNING logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text"#,
    )
    .bind(org_id)
    .bind(&req.logo_url).bind(&req.logo_icon_url).bind(&req.primary_color).bind(&req.accent_color)
    .bind(&req.font_family).bind(req.theme_mode.as_deref().unwrap_or("")).bind(&req.custom_css).bind(&req.sign_in_text)
    .fetch_one(&mut *tx).await.map_err(err_db)?;
    audit_tx(&mut tx, &a, "update", "branding", "org", None, None).await;
    // Stories — emit sys.branding.org.updated, same tx.
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
    emit_sentin8_sys_event_tx(
        &mut tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:branding:org:updated",
        serde_json::json!({ "org_id": org_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "branding", "", Some(org_id), None).await;
    Ok(Json(row_to_branding(&row)))
}

/// `GET /v1/env/{env_id}/branding` — get env-level branding.
#[utoipa::path(
    get,
    operation_id = "branding.get-env",
    path = "/v1/env/{env_id}/branding",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "Env branding", body = BrandingResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Fetch env branding.
pub async fn get_env_branding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<BrandingResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;
    let row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
           FROM branding WHERE org_id = $1 AND env_id = $2 AND scope = 'env'"#,
    )
    .bind(org_id).bind(env_id)
    .fetch_optional(&state.pool).await.map_err(err_db)?;
    Ok(Json(row.as_ref().map(row_to_branding).unwrap_or(
        BrandingResponse {
            logo_url: None,
            logo_icon_url: None,
            primary_color: None,
            accent_color: None,
            font_family: None,
            theme_mode: String::new(),
            custom_css: None,
            sign_in_text: None,
        },
    )))
}

/// `PUT /v1/env/{env_id}/branding` — set env-level branding.
#[utoipa::path(
    put,
    operation_id = "branding.set-env",
    path = "/v1/env/{env_id}/branding",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    request_body = SetBrandingRequest,
    responses(
        (status = 200, description = "Env branding updated", body = BrandingResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Handle set env branding.
pub async fn set_env_branding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
    Json(req): Json<SetBrandingRequest>,
) -> Result<Json<BrandingResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    // Incident (policy design ): was `sentin8:sys:write` —
    // an action no set mirrors; see the org-branding note above.
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:env:admin"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query(
        r#"INSERT INTO branding (org_id, env_id, scope, logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text)
           VALUES ($1, $2, 'env', $3, $4, $5, $6, $7, COALESCE($8, ''), $9, $10)
           ON CONFLICT (org_id, env_id, scope)
           DO UPDATE SET logo_url = EXCLUDED.logo_url, logo_icon_url = EXCLUDED.logo_icon_url,
              primary_color = EXCLUDED.primary_color, accent_color = EXCLUDED.accent_color,
              font_family = EXCLUDED.font_family, theme_mode = EXCLUDED.theme_mode,
              custom_css = EXCLUDED.custom_css, sign_in_text = EXCLUDED.sign_in_text, updated_at = now()
           RETURNING logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text"#,
    )
    .bind(org_id).bind(env_id)
    .bind(&req.logo_url).bind(&req.logo_icon_url).bind(&req.primary_color).bind(&req.accent_color)
    .bind(&req.font_family).bind(req.theme_mode.as_deref().unwrap_or("")).bind(&req.custom_css).bind(&req.sign_in_text)
    .fetch_one(&mut *tx).await.map_err(err_db)?;
    audit_tx(&mut tx, &a, "update", "branding", "env", None, None).await;
    // Stories — emit sys.branding.env.updated, same tx.
    emit_sentin8_sys_event_tx(
        &mut tx,
        env_id,
        "sentin8:sys:branding:env:updated",
        serde_json::json!({ "env_id": env_id }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    crate::domain_events::publish_domain_changed(&state, "branding", "", None, Some(env_id)).await;
    Ok(Json(row_to_branding(&row)))
}

/// `GET /v1/env/{env_id}/branding/merged` — merged org+env branding.
#[utoipa::path(
    get,
    operation_id = "branding.merged",
    path = "/v1/env/{env_id}/branding/merged",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "Merged branding", body = BrandingResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Fetch merged branding.
pub async fn get_merged_branding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<BrandingResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    authorize_org(&a, org_id, &state.pool).await?;
    let org_row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
           FROM branding WHERE org_id = $1 AND env_id IS NULL AND scope = 'org'"#,
    )
    .bind(org_id).fetch_optional(&state.pool).await.map_err(err_db)?;
    let env_row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
           FROM branding WHERE org_id = $1 AND env_id = $2 AND scope = 'env'"#,
    )
    .bind(org_id).bind(env_id).fetch_optional(&state.pool).await.map_err(err_db)?;

    // Merge: env overrides org per-field.
    let org = org_row.as_ref();
    let env = env_row.as_ref();
    let pick = |env_v: Option<String>, org_v: Option<String>| -> Option<String> { env_v.or(org_v) };
    let get_str = |row: Option<&sqlx::postgres::PgRow>, col: &str| -> Option<String> {
        row.and_then(|r| r.get::<Option<String>, _>(col))
    };
    let get_theme = |row: Option<&sqlx::postgres::PgRow>| -> String {
        row.and_then(|r| r.get::<Option<String>, _>("theme_mode"))
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
    };
    Ok(Json(BrandingResponse {
        logo_url: pick(get_str(env, "logo_url"), get_str(org, "logo_url")),
        logo_icon_url: pick(get_str(env, "logo_icon_url"), get_str(org, "logo_icon_url")),
        primary_color: pick(get_str(env, "primary_color"), get_str(org, "primary_color")),
        accent_color: pick(get_str(env, "accent_color"), get_str(org, "accent_color")),
        font_family: pick(get_str(env, "font_family"), get_str(org, "font_family")),
        theme_mode: if get_theme(env).is_empty() {
            get_theme(org)
        } else {
            get_theme(env)
        },
        custom_css: pick(get_str(env, "custom_css"), get_str(org, "custom_css")),
        sign_in_text: pick(get_str(env, "sign_in_text"), get_str(org, "sign_in_text")),
    }))
}

// ── Bootstrap ──────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for bootstrap.
pub struct BootstrapResponse {
    /// user identifier.
    pub user_id: String,
    /// The memberships.
    pub memberships: Vec<MembershipResponse>,
    /// The default org.
    pub default_org: Option<OrgResponse>,
}

// ── Tenant resolution endpoints ──────────────────────────

/// `GET /v1/env/{env_id}/auth-domain` — returns the env's full auth_domain URL.
#[utoipa::path(
    get,
    path = "/v1/env/{env_id}/auth-domain",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "Auth domain", body = serde_json::Value),
        (status = 404, description = "Environment not found"),
    ),
    tag = "sys",
)]
/// Fetch env auth domain.
pub async fn get_env_auth_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // BFF-only surface — zero-trust (sys design ). Step 5 decides:
    // the enforced scope-mirror permits `sentin8:sys:instances:read` (the
    // BFF delegator's M2M scope) and any broader sys admin scope.
    let _a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:instances:read"),
    )
    .await?;
    // Resolve org_id from env_id to validate the env exists (env_id is
    // globally unique and sufficient — the query below uses only env_id).
    let _org_id = resolve_org_id(&state.pool, env_id).await?;

    // Set RLS context to the requested env — this endpoint resolves the
    // auth domain for a specific org/env, so it needs that tenant's context.
    // Same-connection/transaction rule (sys design , rule 2):
    // `sentin8_set_tenant_context` is transaction-local (`set_config(...,
    // true)`) — on an autocommit connection the context evaporates between
    // statements and RLS hides the row (: the endpoint
    // 200'd with `auth_domain: ""` and every BFF `/auth/login` 502'd).
    // Context + query share ONE explicit transaction.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let row = sqlx::query(
        r#"SELECT e.auth_domain, e.slug AS env_slug, o.domain, o.slug AS org_slug
             FROM environments e
             JOIN organizations o ON o.id = e.org_id
            WHERE e.id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    let _ = tx.rollback().await;

    let auth_domain: String = match row {
        Some(r) => {
            use sqlx::Row;
            let subdomain: String = r.try_get("auth_domain").unwrap_or_default();
            let env_slug: String = r.try_get("env_slug").unwrap_or_default();
            let org_domain: String = r.try_get("domain").unwrap_or_default();
            // Derive the env domain centrally via sentin8::config.
            let cfg = sentin8::config::Sentin8Config::from_env();
            let env_domain = cfg.env_domain(&env_slug, &org_domain);
            if subdomain.is_empty() {
                // No custom auth subdomain set — return the default env-scoped
                // auth domain (`auth.{env_domain}`) so callers (BFF) redirect
                // to the tenant's own auth instance instead of falling back to
                // the platform `auth.{sentin8_domain}`.
                format!("https://{}", cfg.env_auth_domain(&env_domain))
            } else {
                // Custom auth subdomain — construct the URL with it.
                format!("https://{}.{}", subdomain, env_domain)
            }
        }
        None => String::new(),
    };

    Ok(Json(serde_json::json!({ "auth_domain": auth_domain })))
}

/// Query params for `get_instance_scopes`.
#[derive(Debug, Deserialize, ToSchema)]
/// The instancescopesquery type.
pub struct InstanceScopesQuery {
    /// The BFF or frontend hostname (e.g. `bff.www.ifintech.local` or
    /// `www.ifintech.local`). TLS-injected `X-Sentin8-Hostname`.
    /// The hostname.
    pub hostname: String,
}

/// `GET /v1/app-instance/scopes` — resolve an app instance's OAuth scopes.
#[utoipa::path(
    get,
    path = "/v1/app-instance/scopes",
    params(("hostname" = String, Query, description = "BFF or frontend hostname")),
    responses(
        (status = 200, description = "Instance scopes", body = serde_json::Value),
        (status = 400, description = "hostname query param is required"),
    ),
    tag = "sys",
)]
/// Fetch instance scopes.
pub async fn get_instance_scopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InstanceScopesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // BFF-only surface — zero-trust (sys design ). Step 5 decides:
    // the enforced scope-mirror permits `sentin8:sys:instances:read` (the
    // BFF delegator's M2M scope) and any broader sys admin scope.
    let _a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:instances:read"),
    )
    .await?;
    let host = q.hostname.trim().to_lowercase();
    if host.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "hostname query param is required".into(),
        ));
    }
    let stripped = host
        .strip_prefix("bff.")
        .map(|s| s.to_string())
        .unwrap_or_else(|| host.clone());
    // Set system org context — these lookups query across all tenants by
    // hostname. The context is transaction-local, so hold it inside an
    // explicit transaction (autocommit evaporates it before the query).
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut conn, sentin8::config::SYSTEM_ENV_ID).await;
    let row = sqlx::query(
        r#"SELECT i.allowed_scopes, i.allowed_services, i.oauth_client_id
             FROM app_instances i
             JOIN organizations o ON o.id = i.org_id
            WHERE i.status = 'active'
              AND ( LOWER(i.sentin8_bff_hostname) = $1 OR LOWER(i.hostname) = $1
                 OR LOWER(i.subdomain) = $1 OR LOWER(i.subdomain) = $2
                 OR LOWER(i.hostname) = $2
                 OR (i.subdomain <> '' AND LOWER(i.subdomain || '.' || o.domain) = $1)
                 OR (i.subdomain <> '' AND LOWER(i.subdomain || '.' || o.domain) = $2) )
            LIMIT 1"#,
    )
    .bind(&host)
    .bind(&stripped)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    match row {
        Some(r) => Ok(Json(serde_json::json!({
            "allowed_scopes": r.try_get::<Vec<String>, _>("allowed_scopes").unwrap_or_default(),
            "allowed_services": r.try_get::<Vec<String>, _>("allowed_services").unwrap_or_default(),
            "oauth_client_id": r.try_get::<String, _>("oauth_client_id").unwrap_or_default(),
        }))),
        None => {
            tracing::warn!(%host, "sys: get_instance_scopes no instance found");
            Ok(Json(serde_json::json!({
                "allowed_scopes": [],
                "allowed_services": [],
                "oauth_client_id": "",
            })))
        }
    }
}

/// `GET /v1/tenants/{env_id}` — VDC-4 tenant-snapshot API
/// (design/sentin8-vertical-data-plane-contract.md §VDC.5).
///
/// The sanctioned on-demand read for a vertical service to obtain tenant
/// identity (env/org slugs, domains, auth domain) — the data fdx-style
/// consumers need to derive issuer/JWKS/callback hostnames, and the initial
/// snapshot for a vertical that boots after lifecycle events were emitted.
///
/// Authorization (three gates, all fail-closed):
/// 1. Bearer verify + M2M-only (`token_tp == "m2m"`) — user/delegated
///    tokens use the user-surface org/env APIs instead.
/// 2. Shield gate on `sentin8:sys:tenants:read` (grantable to workloads
///    only via `m2m_grants` — the scope lives in
///    `PLATFORM_SCOPE_VOCABULARY`, never in user role seeds).
/// 3. **Scoped discovery**: the caller's service identity is derived from
///    the verified `client_id` → `sys.vertical_services` registry mapping;
///    the response answers ONLY for envs where the caller's own service is
///    enabled (404 otherwise). A vertical can never enumerate tenants that
///    have not turned it on.
///
/// DBX: the caller never touches `sys.*` tables — this is the owner API.
#[utoipa::path(
    get,
    operation_id = "tenants.snapshot",
    path = "/v1/tenants/{env_id}",
    params(("env_id" = Uuid, Path, description = "Target environment id")),
    responses(
        (status = 200, description = "Tenant snapshot + the caller's own service enablement", body = serde_json::Value),
        (status = 401, description = "Missing/invalid token"),
        (status = 403, description = "Missing tenants:read scope or non-M2M token"),
        (status = 404, description = "Env unknown or the caller's service is not enabled there (scoped discovery)"),
    ),
    security(("sentin8:sys:tenants:read" = [])),
    tag = "sys",
)]
/// Handle get tenant snapshot.
pub async fn get_tenant_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:tenants:read"),
    )
    .await?;
    if a.claims.token_tp != "m2m" {
        return Err((
            StatusCode::FORBIDDEN,
            "tenant snapshot is an M2M-only surface (VDC-4)".to_string(),
        ));
    }

    // One transaction: SYSTEM context + every lookup (the caller's own
    // enablement row and the env/org snapshot). The context is
    // transaction-local (`set_config(…, true)`), so ALL queries ride this
    // connection — an autocommit lookup before the tx would see zero rows
    // under FORCE RLS (sys.environments is tenant-gated).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;

    // Scoped discovery (VDC-4): the caller's service identity comes from the
    // verified M2M token's `service_type` claim — stamped by Auth from the
    // enroll row (workload names are inconsistent, so the registry is the
    // source of truth). Sys NEVER reads auth tables for this (sys holds no
    // auth-schema grants by rule; the former oauth_clients join 500'd).
    let caller_service = a
        .claims
        .service_type
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "caller token carries no service_type claim (VDC-4 scoped discovery)".to_string(),
            )
        })?;

    // Scoped discovery gate: only envs where the caller's own service is
    // enabled answer; everything else is an indistinguishable 404 (no
    // tenant-existence oracle for foreign verticals). The services table
    // stores the SHORT leaf name (`ledger`, `fdx`) — strip the caller's
    // colon identity (`bank8:ledger` → `ledger`); a full-identity match
    // never hits and every snapshot 404s.
    // The caller's OWN token env answers unconditionally: a service may
    // always read its own env's snapshot (the vertical org-membership
    // checks resolve BOTH the caller's and the requested env's org —
    // staff-auth envs carry no service-enablement rows by design, and a
    // 404 on the caller's own env would fail-close every legitimate
    // org check).
    // The caller's OWN token env answers unconditionally: a service may
    // always read its own env's snapshot (the vertical org-membership
    // checks resolve BOTH the caller's and the requested env's org —
    // staff-auth envs carry no service-enablement rows by design, and a
    // 404 on the caller's own env would fail-close every legitimate
    // org check). The same-transaction SYSTEM-context lookup below.
    if a.claims.env_id.as_deref() == Some(&env_id.to_string()) {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_rls_context(&mut tx, sentin8::config::SYSTEM_ENV_ID).await;
        let snap: Option<(
            Uuid,
            String,
            String,
            String,
            Option<String>,
            Uuid,
            String,
            String,
            String,
        )> = sqlx::query_as(
            r#"SELECT e.id, e.slug, e.display_name, e.status, e.auth_domain,
                          o.id, o.slug, o.display_name, o.domain
                     FROM environments e
                     JOIN organizations o ON o.id = e.org_id
                    WHERE e.id = $1
                    LIMIT 1"#,
        )
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?;
        let _ = tx.rollback().await;
        let Some((e_id, e_slug, e_name, e_status, auth_domain, o_id, o_slug, o_name, o_domain)) =
            snap
        else {
            return Err(not_found());
        };
        return Ok(Json(serde_json::json!({
            "env_id": e_id,
            "env_slug": e_slug,
            "env_display_name": e_name,
            "status": e_status,
            "auth_domain": auth_domain,
            "org_id": o_id,
            "org_slug": o_slug,
            "org_display_name": o_name,
            "org_domain": o_domain,
            "service": {
                "service": caller_service,
                "enabled": true,
                "config": serde_json::Value::Null,
            },
        })));
    }
    let caller_leaf = caller_service.rsplit(':').next().unwrap_or(&caller_service);
    // Enablement gate: the caller's service must be enabled SOMEWHERE in
    // the requested env's org (not necessarily in the requested env —
    // staff-auth envs carry no enablement rows by design, and the vertical
    // org-membership checks resolve envs across the org). Cross-vertical
    // probing stays impossible: a foreign vertical's service is never
    // enabled in this org's envs, so the join misses and the 404 is
    // indistinguishable. The `config` column rides the exact
    // (env, service) row when it exists (the requested env's own config);
    // the org-scope rows only establish enablement.
    let enabled_row: Option<(bool, serde_json::Value)> = sqlx::query_as(
        r#"SELECT s.enabled, s.config
             FROM services s
            WHERE s.service = $2
              AND s.env_id IN (SELECT org_envs.id FROM environments req_env
                                JOIN environments org_envs
                                  ON org_envs.org_id = req_env.org_id
                               WHERE req_env.id = $1)
            ORDER BY (s.env_id = $1) DESC
            LIMIT 1"#,
    )
    .bind(env_id)
    .bind(caller_leaf)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    let (enabled, config) = enabled_row.ok_or_else(not_found)?;
    if !enabled {
        return Err(not_found());
    }

    let snapshot: Option<(
        Uuid,
        String,
        String,
        String,
        Option<String>,
        Uuid,
        String,
        String,
        String,
    )> = sqlx::query_as(
        r#"SELECT e.id, e.slug, e.display_name, e.status, e.auth_domain,
                  o.id, o.slug, o.display_name, o.domain
             FROM environments e
             JOIN organizations o ON o.id = e.org_id
            WHERE e.id = $1
            LIMIT 1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    let _ = tx.rollback().await;

    let Some((e_id, e_slug, e_name, e_status, auth_domain, o_id, o_slug, o_name, o_domain)) =
        snapshot
    else {
        return Err(not_found());
    };

    Ok(Json(serde_json::json!({
        "env_id": e_id,
        "env_slug": e_slug,
        "env_display_name": e_name,
        "status": e_status,
        "auth_domain": auth_domain,
        "org_id": o_id,
        "org_slug": o_slug,
        "org_display_name": o_name,
        "org_domain": o_domain,
        "service": {
            "service": caller_service,
            "enabled": enabled,
            "config": config,
        },
    })))
}

/// `GET /v1/resolve/hostname` — : the single cache-miss path for
/// every service's embedded sentin8-tls DomainResolver. Returns the
/// hostname → (service, org_id, env_id, app_id) mapping so no service
/// needs SELECT grants on sys's domain tables. M2M `sentin8:sys:instances:read`,
/// Shield-gated, audited.
#[utoipa::path(
    get,
    path = "/v1/resolve/hostname",
    params(("hostname" = Option<String>, Query, description = "Fully-qualified hostname to resolve")),
    responses(
        (status = 200, description = "Hostname mapping (service, org_id, env_id, app_id)", body = serde_json::Value),
        (status = 400, description = "hostname query param is required"),
        (status = 404, description = "Hostname not resolvable"),
    ),
    security(("sentin8:sys:instances:read" = [])),
    tag = "sys",
)]
/// Resolve hostname.
pub async fn resolve_hostname(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:instances:read"),
    )
    .await?;
    let host = q
        .get("hostname")
        .map(|h| h.trim().to_lowercase())
        .unwrap_or_default();
    if host.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "hostname query param is required".into(),
        ));
    }

    // Set system org context — cross-tenant hostname lookups. The context
    // is transaction-local: begin an explicit transaction or it evaporates
    // before the queries run.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut conn, sentin8::config::SYSTEM_ENV_ID).await;

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 3 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("hostname {host:?} is not resolvable (too few labels)"),
        ));
    }

    // 1. App-instance exact hostname (frontend or BFF form).
    let app_row = sqlx::query(
        r#"SELECT id, org_id, env_id, sentin8_bff_hostname FROM app_instances
           WHERE status = 'active' AND (LOWER(hostname) = $1 OR LOWER(sentin8_bff_hostname) = $1)
           LIMIT 1"#,
    )
    .bind(&host)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    if let Some(r) = app_row {
        audit(
            &state.pool,
            &a,
            "resolve",
            "hostname",
            &host,
            None,
            Some(serde_json::json!({ "via": "app_instance" })),
        )
        .await;
        return Ok(Json(serde_json::json!({
            "hostname": host,
            "service": "sentin8:web",
            "org_id": r.try_get::<Uuid, _>("org_id").ok().map(|u| u.to_string()),
            "env_id": r.try_get::<Uuid, _>("env_id").ok().map(|u| u.to_string()),
            "app_id": r.try_get::<Uuid, _>("id").ok().map(|u| u.to_string()),
        })));
    }

    // 2. Org-domain suffix walk (the sentin8-tls deduce logic, owner side):
    // progressively shorter suffixes to find the org domain.
    for suffix_len in (2..=labels.len() - 1).rev() {
        let org_domain = labels[labels.len() - suffix_len..].join(".");
        let prefix_labels = &labels[..labels.len() - suffix_len];
        if prefix_labels.is_empty() {
            continue;
        }
        let org_row = match sqlx::query("SELECT id FROM organizations WHERE domain = $1 LIMIT 1")
            .bind(&org_domain)
            .fetch_optional(&mut *conn)
            .await
        {
            Ok(Some(r)) => r,
            _ => continue,
        };
        let org_id: Uuid = org_row.try_get("id").map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("row decode: {e}"),
            )
        })?;

        // Env-scoped pattern: `{service}.{env_slug}.{org_domain}` (3+ prefix
        // labels with the first two = service + env slug). Ops-prefixed
        // (`{service}.ops.{org_domain}`) = the SYSTEM env.
        let (_service_label, env_slug) = if prefix_labels.len() >= 2 {
            (
                prefix_labels[prefix_labels.len() - 2],
                prefix_labels[prefix_labels.len() - 1],
            )
        } else {
            (prefix_labels[0], "ops")
        };
        // Platform service hostnames: `{service}.ops.{org_domain}`.
        let is_system_env = env_slug == sentin8::config::SYSTEM_ENV_SLUG;
        let env_id: Option<Uuid> = if is_system_env {
            Some(sentin8::config::SYSTEM_ENV_ID)
        } else {
            sqlx::query_scalar(
                "SELECT id FROM environments WHERE org_id = $1 AND slug = $2 LIMIT 1",
            )
            .bind(org_id)
            .bind(env_slug)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
        };
        // Resolve the service_type from the hostname label via the runtime
        // subdomain registry (sentin8-config — single source of truth).
        let subdomain_map = sentin8::config::Sentin8Config::from_env()
            .load_subdomain_map(&state.pool)
            .await;
        let service = subdomain_map
            .get(service_label_key(&labels, suffix_len))
            .cloned()
            .unwrap_or_else(|| prefix_labels[0].to_string());
        audit(
            &state.pool,
            &a,
            "resolve",
            "hostname",
            &host,
            None,
            Some(serde_json::json!({ "via": "org_domain", "service": service })),
        )
        .await;
        return Ok(Json(serde_json::json!({
            "hostname": host,
            "service": service,
            "org_id": org_id.to_string(),
            "env_id": env_id.map(|u| u.to_string()),
            "app_id": serde_json::Value::Null,
        })));
    }

    Err((
        StatusCode::NOT_FOUND,
        format!("hostname {host:?} not resolvable"),
    ))
}

/// Key into the subdomain map: the first label of the prefix (the service
/// label), e.g. `auth` for `auth.ops.sys.…`.
fn service_label_key<'a>(labels: &[&'a str], suffix_len: usize) -> &'a str {
    let prefix_len = labels.len() - suffix_len;
    if prefix_len == 0 {
        return "";
    }
    if prefix_len >= 2 {
        labels[prefix_len - 2]
    } else {
        labels[0]
    }
}

/// `GET /v1/app-instance/auth-mode` — returns the app instance's auth_domain and allow_signup.
#[utoipa::path(
    get,
    path = "/v1/app-instance/auth-mode",
    params(("hostname" = Option<String>, Query, description = "BFF or frontend hostname"), ("app_id" = Option<String>, Query, description = "App instance ID")),
    responses(
        (status = 200, description = "Auth mode", body = serde_json::Value),
        (status = 400, description = "hostname or app_id query param is required"),
    ),
    tag = "sys",
)]
/// Fetch instance auth mode.
pub async fn get_instance_auth_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InstanceAuthModeQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // BFF-only surface — zero-trust (sys design ). Step 5 decides:
    // the enforced scope-mirror permits `sentin8:sys:instances:read` (the
    // BFF delegator's M2M scope) and any broader sys admin scope.
    let _a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:instances:read"),
    )
    .await?;
    let host = q.hostname.trim().to_lowercase();
    let app_id = q.app_id.as_deref().unwrap_or("").trim();
    if host.is_empty() && app_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "hostname or app_id query param is required".into(),
        ));
    }
    let stripped = host
        .strip_prefix("bff.")
        .map(|s| s.to_string())
        .unwrap_or_else(|| host.clone());
    // Set system org context — these lookups query across all tenants by
    // hostname. The context is transaction-local, so hold it inside an
    // explicit transaction (autocommit evaporates it before the query).
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut conn, sentin8::config::SYSTEM_ENV_ID).await;
    let instance_id = if !app_id.is_empty() {
        Uuid::parse_str(app_id).ok()
    } else {
        None
    };
    let row = if let Some(id) = instance_id {
        sqlx::query(
            r#"SELECT id, org_id, env_id, instance_name, app_slug, auth_domain, allow_signup, group_gate, oauth_client_id, ciba_oauth_client_id
                 FROM app_instances WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
    } else {
        sqlx::query(
            r#"SELECT i.id, i.org_id, i.env_id, i.instance_name, i.app_slug, i.auth_domain, i.allow_signup, i.group_gate, i.oauth_client_id, i.ciba_oauth_client_id
                 FROM app_instances i
                 JOIN organizations o ON o.id = i.org_id
                WHERE i.status = 'active'
                  AND ( LOWER(i.sentin8_bff_hostname) = $1 OR LOWER(i.hostname) = $1
                     OR LOWER(i.subdomain) = $1 OR LOWER(i.subdomain) = $2
                     OR LOWER(i.hostname) = $2
                     OR (i.subdomain <> '' AND LOWER(i.subdomain || '.' || o.domain) = $1)
                     OR (i.subdomain <> '' AND LOWER(i.subdomain || '.' || o.domain) = $2) )
                LIMIT 1"#,
        )
        .bind(&host)
        .bind(&stripped)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
    };
    match row {
        Some(r) => Ok(Json(serde_json::json!({
        // Stories — full instance identity so the BFF can bind
        // sessions to the creating app (application_id), run the
        // auth-env match (token env vs instance env), and enforce the
        // sentin8:app:{instance_id} group gate at callback
        // (BFF design ; name per ).
                   "application_id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                   "org_id": r.try_get::<Uuid, _>("org_id").map(|u| u.to_string()).unwrap_or_default(),
                   "env_id": r.try_get::<Uuid, _>("env_id").map(|u| u.to_string()).unwrap_or_default(),
                   "instance_name": r.try_get::<String, _>("instance_name").unwrap_or_default(),
                   "app_slug": r.try_get::<String, _>("app_slug").unwrap_or_default(),
                   "auth_domain": r.try_get::<Option<String>, _>("auth_domain").ok().flatten().unwrap_or_default(),
                   "allow_signup": r.try_get::<bool, _>("allow_signup").unwrap_or(true),
        // BFF F-A group-gate mode (see BFF design ): 'strict' →
        // membership required; 'self_service' → authentication + D3
        // auth-env match is sufficient. Defaults to 'strict' so the
        // fail-closed rule applies to every instance that predates
        // the column.
                   "group_gate": r.try_get::<Option<String>, _>("group_gate").ok().flatten().filter(|g| !g.is_empty()).unwrap_or_else(|| "strict".to_string()),
                   "oauth_client_id": r.try_get::<Option<String>, _>("oauth_client_id").ok().flatten().unwrap_or_default(),
                   // Staff-mode CIBA client — the app-instance client registered
                   // at the CUSTOMER env's auth (empty when the instance is not
                   // staff-mode; ciba.rs falls back to oauth_client_id).
                   "ciba_oauth_client_id": r.try_get::<Option<String>, _>("ciba_oauth_client_id").ok().flatten().unwrap_or_default(),
               }))),
        None => Ok(Json(serde_json::json!({
            "application_id": "",
            "org_id": "",
            "env_id": "",
            "instance_name": "",
            "app_slug": "",
            "auth_domain": "",
            "allow_signup": true,
            "group_gate": "strict",
            "oauth_client_id": "",
            "ciba_oauth_client_id": "",
        }))),
    }
}

/// Query params for `get_instance_auth_mode`.
#[derive(Debug, Deserialize, ToSchema)]
/// The instanceauthmodequery type.
pub struct InstanceAuthModeQuery {
    #[serde(default)]
    /// The hostname.
    pub hostname: String,
    #[serde(default)]
    /// app identifier.
    pub app_id: Option<String>,
}

/// `GET /v1/env/{env_id}/app-custom-domain` — returns the custom domain for the app instance.
#[utoipa::path(
    get,
    path = "/v1/env/{env_id}/app-custom-domain",
    params(("env_id" = Uuid, Path, description = "Environment ID")),
    responses(
        (status = 200, description = "Custom domain", body = serde_json::Value),
        (status = 404, description = "Environment not found"),
    ),
    tag = "sys",
)]
/// Fetch app custom domain.
pub async fn get_app_custom_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(env_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // BFF-only surface — zero-trust (sys design ). Step 5 decides:
    // the enforced scope-mirror permits `sentin8:sys:instances:read` (the
    // BFF delegator's M2M scope) and any broader sys admin scope.
    let _a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:instances:read"),
    )
    .await?;
    // Resolve org_id from env_id for the query.
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    // Same-connection/transaction rule (sys design , rule 2):
    // context + query share ONE explicit transaction (transaction-local
    // `set_config` evaporates on autocommit — RLS then hides the row).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, env_id).await;
    let subdomain: String = sqlx::query_scalar(
        "SELECT subdomain FROM app_instances WHERE org_id = $1 AND env_id = $2 AND subdomain <> ''",
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .filter(|s: &String| !s.is_empty())
    .unwrap_or_default();
    let _ = tx.rollback().await;

    Ok(Json(serde_json::json!({ "custom_domain": subdomain })))
}

/// `GET /v1/bootstrap` — user orgs and default org.
#[utoipa::path(
    get,
    operation_id = "bootstrap.get",
    path = "/v1/bootstrap",
    responses(
        (status = 200, description = "Bootstrap data", body = BootstrapResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "sys",
)]
/// Handle bootstrap.
pub async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BootstrapResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    // Incident (policy design ): bootstrap is a GET read —
    // it was gated with the coarse `sentin8:sys:write` action, which NO
    // scope-mirror set permits → the dash bootstrap (and every e2e run)
    // denied 403 for every principal. `sys:read` IS mirrored (granted for
    // sys:admin / sys:org:admin / sys:env:admin effective scopes).
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:read"),
    )
    .await?;
    let user_id = Uuid::parse_str(&a.claims.sub).unwrap_or(Uuid::nil());

    // (): the
    // membership query joined auth.user_roles/group_members directly — a
    // cross-service table read that PostgreSQL rejects under
    // `sentin8_sys_service`'s own-schema-only grants (`relation "user_roles"
    // does not exist` → 500). It had never executed in practice because
    // earlier defects denied at policy BEFORE the SQL ran. Resolution now
    // rides auth's owner API (same pattern as `authorize_org`):
    // the user's group names at SYSTEM_ENV_ID, where per-org groups embed
    // the org UUID ( — `sentin8:org:{org_id}:owners/admins/viewers`),
    // so an org id match proves membership. Env-level roles/groups (the
    // env-realm provisioning) grant env-scoped org access too — the
    // live role closure carries nothing org-embeddable, but the group
    // listing covers the org-realm groups; env-realm memberships surface
    // through the same listing because list_user_groups resolves the
    // caller's env (the token's tenant env) which for these users is the
    // env they hold roles in.
    let exclude_system_org = !a.is_platform_admin();
    let member_org_ids: std::collections::HashSet<Uuid> = if a.is_platform_admin() {
        // Platform admins see every org — no membership filter.
        std::collections::HashSet::new()
    } else {
        member_org_ids_via_auth(user_id)
            .await?
            .into_iter()
            .collect()
    };
    // (PG18 GUC rule): `sys.organizations`
    // is FORCE-RLS'd on `sentin8_context_initialized` — a bare-pool read
    // without tenant context sees ZERO rows (empty memberships) even though
    // the caller holds real memberships. The catalog read rides a
    // transaction whose context covers the whole catalog view: the caller's
    // env (the platform view for platform admins, SYSTEM_ENV_ID otherwise).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, a.claims.env_uuid()).await;
    let orgs = sqlx::query_as::<_, OrgRow>(
        r#"SELECT DISTINCT o.id, o.slug, o.display_name, o.status, o.domain, o.created_at
           FROM organizations o
           WHERE o.status <> 'archived'
             AND ($2::bool = false OR o.id <> $3)
             AND (o.id = ANY($4) OR $4::uuid[] IS NULL)
           ORDER BY o.created_at DESC"#,
    )
    .bind(user_id)
    .bind(exclude_system_org)
    .bind(sentin8::config::SYSTEM_ORG_ID)
    .bind(if a.is_platform_admin() {
        None::<Vec<Uuid>>
    } else {
        Some(member_org_ids.into_iter().collect::<Vec<Uuid>>())
    })
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;

    let membership_responses: Vec<MembershipResponse> = orgs
        .into_iter()
        .map(|r| MembershipResponse {
            id: r.id, // use org_id as the membership id (no separate table)
            user_id,
            org_id: r.id,
            role: "member".into(), // role is in RBAC, not a flat table
            created_at: r.created_at,
        })
        .collect();

    // Default org = the first membership's org (or System Org for platform admins).
    // Same context rule as the catalog read above.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, a.claims.env_uuid()).await;
    let default_org = if a.is_platform_admin() {
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, display_name, status, domain, created_at FROM organizations WHERE id = $1",
        )
        .bind(sentin8::config::SYSTEM_ORG_ID)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?
        .map(|r| OrgResponse {
            id: r.id,
            slug: r.slug,
            display_name: r.display_name,
            status: r.status,
            domain: r.domain,
            created_at: r.created_at,
        })
    } else if let Some(first) = membership_responses.first() {
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, display_name, status, domain, created_at FROM organizations WHERE id = $1",
        )
        .bind(first.org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?
        .map(|r| OrgResponse {
            id: r.id,
            slug: r.slug,
            display_name: r.display_name,
            status: r.status,
            domain: r.domain,
            created_at: r.created_at,
        })
    } else {
        None
    };
    tx.commit().await.map_err(err_db)?;

    Ok(Json(BootstrapResponse {
        user_id: a.claims.sub.clone(),
        memberships: membership_responses,
        default_org,
    }))
}

// ── Audit ─────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for auditevent.
pub struct AuditEventResponse {
    /// Identifier.
    pub id: Uuid,
    /// org identifier.
    pub org_id: Option<Uuid>,
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// Emitting service (DBX — stamped by Sys from the verified M2M client_id).
    /// The service.
    pub service: String,
    /// actor user identifier.
    pub actor_user_id: Option<String>,
    /// The action.
    pub action: String,
    /// The target resource type.
    pub target_resource_type: Option<String>,
    /// target resource identifier.
    pub target_resource_id: Option<String>,
    /// The timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The auditquery type.
pub struct AuditQuery {
    #[serde(default)]
    /// The limit.
    pub limit: i64,
    #[serde(default)]
    /// The offset.
    pub offset: i64,
    /// The action.
    pub action: Option<String>,
    /// Filter by emitting service (DBX ).
    /// The service.
    pub service: Option<String>,
    /// Filter by org (accepted but not yet used for filtering — env_id is the primary filter).
    #[allow(dead_code)]
    /// org identifier.
    pub org_id: Option<Uuid>,
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// Keyset cursor (SYS-2, sys DESIGN §10): return rows strictly older
    /// than this timestamp. Takes precedence over `offset` — stable under
    /// inserts between pages (the `(env_id, timestamp DESC)` index serves it).
    pub after_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Tiebreaker for rows sharing `after_ts` (the row id) — pairs with
    /// `after_ts` for a deterministic keyset position.
    pub after_id: Option<Uuid>,
}

/// `GET /v1/audit` — query orchestration audit events.
#[utoipa::path(
    get,
    operation_id = "audit.list",
    path = "/v1/audit",
    params(
        ("limit" = Option<i64>, Query, description = "Page size"),
        ("offset" = Option<i64>, Query, description = "Page offset"),
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("service" = Option<String>, Query, description = "Filter by emitting service"),
        ("org_id" = Option<Uuid>, Query, description = "Filter by org"),
        ("env_id" = Option<Uuid>, Query, description = "Filter by env"),
        ("after_ts" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Keyset cursor: rows strictly before this timestamp"),
        ("after_id" = Option<Uuid>, Query, description = "Keyset cursor tiebreaker: the last row id from the previous page"),
    ),
    responses(
        (status = 200, description = "Audit events", body = [AuditEventResponse]),
        (status = 403, description = "Missing sys:audit:read scope"),
    ),
    security(("sentin8:sys:audit:read" = [])),
    tag = "sys",
)]
/// List audit.
pub async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEventResponse>>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:audit:read"),
    )
    .await?;
    let limit = if q.limit > 0 { q.limit } else { 100 };
    let offset = q.offset.max(0);

    // Non-admins can only see their env's events.
    let env_filter = if a.is_platform_admin() {
        q.env_id
    } else {
        Some(a.env_id())
    };

    // Keyset mode (SYS-2, sys DESIGN §10): (after_ts, after_id) takes
    // precedence over offset — stable pagination on (timestamp, id).
    let (keyset, after_ts, after_id) = (
        q.after_ts.is_some() || q.after_id.is_some(),
        q.after_ts,
        q.after_id,
    );

    let rows = sqlx::query(
        r#"SELECT id, org_id, env_id, service, actor_user_id, action,
                  target_resource_type, target_resource_id, timestamp
           FROM audit_events
           WHERE ($1::uuid IS NULL OR env_id = $1)
             AND ($2::text IS NULL OR action = $2)
             AND ($5::text IS NULL OR service = $5)
             AND ($6::timestamptz IS NULL OR (timestamp, id) < ($6, $7))
           ORDER BY timestamp DESC, id DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(env_filter)
    .bind(q.action.as_deref())
    .bind(limit)
    .bind(offset)
    .bind(q.service.as_deref())
    .bind(after_ts)
    .bind(after_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;
    let _ = keyset;

    Ok(Json(
        rows.into_iter()
            .map(|r| AuditEventResponse {
                id: r.get("id"),
                org_id: r.get("org_id"),
                env_id: r.get("env_id"),
                service: r.get("service"),
                actor_user_id: r.get("actor_user_id"),
                action: r.get("action"),
                target_resource_type: r.get("target_resource_type"),
                target_resource_id: r.get("target_resource_id"),
                timestamp: r.get("timestamp"),
            })
            .collect(),
    ))
}

// ── Canonical audit ingest (DBX , sys design ) ───────────────

/// One audit event in an ingest batch. `service` is IGNORED server-side —
/// Sys stamps it from the verified M2M `client_id` (never caller-supplied).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The auditingestitem type.
pub struct AuditIngestItem {
    /// env identifier.
    pub env_id: uuid::Uuid,
    /// The action.
    pub action: String,
    /// The target resource type.
    pub target_resource_type: Option<String>,
    /// target resource identifier.
    pub target_resource_id: Option<String>,
    /// actor user identifier.
    pub actor_user_id: Option<String>,
    /// The actor subject type.
    pub actor_subject_type: Option<String>,
    /// The severity.
    pub severity: Option<String>,
    /// correlation identifier.
    pub correlation_id: Option<String>,
    /// The before state.
    pub before_state: Option<serde_json::Value>,
    /// The after state.
    pub after_state: Option<serde_json::Value>,
    /// The details.
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for auditingest.
pub struct AuditIngestRequest {
    /// The events.
    pub events: Vec<AuditIngestItem>,
}

#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for auditingest.
pub struct AuditIngestResponse {
    /// The accepted.
    pub accepted: usize,
    /// The service.
    pub service: String,
}

/// `POST /v1/audit` — canonical audit ingest (M2M, `sentin8:sys:audit:write`).
///
/// DBX : every service pushes its audit events here; Sys persists to
/// `sys.audit_events` with `service` stamped from the verified `client_id`,
/// then emits `sentin8:sys:audit:recorded` per event (family `sys`) for
/// Stat's analytics. A producer keeps a local `{service}.audit_journal`
/// and retries on failure — audit never drops on a Sys outage.
#[utoipa::path(
    post,
    operation_id = "audit.ingest",
    path = "/v1/audit",
    request_body = AuditIngestRequest,
    responses(
        (status = 200, description = "Batch accepted", body = AuditIngestResponse),
        (status = 401, description = "Missing/invalid token"),
        (status = 403, description = "Missing sys:audit:write scope"),
    ),
    security(("sentin8:sys:audit:write" = [])),
    tag = "sys",
)]
/// Handle ingest audit.
pub async fn ingest_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AuditIngestRequest>,
) -> Result<Json<AuditIngestResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sys:audit:write"),
    )
    .await?;

    // DBX: `service` is stamped from the verified token's client identity —
    // for M2M tokens `sub` IS the DCR client_id; user tokens are rejected
    // (M2M-only surface).
    if a.claims.token_tp != "m2m" {
        return Err((
            StatusCode::FORBIDDEN,
            "audit ingest is an M2M-only surface".to_string(),
        ));
    }
    let service = a.effective_subject();

    if req.events.is_empty() {
        return Ok(Json(AuditIngestResponse {
            accepted: 0,
            service,
        }));
    }

    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    for ev in &req.events {
        // Per-event tenant context on THIS connection (RLS).
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', NULL, false, false, false, NULL, 'sys')")
            .bind(ev.env_id)
            .execute(&mut *conn)
            .await;
        if let Err(e) = sqlx::query(
            r#"INSERT INTO audit_events
               (env_id, service, actor_user_id, actor_subject_type, severity,
                correlation_id, action, target_resource_type, target_resource_id,
                before_state, after_state, details)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
        )
        .bind(ev.env_id)
        .bind(&service)
        .bind(ev.actor_user_id.as_deref())
        .bind(ev.actor_subject_type.as_deref())
        .bind(ev.severity.as_deref().unwrap_or("info"))
        .bind(ev.correlation_id.as_deref())
        .bind(&ev.action)
        .bind(ev.target_resource_type.as_deref())
        .bind(ev.target_resource_id.as_deref())
        .bind(&ev.before_state)
        .bind(&ev.after_state)
        .bind(&ev.details)
        .execute(&mut *conn)
        .await
        {
            tracing::error!(error = %e, action = %ev.action, "audit ingest row failed");
        }
    }

    // Fan-out: `sentin8:sys:audit:recorded` per event on the local outbox
    // (the shell's relay pushes it to Bus; Stat's embedded worker aggregates).
    //
    // ENV CONTRACT (same as `audit_tx`'s fan-out): rows carry SYSTEM_ENV_ID
    // — the relay produces with sys's system-env-bound M2M token, so a
    // caller-env row 403s on produce and hot-loops. Each event's own
    // `ev.env_id` rides the payload. The context is re-scoped to the
    // system env ONCE before the loop (the ingest INSERTs above are done;
    // this is the last write block on this connection).
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', NULL, false, false, false, NULL, 'sys')")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *conn)
        .await;
    for ev in &req.events {
        let _ = sentin8::bus::outbox::insert_outbox_row(
            &mut *conn,
            sentin8::config::SYSTEM_ENV_ID,
            "sys",
            "sentin8:sys:audit:recorded",
            &serde_json::json!({
                "service": service,
                "env_id": ev.env_id,
                "action": ev.action,
                "resource_type": ev.target_resource_type,
                "resource_id": ev.target_resource_id,
                "actor": ev.actor_user_id,
                "severity": ev.severity,
            }),
        )
        .await;
    }

    Ok(Json(AuditIngestResponse {
        accepted: req.events.len(),
        service,
    }))
}

// ── Row structs ──────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct OrgRow {
    id: Uuid,
    slug: String,
    display_name: String,
    status: String,
    domain: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct EnvRow {
    id: Uuid,
    org_id: Uuid,
    slug: String,
    display_name: String,
    status: String,
    auth_domain: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

// ── Authorization helper ──────────────────────────────────────────────────

/// Resolve the caller's member-org ids via auth's owner API (
/// ). sys holds NO grants on auth's tables —
/// membership resolution rides `GET /v1/admin/users/{id}/groups` (M2M
/// `sentin8:auth:admin:read`). Per-org group names embed the org UUID
/// (: `sentin8:org:{org_id}:owners/admins/viewers` at SYSTEM_ENV_ID),
/// so a name match proves membership in exactly that org — no slug
/// pattern, no cross-service join.
async fn member_org_ids_via_auth(user_id: Uuid) -> Result<Vec<Uuid>, (StatusCode, String)> {
    let groups = crate::auth_provision::AuthProvisioner::connect()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("auth provisioner connect: {e}"),
            )
        })?
        .user_groups(sentin8::config::SYSTEM_ENV_ID, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("auth membership lookup: {e}"),
            )
        })?;
    Ok(groups
        .iter()
        .filter_map(|name| {
            name.strip_prefix("sentin8:org:")
                .and_then(|rest| rest.split(':').next())
                .and_then(|id| Uuid::parse_str(id).ok())
        })
        .collect())
}

/// Ensure the caller has access to the given organization. Platform admins
/// (`sentin8:sys:admin` scope) bypass the access check.
///
/// Delegated tokens (Delegation Gateway) carry `org_id`/`env_id` claims
/// set to the target org/env. If the token's `org_id` matches the target
/// org_id, access is already validated by the Delegation Gateway — accept
/// it without further checks.
///
/// For direct user tokens, uses the RBAC group/role model
/// (`sentin8_auth_user_roles` + `sentin8_auth_group_members`).
async fn authorize_org(
    a: &AuthContext,
    org_id: Uuid,
    pool: &PgPool,
) -> Result<(), (StatusCode, String)> {
    // Set RLS context for all subsequent queries on this connection.
    // Platform admins get system env context (sees all tenants).
    // Delegated tokens carry the target env in their claims.
    // The context is transaction-local, so the check query runs inside the
    // same transaction ( rule 2).
    let ctx_env = a.claims.env_uuid();
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls_context(&mut tx, ctx_env).await;

    if a.is_platform_admin() {
        tx.commit().await.map_err(err_db)?;
        return Ok(());
    }

    // Delegated tokens from the Delegation Gateway carry the target env
    // in their claims. If the token's env_id matches, the Delegation Gateway
    // already validated RBAC access — accept without further checks.
    let token_env = a.claims.env_uuid();
    if token_env == org_id && org_id != sentin8::config::SYSTEM_ORG_ID {
        tx.commit().await.map_err(err_db)?;
        return Ok(());
    }

    // The System Org is NOT a tenant org — platform-level roles (sys:users)
    // are scoped to it but don't represent org membership. Non-admins cannot
    // access the System Org through this authorization path.
    if org_id == sentin8::config::SYSTEM_ORG_ID {
        return Err((
            StatusCode::FORBIDDEN,
            "not a member of this organization".into(),
        ));
    }
    tx.commit().await.map_err(err_db)?;
    // (/): sys holds NO grants on auth's tables — the
    // membership check rides auth's owner API (`GET /v1/admin/users/{id}/groups`,
    // M2M `sentin8:auth:admin:read`; the write scope satisfies `can_read`).
    // The GROUP names embed the org UUID (provisioning assigns the creator
    // to `sentin8:org:{org_id}:owners`; membership invitations add
    // `:admins`) — any of the three proves membership in THIS org; a
    // foreign org's group names do NOT embed this org_id, so cross-org
    // confusion is impossible by construction. (The ROLE names those
    // groups carry — `sentin8:org:owner/admin/viewer` — are realm-static
    // and shared by every org; matching on roles would admit every
    // org's members to every org. Same resolution as
    // `member_org_ids_via_auth` and `bootstrap`.)
    // The user identity rides the token's `act` claim (auth design, RFC
    // 8693): the sys-proxy hop from auth re-authenticates with auth-sys's
    // OWN M2M token (sub = client_id — not a user), so the membership check
    // MUST resolve the acting user from `act.sub` (RFC 8693 `act`).
    let user_id = a.claims.acting_user_uuid().unwrap_or(Uuid::nil());
    let groups = crate::auth_provision::AuthProvisioner::connect()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .user_groups(sentin8::config::SYSTEM_ENV_ID, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("auth membership check: {e}"),
            )
        })?;
    let owners = format!("sentin8:org:{org_id}:owners");
    let admins = format!("sentin8:org:{org_id}:admins");
    let viewers = format!("sentin8:org:{org_id}:viewers");
    let member = groups
        .iter()
        .any(|g| g == &owners || g == &admins || g == &viewers);
    if member {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "not a member of this organization".into(),
        ))
    }
}

// ── Tenant access model provisioning helpers — RETIRED ──────
// The direct DML helpers (ensure_role / nest_roles / ensure_group /
// assign_group_role / add_group_member / merge_vertical_admin_roles) are
// DELETED — sys no longer INSERTs auth.* tables (
// ). Provisioning rides auth's membership API
// (`/v1/admin/provision/*`) via crate::auth_provision.
// The vertical admin scope merge happens AUTH-side now.

/// Static platform per-service admin roles (auth design role
/// hierarchy) — SENT to auth's provision API (auth owns the rows; sys only
/// describes what to provision). Scope vocabulary mirrors the platform
/// seed (services/auth/sql/init.sql).
const SERVICE_ADMIN_ROLES: &[(&str, &[&str])] = &[
    (
        "sentin8:app:admin",
        &[
            "sentin8:app:store:admin",
            "sentin8:app:store:read",
            "sentin8:app:instances:write",
            "sentin8:app:instances:read",
            "sentin8:app:instances:admin",
        ],
    ),
    (
        "sentin8:db:admin",
        &[
            "sentin8:db:table:admin",
            "sentin8:db:data:read",
            "sentin8:db:data:write",
            "sentin8:db:posture:read",
        ],
    ),
    (
        "sentin8:storage:admin",
        &[
            "sentin8:storage:admin",
            "sentin8:storage:env:read",
            "sentin8:storage:env:write",
            "sentin8:storage:env:admin",
            "sentin8:storage:org:read",
            "sentin8:storage:org:write",
            "sentin8:storage:org:admin",
        ],
    ),
    (
        "sentin8:bus:admin",
        &[
            "sentin8:bus:admin",
            "sentin8:bus:produce",
            "sentin8:bus:consume",
        ],
    ),
    (
        "sentin8:stat:admin",
        &["sentin8:stat:admin", "sentin8:stat:data:read"],
    ),
    (
        "sentin8:flow:admin",
        &["sentin8:flow:read", "sentin8:flow:write"],
    ),
    (
        "sentin8:func:admin",
        &["sentin8:func:write", "sentin8:func:execute"],
    ),
    ("sentin8:cron:admin", &["sentin8:cron:write"]),
    (
        "sentin8:auth:admin",
        &["sentin8:auth:admin:read", "sentin8:auth:admin:write"],
    ),
];

// ── Tenant access model provisioning — auth-API backed ──────
//
// The three helpers below call AUTH's membership provisioning API
// (`/v1/admin/provision/*`) with the `sentin8:sys` M2M client
// (`sentin8:auth:admin:write`) — the former direct INSERTs into
// `auth.groups/group_members/group_roles/role_nesting/roles/user_roles`
// are retired ( ): auth is the owner
// of its tables; sys consumes the owner's API. Idempotent semantics are
// preserved (auth's endpoints are ON CONFLICT-upserts; Flow's at-least-once
// retry is safe). The `tx` parameter is retained in the signature so the
// proxy-back call sites stay stable — HTTP calls are not transactional, so
// the connection is only used for the local identity-invalidation outbox
// event AFTER the API calls succeed.
//
// The vertical admin scope merge now happens AUTH-side (the
// provision API's role upsert reads sys.vertical_admin_scopes through the
// auth-provisioning handler); sys no longer reads that table here.

/// Static platform per-service admin roles — SENT to auth (auth owns the
/// rows; sys only describes what to provision for the new realm). Kept in
/// sync with auth design role hierarchy.
pub(crate) fn platform_admin_roles() -> Vec<(String, Vec<String>)> {
    SERVICE_ADMIN_ROLES
        .iter()
        .map(|(name, perms)| {
            (
                (*name).to_string(),
                perms.iter().map(|s| (*s).to_string()).collect(),
            )
        })
        .collect()
}

/// Provision the tenant access model for a new org (: via auth's
/// API). Roles: sentin8:org:owner (nests sentin8:org:admin, which nests
/// sentin8:org:viewer), groups sentin8:org:{org_id}:owners/admins/viewers
/// ( — names embed the org UUID), creator added to the owners group.
/// `tx` — the caller's open transaction (used ONLY for the local
/// identity-invalidation outbox event after the API calls succeed).
/// Handle provision org access tx.
pub async fn provision_org_access_tx(
    tx: &mut sqlx::PgConnection,
    org_id: Uuid,
    creator_user_id: Uuid,
    sys_env_id: Uuid,
) -> Result<(), sqlx::Error> {
    let provisioner = crate::auth_provision::AuthProvisioner::connect()
        .await
        .map_err(|e| sqlx::Error::Configuration(format!("auth provisioner connect: {e}").into()))?;

    // Option A ( revision): org:admin NEVER carries `sentin8:holder:view-all`
    // — the scope is M2M-only.
    let org_scopes: Vec<String> = vec![
        "sentin8:sys:org:admin".into(),
        "sentin8:sys:memberships:admin".into(),
        "sentin8:dash:org:create".into(),
        "sentin8:dash:org:write".into(),
        "sentin8:dash:org:delete".into(),
        "sentin8:dash:env:create".into(),
        "sentin8:dash:env:delete".into(),
        "sentin8:dash:sentin8ors:read".into(),
        "sentin8:dash:sentin8ors:write".into(),
    ];
    let org_write_scopes: Vec<String> = vec![
        "sentin8:dash:org:write".into(),
        "sentin8:sys:memberships:admin".into(),
        "sentin8:dash:env:create".into(),
        "sentin8:dash:env:write".into(),
        "sentin8:dash:sentin8ors:read".into(),
        "sentin8:dash:sentin8ors:write".into(),
    ];

    // 1. Tenant roles + nesting (owner → admin → viewer).
    provisioner
        .role(sys_env_id, "sentin8:org:owner", &org_scopes)
        .await
        .map_err(auth_err)?;
    provisioner
        .role(sys_env_id, "sentin8:org:admin", &org_write_scopes)
        .await
        .map_err(auth_err)?;
    provisioner
        .role(sys_env_id, "sentin8:org:viewer", &[])
        .await
        .map_err(auth_err)?;
    provisioner
        .role_nesting(sys_env_id, "sentin8:org:owner", "sentin8:org:admin")
        .await
        .map_err(auth_err)?;
    provisioner
        .role_nesting(sys_env_id, "sentin8:org:admin", "sentin8:org:viewer")
        .await
        .map_err(auth_err)?;

    // 2. Per-service admin roles (platform core) + runtime-registered
    // vertical admin roles ( — read from sys.vertical_admin_scopes, sys's
    // OWN table; the earlier comment claiming an auth-side merge was wrong —
    // auth never read that table, so vertical services' admin scopes
    // (acme/ai/post/proxy/captain) were absent from every realm. Incident
    // run 29).
    for (name, perms) in platform_admin_roles() {
        provisioner
            .role(sys_env_id, &name, &perms)
            .await
            .map_err(auth_err)?;
        provisioner
            .role_nesting(sys_env_id, "sentin8:org:owner", &name)
            .await
            .map_err(auth_err)?;
        provisioner
            .role_nesting(sys_env_id, "sentin8:org:admin", &name)
            .await
            .map_err(auth_err)?;
    }
    let vertical_rows = sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT role, scope FROM vertical_admin_scopes ORDER BY role, scope",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut vertical_roles: Vec<(String, Vec<String>)> = Vec::new();
    for (role, scope) in vertical_rows {
        if let Some(entry) = vertical_roles.iter_mut().find(|(n, _)| n == &role) {
            entry.1.push(scope);
        } else {
            vertical_roles.push((role, vec![scope]));
        }
    }
    for (name, perms) in vertical_roles {
        provisioner
            .role(sys_env_id, &name, &perms)
            .await
            .map_err(auth_err)?;
        provisioner
            .role_nesting(sys_env_id, "sentin8:org:owner", &name)
            .await
            .map_err(auth_err)?;
        provisioner
            .role_nesting(sys_env_id, "sentin8:org:admin", &name)
            .await
            .map_err(auth_err)?;
    }

    // 3. Groups ( — org UUID makes the names globally unique).
    let owners_group = format!("sentin8:org:{org_id}:owners");
    let admins_group = format!("sentin8:org:{org_id}:admins");
    let viewers_group = format!("sentin8:org:{org_id}:viewers");
    provisioner
        .group(sys_env_id, &owners_group)
        .await
        .map_err(auth_err)?;
    provisioner
        .group(sys_env_id, &admins_group)
        .await
        .map_err(auth_err)?;
    provisioner
        .group(sys_env_id, &viewers_group)
        .await
        .map_err(auth_err)?;
    // 4. Group↔role assignments + creator membership.
    provisioner
        .group_role(sys_env_id, &owners_group, "sentin8:org:owner")
        .await
        .map_err(auth_err)?;
    provisioner
        .group_role(sys_env_id, &admins_group, "sentin8:org:admin")
        .await
        .map_err(auth_err)?;
    provisioner
        .group_role(sys_env_id, &viewers_group, "sentin8:org:viewer")
        .await
        .map_err(auth_err)?;
    let written = provisioner
        .group_member(sys_env_id, &owners_group, creator_user_id)
        .await
        .map_err(auth_err)?;
    if written == 0 {
        return Err(sqlx::Error::ColumnDecode {
            index: "owners_group".into(),
            source: "owners group row missing after provision API call".into(),
        });
    }

    // 5. Identity-cache invalidation (policy design -1, inbox-first):
    // the creator just received org-scoped access — local outbox event
    // (sys's own stream family; rides the caller's transaction).
    emit_policy_identity_event_tx(
        tx,
        sys_env_id,
        "sentin8:sys:identity:updated",
        serde_json::json!({ "env_id": sys_env_id, "subject_ids": [creator_user_id] }),
    )
    .await;
    tracing::info!(%org_id, creator = %creator_user_id, "sys: provisioned sys-realm tenant access for org (via auth API)");
    Ok(())
}

/// Provision the tenant access model for a new env (: via auth's
/// API). Org-scoped realm (SYSTEM_ENV_ID): sentin8:env:{env_id}:admins/viewers
/// groups → sentin8:env:admin/env:viewer roles; creator added to admins.
/// Handle provision env access tx.
pub async fn provision_env_access_tx(
    tx: &mut sqlx::PgConnection,
    org_id: Uuid,
    env_id: Uuid,
    creator_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    let sys_env_id = sentin8::config::SYSTEM_ENV_ID;
    let provisioner = crate::auth_provision::AuthProvisioner::connect()
        .await
        .map_err(|e| sqlx::Error::Configuration(format!("auth provisioner connect: {e}").into()))?;

    let env_scopes: Vec<String> = vec![
        "sentin8:sys:env:admin".into(),
        "sentin8:sys:instances:read".into(),
        "sentin8:sys:features:admin".into(),
        "sentin8:dash:env:write".into(),
    ];
    let env_read_scopes: Vec<String> = vec![
        "sentin8:app:instances:read".into(),
        "sentin8:storage:env:read".into(),
        "sentin8:bus:consume".into(),
    ];

    provisioner
        .role(sys_env_id, "sentin8:env:admin", &env_scopes)
        .await
        .map_err(auth_err)?;
    provisioner
        .role(sys_env_id, "sentin8:env:viewer", &env_read_scopes)
        .await
        .map_err(auth_err)?;
    provisioner
        .role_nesting(sys_env_id, "sentin8:env:admin", "sentin8:env:viewer")
        .await
        .map_err(auth_err)?;
    let admins_group = format!("sentin8:env:{env_id}:admins");
    let viewers_group = format!("sentin8:env:{env_id}:viewers");
    provisioner
        .group(sys_env_id, &admins_group)
        .await
        .map_err(auth_err)?;
    provisioner
        .group(sys_env_id, &viewers_group)
        .await
        .map_err(auth_err)?;
    provisioner
        .group_role(sys_env_id, &admins_group, "sentin8:env:admin")
        .await
        .map_err(auth_err)?;
    provisioner
        .group_role(sys_env_id, &viewers_group, "sentin8:env:viewer")
        .await
        .map_err(auth_err)?;
    let written = provisioner
        .group_member(sys_env_id, &admins_group, creator_user_id)
        .await
        .map_err(auth_err)?;
    if written == 0 {
        return Err(sqlx::Error::ColumnNotFound(
            "admins group row missing after provision API call".into(),
        ));
    }

    emit_policy_identity_event_tx(
        tx,
        sys_env_id,
        "sentin8:sys:identity:updated",
        serde_json::json!({ "env_id": sys_env_id, "subject_ids": [creator_user_id] }),
    )
    .await;
    tracing::info!(%org_id, %env_id, creator = %creator_user_id, "sys: provisioned org-scoped env access (via auth API)");
    Ok(())
}

/// Provision the env-scoped access model (env realm roles + groups) —
/// : via auth's API. Split out so the env creation step can run
/// it against the env's own env_id. Also seeds the env's platform policy
/// sets + emits the policy-updated event (sys-domain logic, unchanged).
/// Handle provision env realm tx.
/// Copy every `origin='platform'` policy set from the SYSTEM env into
/// `env_id` — the new env's platform policy template (sys owns the
/// policy_sets table). Extracted from `provision_env_realm_tx` so the
/// env-access provisioning can seed policies BEFORE the auth
/// provisioning calls: auth's provision endpoint is Shield-gated
/// per-env and denies fail-closed (`no_set_for_env`) for an env with
/// no policy sets yet (the e2e org/env creation deadlock).
/// Copy every `origin='platform'` policy set from the SYSTEM env into
/// `env_id` — the new env's platform policy template (sys owns the
/// policy_sets table). Extracted from `provision_env_realm_tx` so the
/// env-access provisioning can seed policies BEFORE the auth
/// provisioning calls: auth's provision endpoint is Shield-gated
/// per-env and denies fail-closed (`no_set_for_env`) for an env with
/// no policy sets yet (the e2e org/env creation deadlock).
pub async fn seed_env_platform_policies_tx(
    tx: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO policy_sets
               (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
           SELECT $2, service, policy_set_name, description, policies, schema,
                  'platform', mode, 1, true
           FROM policy_sets
           WHERE env_id = $1 AND origin = 'platform'
           ON CONFLICT (env_id, service, policy_set_name) DO NOTHING"#,
    )
    .bind(sentin8::config::SYSTEM_ENV_ID)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map(|r| r.rows_affected())
}

/// Provision the env-scoped access model (env realm roles + groups) —
/// via auth's API. Split out so the env creation step can run it
/// against the env's own env_id. Also seeds the env's platform policy
/// sets + emits the policy-updated event (sys-domain logic, unchanged).
pub async fn provision_env_realm_tx(
    tx: &mut sqlx::PgConnection,
    org_id: Uuid,
    env_id: Uuid,
    creator_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    let provisioner = crate::auth_provision::AuthProvisioner::connect()
        .await
        .map_err(|e| sqlx::Error::Configuration(format!("auth provisioner connect: {e}").into()))?;

    let env_scopes: Vec<String> = vec![
        "sentin8:sys:env:admin".into(),
        "sentin8:sys:instances:read".into(),
        "sentin8:sys:features:admin".into(),
        "sentin8:dash:env:write".into(),
    ];
    let env_read_scopes: Vec<String> = vec![
        "sentin8:app:instances:read".into(),
        "sentin8:storage:env:read".into(),
        "sentin8:bus:consume".into(),
    ];
    // Create roles in the env realm. Option A ( revision): env:admin
    // never carries `sentin8:holder:view-all` (M2M-only).
    provisioner
        .role(env_id, "sentin8:env:admin", &env_scopes)
        .await
        .map_err(auth_err)?;
    provisioner
        .role(env_id, "sentin8:env:viewer", &env_read_scopes)
        .await
        .map_err(auth_err)?;
    provisioner
        .role_nesting(env_id, "sentin8:env:admin", "sentin8:env:viewer")
        .await
        .map_err(auth_err)?;
    for (name, perms) in platform_admin_roles() {
        provisioner
            .role(env_id, &name, &perms)
            .await
            .map_err(auth_err)?;
        provisioner
            .role_nesting(env_id, "sentin8:env:admin", &name)
            .await
            .map_err(auth_err)?;
    }
    // runtime vertical admin roles: the static list above covers only
    // the platform core services; every VERTICAL service registers its admin
    // scopes in sys.vertical_admin_scopes at `vertical enroll` time and they
    // must ride the same env:admin nesting in every realm — no realm
    // ever carries a vertical's admin scope by default. The table is
    // sys's own.
    let vertical_rows = sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT role, scope FROM vertical_admin_scopes ORDER BY role, scope",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut vertical_roles: Vec<(String, Vec<String>)> = Vec::new();
    for (role, scope) in vertical_rows {
        if let Some(entry) = vertical_roles.iter_mut().find(|(n, _)| n == &role) {
            entry.1.push(scope);
        } else {
            vertical_roles.push((role, vec![scope]));
        }
    }
    for (name, perms) in vertical_roles {
        provisioner
            .role(env_id, &name, &perms)
            .await
            .map_err(auth_err)?;
        provisioner
            .role_nesting(env_id, "sentin8:env:admin", &name)
            .await
            .map_err(auth_err)?;
    }
    // Groups + assignments.
    provisioner
        .group(env_id, "sentin8:env:admins")
        .await
        .map_err(auth_err)?;
    provisioner
        .group(env_id, "sentin8:env:viewers")
        .await
        .map_err(auth_err)?;
    provisioner
        .group_role(env_id, "sentin8:env:admins", "sentin8:env:admin")
        .await
        .map_err(auth_err)?;
    provisioner
        .group_role(env_id, "sentin8:env:viewers", "sentin8:env:viewer")
        .await
        .map_err(auth_err)?;
    let written = provisioner
        .group_member(env_id, "sentin8:env:admins", creator_user_id)
        .await
        .map_err(auth_err)?;
    if written == 0 {
        return Err(sqlx::Error::ColumnNotFound(
            "env:admins group row missing after provision API call".into(),
        ));
    }

    emit_policy_identity_event_tx(
        tx,
        sentin8::config::SYSTEM_ENV_ID,
        "sentin8:sys:identity:updated",
        serde_json::json!({ "env_id": env_id, "subject_ids": [creator_user_id] }),
    )
    .await;

    // Seed the new env's platform policy sets (policy design ): copy
    // each `origin='platform'` set from the system env as the template.
    // (Unchanged — sys owns the policy_sets table.)
    // Order note: the env-access flow calls `seed_env_platform_policies_tx`
    // FIRST (before the auth provisioning calls) — auth's provision
    // endpoint is Shield-gated per-env and denies fail-closed
    // (`no_set_for_env`) when the env has no policy sets yet.
    let seeded = crate::handlers::seed_env_platform_policies_tx(tx, env_id).await?;
    tracing::info!(%env_id, sets = seeded, "sys: seeded per-env platform policy sets");

    // Hot-reload notification (policy design ) — local outbox insert.
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row(
        tx,
        sentin8::config::SYSTEM_ENV_ID,
        "policy",
        "sentin8:sys:policy:updated",
        &serde_json::json!({
            "env_id": env_id,
            "service": "*",
            "policy_set_name": "scope-mirror",
            "version": 1,
            "enabled": true,
            "mode": "enforced",
            "seeded": true
        }),
    )
    .await
    {
        tracing::error!(error = %e, %env_id,
            "sys: failed to emit policy-updated event (services reload on next hot-reload trigger)");
    }
    tracing::info!(%org_id, %env_id, "sys: provisioned env-scoped env access (via auth API)");
    Ok(())
}

/// Map an auth-provision API error into a sqlx::Error so the caller's
/// error path stays a single failure type.
fn auth_err(e: anyhow::Error) -> sqlx::Error {
    sqlx::Error::Configuration(e.to_string().into())
}

/// Synchronously provision the org-realm access model for a new org
/// (create-org handler body, sys DESIGN §2 "Org creation lifecycle").
/// The org row is already committed; this runs the auth provisioning
/// calls (idempotent) and commits the identity-invalidation outbox row.
/// Returns Err on any failure — the caller compensates by deleting the
/// org record.
pub async fn provision_org_access(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    creator_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Tenant context: the outbox row inside provision_org_access_tx is
    // FORCE-RLS'd on (context_initialized, env_id) — SYSTEM_ENV_ID is the
    // tenant these rows belong to (the sys-realm identity event).
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    provision_org_access_tx(
        &mut tx,
        org_id,
        creator_user_id,
        sentin8::config::SYSTEM_ENV_ID,
    )
    .await?;
    tx.commit().await?;
    // Read-your-writes (sys DESIGN §2, backlog RYW-1): the org-scoped
    // grant lives in the SYSTEM env realm — sweep THIS process's
    // resolver cache post-commit so the creator's next request (which
    // may land on the same process) sees the grant without waiting for
    // the async bus event.
    crate::policy::invalidate_local_identity_caches([sentin8::config::SYSTEM_ENV_ID]);
    Ok(())
}

/// Synchronously provision the access model for a new env
/// (create-env handler body, sys DESIGN §2). The env row is already
/// committed; this seeds the env's platform policy sets (committed
/// BEFORE the auth provisioning calls — auth's provision endpoint is
/// Shield-gated per-env and denies fail-closed `no_set_for_env` for an
/// env with no sets; an uncommitted seed is invisible cross-process),
/// then runs the org-scoped + env-scoped realm provisioning.
/// Returns Err on any failure — the caller compensates by deleting the
/// env record.
pub async fn provision_env_access(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    env_id: Uuid,
    creator_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    // Seed the env's platform policy sets in their OWN committed
    // transaction FIRST. Idempotent (ON CONFLICT DO NOTHING) — the realm
    // provisioning's seed below is a no-op.
    {
        let mut seed_tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .execute(&mut *seed_tx)
            .await;
        let seeded = seed_env_platform_policies_tx(&mut seed_tx, env_id).await?;
        seed_tx.commit().await?;
        tracing::info!(%env_id, sets = seeded, "sys: seeded env platform policies (committed pre-provision)");
    }

    let mut tx = pool.begin().await?;
    // Tenant context: the identity-event outbox rows ride SYSTEM_ENV_ID.
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    provision_env_access_tx(&mut tx, org_id, env_id, creator_user_id).await?;
    // Env-scoped realm provisioning: provision sentin8:env:admin/env:viewer
    // roles + groups in the env's own realm (the seed inside is now a
    // no-op ON CONFLICT — the sets landed above).
    provision_env_realm_tx(&mut tx, org_id, env_id, creator_user_id).await?;
    tx.commit().await?;
    // Read-your-writes (sys DESIGN §2, backlog RYW-1): env creation
    // grants in BOTH the SYSTEM realm (org-scoped env access) and the
    // new env's own realm — sweep THIS process's resolver for both.
    crate::policy::invalidate_local_identity_caches([sentin8::config::SYSTEM_ENV_ID, env_id]);
    Ok(())
}
