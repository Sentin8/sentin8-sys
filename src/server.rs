// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Sys.
//!
//! Stories — scaffold Rust service with HTTP router, config loading,
//! health check. Wires the PostgreSQL pool and all Sys routes.

use std::sync::Arc;

use axum::routing::{delete, get, post};

use crate::config::SysConfig;
use crate::handlers::{self, AppState};

/// Build the service state (config, pool, workers). Runs inside the
/// shell's `with_state` closure — the pool arrives already created and
/// PG18-checked; this constructs the service config, spawns background
/// workers, and returns the state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = SysConfig::from_env();

    // : warm the MemBus connection so domain-changed
    // notifications publish from the first mutation on. Fail-soft — a
    // Valkey outage degrades resolver refresh to the 30s safety poll.
    crate::domain_events::init().await;

    // ── Sentin8:Policy (— shell-owned boot): consume the
    // engine the shell booted in step 8 — no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    // auth DESIGN §4.3f: boot-load the workload registry map
    // (the token-free authorization record). Fail-open-with-warning at
    // boot: the bearer path (user/delegated) still serves while
    // certificate-workload calls fail-closed until the map loads. The
    // load presents THIS service's certificate identity over the Valkey
    // TLS plane (group DESIGN.md §3.1).
    let workload_registry =
        match sentin8::auth::workload_registry::WorkloadMap::boot_load("sentin8:sys").await {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(error = %e, "sys: workload registry map unavailable at boot — certificate-workload calls fail-closed until next boot");
                sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("sentin8:sys")
            }
        };

    let state = AppState {
        config: Arc::new(config.clone()),
        pool: core.pool.clone(),
        workload_registry,
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:sys".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
    };

    // DBX (SYS-3, sys DESIGN §10): the sys-post pusher drains the local
    // `post_outbox` (invitation sent/accepted mails) to Post's send API —
    // no direct post.inbox writes. The `sys-post` M2M identity + token
    // source are resolved lazily on the first pass (a boot-time DCR
    // failure only delays the drain; rows stay queued).
    {
        let cfg0 = sentin8::config::Sentin8Config::from_env();
        crate::post_pusher::spawn_post_pusher(
            core.pool.clone(),
            cfg0.sentin8_post_url(),
            cfg0.sentin8_auth_issuer(),
        );
    }

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and middleware
/// stack; this function adds ONLY routes (including the service's own
/// `/v1/health` — custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        // ── Operational (Stories) ───────────────────────────
        .route("/v1/health", get(handlers::health))
        .route("/v1/readiness", get(handlers::readiness))
        // ── Vertical Services (RFW discovery — Stories) ─────────────────
        .route(
            "/v1/verticals/services",
            get(handlers::list_vertical_services),
        )
        // ── Organization API (Stories) ────────────────
        .route("/v1/o", post(handlers::create_org).get(handlers::list_orgs))
        .route(
            "/v1/org/{id}",
            get(handlers::get_org).put(handlers::update_org),
        )
        .route("/v1/org/{id}/archive", post(handlers::archive_org))
        .route("/v1/org/{id}", delete(handlers::delete_org))
        // ── Environment API (Stories) ───────────────
        .route("/v1/e", post(handlers::create_env).get(handlers::list_envs))
        .route(
            "/v1/env/{env_id}",
            get(handlers::get_env).put(handlers::update_env),
        )
        .route("/v1/env/{env_id}/archive", post(handlers::archive_env))
        .route("/v1/env/{env_id}", delete(handlers::delete_env))
        // ── Service enablement ────────────────────────────
        .route(
            "/v1/env/{env_id}/services",
            get(handlers::list_services).put(handlers::set_service),
        )
        // ── Application lifecycle ─────────────────────────
        .route(
            "/v1/env/{env_id}/applications",
            post(handlers::create_application).get(handlers::list_applications),
        )
        .route(
            "/v1/env/{env_id}/applications/{app_id}",
            get(handlers::get_application)
                .put(handlers::update_application)
                .post(handlers::archive_application),
        )
        // ── App-environment bindings ────────────────────
        .route(
            "/v1/env/{env_id}/bindings",
            post(handlers::create_binding).get(handlers::list_bindings),
        )
        .route(
            "/v1/env/{env_id}/bindings/{binding_id}",
            delete(handlers::delete_binding),
        )
        // ── Memberships & invitations ────────────────────
        .route(
            "/v1/org/{org_id}/memberships",
            get(handlers::list_memberships).delete(handlers::remove_membership),
        )
        // — full invitation lifecycle owned by sys; auth's admin
        // UI proxies here.
        .route(
            "/v1/org/{org_id}/invitations",
            get(handlers::list_invitations).post(handlers::send_invitation),
        )
        .route(
            "/v1/org/{org_id}/invitations/{invitation_id}/accept",
            post(handlers::accept_invitation),
        )
        .route(
            "/v1/invitations/{id}/revoke",
            post(handlers::revoke_invitation),
        )
        // ── Branding ─────────────────────────────────────
        .route(
            "/v1/org/{org_id}/branding",
            get(handlers::get_org_branding).put(handlers::set_org_branding),
        )
        .route(
            "/v1/env/{env_id}/branding",
            get(handlers::get_env_branding).put(handlers::set_env_branding),
        )
        .route(
            "/v1/env/{env_id}/branding/merged",
            get(handlers::get_merged_branding),
        )
        // ── Tenant resolution ─────────────────────────────
        // BFF and CLI call these endpoints instead of querying the DB directly.
        .route(
            "/v1/env/{env_id}/auth-domain",
            get(handlers::get_env_auth_domain),
        )
        // VDC-4 (design/sentin8-vertical-data-plane-contract.md §VDC.5): the
        // sanctioned M2M on-demand tenant read for vertical services —
        // scoped discovery answers only for envs where the caller's own
        // service is enabled.
        .route("/v1/tenants/{env_id}", get(handlers::get_tenant_snapshot))
        // Resolve an app instance's OAuth scopes + client_id by hostname.
        // Used by BFF at login to request the app's scopes in the authorize URL.
        .route(
            "/v1/app-instance/scopes",
            get(handlers::get_instance_scopes),
        )
        // — the single cache-miss path for every service's
        // embedded sentin8-tls DomainResolver (no sys.* table grants).
        .route("/v1/resolve/hostname", get(handlers::resolve_hostname))
        // Stories — app instance auth mode + staff Auth domain resolution.
        .route(
            "/v1/app-instance/auth-mode",
            get(handlers::get_instance_auth_mode),
        )
        .route(
            "/v1/env/{env_id}/app-custom-domain",
            get(handlers::get_app_custom_domain),
        )
        // ── Platform scope catalog (Stories) ─────────────────────────
        // Public list of well-known OAuth scopes. Used by Dash's
        // ScopeSelector widget to populate the autocomplete without
        // duplicating the list on the client. Open endpoint — same
        // list for every caller.
        .route("/v1/scopes/catalog", get(handlers::get_scope_catalog))
        // ── Bootstrap ────────────────────────────────────
        .route("/v1/bootstrap", get(handlers::bootstrap))
        // ── Audit ────────────────────────────────────────
        .route(
            "/v1/audit",
            get(handlers::list_audit).post(handlers::ingest_audit),
        )

        // Traffic counter — counts every inbound request (excludes health checks).
        // ── Sentin8:Policy admin API ( — shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor — the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
