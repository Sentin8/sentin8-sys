// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:Sys.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See the service design docs.

use sentin8::registration::{
    AdminScope, PgRole, PolicySetDecl, Registration, RelationDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:sys:read,sentin8:sys:write",
    role: "sentin8_sys_service",
    bypass_rls: false,
    database: "sentin8",
    // Invitation post-mail rides post's inbox-first producer contract:
    // sys is a listed producer (sys DESIGN §2) and writes post.inbox
    // in the invitation domain transaction.
    cross_schema_grants: &[sentin8::registration::CrossSchemaGrant {
        schema: "post",
        table: "inbox",
        privilege: "INSERT",
    }],
}];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::SysOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets (Sentin8:Policy design /):
/// action-granular scope permits over the LIVE effective scope set. Seeded
/// `origin='platform'`, `mode='enforced'` ( - step 5 is
/// the only gate; shadow is the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:sys over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        policies: "permit(principal, action == Action::\"sentin8:sys:org:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"sentin8:sys:org:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:org:create\") };\npermit(principal, action == Action::\"sentin8:sys:org:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:org:update\") };\npermit(principal, action == Action::\"sentin8:sys:org:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:org:delete\") };\npermit(principal, action == Action::\"sentin8:sys:org:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:org:archive\") };\npermit(principal, action == Action::\"sentin8:sys:env:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"sentin8:sys:env:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:env:create\") };\npermit(principal, action == Action::\"sentin8:sys:env:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:env:update\") };\npermit(principal, action == Action::\"sentin8:sys:env:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:env:delete\") };\npermit(principal, action == Action::\"sentin8:sys:env:admin\", resource) when { principal.scopes.contains(\"sentin8:dash:env:archive\") };\npermit(principal, action == Action::\"sentin8:sys:app:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:app:admin\") };\npermit(principal, action == Action::\"sentin8:sys:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:audit:read\") };\npermit(principal, action == Action::\"sentin8:sys:instances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:instances:read\") };\npermit(principal, action == Action::\"sentin8:sys:instances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"sentin8:sys:instances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"sentin8:sys:instances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"sentin8:sys:memberships:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:memberships:admin\") };\npermit(principal, action == Action::\"sentin8:sys:services:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:services:admin\") };\npermit(principal, action == Action::\"sentin8:sys:services:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"sentin8:sys:services:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"sentin8:sys:services:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"sentin8:sys:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"sentin8:sys:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"sentin8:sys:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"sentin8:sys:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:view\") };\npermit(principal, action == Action::\"sentin8:sys:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:view\") };\npermit(principal, action == Action::\"sentin8:sys:read\", resource) when { principal.scopes.contains(\"sentin8:sys:view\") };\npermit(principal, action == Action::\"sentin8:sys:tenants:read\", resource) when { principal.scopes.contains(\"sentin8:sys:tenants:read\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples - none declared by this
/// service today; env admins author their own graph via the admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (self-registration ): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired - this declaration is the ONLY
/// provisioning path ( "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "sys-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // : the provisioning workload calls auth's membership
    // provisioning API (`/v1/admin/provision/*`) with this M2M client.
    sentin8::registration::M2mGrant {
        workload: "sentin8:sys",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:stat:measure",
            "sentin8:auth:admin:write",
            "sentin8:auth:admin:read",
        ],
    },
    sentin8::registration::M2mGrant {
        workload: "sys",
        scopes: &["sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:sys-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "sys-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // SYS-3: the post pusher drains sys's local `post_outbox` to Post's
    // send API with this M2M client (DBX - no direct post.inbox writes).
    sentin8::registration::M2mGrant {
        workload: "sys-post",
        scopes: &["sentin8:post:write"],
    },
    // (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-sys-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Handle print.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:sys",
        subdomain: "sys",
        health_path: "/v1/health",
        admin_scopes: &[
            AdminScope::Tuple("sentin8:sys:admin", "sentin8:sys:admin"),
            // Policy-admin surface (policy design ; per-service scope).
            AdminScope::Tuple("sentin8:sys:admin", "sentin8:sys:policy:read"),
            AdminScope::Tuple("sentin8:sys:admin", "sentin8:sys:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: None,
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
