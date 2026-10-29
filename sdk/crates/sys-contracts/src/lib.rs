// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! # sys-contracts
//!
//! Rust types for the Sys control-plane HTTP API - tenant model
//! (organizations, environments) and the platform scope vocabulary.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A platform organization (the tenant's top-level container).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Organization {
    /// Organization id.
    pub id: Uuid,
    /// URL-safe unique slug.
    pub slug: String,
    /// Human-facing name.
    pub display_name: String,
    /// Lifecycle status (`active`/`suspended`).
    pub status: String,
    /// Creation time (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// An environment within an organization (the tenant isolation unit).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    /// Environment id.
    pub id: Uuid,
    /// Owning organization.
    pub org_id: Uuid,
    /// URL-safe slug, unique within the org.
    pub slug: String,
    /// Human-facing name.
    pub display_name: String,
    /// Environment kind (`production`/`staging`/`dev`).
    #[serde(rename = "type")]
    pub env_type: String,
    /// Lifecycle status (`active`/`suspended`).
    pub status: String,
}

/// `GET /v1/scopes/catalog` - platform-wide list of well-known OAuth
/// scopes. Returned as the default suggestion set for the
/// `ScopeSelector` widget in Dash. Apps may still enter arbitrary
/// `service:resource[:action]` scopes that are not in this list.
///
/// This is intentionally a separate endpoint (not a per-org/per-env
/// setting) because scopes are a platform-level vocabulary - the same
/// set applies to every org and every env.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeCatalog {
    /// All well-known scopes the platform recognizes.  Sorted
    /// alphabetically for deterministic output.
    pub scopes: Vec<String>,
}

/// The platform's well-known OAuth scope vocabulary - the single source of
/// truth shared by sys's `GET /v1/scopes/catalog` endpoint and auth's
/// mTLS-bound DCR scope-grant evaluation (a
/// `sentin8_auth_m2m_scope_grants.allowed_scopes` entry may only contain
/// scopes from this list ∪ runtime-registered `service_actions` scopes ∪
/// the OIDC baseline, so grants can never mint an out-of-vocabulary scope).
/// Uniform naming: every scope starts with its vertical - the platform
/// vertical uses the literal `sentin8:` prefix. Sorted alphabetically for
/// deterministic output.
pub const PLATFORM_SCOPE_VOCABULARY: &[&str] = &[
    // App
    "sentin8:app:instances:admin",
    "sentin8:app:instances:read",
    "sentin8:app:instances:write",
    "sentin8:app:installs:read",
    "sentin8:app:installs:write",
    "sentin8:app:listings:read",
    "sentin8:app:listings:write",
    "sentin8:app:store:admin",
    "sentin8:app:store:read",
    // Acme (client-certificate issuance). The scope name is the
    // OpenAPI/audit marker only: the issuance authority is the
    // `sub == service_name` check in the endpoint (a workload mints
    // certificates for itself only), so no grant row or role ever carries
    // this scope.
    "sentin8:acme:clientcert:issue",
    // Auth (identity / access)
    "sentin8:auth:actor:issue",
    "sentin8:auth:admin:read",
    "sentin8:auth:admin:write",
    "sentin8:auth:user:read",
    "sentin8:auth:user:write",
    // Bus (produce/consume are the service-principal workhorses)
    "sentin8:bus:consume",
    "sentin8:bus:produce",
    // Stat ingest (M2M-only measurement ingestion - the per-service
    // `{short}-policy` stat emitters and stat workloads claim it at DCR;
    // granted to M2M clients, never to user roles).
    "sentin8:stat:measure",
    // Policy-admin surface - one scope pair per platform service (the
    // resource is that service's policy-admin surface, so the resource
    // segment names the OWNING service, not `policy`). Vertical services
    // register their own pair via `vertical enroll`.
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
    // Non-self-describing platform services (registry-fallback policy sets)
    "sentin8:bff:policy:read",
    "sentin8:bff:policy:write",
    "sentin8:captain:policy:read",
    "sentin8:captain:policy:write",
    "sentin8:proxy:policy:read",
    "sentin8:proxy:policy:write",
    "sentin8:web:policy:read",
    "sentin8:web:policy:write",
    // Dash admin surface
    "sentin8:dash:admin",
    "sentin8:dash:env:create",
    "sentin8:dash:org:create",
    "sentin8:dash:org:write",
    // DB
    "sentin8:db:data:read",
    "sentin8:db:data:write",
    "sentin8:db:posture:read",
    "sentin8:db:schemas:read",
    "sentin8:db:schemas:write",
    "sentin8:db:table:admin",
    "sentin8:db:tables:read",
    "sentin8:db:tables:write",
    // Delegation Gateway (BFF delegator)
    "sentin8:delegate:read",
    // Sys (BFF-only tenant resolution + Flow proxy-back)
    "sentin8:sys:instances:read",
    "sentin8:sys:memberships:admin",
    "sentin8:sys:steps:execute",
    // Sys tenant-snapshot API (design/
    // sentin8-vertical-data-plane-contract.md §VDC.5): M2M-only on-demand
    // tenant read for vertical services (initial snapshot + issuer/domain
    // derivation). Scoped discovery: the caller sees only envs where its
    // own service is enabled.
    "sentin8:sys:tenants:read",
    // Storage
    "sentin8:storage:buckets:read",
    "sentin8:storage:buckets:write",
    "sentin8:storage:env:read",
    "sentin8:storage:env:write",
    "sentin8:storage:objects:read",
    "sentin8:storage:objects:write",
];

/// Env-wide visibility across holder-scoped records - M2M-only.
/// Registered-but-ungranted by default: no seed grants it; an M2M client
/// must claim it at DCR time. Kept as a separate const so the RLS policy
/// clauses and the SDK primitive reference the same literal.
pub const HOLDER_VIEW_ALL_SCOPE: &str = "sentin8:holder:view-all";

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn organization_roundtrip() {
        let o = Organization {
            id: uuid::Uuid::new_v4(),
            slug: "acme".into(),
            display_name: "ACME Corp".into(),
            status: "active".into(),
            created_at: utc("2026-01-01T00:00:00Z"),
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["slug"], "acme");
        let back: Organization = serde_json::from_value(v).unwrap();
        assert_eq!(back, o);
    }

    #[test]
    fn environment_type_renamed_from_type_field() {
        // `type` is a Rust keyword - the wire field must remain "type".
        let e = Environment {
            id: uuid::Uuid::new_v4(),
            org_id: uuid::Uuid::new_v4(),
            slug: "prod".into(),
            display_name: "Production".into(),
            env_type: "production".into(),
            status: "active".into(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "production", "wire field must be `type`");
        assert!(v.get("env_type").is_none());
        let back: Environment = serde_json::from_value(v).unwrap();
        assert_eq!(back.env_type, "production");
    }

    #[test]
    fn scope_catalog_sorted_and_roundtrip() {
        let c = ScopeCatalog {
            scopes: vec![
                "sentin8:auth:user:read".into(),
                "sentin8:auth:user:write".into(),
                "bank8:ledger:accounts:read".into(),
            ],
        };
        let v = serde_json::to_value(&c).unwrap();
        let back: ScopeCatalog = serde_json::from_value(v).unwrap();
        assert_eq!(back.scopes, c.scopes);
        // Scope shape convention: vertical:service:resource:action -
        // every scope starts with its vertical; platform scopes carry the
        // literal `sentin8` segment.
        for s in &back.scopes {
            let segs: Vec<&str> = s.split(':').collect();
            assert_eq!(
                segs.len(),
                4,
                "scope {s} must be vertical:service:resource:action"
            );
            assert!(
                !segs.iter().any(|seg| seg.is_empty()),
                "scope {s} must not have empty segments"
            );
        }
        // The platform vocabulary itself is uniformly vertical-prefixed.
        for s in PLATFORM_SCOPE_VOCABULARY {
            let segs: Vec<&str> = s.split(':').collect();
            assert_eq!(segs[0], "sentin8", "scope {s} must start with sentin8:");
            assert!(segs.len() >= 3, "scope {s} must have at least 3 segments");
        }
        assert_eq!(HOLDER_VIEW_ALL_SCOPE, "sentin8:holder:view-all");
    }
}
