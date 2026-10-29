-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8 platform schema - Sentin8:Sys system tables (not tenant-scoped).
-- These tables are owned by Sentin8:Sys and store organization, environment, and
-- application binding records. They also include per-app instance overrides

-- Organizations table
CREATE SCHEMA IF NOT EXISTS sys;
CREATE TABLE IF NOT EXISTS sys.organizations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    domain        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Environments table
CREATE TABLE IF NOT EXISTS sys.environments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES sys.organizations(id),
    slug            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    auth_domain     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
);

-- Application bindings table
CREATE TABLE IF NOT EXISTS sys.app_environment_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES sys.organizations(id),
    env_id  UUID NOT NULL REFERENCES sys.environments(id),
    application_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL,
    type            TEXT NOT NULL CHECK (type IN ('oauth_client', 'api_client', 'm2m')),
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, env_id, slug)
);

-- RLS (mandatory on every tenant data table - architecture-principles
-- §4.3d): the binding row is env-scoped; the write
-- policies admit any initialized context (sys's own provisioning handlers
-- run under delegated context), the SELECT policy additionally admits the
-- platform plane (system env) - same shape as sys_services_select.

-- Sentin8:App instances table - maps hostnames to org/env/application.

CREATE TABLE IF NOT EXISTS sys.app_instances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES sys.organizations(id),
    env_id  UUID NOT NULL REFERENCES sys.environments(id),
    app_slug        TEXT NOT NULL,
    instance_name   TEXT NOT NULL DEFAULT '',
    instance_description TEXT NOT NULL DEFAULT '',
    hostname        TEXT NOT NULL UNIQUE,
    sentin8_bff_hostname   TEXT NOT NULL UNIQUE,
    subdomain       TEXT NOT NULL DEFAULT '',
    domain_type     TEXT NOT NULL DEFAULT 'default' CHECK (domain_type IN ('default', 'custom')),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('provisioning', 'active', 'maintenance', 'offline')),
    oauth_client_id TEXT,
    -- Staff-mode CIBA client (BFF design - the app-instance CIBA
    -- backchannel client, public PKCE). When the instance is staff-mode
    -- (auth_domain set), the sign-in client above is registered at the
    -- STAFF auth, but CIBA bc-authorize targets the CUSTOMER env's auth -
    -- where a SEPARATE registration of the same instance client is
    -- required. Empty when the instance is not staff-mode (the single
    -- env-scoped registration is shared by both flows).
    ciba_oauth_client_id TEXT,
    listing_id      UUID,
    feature_flags   JSONB NOT NULL DEFAULT '{}',
    env_vars_ref    TEXT,
    allowed_scopes   TEXT[] NOT NULL DEFAULT '{}',
    allowed_services TEXT[] NOT NULL DEFAULT '{}',
    -- Auth domain selected at install time (hostname of the env's Auth server).
    -- When NULL, the BFF falls back to the env-scoped Auth domain.
    auth_domain     TEXT,
    -- Whether public sign-up is allowed for this app instance.
    allow_signup    BOOLEAN NOT NULL DEFAULT true,
    -- membership (fail-closed; ID-based name per architecture-principles
    -- passes the D3 auth-env check (first-party platform surfaces such as
    -- the platform Dash, where self-service users have no group yet).
    group_gate      TEXT NOT NULL DEFAULT 'strict' CHECK (group_gate IN ('strict', 'self_service')),
    sentin8_stat_property_id   UUID,
    sentin8_stat_m2m_client_id TEXT,
    domain_verification_token TEXT,
    domain_verified            BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Service enablement table
CREATE TABLE IF NOT EXISTS sys.services (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES sys.organizations(id),
    env_id  UUID NOT NULL REFERENCES sys.environments(id),
    service         TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT false,
    config          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, env_id, service)
);

-- Memberships: now managed via Sentin8:Auth RBAC (sentin8_auth_user_roles + sentin8_auth_group_members).
-- The old sentin8_sys_memberships table has been removed - org access is determined
-- by role assignments and group memberships in the RBAC model.

-- Invitations table
CREATE TABLE IF NOT EXISTS sys.invitations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES sys.organizations(id),
    email           TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'member',
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked')),
    token           TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sys's `POST /v1/audit` ingest API; `service` is stamped by Sys from the
-- verified M2M `client_id` - never caller-supplied. The former
-- `sys.sys_audit_events` orchestration-local table and Stat's shared
-- `sentin8.audit_events` are both absorbed here.
CREATE TABLE IF NOT EXISTS sys.audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID,
    env_id              UUID,
    -- Emitting service (stamped from the verified M2M client_id).
    service             TEXT NOT NULL,
    actor_user_id       TEXT,
    actor_subject_type  TEXT,
    token_id            TEXT,
    correlation_id      TEXT,
    action              TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id  TEXT,
    severity            TEXT NOT NULL DEFAULT 'info',
    before_state        JSONB,
    after_state         JSONB,
    details             JSONB,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS idx_audit_events_service ON sys.audit_events (service, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_env ON sys.audit_events (env_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation ON sys.audit_events (correlation_id) WHERE correlation_id IS NOT NULL;

-- Branding table - hierarchical branding overrides.
-- scope: 'org' (org-level), 'env' (env-level).
-- Branding is merged hierarchically: env overrides org for each field.
-- Fields that are null/empty at a level fall through to the next level up.
-- Sentin8:Auth uses the merged org+env branding (no separate auth branding scope).
CREATE TABLE IF NOT EXISTS sys.branding (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES sys.organizations(id),
    env_id  UUID REFERENCES sys.environments(id),
    scope           TEXT NOT NULL CHECK (scope IN ('org', 'env')),
    logo_url        TEXT,
    logo_icon_url   TEXT,
    primary_color   TEXT,
    accent_color    TEXT,
    font_family     TEXT,
    theme_mode      TEXT NOT NULL DEFAULT '',
    custom_css      TEXT,
    sign_in_text    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, env_id, scope)
);

-- Sentin8:Sys tables are tenant-scoped by org_id. The Delegation Gateway ensures
-- tokens carry the target org/env, so RLS naturally scopes to the right
-- tenant. sys.organizations (the org table itself) uses the org's own id.
-- Platform admins see all orgs via the Sentin8:Sys service layer (not RLS bypass).

-- Organizations: a caller may read the org its env belongs to (env→org
-- resolution for auth/delegation/app). Platform management (org listing,
-- lifecycle) runs on the Sentin8:Sys service layer with the caller's
-- delegated context and explicit org-membership predicates.
ALTER TABLE sys.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sys_organizations_select ON sys.organizations;
CREATE POLICY sys_organizations_select ON sys.organizations FOR SELECT
    USING (sentin8_context_initialized()
           AND (id = sentin8_current_org_id()
                OR sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid));
DROP POLICY IF EXISTS sys_organizations_insert ON sys.organizations;
CREATE POLICY sys_organizations_insert ON sys.organizations FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_organizations_update ON sys.organizations;
CREATE POLICY sys_organizations_update ON sys.organizations FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_organizations_delete ON sys.organizations;
CREATE POLICY sys_organizations_delete ON sys.organizations FOR DELETE
    USING (sentin8_context_initialized());

ALTER TABLE sys.environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.environments FORCE ROW LEVEL SECURITY;
-- SELECT: the caller may read its OWN env row (id = app.env_id - needed for
-- predicate required sentin8_bypass_rls(), which the Delegation Gateway model
-- retired (always returns false) - the lookup was dead for every
-- NOBYPASSRLS service role, caught by the revived auth conformance tests.
DROP POLICY IF EXISTS sys_environments_select ON sys.environments;
CREATE POLICY sys_environments_select ON sys.environments FOR SELECT
    USING (sentin8_context_initialized()
           AND (id = sentin8_current_env_id()
                OR sentin8_bypass_rls()
                OR org_id = sentin8_current_org_id()
                OR sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid));
    -- The SYSTEM-env clause is the platform plane (mirrors the
    -- sys_organizations_select policy shape): platform services run with
    -- SYSTEM_ENV_ID context, and every env row must be visible to them -
    -- most importantly the row an INSERT ... RETURNING just created (its
    -- tenant org_id never equals the system-org current_org_id, and its
    -- fresh uuid never equals the SYSTEM env id - the RETURNING read
    -- re-checks the SELECT policy, so the clause is required for the
    -- write to report its own row back.
-- INSERT/UPDATE/DELETE: Sentin8:Sys handlers own env lifecycle (org/env
-- provisioning). They run on the service pool with the caller's delegated
-- context set by the BFF; the write policies admit any initialized context
-- (the sys:env:admin scope check at the handler layer is the authorization
-- services write policies' shape).
DROP POLICY IF EXISTS sys_environments_insert ON sys.environments;
CREATE POLICY sys_environments_insert ON sys.environments FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_environments_update ON sys.environments;
CREATE POLICY sys_environments_update ON sys.environments FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_environments_delete ON sys.environments;
CREATE POLICY sys_environments_delete ON sys.environments FOR DELETE
    USING (sentin8_context_initialized());

ALTER TABLE sys.app_environment_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.app_environment_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sys_app_env_bindings_select ON sys.app_environment_bindings;
CREATE POLICY sys_app_env_bindings_select ON sys.app_environment_bindings FOR SELECT
    USING (sentin8_context_initialized()
           AND (env_id = sentin8_current_env_id()
                OR sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid));
DROP POLICY IF EXISTS sys_app_env_bindings_insert ON sys.app_environment_bindings;
CREATE POLICY sys_app_env_bindings_insert ON sys.app_environment_bindings FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_app_env_bindings_update ON sys.app_environment_bindings;
CREATE POLICY sys_app_env_bindings_update ON sys.app_environment_bindings FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_app_env_bindings_delete ON sys.app_environment_bindings;
CREATE POLICY sys_app_env_bindings_delete ON sys.app_environment_bindings FOR DELETE
    USING (sentin8_context_initialized());

ALTER TABLE sys.services ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.services FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sys_services_select ON sys.services;
CREATE POLICY sys_services_select ON sys.services FOR SELECT
    USING (sentin8_context_initialized()
           AND (env_id = sentin8_current_env_id()
                OR sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid));
DROP POLICY IF EXISTS sys_services_insert ON sys.services;
CREATE POLICY sys_services_insert ON sys.services FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_services_update ON sys.services;
CREATE POLICY sys_services_update ON sys.services FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_services_delete ON sys.services;
CREATE POLICY sys_services_delete ON sys.services FOR DELETE
    USING (sentin8_context_initialized());

ALTER TABLE sys.app_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.app_instances FORCE ROW LEVEL SECURITY;
-- Lookup policy: a caller may read instances of its own env, or any env of
-- the org its env belongs to - Auth (tenant resolution from hostname), BFF
-- (per-app scope whitelist) and App (runtime context) all resolve app
-- instances for hostnames in the caller's org. The SYSTEM-env clause is the
-- platform plane (mirrors sys_environments_select / sys_organizations_select):
-- platform services resolving an app instance by HOSTNAME (auth-mode lookup,
-- tenant resolution, domain catalog) run with SYSTEM_ENV_ID context and must
-- see every tenant's instance rows - hostname lookups cannot know the
-- caller's org in advance. The bypass clause is inert (always false) but
-- retained for consistency with sibling policies.
DROP POLICY IF EXISTS sys_instances_select ON sys.app_instances;
CREATE POLICY sys_instances_select ON sys.app_instances FOR SELECT
    USING (sentin8_context_initialized()
           AND (sentin8_bypass_rls()
                OR env_id = sentin8_current_env_id()
                OR org_id = sentin8_current_org_id()
                OR sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid));
DROP POLICY IF EXISTS sys_instances_insert ON sys.app_instances;
CREATE POLICY sys_instances_insert ON sys.app_instances FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_instances_update ON sys.app_instances;
CREATE POLICY sys_instances_update ON sys.app_instances FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_instances_delete ON sys.app_instances;
CREATE POLICY sys_instances_delete ON sys.app_instances FOR DELETE
    USING (sentin8_context_initialized());

ALTER TABLE sys.invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sys_invitations_select ON sys.invitations;
CREATE POLICY sys_invitations_select ON sys.invitations FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_invitations_insert ON sys.invitations;
CREATE POLICY sys_invitations_insert ON sys.invitations FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_invitations_update ON sys.invitations;
CREATE POLICY sys_invitations_update ON sys.invitations FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_invitations_delete ON sys.invitations;
CREATE POLICY sys_invitations_delete ON sys.invitations FOR DELETE
    USING (sentin8_context_initialized());

ALTER TABLE sys.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.audit_events FORCE ROW LEVEL SECURITY;
-- Audit rows are queryable within the caller's tenant (env match) or at the
-- system scope for platform admins. Inserts come only from Sys's own ingest
-- handler (same role) with the client_id-stamped service.
DROP POLICY IF EXISTS sys_audit_select ON sys.audit_events;
CREATE POLICY sys_audit_select ON sys.audit_events FOR SELECT
    USING (
        sentin8_context_initialized()
        AND (
            env_id IS NULL
            OR env_id = sentin8_current_env_id()
        )
    );
DROP POLICY IF EXISTS sys_audit_insert ON sys.audit_events;
CREATE POLICY sys_audit_insert ON sys.audit_events FOR INSERT
    WITH CHECK (
        sentin8_context_initialized()
        AND (
            env_id IS NULL
            OR env_id = sentin8_current_env_id()
        )
    );

ALTER TABLE sys.branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.branding FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sys_branding_select ON sys.branding;
CREATE POLICY sys_branding_select ON sys.branding FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_branding_insert ON sys.branding;
CREATE POLICY sys_branding_insert ON sys.branding FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_branding_update ON sys.branding;
CREATE POLICY sys_branding_update ON sys.branding FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sys_branding_delete ON sys.branding;
CREATE POLICY sys_branding_delete ON sys.branding FOR DELETE
    USING (sentin8_context_initialized());

-- ── Grants ──

-- sentin8_sys_service: DML on all sys tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    sys.organizations, sys.environments, sys.app_environment_bindings,
    sys.app_instances, sys.services, sys.invitations,
    sys.audit_events, sys.branding
    TO sentin8_sys_service;

-- Domain-changed notifications ride MemBus now
-- (`mchan:{SYSTEM_ENV_SLUG}:sys-domain`, published post-commit by
-- DROPPED and stay dropped; the notify fn is a no-op stub for safety.
DROP TRIGGER IF EXISTS sentin8_org_domain_notify ON sys.organizations;
DROP TRIGGER IF EXISTS org_domain_notify ON sys.organizations;
DROP TRIGGER IF EXISTS sentin8_env_domain_notify ON sys.environments;
DROP TRIGGER IF EXISTS env_domain_notify ON sys.environments;
DROP TRIGGER IF EXISTS sentin8_app_domain_notify ON sys.app_instances;
DROP TRIGGER IF EXISTS app_domain_notify ON sys.app_instances;

-- Cross-service grants (re-applied from 20-oauth-roles.sql after tables exist).
-- sentin8_app_service: app instance lifecycle management.
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.app_instances TO sentin8_app_service;
-- Sentin8:App resolves env→org (runtime context, install dropdown, RBAC
-- target-env validation) - read-only access to the org/env lookup tables.
GRANT SELECT ON sys.environments, sys.organizations TO sentin8_app_service;

-- (send_invitation/accept_invitation handlers here); auth's admin UI
-- proxies through sys's invitation API with its M2M token.
-- Sentin8:Func reads the per-env `func` feature gate (FUNC-FG-1): a disabled
-- `services` row closes the WASM engine for that environment.
GRANT SELECT ON sys.services, sys.environments TO sentin8_func_service;
-- ── Seed data (system org/env, dash install, dash group) ──
-- Bootstrap data: System Organization, System Environment, the Dash app
-- instance, and the Dash group + role in the auth env. Idempotent.
--
-- System UUIDs (constants - see crates/sentin8-config):
--   System Org ID  = 00000000-0000-0000-0000-000000000001
--   System Env ID  = 00000000-0000-0000-0000-000000000002

-- ── System Organization ──────────────────────────────────────────────
-- The sys org owns platform operator users. It is not tenant-scoped
-- data, but it must exist so RLS queries resolve correctly.
-- `domain` is NOT NULL - the sys org uses the default platform pattern
-- `sys.{sentin8.domain}` (see Sentin8Config::org_domain). The domain is
-- passed as a psql variable (`sentin8.domain`) from db-reset.sh so it
-- matches the SENTIN8_DOMAIN env var at seed time.
INSERT INTO sys.organizations (id, slug, display_name, status, domain)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'sys',
    'Sentin8',
    'active',
    'sys.' || :'sentin8.domain'
)
ON CONFLICT (id) DO UPDATE SET
    slug = EXCLUDED.slug,
    display_name = EXCLUDED.display_name,
    status = EXCLUDED.status,
    domain = EXCLUDED.domain;

-- ── System Environment ──────────────────────────────────────────────────
-- The ops env owns platform operator and org admin sessions. Every operator/admin user
-- has env_id = System Env ID.
INSERT INTO sys.environments (id, org_id, slug, display_name, status)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'ops',
    'Operations',
    'active'
)
ON CONFLICT (id) DO UPDATE SET
    slug = EXCLUDED.slug,
    display_name = EXCLUDED.display_name,
    status = EXCLUDED.status;

-- ── Default admin user ─────────────────────────────────────────────────
-- The default admin signs in as a@m.n / pass.
-- The password hash below is bcrypt (cost 10) for "pass", generated
-- with the `bcrypt = "0.15"` crate (the same crate auth uses) and
-- verified with `bcrypt::verify("pass", hash)`. Do NOT change this
-- hash - it is the bootstrap admin password for all environments.

-- ── Dash app installation (sys/ops) ───────────────────────────────────
-- Sentin8:Dash is installed as an app instance in sys/ops, just like any
-- other app. The OAuth client_id `dash` is seeded in auth's seed.sql.
-- The listing_id is set by vertical enroll (sentin8/vertical-registry.json
-- seeds dash into app.store_listings).
-- Domain mappings (dash.ops.sys.{domain} → web, bff.dash.ops.sys.{domain}
-- → bff) are seeded directly here since there is no API call during SQL seed.
INSERT INTO sys.app_instances
    (id, org_id, env_id, app_slug, instance_name, instance_description,
     hostname, sentin8_bff_hostname, subdomain, domain_type,
     listing_id, status, auth_domain, allow_signup, group_gate)
SELECT
    -- (sentin8:app:{instance_id}[_\:role]) key on this id, and the BFF
    -- gate resolves the group from the seeded instance lookup - so the
    -- seed must be deterministic (no gen_random_uuid()).
    '00000000-0000-0000-0000-00000000000a',
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
    'dash',
    'Sentin8 Dash',
    'Sentin8 operator dashboard',
    'dash.ops.sys.' || :'sentin8.domain',
    'bff.dash.ops.sys.' || :'sentin8.domain',
    '',
    'default',
    (SELECT id FROM app.store_listings WHERE app_slug = 'dash' LIMIT 1),
    'active',
    'auth.ops.sys.' || :'sentin8.domain',
    false,
    -- First-party platform surface: self-service users create their first
    -- org here, so app-group membership cannot be a sign-in prerequisite
    'self_service'
WHERE NOT EXISTS (
    SELECT 1 FROM sys.app_instances
    WHERE org_id = '00000000-0000-0000-0000-000000000001'
      AND env_id = '00000000-0000-0000-0000-000000000002'
      AND app_slug = 'dash'
);
-- Group_gate for an existing dash row (this platform pre-dates the column;
-- idempotent seed keeps re-running it on upgrades).
UPDATE sys.app_instances
SET group_gate = 'self_service'
WHERE org_id = '00000000-0000-0000-0000-000000000001'
  AND env_id = '00000000-0000-0000-0000-000000000002'
  AND app_slug = 'dash'
  AND group_gate <> 'self_service';

-- listing_id for the dash instance: the INSERT above leaves it NULL when
-- the listing is seeded later (or by a different service SQL pass) - backfill
-- by app_slug (idempotent; only fills NULLs).
UPDATE sys.app_instances i
SET listing_id = l.id
FROM app.store_listings l
WHERE i.org_id = '00000000-0000-0000-0000-000000000001'
  AND i.env_id = '00000000-0000-0000-0000-000000000002'
  AND i.app_slug = 'dash'
  AND i.listing_id IS NULL
  AND l.app_slug = 'dash';

-- SQL-seeded instance row bypassed app's `setup_instance`, which is where
-- installs normally copy `listing.oauth_defaults.scopes` →
-- `app_instances.allowed_scopes`. With allowed_scopes empty, the BFF's
-- login scope resolution fell back to the OIDC baseline only, so session
-- tokens never carried `sentin8:app:store:admin` and every store mutation 403'd.
-- Single source of truth: read the scopes from the referenced listing row
-- (CTE - no LATERAL reference into the UPDATE target).
WITH listing_scopes AS (
    SELECT i.id AS instance_id,
           ARRAY(
               SELECT jsonb_array_elements_text(l.oauth_defaults -> 'scopes')
           ) AS scopes
      FROM sys.app_instances i
      JOIN app.store_listings l ON l.app_slug = i.app_slug
     WHERE i.org_id = '00000000-0000-0000-0000-000000000001'
       AND i.env_id = '00000000-0000-0000-0000-000000000002'
       AND i.app_slug = 'dash'
       AND jsonb_typeof(l.oauth_defaults -> 'scopes') = 'array'
)
UPDATE sys.app_instances i
SET allowed_scopes = COALESCE(ls.scopes, i.allowed_scopes),
    allowed_services = COALESCE(
        (
            SELECT ARRAY(
                SELECT DISTINCT split_part(scope, ':', 1)
                  FROM unnest(ls.scopes) AS scope
                 WHERE split_part(scope, ':', 1)
                       NOT IN ('openid','profile','email','offline_access')
            )
        ), i.allowed_services),
    updated_at = now()
FROM listing_scopes ls
WHERE i.id = ls.instance_id
  AND i.allowed_scopes = '{}';

-- ── Dash app group + role (auth/ops env) ─────────────────────────────
-- group membership at session creation for every app instance
-- provision its group in the auth env (sys/ops) with a role carrying
-- the listing's oauth_defaults.scopes, and add the bootstrap admin as
-- a member. Idempotent - safe to re-run on every seed.
--
-- keyed by the instance UUID - app setup_instance, the BFF gate, and
-- the Flutter SDK all read the same `app_instances.id`. The dash
-- seed pins the instance row to the fixed UUID
-- '00000000-0000-0000-0000-00000000000a', so the group/role names
-- below are stable constants (no snake_case derivation anywhere).
WITH dash_listing AS (
    SELECT oauth_defaults->'scopes' AS scopes
      FROM app.store_listings
     WHERE app_slug = 'dash'
     LIMIT 1
), dash_scopes AS (
    SELECT js.scope
      FROM dash_listing l
      CROSS JOIN LATERAL jsonb_array_elements_text(
          COALESCE(l.scopes, '["openid","profile","email"]'::jsonb)
      ) AS js(scope)
), new_role AS (
    INSERT INTO auth.roles (id, env_id, name, permissions)
    SELECT gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
           'sentin8:app:00000000-0000-0000-0000-00000000000a:role',
           COALESCE(
               (SELECT array_agg(js.scope)
                  FROM dash_listing l
                  CROSS JOIN LATERAL jsonb_array_elements_text(
                      COALESCE(l.scopes, '[]'::jsonb)
                  ) AS js(scope)),
               ARRAY['openid', 'profile', 'email']::text[]
           )
    ON CONFLICT (env_id, name) DO UPDATE
        SET permissions = EXCLUDED.permissions, updated_at = now()
    RETURNING id
), new_groups AS (
    INSERT INTO auth.groups (id, env_id, name)
    VALUES
        (gen_random_uuid(), '00000000-0000-0000-0000-000000000002', 'sentin8:app:00000000-0000-0000-0000-00000000000a')
    ON CONFLICT (env_id, name) DO NOTHING
    RETURNING id, name, env_id
), new_links AS (
    INSERT INTO auth.group_roles (group_id, role_id, env_id)
    SELECT g.id, r.id, g.env_id
      FROM new_groups g
      CROSS JOIN new_role r
    ON CONFLICT (group_id, role_id) DO NOTHING
    RETURNING 1
)
SELECT 1 FROM new_links;

-- Bootstrap admin → the group (idempotent). This is a SEPARATE statement:
-- within a single statement, the main query cannot see rows inserted by a
-- data-modifying CTE in the same statement (snapshot isolation), so
-- membership must be linked after the group row is committed.
INSERT INTO auth.group_members (group_id, user_id, env_id)
SELECT g.id, u.id, g.env_id
  FROM auth.groups g
  CROSS JOIN LATERAL (
      SELECT u.id FROM auth.users u
       WHERE u.email = 'a@m.n' AND u.env_id = g.env_id
       LIMIT 1
  ) u
 WHERE g.env_id = '00000000-0000-0000-0000-000000000002'
   AND g.name = 'sentin8:app:00000000-0000-0000-0000-00000000000a'
ON CONFLICT (group_id, user_id) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════
--
-- Each row is one policy set for one service in one environment. Services load
-- their own rows at boot (WHERE service = self, as their own PG role) and
-- hot-reload on the sentin8:sys:policy:updated Bus event. Write-time Shield
-- table stores validated text only.
--
-- origin:  'platform' rows come from vertical-registry.json via `vertical
--          enroll` and are overwritten on re-enroll; 'tenant' rows are
--          authored by env admins and NEVER touched by enroll.
-- mode:    'shadow' evaluates and logs policy.would_deny but never blocks;
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS sys.policy_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL REFERENCES sys.environments(id) ON DELETE CASCADE,
    service         TEXT NOT NULL,
    policy_set_name TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    policies        TEXT NOT NULL,
    schema          TEXT,
    origin          TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform','tenant')),
    mode            TEXT NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow','enforced')),
    version         INT NOT NULL DEFAULT 1,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, service, policy_set_name)
);

ALTER TABLE sys.policy_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.policy_sets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_policy_sets_select ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_select ON sys.policy_sets FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_sets_insert ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_insert ON sys.policy_sets FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_sets_update ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_update ON sys.policy_sets FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_sets_delete ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_delete ON sys.policy_sets FOR DELETE
    USING (sentin8_context_initialized());

-- Every adopting service reads its own rows (PolicyEngine::load). The boot
-- load runs BEFORE any tenant context exists, so RLS
-- (`sentin8_context_initialized()`) would hide every row from per-service
-- OAuth roles - the COLD-START-1 class. Services load through the dedicated
-- `sentin8_boot_policy_load(service)` SECURITY DEFINER function below
GRANT SELECT ON sys.policy_sets TO sentin8_post_service, sentin8_sys_service, sentin8_flow_service, sentin8_bus_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.policy_sets TO sentin8_sys_service;
-- Phase 28 tenant-authored Shield (post admin surface, post DESIGN §5):
-- tenant-authored sets/relation tuples/attrs live in the platform tables
-- with `origin = 'tenant'`; post's admin API writes them through its own
-- M2M role. RLS (`sentin8_context_initialized()`) still bounds every row to
-- the caller's tenant, and the handlers' predicates keep `service =
-- 'sentin8:post'` - the grant cannot touch other services' rows.

-- `PolicyEngine::load` runs at service boot, before any tenant context is
-- set. The table's RLS policy gates on `sentin8_context_initialized()`, so a
-- per-service OAuth role (NOBYPASSRLS) would see ZERO rows at boot (or get
-- `permission denied` where the GRANT is missing) and every request would
-- deny fail-closed. This SECURITY DEFINER function is the sanctioned boot
-- read path: it filters `WHERE service = $1 AND enabled` SERVER-SIDE so a
-- service can only ever load its own rows (owner RLS is bypassed only for
-- this exact filter), and it is granted EXECUTE to every service role.
-- The admin API keeps reading the table directly under the caller's request
-- context - RLS on the table itself is unchanged.
CREATE OR REPLACE FUNCTION public.sentin8_boot_policy_load(p_service TEXT)
RETURNS TABLE (
    id              UUID,
    env_id          UUID,
    service         TEXT,
    policy_set_name TEXT,
    description     TEXT,
    policies        TEXT,
    schema          TEXT,
    origin          TEXT,
    mode            TEXT,
    version         INT,
    enabled         BOOLEAN
)
LANGUAGE sql SECURITY DEFINER SET search_path = sys, public AS $func$
    SELECT id, env_id, service, policy_set_name, description,
           policies, schema, origin, mode, version, enabled
      FROM sys.policy_sets
     WHERE service = p_service AND enabled;
$func$;

-- EXECUTE for the shared dev role + every existing and future PLATFORM
-- service role (the dynamic loop covers late-created platform roles).
-- Vertical services boot-load from their OWN database's substrate copy
-- - the platform copy's EXECUTE stays platform-only .
GRANT EXECUTE ON FUNCTION public.sentin8_boot_policy_load(TEXT) TO sentin8_app_dev;
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles
             WHERE rolname LIKE 'sentin8\_%\_service'
               AND rolname NOT LIKE 'pg_%'
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.sentin8_boot_policy_load(TEXT) TO %I', r.rolname);
    END LOOP;
EXCEPTION WHEN undefined_function THEN NULL;
END $$;

-- ═══════════════════════════════════════════════════════════════════════════
--
-- Zanzibar-lite: one row = one edge (subject, relation, object) in the
-- entity graph. Loaded per (env_id, service) as Shield entity-hierarchy
-- `parents` edges at evaluation time; policies use the `in` operator
-- (`principal in Group::"fx-ops"`). Size-capped by the loader
-- (RELATION_SLICE_CAP - over-cap fails the load, which denies in enforced
-- mode). Hot-reload via `sentin8:sys:policy:relations:updated`.
--
-- origin: 'platform' tuples come from vertical-registry.json `relations`
--         via enroll and are overwritten on re-enroll; 'tenant' tuples are
--         authored by env admins and NEVER touched by enroll.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS sys.policy_relations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id       UUID NOT NULL REFERENCES sys.environments(id) ON DELETE CASCADE,
    service      TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    relation     TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    origin       TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform','tenant')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, subject_type, subject_id, relation, object_type, object_id)
);

ALTER TABLE sys.policy_relations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.policy_relations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_policy_relations_select ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_select ON sys.policy_relations FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_relations_insert ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_insert ON sys.policy_relations FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_relations_update ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_update ON sys.policy_relations FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_relations_delete ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_delete ON sys.policy_relations FOR DELETE
    USING (sentin8_context_initialized());

-- ═══════════════════════════════════════════════════════════════════════════
--
-- Identity-adjacent attributes (department, clearance, vip, employment type)
-- for the principal side of attribute rules. Resource attributes are NOT
-- stored here - services supply them on the EvalTarget at the call site
-- (payload completeness; no duplicate attribute store). Injected into the
-- evaluation context at request time; hot-reload is not needed (rows are
-- read per evaluation from the DB - attributes are small and change rarely).
-- The `sentin8:sys:policy:attrs:updated` event tells admin UIs to refresh;
-- services reading per-request always see fresh values.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS sys.policy_principal_attrs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL REFERENCES sys.environments(id) ON DELETE CASCADE,
    subject_id  TEXT NOT NULL,
    attr_key    TEXT NOT NULL,
    attr_value  JSONB NOT NULL,
    origin      TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform','tenant')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, subject_id, attr_key)
);

ALTER TABLE sys.policy_principal_attrs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.policy_principal_attrs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_policy_attrs_select ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_select ON sys.policy_principal_attrs FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_attrs_insert ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_insert ON sys.policy_principal_attrs FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_attrs_update ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_update ON sys.policy_principal_attrs FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_attrs_delete ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_delete ON sys.policy_principal_attrs FOR DELETE
    USING (sentin8_context_initialized());

-- Reading rights mirror policy_sets: services load their own
-- sys manages writes via the admin API + enroll. The bus relay role reads
-- the relation/attr slices at evaluation time (see the sets grant above).
GRANT SELECT ON sys.policy_relations, sys.policy_principal_attrs
    TO sentin8_post_service, sentin8_sys_service, sentin8_flow_service, sentin8_bus_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.policy_relations, sys.policy_principal_attrs
    TO sentin8_sys_service;
GRANT INSERT, UPDATE, DELETE ON sys.policy_sets TO sentin8_post_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.policy_relations TO sentin8_post_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.policy_principal_attrs TO sentin8_post_service;

-- inside EVERY adopting service's process and reads these platform tables
-- per request under the service's own role (crates/policy/src/substrate.rs
-- `load_relations` / `load_principal_attrs`). The four-role grants above are
-- historical only - under per-service DSNs every `*_service` role that boots
-- Shield needs SELECT on both tables or the evaluation degrades (warns
-- `permission denied` + evaluates without hierarchy edges/attrs). RLS on the
-- tables (`sentin8_context_initialized()`) still bounds every read to the
-- caller's tenant; the grant only enables the engine's in-process evaluation.
-- - no direct table grant here. Dynamic loop mirrors that function's EXECUTE
-- loop so late-created platform roles are covered too.
-- (design/sentin8-vertical-data-plane-contract.md §VDC.7): PLATFORM
-- roles only - a vertical domain role reads its Shield substrate from the
-- VERTICAL database's local copy, never from the platform tables.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles
             WHERE rolname LIKE 'sentin8\_%\_service'
               AND rolname NOT LIKE 'pg_%'
    LOOP
        EXECUTE format(
            'GRANT SELECT ON sys.policy_relations, sys.policy_principal_attrs TO %I',
            r.rolname);
    END LOOP;
EXCEPTION WHEN undefined_table THEN NULL;
END $$;


-- Producer path: sys.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("sys").
CREATE TABLE IF NOT EXISTS sys.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sys_outbox_unrelayed
    ON sys.outbox (created_at) WHERE relayed = false;
ALTER TABLE sys.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON sys.outbox;
CREATE POLICY outbox_select ON sys.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON sys.outbox;
CREATE POLICY outbox_insert ON sys.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON sys.outbox;
CREATE POLICY outbox_update ON sys.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION sys.sys_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('sys_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON sys.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON sys.outbox
    FOR EACH ROW
    EXECUTE FUNCTION sys.sys_notify_outbox();

-- ── Local post_outbox (DBX-POST-3, architecture-principles §6.7) ────────
-- Queue for Sentin8:Post notifications (invitation sent/accepted mails).
-- Producers enqueue here in the SAME transaction as the domain change;
-- the sys-post pusher drains it to POST post /v1/send (M2M, scope
-- sentin8:post:write) - no direct post.inbox writes, no cross-schema
-- INSERT grant on Post's internal tables. RLS is env-scoped: the row's
-- env_id is the ORG's env, written under the caller's context (same-tx
-- discipline with the invitation INSERT it accompanies).
CREATE TABLE IF NOT EXISTS sys.post_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    message_type    TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT 'system',
    priority        TEXT NOT NULL DEFAULT 'normal',
    recipient_user_id UUID,
    recipient_email TEXT,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sys_post_outbox_unpushed
    ON sys.post_outbox (created_at) WHERE pushed = false;
ALTER TABLE sys.post_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.post_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS post_outbox_dml ON sys.post_outbox;
CREATE POLICY post_outbox_dml ON sys.post_outbox
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- Owner-side env helper (RLS drain discipline, post DESIGN §5 pattern):
-- the pusher task has NO tenant context of its own, so a bare-pool
-- SELECT silently returns 0 rows (FORCE RLS). This returns only env
-- UUIDs (no row content); the pusher sets per-env context and drains
-- each row's read/update under it.
CREATE OR REPLACE FUNCTION sys.sys_post_outbox_unpushed_envs()
    RETURNS TABLE (env_id UUID)
LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    RETURN QUERY SELECT DISTINCT o.env_id FROM post_outbox o WHERE o.pushed = false;
END;
$fn$;


-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("sys").
CREATE TABLE IF NOT EXISTS sys.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sys_audit_journal_unpushed
    ON sys.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE sys.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON sys.audit_journal;
CREATE POLICY audit_journal_dml ON sys.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned - the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA sys TO sentin8_sys_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.outbox TO sentin8_sys_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.post_outbox TO sentin8_sys_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sys TO sentin8_sys_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sys.audit_journal TO sentin8_sys_service;

-- runtime-registered trigger/event surfaces (sys registration.rs).
-- These two tables are created on demand by the CLI during `vertical
-- enroll` (they hold verticals' runtime-registered event trigger
-- declarations and error codes; no owned DDL in sys's init) and may not
-- exist on a fresh platform - the GRANT is guarded (a bare GRANT on a
-- missing table aborts the whole init migration on a fresh bootstrap).
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON sys.event_triggers, sys.vertical_error_codes TO sentin8_sys_service;
EXCEPTION WHEN undefined_table THEN NULL;
END $$;
