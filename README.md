# Design Doc: Sentin8:Sys - Platform Control Plane
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://sentin8.dev/docs/services/sys)
[![Website](https://img.shields.io/badge/website-sentin8.dev-1a73e8.svg)](https://sentin8.dev)

## 1. Summary

Sentin8:Sys is the platform control plane: it owns organizations,
environments, app instances and their bindings, service enablement,
memberships and invitations, tenant branding, the hostname → app-instance
resolver, the platform bootstrap surface, and the shared audit trail.
Org/env creation is a **synchronous, in-process lifecycle**: the handler
writes the record, provisions the access model (roles, groups, creator
membership) through auth's membership provisioning API, and returns 200
only when the org/env is fully usable - no workflow engine on the
fundamental path, no background steps, no caller-side settle windows.
Every domain change emits a durable local-outbox event (Sentin8:Bus produce
path) plus a best-effort MemBus invalidation notification post-commit.

## 2. Motivation

- **One tenant registry.** Orgs, envs, and app instances are platform-level
  facts every service needs at request time (tenant resolution, branding,
  feature gating). They live in `sys.*` tables owned by exactly one service;
  everything else reads them through APIs, membus state, or bus events.
- **Zero compile-time vertical knowledge.** Sys knows nothing about bank8,
  hotel8, or any other vertical. Verticals register their admin scopes,
  services, error codes, and app-store listings at runtime
  (`vertical enroll`); sys only persists and serves them.
- **Authorization is data, not code.** Shield policy sets, ReBAC relation
  tuples, and principal attributes are sys-owned rows per environment; the
  per-service engines load and evaluate them (see
  `crates/policy` - the Shield engine). Sys is the durable substrate and the
  admin surface, not the evaluator.
- **Synchronous fundamental lifecycle.** Org/env creation spans two
  services (sys record + auth access model), but the span is two
  idempotent HTTP calls wide - the create handler performs both before
  responding, with an in-handler compensating delete when provisioning
  fails. A workflow engine on this path added a proxy-back hop, a DLQ,
  and a read-your-writes window (the caller got 200 before its own
  membership existed) without removing the crash window it was meant to
  cover. Flow remains the engine for long-running multi-step business
  workflows; sys is not one of them.

## 3. Architecture & High-Level Design

### 3.1 Modules

| Module | Responsibility |
|---|---|
| `handlers.rs` | All HTTP endpoints (orgs, envs, services, applications, bindings, memberships, invitations, branding, resolver, bootstrap, audit ingest/query) + the synchronous org/env provisioning bodies. |
| `server.rs` | Axum router assembly, middleware stack, health/readiness. |
| `auth_provision.rs` | Client for auth's membership provisioning API (`/v1/admin/provision/*`) + live group reads (`/v1/admin/users/{id}/groups`). |
| `auth.rs` | Bearer verification against the shared Sentin8:Auth client (JWKS + issuer, cached). |
| `policy.rs` | Thin re-export of the shared Shield bridge (`sentin8::policy::runtime`). |
| `domain_events.rs` | Post-commit MemBus `sentin8:sys:domain:changed` notifications (ephemeral pub/sub, best-effort). |
| `config.rs` | Service-specific env config (port, Flow target, shared auth client). |
| `registration.rs` | Self-registration: DDL, PG role, policy sets, M2M workload grants, admin scopes, OpenAPI. |
| `openapi.rs` | OpenAPI spec assembly. |

### 3.2 Data model (schema `sys`)

| Table | Purpose |
|---|---|
| `organizations` | Org identity: slug (unique), display name, status (`active`/`suspended`/`archived`), domain. |
| `environments` | Env per org (`UNIQUE(org_id, slug)`), status, optional `auth_domain`. |
| `app_instances` | Hostname → app mapping: unique `hostname` + `sentin8_bff_hostname`, app slug, OAuth client id, feature flags, scope/service whitelists, auth-mode/group-gate settings, custom-domain verification state. |
| `app_environment_bindings` | App ↔ env binding with slug uniqueness per (org, env). |
| `services` | Per-env service enablement (`service`, `enabled`, `config`). |
| `invitations` | Pending/accepted/revoked invitations with one-time token + expiry. |
| `branding` | Org-level base + env-level override; non-empty value wins at merge time. |
| `policy_sets` | Shield policy sets per (env, service, name) with origin, mode (`shadow`/`enforced`), version. |
| `policy_relations` | ReBAC relation tuples per (env, service). |
| `policy_principal_attrs` | ABAC attributes per (env, subject). |
| `vertical_admin_scopes` | Runtime-registered vertical admin roles (from `vertical-registry.json` at `vertical enroll`). |
| `outbox` | Local DBX outbox (producer path to Bus). |
| `audit_events` | Sys's own orchestration audit trail. |
| `audit_journal` | Local retry journal for the shared audit ingest. |

RLS: every tenant-scoped table is `ENABLE`+`FORCE`-RLS'd, gated on
`sentin8_context_initialized()` and `env_id = sentin8_current_env_id()`
(plus a system-env clause where the platform plane needs visibility).
Cross-env access for admins is enforced at the handler layer (role/group
validation via auth's owner API), not by widening RLS.

### 3.3 API surface

- **Lifecycle**: `POST/GET /v1/o`, `GET/PUT/DELETE /v1/org/{id}`,
  `POST /v1/org/{id}/archive`; `POST/GET /v1/e`,
  `GET/PUT/DELETE /v1/env/{env_id}`, `POST /v1/env/{env_id}/archive`.
- **Enablement**: `GET/PUT /v1/env/{env_id}/services`; emits
  `sentin8:sys:service:updated` (verticals react event-driven).
- **Applications**: CRUD under `/v1/env/{env_id}/applications`,
  bindings under `/v1/env/{env_id}/bindings`, custom-domain verification,
  auth-mode (`/v1/app-instance/auth-mode`) and scope catalog
  (`/v1/app-instance/scopes`).
- **Memberships**: list/delete `/v1/org/{org_id}/memberships`;
  invitations create/list/revoke/accept
  (`/v1/org/{org_id}/invitations…`); acceptance assigns the user to
  `sentin8:org:{org_id}:admins` through auth's API and mails a
  notification via post's inbox.
- **Branding**: org base + env override + merged view
  (`/v1/env/{env_id}/branding/merged`).
- **Resolver**: `GET /v1/resolve/hostname` - hostname → org/env/app
  instance (BFF, Auth, TLS all consume this).
- **Bootstrap**: `GET /v1/bootstrap` - the dash's first-screen data
  (orgs the caller can reach, computed via auth's live group listing).
- **Audit**: `POST /v1/audit` (service ingest → canonical rows + local
  journal) and `GET /v1/audit` (admin query: `limit`/`offset` plus
  keyset pagination - `after_ts`/`after_id` return rows strictly older
  than the cursor on the `(timestamp DESC, id DESC)` ordering, with
  `service`/`action`/`env_id` filters).
- **Verticals**: `GET /v1/verticals/services`,
  `GET /v1/scopes/catalog`.

### 3.4 Event-driven surface (DBX outbox)

Emissions (`emit_sentin8_sys_event_tx`, family `sys`, same transaction as
the domain write): `org:created|updated|archived|deleted`,
`env:created|updated|archived|deleted`, `app:created|updated|archived`,
`binding:created|deleted`, `invitation:accepted`,
`service:updated`, `audit:recorded`. The shell-spawned relay pushes rows to
Bus `POST /v1/produce` and marks them relayed. Identity-invalidation events
ride the `policy` family (`sentin8:sys:identity:updated`,
`sentin8:sys:policy:updated` - payload-complete envelopes so consumers
reload without callbacks).

Post-commit MemBus notifications (`domain_events.rs`) publish
`sentin8:sys:domain:changed` on the ephemeral `sys-domain` channel so the
proxy's hostname resolver and the TLS layer refresh surgically; a Valkey
outage degrades to their safety poll and never fails the mutation.

## 4. Key Traits and Data Structures

- **`SysConfig`** (`config.rs`): port, shared `AuthClient`
  (discovery/JWKS caches reused per request).
- **`AppState`**: config, pool, seeded Shield engine, workload registry
  map, shared policy-admin state.
- **`AuthProvisioner`** (`auth_provision.rs`): process-cached M2M token
  source for `sentin8:sys` (scopes `sentin8:auth:admin:write` +
  `sentin8:auth:admin:read`, cert-bound) + `post/get` helpers that carry
  the target env (`x-sentin8-target-env-id` header / `target_env_id`
  query).
- **Registration decls** (`registration.rs`): one PG role
  (`sentin8_sys_service`, NOBYPASSRLS, search_path `sys, public`), the
  enforced `scope-mirror` policy set, the M2M workload grants
  (provisioning, stat, policy×2, post, tls-resolver), admin scopes, and
  the init SQL.

## 5. Rationale, Trade-offs, and Alternatives

- **Synchronous lifecycle instead of saga delegation.** Org/env creation
  is a fundamental platform operation; its cross-service span is two
  idempotent auth-API calls. Executing them in-handler with a
  compensating delete keeps 200 meaning "fully provisioned" (the caller
  needs no retry/settle logic). The alternative - delegating to a
  workflow engine - put a saga hop on the critical path, introduced a
  read-your-writes window (200 before membership existed), and still
  left the same two-call crash window. Flow is for long-running
  multi-step business workflows, not fundamental lifecycles.
- **Provisioning through auth's API instead of cross-schema DML.** Sys
  holds no grants on `auth.*`; roles/groups/nesting are auth-owned rows
  written through the owner's provisioning endpoints with an M2M token.
  This keeps a single writer per table family and makes auth's policy
  gate (target-env header) the enforcement point.
- **Audit in the same transaction, event emissions in the same
  transaction, MemBus notifications strictly post-commit.** The audit row
  and the outbox row must never survive without the domain change (or
  vice versa) - a crash between statements loses the whole transaction.
  MemBus is best-effort by contract (subscribers have safety polls).
- **Audit row's env is the caller's env.** Handlers that act on a target
  env different from the caller's set their transaction context to the
  target env (RLS for the domain write); `audit_tx` re-sets the context to
  the caller's env for its own INSERT because the FORCE-RLS policy admits
  rows only under their own env's context. Every call site is the last
  domain write before the emit block, which re-sets its own context, so
  the swap is safe.
- **Ephemeral MemBus for resolver invalidation, durable bus events for
  lifecycle.** Resolvers need freshness, not durability (a missed
  notification is healed by their periodic poll); lifecycle reactions
  (e.g. env-init seeding) need durability and auditing - hence the outbox
  + Bus produce path for those.

## 6. Internal Implementation & Invariants (Private Design)

1. **Same-transaction tenant context.** The RLS context
   (`sentin8_set_tenant_context`, `set_config(…, true)`) is
   transaction-local: every multi-statement write path sets the context on
   the transaction's connection inside one explicit transaction, and any
   statement that needs a different env re-sets it inline (e.g. the emit
   block switches to the system env because outbox rows for the `sys`
   family live there).
2. **Outbox-first emissions.** `emit_sentin8_sys_event_tx` inserts into
   `sys.outbox` inside the caller's transaction; the relay drains
   env-by-env under RLS (owner-side helper
   `public.sentin8_outbox_unrelayed_envs('sys')`). A failed emission is
   logged and never blocks the request (degrades to TTL-based fallbacks).
3. **Org/env creation is synchronous in-process.** The create handler
   commits the record (with its lifecycle outbox row), provisions the
   access model through auth's API, writes the identity-invalidation
   outbox row, then returns 200 - the caller's next request already
   carries its membership. A provisioning failure compensates by deleting
   the record (500); a caller retry starts clean.
4. **Platform-initiated calls use the derived platform hostname**
   (`sys.ops.sys.{sentin8_domain}` + captain-assigned port), never
   `localhost` - the listener is PQ-TLS SNI-routed, so callers must
   present the registered hostname.
5. **Invitation acceptance is email-bound**: the token must carry the
   invited email; the group assignment rides auth's provisioning API and
   the write fails (409) when the access model was never provisioned -
   acceptance never fabricates groups.
6. **Org access checks never join auth tables.** `authorize_org` accepts
   platform admins (scope `sentin8:sys:admin`), delegated tokens whose env
   matches the target, and otherwise reads the caller's live GROUP
   listing from auth's API, matching the org-embedded
   `sentin8:org:{org_id}:owners|admins|viewers` group names provisioning
   assigns. (Role names are realm-static - matching on them would
   cross-admit every org's members.)
7. **Branding merge is layer-priority**: env override first, then org
   base, non-empty wins; `merged` is read-only.
8. **Audit journal first**: `POST /v1/audit` writes the canonical row and a
   local journal row so a downstream failure never loses the event; the
   pusher retries.
9. **No migration paths**: schema changes land as new `CREATE TABLE` /
   `CREATE POLICY` statements in the init SQL; old data is disposable
   (re-bootstrap recreates everything).

## 7. Unresolved Questions / Future Designs

- The bootstrap surface keeps the shared shape as the contract; per-app
  dashboards are RFW pages served by the owning service and discovered via the
  runtime context - the bootstrap endpoint stays platform-level by design.

---

**Architecture & Design:** sentin8:sys and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
