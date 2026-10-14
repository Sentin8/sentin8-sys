// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Auth provisioning client ().
//!
//! Sys's Flow proxy-back provisioning steps call **auth's membership
//! provisioning API** (`POST /v1/admin/provision/*`) instead of INSERTing
//! `auth.*` tables directly — the cross-service table access is retired
//! : the owner exposes the verbs, sys holds a token
//! (`sentin8:auth:admin:write` on the `sentin8:sys` workload).
//!
//! Every call is idempotent (auth's endpoints use `ON CONFLICT` semantics),
//! matching Flow's at-least-once retry. Failures propagate as sqlx-unmapped
//! errors to the proxy-back step (fail-closed — a provisioning step that
//! fails surfaces to Flow's retry/DLQ, never silently skipped).

/// Auth provisioning API client — **certificate-presenting** (,
/// auth DESIGN §4.3f): the `sentin8:sys` CERTIFICATE is the identity,
/// presented on the TLS handshake of every call; Auth's TLS layer
/// authenticates it. No bearer token exists on this path.
pub struct AuthProvisioner {
    auth_url: String,
    http: reqwest::Client,
}

impl AuthProvisioner {
    /// Build (or reuse) the process provisioner. Ensures the
    /// `sentin8:sys` workload certificate (load-or-mint from Acme) and
    /// builds the cert-presenting transport. The registry map authorizes
    /// the workload's scopes (`sentin8:auth:admin:write`/`read`) —
    /// resolved LIVE per call server-side.
    pub async fn connect() -> anyhow::Result<Self> {
        let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
        let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
        let cert = sentin8::auth::m2m::ensure_workload_certificate(
            &issuer,
            "sentin8:sys",
            &ca_cert_path,
        )
        .await?;
        let mtls = sentin8::middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        Ok(Self {
            auth_url: issuer.trim_end_matches('/').to_string(),
            http: sentin8::middleware::mtls::build_mtls_client(&mtls)
                .map_err(|e| anyhow::anyhow!("sys provisioner transport: {e}"))?,
        })
    }

    /// POST to auth's admin provisioning API.
    ///
    /// `x-sentin8-target-env-id` header (auth design /): auth is
    /// env-scoped — the body's `env_id` alone does NOT authorize the target;
    /// the header IS the target-env declaration the access check reads
    /// (`x-sentin8-target-env-id`, services/auth/src/provision.rs
    /// `authorize_provisioning`). Without it every provisioning call 400s
    /// ("missing target_env_id — auth is env-scoped", :
    /// org-create failed at `provision_org_access`). The env rides in each
    /// request body under the `env_id` key; when absent (no tenant scope)
    /// the header is omitted and auth resolves SYSTEM env defaults.
    async fn post(&self, path: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.auth_url, path);
        let mut req = self
            .http
            .post(&url)
            .json(&body);
        if let Some(env_id) = body.get("env_id").and_then(|v| v.as_str()) {
            if !env_id.is_empty() {
                req = req.header("x-sentin8-target-env-id", env_id);
            }
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("auth provision {path}: {status} {text}");
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
    }

    /// GET from auth's admin API (read path — `sentin8:auth:admin:read` or
    /// the `admin:write` scope satisfies `can_read`, sentin8or_auth.rs).
    /// The `target_env_id` query param declares the target env (auth is
    /// env-scoped, same rule as `post`'s header).
    async fn get(&self, path: &str, env_id: uuid::Uuid) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}?target_env_id={}", self.auth_url, path, env_id);
        let resp = self
            .http
            .get(&url)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("auth read {path}: {status} {text}");
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
    }

    /// The user's resolved role names (auth-side closure over direct +
    /// group-assigned roles + nesting). Read path for cross-service
    /// authorization checks (: sys holds NO grants on auth's
    /// tables — the check rides auth's
    /// `GET /v1/admin/users/{id}/roles` API).
    /// Handle user roles.
    pub async fn user_roles(
        &self,
        env_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<Vec<String>> {
        let v = self
            .get(&format!("/v1/admin/users/{user_id}/roles"), env_id)
            .await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The user's group names in `env_id` (owner-API read, :
    /// bootstrap membership resolution rides auth's
    /// `GET /v1/admin/users/{id}/groups` — sys holds NO grants on
    /// auth's tables). Per-org group names embed the org UUID (:
    /// `sentin8:org:{org_id}:owners/admins/viewers` at SYSTEM_ENV_ID),
    /// so an org id match proves membership in that org.
    /// Handle user groups.
    pub async fn user_groups(
        &self,
        env_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<Vec<String>> {
        let v = self
            .get(&format!("/v1/admin/users/{user_id}/groups"), env_id)
            .await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Handle role.
    pub async fn role(
        &self,
        env_id: uuid::Uuid,
        name: &str,
        permissions: &[String],
    ) -> anyhow::Result<Uuid2> {
        let v = self
            .post(
                "/v1/admin/provision/role",
                serde_json::json!({ "env_id": env_id, "name": name, "permissions": permissions }),
            )
            .await?;
        Ok(parse_uuid(&v, "role_id"))
    }

    /// Handle role nesting.
    pub async fn role_nesting(
        &self,
        env_id: uuid::Uuid,
        parent_name: &str,
        child_name: &str,
    ) -> anyhow::Result<()> {
        self.post(
            "/v1/admin/provision/role_nesting",
            serde_json::json!({ "env_id": env_id, "parent_name": parent_name, "child_name": child_name }),
        )
        .await?;
        Ok(())
    }

    /// Handle group.
    pub async fn group(&self, env_id: uuid::Uuid, name: &str) -> anyhow::Result<Uuid2> {
        let v = self
            .post(
                "/v1/admin/provision/group",
                serde_json::json!({ "env_id": env_id, "name": name }),
            )
            .await?;
        Ok(parse_uuid(&v, "group_id"))
    }

    /// Handle group role.
    pub async fn group_role(
        &self,
        env_id: uuid::Uuid,
        group_name: &str,
        role_name: &str,
    ) -> anyhow::Result<()> {
        self.post(
            "/v1/admin/provision/group_role",
            serde_json::json!({ "env_id": env_id, "group_name": group_name, "role_name": role_name }),
        )
        .await?;
        Ok(())
    }

    /// Handle group member.
    pub async fn group_member(
        &self,
        env_id: uuid::Uuid,
        group_name: &str,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<u64> {
        let v = self
            .post(
                "/v1/admin/provision/group_member",
                serde_json::json!({ "env_id": env_id, "group_name": group_name, "user_id": user_id }),
            )
            .await?;
        Ok(v["count"].as_u64().unwrap_or(0))
    }

    /// Handle user role.
    pub async fn user_role(
        &self,
        env_id: uuid::Uuid,
        user_id: uuid::Uuid,
        role_name: &str,
    ) -> anyhow::Result<()> {
        self.post(
            "/v1/admin/provision/user_role",
            serde_json::json!({ "env_id": env_id, "user_id": user_id, "role_name": role_name }),
        )
        .await?;
        Ok(())
    }
}

/// UUID wrapper (avoids the sqlx::Error import in the signature).
/// Type alias for uuid2.
pub type Uuid2 = uuid::Uuid;

fn parse_uuid(v: &serde_json::Value, key: &str) -> Uuid2 {
    v[key]
        .as_str()
        .and_then(|s| Uuid2::parse_str(s).ok())
        .unwrap_or_else(Uuid2::nil)
}
