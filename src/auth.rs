// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Sys.
//!
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original Sys call sites (taking `&SysConfig` + `&HeaderMap`).

use axum::http::{self, HeaderMap, StatusCode};

use crate::config::SysConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context.
pub async fn verify_token(
    config: &SysConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.auth_client, headers).await
}

/// The combined verification entry (auth DESIGN §4.3f + DESIGN §5):
/// Bearer-first, certificate fallback. When the request carries no
/// Authorization header and the TLS handshake presented an enrolled
/// platform-workload certificate, the identity is resolved against
/// the boot-loaded registry map (the map IS the authorization record -
/// scopes + vertical + enabled; no token involved). A Bearer JWT is
/// verified first and always wins when present (a delegated token
/// names the acting user in `act.sub` - see `verify` below).
/// Handle verification.
///
/// Bearer-first, certificate fallback (DESIGN §5): a Bearer JWT
/// (user/delegated/actor token) always wins; the client-certificate
/// workload resolution runs only when no Authorization header is
/// present. The mTLS-transported proxy hop (auth's `sys_proxy_with_actor`)
/// presents BOTH the `auth-sys` certificate AND a delegated JWT naming
/// the acting user (`act.sub`, RFC 8693) - resolving the certificate
/// first would shadow the delegated token and drop the acting user
/// (the membership probe would then query auth with the nil UUID and
/// fail "not a member of this organization"). The certificate remains
/// the sole path for pure-M2M calls (no bearer).
pub async fn verify(
    registry: &sentin8::auth::workload_registry::WorkloadMap,
    config: &SysConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let has_bearer =
        headers.contains_key(http::header::AUTHORIZATION) || headers.contains_key("authorization");
    if !has_bearer {
        if let Some(workload) =
            sentin8::auth::client::resolve_workload_identity(registry, headers).await?
        {
            let tls = sentin8::middleware::context::TLSContext::from_headers(headers);
            return Ok(AuthContext::from_workload(workload, tls.env_id));
        }
    }
    verify_token(config, headers).await
}
