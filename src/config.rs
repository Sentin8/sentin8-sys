// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Sys configuration loaded from environment variables.
//!
//! The Sentin8:Shell owns the DB URL (`SENTIN8_SYS_DATABASE_URL`) and the
//! middleware/TLS stack; this config carries only the service-specific
//! settings: port and the shared Auth client.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for sys.
pub struct SysConfig {
    /// The port.
    pub port: u16,
    /// Shared Auth client - constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    /// The auth client.
    pub auth_client: AuthClient,
}

impl SysConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_SYS_PORT")
                .expect("SENTIN8_SYS_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_SYS_PORT must be a valid u16"),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}
