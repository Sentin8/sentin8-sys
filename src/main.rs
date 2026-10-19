// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Sys - cross-service orchestration (org/env/app lifecycle).
//!
//! See.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! ): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

mod auth;
#[allow(dead_code)]
mod auth_provision;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod domain_events;
mod handlers;
mod openapi;
#[allow(dead_code)]
mod policy;
mod post_pusher;
mod registration;
mod server;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:sys", "SENTIN8_SYS")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::SysOpenApi::openapi()),
    )
    .await
}
