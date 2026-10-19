// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! MemBus domain-changed notifications (membus design ).
//!
//! Every org/env/app-instance/branding mutation publishes
//! `sentin8:sys:domain:changed` on the ephemeral pub/sub class
//! (`mchan:{SYSTEM_ENV_ID}:sys-domain`) AFTER the domain transaction
//! commits. Subscribers (the proxy's DomainResolver, sentin8-tls's
//! resolver) refresh surgically instead of the former LISTEN/NOTIFY +
//! full-table reload - the DB triggers are retired with this path (no
//! cross-schema notify fn).
//!
//! Best-effort by contract: a Valkey outage only delays resolver refresh
//! (the 30s safety-poll backstop still exists in the proxy); it never
//! fails the mutation. The MemBus handle is connected once per process
//! (`MemBusConfig::from_env` - `VALKEY_URL`).

use sentin8::membus::{Envelope, MemBus};

use crate::handlers::AppState;

/// The membus family (stream/channel suffix) for sys domain notifications.
pub const DOMAIN_FAMILY: &str = "sys-domain";
/// The ephemeral event type carried in the envelope.
pub const DOMAIN_EVENT: &str = "sentin8:sys:domain:changed";

/// Process-wide MemBus handle - connected once at boot (fail-soft: a
/// Valkey outage degrades refresh to the safety poll).
static MEMBUS_HANDLE: tokio::sync::OnceCell<Option<MemBus>> = tokio::sync::OnceCell::const_new();

/// Connect once (awaited from `build_state`); subsequent calls reuse the
/// handle (borrowed - MemBus is not Clone, so the publish path borrows
/// through the OnceCell). `None` = Valkey unreachable (notifications
/// disabled).
async fn handle() -> Option<&'static MemBus> {
    MEMBUS_HANDLE
        .get_or_init(|| async {
            let cfg = sentin8::membus::MemBusConfig::from_env("sentin8:sys");
            match MemBus::connect(cfg).await {
                Ok(bus) => Some(bus),
                Err(e) => {
                    tracing::warn!(error = %e, "sys: MemBus connect failed - domain-changed notifications disabled (resolver safety poll covers)");
                    None
                }
            }
        })
        .await
        .as_ref()
}

/// Warm the MemBus connection at boot so the first mutation doesn't pay
/// the connect cost. Failure is non-fatal (best-effort contract).
pub async fn init() {
    let _ = handle().await;
}

/// Publish a domain-changed notification post-commit. Fire-and-forget:
/// failures log at warn and degrade to the resolver's 30s safety poll.
///
/// `scope` - `org` | `env` | `app` | `branding` (lets subscribers decide
/// how surgical the refresh can be). `hostname` - the specific hostname
/// that changed (empty = full refresh).
pub async fn publish_domain_changed(
    _state: &AppState,
    scope: &str,
    hostname: &str,
    org_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
) {
    let Some(bus) = handle().await else {
        return; // notifications disabled - safety poll covers
    };
    // System-domain notifications ride the SYSTEM env's ephemeral channel
    // (the sys org/env is the platform's own tenant, membus design ).
    // `for_env` is UUID-bound (membus validates the env id); the platform
    // env's UUID is the SYSTEM_ENV_ID constant - the slug alone fails the
    // binding gate and would have silently disabled every notification.
    let Ok(env_bus) = bus.for_env(&sentin8::config::SYSTEM_ENV_ID.to_string()) else {
        return;
    };
    let payload = serde_json::json!({
        "event_type": DOMAIN_EVENT,
        "scope": scope,
        "hostname": hostname,
        "org_id": org_id.map(|u| u.to_string()),
        "env_id": env_id.map(|u| u.to_string()),
    });
    let envelope = Envelope::new(DOMAIN_EVENT, payload.to_string().into_bytes());
    if let Err(e) = env_bus.publish_pubsub(DOMAIN_FAMILY, &envelope).await {
        tracing::warn!(error = %e, "sys: domain-changed membus publish failed (resolver safety poll covers)");
    }
}
