// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy integration for sys.
//!
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`) -
//! the consolidated implementation every service uses. Nothing is
//! service-specific here beyond the colon service_type.
//!
use std::sync::Arc;

// The full bridge is re-exported so handlers and tests can use any
// piece of the shared surface without reaching into `sentin8::policy`
// directly. Not every name is referenced by this service today.
#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    check_policy, engine_for, policy_bus_client, request_ctx, require_policy, shared_deps,
    spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Test helper: build a bare engine for sys (empty until `load` runs - refuse to
/// start on invalid policy text, design 3.3).
pub fn engine() -> Arc<Engine> {
    engine_for("sentin8:sys")
}

/// Sweep THIS process's `RoleResolver` cache for every realm just
/// granted by an org/env lifecycle or invitation-acceptance handler
/// (sys DESIGN §2 read-your-writes).
///
/// The bus `identity:updated` event is the fleet-wide invalidation
/// channel, but it is asynchronous (outbox → relay → bus → policy
/// SSE) and reaches sys's own consumer seconds after the 200 - while
/// the create request's own Shield evaluation has already primed the
/// per-process resolver with the creator's PRE-grant identity (empty
/// scopes, 30 s TTL). Without this sweep, the very next request in the
/// granting process evaluates against the stale entry and 403s, so
/// the synchronous-lifecycle contract ("200 means the caller's next
/// request already carries its membership") would hold for every
/// process except the one that granted. Same whole-env granularity
/// the bus consumer uses (`RoleResolver::invalidate_env`); no-op when
/// the resolver is not initialized (tests).
pub fn invalidate_local_identity_caches(envs: impl IntoIterator<Item = uuid::Uuid>) {
    let Some(deps) = shared_deps() else {
        return;
    };
    for env_id in envs {
        deps.resolver.invalidate_env(env_id);
        tracing::info!(%env_id, "sys: local identity cache swept (read-your-writes)");
    }
}
