// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Sys - library re-exports for integration tests.

#![deny(missing_docs)]

/// Produce/consume authentication helpers.
pub mod auth;
/// Auth membership provisioning client (proxy-back verbs).
pub mod auth_provision;
/// Environment configuration.
pub mod config;
/// Domain event emission (outbox) for sys lifecycle changes.
pub mod domain_events;
/// HTTP handlers - orgs, envs, memberships, services, invitations.
pub mod handlers;
/// OpenAPI spec assembly.
pub mod openapi;
/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
/// `sys-post` pusher - drains the local `post_outbox` to Post's send API.
pub mod post_pusher;
/// Service self-registration declarations.
pub mod registration;
/// Axum router and server.
pub mod server;
