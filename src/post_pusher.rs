// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sys
// SPDX-License-Identifier: Apache-2.0

//! `sys-post` pusher task (sys DESIGN §10, DBX-POST-3).
//!
//! Drains `sys.post_outbox` (rows enqueued in the SAME transaction as the
//! domain change - invitation sent/accepted mails) to Sentin8:Post's
//! `POST /v1/send` with the `sys-post` M2M identity (scope
//! `sentin8:post:write`). sys never writes `post.inbox` directly and holds
//! no INSERT grant on Post's internal tables (principles §6.7).
//!
//! Drain discipline follows the owner-side RLS pattern (post DESIGN §5):
//! `sys.post_outbox` is FORCE-RLS'd, so the context-less background task
//! cannot see rows directly. The SECURITY DEFINER helper
//! `sys_post_outbox_unpushed_envs()` returns only the env UUIDs with
//! unpushed rows; each env's rows are then selected and marked pushed
//! under that env's tenant context (same-transaction rule). Post receives
//! the per-row env via the `X-Sentin8-Env-Id` header - the contract its
//! send API resolves tenant context from.
//!
//! Identity lifecycle mirrors the audit-pusher pattern (crates/audit):
//! the cert-presenting transport is resolved ONCE for the process
//! lifetime and reused across passes - a per-pass DCR load + credential
//! probe + fresh PQ-TLS client would ratchet allocator arenas. Stale
//! identities re-establish through the certificate transport's own
//! single-flight self-heal. Failures leave rows unpushed for the next
//! pass - a Post outage never drops notifications.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// Spawn the pusher loop. Call once at boot (server.rs).
pub fn spawn_post_pusher(pool: PgPool, post_url: String, auth_issuer: String) {
    tokio::spawn(async move {
        // auth DESIGN §4.3f: the `sys-post` CERTIFICATE is the
        // identity - ensure it once (mint retries while Acme comes up),
        // then build the ONE cert-presenting client for the task lifetime
        // (connection reuse across passes; webhook relay pattern - a
        // per-pass client churns pools). No token exists on this path.
        let cert = loop {
            match sentin8::auth::m2m::ensure_workload_certificate(
                &auth_issuer,
                "sys-post",
                &sentin8::auth::m2m::platform_ca_path(),
            )
            .await
            {
                Ok(c) => break c,
                Err(e) => {
                    tracing::debug!(error = %e, "sys: post push certificate not ready yet");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };
        let mtls = sentin8::middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        let client = match sentin8::middleware::mtls::build_mtls_client(&mtls) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "sys: post push transport build failed - pusher disabled");
                return;
            }
        };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            if let Err(e) = drain_and_push_post(&pool, &client, &post_url).await {
                tracing::warn!(error = %e, "sys: post notification push pass failed");
            }
        }
    });
}

/// One unpushed row as read under its env's tenant context.
struct PendingRow {
    id: Uuid,
    env_id: Uuid,
    message_type: String,
    category: String,
    priority: String,
    recipient_user_id: Option<Uuid>,
    recipient_email: Option<String>,
    subject: String,
    body: String,
    metadata: serde_json::Value,
}

/// One drain pass: list envs with unpushed rows (SECURITY DEFINER), then
/// per env - under that env's context - select up to 50 rows, push each to
/// `POST /v1/send` (per-row `X-Sentin8-Env-Id`), and mark pushed on 2xx.
async fn drain_and_push_post(
    pool: &PgPool,
    client: &reqwest::Client,
    post_url: &str,
) -> anyhow::Result<usize> {
    // Envs that have unpushed rows (owner-side helper - no row content).
    let envs: Vec<Uuid> = sqlx::query_scalar("SELECT env_id FROM sys_post_outbox_unpushed_envs()")
        .fetch_all(pool)
        .await?;

    let mut pushed = 0usize;
    for env_id in envs {
        // Read the batch under the env's context (FORCE RLS; one explicit
        // transaction per env - the context is transaction-local).
        let mut tx = pool.begin().await?;
        set_context(&mut tx, env_id).await;
        let rows = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                String,
                String,
                Option<Uuid>,
                Option<String>,
                String,
                String,
                serde_json::Value,
            ),
        >(
            r#"SELECT id, env_id, message_type, category, priority,
                      recipient_user_id, recipient_email, subject, body, metadata
                 FROM post_outbox WHERE pushed = false ORDER BY created_at LIMIT 50"#,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        for (
            id,
            _env,
            message_type,
            category,
            priority,
            recipient_user_id,
            recipient_email,
            subject,
            body,
            metadata,
        ) in rows
        {
            let row = PendingRow {
                id,
                env_id,
                message_type,
                category,
                priority,
                recipient_user_id,
                recipient_email,
                subject,
                body,
                metadata,
            };
            match push_one(pool, client, post_url, &row).await {
                Ok(true) => pushed += 1,
                Ok(false) => {} // rejected/failed - retried next pass
                Err(e) => {
                    tracing::warn!(error = %e, message_id = %row.id, "sys: post push row failed - retried next pass");
                }
            }
            if pushed >= 100 {
                return Ok(pushed); // batch cap - next pass continues
            }
        }
    }
    Ok(pushed)
}

/// Push one row and mark it pushed on success. The UPDATE re-checks
/// `pushed = false` so a concurrent pass (or a replayed row) cannot
/// double-mark, and runs under the row's env context (FORCE RLS).
async fn push_one(
    pool: &PgPool,
    client: &reqwest::Client,
    post_url: &str,
    row: &PendingRow,
) -> anyhow::Result<bool> {
    let payload = serde_json::json!({
        "message_type": row.message_type,
        "category": row.category,
        "priority": row.priority,
        "recipient_user_id": row.recipient_user_id,
        "recipient_email": row.recipient_email,
        "subject": row.subject,
        "body": row.body,
        "metadata": row.metadata,
    });
    let resp = client
        .post(format!("{}/v1/send", post_url.trim_end_matches('/')))
        .header("X-Sentin8-Env-Id", row.env_id.to_string())
        .json(&payload)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let n = mark_pushed(pool, row.env_id, row.id).await?;
            Ok(n > 0)
        }
        Ok(r) => {
            tracing::warn!(status = %r.status(), message_type = %row.message_type, "sys: post send rejected - will retry");
            Ok(false)
        }
        Err(e) => {
            tracing::warn!(error = %e, message_type = %row.message_type, "sys: post send failed - will retry");
            Ok(false)
        }
    }
}

/// Mark one row pushed under its env's context (same-transaction rule).
async fn mark_pushed(pool: &PgPool, env_id: Uuid, id: Uuid) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    set_context(&mut tx, env_id).await;
    let n = sqlx::query(
        "UPDATE post_outbox SET pushed = true, pushed_at = now() WHERE id = $1 AND pushed = false",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(n)
}

/// Set the tenant context on a transaction (transaction-local GUCs -
/// sys DESIGN §5 same-connection rule).
async fn set_context(conn: &mut PgConnection, env_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(conn)
        .await;
}
