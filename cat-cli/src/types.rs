//! CLI-specific types (API response shapes).

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct AgentInfo {
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

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ResultItem {
    pub agent_id: String,
    pub cmd_id: String,
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
    pub ts_ms: i64,
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub context: serde_json::Value,
}

#[derive(Deserialize)]
pub struct TagsResponse {
    #[serde(default)]
    pub tags: Vec<String>,
}
