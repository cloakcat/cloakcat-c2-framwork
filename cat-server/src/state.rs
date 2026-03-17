//! Application state and view types.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

/// Shared application state (DB pool).
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub shared_token: Vec<u8>,
    pub operator_token: String,
}

/// Operator view of an agent.
#[derive(Serialize)]
pub struct AgentView {
    pub agent_id: String,
    pub alias: Option<String>,
    pub platform: String,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
    pub profile_name: Option<String>,
    pub beacon_min_ms: Option<i32>,
    pub beacon_max_ms: Option<i32>,
    pub backoff_max_ms: Option<i32>,
    pub kill_after_hours: Option<i32>,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_version: Option<String>,
    pub ip_addrs: Option<String>,
}

impl From<crate::db::AgentRecord> for AgentView {
    fn from(a: crate::db::AgentRecord) -> Self {
        AgentView {
            agent_id: a.agent_id,
            alias: a.alias,
            platform: a.platform,
            last_seen_at: a.last_seen_at,
            note: a.note,
            profile_name: a.profile_name,
            beacon_min_ms: a.beacon_min_ms,
            beacon_max_ms: a.beacon_max_ms,
            backoff_max_ms: a.backoff_max_ms,
            kill_after_hours: a.kill_after_hours,
            hostname: a.hostname,
            username: a.username,
            os_version: a.os_version,
            ip_addrs: a.ip_addrs,
        }
    }
}

/// Operator view of a command result.
#[derive(Serialize, Clone)]
pub struct ResultView {
    pub agent_id: String,
    pub cmd_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub ts_ms: i64,
}
