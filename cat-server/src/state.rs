//! Application state and view types.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use cloakcat_protocol::DerivedKeys;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};

/// Shared application state (DB pool + command notification).
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// HKDF-derived keys from SHARED_TOKEN (auth + signing).
    pub derived_keys: DerivedKeys,
    pub operator_token: String,
    /// Per-agent notification: poll_command waits, push_command notifies.
    pub cmd_notify: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
}

impl AppState {
    /// Get or create a Notify handle for an agent.
    pub async fn get_notify(&self, agent_id: &str) -> Arc<Notify> {
        let mut map = self.cmd_notify.lock().await;
        map.entry(agent_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }
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
