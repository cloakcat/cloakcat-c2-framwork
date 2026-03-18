//! Application state.

use std::collections::HashMap;
use std::sync::Arc;

use cloakcat_protocol::DerivedKeys;
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
