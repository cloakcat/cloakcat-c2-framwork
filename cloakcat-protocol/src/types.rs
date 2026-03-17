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

