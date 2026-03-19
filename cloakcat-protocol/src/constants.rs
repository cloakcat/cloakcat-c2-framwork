//! Protocol constants for health profile and endpoints.

pub const HEALTH_PROFILE_NAME: &str = "health_api";
pub const HEALTH_BASE_PATH: &str = "/api/health/metrics";
pub const HEALTH_USER_AGENT: &str = "HealthMonitor/1.3";

/// Chunk size for file transfers: 512 KB.
pub const CHUNK_SIZE: usize = 512 * 1024;

/// Maximum file size for a single transfer: 50 MB.
pub const MAX_TRANSFER_SIZE: usize = 50 * 1024 * 1024;
