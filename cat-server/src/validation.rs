//! Profile and request validation (e.g. health profile path/UA).

use axum::http::{self, HeaderMap};
use cloakcat_protocol::{HEALTH_BASE_PATH, HEALTH_PROFILE_NAME, HEALTH_USER_AGENT};

use crate::error::ServerError;

/// Validates health profile requests (path prefix and User-Agent).
pub fn validate_profile(
    profile_name: Option<&str>,
    path: &str,
    headers: &HeaderMap,
) -> Result<(), ServerError> {
    if profile_name == Some(HEALTH_PROFILE_NAME) {
        if !path.starts_with(HEALTH_BASE_PATH) {
            return Err(ServerError::Forbidden("bad_profile_path".into()));
        }
        let ua_ok = headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v == HEALTH_USER_AGENT)
            .unwrap_or(false);
        if !ua_ok {
            return Err(ServerError::Forbidden("bad_user_agent".into()));
        }
    }
    Ok(())
}
