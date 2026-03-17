//! Profile and request validation (e.g. health profile path/UA).

use axum::{http::HeaderMap, Json};
use cloakcat_protocol::{HEALTH_BASE_PATH, HEALTH_PROFILE_NAME, HEALTH_USER_AGENT};

/// Validates health profile requests (path prefix and User-Agent).
/// Returns Some(Json) error response if validation fails.
pub fn validate_profile_request(
    profile: Option<&str>,
    path: &str,
    headers: &HeaderMap,
) -> Option<Json<serde_json::Value>> {
    if profile == Some(HEALTH_PROFILE_NAME) {
        let ua_ok = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v == HEALTH_USER_AGENT)
            .unwrap_or(false);
        if !path.starts_with(HEALTH_BASE_PATH) {
            return Some(Json(serde_json::json!({
                "status": "bad_profile_path"
            })));
        }
        if !ua_ok {
            return Some(Json(serde_json::json!({
                "status": "bad_user_agent"
            })));
        }
    }
    None
}
