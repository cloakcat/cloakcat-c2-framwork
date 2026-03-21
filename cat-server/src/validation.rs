//! Profile and request validation via ListenerProfile trait.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::{self, HeaderMap};
use cloakcat_protocol::{profile_by_name, ListenerProfile as _, MalleableProfile};

use crate::error::ServerError;

/// Validates that the request path and User-Agent match the agent's registered profile.
///
/// Checks loaded malleable profiles first (full path + UA validation), then falls
/// back to built-in profiles. The default/empty profile skips validation entirely.
pub fn validate_profile(
    profile_name: Option<&str>,
    path: &str,
    headers: &HeaderMap,
    profiles: &HashMap<String, Arc<MalleableProfile>>,
) -> Result<(), ServerError> {
    let name = profile_name.unwrap_or("default");
    let ua = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    // Prefer loaded malleable profiles — they carry full base_path + UA info.
    if let Some(mp) = profiles.get(name) {
        if !mp.validate(path, ua) {
            return Err(ServerError::Forbidden("profile_mismatch".into()));
        }
        return Ok(());
    }

    // Fall back to built-in profiles.
    let profile = profile_by_name(name);
    if profile.base_path().is_empty() && profile.user_agent().is_none() {
        // Default profile: allow everything.
        return Ok(());
    }
    if !profile.validate(path, ua) {
        return Err(ServerError::Forbidden("profile_mismatch".into()));
    }
    Ok(())
}
