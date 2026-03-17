//! API key authentication middleware for operator routes.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use subtle::ConstantTimeEq;

use crate::state::AppState;

pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get("X-Operator-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = &state.operator_token;
    let ct_match: bool = expected.as_bytes().ct_eq(token.as_bytes()).into();
    if expected.is_empty() || !ct_match {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"status":"unauthorized"})),
        )
            .into_response();
    }
    next.run(req).await
}
