//! Router and route registration.

use axum::{routing::{get, post}, Router};

use crate::handlers;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/ping", get(handlers::ping_handler))
        .route("/register", post(handlers::register_handler))
        .route("/poll/{agent_id}", get(handlers::poll_handler))
        .route("/result/{agent_id}", post(handlers::result_handler))
        .route("/api/health/metrics/register", post(handlers::register_handler))
        .route("/api/health/metrics/poll/{agent_id}", get(handlers::poll_handler))
        .route("/api/health/metrics/result/{agent_id}", post(handlers::result_handler));

    let protected_routes = Router::new()
        .route("/command/{agent_id}", post(handlers::push_command_handler))
        .route("/admin/agents", get(handlers::admin_agents))
        .route(
            "/admin/agents/{agent_id}/alias",
            post(handlers::admin_update_agent_alias),
        )
        .route("/admin/results", get(handlers::admin_results))
        .route("/admin/audit", get(handlers::admin_audit))
        .route("/admin/agents/{agent_id}/tags", get(handlers::admin_agent_tags))
        .route("/admin/agents/{agent_id}/tags", post(handlers::admin_set_agent_tags))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth_middleware,
        ));

    public_routes
        .merge(protected_routes)
        .with_state(state)
}
