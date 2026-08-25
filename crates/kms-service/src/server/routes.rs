use crate::handlers::{admin, crypto, health, keys};
use crate::server::middleware::{self, RateLimitLayers};
use crate::server::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};

//#region router
pub fn router(state: AppState) -> Router {
    let cors = middleware::create_cors_layer(&state.settings);
    let security = middleware::create_security_headers_layer().into_inner();
    let rate_limits = RateLimitLayers::new(&state.settings, state.rate_limiter.clone());

    let redis_mw = axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::redis_rate_limit_middleware,
    );

    let enable_rewrap = state.settings.crypto.enable_http_rewrap;

    let mut router = Router::new()
        .route(
            "/health",
            get(health::health).layer(rate_limits.health.clone()),
        )
        .route(
            "/status",
            get(health::status).layer(rate_limits.health.clone()),
        )
        .route(
            "/api/v1/keys/generate",
            post(keys::generate_key_handler).layer(rate_limits.auth.clone()),
        )
        .route(
            "/api/v1/keys/generate-data-key",
            post(keys::generate_data_key_handler).layer(rate_limits.auth.clone()),
        )
        .route(
            "/api/v1/keys/public/{service_id}/{algorithm}",
            get(keys::get_public_key_handler).layer(rate_limits.health.clone()),
        )
        .route(
            "/api/v1/keys/rotate",
            post(keys::rotate_key_handler).layer(rate_limits.auth.clone()),
        )
        .route(
            "/api/v1/keys/symmetric",
            post(keys::get_symmetric_key_handler).layer(rate_limits.auth.clone()),
        )
        .route(
            "/api/v1/keys/sign",
            post(crypto::sign_data_handler).layer(rate_limits.auth.clone()),
        )
        .route(
            "/api/v1/encrypt",
            post(crypto::encrypt_handler).layer(rate_limits.auth.clone()),
        )
        .route(
            "/api/v1/decrypt",
            post(crypto::decrypt_handler).layer(rate_limits.auth.clone()),
        );

    if enable_rewrap {
        router = router.route(
            "/api/v1/admin/kms/rewrap",
            post(admin::rewrap_keys_handler).layer(rate_limits.auth.clone()),
        );
    }

    router
        .route_layer(rate_limits.global.clone())
        .layer(redis_mw)
        .layer(security)
        .layer(cors)
        .layer(middleware::http_trace_layer())
        .with_state(state)
}
