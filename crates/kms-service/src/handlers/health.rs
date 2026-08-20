use crate::server::state::AppState;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use mongodb::bson::doc;
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    database: &'static str,
    redis: &'static str,
    kms: &'static str,
}

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let check_timeout = Duration::from_secs(2);

    let db_res = timeout(check_timeout, state.db.run_command(doc! {"ping": 1})).await;

    let redis_status = match state.redis_manager.as_ref() {
        Some(redis) => match timeout(check_timeout, redis.ping()).await {
            Ok(Ok(_)) => "ok",
            Ok(Err(_)) => "error",
            Err(_) => "error",
        },
        None => {
            if state.settings.redis.enabled {
                "error"
            } else {
                "disabled"
            }
        }
    };

    let db_status = match db_res {
        Ok(Ok(_)) => "ok",
        _ => "error",
    };

    let kms_status = "ready";
    let is_ok = db_status == "ok" && (redis_status == "ok" || redis_status == "disabled");

    let status_code = if is_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(HealthResponse {
            status: if is_ok { "ok" } else { "degraded" },
            database: db_status,
            redis: redis_status,
            kms: kms_status,
        }),
    )
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
}

pub async fn status(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(StatusResponse { status: "READY" }))
}
