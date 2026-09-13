use crate::config::cors::AllowedOrigins;
use crate::config::{HttpMethod, Settings};
use axum::http::{HeaderValue, Method};
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

//#region create_cors_layer
pub fn create_cors_layer(settings: &Settings) -> CorsLayer {
    let mut layer = CorsLayer::new();

    // 1. Obsługa Originów (nowy enum)
    layer = match &settings.cors.allowed_origin {
        AllowedOrigins::Any => layer.allow_origin(Any),
        AllowedOrigins::Single(origin) => match origin.parse::<HeaderValue>() {
            Ok(value) => layer.allow_origin(value),
            Err(error) => {
                tracing::warn!(
                    origin = %origin,
                    error = %error,
                    "Invalid CORS origin configured; falling back to wildcard"
                );
                layer.allow_origin(Any)
            }
        },
        AllowedOrigins::List(origins) => {
            let header_values: Vec<HeaderValue> = origins
                .iter()
                .filter_map(|origin| match origin.parse::<HeaderValue>() {
                    Ok(value) => Some(value),
                    Err(error) => {
                        tracing::warn!(
                            origin = %origin,
                            error = %error,
                            "Ignoring invalid CORS origin in configured list"
                        );
                        None
                    }
                })
                .collect();

            if header_values.is_empty() {
                layer.allow_origin(Any)
            } else {
                layer.allow_origin(header_values)
            }
        }
    };

    // 2. Obsługa Metod
    let methods: Vec<axum::http::Method> = settings
        .cors
        .allowed_methods
        .iter()
        .map(|m| match m {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Options => Method::OPTIONS,
        })
        .collect();

    layer
        .allow_methods(methods)
        .allow_headers(Any)
        .max_age(Duration::from_secs(settings.cors.max_age))
}
