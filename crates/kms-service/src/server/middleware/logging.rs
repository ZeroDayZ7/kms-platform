use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::Instrument;

const MAX_DEBUG_BODY_SIZE: usize = 1024 * 1024; // 1MB limit dla bufora debugowania

//#region request_id_for_request
fn request_id_for_request(request: &Request<Body>) -> String {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}
//#endregion

//#region http_logger
pub async fn http_logger(request: Request<Body>, next: Next) -> Response {
    let request_id = request_id_for_request(&request);
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    // Tworzymy Span - od tego momentu WSZYSTKIE logi z wewnątrz tego żądania będą miały doklejony request_id
    let span = tracing::info_span!(
        "http-request",
        request_id = %request_id,
        method = %method,
        path = %uri.path(),
    );

    async move {
        // Logowanie payloadu tylko w trybie DEBUG
        if tracing::enabled!(tracing::Level::DEBUG) {
            let (parts, body) = request.into_parts();

            let bytes = match to_bytes(body, MAX_DEBUG_BODY_SIZE).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::error!(error = %err, "Nie udało się odczytać body dla debuggera HTTP");
                    return next.run(Request::from_parts(parts, Body::empty())).await;
                }
            };

            let debug_message =
                format_debug_request(method.as_str(), uri.path(), &parts.headers, &bytes);
            tracing::debug!("{debug_message}");

            let request = Request::from_parts(parts, Body::from(bytes));
            let response = next.run(request).await;

            tracing::info!(
                status = response.status().as_u16(),
                latency_ms = start.elapsed().as_millis(),
                "finished processing request"
            );

            response
        } else {
            // Ścieżka szybka (Zero-Copy) dla trybu INFO / PRODUCTION
            let response = next.run(request).await;

            tracing::info!(
                status = response.status().as_u16(),
                latency_ms = start.elapsed().as_millis(),
                "finished processing request"
            );

            response
        }
    }
    .instrument(span)
    .await
}
//#endregion

//#region formatters
fn format_debug_request(method: &str, uri: &str, headers: &HeaderMap, body_bytes: &[u8]) -> String {
    let headers_formatted = if headers.is_empty() {
        "\n │   <NONE>".to_string()
    } else {
        headers
            .iter()
            .map(|(name, value)| {
                let val_str = value.to_str().unwrap_or("<BINARY_DATA>");
                format!("\n │   ├── {:<20} : {}", name.as_str(), val_str)
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let body_formatted = format_body_for_debug(body_bytes);

    format!(
        "\n┌── 🚀 [HTTP DEBUG INCOMING REQUEST] ──────────────────────────────────────────\n\
         │ 📌 Endpoint : {} {}\n\
         │ 📋 Headers  :{}\n\
         │ 📦 Payload  :{}\n\
         └──────────────────────────────────────────────────────────────────────────────",
        method, uri, headers_formatted, body_formatted
    )
}

fn format_body_for_debug(body_bytes: &[u8]) -> String {
    if body_bytes.is_empty() {
        "\n │   <EMPTY>".to_string()
    } else if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        match serde_json::to_string_pretty(&json_value) {
            Ok(pretty) => pretty
                .lines()
                .map(|line| format!("\n │   {}", line))
                .collect::<Vec<_>>()
                .join(""),
            Err(_) => format!("\n │   {}", String::from_utf8_lossy(body_bytes)),
        }
    } else {
        format!(
            "\n │   {}",
            String::from_utf8_lossy(body_bytes).replace('\n', "\n │   ")
        )
    }
}
//#endregion

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderMap, Request};

    #[test]
    fn request_id_uses_header_when_present() {
        let request = Request::builder()
            .uri("/ping")
            .header("x-request-id", "req-123")
            .body(Body::empty())
            .unwrap();

        assert_eq!(request_id_for_request(&request), "req-123");
    }

    #[test]
    fn request_id_is_generated_when_header_missing() {
        let request = Request::builder().uri("/ping").body(Body::empty()).unwrap();

        let request_id = request_id_for_request(&request);
        assert!(!request_id.trim().is_empty());
        assert_eq!(request_id.len(), 36);
    }

    #[test]
    fn debug_body_formatting_pretty_prints_json() {
        let body = br#"{"hello":"world","nested":{"enabled":true}}"#;
        let formatted = format_body_for_debug(body);

        assert!(formatted.contains("hello"));
        assert!(formatted.contains("world"));
        assert!(formatted.contains("enabled"));
        assert!(formatted.starts_with("\n │   {"));
    }

    #[test]
    fn debug_request_formatting_includes_headers_and_body() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());

        let formatted = format_debug_request("POST", "/api/v1/test", &headers, br#"{"ok":true}"#);

        assert!(formatted.contains("POST /api/v1/test"));
        assert!(formatted.contains("content-type"));
        assert!(formatted.contains("ok"));
    }
}
