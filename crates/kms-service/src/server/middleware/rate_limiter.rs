use crate::config::Settings;
use crate::domain::rate_limiter::RateLimiter;
use axum::body::Body;
use governor::middleware::StateInformationMiddleware;
use std::sync::Arc;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

type AxumGovernorLayer = GovernorLayer<SmartIpKeyExtractor, StateInformationMiddleware, Body>;

#[derive(Clone)]
pub struct RateLimitLayers {
    pub global: AxumGovernorLayer,
    pub health: AxumGovernorLayer,
    pub auth: AxumGovernorLayer,
    pub rate_limiter: Arc<dyn RateLimiter>,
}

impl RateLimitLayers {
    //# region new
    //#region new
    pub fn new(settings: &Settings, limiter: Arc<dyn RateLimiter>) -> Self {
        let build_config = |label: &str,
                            per_second: u64,
                            burst_size: u32|
         -> tower_governor::governor::GovernorConfig<
            SmartIpKeyExtractor,
            StateInformationMiddleware,
        > {
            let config = GovernorConfigBuilder::default()
                .key_extractor(SmartIpKeyExtractor)
                .per_second(per_second)
                .burst_size(burst_size)
                .use_headers()
                .finish();

            if let Some(config) = config {
                return config;
            }

            tracing::error!(
                label = label,
                per_second,
                burst_size,
                "Invalid governor rate-limit config; using conservative fallback"
            );

            // This fallback is intentionally conservative and guaranteed to be valid for the
            // builder configuration used here. It avoids panic-driven handling while preserving
            // service safety in a degraded operating mode.
            GovernorConfigBuilder::default()
                .key_extractor(SmartIpKeyExtractor)
                .per_second(1)
                .burst_size(1)
                .use_headers()
                .finish()
                .unwrap_or_else(|| {
                    tracing::error!(
                        "Governor fallback config is invalid; aborting to preserve invariant safety"
                    );
                    std::process::abort();
                })
        };

        let global_conf = build_config(
            "global",
            settings.rate_limit.global_per_second,
            settings.rate_limit.global_burst,
        );
        let health_conf = build_config(
            "health",
            settings.rate_limit.health_per_second,
            settings.rate_limit.health_burst,
        );
        let auth_conf = build_config(
            "auth",
            settings.rate_limit.auth_per_second,
            settings.rate_limit.auth_burst,
        );

        Self {
            global: GovernorLayer::new(Arc::new(global_conf)),
            health: GovernorLayer::new(Arc::new(health_conf)),
            auth: GovernorLayer::new(Arc::new(auth_conf)),
            rate_limiter: limiter,
        }
    }
    //# endregion
}
