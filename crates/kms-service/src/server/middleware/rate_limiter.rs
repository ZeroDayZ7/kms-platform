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
    pub fn new(settings: &Settings, limiter: Arc<dyn RateLimiter>) -> Self {
        let global_conf = GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(settings.rate_limit.global_per_second)
            .burst_size(settings.rate_limit.global_burst)
            .use_headers()
            .finish()
            .unwrap();

        let health_conf = GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(settings.rate_limit.health_per_second)
            .burst_size(settings.rate_limit.health_burst)
            .use_headers()
            .finish()
            .unwrap();

        let auth_conf = GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(settings.rate_limit.auth_per_second)
            .burst_size(settings.rate_limit.auth_burst)
            .use_headers()
            .finish()
            .unwrap();

        Self {
            global: GovernorLayer::new(Arc::new(global_conf)),
            health: GovernorLayer::new(Arc::new(health_conf)),
            auth: GovernorLayer::new(Arc::new(auth_conf)),
            rate_limiter: limiter,
        }
    }
    //# endregion
}
