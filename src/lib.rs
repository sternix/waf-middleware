pub mod config;
pub mod engine;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix-web")]
pub mod actix;

pub use config::{WafBlockedResponse, WafConfig, WafRulesConfig};
pub use engine::WafEngine;

#[derive(Debug, Clone)]
pub struct WafMiddlewareBuilder {
    config: WafConfig,
}

impl Default for WafMiddlewareBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WafMiddlewareBuilder {
    pub fn new() -> Self {
        Self {
            config: WafConfig::default(),
        }
    }

    pub fn with_threshold(mut self, threshold: i32) -> Self {
        self.config.threshold = threshold;
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn with_blocked_response(
        mut self,
        status_code: u16,
        body: &str,
        content_type: &str,
    ) -> Self {
        self.config.blocked_response = Some(WafBlockedResponse {
            status_code,
            body: body.to_string(),
            content_type: content_type.to_string(),
        });
        self
    }

    pub fn with_rules(mut self, rules: WafRulesConfig) -> Self {
        self.config.rules = rules;
        self
    }

    pub fn with_sqli(mut self, enabled: bool) -> Self {
        self.config.rules.sqli = enabled;
        self
    }

    pub fn with_xss(mut self, enabled: bool) -> Self {
        self.config.rules.xss = enabled;
        self
    }

    pub fn with_lfi(mut self, enabled: bool) -> Self {
        self.config.rules.lfi = enabled;
        self
    }

    pub fn with_rfi(mut self, enabled: bool) -> Self {
        self.config.rules.rfi = enabled;
        self
    }

    pub fn with_rce(mut self, enabled: bool) -> Self {
        self.config.rules.rce = enabled;
        self
    }

    pub fn with_php(mut self, enabled: bool) -> Self {
        self.config.rules.php = enabled;
        self
    }

    pub fn with_generic_attack(mut self, enabled: bool) -> Self {
        self.config.rules.generic = enabled;
        self
    }

    pub fn with_java(mut self, enabled: bool) -> Self {
        self.config.rules.java = enabled;
        self
    }

    pub fn with_protocol_enforcement(mut self, enabled: bool) -> Self {
        self.config.rules.protocol_enforcement = enabled;
        self
    }

    pub fn with_protocol_attack(mut self, enabled: bool) -> Self {
        self.config.rules.protocol_attack = enabled;
        self
    }

    pub fn with_scanner_detection(mut self, enabled: bool) -> Self {
        self.config.rules.scanner_detection = enabled;
        self
    }

    pub fn with_initialization(mut self, enabled: bool) -> Self {
        self.config.rules.initialization = enabled;
        self
    }

    pub fn with_data_leakage(mut self, enabled: bool) -> Self {
        self.config.rules.data_leakage = enabled;
        self
    }

    pub fn with_web_shells(mut self, enabled: bool) -> Self {
        self.config.rules.web_shells = enabled;
        self
    }

    pub fn enable_rule(mut self, rule_id: &str) -> Self {
        self.config.rules.enabled_rules.insert(rule_id.to_string());
        self.config.rules.disabled_rules.remove(rule_id);
        self
    }

    pub fn disable_rule(mut self, rule_id: &str) -> Self {
        self.config.rules.disabled_rules.insert(rule_id.to_string());
        self.config.rules.enabled_rules.remove(rule_id);
        self
    }

    pub fn with_paranoia_level(mut self, level: u8) -> Self {
        self.config.rules.paranoia_level = level;
        self
    }

    pub fn build(self) -> WafConfig {
        self.config
    }

    #[cfg(feature = "axum")]
    pub fn build_axum_layer(
        self,
    ) -> ::axum::middleware::FromFnLayer<
        fn(
            ::std::sync::Arc<WafConfig>,
            ::axum::extract::Request,
            ::axum::middleware::Next,
        ) -> ::futures_util::future::BoxFuture<
            'static,
            Result<::axum::response::Response, ::axum::http::StatusCode>,
        >,
        ::std::sync::Arc<WafConfig>,
        (::std::sync::Arc<WafConfig>,),
    > {
        use ::axum::middleware::from_fn_with_state;
        use ::futures_util::FutureExt;
        use ::std::sync::Arc;
        let config = Arc::new(self.config);
        from_fn_with_state(config, |state, req, next| {
            crate::axum::waf_middleware(state, req, next).boxed()
        })
    }

    #[cfg(feature = "actix-web")]
    pub fn build_actix_middleware(self) -> crate::actix::WafTransform {
        crate::actix::WafTransform::new(self.config)
    }
}
