use crate::config::WafConfig;
use crate::engine::WafEngine;
use actix_web::{
    Error, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use futures_util::FutureExt;
use futures_util::future::{Ready, ok};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct WafTransform {
    config: Arc<WafConfig>,
}

impl WafTransform {
    pub fn new(config: WafConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for WafTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = WafMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(WafMiddleware {
            service: Rc::new(service),
            config: self.config.clone(),
        })
    }
}

pub struct WafMiddleware<S> {
    service: Rc<S>,
    config: Arc<WafConfig>,
}

impl<S, B> Service<ServiceRequest> for WafMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future =
        futures_util::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let config = self.config.clone();

        async move {
            if !config.enabled {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            let path = req.path().to_string();
            let query = req.query_string().to_string();

            let mut headers_map = HashMap::new();
            for (header_name, header_value) in req.headers() {
                headers_map.insert(
                    header_name.as_str().to_lowercase(),
                    header_value.to_str().unwrap_or("[invalid]").to_string(),
                );
            }

            if req.method() == actix_web::http::Method::OPTIONS {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // For actix-web, reading the body in middleware is tricky because it's a stream.
            // Simplified version here only checks path, query and headers for now.
            // Body check would require buffering the entire body.

            let (total_score, matched_rules) = WafEngine::analyze_request(
                &path,
                &query,
                &headers_map,
                None, // Body check skipped in actix for now or requires more complexity
                &config,
            );

            if total_score >= config.threshold {
                let attack_types = WafEngine::get_attack_types(&matched_rules);
                tracing::warn!(
                    "WAF: Blocked malicious request at {} (Score: {}, Types: {}, Rules: {:?})",
                    path,
                    total_score,
                    attack_types,
                    matched_rules
                );

                if let Some(custom_res) = &config.blocked_response {
                    let status = actix_web::http::StatusCode::from_u16(custom_res.status_code)
                        .unwrap_or(actix_web::http::StatusCode::FORBIDDEN);
                    let res = HttpResponse::build(status)
                        .content_type(custom_res.content_type.clone())
                        .body(custom_res.body.clone());
                    return Ok(req.into_response(res).map_into_right_body());
                }

                let res = HttpResponse::Forbidden()
                    .content_type("text/html")
                    .body("<h1>403 Forbidden</h1><p>Request blocked by WAF</p>");

                return Ok(req.into_response(res).map_into_right_body());
            }

            if total_score > 0 {
                tracing::info!(
                    "WAF: Request at {} has anomaly score {} (Rules: {:?})",
                    path,
                    total_score,
                    matched_rules
                );
            }

            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        }
        .boxed_local()
    }
}
