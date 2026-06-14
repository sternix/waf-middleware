use crate::config::WafConfig;
use crate::engine::WafEngine;
use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub async fn waf_middleware(
    config: Arc<WafConfig>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !config.enabled {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();

    let headers_map: std::collections::HashMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("[invalid]").to_string(),
            )
        })
        .collect();

    // Skip WAF for OPTIONS requests
    if request.method() == "OPTIONS" {
        return Ok(next.run(request).await);
    }

    let content_type = headers_map.get("content-type").cloned().unwrap_or_default();
    let content_length = headers_map
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let (parts, body) = request.into_parts();
    let mut body_str_owned = None;
    let final_body;

    if (content_type.contains("application/json") || content_type.contains("text/plain"))
        && content_length > 0
        && content_length < 64 * 1024
    {
        let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
            Ok(bytes) => bytes,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };

        if let Ok(s) = std::str::from_utf8(&bytes) {
            body_str_owned = Some(s.to_string());
        }
        final_body = Body::from(bytes);
    } else {
        final_body = body;
    }

    let (total_score, matched_rules) = WafEngine::analyze_request(
        &path,
        &query,
        &headers_map,
        body_str_owned.as_deref(),
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
            return Ok(Response::builder()
                .status(
                    StatusCode::from_u16(custom_res.status_code).unwrap_or(StatusCode::FORBIDDEN),
                )
                .header(header::CONTENT_TYPE, &custom_res.content_type)
                .body(Body::from(custom_res.body.clone()))
                .unwrap());
        }

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(
                "<h1>403 Forbidden</h1><p>Request blocked by WAF</p>",
            ))
            .unwrap());
    }

    if total_score > 0 {
        tracing::info!(
            "WAF: Request at {} has anomaly score {} (Rules: {:?})",
            path,
            total_score,
            matched_rules
        );
    }

    let request = Request::from_parts(parts, final_body);
    Ok(next.run(request).await)
}
