use std::collections::HashMap;
use waf_middleware::{WafEngine, WafMiddlewareBuilder, WafRulesConfig};

#[test]
fn test_clonability() {
    let builder = WafMiddlewareBuilder::new();
    let _cloned_builder = builder.clone();

    #[cfg(feature = "actix-web")]
    {
        let transform = builder.build_actix_middleware();
        let _cloned_transform = transform.clone();
    }
}

#[test]
fn test_sql_injection_detection() {
    let config = WafMiddlewareBuilder::new().build();
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

    let malicious_query = "id=1' OR '1'='1";
    let (score, rules) =
        WafEngine::analyze_request("/api/users", malicious_query, &headers, None, &config);

    assert!(
        score >= 5,
        "Should detect SQL injection in query. Score: {}",
        score
    );
    assert!(
        rules
            .iter()
            .any(|r| r == "GENERIC-SQLI" || r.starts_with("942")),
        "Should match SQLi rules"
    );
}

#[test]
fn test_xss_detection() {
    let config = WafMiddlewareBuilder::new().build();
    let headers = HashMap::new();

    let malicious_body = r#"{"name": "<script>alert('xss')</script>"}"#;
    let (score, rules) =
        WafEngine::analyze_request("/api/submit", "", &headers, Some(malicious_body), &config);

    assert!(score >= 5, "Should detect XSS in body. Score: {}", score);
    assert!(
        rules.iter().any(|r| r.starts_with("941")),
        "Should match XSS rules"
    );
}

#[test]
fn test_path_traversal_detection() {
    let config = WafMiddlewareBuilder::new().build();
    let headers = HashMap::new();

    let malicious_path = "/../../etc/passwd";
    let (score, rules) = WafEngine::analyze_request(malicious_path, "", &headers, None, &config);

    assert!(
        score >= 5,
        "Should detect LFI/Path traversal. Score: {}",
        score
    );
    assert!(
        rules.iter().any(|r| r.starts_with("930")),
        "Should match LFI rules"
    );
}

#[test]
fn test_rule_disabling() {
    let mut rules_config = WafRulesConfig::default();
    rules_config.sqli = false; // Disable SQLi

    let config = WafMiddlewareBuilder::new().with_rules(rules_config).build();

    let headers = HashMap::new();
    let malicious_query = "id=1' OR '1'='1";

    let (score, rules) =
        WafEngine::analyze_request("/api/users", malicious_query, &headers, None, &config);

    assert_eq!(
        score, 0,
        "Score should be 0 when SQLi rules are disabled. Score: {}",
        score
    );
    assert!(
        rules.is_empty(),
        "Rules should be empty when SQLi is disabled"
    );
}

#[test]
fn test_paranoia_level_control() {
    let headers = HashMap::new();
    let malicious_payload = " onclick=alert(1)"; // Should be caught by 941120 at PL2

    // Case 1: PL1 (Default) - Should NOT catch it
    let config = WafMiddlewareBuilder::new().with_paranoia_level(1).build();
    let (_score, rules) =
        WafEngine::analyze_request("/api/test", "", &headers, Some(malicious_payload), &config);
    assert!(
        !rules.contains(&"941120".to_string()),
        "Rule 941120 should NOT trigger at PL1"
    );

    // Case 2: PL2 - Should catch it
    let config = WafMiddlewareBuilder::new().with_paranoia_level(2).build();
    let (score, rules) =
        WafEngine::analyze_request("/api/test", "", &headers, Some(malicious_payload), &config);
    assert!(
        rules.contains(&"941120".to_string()),
        "Rule 941120 SHOULD trigger at PL2"
    );
    assert!(score >= 5);
}
