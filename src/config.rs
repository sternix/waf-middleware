use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub enabled: bool,
    pub threshold: i32,
    pub rules: WafRulesConfig,
    pub blocked_response: Option<WafBlockedResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafBlockedResponse {
    pub status_code: u16,
    pub body: String,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRulesConfig {
    // Attack Categories
    pub lfi: bool,
    pub rfi: bool,
    pub rce: bool,
    pub php: bool,
    pub java: bool,
    pub generic: bool,
    pub xss: bool,
    pub sqli: bool,
    pub session: bool,

    // Protocol & Scanner
    pub protocol_enforcement: bool,
    pub protocol_attack: bool,
    pub scanner_detection: bool,
    pub initialization: bool,

    // Response / Data Leakage
    pub data_leakage: bool,
    pub web_shells: bool,

    pub paranoia_level: u8,

    // Fine-grained control
    pub enabled_rules: HashSet<String>,
    pub disabled_rules: HashSet<String>,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 10,
            rules: WafRulesConfig::default(),
            blocked_response: None,
        }
    }
}

impl Default for WafRulesConfig {
    fn default() -> Self {
        Self {
            lfi: true,
            rfi: true,
            rce: true,
            php: true,
            java: true,
            generic: true,
            xss: true,
            sqli: true,
            session: true,
            protocol_enforcement: true,
            protocol_attack: true,
            scanner_detection: true,
            initialization: true,
            data_leakage: true,
            web_shells: true,
            paranoia_level: 1,
            enabled_rules: HashSet::new(),
            disabled_rules: HashSet::new(),
        }
    }
}

impl WafRulesConfig {
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        // Individual rule overrides
        if self.enabled_rules.contains(rule_id) {
            return true;
        }
        if self.disabled_rules.contains(rule_id) {
            return false;
        }

        // Category toggles
        if rule_id.starts_with("901") {
            self.initialization
        } else if rule_id.starts_with("913") {
            self.scanner_detection
        } else if rule_id.starts_with("920") {
            self.protocol_enforcement
        } else if rule_id.starts_with("921") {
            self.protocol_attack
        } else if rule_id.starts_with("930") {
            self.lfi
        } else if rule_id.starts_with("931") {
            self.rfi
        } else if rule_id.starts_with("932") {
            self.rce
        } else if rule_id.starts_with("933") {
            self.php
        } else if rule_id.starts_with("934") {
            self.generic
        } else if rule_id.starts_with("941") {
            self.xss
        } else if rule_id.starts_with("942") || rule_id == "GENERIC-SQLI" {
            self.sqli
        } else if rule_id.starts_with("943") {
            self.session
        } else if rule_id.starts_with("944") {
            self.java
        } else if rule_id.starts_with("95") {
            self.data_leakage
        } else if rule_id.starts_with("955") {
            self.web_shells
        } else {
            true
        }
    }
}
