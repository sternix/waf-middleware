use std::fs;
use std::path::Path;

fn main() {
    //println!("cargo:rerun-if-changed=src/rules");

    generate_waf_rules();
}

fn generate_waf_rules() {
    let dest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("waf_rules_generated.rs");

    let waf_rules_dir = Path::new("src/rules");
    /*
    if !waf_rules_dir.exists() {
        fs::write(
            &dest_path,
            "pub static GENERATED_CRS_RULES: &[(&str, &str)] = &[];",
        )
        .unwrap();
        return;
    }
     */

    let mut generated_code =
        String::from("pub static GENERATED_CRS_RULES: &[(&str, &str, u8)] = &[\n");

    let mut entries: Vec<_> = fs::read_dir(waf_rules_dir)
        .unwrap()
        .map(|res| res.unwrap().path())
        .filter(|path| path.extension().map_or(false, |ext| ext == "conf"))
        .collect();

    // Sort for deterministic build
    entries.sort();

    for file_path in entries {
        let content = fs::read_to_string(&file_path).unwrap();
        let rules = parse_crs_rules(&content);
        for (id, regex, paranoia_level) in rules {
            // Escape backslashes for Rust string literal
            let escaped_regex = regex.replace('\\', "\\\\").replace('"', "\\\"");
            generated_code.push_str(&format!(
                "    (\"{}\", \"{}\", {}),\n",
                id, escaped_regex, paranoia_level
            ));
        }
    }

    generated_code.push_str("];\n");
    fs::write(&dest_path, generated_code).unwrap();
}

fn parse_crs_rules(content: &str) -> Vec<(String, String, u8)> {
    let mut rules = Vec::new();
    let mut in_rule = false;
    let mut rule_buffer = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("SecRule") {
            if in_rule {
                if let Some(res) = process_rule_buffer(&rule_buffer) {
                    rules.push(res);
                }
            }
            in_rule = true;
            rule_buffer = line.to_string();
        } else if in_rule {
            rule_buffer.push(' ');
            rule_buffer.push_str(line.trim_end_matches('\\').trim());
        }

        if !line.ends_with('\\') && in_rule {
            if let Some(res) = process_rule_buffer(&rule_buffer) {
                rules.push(res);
            }
            in_rule = false;
            rule_buffer.clear();
        }
    }
    rules
}

fn process_rule_buffer(buffer: &str) -> Option<(String, String, u8)> {
    let mut current_id = String::new();
    if let Some(id_start) = buffer.find("id:") {
        let id_part = &buffer[id_start + 3..];
        current_id = id_part
            .chars()
            .take_while(|c| c.is_digit(10))
            .collect::<String>();
    }

    if current_id.is_empty() {
        return None;
    }

    let paranoia_level = if buffer.contains("paranoia-level/2") {
        2
    } else if buffer.contains("paranoia-level/3") {
        3
    } else if buffer.contains("paranoia-level/4") {
        4
    } else {
        1
    };

    if buffer.contains("pass,") || buffer.contains("pass\"") {
        return None;
    }

    if buffer.contains("chain") {
        return None;
    }

    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut current_part = String::new();
    let mut escaped = false;

    for c in buffer.chars() {
        if escaped {
            current_part.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
            current_part.push(c);
        } else if c == '"' {
            if in_quotes {
                parts.push(current_part.clone());
                current_part.clear();
            }
            in_quotes = !in_quotes;
        } else if in_quotes {
            current_part.push(c);
        }
    }

    for op_content in parts {
        if op_content.starts_with("@rx ") || op_content.starts_with("@rx") {
            let regex_str = if op_content.starts_with("@rx ") {
                &op_content[4..]
            } else {
                &op_content[3..]
            };

            let regex_str = regex_str.replace(r"\\", r"\");
            let final_regex = if regex_str.contains("(?i)") || regex_str.contains("(?is)") {
                regex_str.to_string()
            } else {
                format!("(?i){}", regex_str)
            };

            return Some((current_id, final_regex, paranoia_level));
        }

        if op_content.contains("@detectSQLi") {
            let sql_regex = r#"(?i)(?:(?:\'|\")\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|;)|(?:\'|\")\s*\d+\s*=\s*\d+|\b(?:union|select|insert|update|delete|drop|alter|create|truncate|exec|xp_cmdshell|benchmark|sleep)\b|;\s*\b(?:select|insert|update|delete|drop|union)\b)"#;
            return Some((current_id, sql_regex.to_string(), paranoia_level));
        }
    }
    None
}
