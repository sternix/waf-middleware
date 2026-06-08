use std::path::Path;
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=src/rules");

    generate_waf_rules();
}

fn generate_waf_rules() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("waf_rules_generated.rs");
    
    let waf_rules_dir = Path::new("src/rules");
    if !waf_rules_dir.exists() {
        fs::write(&dest_path, "pub static GENERATED_CRS_RULES: &[(&str, &str)] = &[];").unwrap();
        return;
    }

    let mut generated_code = String::from("pub static GENERATED_CRS_RULES: &[(&str, &str, u8)] = &[\n");

    let mut entries: Vec<_> = fs::read_dir(waf_rules_dir).unwrap()
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
            generated_code.push_str(&format!("    (\"{}\", \"{}\", {}),\n", id, escaped_regex, paranoia_level));
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
