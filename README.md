# https://docs.rs/crate/waf-middleware/latest

# WAF Middleware for Rust


A robust Web Application Firewall (WAF) middleware for `axum` and `actix-web`, powered by OWASP Core Rule Set (CRS) patterns. It provides protection against common web attacks like SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), and more.

## Features


- **OWASP CRS Rules**: Automatically parses and compiles rules from the official OWASP Core Rule Set.
- **Paranoia Levels**: Supports Paranoia Levels 1-4 for adjustable security vs. false-positive balance.
- **Anomaly Scoring**: Uses a scoring system to decide whether to block requests (default threshold is 10).
- **Fine-grained Control**: Enable/disable specific attack categories or individual rule IDs.
- **Multi-Framework Support**: First-class support for both `axum` and `actix-web`.

## Installation


Add this to your `Cargo.toml`:

```toml
[dependencies]
waf-middleware = { path = "../waf-middleware" } # Or your repository link
```

Choose your framework features:
```toml
# For Axum only

waf-middleware = { version = "0.1", default-features = false, features = ["axum"] }

# For Actix-web only

waf-middleware = { version = "0.1", default-features = false, features = ["actix-web"] }
```

## Usage


### Axum Example


```rust
use axum::{routing::get, Router};
use waf_middleware::WafMiddlewareBuilder;
use std::net::SocketAddr;

#[tokio::main]

async fn main() {
    // Create WAF layer using the builder
    let waf_layer = WafMiddlewareBuilder::new()
        .with_threshold(10)          // Block if anomaly score >= 10
        .with_paranoia_level(1)      // Standard protection
        .with_sqli(true)             // Enable SQL Injection protection
        .with_xss(true)              // Enable XSS protection
        .build_axum_layer();

    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .layer(waf_layer);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

### Actix-web Example


```rust
use actix_web::{web, App, HttpServer, Responder};
use waf_middleware::WafMiddlewareBuilder;

async fn index() -> impl Responder {
    "Hello, secure world!"
}

#[actix_web::main]

async fn main() -> std::io::Result<()> {
    // Create WAF middleware using the builder
    let waf_middleware = WafMiddlewareBuilder::new()
        .with_threshold(15)          // Slightly more relaxed threshold
        .with_paranoia_level(2)      // Higher paranoia level
        .with_initialization(true)
        .build_actix_middleware();

    HttpServer::new(move || {
        App::new()
            .wrap(waf_middleware.clone()) // Add WAF to the pipeline
            .service(web::resource("/").to(index))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

### Manual Usage (No Framework)


You can also use the WafEngine manually for custom integrations or testing:

```rust
use waf_middleware::{WafMiddlewareBuilder, WafEngine};
use std::collections::HashMap;

fn main() {
    // 1. Create your configuration
    let config = WafMiddlewareBuilder::new()
        .with_paranoia_level(2)
        .build();

    // 2. Prepare request data
    let path = "/api/search";
    let query = "q=1' OR '1'='1";
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
    
    // 3. Manually analyze the request
    let (score, matched_rules) = WafEngine::analyze_request(
        path,
        query,
        &headers,
        None, // Body
        &config,
    );

    if score >= config.threshold {
        println!("Blocked! Score: {}, Rules: {:?}", score, matched_rules);
    }
}
```

## Advanced Configuration


The `WafMiddlewareBuilder` allows you to customize exactly how the WAF behaves:

```rust
let config = WafMiddlewareBuilder::new()
    // Set global threshold for blocking
    .with_threshold(20)
    
    // Set Paranoia Level (1-4)
    // 1: Low false positives (Default)
    // 2: Better protection, some false positives
    // 3: High protection, more false positives
    // 4: Extreme protection
    .with_paranoia_level(2)
    
    // Toggle attack categories
    .with_sqli(true)
    .with_xss(true)
    .with_lfi(true)
    .with_rce(true)
    .with_php(false)  // Disable PHP specific rules if not using PHP
    .with_java(false)
    
    // Enable/Disable specific rules by ID
    .disable_rule("941110") // Disable a specific noisy XSS rule
    .enable_rule("942100")  // Explicitly ensure a rule is enabled
    
    .build();
```

## Attack Categories Supported


- `sqli`: SQL Injection
- `xss`: Cross-Site Scripting
- `lfi`: Local File Inclusion
- `rfi`: Remote File Inclusion
- `rce`: Remote Code Execution
- `php`: PHP Injection
- `java`: Java Injection
- `initialization`: CRS Initialization rules
- `protocol_enforcement`: HTTP Protocol Enforcement
- `scanner_detection`: Detection of known scanners/bots
- `data_leakage`: Detection of sensitive data in responses
- `web_shells`: Detection of common web shell signatures

## Performance


The rules are pre-parsed and compiled into optimized Regular Expressions using `fancy-regex` during the build process. Body inspection is currently supported for `axum` (JSON and Text payloads), while `actix-web` primarily focuses on Path, Query, and Header inspection in the current version.

## License


This project is licensed under the MIT License.
