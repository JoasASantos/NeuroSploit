//! Import an API collection as a test surface.
//!
//! An operator often already has the API mapped — a Postman collection, an
//! OpenAPI/Swagger spec, or a HAR capture from the browser. Rather than make
//! recon re-discover those endpoints (and maybe miss the undocumented or
//! auth-gated ones), we parse the collection into a flat endpoint list and
//! inject it into the engagement as known surface, so every agent tests exactly
//! those routes.
//!
//! Supported inputs (auto-detected by shape), JSON only:
//!   - Postman Collection v2.x  (`info` + `item[]`, nested folders allowed)
//!   - OpenAPI 3.x / Swagger 2.0 (`openapi`/`swagger` + `paths{}`)
//!   - HAR 1.2                  (`log.entries[].request`)
//!
//! YAML OpenAPI is not parsed here (no YAML dependency) — convert to JSON first.

use anyhow::{anyhow, Result};
use serde_json::Value;

/// One endpoint recovered from a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedEndpoint {
    pub method: String,
    pub url: String,
    /// Short human hint (summary / body content-type / folder), may be empty.
    pub note: String,
}

/// Which collection format a JSON document is, by shape.
fn detect(v: &Value) -> &'static str {
    if v.get("log").and_then(|l| l.get("entries")).is_some() {
        "har"
    } else if v.get("openapi").is_some() || v.get("swagger").is_some() {
        "openapi"
    } else if v.get("item").is_some() || v.get("info").is_some() {
        "postman"
    } else {
        "unknown"
    }
}

/// Parse a collection file into a de-duplicated endpoint list.
pub fn parse_file(path: &str) -> Result<Vec<SeedEndpoint>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("cannot read collection '{path}': {e}"))?;
    parse_str(&raw)
}

/// Parse a collection from a JSON string.
pub fn parse_str(raw: &str) -> Result<Vec<SeedEndpoint>> {
    let v: Value = serde_json::from_str(raw.trim())
        .map_err(|e| anyhow!("collection is not valid JSON (YAML specs must be converted to JSON first): {e}"))?;
    let mut out = match detect(&v) {
        "har" => from_har(&v),
        "openapi" => from_openapi(&v),
        "postman" => from_postman(&v),
        _ => return Err(anyhow!("unrecognised collection format — expected a Postman collection, an OpenAPI/Swagger spec, or a HAR capture (JSON)")),
    };
    dedup(&mut out);
    if out.is_empty() {
        return Err(anyhow!("no endpoints found in the collection"));
    }
    Ok(out)
}

fn dedup(items: &mut Vec<SeedEndpoint>) {
    let mut seen = std::collections::HashSet::new();
    items.retain(|e| seen.insert((e.method.clone(), e.url.clone())));
}

// ---- Postman v2.x --------------------------------------------------------

fn from_postman(v: &Value) -> Vec<SeedEndpoint> {
    // Collection variables (incl. the common {{baseUrl}}) for substitution.
    let mut vars = std::collections::HashMap::new();
    if let Some(arr) = v.get("variable").and_then(|x| x.as_array()) {
        for it in arr {
            if let (Some(k), Some(val)) = (it.get("key").and_then(|x| x.as_str()), it.get("value").and_then(|x| x.as_str())) {
                vars.insert(k.to_string(), val.to_string());
            }
        }
    }
    let mut out = Vec::new();
    if let Some(items) = v.get("item").and_then(|x| x.as_array()) {
        for it in items {
            walk_postman(it, &vars, &mut out);
        }
    }
    out
}

fn walk_postman(item: &Value, vars: &std::collections::HashMap<String, String>, out: &mut Vec<SeedEndpoint>) {
    // A folder has its own `item[]`; recurse.
    if let Some(children) = item.get("item").and_then(|x| x.as_array()) {
        for c in children {
            walk_postman(c, vars, out);
        }
        return;
    }
    let Some(req) = item.get("request") else { return };
    let method = req.get("method").and_then(|x| x.as_str()).unwrap_or("GET").to_uppercase();
    let url = postman_url(req.get("url"), vars);
    if url.is_empty() {
        return;
    }
    let note = item.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
    out.push(SeedEndpoint { method, url: subst_vars(&url, vars), note });
}

fn postman_url(url: Option<&Value>, vars: &std::collections::HashMap<String, String>) -> String {
    match url {
        Some(Value::String(s)) => s.clone(),
        Some(o @ Value::Object(_)) => {
            if let Some(raw) = o.get("raw").and_then(|x| x.as_str()) {
                return raw.to_string();
            }
            // Reconstruct host + path when `raw` is absent.
            let host = join_parts(o.get("host"), ".");
            let path = join_parts(o.get("path"), "/");
            let scheme = o.get("protocol").and_then(|x| x.as_str()).unwrap_or("https");
            if host.is_empty() { return String::new(); }
            let _ = vars;
            format!("{scheme}://{host}/{path}")
        }
        _ => String::new(),
    }
}

fn join_parts(v: Option<&Value>, sep: &str) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(sep),
        _ => String::new(),
    }
}

fn subst_vars(s: &str, vars: &std::collections::HashMap<String, String>) -> String {
    let mut out = s.to_string();
    for (k, val) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), val);
    }
    out
}

// ---- OpenAPI 3.x / Swagger 2.0 ------------------------------------------

fn from_openapi(v: &Value) -> Vec<SeedEndpoint> {
    // Base URL: OpenAPI 3 `servers[0].url`, or Swagger 2 `schemes`+`host`+`basePath`.
    let base = v.get("servers")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("url"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let scheme = v.get("schemes").and_then(|x| x.as_array()).and_then(|a| a.first()).and_then(|x| x.as_str()).unwrap_or("https");
            let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("");
            let bp = v.get("basePath").and_then(|x| x.as_str()).unwrap_or("");
            if host.is_empty() { String::new() } else { format!("{scheme}://{host}{bp}") }
        });
    let base = base.trim_end_matches('/').to_string();
    const METHODS: [&str; 7] = ["get", "post", "put", "patch", "delete", "head", "options"];
    let mut out = Vec::new();
    if let Some(paths) = v.get("paths").and_then(|x| x.as_object()) {
        for (path, ops) in paths {
            let Some(ops) = ops.as_object() else { continue };
            for (m, op) in ops {
                if !METHODS.contains(&m.to_lowercase().as_str()) {
                    continue;
                }
                let note = op.get("summary").or_else(|| op.get("operationId")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let url = if base.is_empty() { path.clone() } else { format!("{base}{path}") };
                out.push(SeedEndpoint { method: m.to_uppercase(), url, note });
            }
        }
    }
    out
}

// ---- HAR 1.2 -------------------------------------------------------------

fn from_har(v: &Value) -> Vec<SeedEndpoint> {
    let mut out = Vec::new();
    if let Some(entries) = v.pointer("/log/entries").and_then(|x| x.as_array()) {
        for e in entries {
            let Some(req) = e.get("request") else { continue };
            let method = req.get("method").and_then(|x| x.as_str()).unwrap_or("GET").to_uppercase();
            let url = req.get("url").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if url.is_empty() {
                continue;
            }
            let note = req.get("postData").and_then(|p| p.get("mimeType")).and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(SeedEndpoint { method, url, note });
        }
    }
    out
}

// ---- rendering -----------------------------------------------------------

/// Render the endpoint list as a prompt block injected into every agent, so the
/// imported surface is tested directly. Capped so a huge collection can't blow
/// the context budget.
pub fn render_block(endpoints: &[SeedEndpoint], cap: usize) -> String {
    if endpoints.is_empty() {
        return String::new();
    }
    let shown = endpoints.len().min(cap);
    let mut s = String::new();
    s.push_str(&format!(
        "IMPORTED API SURFACE — the operator supplied {} known endpoint(s) from an API collection (Postman/OpenAPI/HAR). TEST EVERY ONE of these in addition to what recon finds; they are in scope and often include undocumented or auth-gated routes recon would miss:\n",
        endpoints.len()
    ));
    for e in endpoints.iter().take(cap) {
        if e.note.trim().is_empty() {
            s.push_str(&format!("  - {} {}\n", e.method, e.url));
        } else {
            s.push_str(&format!("  - {} {}  ({})\n", e.method, e.url, e.note.trim()));
        }
    }
    if endpoints.len() > shown {
        s.push_str(&format!("  … and {} more (see the collection file)\n", endpoints.len() - shown));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_postman_v21_with_folders_and_vars() {
        let raw = r#"{
          "info": {"name": "api"},
          "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
          "item": [
            {"name": "Auth", "item": [
              {"name": "login", "request": {"method": "POST", "url": {"raw": "{{baseUrl}}/api/auth/login"}}}
            ]},
            {"name": "search", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/api/search?q=x"}}}
          ]
        }"#;
        let eps = parse_str(raw).unwrap();
        assert_eq!(eps.len(), 2);
        assert!(eps.iter().any(|e| e.method == "POST" && e.url == "https://api.example.com/api/auth/login"));
        assert!(eps.iter().any(|e| e.method == "GET" && e.url == "https://api.example.com/api/search?q=x"));
    }

    #[test]
    fn parses_openapi3() {
        let raw = r#"{
          "openapi": "3.0.0",
          "servers": [{"url": "https://api.example.com/v1"}],
          "paths": {
            "/users": {"get": {"summary": "list"}, "post": {"operationId": "create"}},
            "/users/{id}": {"delete": {}}
          }
        }"#;
        let eps = parse_str(raw).unwrap();
        assert_eq!(eps.len(), 3);
        assert!(eps.iter().any(|e| e.method == "GET" && e.url == "https://api.example.com/v1/users"));
        assert!(eps.iter().any(|e| e.method == "DELETE" && e.url == "https://api.example.com/v1/users/{id}"));
    }

    #[test]
    fn parses_swagger2() {
        let raw = r#"{
          "swagger": "2.0",
          "host": "api.example.com",
          "basePath": "/v2",
          "schemes": ["https"],
          "paths": {"/ping": {"get": {}}}
        }"#;
        let eps = parse_str(raw).unwrap();
        assert_eq!(eps, vec![SeedEndpoint { method: "GET".into(), url: "https://api.example.com/v2/ping".into(), note: String::new() }]);
    }

    #[test]
    fn parses_har_and_dedups() {
        let raw = r#"{"log": {"entries": [
          {"request": {"method": "GET", "url": "https://api.example.com/a"}},
          {"request": {"method": "GET", "url": "https://api.example.com/a"}},
          {"request": {"method": "POST", "url": "https://api.example.com/b", "postData": {"mimeType": "application/json"}}}
        ]}}"#;
        let eps = parse_str(raw).unwrap();
        assert_eq!(eps.len(), 2, "duplicate GET /a collapses");
    }

    #[test]
    fn rejects_unknown_and_empty() {
        assert!(parse_str(r#"{"hello": "world"}"#).is_err());
        assert!(parse_str(r#"{"openapi": "3.0.0", "paths": {}}"#).is_err());
        assert!(parse_str("not json").is_err());
    }

    #[test]
    fn render_caps_long_lists() {
        let eps: Vec<SeedEndpoint> = (0..300).map(|i| SeedEndpoint { method: "GET".into(), url: format!("https://x/{i}"), note: String::new() }).collect();
        let block = render_block(&eps, 200);
        assert!(block.contains("300 known endpoint"));
        assert!(block.contains("and 100 more"));
    }
}
