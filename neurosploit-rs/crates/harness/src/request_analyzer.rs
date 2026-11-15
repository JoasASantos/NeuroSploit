//! Request Analyzer — intelligent HTTP request/response understanding.
//!
//! Agents need to read HTTP exchanges the way a human pentester does: not as raw
//! text, but as structured intent. This module provides:
//!
//! 1. **Response diffing** — what changed between baseline and attack
//! 2. **Reflection detection** — where input appears in the response
//! 3. **Error fingerprinting** — what errors reveal about the stack
//! 4. **Parameter discovery** — finding hidden inputs from responses
//! 5. **Auth context analysis** — understanding session state from cookies/headers
//! 6. **Content-type aware parsing** — JSON, HTML, XML, multipart, GraphQL

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Analysis of an HTTP response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseAnalysis {
    pub status: u16,
    pub content_type: ContentType,
    pub body_length: usize,
    pub reflections: Vec<Reflection>,
    pub errors: Vec<ErrorSignal>,
    pub params_discovered: Vec<DiscoveredParam>,
    pub auth_context: AuthContext,
    pub security_headers: SecurityHeaders,
    pub interesting_headers: Vec<(String, String)>,
    pub technology_hints: Vec<TechHint>,
    pub timing_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentType {
    #[default]
    Unknown,
    Html,
    Json,
    Xml,
    JavaScript,
    Css,
    PlainText,
    FormUrlencoded,
    Multipart,
    GraphQL,
    Protobuf,
    Grpc,
    Pdf,
    Binary,
}

impl ContentType {
    pub fn from_header(ct: &str) -> Self {
        let lower = ct.to_lowercase();
        if lower.contains("html") { ContentType::Html }
        else if lower.contains("json") || lower.contains("graphql") { ContentType::Json }
        else if lower.contains("xml") || lower.contains("soap") { ContentType::Xml }
        else if lower.contains("javascript") || lower.contains("ecmascript") { ContentType::JavaScript }
        else if lower.contains("css") { ContentType::Css }
        else if lower.contains("text/plain") { ContentType::PlainText }
        else if lower.contains("urlencoded") { ContentType::FormUrlencoded }
        else if lower.contains("multipart") { ContentType::Multipart }
        else if lower.contains("protobuf") || lower.contains("grpc") { ContentType::Grpc }
        else if lower.contains("pdf") { ContentType::Pdf }
        else if lower.contains("octet-stream") || lower.contains("image/") { ContentType::Binary }
        else { ContentType::Unknown }
    }
}

/// Where and how user input appears in the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reflection {
    pub input: String,
    pub context: ReflectionContext,
    pub position: usize,
    pub encoded: bool,
    pub filtered: bool,
    pub surrounding: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReflectionContext {
    HtmlBody,
    HtmlAttribute,
    HtmlAttributeUnquoted,
    HtmlTag,
    HtmlComment,
    ScriptBlock,
    StyleBlock,
    JsonValue,
    JsonKey,
    XmlText,
    XmlAttribute,
    HttpHeader,
    UrlPath,
    UrlParam,
    PlainText,
}

impl ReflectionContext {
    /// Which XSS payload types are viable in this context.
    pub fn viable_payloads(&self) -> &'static [&'static str] {
        match self {
            ReflectionContext::HtmlBody => &["<script>", "<img", "<svg", "<details"],
            ReflectionContext::HtmlAttribute => &["\" onmouseover=", "' onfocus=", "\" autofocus onfocus="],
            ReflectionContext::HtmlAttributeUnquoted => &[" onmouseover=alert(1) ", " onfocus=alert(1) autofocus "],
            ReflectionContext::ScriptBlock => &["';alert(1)//", "\";alert(1)//", "-alert(1)-"],
            ReflectionContext::JsonValue => &["</script><script>alert(1)//"],
            ReflectionContext::HtmlComment => &["--><script>alert(1)</script><!--"],
            _ => &[],
        }
    }
}

/// An error message that reveals something about the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSignal {
    pub kind: ErrorKind,
    pub message: String,
    pub technology: String,
    pub version: String,
    pub file_path: String,
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorKind {
    SqlError,
    StackTrace,
    DebugInfo,
    FileNotFound,
    PermissionDenied,
    TemplateError,
    ValidationError,
    AuthError,
    RateLimitError,
    InternalError,
    FrameworkDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredParam {
    pub name: String,
    pub source: ParamSource,
    pub value_hint: String,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamSource {
    FormInput,
    HiddenInput,
    JsonKey,
    UrlInLink,
    JavaScriptVar,
    ApiDoc,
    ErrorMessage,
    Comment,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthContext {
    pub cookies: Vec<CookieInfo>,
    pub auth_header: Option<String>,
    pub csrf_token: Option<String>,
    pub session_type: SessionType,
    pub roles_detected: Vec<String>,
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionType {
    #[default]
    Unknown,
    JwtBearer,
    SessionCookie,
    BasicAuth,
    ApiKey,
    OAuth2,
    Saml,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: String,
    pub path: String,
    pub is_session: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub csp: Option<String>,
    pub hsts: bool,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub cors_origin: Option<String>,
    pub cors_credentials: bool,
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechHint {
    pub technology: String,
    pub version: String,
    pub source: String,
    pub confidence: f64,
}

/// Differential analysis between two responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub status_from: u16,
    pub status_to: u16,
    pub length_delta: i64,
    pub content_type_changed: bool,
    pub new_headers: Vec<(String, String)>,
    pub removed_headers: Vec<String>,
    pub body_similarity: f64,
    pub new_content: Vec<String>,
    pub removed_content: Vec<String>,
    pub timing_delta_ms: i64,
    pub verdict: DiffVerdict,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffVerdict {
    #[default]
    Identical,
    MinorChange,
    SignificantChange,
    DifferentResponse,
    ErrorInduced,
    WafTriggered,
}

/// Analyze an HTTP response body and headers.
pub fn analyze(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &str,
    inputs_to_track: &[&str],
    timing_ms: u64,
) -> ResponseAnalysis {
    let ct_str = headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
    let content_type = ContentType::from_header(ct_str);

    ResponseAnalysis {
        status,
        content_type,
        body_length: body.len(),
        reflections: find_reflections(body, inputs_to_track, content_type),
        errors: detect_errors(body, status),
        params_discovered: discover_params(body, content_type),
        auth_context: analyze_auth(headers),
        security_headers: analyze_security_headers(headers),
        interesting_headers: find_interesting_headers(headers),
        technology_hints: fingerprint_technology(headers, body),
        timing_ms,
    }
}

/// Compute the differential between a baseline and an attack response.
pub fn diff(
    baseline_status: u16,
    baseline_headers: &BTreeMap<String, String>,
    baseline_body: &str,
    baseline_timing: u64,
    attack_status: u16,
    attack_headers: &BTreeMap<String, String>,
    attack_body: &str,
    attack_timing: u64,
) -> ResponseDiff {
    let new_headers: Vec<(String, String)> = attack_headers.iter()
        .filter(|(k, v)| baseline_headers.get(*k) != Some(v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let removed_headers: Vec<String> = baseline_headers.keys()
        .filter(|k| !attack_headers.contains_key(*k))
        .cloned()
        .collect();

    let similarity = body_similarity(baseline_body, attack_body);

    let (new_content, removed_content) = content_diff(baseline_body, attack_body);

    let status_changed = baseline_status != attack_status;
    let length_delta = attack_body.len() as i64 - baseline_body.len() as i64;
    let timing_delta = attack_timing as i64 - baseline_timing as i64;

    let ct_changed = baseline_headers.get("content-type") != attack_headers.get("content-type");

    let verdict = if similarity > 0.99 && !status_changed {
        DiffVerdict::Identical
    } else if attack_status == 403 || attack_status == 406 || is_waf_body(attack_body) {
        DiffVerdict::WafTriggered
    } else if attack_status >= 500 && baseline_status < 500 {
        DiffVerdict::ErrorInduced
    } else if similarity < 0.5 || status_changed {
        DiffVerdict::DifferentResponse
    } else if similarity < 0.9 || length_delta.unsigned_abs() > 500 {
        DiffVerdict::SignificantChange
    } else {
        DiffVerdict::MinorChange
    };

    ResponseDiff {
        status_changed,
        status_from: baseline_status,
        status_to: attack_status,
        length_delta,
        content_type_changed: ct_changed,
        new_headers,
        removed_headers,
        body_similarity: similarity,
        new_content,
        removed_content,
        timing_delta_ms: timing_delta,
        verdict,
    }
}

/// Generate a prompt block summarizing the analysis for agent consumption.
pub fn prompt_block(analysis: &ResponseAnalysis) -> String {
    let mut s = String::new();

    if !analysis.reflections.is_empty() {
        s.push_str("REFLECTIONS DETECTED:\n");
        for r in &analysis.reflections {
            s.push_str(&format!("  Input '{}' reflected in {:?} context (encoded={}, filtered={})\n",
                truncate(&r.input, 40), r.context, r.encoded, r.filtered));
            let viable = r.context.viable_payloads();
            if !viable.is_empty() {
                s.push_str(&format!("    Viable payloads for this context: {}\n",
                    viable.iter().take(3).map(|p| truncate(p, 50)).collect::<Vec<_>>().join(", ")));
            }
        }
    }

    if !analysis.errors.is_empty() {
        s.push_str("ERROR SIGNALS:\n");
        for e in &analysis.errors {
            s.push_str(&format!("  {:?}: {} (tech={} ver={})\n",
                e.kind, truncate(&e.message, 80), e.technology, e.version));
        }
    }

    if !analysis.params_discovered.is_empty() {
        s.push_str("DISCOVERED PARAMETERS:\n");
        for p in &analysis.params_discovered {
            s.push_str(&format!("  {} (from {:?}, hint='{}')\n",
                p.name, p.source, truncate(&p.value_hint, 30)));
        }
    }

    if analysis.auth_context.session_type != SessionType::Unknown {
        s.push_str(&format!("AUTH: {:?}", analysis.auth_context.session_type));
        if let Some(ref csrf) = analysis.auth_context.csrf_token {
            s.push_str(&format!(", CSRF token present ({})", truncate(csrf, 20)));
        }
        s.push('\n');
    }

    if !analysis.security_headers.missing.is_empty() {
        s.push_str(&format!("MISSING SECURITY HEADERS: {}\n",
            analysis.security_headers.missing.join(", ")));
    }

    if !analysis.technology_hints.is_empty() {
        s.push_str("TECH FINGERPRINT:\n");
        for h in &analysis.technology_hints {
            s.push_str(&format!("  {} {} (from {}, conf={:.0}%)\n",
                h.technology, h.version, h.source, h.confidence * 100.0));
        }
    }

    s
}

/// Generate a diff summary for agent consumption.
pub fn diff_prompt_block(diff: &ResponseDiff) -> String {
    let mut s = String::from("RESPONSE DIFFERENTIAL:\n");
    s.push_str(&format!("  Verdict: {:?}\n", diff.verdict));
    if diff.status_changed {
        s.push_str(&format!("  Status: {} -> {}\n", diff.status_from, diff.status_to));
    }
    if diff.length_delta != 0 {
        s.push_str(&format!("  Body length delta: {:+} bytes\n", diff.length_delta));
    }
    s.push_str(&format!("  Similarity: {:.1}%\n", diff.body_similarity * 100.0));
    if diff.timing_delta_ms.unsigned_abs() > 1000 {
        s.push_str(&format!("  Timing delta: {:+}ms (possible time-based signal)\n", diff.timing_delta_ms));
    }
    if !diff.new_content.is_empty() {
        s.push_str("  New content in attack response:\n");
        for c in diff.new_content.iter().take(5) {
            s.push_str(&format!("    + {}\n", truncate(c, 100)));
        }
    }
    s
}

// ── Internal ──

fn find_reflections(body: &str, inputs: &[&str], ct: ContentType) -> Vec<Reflection> {
    let mut reflections = Vec::new();
    for &input in inputs {
        if input.is_empty() || input.len() < 3 { continue; }
        let lower_body = body.to_lowercase();
        let lower_input = input.to_lowercase();

        // Direct reflection
        let mut start = 0;
        while let Some(pos) = lower_body[start..].find(&lower_input) {
            let abs_pos = start + pos;
            let context = determine_context(body, abs_pos, ct);
            let surrounding = safe_slice(body, abs_pos.saturating_sub(30), abs_pos + input.len() + 30);
            reflections.push(Reflection {
                input: input.to_string(),
                context,
                position: abs_pos,
                encoded: false,
                filtered: false,
                surrounding,
            });
            start = abs_pos + 1;
            if reflections.len() > 20 { break; }
        }

        // URL-encoded reflection
        let encoded = input.replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        if encoded != input {
            if let Some(pos) = lower_body.find(&encoded.to_lowercase()) {
                let context = determine_context(body, pos, ct);
                reflections.push(Reflection {
                    input: input.to_string(),
                    context,
                    position: pos,
                    encoded: true,
                    filtered: true,
                    surrounding: safe_slice(body, pos.saturating_sub(30), pos + encoded.len() + 30),
                });
            }
        }
    }
    reflections
}

fn determine_context(body: &str, pos: usize, ct: ContentType) -> ReflectionContext {
    match ct {
        ContentType::Json => {
            let before = &body[..pos];
            if before.ends_with('"') || before.ends_with(':') {
                return ReflectionContext::JsonValue;
            }
            return ReflectionContext::JsonKey;
        }
        ContentType::Xml => {
            let before = &body[pos.saturating_sub(100)..pos];
            if before.contains('=') && (before.ends_with('"') || before.ends_with('\'')) {
                return ReflectionContext::XmlAttribute;
            }
            return ReflectionContext::XmlText;
        }
        _ => {}
    }

    let before = body[pos.saturating_sub(200)..pos].to_lowercase();

    if before.rfind("<script").map_or(false, |s| {
        before[s..].find("</script").is_none()
    }) {
        return ReflectionContext::ScriptBlock;
    }

    if before.rfind("<style").map_or(false, |s| {
        before[s..].find("</style").is_none()
    }) {
        return ReflectionContext::StyleBlock;
    }

    if before.rfind("<!--").map_or(false, |s| {
        before[s..].find("-->").is_none()
    }) {
        return ReflectionContext::HtmlComment;
    }

    // Inside an HTML tag attribute?
    if let Some(tag_start) = before.rfind('<') {
        let in_tag = &before[tag_start..];
        if !in_tag.contains('>') {
            if in_tag.contains('=') {
                if in_tag.ends_with('"') || in_tag.ends_with('\'') {
                    return ReflectionContext::HtmlAttribute;
                }
                return ReflectionContext::HtmlAttributeUnquoted;
            }
            return ReflectionContext::HtmlTag;
        }
    }

    ReflectionContext::HtmlBody
}

fn detect_errors(body: &str, status: u16) -> Vec<ErrorSignal> {
    let mut errors = Vec::new();
    let lower = body.to_lowercase();

    let sql_patterns = [
        ("mysql", "you have an error in your sql syntax", "MySQL"),
        ("pgsql", "pg_query", "PostgreSQL"),
        ("pgsql", "pg_exec", "PostgreSQL"),
        ("mssql", "microsoft ole db", "MSSQL"),
        ("mssql", "unclosed quotation mark", "MSSQL"),
        ("oracle", "ora-", "Oracle"),
        ("sqlite", "sqlite3", "SQLite"),
        ("sql", "sql syntax", "SQL"),
    ];
    for (kind_tag, pattern, tech) in sql_patterns {
        if lower.contains(pattern) {
            let _ = kind_tag;
            errors.push(ErrorSignal {
                kind: ErrorKind::SqlError,
                message: extract_error_line(body, pattern),
                technology: tech.into(),
                version: extract_version_from_error(body, tech),
                file_path: String::new(),
                line_number: None,
            });
        }
    }

    let stack_patterns = [
        ("at ", "File \"", "Python"),
        ("traceback", "Traceback", "Python"),
        ("java.lang", "java.lang.", "Java"),
        ("javax.", "javax.", "Java"),
        ("at sun.", "at sun.", "Java"),
        ("system.web", "System.Web", ".NET"),
        ("microsoft.aspnet", "Microsoft.AspNet", ".NET"),
        ("node_modules", "node_modules/", "Node.js"),
        ("typeerror:", "TypeError:", "JavaScript"),
        ("referenceerror:", "ReferenceError:", "JavaScript"),
    ];
    for (_tag, pattern, tech) in stack_patterns {
        if lower.contains(&pattern.to_lowercase()) {
            errors.push(ErrorSignal {
                kind: ErrorKind::StackTrace,
                message: extract_error_line(body, pattern),
                technology: tech.into(),
                version: String::new(),
                file_path: extract_file_path(body),
                line_number: extract_line_number(body),
            });
        }
    }

    if status >= 500 && errors.is_empty() {
        errors.push(ErrorSignal {
            kind: ErrorKind::InternalError,
            message: format!("HTTP {status}"),
            technology: String::new(),
            version: String::new(),
            file_path: String::new(),
            line_number: None,
        });
    }

    errors
}

fn discover_params(body: &str, ct: ContentType) -> Vec<DiscoveredParam> {
    let mut params = Vec::new();

    match ct {
        ContentType::Html => {
            // Hidden inputs
            for cap in find_inputs(body) {
                params.push(cap);
            }
        }
        ContentType::Json => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
                extract_json_keys(&val, "", &mut params);
            }
        }
        _ => {}
    }

    // JS variable extraction (works across content types)
    for name in find_js_vars(body) {
        if !params.iter().any(|p| p.name == name) {
            params.push(DiscoveredParam {
                name,
                source: ParamSource::JavaScriptVar,
                value_hint: String::new(),
                required: false,
            });
        }
    }

    params.truncate(100);
    params
}

fn find_inputs(html: &str) -> Vec<DiscoveredParam> {
    let mut params = Vec::new();
    let lower = html.to_lowercase();
    let mut start = 0;
    while let Some(pos) = lower[start..].find("<input") {
        let abs = start + pos;
        let end = lower[abs..].find('>').map(|e| abs + e).unwrap_or(html.len());
        let tag = &html[abs..end.min(html.len())];

        let name = extract_attr(tag, "name").unwrap_or_default();
        let typ = extract_attr(tag, "type").unwrap_or_default();
        let value = extract_attr(tag, "value").unwrap_or_default();

        if !name.is_empty() {
            params.push(DiscoveredParam {
                name,
                source: if typ == "hidden" { ParamSource::HiddenInput } else { ParamSource::FormInput },
                value_hint: value,
                required: tag.to_lowercase().contains("required"),
            });
        }
        start = end + 1;
    }
    params
}

fn find_js_vars(body: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let patterns = [
        r#"var "#, r#"let "#, r#"const "#, r#"window."#, r#"this."#,
    ];
    for pat in patterns {
        let mut start = 0;
        while let Some(pos) = body[start..].find(pat) {
            let abs = start + pos + pat.len();
            let name: String = body[abs..].chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if name.len() >= 2 && !vars.contains(&name) {
                vars.push(name);
            }
            start = abs + 1;
            if vars.len() >= 50 { break; }
        }
    }
    vars
}

fn extract_json_keys(val: &serde_json::Value, prefix: &str, params: &mut Vec<DiscoveredParam>) {
    if params.len() >= 100 { return; }
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                params.push(DiscoveredParam {
                    name: path.clone(),
                    source: ParamSource::JsonKey,
                    value_hint: match v {
                        serde_json::Value::String(s) => s.chars().take(50).collect(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => String::new(),
                    },
                    required: false,
                });
                extract_json_keys(v, &path, params);
            }
        }
        serde_json::Value::Array(arr) => {
            if let Some(first) = arr.first() {
                extract_json_keys(first, &format!("{prefix}[]"), params);
            }
        }
        _ => {}
    }
}

fn analyze_auth(headers: &BTreeMap<String, String>) -> AuthContext {
    let mut ctx = AuthContext::default();

    if let Some(auth) = headers.get("authorization").or_else(|| headers.get("www-authenticate")) {
        ctx.auth_header = Some(auth.clone());
        let lower = auth.to_lowercase();
        if lower.starts_with("bearer ") {
            let token = &auth[7..];
            if token.split('.').count() == 3 { ctx.session_type = SessionType::JwtBearer; }
            else { ctx.session_type = SessionType::ApiKey; }
        } else if lower.starts_with("basic ") {
            ctx.session_type = SessionType::BasicAuth;
        }
    }

    if let Some(cookies) = headers.get("set-cookie") {
        for cookie_str in cookies.split(',') {
            let parts: Vec<&str> = cookie_str.split(';').collect();
            if let Some(name_val) = parts.first() {
                let name: String = name_val.split('=').next().unwrap_or("").trim().to_string();
                let is_session = name.to_lowercase().contains("session")
                    || name.to_lowercase().contains("sid")
                    || name.to_lowercase().contains("token")
                    || name.to_lowercase().contains("auth");
                ctx.cookies.push(CookieInfo {
                    name,
                    secure: cookie_str.to_lowercase().contains("secure"),
                    http_only: cookie_str.to_lowercase().contains("httponly"),
                    same_site: extract_cookie_attr(cookie_str, "samesite"),
                    path: extract_cookie_attr(cookie_str, "path"),
                    is_session,
                });
                if is_session && ctx.session_type == SessionType::Unknown {
                    ctx.session_type = SessionType::SessionCookie;
                }
            }
        }
    }

    // CSRF token from headers
    for name in &["x-csrf-token", "x-xsrf-token", "csrf-token"] {
        if let Some(val) = headers.get(*name) {
            ctx.csrf_token = Some(val.clone());
        }
    }

    ctx
}

fn analyze_security_headers(headers: &BTreeMap<String, String>) -> SecurityHeaders {
    let mut sh = SecurityHeaders::default();

    sh.csp = headers.get("content-security-policy").cloned();
    sh.hsts = headers.contains_key("strict-transport-security");
    sh.x_frame_options = headers.get("x-frame-options").cloned();
    sh.x_content_type_options = headers.get("x-content-type-options")
        .map(|v| v.to_lowercase().contains("nosniff")).unwrap_or(false);
    sh.referrer_policy = headers.get("referrer-policy").cloned();
    sh.permissions_policy = headers.get("permissions-policy").cloned();
    sh.cors_origin = headers.get("access-control-allow-origin").cloned();
    sh.cors_credentials = headers.get("access-control-allow-credentials")
        .map(|v| v == "true").unwrap_or(false);

    let expected = [
        ("content-security-policy", "CSP"),
        ("strict-transport-security", "HSTS"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
    ];
    for (header, label) in expected {
        if !headers.contains_key(header) {
            sh.missing.push(label.into());
        }
    }

    sh
}

fn find_interesting_headers(headers: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let interesting = [
        "server", "x-powered-by", "x-aspnet-version", "x-runtime",
        "x-generator", "x-debug", "x-request-id", "x-amzn-requestid",
        "cf-ray", "x-cache", "via", "x-forwarded-for",
    ];
    headers.iter()
        .filter(|(k, _)| interesting.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn fingerprint_technology(headers: &BTreeMap<String, String>, body: &str) -> Vec<TechHint> {
    let mut hints = Vec::new();

    if let Some(server) = headers.get("server") {
        hints.push(TechHint {
            technology: "Server".into(),
            version: server.clone(),
            source: "Server header".into(),
            confidence: 0.95,
        });
    }

    if let Some(powered) = headers.get("x-powered-by") {
        hints.push(TechHint {
            technology: "Framework".into(),
            version: powered.clone(),
            source: "X-Powered-By header".into(),
            confidence: 0.9,
        });
    }

    let body_sigs: &[(&str, &str, f64)] = &[
        ("wp-content", "WordPress", 0.9),
        ("__next", "Next.js", 0.85),
        ("__nuxt", "Nuxt.js", 0.85),
        ("ng-app", "Angular", 0.8),
        ("data-reactroot", "React", 0.8),
        ("_token", "Laravel", 0.7),
        ("csrfmiddlewaretoken", "Django", 0.85),
        ("__RequestVerificationToken", "ASP.NET MVC", 0.9),
        ("phpsessid", "PHP", 0.85),
    ];

    let lower = body.to_lowercase();
    for (sig, tech, conf) in body_sigs {
        if lower.contains(sig) {
            hints.push(TechHint {
                technology: tech.to_string(),
                version: String::new(),
                source: format!("Body contains '{sig}'"),
                confidence: *conf,
            });
        }
    }

    hints
}

fn body_similarity(a: &str, b: &str) -> f64 {
    if a == b { return 1.0; }
    if a.is_empty() || b.is_empty() { return 0.0; }

    let lines_a: Vec<&str> = a.lines().collect();
    let lines_b: Vec<&str> = b.lines().collect();

    let set_a: std::collections::HashSet<&str> = lines_a.iter().copied().collect();
    let set_b: std::collections::HashSet<&str> = lines_b.iter().copied().collect();

    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();

    if union == 0 { return 1.0; }
    intersection as f64 / union as f64
}

fn content_diff(baseline: &str, attack: &str) -> (Vec<String>, Vec<String>) {
    let lines_b: std::collections::HashSet<&str> = baseline.lines().collect();
    let lines_a: std::collections::HashSet<&str> = attack.lines().collect();

    let new: Vec<String> = lines_a.difference(&lines_b)
        .take(20)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = lines_b.difference(&lines_a)
        .take(20)
        .map(|s| s.to_string())
        .collect();
    (new, removed)
}

fn is_waf_body(body: &str) -> bool {
    let lower = body.to_lowercase();
    let waf_sigs = [
        "access denied", "request blocked", "web application firewall",
        "security policy", "blocked by", "cf-error-details",
        "akamai ghost", "incapsula", "sucuri", "barracuda",
        "fortiweb", "imperva", "f5 big-ip",
    ];
    waf_sigs.iter().any(|sig| lower.contains(sig))
}

fn extract_error_line(body: &str, pattern: &str) -> String {
    let lower = body.to_lowercase();
    let lower_pattern = pattern.to_lowercase();
    if let Some(pos) = lower.find(&lower_pattern) {
        let start = body[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let end = body[pos..].find('\n').map(|p| pos + p).unwrap_or(body.len());
        return body[start..end.min(start + 200)].trim().to_string();
    }
    String::new()
}

fn extract_version_from_error(body: &str, tech: &str) -> String {
    let _ = tech;
    let re_like = |s: &str| -> Option<String> {
        let mut start = None;
        for (i, c) in s.char_indices() {
            if c.is_ascii_digit() && start.is_none() { start = Some(i); }
            if start.is_some() && !c.is_ascii_digit() && c != '.' { return Some(s[start.unwrap()..i].to_string()); }
        }
        start.map(|s_idx| s[s_idx..].to_string())
    };
    re_like(body).unwrap_or_default()
}

fn extract_file_path(body: &str) -> String {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.contains('/') && (trimmed.contains(".py") || trimmed.contains(".js")
            || trimmed.contains(".php") || trimmed.contains(".java") || trimmed.contains(".rb")
            || trimmed.contains(".cs")) {
            let path: String = trimmed.chars().take(200).collect();
            return path;
        }
    }
    String::new()
}

fn extract_line_number(body: &str) -> Option<u32> {
    for line in body.lines() {
        if let Some(pos) = line.find("line ") {
            let num: String = line[pos + 5..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num.parse() { return Some(n); }
        }
    }
    None
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let pattern = format!("{attr}=");
    if let Some(pos) = lower.find(&pattern) {
        let rest = &tag[pos + pattern.len()..];
        if rest.starts_with('"') || rest.starts_with('\'') {
            let quote = rest.chars().next().unwrap();
            let end = rest[1..].find(quote).map(|e| e + 1)?;
            return Some(rest[1..end].to_string());
        }
        let val: String = rest.chars().take_while(|c| !c.is_whitespace() && *c != '>').collect();
        return Some(val);
    }
    None
}

fn extract_cookie_attr(cookie: &str, attr: &str) -> String {
    let lower = cookie.to_lowercase();
    let pattern = format!("{}=", attr.to_lowercase());
    if let Some(pos) = lower.find(&pattern) {
        let rest = &cookie[pos + pattern.len()..];
        return rest.split(';').next().unwrap_or("").trim().to_string();
    }
    String::new()
}

fn safe_slice(s: &str, start: usize, end: usize) -> String {
    let start = start.min(s.len());
    let end = end.min(s.len());
    s.get(start..end).unwrap_or("").to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_detection() {
        assert_eq!(ContentType::from_header("text/html; charset=utf-8"), ContentType::Html);
        assert_eq!(ContentType::from_header("application/json"), ContentType::Json);
        assert_eq!(ContentType::from_header("application/xml"), ContentType::Xml);
    }

    #[test]
    fn test_reflection_detection() {
        let body = r#"<input type="text" value="test_input_123">"#;
        let reflections = find_reflections(body, &["test_input_123"], ContentType::Html);
        assert!(!reflections.is_empty());
        assert_eq!(reflections[0].context, ReflectionContext::HtmlAttribute);
    }

    #[test]
    fn test_sql_error_detection() {
        let body = "You have an error in your SQL syntax near 'test' at line 1";
        let errors = detect_errors(body, 500);
        assert!(errors.iter().any(|e| e.kind == ErrorKind::SqlError));
    }

    #[test]
    fn test_response_diff() {
        let headers = BTreeMap::new();
        let d = diff(200, &headers, "hello world", 100, 500, &headers, "internal error", 100);
        assert_eq!(d.verdict, DiffVerdict::ErrorInduced);
        assert!(d.status_changed);
    }

    #[test]
    fn test_param_discovery_html() {
        let html = r#"<form><input type="hidden" name="csrf_token" value="abc123"><input name="email" required></form>"#;
        let params = discover_params(html, ContentType::Html);
        assert!(params.iter().any(|p| p.name == "csrf_token" && matches!(p.source, ParamSource::HiddenInput)));
        assert!(params.iter().any(|p| p.name == "email"));
    }
}
