//! Secret redaction for the human-facing reports.
//!
//! The reports (`report.md`, `.html`, `.json`, `.sarif`, `.typ`/`.pdf`) are the
//! documents that leave the operator's machine. Agents write narrative, and the
//! narrative of a credential finding naturally quotes the credential: "logged in
//! as admin with `password=…` leaked by the SQLi". `findings.json` and the vault
//! keep the raw values for re-testing; everything rendered for people goes
//! through here first.
//!
//! Two passes. `learn` walks every string of every finding (as JSON, so new
//! fields are covered without touching this file) and collects secret values:
//! generated account secrets, credential-named `key=value` / `"key": "value"`
//! pairs, bearer/basic tokens, JWTs, cookie values, cloud keys, and the values
//! of credential-named fields and headers. Each distinct value gets a stable
//! placeholder (`$SECRET_1`, …) so a reproduction step stays readable and
//! pasteable once the reader exports the variable. `text` then replaces the
//! learned values wherever they appear — including free prose — and redacts any
//! remaining pattern match it did not learn.
//!
//! A learned value is replaced in free prose only when it looks like a secret
//! (6+ characters mixing character classes); a short or dictionary-like value
//! (`admin`, `authenticated`) is redacted only where it sits in a credential
//! context, so a username or an ordinary word is never wiped from the report.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::Finding;

const PLACEHOLDER: &str = "$SECRET";

/// Field and header names whose values are credentials.
fn credential_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase().replace('-', "_");
    const EXACT: &[&str] = &["secret", "authorization", "proxy_authorization", "cookie", "set_cookie", "pwd", "pass", "passwd", "sid"];
    const PART: &[&str] = &["password", "passphrase", "token", "api_key", "apikey", "client_secret", "secret_key", "private_key", "sessionid", "session_id", "jsessionid", "phpsessid", "x_api_key", "x_auth"];
    EXACT.contains(&k.as_str()) || PART.iter().any(|p| k.contains(p))
}

/// Fields that are identifiers or paths, never prose with credentials.
const SKIP_FIELDS: &[&str] = &["id", "agent", "severity", "cwe", "cvss", "owasp", "mitre", "stage", "chains_from", "screenshots", "review_status", "account"];

fn kv_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)\b((?:[a-z0-9_\-]*(?:password|passwd|passphrase|token|api[_\-]?key|client[_\-]?secret|secret[_\-]?key|sessionid|session_id|jsessionid|phpsessid))|pwd|pass|secret|sid)(\\?["']?\s*[:=]\s*\\?["']?)([^\s"'\\&,;}<>)\]]{3,})"#)
            .expect("kv regex")
    })
}

fn token_res() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        [
            r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{8,}=*)",
            r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,}=*)",
            r"\b(eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*)",
            r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
            r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b",
            r"\b(xox[abpr]-[A-Za-z0-9\-]{10,})\b",
            r"(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("token regex"))
        .collect()
    })
}

/// "…plaintext password for every account (admin: X / Y; alice: Z)": a
/// parenthesised list of `user: value` pairs in a sentence about credentials.
fn listed_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(?:password|passwd|credential|api ?key)[^.\n]{0,160}?\(([^()]{3,240})\)").expect("listed regex"))
}

fn listed_pair_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"([A-Za-z0-9_.@\-]{2,40}):\s*([^\s;,/()]{4,})(?:\s*/\s*([^\s;,/()]{4,}))?").expect("listed pair regex"))
}

fn cookie_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?im)^\s*(?:set-)?cookie\s*:\s*(.+)$").expect("cookie regex"))
}

fn cookie_pair_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"([A-Za-z0-9_\-.]+)=([^;\s]+)").expect("cookie pair regex"))
}

/// Cookie attributes that are not values worth hiding.
fn cookie_attr(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "path" | "domain" | "expires" | "max-age" | "samesite" | "priority")
}

fn already_redacted(v: &str) -> bool {
    v.starts_with(PLACEHOLDER) || v.starts_with('$') || v.starts_with("{{") || v.contains('•') || v.chars().all(|c| c == '*' || c == 'x' || c == 'X')
}

/// Strong enough to be replaced in free prose without wiping ordinary words.
fn distinctive(v: &str) -> bool {
    if v.chars().count() < 6 {
        return false;
    }
    let classes = [
        v.chars().any(|c| c.is_ascii_lowercase()),
        v.chars().any(|c| c.is_ascii_uppercase()),
        v.chars().any(|c| c.is_ascii_digit()),
        v.chars().any(|c| !c.is_ascii_alphanumeric()),
    ];
    classes.iter().filter(|b| **b).count() >= 2
}

/// The findings as they may be shown to people. Idempotent.
pub fn for_people(findings: &[Finding]) -> Vec<Finding> {
    Redactor::learn(findings).findings(findings)
}

#[derive(Default, Debug, Clone)]
pub struct Redactor {
    /// value → placeholder, in order of discovery.
    map: BTreeMap<String, String>,
    order: Vec<String>,
}

impl Redactor {
    /// Learn every secret value the findings carry.
    pub fn learn(findings: &[Finding]) -> Self {
        let mut r = Redactor::default();
        for f in findings {
            if !f.secret.is_empty() && !already_redacted(&f.secret) {
                r.add(&f.secret);
            }
            if let Ok(v) = serde_json::to_value(f) {
                r.learn_value(None, &v);
            }
        }
        r
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn add(&mut self, v: &str) {
        let v = v.trim();
        if v.len() < 3 || already_redacted(v) || self.map.contains_key(v) {
            return;
        }
        let ph = format!("{PLACEHOLDER}_{}", self.map.len() + 1);
        self.map.insert(v.to_string(), ph);
        self.order.push(v.to_string());
    }

    fn learn_value(&mut self, key: Option<&str>, v: &serde_json::Value) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(k) = key {
                    if SKIP_FIELDS.contains(&k) {
                        return;
                    }
                    if credential_key(k) {
                        self.learn_header(k, s);
                        return;
                    }
                }
                self.learn_text(s);
            }
            serde_json::Value::Array(a) => {
                // Header lists as [name, value] pairs.
                if let [serde_json::Value::String(n), serde_json::Value::String(val)] = a.as_slice() {
                    if credential_key(n) {
                        self.learn_header(n, val);
                        return;
                    }
                }
                for x in a {
                    self.learn_value(key, x);
                }
            }
            serde_json::Value::Object(o) => {
                for (k, x) in o {
                    self.learn_value(Some(k), x);
                }
            }
            _ => {}
        }
    }

    /// The value of a credential-named field or header.
    fn learn_header(&mut self, name: &str, value: &str) {
        let n = name.to_ascii_lowercase();
        if n.contains("cookie") {
            for c in cookie_pair_re().captures_iter(value) {
                if !cookie_attr(&c[1]) {
                    self.add(&c[2]);
                }
            }
        } else if let Some((scheme, rest)) = value.trim().split_once(' ').filter(|(s, _)| ["bearer", "basic", "token", "digest"].contains(&s.to_ascii_lowercase().as_str())) {
            let _ = scheme;
            self.add(rest);
        } else {
            self.add(value);
        }
        self.learn_text(value);
    }

    fn learn_text(&mut self, s: &str) {
        for c in kv_re().captures_iter(s) {
            self.add(&c[3]);
        }
        for re in token_res() {
            for c in re.captures_iter(s) {
                self.add(&c[1]);
            }
        }
        for l in listed_re().captures_iter(s) {
            for c in listed_pair_re().captures_iter(&l[1]) {
                self.add(&c[2]);
                if let Some(m) = c.get(3) {
                    self.add(m.as_str());
                }
            }
        }
        for line in cookie_re().captures_iter(s) {
            for c in cookie_pair_re().captures_iter(&line[1]) {
                if !cookie_attr(&c[1]) {
                    self.add(&c[2]);
                }
            }
        }
    }

    fn placeholder(&self, v: &str) -> String {
        self.map.get(v.trim()).cloned().unwrap_or_else(|| PLACEHOLDER.to_string())
    }

    /// Redact one rendered string.
    pub fn text(&self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }
        // Learned distinctive values anywhere, longest first so a token that
        // contains another is replaced whole.
        let mut out = s.to_string();
        let mut learned: Vec<&String> = self.order.iter().filter(|v| distinctive(v)).collect();
        learned.sort_by_key(|v| std::cmp::Reverse(v.len()));
        for v in learned {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), &self.map[v.as_str()]);
            }
        }
        // Contextual matches (short values, values not learned).
        out = kv_re()
            .replace_all(&out, |c: &regex::Captures| {
                if already_redacted(&c[3]) {
                    c[0].to_string()
                } else {
                    format!("{}{}{}", &c[1], &c[2], self.placeholder(&c[3]))
                }
            })
            .into_owned();
        for re in token_res() {
            out = re
                .replace_all(&out, |c: &regex::Captures| {
                    let whole = &c[0];
                    let v = &c[1];
                    if already_redacted(v) { whole.to_string() } else { whole.replacen(v, &self.placeholder(v), 1) }
                })
                .into_owned();
        }
        out = cookie_re()
            .replace_all(&out, |c: &regex::Captures| {
                let pairs = cookie_pair_re().replace_all(&c[1], |p: &regex::Captures| {
                    if cookie_attr(&p[1]) || already_redacted(&p[2]) { p[0].to_string() } else { format!("{}={}", &p[1], self.placeholder(&p[2])) }
                });
                c[0].replacen(&c[1], &pairs, 1)
            })
            .into_owned();
        out
    }

    /// A copy of the findings safe to render for people.
    pub fn findings(&self, findings: &[Finding]) -> Vec<Finding> {
        findings
            .iter()
            .map(|f| {
                let Ok(mut v) = serde_json::to_value(f) else { return f.clone() };
                self.redact_value(None, &mut v);
                let mut out: Finding = serde_json::from_value(v).unwrap_or_else(|_| f.clone());
                if !f.secret.is_empty() && !already_redacted(&f.secret) {
                    out.secret = "•••• (see vault.json)".into();
                }
                out
            })
            .collect()
    }

    fn redact_value(&self, key: Option<&str>, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => {
                if key.is_some_and(|k| SKIP_FIELDS.contains(&k)) {
                    return;
                }
                if key.is_some_and(|k| credential_key(k) && !k.eq_ignore_ascii_case("secret")) && !s.is_empty() && !already_redacted(s) {
                    *s = self.header_value(key.unwrap_or_default(), s);
                    return;
                }
                *s = self.text(s);
            }
            serde_json::Value::Array(a) => {
                if let [serde_json::Value::String(n), serde_json::Value::String(val)] = a.as_mut_slice() {
                    if credential_key(n) {
                        *val = self.header_value(n, val);
                        return;
                    }
                }
                for x in a.iter_mut() {
                    self.redact_value(key, x);
                }
            }
            serde_json::Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    self.redact_value(Some(k), x);
                }
            }
            _ => {}
        }
    }

    /// A credential header keeps its shape (`Bearer $SECRET_2`, `sid=$SECRET_3`).
    fn header_value(&self, name: &str, value: &str) -> String {
        let n = name.to_ascii_lowercase();
        if n.contains("cookie") {
            return cookie_pair_re()
                .replace_all(value, |p: &regex::Captures| {
                    if cookie_attr(&p[1]) { p[0].to_string() } else { format!("{}={}", &p[1], self.placeholder(&p[2])) }
                })
                .into_owned();
        }
        if let Some((scheme, rest)) = value.trim().split_once(' ') {
            if ["bearer", "basic", "token", "digest"].contains(&scheme.to_ascii_lowercase().as_str()) {
                return format!("{scheme} {}", self.placeholder(rest));
            }
        }
        self.placeholder(value)
    }

    /// How many distinct values were redacted (for the report note).
    pub fn count(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> Finding {
        let mut f: Finding = serde_json::from_value(serde_json::json!({
            "id": "f1", "agent": "credential_reuse", "title": "Credential reuse via SQLi-leaked admin password", "severity": "High"
        }))
        .unwrap();
        f.payload = "username=admin&password=Hunter2Secret".into();
        f.evidence = "POST /login\nCookie: sid=ab12CD34ef56; Path=/\nAuthorization: Bearer abcdefghijkl123456\nlogged in with Hunter2Secret".into();
        f.impact = "The leaked password Hunter2Secret opens /admin for user admin.".into();
        f.repro_steps = vec!["curl -d 'username=admin&password=Hunter2Secret' https://t.test/login".into()];
        f.account = "admin".into();
        f
    }

    #[test]
    fn credentials_leave_no_trace_in_rendered_findings() {
        let fs = vec![finding()];
        let r = Redactor::learn(&fs);
        let out = r.findings(&fs);
        let all = serde_json::to_string(&out).unwrap();
        for raw in ["Hunter2Secret", "ab12CD34ef56", "abcdefghijkl123456"] {
            assert!(!all.contains(raw), "{raw} leaked: {all}");
        }
        assert!(all.contains("$SECRET_"), "{all}");
        // Ordinary words and the username survive.
        assert!(out[0].impact.contains("for user admin"), "{}", out[0].impact);
        assert_eq!(out[0].account, "admin");
        assert!(out[0].evidence.contains("Path=/"));
        assert!(out[0].evidence.contains("Bearer $SECRET_"));
    }

    #[test]
    fn the_same_value_gets_the_same_placeholder() {
        let fs = vec![finding()];
        let r = Redactor::learn(&fs);
        let out = r.findings(&fs);
        let ph = out[0].payload.split("password=").nth(1).unwrap().to_string();
        assert!(ph.starts_with("$SECRET_"));
        assert!(out[0].impact.contains(&ph), "{} / {}", ph, out[0].impact);
        assert!(out[0].repro_steps[0].contains(&ph));
    }

    #[test]
    fn short_values_are_redacted_only_in_context() {
        let mut f = finding();
        f.payload = "user=admin&pass=admin".into();
        f.evidence = "admin console reached".into();
        let fs = vec![f];
        let out = Redactor::learn(&fs).findings(&fs);
        assert!(!out[0].payload.contains("pass=admin"), "{}", out[0].payload);
        assert!(out[0].payload.contains("user=admin"));
        assert!(out[0].evidence.contains("admin console"));
    }

    #[test]
    fn jwt_and_cloud_keys_in_prose() {
        let r = Redactor::default();
        let s = r.text("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part and key AKIAABCDEFGHIJKLMNOP");
        assert!(!s.contains("eyJhbGciOiJIUzI1NiJ9"), "{s}");
        assert!(!s.contains("AKIAABCDEFGHIJKLMNOP"), "{s}");
    }

    #[test]
    fn credentials_listed_in_prose() {
        let mut f = finding();
        f.evidence = "returned the plaintext password for every account (admin: Adm1nPass! / sk_live_ab12; alice: alice123). Dump: 'alicealice123admin'".into();
        let fs = vec![f];
        let out = Redactor::learn(&fs).findings(&fs);
        for raw in ["Adm1nPass!", "sk_live_ab12", "alice123"] {
            assert!(!out[0].evidence.contains(raw), "{raw}: {}", out[0].evidence);
        }
        assert!(out[0].evidence.contains("alice: $SECRET_"));
    }

    #[test]
    fn placeholders_are_not_redacted_again() {
        let r = Redactor::default();
        assert_eq!(r.text("password=$SECRET_1"), "password=$SECRET_1");
        assert_eq!(r.text("password=${PASSWORD}"), "password=${PASSWORD}");
    }

    #[test]
    fn generated_account_secret_is_masked() {
        let mut f = finding();
        f.secret = "Gen3rated!Pw".into();
        f.evidence = "account created, password Gen3rated!Pw".into();
        let fs = vec![f];
        let out = Redactor::learn(&fs).findings(&fs);
        assert!(!out[0].evidence.contains("Gen3rated!Pw"));
        assert!(out[0].secret.contains("vault"));
    }
}
