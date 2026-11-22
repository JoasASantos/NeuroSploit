//! Rich, step-by-step reproduction kits — and secrets that stay in the vault.
//!
//! A report that says "SQL injection on /search" is a claim. A reproduction kit
//! that says *run this exact request, expect this exact difference, repeat it
//! twice* is evidence someone else can check. This module turns a finding's
//! recorded exchanges into that kit:
//!
//! 1. **Baseline** — the request without the payload, and what it returned.
//! 2. **Attack** — the request with the payload, byte for byte.
//! 3. **Verify** — the deterministic difference (status, length, marker,
//!    repeats) that makes the effect more than a hunch.
//! 4. **Cleanup** — when the request changed state, how to undo it.
//!
//! ## Secrets
//!
//! Reproduction often needs the exact credential that proved the bug, but a
//! document is shared far more widely than the vault. So a kit carries a
//! **token** — `{{REVEALSECRET:name}}` — instead of the value. The vault on
//! disk is the only place the value lives; [`SecretStore::load`] reads it and
//! [`expand`] substitutes on demand (`neurosploit repro --reveal`). Without
//! `--reveal` the token is rendered as a masked placeholder, which is the safe
//! default for anything that leaves the operator's machine.

use crate::types::Finding;
use std::collections::BTreeMap;
use std::path::Path;

/// Named secrets read from a run's vault. Lookup is by account name, header
/// label (`authorization`, `cookie`), and any explicit `secrets.json` keys.
#[derive(Clone, Debug, Default)]
pub struct SecretStore {
    map: BTreeMap<String, String>,
}

impl SecretStore {
    pub fn load(run_dir: &Path) -> Self {
        let mut map = BTreeMap::new();
        for name in ["secrets.json", "vault.json"] {
            if let Ok(text) = std::fs::read_to_string(run_dir.join(name)) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    absorb(&mut map, &v);
                }
            }
        }
        if let Ok(text) = std::fs::read_to_string(run_dir.join("vault.jsonl")) {
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    absorb(&mut map, &v);
                }
            }
        }
        SecretStore { map }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let k = key.into().trim().to_lowercase();
        let v = value.into();
        if !k.is_empty() && !v.is_empty() {
            self.map.insert(k, v);
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

fn absorb(map: &mut BTreeMap<String, String>, v: &serde_json::Value) {
    match v {
        serde_json::Value::Array(items) => {
            for it in items {
                absorb(map, it);
            }
        }
        serde_json::Value::Object(o) => {
            // A vault entry: account + secret (+ optional role/endpoint).
            let account = o.get("account").and_then(|x| x.as_str()).unwrap_or("");
            let secret = o.get("secret").or_else(|| o.get("password")).and_then(|x| x.as_str()).unwrap_or("");
            if !account.is_empty() && !secret.is_empty() {
                map.insert(account.trim().to_lowercase(), secret.to_string());
            }
            // A plain map of name -> value (secrets.json).
            for (k, val) in o {
                if let Some(s) = val.as_str() {
                    if k != "account" && k != "secret" {
                        map.insert(k.trim().to_lowercase(), s.to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

/// Replace `{{REVEALSECRET:key}}`, `[[REVEALSECRET:key]]` and
/// `REVEALSECRET(key)` with the vault value. When `reveal` is false (or the
/// key is unknown) a masked placeholder is left, so the token itself never
/// leaks the secret.
pub fn expand(text: &str, store: &SecretStore, reveal: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (open, close, prefix_len) = if text[i..].starts_with("{{REVEALSECRET:") {
            ("{{REVEALSECRET:", "}}", 15)
        } else if text[i..].starts_with("[[REVEALSECRET:") {
            ("[[REVEALSECRET:", "]]", 15)
        } else if text[i..].starts_with("REVEALSECRET(") {
            ("REVEALSECRET(", ")", 13)
        } else {
            let ch = text[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };
        let _ = open;
        let start = i + prefix_len;
        let Some(rel_end) = text[start..].find(close) else {
            let ch = text[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };
        let key = text[start..start + rel_end].trim();
        match store.get(key) {
            Some(v) if reveal => out.push_str(v),
            Some(_) => out.push_str(&format!("•••••• (REVEALSECRET:{key})")),
            None => out.push_str(&format!("{{{{REVEALSECRET:{key}}}}}")),
        }
        i = start + rel_end + close.len();
    }
    out
}

/// Build the ordered, human-runnable steps for one finding.
///
/// Recorded `repro_steps` win (they are what the agent actually did); this only
/// fills the gaps and expands tokens. Every step is self-contained enough to
/// paste into a shell, because the reader should not have to reconstruct a
/// request from prose.
pub fn steps(f: &Finding, store: &SecretStore, reveal: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let push = |out: &mut Vec<String>, s: String| {
        let s = expand(&s, store, reveal);
        if !s.trim().is_empty() && !out.iter().any(|x| *x == s) {
            out.push(s);
        }
    };

    if !f.repro_steps.is_empty() {
        for s in &f.repro_steps {
            push(&mut out, s.clone());
        }
    }

    if let Some(ev) = &f.evidence_data {
        // 1 — baseline.
        if let Some(b) = &ev.baseline {
            push(&mut out, format!(
                "Baseline (no payload) — expect HTTP {} ({} bytes):\n{}",
                b.status, b.len(), exchange_curl(b)
            ));
        }
        // 2 — attack.
        if let Some(a) = &ev.attack {
            push(&mut out, format!(
                "Attack — send the payload. Recorded response: HTTP {} ({} bytes, {} ms):\n{}",
                a.status, a.len(), a.elapsed_ms, exchange_curl(a)
            ));
        }
        // 3 — verification.
        if let (Some(b), Some(a)) = (&ev.baseline, &ev.attack) {
            let d = crate::validation::diff(b, a);
            let mut verify = format!("Verify the difference — expected: {}", d.describe());
            if !ev.repeats.is_empty() {
                let (ok, hits) = crate::validation::reproducible(b, &ev.repeats, 2);
                verify.push_str(&format!(
                    "\nRepeat the attack {}×; the same difference must appear each time (recorded: {hits}/{}).",
                    ev.repeats.len() + 1,
                    ev.repeats.len()
                ));
                if !ok {
                    verify.push_str(" Not deterministic — treat as needs-review.");
                }
            }
            if !ev.marker.is_empty() {
                verify.push_str(&format!(
                    "\nControlled marker `{}` — observed: {}.",
                    ev.marker,
                    if ev.marker_observed { "yes" } else { "no" }
                ));
            }
            push(&mut out, verify);
        } else if !ev.marker.is_empty() {
            push(&mut out, format!(
                "Verify the marker `{}` appears in the response (observed: {}).",
                ev.marker,
                if ev.marker_observed { "yes" } else { "no" }
            ));
        }
    }

    if out.is_empty() {
        let curl = crate::report::curl_command(f);
        if !curl.is_empty() {
            push(&mut out, format!("Send the request:\n{curl}"));
        }
        if !f.payload.trim().is_empty() {
            push(&mut out, format!("Payload:\n{}", f.payload.trim()));
        }
    }

    // 4 — cleanup for state-changing proofs.
    let method = f
        .evidence_data
        .as_ref()
        .and_then(|e| e.attack.as_ref())
        .map(|a| a.method.to_uppercase())
        .unwrap_or_default();
    if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        push(&mut out, "Cleanup — this request changed state. Delete the created object/account or restore the original value before leaving the engagement.".into());
    }

    if out.is_empty() {
        out.push("No reproduction steps were recorded for this finding.".into());
    }
    out
}

fn exchange_curl(x: &crate::validation::Exchange) -> String {
    let mut cmd = String::from("curl -i -s");
    let method = x.method.to_uppercase();
    if !method.is_empty() && method != "GET" {
        cmd.push_str(&format!(" -X {method}"));
    }
    for (k, v) in &x.request_headers {
        let value = if is_secret_header(k) {
            format!("{{{{REVEALSECRET:{}}}}}", k.to_lowercase())
        } else {
            v.clone()
        };
        cmd.push_str(&format!(" \\\n  -H '{}: {}'", k, value.replace('\'', "'\\''")));
    }
    if !x.body.trim().is_empty() && method != "GET" {
        cmd.push_str(&format!(" \\\n  --data-raw '{}'", x.body.replace('\'', "'\\''")));
    }
    cmd.push_str(&format!(" \\\n  '{}'", x.url));
    cmd
}

fn is_secret_header(k: &str) -> bool {
    let k = k.to_lowercase();
    k == "authorization" || k == "cookie" || k == "x-api-key" || k.contains("token") || k.contains("secret")
}

/// A complete Markdown reproduction kit for a run's findings.
pub fn markdown(run_dir: &Path, findings: &[Finding], store: &SecretStore, reveal: bool, only: Option<&str>) -> String {
    let mut s = String::from("# Reproduction kit\n\n");
    s.push_str(&format!(
        "Vault: {} secret(s) available. Secrets appear as `{{{{REVEALSECRET:name}}}}`; \
         run `neurosploit repro <run> --reveal` to print the values.\n\n",
        store.len()
    ));
    let mut n = 0;
    for f in findings {
        if let Some(id) = only {
            if f.id != id && !f.title.eq_ignore_ascii_case(id) {
                continue;
            }
        }
        n += 1;
        s.push_str(&format!("## {}. {} — {}\n\n", n, f.title, f.severity));
        s.push_str(&format!("- Endpoint: `{}`\n", if f.endpoint.is_empty() { "(not recorded)" } else { &f.endpoint }));
        if !f.cwe.is_empty() {
            s.push_str(&format!("- CWE: {}\n", f.cwe));
        }
        s.push_str("\n");
        for (i, step) in steps(f, store, reveal).iter().enumerate() {
            s.push_str(&format!("### Step {}\n\n```sh\n{}\n```\n\n", i + 1, step));
        }
        if !f.evidence.trim().is_empty() {
            s.push_str("### Recorded evidence\n\n```\n");
            s.push_str(&expand(f.evidence.trim(), store, reveal));
            s.push_str("\n```\n\n");
        }
        s.push_str("---\n\n");
    }
    if n == 0 {
        s.push_str("_No matching findings._\n");
    }
    let _ = run_dir;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tokens_and_masks_by_default() {
        let mut st = SecretStore::default();
        st.insert("alice", "s3cret");
        assert_eq!(expand("pw={{REVEALSECRET:alice}}", &st, false), "pw=•••••• (REVEALSECRET:alice)");
        assert_eq!(expand("pw={{REVEALSECRET:alice}}", &st, true), "pw=s3cret");
        assert_eq!(expand("pw=[[REVEALSECRET:alice]]", &st, true), "pw=s3cret");
        assert_eq!(expand("pw=REVEALSECRET(alice)", &st, true), "pw=s3cret");
        assert_eq!(expand("{{REVEALSECRET:missing}}", &st, true), "{{REVEALSECRET:missing}}");
    }

    #[test]
    fn absorbs_vault_array_and_jsonl_shape() {
        let mut map = BTreeMap::new();
        absorb(&mut map, &serde_json::json!({"account":"u1","secret":"p1"}));
        assert_eq!(map.get("u1").map(String::as_str), Some("p1"));
    }
}
