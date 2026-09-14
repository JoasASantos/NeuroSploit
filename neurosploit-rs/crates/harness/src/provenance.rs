//! Provenance — proving which engine produced a finding, and which build.
//!
//! Two different problems share one mechanism:
//!
//! 1. **Evidence integrity.** A marker the harness minted and later observed in
//!    a response is proof of a data path. It is only proof if nobody else could
//!    have minted it, and if, months later, we can still say *this* run made it.
//! 2. **Attribution.** Reports, prompts and artifacts leave the building. When
//!    one comes back — in a customer's ticket, in a competitor's output, in a
//!    corpus — the question "did this come from us, and from which build?" has
//!    to have an answer that does not depend on a filename.
//!
//! So every artifact carries the same three-part identity:
//!
//! ```text
//!   JOASNSCOPE - <build fingerprint> - <run id> - <per-artifact nonce>
//!        │             │                  │              │
//!     who made it   which build      which engagement   which artifact
//! ```
//!
//! The prefix is deliberately a single literal, `JOASNSCOPE`, so a grep for it
//! across any document finds every trace at once — a marker nobody can find is
//! a marker that proves nothing when it matters.
//!
//! What this is **not**: it is not a secret, and it is not DRM. Anyone holding
//! a report can read the marker, and anyone can copy one. What they cannot do
//! is *forge* a signed manifest, which is why the manifest is what a dispute
//! actually turns on — the marker points at the claim, the signature carries it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The literal every trace shares. Grep-able on purpose.
pub const SIGIL: &str = "JOASNSCOPE";

/// Engine name as it appears in artifacts.
pub const ENGINE: &str = "neurosploit";

fn hex12(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

static PROCESS: std::sync::OnceLock<Provenance> = std::sync::OnceLock::new();

/// Identity of one build of the engine, plus the run currently using it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// Derived from the build, not from the clock: the same binary always
    /// fingerprints the same way, and a rebuild with changed code does not.
    pub build: String,
    /// Crate version, carried separately so a human can read it.
    pub version: String,
    /// Per-engagement id. Distinguishes two runs of the same build.
    pub run: String,
    /// Optional per-customer build id, for a binary shipped to one client.
    /// Present in every marker when set, absent entirely when not.
    pub customer: Option<String>,
    /// When this provenance was minted (unix seconds).
    pub minted: u64,
}

impl Default for Provenance {
    fn default() -> Self {
        Provenance::for_run("")
    }
}

impl Provenance {
    /// The fingerprint of *this* build.
    ///
    /// Derived from what the compiler knew: the crate version, the target
    /// triple, the profile, and the source-control revision when the build
    /// recorded one. Two different builds of different code get different
    /// fingerprints; the same build re-run gets the same one, which is the
    /// property that makes it useful as an identifier at all.
    pub fn build_fingerprint() -> String {
        static FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        FP.get_or_init(|| {
            let seed = format!(
                "{}|{}|{}|{}|{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                std::env::consts::ARCH,
                std::env::consts::OS,
                option_env!("NEUROSPLOIT_BUILD_REV").unwrap_or("dev"),
            );
            hex12(seed.as_bytes())
        })
        .clone()
    }

    /// Provenance for one engagement. `run_id` is the workdir basename when
    /// there is one; an empty string mints a standalone id instead, so a
    /// one-off invocation is still attributable.
    pub fn for_run(run_id: &str) -> Self {
        let run = if run_id.trim().is_empty() {
            format!("adhoc-{}", hex12(&now_secs().to_le_bytes()))
        } else {
            run_id.trim().to_string()
        };
        Provenance {
            build: Self::build_fingerprint(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            run,
            customer: std::env::var("NEUROSPLOIT_CUSTOMER_ID").ok().filter(|s| !s.trim().is_empty()),
            minted: now_secs(),
        }
    }

    /// The provenance for this process.
    ///
    /// Bound once, at the start of a run, so every prompt, marker and artifact
    /// made by that process agrees on which engagement it belongs to. Reading
    /// it before it is bound is fine — it mints an ad-hoc identity rather than
    /// failing, because an unattributed artifact is worse than a vague one.
    pub fn process() -> &'static Provenance {
        PROCESS.get_or_init(|| Provenance::for_run(""))
    }

    /// Bind this process to a run. First call wins: a run's identity must not
    /// change underneath the markers already minted against it.
    pub fn bind_run(run_id: &str) -> &'static Provenance {
        let _ = PROCESS.set(Provenance::for_run(run_id));
        Provenance::process()
    }

    /// Short identity string: what goes in a footer or a log line.
    pub fn tag(&self) -> String {
        match &self.customer {
            Some(c) => format!("{SIGIL}-{}-{}-{}", self.build, sanitize(c), self.run),
            None => format!("{SIGIL}-{}-{}", self.build, self.run),
        }
    }

    /// A marker for one artifact or one probe.
    ///
    /// `kind` says what it is for (`xss`, `oob`, `file`, `prompt`, …). The
    /// nonce is what makes observing it later evidence rather than a guess:
    /// the target could not have produced this string on its own.
    pub fn marker(&self, kind: &str) -> String {
        // canary() already carries the sigil; the build prefix says which
        // build minted it, so a marker found later dates itself.
        let nonce = crate::validation::canary(&format!("{}{}", sanitize(kind), &self.build[..6]));
        if nonce.starts_with(SIGIL) { nonce } else { format!("{SIGIL}{nonce}") }
    }

    /// Is this string one of ours? Cheap, and deliberately permissive about
    /// what comes after the sigil — a truncated or re-cased copy still counts
    /// as a trace worth investigating.
    pub fn is_ours(s: &str) -> bool {
        s.contains(SIGIL)
    }

    /// Pull every marker out of a document.
    ///
    /// Used on a report that came back to us, and on a response body where a
    /// marker resurfacing is the finding itself.
    pub fn extract(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let sig = SIGIL.as_bytes();
        let mut i = 0;
        while i + sig.len() <= bytes.len() {
            if &bytes[i..i + sig.len()] == sig {
                let start = i;
                let mut end = i + sig.len();
                // A marker runs to the first character that cannot be part of
                // one — so it survives being pasted inside prose, a JSON
                // string, or an HTML attribute.
                while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-' || bytes[end] == b'_') {
                    end += 1;
                }
                out.push(text[start..end].to_string());
                i = end;
            } else {
                i += 1;
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Watermark a system prompt.
    ///
    /// The line is functional, not decorative: a model told to preserve an
    /// identifier will carry it into its output, so a transcript or a derived
    /// corpus keeps the trace. It is appended rather than prepended so it can
    /// never displace the instruction the prompt exists to give.
    pub fn watermark_prompt(&self, system: &str) -> String {
        format!(
            "{system}\n\n<!-- engine: {ENGINE} {} · build {} · run {} · {} -->",
            self.version,
            self.build,
            self.run,
            self.tag()
        )
    }

    /// Stamp a finding's JSON with the engine that produced it.
    ///
    /// Additive only: `_engine` and `_provenance` are new keys, and an existing
    /// stamp is left alone so re-reporting an old run does not rewrite history
    /// as if this build had found it.
    pub fn stamp(&self, value: &mut serde_json::Value) {
        let obj = match value.as_object_mut() {
            Some(o) => o,
            None => return,
        };
        if obj.contains_key("_engine") {
            return;
        }
        obj.insert("_engine".into(), serde_json::Value::String(self.build.clone()));
        obj.insert("_provenance".into(), serde_json::Value::String(self.tag()));
    }

    /// The manifest that ships beside a report.
    pub fn manifest(&self, target: &str, findings: &[crate::types::Finding]) -> Manifest {
        Manifest {
            engine: ENGINE.to_string(),
            version: self.version.clone(),
            build: self.build.clone(),
            run: self.run.clone(),
            customer: self.customer.clone(),
            target: target.to_string(),
            generated: now_secs(),
            findings: findings.len(),
            structure: structural_signature(findings),
            tag: self.tag(),
            signature: None,
        }
    }
}

/// Strip anything that would break a marker's own grammar.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).take(24).collect::<String>().to_lowercase()
}

/// A signature over the *shape* of a result set, not its text.
///
/// Wording can be rewritten and a report can be reformatted, but the set of
/// CWEs found, at which severities, against which endpoints, is a property of
/// the engine's behaviour. Two reports with the same structural signature came
/// from the same analysis; a plagiarised report keeps it even after the prose
/// is replaced, which is exactly the case a filename cannot answer.
pub fn structural_signature(findings: &[crate::types::Finding]) -> String {
    let mut rows: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "{}|{}|{}",
                f.cwe.trim().to_lowercase(),
                f.severity.trim().to_lowercase(),
                normalize_endpoint(&f.endpoint)
            )
        })
        .collect();
    // Order of discovery is incidental; the set is not.
    rows.sort();
    rows.dedup();
    hex12(rows.join("\n").as_bytes())
}

/// Endpoints differ by host and by id; the *shape* is what repeats.
fn normalize_endpoint(ep: &str) -> String {
    let path = ep
        .split_once("://")
        .map(|(_, rest)| rest.split_once('/').map(|(_, p)| p.to_string()).unwrap_or_default())
        .unwrap_or_else(|| ep.trim_start_matches('/').to_string());
    let path = path.split(['?', '#']).next().unwrap_or("").to_string();
    path.split('/')
        .map(|seg| {
            if seg.chars().any(|c| c.is_ascii_digit()) && seg.len() > 2 {
                "{id}"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
        .to_lowercase()
}

/// What ships beside a report so its origin is checkable later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub engine: String,
    pub version: String,
    pub build: String,
    pub run: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
    pub target: String,
    pub generated: u64,
    pub findings: usize,
    /// Signature over the finding set's shape (see [`structural_signature`]).
    pub structure: String,
    pub tag: String,
    /// HMAC over everything above, when a signing key was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Manifest {
    /// Bytes the signature covers: every field except the signature itself.
    fn signing_body(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        serde_json::to_vec(&unsigned).unwrap_or_default()
    }

    /// Sign the manifest. Without a key the manifest still ships — it just
    /// carries identity without proof, which is honest about what it is.
    pub fn sign(mut self, key: &[u8]) -> Manifest {
        let body = self.signing_body();
        self.signature = Some(hmac_hex(key, &body));
        self
    }

    /// Was this manifest signed by the holder of `key`, and does it still
    /// describe the findings it claims to?
    pub fn verify(&self, key: &[u8], findings: &[crate::types::Finding]) -> Result<(), String> {
        let sig = self.signature.as_ref().ok_or("manifest is unsigned")?;
        let expected = hmac_hex(key, &self.signing_body());
        if !constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
            return Err("signature does not match this key".into());
        }
        let actual = structural_signature(findings);
        if actual != self.structure {
            return Err(format!(
                "findings do not match the manifest: structure {} vs {}",
                actual, self.structure
            ));
        }
        Ok(())
    }
}

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    // HMAC-SHA256, spelled out rather than pulled in: the same construction
    // capability.rs uses, kept local so provenance has no new dependency.
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(cwe: &str, sev: &str, ep: &str) -> crate::types::Finding {
        crate::types::Finding {
            cwe: cwe.into(),
            severity: sev.into(),
            endpoint: ep.into(),
            ..Default::default()
        }
    }

    #[test]
    fn process_provenance_is_stable_once_bound() {
        let a = Provenance::process().run.clone();
        let b = Provenance::process().run.clone();
        assert_eq!(a, b, "markers minted in one process must agree on the run");
        // Binding after the fact must not move the ground under markers that
        // already went out.
        let c = Provenance::bind_run("ns-9-other").run.clone();
        assert_eq!(a, c, "first identity wins");
    }

    #[test]
    fn build_fingerprint_is_stable_within_a_build() {
        assert_eq!(Provenance::build_fingerprint(), Provenance::build_fingerprint());
        assert_eq!(Provenance::build_fingerprint().len(), 12);
    }

    #[test]
    fn markers_are_unique_and_findable() {
        let p = Provenance::for_run("ns-1-example");
        let a = p.marker("xss");
        let b = p.marker("xss");
        assert_ne!(a, b, "two probes must not share a marker — a repeat proves nothing");
        assert!(Provenance::is_ours(&a));
        // Pasted inside a response body, the marker still comes back out whole.
        let body = format!("<div title=\"{a}\">hello</div> and {b}.");
        let found = Provenance::extract(&body);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&a) && found.contains(&b));
    }

    #[test]
    fn prompt_watermark_keeps_the_instruction_first() {
        let p = Provenance::for_run("ns-1-x");
        let w = p.watermark_prompt("You are a scanner. Report only what you proved.");
        assert!(w.starts_with("You are a scanner."), "the watermark must never displace the prompt");
        assert!(w.contains(SIGIL));
    }

    #[test]
    fn stamping_is_additive_and_never_rewrites_history() {
        let p = Provenance::for_run("ns-1-x");
        let mut v = serde_json::json!({"title": "Reflected XSS", "_engine": "older-build"});
        p.stamp(&mut v);
        assert_eq!(v["_engine"], "older-build", "an existing stamp is evidence, not a default");

        let mut fresh = serde_json::json!({"title": "Reflected XSS"});
        p.stamp(&mut fresh);
        assert_eq!(fresh["_engine"], Provenance::build_fingerprint());
        assert!(fresh["_provenance"].as_str().unwrap().contains(SIGIL));
    }

    #[test]
    fn structure_survives_reordering_and_rewording_but_not_a_changed_result() {
        let a = vec![
            finding("CWE-79", "high", "https://x.test/search?q=1"),
            finding("CWE-307", "medium", "https://x.test/api/login"),
        ];
        let reordered = vec![a[1].clone(), a[0].clone()];
        assert_eq!(structural_signature(&a), structural_signature(&reordered));

        // Same endpoint family, different id — still the same finding.
        let same_family = vec![
            finding("CWE-79", "high", "https://x.test/search?q=9999"),
            finding("CWE-307", "medium", "https://x.test/api/login"),
        ];
        assert_eq!(structural_signature(&a), structural_signature(&same_family));

        // A different severity is a different result.
        let downgraded = vec![finding("CWE-79", "low", "https://x.test/search?q=1"), a[1].clone()];
        assert_ne!(structural_signature(&a), structural_signature(&downgraded));
    }

    #[test]
    fn manifest_signature_catches_a_swapped_finding_set() {
        let key = b"release-signing-key";
        let findings = vec![finding("CWE-79", "high", "https://x.test/search")];
        let m = Provenance::for_run("ns-1-x").manifest("https://x.test", &findings).sign(key);

        assert!(m.verify(key, &findings).is_ok());
        assert!(m.verify(b"someone-elses-key", &findings).is_err(), "a manifest must not verify under the wrong key");

        let tampered = vec![finding("CWE-89", "critical", "https://x.test/search")];
        let err = m.verify(key, &tampered).unwrap_err();
        assert!(err.contains("do not match"), "got: {err}");
    }

    #[test]
    fn unsigned_manifest_says_so_rather_than_passing() {
        let findings = vec![finding("CWE-79", "high", "https://x.test/s")];
        let m = Provenance::for_run("ns-1-x").manifest("https://x.test", &findings);
        assert_eq!(m.verify(b"k", &findings).unwrap_err(), "manifest is unsigned");
    }
}
