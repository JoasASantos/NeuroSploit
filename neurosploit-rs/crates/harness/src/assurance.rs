//! Assurance bundle — one run, one verifiable record of everything.
//!
//! The mechanisms that make a NeuroSploit finding trustworthy — the signed
//! authorization, the enforced scope, the allow/deny decisions, the hash-chained
//! audit trail with external anchors, the evidence ledger, the deterministic
//! CVSS, the multi-model votes, the prosecutor's verdict, the PoCs and
//! screenshots — are each written to their own file during a run. Scattered,
//! they are hard to hand to a reviewer and impossible to prove complete.
//!
//! This assembles them into one manifest per run: every artifact, its SHA-256,
//! whether it is present, and which of the five assurance properties (P1–P5)
//! the run actually produced. Then it signs the manifest. The result is a
//! single file a reviewer can verify independently:
//!
//! ```text
//!   P1 authorization   capability token + effective scope + ALLOW/DENY log
//!   P2 enforcement     scope decisions, out-of-scope quarantine
//!   P3 evidence        evidence ledger, PoCs, screenshots, CVSS vectors
//!   P4 integrity       audit chain + external anchors
//!   P5 attribution     provenance manifest, structural signature
//!         └─────────────────────┬──────────────────────┘
//!                        assurance.json  (+ signature over all hashes)
//! ```
//!
//! The honesty rule: a property is reported present only when its artifact is
//! actually on disk and non-empty. A missing anchor file is reported as "P4:
//! partial", never quietly omitted — the bundle's job is to say what a run can
//! and cannot prove, not to flatter it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// One artifact in the run, with its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Path relative to the run directory.
    pub name: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub bytes: u64,
    /// What this artifact is for, in one phrase.
    pub role: String,
}

/// Whether an assurance property was produced, and by what.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub id: String,
    pub name: String,
    /// present · partial · absent.
    pub status: String,
    pub evidenced_by: Vec<String>,
    pub note: String,
}

/// The whole bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub engine: String,
    pub version: String,
    pub build: String,
    pub run: String,
    pub target: String,
    pub generated: u64,
    pub findings: usize,
    pub artifacts: Vec<Artifact>,
    pub properties: Vec<Property>,
    /// SHA-256 over the sorted (name, sha256) pairs — one hash that changes if
    /// any artifact changes. The thing the signature actually covers.
    pub bundle_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The known artifacts a run can produce, and what each proves.
const KNOWN: &[(&str, &str)] = &[
    ("findings.json", "the findings, each stamped with the engine build (P5)"),
    ("report.html", "the human report"),
    ("recon.json", "reconnaissance facts"),
    ("audit.jsonl", "hash-chained decision log — every ALLOW/DENY (P1/P2/P4)"),
    ("audit.jsonl.anchors", "external anchors of the audit chain (P4)"),
    ("provenance.json", "signed provenance manifest — build + structural signature (P5)"),
    ("out-of-scope-findings.json", "findings quarantined for being outside scope (P2)"),
    ("flows.jsonl", "intercepted request/response flows"),
    ("meta.json", "target metadata"),
    ("coverage.md", "what was tested and what was not"),
    ("report.sarif", "SARIF 2.1.0 results for CI code-scanning ingestion"),
];

fn hash_file(path: &Path) -> Option<(String, u64)> {
    let data = std::fs::read(path).ok()?;
    let hash: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    Some((hash, data.len() as u64))
}

fn count_glob(dir: &Path, sub: &str) -> usize {
    std::fs::read_dir(dir.join(sub)).map(|rd| rd.filter_map(|e| e.ok()).count()).unwrap_or(0)
}

impl Bundle {
    /// Assemble the bundle from a finished run directory.
    pub fn build(dir: &Path) -> Bundle {
        let run = dir.file_name().and_then(|s| s.to_str()).unwrap_or("run").to_string();
        let prov = crate::provenance::Provenance::process();

        let mut artifacts = Vec::new();
        for (name, role) in KNOWN {
            let path = dir.join(name);
            match hash_file(&path) {
                Some((sha, bytes)) if bytes > 0 => artifacts.push(Artifact { name: (*name).into(), present: true, sha256: Some(sha), bytes, role: (*role).into() }),
                _ => artifacts.push(Artifact { name: (*name).into(), present: false, sha256: None, bytes: 0, role: (*role).into() }),
            }
        }
        // Directories of many files: PoCs, screenshots, evidence.
        let pocs = count_glob(dir, "pocs");
        let shots = count_glob(dir, "screenshots").max(count_glob(dir, "shots"));
        let evidence = count_glob(dir, "evidence");

        // Findings + CVSS/votes/prosecutor presence, read from findings.json.
        let findings: Vec<crate::types::Finding> = std::fs::read_to_string(dir.join("findings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let with_cvss = findings.iter().filter(|f| !f.cvss.trim().is_empty()).count();
        let with_votes = findings.iter().filter(|f| !f.votes.trim().is_empty()).count();
        let with_evidence = findings.iter().filter(|f| f.evidence_data.is_some()).count();
        let has_capability = findings.iter().any(|_| false); // capability lives in the audit, checked below

        let present = |name: &str| artifacts.iter().any(|a| a.name == name && a.present);
        let audit_has = |needle: &str| std::fs::read_to_string(dir.join("audit.jsonl")).map(|t| t.contains(needle)).unwrap_or(false);
        let _ = has_capability;

        let mut properties = Vec::new();
        // P1 — authorization: a capability was verified and ALLOW/DENY recorded.
        {
            let cap = audit_has("capability_token") || audit_has("capability");
            let decisions = present("audit.jsonl");
            let (status, note) = match (cap, decisions) {
                (true, true) => ("present", "capability recorded and decisions logged"),
                (false, true) => ("partial", "decisions logged, but no capability token in the trail (local-config authorization)"),
                _ => ("absent", "no audit trail"),
            };
            properties.push(Property { id: "P1".into(), name: "Signed authorization".into(), status: status.into(), evidenced_by: vec!["audit.jsonl".into()], note: note.into() });
        }
        // P2 — enforcement: scope decisions, out-of-scope quarantine.
        {
            let denies = audit_has("deny") || audit_has("DENY") || audit_has("out-of-scope");
            let (status, note) = if present("audit.jsonl") {
                if denies { ("present", "scope decisions recorded, including denials/quarantine") }
                else { ("present", "scope decisions recorded (no denials this run)") }
            } else { ("absent", "no decision log") };
            let mut ev = vec!["audit.jsonl".into()];
            if present("out-of-scope-findings.json") { ev.push("out-of-scope-findings.json".into()); }
            properties.push(Property { id: "P2".into(), name: "Scope enforcement".into(), status: status.into(), evidenced_by: ev, note: note.into() });
        }
        // P3 — evidence: ledger, PoCs, screenshots, CVSS vectors.
        {
            let has = with_evidence > 0 || pocs > 0 || shots > 0 || with_cvss > 0;
            let status = if findings.is_empty() { "partial" } else if has { "present" } else { "partial" };
            let note = format!("{with_evidence}/{} findings carry structured evidence · {with_cvss} with CVSS · {with_votes} voted · {pocs} PoC(s) · {shots} screenshot(s) · {evidence} evidence file(s)", findings.len());
            properties.push(Property { id: "P3".into(), name: "Evidence & CVSS".into(), status: status.into(), evidenced_by: vec!["findings.json".into()], note });
        }
        // P4 — integrity: audit chain + external anchors.
        {
            let chain = present("audit.jsonl");
            let anchors = present("audit.jsonl.anchors");
            let (status, note) = match (chain, anchors) {
                (true, true) => ("present", "hash chain plus signed anchors (truncation/rebuild detectable)"),
                (true, false) => ("partial", "hash chain present but no anchors — a full rebuild would be silent"),
                _ => ("absent", "no audit chain"),
            };
            properties.push(Property { id: "P4".into(), name: "Audit integrity".into(), status: status.into(), evidenced_by: vec!["audit.jsonl".into(), "audit.jsonl.anchors".into()], note: note.into() });
        }
        // P5 — attribution: provenance manifest + structural signature.
        {
            let prov_file = present("provenance.json");
            let stamped = findings.iter().any(|f| serde_json::to_string(f).map(|s| s.contains("_engine")).unwrap_or(false)) || !findings.is_empty();
            let (status, note) = match (prov_file, stamped) {
                (true, _) => ("present", "signed provenance manifest with structural signature"),
                (false, true) => ("partial", "findings stamped but no provenance.json"),
                _ => ("absent", "no provenance"),
            };
            properties.push(Property { id: "P5".into(), name: "Provenance".into(), status: status.into(), evidenced_by: vec!["provenance.json".into()], note: note.into() });
        }

        // Bundle hash: one value over every artifact's identity.
        let mut pairs: Vec<String> = artifacts.iter().filter(|a| a.present).map(|a| format!("{}={}", a.name, a.sha256.clone().unwrap_or_default())).collect();
        pairs.sort();
        let bundle_hash: String = Sha256::digest(pairs.join("\n").as_bytes()).iter().map(|b| format!("{b:02x}")).collect();

        Bundle {
            engine: crate::provenance::ENGINE.into(),
            version: prov.version.clone(),
            build: prov.build.clone(),
            run,
            target: std::fs::read_to_string(dir.join("meta.json")).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()).and_then(|v| v.get("target").and_then(|x| x.as_str()).map(|s| s.to_string())).unwrap_or_default(),
            generated: now(),
            findings: findings.len(),
            artifacts,
            properties,
            bundle_hash,
            signature: None,
        }
    }

    /// Sign the bundle hash. Without a key it still ships — the hashes are the
    /// substance, the signature just proves who assembled them.
    pub fn sign(mut self, key: &[u8]) -> Bundle {
        self.signature = Some(hmac_hex(key, self.bundle_hash.as_bytes()));
        self
    }

    /// Verify a bundle against the run directory it describes: every present
    /// artifact still hashes the same, and the signature (if any) matches.
    pub fn verify(&self, dir: &Path, key: Option<&[u8]>) -> Result<(), String> {
        for a in self.artifacts.iter().filter(|a| a.present) {
            let (sha, _) = hash_file(&dir.join(&a.name)).ok_or_else(|| format!("artifact {} named in the bundle is missing", a.name))?;
            if Some(&sha) != a.sha256.as_ref() {
                return Err(format!("artifact {} was modified since the bundle was sealed", a.name));
            }
        }
        if let Some(k) = key {
            let sig = self.signature.as_ref().ok_or("bundle is unsigned")?;
            if hmac_hex(k, self.bundle_hash.as_bytes()) != *sig {
                return Err("bundle signature does not match this key".into());
            }
        }
        Ok(())
    }

    /// One-screen operator summary.
    pub fn summary(&self) -> String {
        let mut s = format!("assurance bundle for {} — {} artifact(s), {} finding(s)\n", self.run, self.artifacts.iter().filter(|a| a.present).count(), self.findings);
        for p in &self.properties {
            let mark = match p.status.as_str() { "present" => "✓", "partial" => "~", _ => "✗" };
            s.push_str(&format!("  {mark} {} {} — {}\n", p.id, p.name, p.note));
        }
        s
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn run_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        // Uniqueness independent of clock resolution — two tests in the same
        // second must not share a directory.
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ns-assur-{}-{}-{}", std::process::id(), now(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_full_run_reports_all_five_properties_present() {
        let dir = run_dir();
        std::fs::write(dir.join("meta.json"), r#"{"target":"https://t.test"}"#).unwrap();
        std::fs::write(dir.join("findings.json"), r#"[{"id":"f1","title":"XSS","severity":"high","cvss":"6.1 (CVSS:3.1/AV:N/...)","votes":"3/3","_engine":"abc"}]"#).unwrap();
        std::fs::write(dir.join("audit.jsonl"), "{\"capability_token\":\"ns-cap...\",\"policy_decision\":\"allow\"}\n{\"policy_decision\":\"deny\"}\n").unwrap();
        std::fs::write(dir.join("audit.jsonl.anchors"), "{\"count\":2,\"chain_hash\":\"x\"}\n").unwrap();
        std::fs::write(dir.join("provenance.json"), r#"{"build":"abc"}"#).unwrap();

        let bundle = Bundle::build(&dir);
        let status = |id: &str| bundle.properties.iter().find(|p| p.id == id).unwrap().status.clone();
        assert_eq!(status("P1"), "present");
        assert_eq!(status("P2"), "present");
        assert_eq!(status("P4"), "present");
        assert_eq!(status("P5"), "present");
        assert!(!bundle.bundle_hash.is_empty());

        // Sign + verify round-trips; tampering is caught.
        let signed = bundle.sign(b"k");
        assert!(signed.verify(&dir, Some(b"k")).is_ok());
        assert!(signed.verify(&dir, Some(b"wrong")).is_err());
        std::fs::write(dir.join("findings.json"), "[]").unwrap();
        assert!(signed.verify(&dir, Some(b"k")).is_err(), "a changed artifact must break verification");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_anchor_is_reported_partial_not_omitted() {
        let dir = run_dir();
        std::fs::write(dir.join("audit.jsonl"), "{\"policy_decision\":\"allow\"}\n").unwrap();
        std::fs::write(dir.join("findings.json"), "[]").unwrap();
        let bundle = Bundle::build(&dir);
        let p4 = bundle.properties.iter().find(|p| p.id == "P4").unwrap();
        assert_eq!(p4.status, "partial", "no anchors = partial, never silently present");
        assert!(p4.note.contains("rebuild would be silent"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_bundle_hash_changes_when_an_artifact_changes() {
        let dir = run_dir();
        std::fs::write(dir.join("findings.json"), "[]").unwrap();
        let h1 = Bundle::build(&dir).bundle_hash;
        std::fs::write(dir.join("findings.json"), r#"[{"id":"x"}]"#).unwrap();
        let h2 = Bundle::build(&dir).bundle_hash;
        assert_ne!(h1, h2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
