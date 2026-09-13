//! Capability tokens — authorization the harness can verify, not just trust.
//!
//! Everything in [`crate::scope`] and [`crate::policy`] is configuration: the
//! operator types a scope, the harness enforces it. That is right for a local
//! run and not enough for a real engagement, where the person running the tool
//! and the person who authorized the test are different people, and the client
//! wants the boundary to be theirs rather than whatever was typed at the
//! keyboard.
//!
//! A capability token is that grant, made checkable: an HMAC-signed statement
//! of *who authorized what, against which hosts, in which environment, until
//! when*. The harness verifies the signature with a shared secret, refuses an
//! expired or not-yet-valid token, and then treats the token as the ceiling —
//! local configuration may narrow it and can never widen it.
//!
//! ```text
//! ns-cap.v1.<base64url(payload json)>.<base64url(hmac-sha256)>
//! ```
//!
//! Two properties worth stating plainly:
//!
//! - **The token narrows, never widens.** [`CapabilityToken::constrain`] takes
//!   the intersection with the local policy. A token that says `*.example.com`
//!   does not authorize a run configured for one host to wander to the others.
//! - **It is not a secret store.** The signature proves the grant was issued by
//!   someone holding the key; it does not encrypt anything. Never put
//!   credentials in a token — its payload is readable by anyone holding it.

use crate::policy::{ActionKind, Environment};
use crate::scope::{Pattern, ScopePolicy};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const PREFIX: &str = "ns-cap.v1.";

/// The signed statement of what is authorized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    /// Stable id, quoted in every audit record so an action can be traced back
    /// to the grant that permitted it.
    pub id: String,
    /// Who authorized the engagement (the client contact, ticket, or system).
    pub issuer: String,
    /// Who it was issued to (the tester or team).
    pub subject: String,
    /// Hosts / wildcards / CIDRs / URL prefixes this grant covers.
    #[serde(default)]
    pub scope: Vec<String>,
    /// Explicit exclusions inside that scope.
    #[serde(default)]
    pub exclude: Vec<String>,
    pub environment: Environment,
    /// The strongest action this grant permits.
    pub max_action: ActionKind,
    /// Ceiling on `effective_risk` (see [`crate::policy::Risk`]).
    pub max_risk: f64,
    /// Unix seconds. A grant without an end is not a grant, it is a standing
    /// permission nobody remembers issuing.
    pub expires_at: u64,
    #[serde(default)]
    pub not_before: u64,
    /// Free-text reference (engagement id, statement of work, ticket).
    #[serde(default)]
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenError {
    Malformed(String),
    BadSignature,
    Expired { expired_at: u64, now: u64 },
    NotYetValid { starts_at: u64, now: u64 },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Malformed(w) => write!(f, "capability token is malformed: {w}"),
            TokenError::BadSignature => write!(f, "capability token signature does not verify — it was not issued by the holder of this key, or it was altered"),
            TokenError::Expired { expired_at, now } => write!(f, "capability token expired {}s ago", now.saturating_sub(*expired_at)),
            TokenError::NotYetValid { starts_at, now } => write!(f, "capability token is not valid for another {}s", starts_at.saturating_sub(*now)),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

impl Capability {
    /// Sign this grant with the issuer's key.
    pub fn issue(&self, key: &[u8]) -> String {
        let payload = serde_json::to_vec(self).unwrap_or_default();
        let body = b64().encode(&payload);
        let sig = sign(key, body.as_bytes());
        format!("{PREFIX}{body}.{}", b64().encode(sig))
    }

    /// Verify a token and return the grant it carries.
    ///
    /// Signature first, then validity window: a well-formed token from the
    /// wrong key must never get as far as having its claims read, or an
    /// attacker-supplied "grant" decides what the harness believes.
    pub fn verify(token: &str, key: &[u8]) -> Result<Capability, TokenError> {
        let rest = token.trim().strip_prefix(PREFIX).ok_or_else(|| TokenError::Malformed("wrong prefix or version".into()))?;
        let (body, sig_b64) = rest.rsplit_once('.').ok_or_else(|| TokenError::Malformed("missing signature".into()))?;
        let expected = sign(key, body.as_bytes());
        let given = b64().decode(sig_b64).map_err(|_| TokenError::Malformed("signature is not base64url".into()))?;
        if !constant_time_eq(&expected, &given) {
            return Err(TokenError::BadSignature);
        }
        let payload = b64().decode(body).map_err(|_| TokenError::Malformed("payload is not base64url".into()))?;
        let cap: Capability = serde_json::from_slice(&payload).map_err(|e| TokenError::Malformed(e.to_string()))?;
        let t = now();
        if cap.not_before > 0 && t < cap.not_before {
            return Err(TokenError::NotYetValid { starts_at: cap.not_before, now: t });
        }
        if cap.expires_at > 0 && t > cap.expires_at {
            return Err(TokenError::Expired { expired_at: cap.expires_at, now: t });
        }
        Ok(cap)
    }

    /// Read a token's claims WITHOUT verifying them — for displaying an
    /// unverified token in a UI. Never use this to make a decision.
    pub fn peek(token: &str) -> Option<Capability> {
        let rest = token.trim().strip_prefix(PREFIX)?;
        let (body, _) = rest.rsplit_once('.')?;
        serde_json::from_slice(&b64().decode(body).ok()?).ok()
    }

    /// Intersect a local policy with this grant.
    ///
    /// The token is the ceiling: entries the operator configured that the grant
    /// does not cover are dropped (and reported), and the grant's exclusions are
    /// added. Configuration can only ever be narrower than the authorization it
    /// runs under.
    pub fn constrain(&self, local: &ScopePolicy) -> (ScopePolicy, Vec<String>) {
        let mut granted = ScopePolicy::default();
        for s in &self.scope {
            granted.allow(s);
        }
        for e in &self.exclude {
            granted.deny(e);
        }
        granted.soft = local.soft.clone();

        let mut dropped = Vec::new();
        let mut kept: Vec<Pattern> = Vec::new();
        for p in &local.hard {
            // A local entry survives only if the grant covers it. Host-shaped
            // patterns are checked as a URL; anything the grant does not match
            // is refused rather than silently kept.
            let probe = format!("https://{}", p.as_text().trim_start_matches("*."));
            if granted.in_hard_scope(&probe) {
                kept.push(p.clone());
            } else {
                dropped.push(p.as_text());
            }
        }
        let mut out = if kept.is_empty() {
            // The operator configured nothing the grant covers (or configured
            // nothing at all) — fall back to exactly what was granted.
            granted.clone()
        } else {
            let mut o = ScopePolicy::default();
            o.hard = kept;
            o.soft = local.soft.clone();
            o
        };
        for e in &self.exclude {
            out.deny(e);
        }
        for e in &local.exclude {
            out.deny(&e.as_text());
        }
        (out, dropped)
    }

    /// Is this action kind within the grant?
    pub fn permits(&self, action: ActionKind) -> bool {
        rank(action) <= rank(self.max_action)
    }

    pub fn summary(&self) -> String {
        let left = self.expires_at.saturating_sub(now());
        format!(
            "{} · issued by {} to {} · {} · max {} · risk ≤ {:.1} · {}",
            self.id,
            self.issuer,
            self.subject,
            self.scope.join(","),
            self.max_action.as_str(),
            self.max_risk,
            if self.expires_at == 0 {
                "no expiry".to_string()
            } else if left == 0 {
                "EXPIRED".to_string()
            } else {
                format!("{}h left", left / 3600)
            }
        )
    }
}

fn rank(a: ActionKind) -> u8 {
    match a {
        ActionKind::Read => 0,
        ActionKind::Enumerate => 1,
        ActionKind::Authenticate => 2,
        ActionKind::ProbeExploit => 3,
        ActionKind::Write => 4,
        ActionKind::Disruptive => 5,
    }
}

fn sign(key: &[u8], body: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Compare without an early return, so a forged signature cannot be recovered
/// byte by byte from how long the check took.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The signing key, from `NEUROSPLOIT_CAPABILITY_KEY` or a file path in
/// `NEUROSPLOIT_CAPABILITY_KEY_FILE`. Returns `None` when no key is
/// configured — in which case tokens cannot be verified and the harness must
/// say so rather than accepting them.
pub fn key_from_env() -> Option<Vec<u8>> {
    if let Ok(k) = std::env::var("NEUROSPLOIT_CAPABILITY_KEY") {
        if !k.trim().is_empty() {
            return Some(k.into_bytes());
        }
    }
    if let Ok(p) = std::env::var("NEUROSPLOIT_CAPABILITY_KEY_FILE") {
        if let Ok(bytes) = std::fs::read(p.trim()) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap() -> Capability {
        Capability {
            id: "cap-001".into(),
            issuer: "acme-security@example.com".into(),
            subject: "red-team".into(),
            scope: vec!["*.example.com".into()],
            exclude: vec!["payments.example.com".into()],
            environment: Environment::Production,
            max_action: ActionKind::ProbeExploit,
            max_risk: 3.5,
            expires_at: now() + 3600,
            not_before: 0,
            reference: "SOW-2026-14".into(),
        }
    }

    #[test]
    fn a_token_round_trips_and_verifies() {
        let t = cap().issue(b"secret-key");
        let back = Capability::verify(&t, b"secret-key").expect("must verify");
        assert_eq!(back, cap());
    }

    #[test]
    fn a_token_signed_with_another_key_is_refused() {
        let t = cap().issue(b"secret-key");
        assert_eq!(Capability::verify(&t, b"different-key"), Err(TokenError::BadSignature));
    }

    #[test]
    fn altering_the_claims_breaks_the_signature() {
        let t = cap().issue(b"secret-key");
        // Widen the scope by hand, the way an over-eager tester might.
        let mut forged = cap();
        forged.scope = vec!["*".into()];
        let payload = b64().encode(serde_json::to_vec(&forged).unwrap());
        let sig = t.rsplit_once('.').unwrap().1;
        let tampered = format!("{PREFIX}{payload}.{sig}");
        assert_eq!(Capability::verify(&tampered, b"secret-key"), Err(TokenError::BadSignature));
    }

    #[test]
    fn an_expired_token_is_refused_even_with_a_valid_signature() {
        let mut c = cap();
        c.expires_at = now() - 10;
        let t = c.issue(b"secret-key");
        match Capability::verify(&t, b"secret-key") {
            Err(TokenError::Expired { .. }) => {}
            other => panic!("an expired grant is not a grant: {other:?}"),
        }
    }

    #[test]
    fn a_token_that_has_not_started_is_refused() {
        let mut c = cap();
        c.not_before = now() + 600;
        let t = c.issue(b"secret-key");
        assert!(matches!(Capability::verify(&t, b"secret-key"), Err(TokenError::NotYetValid { .. })));
    }

    #[test]
    fn the_grant_narrows_local_scope_and_never_widens_it() {
        let c = cap();
        let mut local = ScopePolicy::default();
        local.allow("app.example.com");
        local.allow("unrelated.test"); // not covered by the grant
        let (effective, dropped) = c.constrain(&local);
        assert!(effective.in_hard_scope("https://app.example.com/x"));
        assert!(!effective.in_hard_scope("https://unrelated.test/"), "a host outside the grant must not survive");
        assert_eq!(dropped, vec!["unrelated.test"]);
        // The grant's own exclusion still applies to everything.
        assert!(!effective.in_hard_scope("https://payments.example.com/"));
    }

    #[test]
    fn an_empty_local_policy_inherits_exactly_what_was_granted() {
        let (effective, dropped) = cap().constrain(&ScopePolicy::default());
        assert!(dropped.is_empty());
        assert!(effective.in_hard_scope("https://api.example.com/"));
        assert!(!effective.in_hard_scope("https://payments.example.com/"));
    }

    #[test]
    fn the_grant_caps_which_actions_are_permitted() {
        let c = cap(); // max_action = ProbeExploit
        assert!(c.permits(ActionKind::Read));
        assert!(c.permits(ActionKind::ProbeExploit));
        assert!(!c.permits(ActionKind::Write));
        assert!(!c.permits(ActionKind::Disruptive));
    }

    #[test]
    fn peek_reads_claims_but_is_not_a_decision() {
        let t = cap().issue(b"secret-key");
        assert_eq!(Capability::peek(&t).unwrap().id, "cap-001");
        // Even garbage signatures peek fine — which is exactly why peek must
        // never gate anything.
        let tampered = format!("{}.{}", t.rsplit_once('.').unwrap().0, b64().encode(b"nonsense"));
        assert!(Capability::peek(&tampered).is_some());
        assert!(Capability::verify(&tampered, b"secret-key").is_err());
    }

    #[test]
    fn malformed_input_is_reported_as_malformed_not_as_a_bad_signature() {
        assert!(matches!(Capability::verify("not-a-token", b"k"), Err(TokenError::Malformed(_))));
        assert!(matches!(Capability::verify("ns-cap.v1.nosignature", b"k"), Err(TokenError::Malformed(_))));
    }
}
