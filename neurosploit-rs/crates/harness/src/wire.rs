//! Wire-bound evidence — the validators judge what the wire showed, not what
//! the agent said.
//!
//! An agent's finding carries its own account of the exchanges that prove it:
//! the request it sent, the status and body it says came back. The
//! deterministic validators in [`crate::validation`] are strict about what an
//! exchange must show, but until this pass they were strict about the agent's
//! *description* of the exchange. That is the weak link: a model that
//! misremembers a status, pastes a narrative where the body should be, or
//! confuses two requests produces evidence nobody observed.
//!
//! This pass runs before validation, on every finding, with no switch:
//!
//! 1. **Recorded traffic.** When the recording interceptor ran, each claimed
//!    exchange is matched against `flows.jsonl` by method and URL. A recorded
//!    status that differs from the agent's is a contradiction. A claimed request
//!    to a host the interceptor never saw is noted (a signal — tools can bypass
//!    a proxy — not a verdict).
//! 2. **Replay.** The harness re-sends the request itself through
//!    [`crate::replay::ReplayEngine`] — its own client, behind the scope guard,
//!    never a mutating verb. If the wire reproduces the account (same status
//!    class, the harness marker still present), the observation *replaces* the
//!    agent's account, so the validator judges real bytes. If it does not, the
//!    disagreement is recorded and [`crate::validation::judge`] will not let the
//!    finding stand as confirmed.
//!
//! What cannot be checked — a DELETE, an identity whose credentials were not
//! recorded, a host the scope guard refuses — is counted as unverified and left
//! exactly as the agent reported it. Nothing here ever upgrades a verdict.

use crate::proxy::Flow;
use crate::replay::{spec_of, ReplayEngine};
use crate::validation::{Evidence, Exchange, WireCheck};

/// Read the recording interceptor's log for a run (empty when it did not run).
pub fn load_flows(workdir: Option<&str>) -> Vec<Flow> {
    let Some(d) = workdir else { return Vec::new() };
    let Ok(text) = std::fs::read_to_string(std::path::Path::new(d).join("flows.jsonl")) else { return Vec::new() };
    text.lines().filter_map(|l| serde_json::from_str::<Flow>(l).ok()).collect()
}

/// URL without fragment or trailing slash, lower-cased scheme/host.
fn norm(url: &str) -> String {
    let u = url.split('#').next().unwrap_or(url).trim();
    let u = u.trim_end_matches('/');
    match u.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            format!("{}://{}{}", scheme.to_lowercase(), host.to_lowercase(), path)
        }
        None => u.to_string(),
    }
}

fn host(url: &str) -> String {
    crate::scope::host_of(url).to_lowercase()
}

/// The exchange carries recorded credentials, so a replay acts as the same identity.
fn has_auth(x: &Exchange) -> bool {
    x.request_headers.keys().any(|k| matches!(k.to_ascii_lowercase().as_str(), "authorization" | "cookie" | "x-api-key" | "x-auth-token"))
}

fn class(status: u16) -> u16 {
    status / 100
}

/// Did the observation reproduce what the agent reported?
fn reproduces(claimed: &Exchange, observed: &Exchange, marker: &str) -> Result<(), String> {
    if claimed.status != 0 && class(claimed.status) != class(observed.status) {
        return Err(format!("the agent reported HTTP {}, the wire returned HTTP {}", claimed.status, observed.status));
    }
    if !marker.is_empty() && claimed.body.contains(marker) && !observed.body.contains(marker) {
        return Err(format!("the harness marker `{marker}` the agent reported is absent from the wire response"));
    }
    Ok(())
}

/// Check one exchange. Replaces it with the wire observation when reproduced.
async fn check(x: &mut Exchange, role: &str, marker: &str, engine: &ReplayEngine, flows: &[Flow], replay: bool, wc: &mut WireCheck, notes: &mut Vec<String>) {
    if x.from_wire() {
        wc.harness_observed += 1;
        return;
    }
    if x.url.trim().is_empty() {
        wc.unverified += 1;
        return;
    }
    let method = if x.method.is_empty() { "GET".to_string() } else { x.method.to_uppercase() };

    // 1. The recording interceptor's view.
    let mut corroborated = false;
    if !flows.is_empty() {
        let target = norm(&x.url);
        match flows.iter().rev().find(|f| !f.tunnelled && f.method.eq_ignore_ascii_case(&method) && norm(&f.url) == target) {
            Some(fl) if x.status == 0 || fl.status == x.status => {
                wc.corroborated += 1;
                corroborated = true;
            }
            Some(fl) => wc.contradicted.push(format!(
                "{role}: the recording interceptor saw {method} {} return HTTP {}, the agent reported HTTP {}",
                x.url, fl.status, x.status
            )),
            None => {
                let h = host(&x.url);
                if !h.is_empty() && !flows.iter().any(|f| host(&f.url) == h || f.url.to_lowercase().starts_with(&h)) {
                    wc.absent_from_capture.push(format!("{role}: {method} {}", x.url));
                }
            }
        }
    }

    // 2. The harness re-observes it.
    let spec = spec_of(x);
    let can_replay = replay && !spec.is_mutating() && (x.identity.is_empty() || has_auth(x));
    if !can_replay {
        if !corroborated {
            wc.unverified += 1;
        }
        return;
    }
    match engine.send(&spec).await {
        Ok(mut obs) => match reproduces(x, &obs, marker) {
            Ok(()) => {
                notes.push(format!("{role}: the agent's account was replaced by the harness's own observation (HTTP {} → HTTP {})", x.status, obs.status));
                obs.identity = x.identity.clone();
                *x = obs;
                wc.reproduced += 1;
            }
            Err(why) => wc.contradicted.push(format!("{role}: {why}")),
        },
        Err(_) => {
            if !corroborated {
                wc.unverified += 1;
            }
        }
    }
}

/// Check every exchange in a finding's evidence against the wire.
pub async fn verify(ev: &mut Evidence, engine: &ReplayEngine, flows: &[Flow], replay: bool) -> WireCheck {
    let mut wc = WireCheck::default();
    let marker = ev.marker.clone();
    let mut notes: Vec<String> = Vec::new();
    if let Some(x) = ev.baseline.as_mut() {
        check(x, "control", &marker, engine, flows, replay, &mut wc, &mut notes).await;
    }
    if let Some(x) = ev.attack.as_mut() {
        check(x, "attack", &marker, engine, flows, replay, &mut wc, &mut notes).await;
    }
    if let Some(x) = ev.identity_a.as_mut() {
        check(x, "identity A", &marker, engine, flows, replay, &mut wc, &mut notes).await;
    }
    if let Some(x) = ev.identity_b.as_mut() {
        check(x, "identity B", &marker, engine, flows, replay, &mut wc, &mut notes).await;
    }
    if let Some(o) = ev.oracle.as_mut() {
        check(&mut o.privileged, "oracle privileged", &marker, engine, flows, replay, &mut wc, &mut notes).await;
        check(&mut o.denied, "oracle denied", &marker, engine, flows, replay, &mut wc, &mut notes).await;
    }
    for p in ev.matrix.iter_mut() {
        let role = format!("matrix {}", p.identity);
        check(&mut p.exchange, &role, &marker, engine, flows, replay, &mut wc, &mut notes).await;
    }
    // Repeats the agent typed in are accounts too; the harness's own repeats
    // (added by the evidence-gap loop) are already wire.
    for r in ev.repeats.iter() {
        if r.from_wire() {
            wc.harness_observed += 1;
        }
    }
    ev.notes.extend(notes);
    wc
}

/// One line for the operator.
pub fn summary(checks: &[WireCheck]) -> String {
    let (mut rep, mut cor, mut har, mut unv, mut con, mut abs) = (0, 0, 0, 0, 0, 0);
    for w in checks {
        rep += w.reproduced;
        cor += w.corroborated;
        har += w.harness_observed;
        unv += w.unverified;
        con += w.contradicted.len();
        abs += w.absent_from_capture.len();
    }
    format!(
        "wire: {rep} exchange(s) re-observed by the harness, {cor} corroborated by recorded traffic, {har} already harness-observed, {con} contradicted, {unv} unverifiable{}",
        if abs > 0 { format!(", {abs} absent from the capture") } else { String::new() }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopePolicy;

    fn ex(method: &str, url: &str, status: u16, body: &str) -> Exchange {
        Exchange { method: method.into(), url: url.into(), status, body: body.into(), ..Default::default() }
    }
    fn flow(method: &str, url: &str, status: u16) -> Flow {
        Flow { method: method.into(), url: url.into(), status, ..Default::default() }
    }
    fn engine() -> ReplayEngine {
        ReplayEngine::new(ScopePolicy::from_yaml("hard:\n  - t.test\n"))
    }

    #[tokio::test]
    async fn recorded_status_contradiction_is_caught() {
        let mut ev = Evidence { attack: Some(ex("GET", "http://t.test/admin", 200, "admin panel")), ..Default::default() };
        let flows = vec![flow("GET", "http://t.test/admin", 403)];
        let wc = verify(&mut ev, &engine(), &flows, false).await;
        assert_eq!(wc.contradicted.len(), 1, "{wc:?}");
        assert!(wc.contradicted[0].contains("403"));
    }

    #[tokio::test]
    async fn recorded_match_corroborates() {
        let mut ev = Evidence { attack: Some(ex("GET", "http://t.test/admin/", 200, "admin panel")), ..Default::default() };
        let flows = vec![flow("GET", "http://T.TEST/admin", 200)];
        let wc = verify(&mut ev, &engine(), &flows, false).await;
        assert_eq!(wc.corroborated, 1);
        assert!(wc.contradicted.is_empty());
    }

    #[tokio::test]
    async fn request_to_unseen_host_is_flagged_absent() {
        let mut ev = Evidence { attack: Some(ex("GET", "http://t.test/x", 200, "x")), ..Default::default() };
        let flows = vec![flow("GET", "http://other.test/y", 200)];
        let wc = verify(&mut ev, &engine(), &flows, false).await;
        assert_eq!(wc.absent_from_capture.len(), 1);
    }

    #[tokio::test]
    async fn harness_observed_is_not_rechecked() {
        let mut x = ex("GET", "http://t.test/x", 200, "x");
        x.provenance = "wire:harness".into();
        let mut ev = Evidence { attack: Some(x), ..Default::default() };
        let wc = verify(&mut ev, &engine(), &[], true).await;
        assert_eq!(wc.harness_observed, 1);
        assert_eq!(wc.unverified, 0);
    }

    #[tokio::test]
    async fn mutating_and_credentialless_identity_are_unverified_not_contradicted() {
        let mut del = ex("DELETE", "http://t.test/users/1", 200, "deleted");
        del.identity = String::new();
        let mut b = ex("GET", "http://t.test/orders/9", 200, "other's order");
        b.identity = "userB".into(); // no recorded credentials → cannot act as B
        let mut ev = Evidence { attack: Some(del), identity_b: Some(b), ..Default::default() };
        let wc = verify(&mut ev, &engine(), &[], true).await;
        assert_eq!(wc.unverified, 2, "{wc:?}");
        assert!(wc.contradicted.is_empty());
    }

    /// A one-shot local HTTP server returning a fixed status/body to every request.
    async fn serve(status: u16, body: &'static str) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!("HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    #[tokio::test]
    async fn live_replay_replaces_or_contradicts() {
        let base = serve(200, "hello ns-mark-77 world").await;
        let engine = ReplayEngine::new(ScopePolicy::from_yaml("hard:\n  - 127.0.0.1\n"));
        // Agent's account matches the wire → replaced by the harness observation.
        let mut ev = Evidence { marker: "ns-mark-77".into(), attack: Some(ex("GET", &format!("{base}/p"), 200, "agent says ns-mark-77")), ..Default::default() };
        let wc = verify(&mut ev, &engine, &[], true).await;
        if wc.unverified == 1 {
            eprintln!("replay refused by the scope/netguard for loopback — skipping live assertion");
            return;
        }
        assert_eq!(wc.reproduced, 1, "{wc:?}");
        let a = ev.attack.as_ref().unwrap();
        assert_eq!(a.provenance, "wire:replay");
        assert!(a.body.contains("hello ns-mark-77"), "the validator must now see real bytes: {}", a.body);
        // Agent claims a 500 SQL error the wire never produced → contradiction.
        let mut ev2 = Evidence { attack: Some(ex("GET", &format!("{base}/q"), 500, "SQL syntax error")), ..Default::default() };
        let wc2 = verify(&mut ev2, &engine, &[], true).await;
        assert_eq!(wc2.contradicted.len(), 1, "{wc2:?}");
        assert!(wc2.contradicted[0].contains("HTTP 500") && wc2.contradicted[0].contains("HTTP 200"));
    }

    #[test]
    fn reproduction_rules() {
        let claimed = ex("GET", "u", 200, "proof ns-marker-1");
        assert!(reproduces(&claimed, &ex("GET", "u", 204, "ns-marker-1 here"), "ns-marker-1").is_ok());
        assert!(reproduces(&claimed, &ex("GET", "u", 403, "nope"), "ns-marker-1").is_err());
        assert!(reproduces(&claimed, &ex("GET", "u", 200, "no marker"), "ns-marker-1").is_err());
        // Unknown claimed status: anything the wire returns is the evidence.
        assert!(reproduces(&ex("GET", "u", 0, ""), &ex("GET", "u", 500, "err"), "").is_ok());
    }
}
