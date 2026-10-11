//! Authorization matrix engine.
//!
//! A deterministic pass that sweeps the discovered route surface against every
//! identity in `creds.yaml` and diffs what happened against what the access
//! policy says should happen. It produces ordinary [`Finding`]s carrying
//! [`Evidence::matrix`] / [`Evidence::oracle`], which the normal
//! [`crate::validation`] path judges — so CVSS grading, scope withholding and
//! the assurance bundle all apply unchanged.
//!
//! Two probes per route:
//! - **read routes** — replay as each should-be-denied identity; a protected
//!   resource served to one of them is a function-level authorization flaw.
//! - **write routes** — the 403-vs-business-error oracle: a should-be-denied
//!   identity and the privileged control both call the route with a well-formed
//!   **non-existent** id, so reachability is proven without mutating real data.
//!
//! The engine never decides the verdict itself; it gathers evidence and lets
//! `validation::apply` judge, keeping the deterministic, model-independent
//! guarantee of the rest of the pipeline.

use crate::creds::{Creds, Identity, Tier};
use crate::scope::{Action, ScopePolicy};
use crate::types::Finding;
use crate::validation::{Evidence, Exchange, Expect, MatrixProbe, OracleProbe};
use std::future::Future;

/// Whether a route changes state. Decides read-matrix vs write-oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Read,
    Write,
}

/// One route to test. `url` is the full absolute URL as recon found it.
#[derive(Debug, Clone)]
pub struct Route {
    pub method: String,
    pub url: String,
    pub kind: RouteKind,
}

impl Route {
    pub fn new(method: &str, url: &str) -> Route {
        let kind = if is_write_method(method) { RouteKind::Write } else { RouteKind::Read };
        Route { method: method.to_uppercase(), url: url.to_string(), kind }
    }
}

/// `true` for state-changing HTTP methods.
pub fn is_write_method(method: &str) -> bool {
    matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
}

/// The set of routes to sweep, deduplicated by method + path template.
#[derive(Debug, Default, Clone)]
pub struct RouteInventory {
    pub routes: Vec<Route>,
}

impl RouteInventory {
    /// Build from recon's `(method, url)` pairs, collapsing `/users/123` and
    /// `/users/456` to a single template so the sweep is O(routes), not
    /// O(objects).
    pub fn from_endpoints(eps: &[(String, String)]) -> RouteInventory {
        let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        let mut routes = Vec::new();
        for (method, url) in eps {
            let m = method.to_uppercase();
            let key = (m.clone(), template(url));
            if seen.insert(key) {
                routes.push(Route::new(&m, url));
            }
        }
        RouteInventory { routes }
    }
}

/// Replace id-shaped path segments with `{id}` so two instances of the same
/// route collapse to one.
pub fn template(url: &str) -> String {
    let (head, path) = split_path(url);
    let segs: Vec<String> = path
        .split('/')
        .map(|s| if looks_like_id(s) { "{id}".to_string() } else { s.to_string() })
        .collect();
    format!("{head}{}", segs.join("/"))
}

/// A path segment that is a numeric id, a UUID, or a 24-hex Mongo ObjectId.
fn looks_like_id(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let s = seg.split('?').next().unwrap_or(seg);
    let all_digits = s.chars().all(|c| c.is_ascii_digit());
    if all_digits && s.len() >= 1 {
        return true;
    }
    let hex = s.chars().all(|c| c.is_ascii_hexdigit());
    if hex && s.len() == 24 {
        return true;
    }
    // UUID 8-4-4-4-12
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() == 5 {
        let lens = [8, 4, 4, 4, 12];
        if parts.iter().zip(lens).all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit())) {
            return true;
        }
    }
    false
}

/// Split `scheme://host[:port]` from the path (`/a/b`). Keeps the query out.
fn split_path(url: &str) -> (String, String) {
    if let Some(idx) = url.find("://") {
        let after = &url[idx + 3..];
        if let Some(slash) = after.find('/') {
            let head = &url[..idx + 3 + slash];
            let path = &after[slash..];
            return (head.to_string(), path.to_string());
        }
        return (url.to_string(), String::new());
    }
    (String::new(), url.to_string())
}

/// Rewrite the last id-shaped segment to a well-formed NON-EXISTENT id (zeros),
/// so a write route can be reached without touching a real object. If the route
/// has no id segment, append one.
pub fn with_nonexistent_id(url: &str) -> String {
    let (head, path) = split_path(url);
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p.to_string(), format!("?{q}")),
        None => (path.clone(), String::new()),
    };
    let mut segs: Vec<String> = path_only.split('/').map(|s| s.to_string()).collect();
    if let Some(pos) = segs.iter().rposition(|s| looks_like_id(s)) {
        segs[pos] = nonexistent_like(&segs[pos]);
        return format!("{head}{}{query}", segs.join("/"));
    }
    // No id in the path — append a sentinel ObjectId.
    let sep = if path_only.ends_with('/') { "" } else { "/" };
    format!("{head}{path_only}{sep}000000000000000000000000{query}")
}

/// A non-existent value shaped like the original id.
fn nonexistent_like(seg: &str) -> String {
    if seg.len() == 24 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return "0".repeat(24);
    }
    if seg.split('-').count() == 5 {
        return "00000000-0000-0000-0000-000000000000".to_string();
    }
    // Numeric: a very large value is far more likely to be unused than 0.
    "999999999999".to_string()
}

/// Parse an identity's `Name: value` header into a `(name, value)` pair.
fn header_pair(id: &Identity) -> Option<(String, String)> {
    let line = id.header_line()?;
    let (n, v) = line.split_once(':')?;
    Some((n.trim().to_string(), v.trim().to_string()))
}

/// Headers to send for an identity (empty for anonymous).
fn headers_for(id: &Identity) -> Vec<(String, String)> {
    header_pair(id).into_iter().collect()
}

/// The single should-be-denied identity used for a write-route oracle: prefer
/// anonymous, then read-only, then any tenant.
fn pick_denied<'a>(creds: &'a Creds) -> Option<&'a Identity> {
    let by = |t: Tier| creds.roles.iter().find(|r| r.tier_kind() == t);
    by(Tier::None).or_else(|| by(Tier::ReadOnly)).or_else(|| by(Tier::Tenant))
}

/// Synthesize the candidate finding for a route (verdict comes later from
/// `validation::apply`).
fn synth_finding(route: &Route, kind_label: &str) -> Finding {
    let mut id = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    (route.method.clone(), template(&route.url)).hash(&mut id);
    Finding {
        id: format!("authzmx-{:x}", id.finish()),
        agent: "authz-matrix".into(),
        title: format!("Broken authorization ({kind_label}) at {} {}", route.method, template(&route.url)),
        cwe: "862".into(),
        endpoint: route.url.clone(),
        owasp: "A01:2025-Broken Access Control".into(),
        stage: "privesc".into(),
        exploitability: "moderate".into(),
        ..Default::default()
    }
}

/// Run the matrix. `send(method, url, headers, body) -> Exchange` is the only IO
/// seam; the pipeline passes a reqwest-backed closure, tests pass a fake.
/// `max_requests` caps the sweep (the reasoning-budget governor's share).
pub async fn run<F, Fut>(
    inv: &RouteInventory,
    creds: &Creds,
    scope: &ScopePolicy,
    max_requests: usize,
    send: F,
) -> Vec<(Finding, Evidence)>
where
    F: Fn(String, String, Vec<(String, String)>, String) -> Fut,
    Fut: Future<Output = Exchange>,
{
    let mut out = Vec::new();
    let mut budget = max_requests;
    if !creds.authz_matrix_ready() {
        return out;
    }
    let Some(highest) = creds.highest_identity() else {
        return out;
    };

    for route in &inv.routes {
        if budget == 0 {
            break;
        }
        match route.kind {
            RouteKind::Read => {
                // Replay as each should-be-denied identity.
                let mut probes = Vec::new();
                for id in creds.roles.iter() {
                    if id.name == highest.name {
                        continue;
                    }
                    let expect = id.expected(false);
                    if expect != Expect::Deny {
                        continue; // only probes we expect to be refused prove anything
                    }
                    if !allowed(scope, &route.url, &route.method) || budget == 0 {
                        continue;
                    }
                    budget -= 1;
                    let x = send(route.method.clone(), route.url.clone(), headers_for(id), String::new()).await;
                    probes.push(MatrixProbe { identity: id.name.clone(), expect, exchange: with_identity(x, &id.name) });
                }
                if probes.iter().any(|p| p.expect == Expect::Deny) {
                    let ev = Evidence { matrix: probes, ..Default::default() };
                    out.push((synth_finding(route, "missing authorization"), ev));
                }
            }
            RouteKind::Write => {
                let Some(denied) = pick_denied(creds) else { continue };
                if denied.name == highest.name {
                    continue;
                }
                let url = with_nonexistent_id(&route.url);
                // Writes use a non-existent id: Probe action, not Destructive.
                if !allowed(scope, &url, &route.method) || budget < 2 {
                    continue;
                }
                budget -= 2;
                let denied_x = send(route.method.clone(), url.clone(), headers_for(denied), String::new()).await;
                let priv_x = send(route.method.clone(), url.clone(), headers_for(highest), String::new()).await;
                let ev = Evidence {
                    oracle: Some(OracleProbe {
                        denied: with_identity(denied_x, &denied.name),
                        privileged: with_identity(priv_x, &highest.name),
                    }),
                    ..Default::default()
                };
                out.push((synth_finding(route, "read-only / unauthorized write"), ev));
            }
        }
    }
    out
}

/// Run the matrix and apply the deterministic verdict to each candidate, so the
/// caller gets findings with `review_status`/`confidence` already set — ready to
/// merge into the run's finding list. Rejected candidates are dropped (they are
/// the control working); confirmed and needs-review are kept.
pub async fn run_pass<F, Fut>(
    inv: &RouteInventory,
    creds: &Creds,
    scope: &ScopePolicy,
    max_requests: usize,
    send: F,
) -> Vec<Finding>
where
    F: Fn(String, String, Vec<(String, String)>, String) -> Fut,
    Fut: Future<Output = Exchange>,
{
    let mut out = Vec::new();
    for (mut f, ev) in run(inv, creds, scope, max_requests, send).await {
        let verdict = crate::validation::apply(&mut f, Some(&ev));
        if !matches!(verdict, crate::validation::Verdict::Rejected(_)) {
            f.evidence = verdict.reason().to_string();
            out.push(f);
        }
    }
    out
}

/// A reqwest-backed sender for [`run`]/[`run_pass`]. The pipeline builds the
/// closure inline: `|m, u, h, b| authz_matrix::send_via(&client, m, u, h, b)`.
pub async fn send_via(
    client: &reqwest::Client,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
) -> Exchange {
    let started = std::time::Instant::now();
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut req = client.request(m, &url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !body.is_empty() {
        req = req.body(body.clone());
    }
    let mut out = Exchange { method, url, provenance: "wire:harness".into(), ..Default::default() };
    match req.send().await {
        Ok(resp) => {
            out.status = resp.status().as_u16();
            out.content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            for (k, v) in resp.headers().iter() {
                if let Ok(val) = v.to_str() {
                    out.headers.insert(k.as_str().to_lowercase(), val.to_string());
                }
            }
            out.body = resp.text().await.unwrap_or_default();
        }
        Err(_) => {
            out.status = 0; // network error — reached nothing
        }
    }
    out.elapsed_ms = started.elapsed().as_millis() as u64;
    out
}

fn with_identity(mut x: Exchange, id: &str) -> Exchange {
    if x.identity.is_empty() {
        x.identity = id.to_string();
    }
    x
}

/// Scope guard: a write with a non-existent id is a Probe (non-mutating in
/// effect), a read is Probe too.
fn allowed(scope: &ScopePolicy, url: &str, _method: &str) -> bool {
    scope.check(url, Action::Probe).allowed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::{self, Verdict};

    fn creds_three() -> Creds {
        let mk = |name: &str, tier: &str, hdr: &str| Identity {
            name: name.into(),
            header: hdr.into(),
            tier: tier.into(),
            ..Default::default()
        };
        Creds {
            roles: vec![
                mk("admin", "high", "Authorization: Bearer AAA"),
                mk("readonly", "readonly", "Authorization: Bearer BBB"),
                Identity { name: "anonymous".into(), tier: "none".into(), ..Default::default() },
            ],
            ..Default::default()
        }
    }

    fn ex(status: u16, body: &str) -> Exchange {
        Exchange { status, body: body.into(), ..Default::default() }
    }

    fn open_scope() -> ScopePolicy {
        ScopePolicy::from_yaml("hard:\n  - t.test\n")
    }

    #[tokio::test]
    async fn read_route_served_to_denied_identity_is_confirmed() {
        let inv = RouteInventory::from_endpoints(&[("GET".into(), "https://t.test/chargeback/list".into())]);
        // Every identity gets the protected list back → missing authorization.
        let send = |_m: String, _u: String, _h: Vec<(String, String)>, _b: String| {
            std::future::ready(ex(200, "{\"total\":86776,\"items\":[{\"cpf\":\"...\"}]}"))
        };
        let found = run(&inv, &creds_three(), &open_scope(), 100, send).await;
        assert_eq!(found.len(), 1, "one read finding expected");
        let (f, evd) = &found[0];
        match validation::judge(f, Some(evd)) {
            Verdict::Confirmed(r) => assert!(r.contains("expected deny"), "{r}"),
            v => panic!("expected confirmation, got {v:?}"),
        }
    }

    #[tokio::test]
    async fn enforced_read_route_yields_no_confirmation() {
        let inv = RouteInventory::from_endpoints(&[("GET".into(), "https://t.test/admin/users".into())]);
        // Denied identities are correctly refused.
        let send = |_m: String, _u: String, _h: Vec<(String, String)>, _b: String| {
            std::future::ready(ex(403, "Forbidden"))
        };
        let found = run(&inv, &creds_three(), &open_scope(), 100, send).await;
        // A finding object is still produced, but the verdict rejects it.
        assert_eq!(found.len(), 1);
        let (f, evd) = &found[0];
        assert!(matches!(validation::judge(f, Some(evd)), Verdict::Rejected(_)));
    }

    #[tokio::test]
    async fn write_oracle_business_error_confirms() {
        let inv = RouteInventory::from_endpoints(&[("PATCH".into(), "https://t.test/chargeback/6531aa/decision".into())]);
        // Non-existent id → both denied and privileged get the same business
        // "not found": authorization did nothing.
        let send = |_m: String, _u: String, _h: Vec<(String, String)>, _b: String| {
            std::future::ready(ex(404, "record not found"))
        };
        let found = run(&inv, &creds_three(), &open_scope(), 100, send).await;
        assert_eq!(found.len(), 1, "one write finding expected");
        let (f, evd) = &found[0];
        assert!(evd.oracle.is_some(), "write route should carry an oracle probe");
        match validation::judge(f, Some(evd)) {
            Verdict::Confirmed(r) => assert!(r.contains("business logic"), "{r}"),
            v => panic!("expected confirmation, got {v:?}"),
        }
    }

    #[tokio::test]
    async fn write_oracle_403_is_rejected() {
        let inv = RouteInventory::from_endpoints(&[("DELETE".into(), "https://t.test/users/123".into())]);
        let send = |_m: String, _u: String, _h: Vec<(String, String)>, _b: String| {
            std::future::ready(ex(403, "Forbidden"))
        };
        let found = run(&inv, &creds_three(), &open_scope(), 100, send).await;
        assert_eq!(found.len(), 1);
        let (f, evd) = &found[0];
        assert!(matches!(validation::judge(f, Some(evd)), Verdict::Rejected(_)));
    }

    #[tokio::test]
    async fn no_matrix_without_two_tiers() {
        let one = Creds {
            roles: vec![Identity { name: "admin".into(), header: "Authorization: Bearer A".into(), tier: "high".into(), ..Default::default() }],
            ..Default::default()
        };
        let inv = RouteInventory::from_endpoints(&[("GET".into(), "https://t.test/x".into())]);
        let send = |_m: String, _u: String, _h: Vec<(String, String)>, _b: String| std::future::ready(ex(200, "x"));
        assert!(run(&inv, &one, &open_scope(), 100, send).await.is_empty());
    }

    #[test]
    fn template_collapses_ids() {
        assert_eq!(template("https://t.test/users/123/orders/456"), "https://t.test/users/{id}/orders/{id}");
        assert_eq!(template("https://t.test/u/6531aaffbbccddeeff001122"), "https://t.test/u/{id}");
        assert_eq!(
            template("https://t.test/u/550e8400-e29b-41d4-a716-446655440000"),
            "https://t.test/u/{id}"
        );
    }

    #[test]
    fn nonexistent_id_keeps_shape() {
        assert_eq!(with_nonexistent_id("https://t.test/users/123"), "https://t.test/users/999999999999");
        assert_eq!(
            with_nonexistent_id("https://t.test/u/6531aaffbbccddeeff001122/go"),
            "https://t.test/u/000000000000000000000000/go"
        );
        assert_eq!(with_nonexistent_id("https://t.test/refund"), "https://t.test/refund/000000000000000000000000");
    }
}
