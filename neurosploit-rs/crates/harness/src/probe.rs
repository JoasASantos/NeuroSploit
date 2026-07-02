//! Deterministic HTTP request/response analysis (v3.5.5).
//!
//! Before the LLM recon runs, the harness performs a **real** probe of the
//! target and captures observed facts — status, headers, security headers,
//! cookie flags, CORS reflection, redirect, tech hints, linked scripts, a small
//! set of interesting paths, and a 404 baseline for differentials. Those facts
//! are injected into recon so agent selection and exploitation decisions are
//! grounded in the actual request/response, not just the model's guess. This
//! makes the harness more robust (works even when the model's recon is weak) and
//! its decisions sharper. Best-effort: failures are noted, never fatal. Honors
//! NEUROSPLOIT_UA (identifying User-Agent) and NEUROSPLOIT_PROXY (Burp/ZAP).
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize, Default)]
pub struct SecHeaders {
    pub hsts: bool,
    pub csp: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub referrer_policy: bool,
    pub permissions_policy: bool,
    /// Count present (of the 6 tracked).
    pub present: u8,
}

#[derive(Serialize, Default)]
pub struct CookieFlags {
    pub name: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: String,
}

#[derive(Serialize, Default)]
pub struct Cors {
    /// Does the app reflect an arbitrary Origin into Access-Control-Allow-Origin?
    pub reflects_origin: bool,
    pub wildcard: bool,
    pub allow_credentials: bool,
}

#[derive(Serialize, Default)]
pub struct PathHit {
    pub path: String,
    pub status: u16,
    pub len: usize,
}

#[derive(Serialize, Default)]
pub struct Probe {
    pub url: String,
    pub final_url: String,
    pub redirected: bool,
    pub status: u16,
    pub server: String,
    pub powered_by: String,
    pub content_type: String,
    pub title: String,
    pub tech: Vec<String>,
    pub security_headers: SecHeaders,
    pub cookies: Vec<CookieFlags>,
    pub cors: Cors,
    pub scripts: Vec<String>,
    pub forms: usize,
    pub interesting_paths: Vec<PathHit>,
    /// Baseline for a random non-existent path (status + body length), so agents
    /// can tell a real hit from a soft-404 catch-all.
    pub baseline_404_status: u16,
    pub baseline_404_len: usize,
    pub notes: Vec<String>,
}

fn client() -> reqwest::Client {
    let ua = std::env::var("NEUROSPLOIT_UA").ok().filter(|v| !v.trim().is_empty())
        .unwrap_or_else(crate::pipeline::default_user_agent);
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(ua);
    if let Ok(p) = std::env::var("NEUROSPLOIT_PROXY") {
        if !p.trim().is_empty() {
            if let Ok(px) = reqwest::Proxy::all(&p) { b = b.proxy(px); }
        }
    }
    b.build().unwrap_or_default()
}

fn hget(h: &reqwest::header::HeaderMap, k: &str) -> String {
    h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let j = s[i..].find(b)? + i;
    Some(&s[i..j])
}

/// Run the probe. Never panics; on total failure returns a Probe with a note.
pub async fn probe(target: &str) -> Probe {
    let mut p = Probe { url: target.to_string(), ..Default::default() };
    let c = client();

    let resp = match c.get(target).send().await {
        Ok(r) => r,
        Err(e) => { p.notes.push(format!("initial GET failed: {e}")); return p; }
    };
    p.final_url = resp.url().to_string();
    p.redirected = p.final_url.trim_end_matches('/') != target.trim_end_matches('/');
    p.status = resp.status().as_u16();
    let h = resp.headers().clone();
    p.server = hget(&h, "server");
    p.powered_by = hget(&h, "x-powered-by");
    p.content_type = hget(&h, "content-type");

    // Security headers.
    let mut sec = SecHeaders::default();
    sec.hsts = h.contains_key("strict-transport-security");
    sec.csp = h.contains_key("content-security-policy");
    sec.x_frame_options = h.contains_key("x-frame-options");
    sec.x_content_type_options = h.contains_key("x-content-type-options");
    sec.referrer_policy = h.contains_key("referrer-policy");
    sec.permissions_policy = h.contains_key("permissions-policy");
    sec.present = [sec.hsts, sec.csp, sec.x_frame_options, sec.x_content_type_options, sec.referrer_policy, sec.permissions_policy]
        .iter().filter(|x| **x).count() as u8;
    p.security_headers = sec;

    // Cookie flags.
    for hv in h.get_all("set-cookie") {
        if let Ok(s) = hv.to_str() {
            let name = s.split('=').next().unwrap_or("").trim().to_string();
            let low = s.to_lowercase();
            let same = if low.contains("samesite=strict") { "Strict" }
                else if low.contains("samesite=lax") { "Lax" }
                else if low.contains("samesite=none") { "None" } else { "(none)" };
            p.cookies.push(CookieFlags {
                name, http_only: low.contains("httponly"), secure: low.contains("secure"),
                same_site: same.to_string(),
            });
        }
    }

    // Body-derived facts (bounded).
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 400_000 { body[..400_000].to_string() } else { body };
    if let Some(t) = between(&body, "<title>", "</title>") {
        p.title = t.trim().chars().take(120).collect();
    }
    p.forms = body.matches("<form").count();
    // linked scripts (src="...")
    for cap in body.split("<script").skip(1) {
        if let Some(src) = between(cap, "src=\"", "\"").or_else(|| between(cap, "src='", "'")) {
            if !src.is_empty() && p.scripts.len() < 40 && !p.scripts.iter().any(|x| x == src) {
                p.scripts.push(src.to_string());
            }
        }
    }
    // Tech hints (headers + body keywords).
    let hay = format!("{} {} {} {}", p.server, p.powered_by, p.content_type, body.chars().take(20_000).collect::<String>()).to_lowercase();
    for (needle, tech) in [
        ("wp-content", "WordPress"), ("/wp-json", "WordPress"), ("drupal", "Drupal"), ("joomla", "Joomla"),
        ("x-drupal", "Drupal"), ("laravel_session", "Laravel"), ("csrftoken", "Django"), ("__next", "Next.js"),
        ("react", "React"), ("vue", "Vue"), ("angular", "Angular"), ("nginx", "nginx"), ("apache", "Apache"),
        ("microsoft-iis", "IIS"), ("express", "Express"), ("phpsessid", "PHP"), ("jsessionid", "Java"),
        ("cloudflare", "Cloudflare"), ("swagger", "Swagger/OpenAPI"), ("graphql", "GraphQL"),
    ] {
        if hay.contains(needle) && !p.tech.iter().any(|t| t == tech) { p.tech.push(tech.to_string()); }
    }

    // CORS reflection probe.
    if let Ok(r2) = c.get(target).header("Origin", "https://evil.neurosploit.test").send().await {
        let acao = hget(r2.headers(), "access-control-allow-origin");
        let acac = hget(r2.headers(), "access-control-allow-credentials");
        p.cors.wildcard = acao.trim() == "*";
        p.cors.reflects_origin = acao.contains("evil.neurosploit.test");
        p.cors.allow_credentials = acac.trim().eq_ignore_ascii_case("true");
    }

    // 404 baseline (soft-404 detection).
    let base = format!("{}/nrsplt_baseline_404_check_9x7", target.trim_end_matches('/'));
    if let Ok(rb) = c.get(&base).send().await {
        p.baseline_404_status = rb.status().as_u16();
        p.baseline_404_len = rb.text().await.unwrap_or_default().len();
    }

    // A few high-signal paths (kept small to stay fast).
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/config", "/.env"] {
        let u = format!("{}{}", target.trim_end_matches('/'), path);
        if let Ok(rp) = c.get(&u).send().await {
            let st = rp.status().as_u16();
            let len = rp.text().await.unwrap_or_default().len();
            // only report if it looks like a real hit (200 and unlike the 404 baseline)
            if st == 200 && !(st == p.baseline_404_status && len == p.baseline_404_len) {
                p.interesting_paths.push(PathHit { path: path.to_string(), status: st, len });
            }
        }
    }
    p
}

/// Pretty-JSON of the probe for injection into recon context.
pub fn probe_json(p: &Probe) -> String {
    serde_json::to_string_pretty(p).unwrap_or_default()
}

/// One-line human summary for the live feed.
pub fn probe_summary(p: &Probe) -> String {
    format!(
        "probe: HTTP {} {}{} · {}{} · sec-headers {}/6 · {} cookie(s) · {} script(s){}{}",
        p.status,
        if p.server.is_empty() { "".into() } else { format!("{} ", p.server) },
        if p.tech.is_empty() { "".to_string() } else { format!("[{}]", p.tech.join(",")) },
        if p.redirected { "→ " } else { "" },
        if p.redirected { p.final_url.clone() } else { String::new() },
        p.security_headers.present,
        p.cookies.len(),
        p.scripts.len(),
        if p.cors.reflects_origin { " · CORS reflects origin!" } else { "" },
        if p.interesting_paths.is_empty() { String::new() } else { format!(" · hits: {}", p.interesting_paths.iter().map(|h| h.path.clone()).collect::<Vec<_>>().join(",")) },
    )
}
