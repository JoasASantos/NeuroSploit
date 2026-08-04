//! Deterministic HTTP request/response analysis (v3.6.5).
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

/// A parsed HTML `<form>` — enough for an agent to auto-submit it (e.g. register
/// an account) with curl or the browser, without re-parsing the page.
#[derive(Serialize, Default, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    /// input/select/textarea field names with their type (name → type).
    pub fields: Vec<(String, String)>,
    /// Best-effort role guess: "register" | "login" | "search" | "other".
    pub kind: String,
    /// True if a CSRF/anti-forgery hidden token was seen in the form.
    pub has_csrf: bool,
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
    /// Business/brand hint extracted from the page (og:site_name, application-name,
    /// or a "© <Name>" copyright) so the report can name the org, not just the URL.
    pub brand: String,
    pub forms: usize,
    /// Parsed forms (action/method/fields) so an agent can auto-submit them —
    /// e.g. register a test account to reach the authenticated surface.
    pub form_details: Vec<FormInfo>,
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

/// Read one HTML attribute value (double- or single-quoted) from a tag slice.
fn attr(tag: &str, name: &str) -> String {
    for q in ["\"", "'"] {
        if let Some(v) = between(tag, &format!("{name}={q}"), q) {
            return v.trim().to_string();
        }
    }
    String::new()
}

/// Best-effort business/brand name from the page: `og:site_name` or
/// `application-name` meta, else a "© <Name>" / "Copyright <Name>" notice. Helps
/// the report name the organisation/product instead of only the URL.
fn extract_brand(body: &str) -> String {
    let low = body.to_lowercase();
    // <meta property="og:site_name" content="X"> / name="application-name"
    for key in ["og:site_name", "application-name", "author", "twitter:site"] {
        if let Some(i) = low.find(key) {
            let seg = &body[i..(i + 220).min(body.len())];
            if let Some(c) = between(seg, "content=\"", "\"").or_else(|| between(seg, "content='", "'")) {
                let c = c.trim();
                if c.len() >= 2 && c.len() <= 60 { return c.to_string(); }
            }
        }
    }
    // Copyright notice: "© Company" or "Copyright 2024 Company".
    for marker in ["©", "&copy;", "copyright"] {
        if let Some(i) = low.find(marker) {
            let seg: String = body[i..].chars().take(80).collect();
            // strip the marker + a year, take the first capitalised words.
            let cleaned = seg.replace('©', " ").replace("&copy;", " ");
            let cleaned = cleaned.trim_start_matches(|c: char| !c.is_alphabetic());
            let name: String = cleaned.split(['<', '.', '|', '\n'])
                .next().unwrap_or("").chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '&' || *c == '-')
                .collect::<String>().trim().to_string();
            // drop a leading year like "2024 "
            let name = name.split_whitespace().filter(|w| !w.chars().all(|c| c.is_ascii_digit()))
                .collect::<Vec<_>>().join(" ");
            if name.len() >= 2 && name.len() <= 50 && name.to_lowercase() != "copyright" { return name; }
        }
    }
    String::new()
}

/// Best-effort parse of the HTML `<form>`s on a page so agents can auto-submit
/// them (e.g. register a test account) without re-parsing. Non-destructive: this
/// only READS the markup. Bounded to the first few forms.
fn parse_forms(body: &str) -> Vec<FormInfo> {
    let mut out = Vec::new();
    for chunk in body.split("<form").skip(1).take(8) {
        // The form's own attributes live before the first '>'.
        let head = chunk.split('>').next().unwrap_or("");
        let inner = chunk.split("</form").next().unwrap_or(chunk);
        let mut f = FormInfo {
            action: attr(head, "action"),
            method: {
                let m = attr(head, "method");
                if m.is_empty() { "get".into() } else { m.to_lowercase() }
            },
            ..Default::default()
        };
        // Fields: <input>, <select>, <textarea> — capture name + type.
        for tag in ["<input", "<select", "<textarea"] {
            for seg in inner.split(tag).skip(1) {
                let t = seg.split('>').next().unwrap_or("");
                let name = attr(t, "name");
                if name.is_empty() { continue; }
                let ty = if tag == "<input" {
                    let ty = attr(t, "type");
                    if ty.is_empty() { "text".into() } else { ty.to_lowercase() }
                } else { tag.trim_start_matches('<').into() };
                if ty == "hidden" && (t.to_lowercase().contains("csrf") || t.to_lowercase().contains("token") || name.to_lowercase().contains("csrf") || name.to_lowercase().contains("_token")) {
                    f.has_csrf = true;
                }
                if f.fields.len() < 25 && !f.fields.iter().any(|(n, _)| *n == name) {
                    f.fields.push((name, ty));
                }
            }
        }
        // Guess the form's role from action + field names.
        let hay = format!("{} {}", f.action, f.fields.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(" ")).to_lowercase();
        let has_pw = f.fields.iter().any(|(_, t)| t == "password");
        f.kind = if hay.contains("regist") || hay.contains("signup") || hay.contains("sign-up") || hay.contains("create") || (has_pw && (hay.contains("confirm") || hay.contains("repeat"))) {
            "register".into()
        } else if hay.contains("login") || hay.contains("signin") || hay.contains("sign-in") || hay.contains("auth") || has_pw {
            "login".into()
        } else if hay.contains("search") || hay.contains("query") || f.fields.iter().any(|(n, _)| n == "q") {
            "search".into()
        } else { "other".into() };
        out.push(f);
    }
    out
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
    p.form_details = parse_forms(&body);
    p.brand = extract_brand(&body);
    // linked scripts (src="...")
    for cap in body.split("<script").skip(1) {
        if let Some(src) = between(cap, "src=\"", "\"").or_else(|| between(cap, "src='", "'")) {
            if !src.is_empty() && p.scripts.len() < 40 && !p.scripts.iter().any(|x| x == src) {
                p.scripts.push(src.to_string());
            }
        }
    }
    // Tech hints (headers + body keywords).
    let hay = format!("{} {} {} {}", p.server, p.powered_by, p.content_type, body.chars().take(30_000).collect::<String>()).to_lowercase();
    for (needle, tech) in [
        ("wp-content", "WordPress"), ("/wp-json", "WordPress"), ("drupal", "Drupal"), ("joomla", "Joomla"),
        ("x-drupal", "Drupal"), ("laravel_session", "Laravel"), ("csrftoken", "Django"), ("__next", "Next.js"),
        ("react", "React"), ("vue", "Vue"), ("nginx", "nginx"), ("apache", "Apache"),
        ("microsoft-iis", "IIS"), ("express", "Express"), ("phpsessid", "PHP"), ("jsessionid", "Java"),
        ("cloudflare", "Cloudflare"), ("swagger", "Swagger/OpenAPI"), ("graphql", "GraphQL"),
        // SPA / framework markers (Juice Shop = Angular <app-root>).
        ("<app-root", "Angular"), ("ng-version", "Angular"), ("angular", "Angular"),
        ("data-reactroot", "React"), ("id=\"root\"", "SPA"), ("id=\"app\"", "SPA"),
        ("polyfills", "SPA"), ("runtime.", "SPA"),
    ] {
        if hay.contains(needle) && !p.tech.iter().any(|t| t == tech) { p.tech.push(tech.to_string()); }
    }
    // Heuristic: a nearly-empty body with several linked scripts is a JS SPA
    // (curl sees the shell only — the browser is required to render it).
    let text_len = body.chars().filter(|c| !c.is_whitespace()).count();
    if p.scripts.len() >= 2 && text_len < 3000 && !p.tech.iter().any(|t| t == "SPA") {
        p.tech.push("SPA".to_string());
    }
    if p.tech.iter().any(|t| t == "SPA" || t == "Angular" || t == "React" || t == "Vue") {
        p.notes.push("JS-rendered SPA — curl sees the shell only; use the browser (MCP/Playwright) to render, enumerate routes, and discover the API.".to_string());
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
        "probe: HTTP {} {}{} · {}{} · sec-headers {}/6 · {} cookie(s) · {} script(s){}{}{}",
        p.status,
        if p.server.is_empty() { "".into() } else { format!("{} ", p.server) },
        if p.tech.is_empty() { "".to_string() } else { format!("[{}]", p.tech.join(",")) },
        if p.redirected { "→ " } else { "" },
        if p.redirected { p.final_url.clone() } else { String::new() },
        p.security_headers.present,
        p.cookies.len(),
        p.scripts.len(),
        {
            let kinds: Vec<&str> = p.form_details.iter().map(|f| f.kind.as_str()).filter(|k| *k == "register" || *k == "login").collect();
            if kinds.is_empty() { String::new() } else { format!(" · forms: {}", kinds.join(",")) }
        },
        if p.cors.reflects_origin { " · CORS reflects origin!" } else { "" },
        if p.interesting_paths.is_empty() { String::new() } else { format!(" · hits: {}", p.interesting_paths.iter().map(|h| h.path.clone()).collect::<Vec<_>>().join(",")) },
    )
}

#[cfg(test)]
mod tests {
    use super::parse_forms;

    #[test]
    fn parses_register_form_fields_and_kind() {
        let html = r#"<html><body>
          <form action="/api/register" method="post">
            <input type="text" name="username">
            <input type="email" name="email">
            <input type="password" name="password">
            <input type="password" name="confirmPassword">
            <input type="hidden" name="csrf_token" value="abc">
            <button>Sign up</button>
          </form>
          <form action="/search" method="get"><input name="q"></form>
        </body></html>"#;
        let forms = parse_forms(html);
        assert_eq!(forms.len(), 2);
        let reg = &forms[0];
        assert_eq!(reg.action, "/api/register");
        assert_eq!(reg.method, "post");
        assert_eq!(reg.kind, "register");
        assert!(reg.has_csrf, "hidden csrf_token should be detected");
        assert!(reg.fields.iter().any(|(n, t)| n == "password" && t == "password"));
        assert_eq!(forms[1].kind, "search");
    }

    #[test]
    fn login_form_detected_by_password() {
        let html = r#"<form action="/login"><input name="user"><input type="password" name="pw"></form>"#;
        let f = parse_forms(html);
        assert_eq!(f[0].kind, "login");
    }
}
