//! Browser validator — proving a payload *executed*, not that it appeared.
//!
//! A payload echoed into HTML is reflection. It becomes cross-site scripting
//! only when a browser parses that response and runs it, and the gap between
//! the two is where most XSS false positives live: the value lands inside an
//! attribute that is never evaluated, inside a `<textarea>`, HTML-encoded on
//! the way out, or blocked by CSP. Every one of those looks identical to a
//! string match against the response body.
//!
//! So [`XssValidator`](crate::validation::XssValidator) refuses to confirm
//! without `browser_executed` and `marker_observed`, and this module is what
//! sets them: a real Chromium, driven by Playwright, loading the URL and
//! reporting whether a marker **the harness chose** came back through a channel
//! that only executing code can reach.
//!
//! ## Why a marker, and why these channels
//!
//! The marker is generated per attempt (see [`crate::validation::canary`]), so
//! observing it cannot be coincidence — the target has no way to produce that
//! string on its own. It is reported through whichever channel fires first:
//!
//! | channel | what it proves |
//! |---------|----------------|
//! | `dialog` | `alert()`/`confirm()`/`prompt()` ran with our marker as its message |
//! | `title` | script assigned `document.title` — execution with no dialog to dismiss |
//! | `global` | script wrote `window.__neurosploit` |
//! | `console` | script called `console.log` (weakest: a page could log the reflected value itself, so it is reported and never treated as decisive on its own) |
//!
//! ## Degrading honestly
//!
//! Node or Playwright may be absent. In that case the result says
//! `available: false` and nothing is confirmed — the one thing this module must
//! never do is let a missing tool read as a missing vulnerability, or worse, as
//! a present one.

use crate::scope::{Action, ScopePolicy};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// What the browser saw.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BrowserResult {
    /// A browser actually ran. False means "we could not look", never "nothing
    /// happened".
    pub available: bool,
    /// Script from the payload executed.
    pub executed: bool,
    /// The harness's marker was observed at runtime.
    pub marker_observed: bool,
    /// Which channel carried it: dialog · title · global · console.
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub console: Vec<String>,
    /// Path to the screenshot taken at the moment of observation.
    #[serde(default)]
    pub screenshot: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl BrowserResult {
    /// Did this run produce proof of execution?
    ///
    /// A console line alone does not: a page can log the value it reflected
    /// without ever executing it.
    pub fn proves_execution(&self) -> bool {
        self.available && self.executed && self.marker_observed && self.channel != "console"
    }
    fn unavailable(note: &str) -> Self {
        BrowserResult { available: false, notes: vec![note.to_string()], ..Default::default() }
    }
}

/// Payloads that, if they execute, report the marker through a channel this
/// module watches.
///
/// They are deliberately *self-reporting* rather than generic (`<script>alert(1)</script>`
/// proves nothing we can attribute), and they cover the contexts a reflected
/// value usually lands in: raw HTML, inside an attribute, inside an existing
/// script, and as a URL.
pub fn xss_payloads(marker: &str) -> Vec<String> {
    let m = marker;
    vec![
        format!("<script>document.title='{m}';window.__neurosploit='{m}'</script>"),
        format!("\"><script>document.title='{m}';window.__neurosploit='{m}'</script>"),
        format!("<img src=x onerror=\"document.title='{m}';window.__neurosploit='{m}'\">"),
        format!("'\"><svg/onload=\"document.title='{m}';window.__neurosploit='{m}'\">"),
        format!("javascript:document.title='{m}'"),
        format!("';document.title='{m}';//"),
        format!("</textarea><script>document.title='{m}'</script>"),
        format!("{{{{constructor.constructor(\"document.title='{m}'\")()}}}}"),
    ]
}

/// The driver script. Written to a temp file and run with `node`.
///
/// It reports a single JSON line on stdout so the Rust side never has to parse
/// Playwright's own chatter, and it takes a screenshot only when it observed
/// something — an image of a page that did nothing is not evidence.
fn driver_js() -> &'static str {
    r#"
const { chromium } = require('playwright');
const [,, url, marker, shotPath, waitMs] = process.argv;
(async () => {
  const out = { available: true, executed: false, marker_observed: false, channel: '', console: [], screenshot: '', notes: [] };
  let browser;
  try {
    browser = await chromium.launch({ args: ['--no-sandbox'] });
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();

    // A dialog blocks the page until it is handled; handling it is also how we
    // read its message.
    page.on('dialog', async (d) => {
      const msg = d.message() || '';
      if (msg.includes(marker)) { out.executed = true; out.marker_observed = true; out.channel = out.channel || 'dialog'; }
      try { await d.dismiss(); } catch {}
    });
    page.on('console', (m) => {
      const t = m.text();
      if (out.console.length < 40) out.console.push(t);
      if (t.includes(marker)) { out.executed = true; out.marker_observed = true; out.channel = out.channel || 'console'; }
    });
    page.on('pageerror', (e) => { if (out.console.length < 40) out.console.push('pageerror: ' + e.message); });

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: Number(waitMs) });
    // Give deferred handlers (onerror, onload, timers) a chance to run.
    await page.waitForTimeout(Math.min(2500, Number(waitMs) / 2));

    const title = await page.title().catch(() => '');
    if (title.includes(marker)) { out.executed = true; out.marker_observed = true; out.channel = out.channel || 'title'; }
    const global = await page.evaluate(() => window.__neurosploit || '').catch(() => '');
    if (String(global).includes(marker)) { out.executed = true; out.marker_observed = true; out.channel = out.channel || 'global'; }

    // Reflection without execution is worth recording: it tells the operator
    // the input reaches the response and the context is what blocked it.
    if (!out.executed) {
      const html = await page.content().catch(() => '');
      if (html.includes(marker)) out.notes.push('marker is reflected in the DOM but did not execute — encoded, non-executing context, or blocked by CSP');
    }
    if (out.marker_observed && shotPath) {
      try { await page.screenshot({ path: shotPath, fullPage: false }); out.screenshot = shotPath; } catch {}
    }
  } catch (e) {
    out.notes.push('browser error: ' + (e && e.message ? e.message : String(e)));
  } finally {
    try { if (browser) await browser.close(); } catch {}
    process.stdout.write('NSJSON' + JSON.stringify(out) + 'NSEND');
  }
})();
"#
}

/// Pull the driver's result out of its stdout.
///
/// Playwright and npx print their own noise, so the payload is delimited rather
/// than assumed to be the whole stream.
pub fn parse_result(stdout: &str) -> Option<BrowserResult> {
    let start = stdout.find("NSJSON")? + "NSJSON".len();
    let end = stdout[start..].find("NSEND")? + start;
    serde_json::from_str(&stdout[start..end]).ok()
}

pub struct BrowserProbe {
    policy: ScopePolicy,
    timeout: Duration,
}

impl BrowserProbe {
    pub fn new(policy: ScopePolicy) -> Self {
        BrowserProbe { policy, timeout: Duration::from_secs(30) }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Is a browser usable on this machine?
    pub fn available() -> bool {
        which("node") && (playwright_installed() || which("npx"))
    }

    /// Load `url` in a real browser and report whether `marker` executed.
    ///
    /// The scope guard runs first: driving a browser is still sending traffic,
    /// and a validator that wanders off-target while confirming a finding would
    /// undo the whole point of having a boundary.
    pub async fn confirm_execution(&self, url: &str, marker: &str, shot: Option<&str>) -> BrowserResult {
        let decision = self.policy.check(url, Action::Exploit);
        if !decision.allowed() {
            return BrowserResult::unavailable(&format!("scope guard refused the browser check: {}", decision.reason()));
        }
        if !Self::available() {
            return BrowserResult::unavailable(
                "no browser available — install node and `npx playwright install chromium`. Nothing is confirmed without one.",
            );
        }

        let dir = std::env::temp_dir().join(format!("ns-browser-{}", std::process::id()));
        if std::fs::create_dir_all(&dir).is_err() {
            return BrowserResult::unavailable("could not create a temp dir for the browser driver");
        }
        let script = dir.join("ns-xss-probe.js");
        if std::fs::write(&script, driver_js()).is_err() {
            return BrowserResult::unavailable("could not write the browser driver");
        }

        let ms = self.timeout.as_millis().to_string();
        let mut cmd = tokio::process::Command::new("node");
        cmd.arg(&script).arg(url).arg(marker).arg(shot.unwrap_or("")).arg(&ms);
        cmd.kill_on_drop(true);
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());

        let run = tokio::time::timeout(self.timeout + Duration::from_secs(10), async {
            cmd.output().await
        })
        .await;

        let output = match run {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return BrowserResult::unavailable(&format!("could not start node: {e}")),
            Err(_) => return BrowserResult::unavailable("the browser check timed out"),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        match parse_result(&stdout) {
            Some(r) => r,
            None => {
                let err = String::from_utf8_lossy(&output.stderr);
                let hint = if err.contains("Cannot find module 'playwright'") {
                    "playwright is not installed — run `npx playwright install chromium`"
                } else {
                    "the browser driver produced no result"
                };
                BrowserResult::unavailable(&format!("{hint}: {}", err.chars().take(200).collect::<String>()))
            }
        }
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

fn playwright_installed() -> bool {
    // A local install is what makes the driver's `require` work without a
    // network round trip on every check.
    ["node_modules/playwright", "node_modules/.bin/playwright"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_carries_the_marker_and_a_self_report() {
        let m = crate::validation::canary("nsxss");
        for p in xss_payloads(&m) {
            assert!(p.contains(&m), "payload must carry the marker: {p}");
            assert!(
                p.contains("document.title") || p.contains("__neurosploit"),
                "a payload that does not report itself proves nothing we can attribute: {p}"
            );
        }
    }

    #[test]
    fn payloads_cover_the_contexts_a_value_lands_in() {
        let p = xss_payloads("M");
        let all = p.join(" ");
        assert!(all.contains("\"><script"), "attribute break-out");
        assert!(all.contains("onerror"), "event handler");
        assert!(all.contains("javascript:"), "URL context");
        assert!(all.contains("</textarea>"), "raw-text element");
        assert!(all.contains("constructor.constructor"), "template expression");
    }

    #[test]
    fn a_console_hit_alone_is_not_proof_of_execution() {
        let r = BrowserResult { available: true, executed: true, marker_observed: true, channel: "console".into(), ..Default::default() };
        assert!(!r.proves_execution(), "a page can log the value it reflected without running it");
        let r = BrowserResult { channel: "dialog".into(), ..r };
        assert!(r.proves_execution());
    }

    #[test]
    fn an_unavailable_browser_confirms_nothing() {
        let r = BrowserResult::unavailable("node missing");
        assert!(!r.available && !r.proves_execution());
        // The distinction that matters: this is "we could not look", and it
        // must never read as either a clean result or a finding.
        assert!(!r.executed && !r.marker_observed);
    }

    #[test]
    fn the_driver_result_is_parsed_out_of_surrounding_noise() {
        let out = "npm warn something\nDownloading Chromium...\nNSJSON{\"available\":true,\"executed\":true,\"marker_observed\":true,\"channel\":\"dialog\",\"console\":[],\"screenshot\":\"\",\"notes\":[]}NSEND\ntrailing chatter";
        let r = parse_result(out).expect("must find the delimited payload");
        assert!(r.proves_execution());
        assert_eq!(r.channel, "dialog");
    }

    #[test]
    fn garbage_output_yields_no_result_rather_than_a_default_one() {
        assert!(parse_result("playwright exploded").is_none());
        assert!(parse_result("NSJSON{not json}NSEND").is_none());
    }

    #[tokio::test]
    async fn an_out_of_scope_url_is_refused_before_a_browser_starts() {
        let mut policy = ScopePolicy::for_target("https://app.example.com/");
        policy.soft.max_requests_per_minute = 0;
        let probe = BrowserProbe::new(policy);
        let r = probe.confirm_execution("https://evil.test/x", "M", None).await;
        assert!(!r.available);
        assert!(r.notes[0].contains("scope guard refused"), "{:?}", r.notes);
    }
}
