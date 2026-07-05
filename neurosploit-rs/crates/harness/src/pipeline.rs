use crate::agents::{Agent, Library};
use crate::pool::{ModelPool, Task};
use crate::rl::{severity_reward, RlState};
use crate::types::{Finding, RunConfig};
use crate::report;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Sender;

/// Result of an engagement run.
#[derive(Default, Serialize)]
pub struct RunOutput {
    pub target: String,
    pub findings: Vec<Finding>,
    pub agents_ran: Vec<String>,
    pub candidates: usize,
    pub recon: String,
    /// The run's output directory (runs/ns-<ts>-<target>/).
    pub workdir: String,
    /// Paths to persisted artifacts (recon/exploit/findings/report), if any.
    pub artifacts: Vec<String>,
}

const RECON_SYS: &str = "You are an elite web recon specialist on an AUTHORIZED engagement. Actively fetch the target with your tools and map the REAL attack surface in DEPTH — do not ask for permission, proceed:\n\
- Crawl pages, forms and parameters; record every input, header, cookie and redirect.\n\
- DOWNLOAD the linked JavaScript bundles (curl each script) and ANALYZE them: extract API endpoints/routes, hidden/undocumented parameters, GraphQL operations, secrets / API keys / tokens, cloud & third-party URLs, feature flags, and `sourceMappingURL` references (fetch source maps if exposed to recover original source).\n\
- Fingerprint the tech stack and EXACT versions (server, framework, libraries, CMS, JS libs) from headers, HTML, asset paths and JS.\n\
- Analyze responses deeply: status codes, ALL headers, Set-Cookie flags, verbose errors/stack traces, content types, and length/timing differentials.\n\
- Map auth (cookie/JWT/OAuth), APIs (REST & GraphQL), and any dev/staging/internal hosts referenced anywhere.\n\
Base everything on real observed responses — never assume. Reply with a COMPACT JSON object with keys {tech, versions, endpoints, params, apis, auth, js_findings, secrets, hosts, notes}. No prose.";

/// Operator directives (focus instructions + auth material) prepended to
/// recon/exploit prompts so the engagement is steered as the user asked.
fn operator_directives(cfg: &RunConfig) -> String {
    let mut s = String::new();
    if let Some(focus) = cfg.instructions.as_deref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!("OPERATOR FOCUS — prioritise this: {focus}\n"));
    }
    if let Some(auth) = cfg.auth.as_deref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!("AUTHENTICATION — test as an authenticated user; send this with each request: {auth}\n"));
    }
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

/// Tool-usage doctrine prepended to recon/exploit prompts so the agent knows
/// exactly what it may use. Best run on Kali Linux (or the Kali Docker image),
/// where these tools are preinstalled.
fn tool_doctrine(mcp_on: bool) -> String {
    let browser = if mcp_on {
        "BROWSER (Playwright MCP is available — USE IT, don't rely on curl alone): for any JS-heavy / SPA / Angular / React / Vue target, DRIVE THE REAL BROWSER — navigate, wait for the app to render, read the live DOM, click through client-side routes (e.g. #/admin, #/administration, #/score-board), submit forms, and watch the NETWORK requests the app makes to discover the real REST/GraphQL API. PROVE client-side issues (XSS actually firing, DOM sinks, auth flows) in the browser and capture a screenshot as evidence. Use curl for the API/backend calls you discover; use the browser for anything the SPA renders or executes client-side."
    } else {
        "BROWSER (no MCP — use the Playwright CLI to complement curl on JS-heavy targets): curl only sees the initial HTML (an empty SPA shell renders nothing useful). To render/interact, write a small Playwright script and run it, e.g.:\n\
         `npx -y playwright@latest install chromium >/dev/null 2>&1; cat > /tmp/pw.js <<'EOF'\n\
         const { chromium } = require('playwright');\n(async () => { const b = await chromium.launch(); const p = await b.newPage();\n\
         p.on('request', r => console.log('REQ', r.method(), r.url()));\n await p.goto(process.argv[2], {waitUntil:'networkidle'});\n\
         console.log(await p.content()); await p.screenshot({path:'/tmp/shot.png'}); await b.close(); })();\nEOF`\n\
         then `node /tmp/pw.js <url>` to get the rendered DOM + the XHR/fetch URLs the app calls (that reveals the real API). Use `npx playwright screenshot <url> out.png` for quick proof. Combine with curl for the discovered API endpoints."
    };
    format!(
        "TOOLING (authorized; best on Kali Linux or the kalilinux/kali-rolling Docker image):\n\
         - HTTP: `curl` (dump ALL response headers with -i/-D-, follow/inspect redirects, set methods/params/cookies), `wget`.\n\
         - Ports/services: `rustscan` if present, else `nmap`; if neither is installed you may \
           install via apt (`apt install -y nmap`), brew, or cargo (`cargo install rustscan`) — \
           otherwise probe common ports with `curl`/`nc`.\n\
         - Content/params/URLs: `ffuf`, `gobuster`, `gau`, `katana`, `waybackurls`, `linkfinder` when available.\n\
         - JS ANALYSIS: download every linked script (`curl -s <script.js>`) and grep it for endpoints/paths, \
           `fetch(`/`axios`/XHR URLs, API & GraphQL routes, hidden params, and secrets (AKIA…, `api_key`, `token`, \
           `Bearer `, `authorization`), plus `sourceMappingURL` (fetch the .map to recover original source). \
           Prefer `linkfinder`/`gau`/`katana` to harvest more URLs when present, else regex with `grep -Eo`.\n\
         - REQUEST/RESPONSE ANALYSIS: read status codes, every header, Set-Cookie flags, content-type, body length \
           and response timing; use DIFFERENTIALS (authenticated vs anonymous, valid vs invalid input, existing vs \
           missing resource) and reflected input / verbose errors to infer behavior and CONFIRM issues with evidence. \
           Save full request/response pairs when they matter for the PoC.\n\
         - NUCLEI (fast, targeted — never a blind full scan): first fingerprint the stack, then run nuclei ONLY on \
           relevant templates, e.g. `nuclei -u <target> -tags <detected-tech,cve> -severity critical,high,medium \
           -rl 50 -timeout 8 -retries 1` (or `-t <specific-template>` for a suspected CVE). Prefer targeted \
           `-id`/`-tags` over the whole template set so it stays quick; confirm any hit manually with curl.\n\
         - MISCONFIG HUNTING: probe for absurd-but-common misconfigurations — exposed `.git`/`.env`/backup & config \
           files, directory listing, debug/actuator/trace endpoints, default & weak credentials, open admin panels, \
           permissive CORS, verbose stack traces, exposed dashboards (Kibana/Grafana/Jenkins/phpMyAdmin), and cloud \
           metadata (169.254.169.254) via SSRF.\n\
         - RATE-LIMIT / ANTI-AUTOMATION: on auth, password-reset, OTP and sensitive endpoints, send a controlled \
           burst (e.g. ~20-30 requests) and check for 429/lockout/Retry-After/backoff; report absence as a finding. \
           Keep bursts small and non-disruptive — this is a control check, not a DoS.\n\
         - TOOL DOWNLOAD (authorized): when a public PoC or scanner is needed you MAY `git clone` a specific PoC/exploit \
           repo or download a tool (`git clone`, `wget`, `pip install`, `go install`, `cargo install`) — use pinned, \
           reputable sources; review before running; never run destructive payloads.\n\
         - {browser}\n\
         - {ua}{proxy}{pocs}\
         Use only what is installed; degrade gracefully. Never run destructive or DoS actions.\n\n",
        ua = ua_line(),
        proxy = proxy_line(),
        pocs = pocs_line(),
    )
}

/// Default identifying User-Agent so target owners (and the operator) can tell
/// traffic came from NeuroSploit — and so authorship of a scan is unambiguous.
pub fn default_user_agent() -> String {
    format!("NeuroSploit/{} (authorized security assessment; +https://github.com/JoasASantos/NeuroSploit)",
        env!("CARGO_PKG_VERSION"))
}

/// Identify NeuroSploit traffic at the request layer (User-Agent + a marker
/// header). Overridable via `NEUROSPLOIT_UA`.
fn ua_line() -> String {
    let ua = std::env::var("NEUROSPLOIT_UA").ok().filter(|v| !v.trim().is_empty())
        .unwrap_or_else(default_user_agent);
    format!(
        "IDENTIFY (attribution — do NOT strip): tag every HTTP request as NeuroSploit so the scan is \
         attributable — add `-A \"{ua}\"` (User-Agent) AND `-H \"X-NeuroSploit-Scan: {}\"` to curl. Only omit \
         when a specific test requires a different/absent User-Agent.\n         ",
        env!("CARGO_PKG_VERSION"))
}

/// Attribution stamped into every finding's impact so the provenance travels
/// with the finding across the report, findings.json and any copy — making it
/// hard to silently re-badge NeuroSploit's output as someone else's work.
const ATTRIBUTION: &str = "Identified and validated by NeuroSploit (multi-model adversarial validation) — https://github.com/JoasASantos/NeuroSploit · by Joas A Santos & Red Team Leaders.";

/// Re-validate a set of candidate findings (N-model voting + adversarial refute)
/// WITHOUT re-running recon/exploitation — for recovered/interrupted runs, so the
/// operator can filter false positives on what was already found. Streams
/// progress and returns the surviving, attribution-stamped findings.
pub async fn revalidate(findings: Vec<Finding>, pool: &ModelPool, vote_n: usize, tx: Sender<String>) -> Vec<Finding> {
    pool.set_progress(tx.clone());
    let _ = tx.send(format!("re-validating {} recovered finding(s) by {}-model vote…", findings.len(), vote_n)).await;
    let deduped = dedup_findings(findings);
    let mut v = validate(deduped, pool, VOTE_SYS, vote_n, &tx).await;
    v = refute_pass(v, pool, vote_n, &tx).await;
    stamp_attribution(&mut v);
    let _ = tx.send(format!("re-validation done — {} finding(s) survived", v.len())).await;
    v
}

/// Append the NeuroSploit attribution to each finding's impact (idempotent).
pub fn stamp_attribution(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        if !f.impact.contains("Identified and validated by NeuroSploit") {
            let sep = if f.impact.trim().is_empty() { "" } else { "\n\n" };
            f.impact = format!("{}{sep}{ATTRIBUTION}", f.impact.trim_end());
        }
    }
}

/// If a local proxy is configured (Burp/ZAP), tell agents to route HTTP through
/// it so the operator can inspect/replay traffic in Burp Suite.
fn proxy_line() -> String {
    match std::env::var("NEUROSPLOIT_PROXY").ok().filter(|v| !v.trim().is_empty()) {
        Some(p) => format!(
            "PROXY: route ALL HTTP through the local intercepting proxy at {p} (Burp/ZAP) so the operator can \
             inspect & replay in Burp — add `--proxy {p} -k` to every curl (and set http(s)_proxy for other tools). \
             Send anything noteworthy through it for manual review.\n         "),
        None => String::new(),
    }
}

/// If a PoC directory is set, tell agents to save custom exploit scripts there.
fn pocs_line() -> String {
    match std::env::var("NEUROSPLOIT_POCS").ok().filter(|v| !v.trim().is_empty()) {
        Some(d) => format!(
            "POCS: when an issue needs a custom multi-step exploit/script to prove it, WRITE a runnable PoC \
             (curl/python/bash) to {d}/ with a short header comment (target, what it proves, usage), run it to \
             confirm, and reference the file path in the finding evidence.\n         "),
        None => String::new(),
    }
}

/// Data-safety guardrail prepended to every exploit/chain prompt.
const SAFETY_DOCTRINE: &str = "DATA SAFETY (strict): prove impact WITHOUT harming data. Do NOT modify, delete, \
overwrite, encrypt or exfiltrate data, create/alter/escalate accounts, or change configuration/state — unless the \
operator has explicitly authorized that specific action. Read-only, minimal proof. If you encounter PII (names, \
emails, CPF/SSN, phones, cards, tokens): confirm access with the SMALLEST possible sample and REDACT it in the \
report (e.g. show 1 masked record + a count) — never dump, store, or transmit the dataset. Prefer benign markers \
and OOB/echo checks over any state-changing payload. When unsure whether an action is safe, don't do it — report \
it as reachable and stop.\n\n";
const VOTE_SYS: &str = "You are an adversarial security validator. Decide if the candidate finding is a REAL, reproducible, exploitable vulnerability whose EVIDENCE actually proves impact. Reject common false positives: input merely reflected but not executed; version/banner guesses with no working PoC; self-XSS; theoretical issues; an error message or stack trace mistaken for injection; missing, generic, or non-reproducible evidence; severity inflated beyond what the evidence demonstrates. Confirm only if the provided evidence (request/response) concretely proves the vulnerability. Reply with JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}. Default to rejected when uncertain.";
/// Adversarial second pass for High/Critical findings: assume false positive
/// until the evidence forces otherwise. A finding that can't withstand the
/// skeptics is dropped.
const REFUTE_SYS: &str = "You are a skeptical senior reviewer trying to DISPROVE a reported vulnerability. Assume it is a FALSE POSITIVE unless the evidence forces otherwise. Scrutinize: does the evidence PROVE execution/impact, or only that input was reflected/accepted? Is there a real working PoC, or just a version/banner/theory? Could it be self-XSS, an error message, or an unreachable path? Reply JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"} where confirmed means the vulnerability is REAL and proven by the evidence. When in doubt, reject.";
const CODE_VOTE_SYS: &str = "You are an adversarial source-code reviewer. Decide if the reported issue is a REAL vulnerability in the provided code (reachable, exploitable, not a false positive). Reply JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}.";

/// ReAct loop directive: make the agent reason → act with a tool → observe →
/// iterate, instead of one-shot guessing. Keeps it grounded in real evidence.
const REACT_DOCTRINE: &str = "METHOD (ReAct): work in explicit Thought → Action → Observation cycles. \
Each Action runs ONE concrete tool command (e.g. a curl request); read its real Observation before the next Thought. \
Base every claim on an actual observed response — never assume. Stop when you've either proven an issue or exhausted reasonable checks. Be token-efficient: no filler, no repetition.\n\n";

/// DEPTH doctrine (v3.5.2): push past detection to demonstrated impact, and
/// chain. Distilled from reviewing real AI-pentest output that kept stopping at
/// "exposed" instead of "exploited".
const DEPTH_DOCTRINE: &str = "DEPTH (exploit, don't just expose):\n\
- Exposed → exploited: any info-disclosure, exposed service/catalog/WSDL, leaked credential/token, or non-prod (dev/staging) host you find MUST be USED before you report it — call the exposed endpoint, decode the leaked artifact, log in with the leaked credential, hit the dev host. If you only observed it but never used it, report it as a LEAD (low confidence), not a confirmed finding.\n\
- Chain across steps: reuse any session/JWT/cookie/credential you obtain in one step against every other module; if one bug yields access, pivot it into IDOR/privesc/data-exfil and report the CHAIN, not isolated parts.\n\
- Decode & fingerprint → CVE: decode opaque tokens/paths (base64/JSON/marshal) and fingerprint the stack (server, framework, library/gem/plugin versions); map exact versions to known CVEs and attempt a safe, non-destructive PoC.\n\
- Audit tokens: for any JWT, check alg-confusion (RS→HS), alg:none, kid/jku injection, whether the signature is actually verified, and weak/guessable HS256 secrets.\n\
- Calibrate honestly: claim High/Critical ONLY when impact is DEMONSTRATED; unproven DoS/abuse is Low/Info or a lead, never inflated.\n\n";

/// Black-box web engagement: recon → parallel exploit → N-model vote → report.
pub async fn run(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    pool.set_progress(tx.clone());
    let _ = tx
        .send(format!(
            "Loaded {} agents ({} vuln / {} recon / {} code / {} meta) · models: {} · vote_n={} · concurrency={}{}",
            lib.total(), lib.vulns.len(), lib.recon.len(), lib.code.len(), lib.meta.len(),
            pool.candidates.iter().map(|m| m.label()).collect::<Vec<_>>().join(", "),
            cfg.vote_n, cfg.concurrency,
            if pool.mcp_config.is_some() { " · Playwright MCP ON" } else { "" },
        ))
        .await;

    // ---- 1. Recon ------------------------------------------------------
    // 1a. Deterministic HTTP probe (real request/response facts) — grounds the
    // model recon and every downstream decision. Best-effort, skipped offline.
    let probe_facts = if cfg.offline {
        String::new()
    } else {
        let p = crate::probe::probe(&cfg.target).await;
        let _ = tx.send(crate::probe::probe_summary(&p)).await;
        crate::probe::probe_json(&p)
    };
    let recon = if cfg.offline {
        let _ = tx.send("recon: offline mode — skipping model calls".into()).await;
        "{}".to_string()
    } else {
        let recon_user = format!(
            "{}{}OBSERVED HTTP PROBE (real request/response facts — build on these, verify, and go deeper):\n{}\n\nTarget: {}",
            operator_directives(&cfg), tool_doctrine(pool.mcp_config.is_some()), probe_facts, cfg.target);
        match pool.complete_routed(Task::Recon, "recon", RECON_SYS, &recon_user).await {
            Ok((m, t)) => {
                let _ = tx.send(format!("recon complete via {}", m.label())).await;
                if cfg.verbose {
                    let snip: String = t.chars().take(280).collect();
                    let _ = tx.send(format!("  recon> {}", snip.replace('\n', " "))).await;
                }
                // Keep the deterministic probe facts alongside the model recon so
                // exploitation agents always see the observed evidence.
                format!("{}\n\nMODEL RECON:\n{}", probe_facts, t)
            }
            Err(e) => {
                let _ = tx.send(format!("recon failed ({e}) — continuing with probe facts only")).await;
                probe_facts.clone()
            }
        }
    };

    // ---- 2. Intelligent, RL-ranked agent selection ---------------------
    let mut rl = cfg.rl_path.as_ref().map(|p| RlState::load(Path::new(p))).unwrap_or_default();
    let mut ranked: Vec<Agent> = lib.vulns.clone();
    ranked.sort_by(|a, b| rl.weight(&b.name).partial_cmp(&rl.weight(&a.name)).unwrap_or(std::cmp::Ordering::Equal));
    let cap = if cfg.max_agents > 0 { cfg.max_agents.min(ranked.len()) } else { ranked.len() };

    if cfg.offline {
        let selected: Vec<Agent> = ranked.into_iter().take(cap).collect();
        let _ = tx.send(format!("selected {} specialist agents (RL-ranked)", selected.len())).await;
        let _ = tx.send("offline: no exploitation performed (provide API keys or --subscription to run live)".into()).await;
        let artifacts = persist(&cfg, &recon, "", &[]);
        return RunOutput { target: cfg.target.clone(), workdir: cfg.workdir.clone().unwrap_or_default(), findings: vec![], agents_ran: selected.iter().map(|a| a.name.clone()).collect(), candidates: 0, recon, artifacts };
    }

    // Use the model to pick the agents whose preconditions match the recon —
    // the harness reasons about *which* specialists to run, not all of them.
    let focus = cfg.instructions.clone().unwrap_or_default();
    let chosen = select_agents(pool, &recon, &focus, &ranked, &tx).await;
    let selected: Vec<Agent> = if !chosen.is_empty() {
        let sel: Vec<Agent> =
            ranked.iter().filter(|a| chosen.iter().any(|c| c == &a.name)).cloned().collect();
        if sel.is_empty() {
            heuristic_select(&ranked, &recon, &focus, cap)
        } else {
            sel.into_iter().take(cap).collect()
        }
    } else {
        // LLM selection failed/empty → recon+focus keyword heuristic, not a blind flat list.
        let _ = tx.send("selection empty — using recon-keyword heuristic".into()).await;
        heuristic_select(&ranked, &recon, &focus, cap)
    };
    // Dedup: never run the same agent twice in one engagement.
    let selected: Vec<Agent> = {
        let mut seen = std::collections::HashSet::new();
        selected.into_iter().filter(|a| seen.insert(a.name.clone())).collect()
    };
    let _ = tx
        .send(format!("intelligently selected {} agent(s) matching recon: {}", selected.len(),
            selected.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ")))
        .await;

    // ---- 3. Exploit (parallel) -----------------------------------------
    let target = cfg.target.clone();
    let verbose = cfg.verbose;
    let mcp_on = pool.mcp_config.is_some();
    let directives = operator_directives(&cfg);
    // Token economy: each agent gets a capped recon context, not the full blob.
    let recon_ctx: String = recon.chars().take(3500).collect();
    let raw: Vec<(String, String, Vec<Finding>)> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let target = target.clone();
            let recon = recon_ctx.clone();
            let directives = directives.clone();
            let txc = tx.clone();
            async move {
                if pool.stop_exploiting() {
                    return (ag.name.clone(), String::new(), vec![]);
                }
                if verbose {
                    let _ = txc.send(format!("  ▶ launching agent: {} ({})", ag.name, ag.title.replace(" Agent", ""))).await;
                }
                let user = format!(
                    "AUTHORIZED engagement — you have explicit permission to test {target}. \
                     Do not ask for confirmation — proceed and PROVE each issue.\n\n\
                     {directives}{react}{depth}{safety}{doctrine}{body}\n\nWhen done, reply with ONLY a JSON array of confirmed findings (may be empty []). \
                     Each item: {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}. \
                     `evidence` must contain the concrete proof (request/response excerpt).",
                    target = target,
                    directives = directives,
                    react = REACT_DOCTRINE,
                    depth = DEPTH_DOCTRINE, safety = SAFETY_DOCTRINE,
                    doctrine = tool_doctrine(mcp_on),
                    body = ag.user.replace("{target}", &target).replace("{recon_json}", &recon),
                );
                match pool.complete_routed(Task::Exploit, &ag.name, &ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("exploit {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
                        // Live findings feed: surface each candidate the moment it appears.
                        for c in &f {
                            let _ = txc.send(format!("finding: [{}] {} @ {}", c.severity, c.title, c.endpoint)).await;
                            if let Ok(j) = serde_json::to_string(c) { let _ = txc.send(format!("finding_json: {j}")).await; }
                        }
                        (ag.name.clone(), text, f)
                    }
                    Err(e) => {
                        let _ = txc.send(format!("exploit {} failed: {e}", ag.name)).await;
                        (ag.name.clone(), format!("ERROR: {e}"), vec![])
                    }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    let transcript = transcript_of(&raw);
    let candidates = dedup_findings(raw.iter().flat_map(|(_, _, f)| f.clone()).collect());
    let _ = tx.send(format!("{} candidate finding(s) (deduped) — validating by {}-model vote", candidates.len(), cfg.vote_n)).await;

    // ---- 4. Validate by N-model voting ---------------------------------
    let mut findings = validate(candidates, pool, VOTE_SYS, cfg.vote_n, &tx).await;

    // ---- 5. Attack chaining: multi-round post-exploitation pivots ------
    let chained = attack_chain(pool, &cfg, &recon, &findings, &lib.chains, &tx).await;
    findings.extend(chained);
    findings = dedup_findings(findings);
    let findings = refute_pass(findings, pool, cfg.vote_n, &tx).await;
    finish(cfg, lib, recon, transcript, findings, selected, &mut rl, tx).await
}

/// White-box engagement: analyse a repository's source for vulnerabilities.
pub async fn run_whitebox(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    pool.set_progress(tx.clone());
    let _ = tx.send(format!("WHITEBOX · repo: {} · {} code agents · models: {}", cfg.target, lib.code.len(),
        pool.candidates.iter().map(|m| m.label()).collect::<Vec<_>>().join(", "))).await;

    let context = collect_repo_context(Path::new(&cfg.target), 200, 120_000);
    let bytes = context.len();
    let _ = tx.send(format!("collected {} bytes of source context", bytes)).await;
    if bytes == 0 {
        let _ = tx.send("no readable source found at the given path".into()).await;
    }

    let mut rl = cfg.rl_path.as_ref().map(|p| RlState::load(Path::new(p))).unwrap_or_default();
    let mut ranked: Vec<Agent> = if lib.code.is_empty() { lib.vulns.clone() } else { lib.code.clone() };
    ranked.sort_by(|a, b| rl.weight(&b.name).partial_cmp(&rl.weight(&a.name)).unwrap_or(std::cmp::Ordering::Equal));
    let cap = if cfg.max_agents > 0 { cfg.max_agents.min(ranked.len()) } else { ranked.len() };
    let selected: Vec<Agent> = ranked.into_iter().take(cap).collect();
    let _ = tx.send(format!("selected {} code-analysis agents", selected.len())).await;

    if cfg.offline || bytes == 0 {
        let artifacts = persist(&cfg, "{}", &context, &[]);
        return RunOutput { target: cfg.target.clone(), workdir: cfg.workdir.clone().unwrap_or_default(), findings: vec![], agents_ran: selected.iter().map(|a| a.name.clone()).collect(), candidates: 0, recon: String::new(), artifacts };
    }

    let raw: Vec<(String, String, Vec<Finding>)> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let ctx = context.clone();
            let txc = tx.clone();
            async move {
                let user = format!(
                    "{}\n\nSOURCE CODE TO REVIEW:\n```\n{}\n```\n\nReply ONLY with a JSON array of findings (may be empty []). \
                     Each item: {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}} \
                     where `endpoint` is the file:line and `evidence` quotes the vulnerable code.",
                    ag.user.replace("{target}", "the provided repository").replace("{recon_json}", "{}"),
                    ctx
                );
                match pool.complete_routed(Task::Exploit, &ag.name, &ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("analyze {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
                        (ag.name.clone(), text, f)
                    }
                    Err(e) => {
                        let _ = txc.send(format!("analyze {} failed: {e}", ag.name)).await;
                        (ag.name.clone(), format!("ERROR: {e}"), vec![])
                    }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    let transcript = transcript_of(&raw);
    let candidates = dedup_findings(raw.iter().flat_map(|(_, _, f)| f.clone()).collect());
    let _ = tx.send(format!("{} candidate finding(s) (deduped) — validating", candidates.len())).await;
    let findings = validate(candidates, pool, CODE_VOTE_SYS, cfg.vote_n, &tx).await;
    let findings = refute_pass(findings, pool, cfg.vote_n, &tx).await;
    finish(cfg, lib, "{}".into(), transcript, findings, selected, &mut rl, tx).await
}

/// Greybox engagement: review the source code AND exploit the running app in one
/// pipeline — code-review findings become *leads* that guide live exploitation
/// (with credentials/auth so testing is authenticated).
pub async fn run_greybox(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    pool.set_progress(tx.clone());
    let repo = cfg.repo.clone().unwrap_or_default();
    let _ = tx.send(format!("GREYBOX · live: {} · repo: {} · {} code agents",
        cfg.target, repo, lib.code.len())).await;

    // ---- 1. Recon the live target (deterministic probe + model) -------
    let recon = if cfg.offline {
        "{}".to_string()
    } else {
        let p = crate::probe::probe(&cfg.target).await;
        let _ = tx.send(crate::probe::probe_summary(&p)).await;
        let facts = crate::probe::probe_json(&p);
        match pool.complete_routed(Task::Recon, "recon", RECON_SYS,
            &format!("{}{}OBSERVED HTTP PROBE (real facts — build on these):\n{}\n\nTarget: {}",
                operator_directives(&cfg), tool_doctrine(pool.mcp_config.is_some()), facts, cfg.target)).await {
            Ok((m, t)) => { let _ = tx.send(format!("recon complete via {}", m.label())).await; format!("{facts}\n\nMODEL RECON:\n{t}") }
            Err(e) => { let _ = tx.send(format!("recon failed ({e}) — probe facts only")).await; facts }
        }
    };

    // ---- 2. Review the source for leads -------------------------------
    let context = collect_repo_context(Path::new(&repo), 200, 90_000);
    let _ = tx.send(format!("collected {} bytes of source for code review", context.len())).await;
    let mut rl = cfg.rl_path.as_ref().map(|p| RlState::load(Path::new(p))).unwrap_or_default();

    let mut code_leads = String::new();
    if !cfg.offline && !context.is_empty() {
        let code_cap = if cfg.max_agents > 0 { cfg.max_agents.min(lib.code.len()) } else { lib.code.len().min(12) };
        let code_agents: Vec<Agent> = lib.code.iter().take(code_cap).cloned().collect();
        let leads: Vec<Finding> = stream::iter(code_agents.into_iter())
            .map(|ag| {
                let ctx = context.clone();
                let txc = tx.clone();
                async move {
                    let user = format!(
                        "{}\n\nSOURCE:\n```\n{}\n```\nReply ONLY a JSON array of issues (may be []): \
                         {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}} \
                         where endpoint is file:line.",
                        ag.user.replace("{target}", "the repository").replace("{recon_json}", "{}"), ctx
                    );
                    match pool.complete_routed(Task::Select, &ag.name, &ag.system, &user).await {
                        Ok((_, text)) => { let f = extract_findings(&text, &ag.name);
                            let _ = txc.send(format!("review {} → {} lead(s)", ag.name, f.len())).await; f }
                        Err(_) => vec![],
                    }
                }
            })
            .buffer_unordered(cfg.concurrency)
            .collect::<Vec<Vec<Finding>>>().await.into_iter().flatten().collect();
        let leads = dedup_findings(leads);
        if !leads.is_empty() {
            code_leads.push_str("CODE-REVIEW LEADS (confirm these against the LIVE app):\n");
            for l in leads.iter().take(25) {
                code_leads.push_str(&format!("- [{}] {} @ {} ({})\n", l.severity, l.title, l.endpoint, l.cwe));
            }
            code_leads.push('\n');
        }
        let _ = tx.send(format!("{} code lead(s) → guiding live exploitation", leads.len())).await;
    }

    // ---- 3. Select live agents (recon + focus + code leads) -----------
    let mut ranked: Vec<Agent> = lib.vulns.clone();
    ranked.sort_by(|a, b| rl.weight(&b.name).partial_cmp(&rl.weight(&a.name)).unwrap_or(std::cmp::Ordering::Equal));
    let cap = if cfg.max_agents > 0 { cfg.max_agents.min(ranked.len()) } else { ranked.len() };
    let focus = format!("{} {}", cfg.instructions.clone().unwrap_or_default(), code_leads);

    if cfg.offline {
        let selected: Vec<Agent> = ranked.into_iter().take(cap).collect();
        let _ = tx.send(format!("offline: selected {} agent(s); no live exploitation", selected.len())).await;
        let artifacts = persist(&cfg, &recon, &code_leads, &[]);
        return RunOutput { target: cfg.target.clone(), workdir: cfg.workdir.clone().unwrap_or_default(), findings: vec![],
            agents_ran: selected.iter().map(|a| a.name.clone()).collect(), candidates: 0, recon, artifacts };
    }

    let chosen = select_agents(pool, &recon, &focus, &ranked, &tx).await;
    let selected: Vec<Agent> = if !chosen.is_empty() {
        let sel: Vec<Agent> = ranked.iter().filter(|a| chosen.iter().any(|c| c == &a.name)).cloned().collect();
        if sel.is_empty() { heuristic_select(&ranked, &recon, &focus, cap) } else { sel.into_iter().take(cap).collect() }
    } else {
        heuristic_select(&ranked, &recon, &focus, cap)
    };
    let selected: Vec<Agent> = { let mut seen = std::collections::HashSet::new();
        selected.into_iter().filter(|a| seen.insert(a.name.clone())).collect() };
    let _ = tx.send(format!("selected {} live agent(s): {}", selected.len(),
        selected.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "))).await;

    // ---- 4. Exploit live, guided by code leads ------------------------
    let target = cfg.target.clone();
    let verbose = cfg.verbose;
    let mcp_on = pool.mcp_config.is_some();
    let directives = operator_directives(&cfg);
    let recon_ctx: String = recon.chars().take(3000).collect();
    let leads_ctx = code_leads.clone();
    let raw: Vec<(String, String, Vec<Finding>)> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let target = target.clone();
            let recon = recon_ctx.clone();
            let directives = directives.clone();
            let leads = leads_ctx.clone();
            let txc = tx.clone();
            async move {
                if pool.stop_exploiting() {
                    return (ag.name.clone(), String::new(), vec![]);
                }
                if verbose {
                    let _ = txc.send(format!("  ▶ launching agent: {} ({})", ag.name, ag.title.replace(" Agent", ""))).await;
                }
                let user = format!(
                    "AUTHORIZED greybox engagement on {target} — you also have the source review below. \
                     Proceed and PROVE each issue against the LIVE app.\n\n{directives}{leads}{react}{depth}{safety}{doctrine}{body}\n\n\
                     Reply ONLY a JSON array of confirmed findings (may be []): \
                     {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}.",
                    target = target, directives = directives, leads = leads,
                    react = REACT_DOCTRINE, depth = DEPTH_DOCTRINE, safety = SAFETY_DOCTRINE, doctrine = tool_doctrine(mcp_on),
                    body = ag.user.replace("{target}", &target).replace("{recon_json}", &recon),
                );
                match pool.complete_routed(Task::Exploit, &ag.name, &ag.system, &user).await {
                    Ok((m, text)) => { let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("exploit {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
                        (ag.name.clone(), text, f) }
                    Err(e) => { let _ = txc.send(format!("exploit {} failed: {e}", ag.name)).await;
                        (ag.name.clone(), format!("ERROR: {e}"), vec![]) }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect::<Vec<_>>().await;

    let transcript = format!("{}\n{}", code_leads, transcript_of(&raw));
    let candidates = dedup_findings(raw.iter().flat_map(|(_, _, f)| f.clone()).collect());
    let _ = tx.send(format!("{} candidate finding(s) (deduped) — validating", candidates.len())).await;
    let mut findings = validate(candidates, pool, VOTE_SYS, cfg.vote_n, &tx).await;
    let chained = attack_chain(pool, &cfg, &recon, &findings, &lib.chains, &tx).await;
    findings.extend(chained);
    findings = dedup_findings(findings);
    let findings = refute_pass(findings, pool, cfg.vote_n, &tx).await;
    finish(cfg, lib, recon, transcript, findings, selected, &mut rl, tx).await
}

const CHAIN_SYS: &str = "You are a post-exploitation & attack-chaining specialist. You are given ONE confirmed foothold plus any loot already gathered. DECIDE the most promising directions to expand from THIS foothold and pursue them with real tools: post-exploitation (loot credentials/tokens/keys/config/source), credential reuse, privilege escalation (horizontal AND vertical), lateral movement to adjacent services/hosts, data exfiltration, and reaching NEW attack surface the foothold exposes (e.g. SSRF→cloud metadata creds→IAM, SQLi→DB dump→credential reuse→admin, arbitrary file read→secrets→RCE, IDOR→account takeover, auth bypass→internal APIs). PROVE each escalated step with a real tool receipt. Report ONLY NEW findings beyond the input, plus any new loot you discovered (creds, tokens, hosts, internal endpoints) so later stages can reuse it. Authorized engagement; never destructive/DoS.";

/// One orchestration round: take the confirmed findings and try to chain them
/// into higher-impact follow-ups, reusing the recon/auth context. Returns the
/// (unvalidated) new candidate findings produced by chaining.
/// Dedup / identity key for a finding (cwe|endpoint|title-prefix).
fn finding_key(f: &Finding) -> String {
    format!("{}|{}|{}", f.cwe.to_lowercase(), f.endpoint.to_lowercase(),
        f.title.to_lowercase().chars().take(40).collect::<String>())
}

fn sev_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        x if x.starts_with("crit") => 4,
        x if x.starts_with("high") => 3,
        x if x.starts_with("med") => 2,
        x if x.starts_with("low") => 1,
        _ => 0,
    }
}

/// Max footholds expanded per round (keeps token cost bounded).
const CHAIN_SEEDS_PER_ROUND: usize = 6;

/// Robust attack-chaining engine (v3.5.4): iterative, decision-driven,
/// post-exploitation pivoting. Each round takes the newest confirmed footholds,
/// and for EACH one an agent decides which directions to expand (post-ex, cred
/// reuse, privesc, lateral, exfil, new surface), proves new impact, and reports
/// new findings + **loot** (creds/tokens/hosts/endpoints). Loot is carried
/// forward so later rounds reuse it. New validated findings become the next
/// round's footholds; the loop stops at `chain_depth` rounds or when a round
/// yields nothing new (loop-until-dry). Findings are validated each round so we
/// never pivot off a false positive.
async fn attack_chain(pool: &ModelPool, cfg: &RunConfig, recon: &str,
                      confirmed: &[Finding], chains: &[Agent], tx: &Sender<String>) -> Vec<Finding> {
    let max_rounds = cfg.chain_depth;
    if max_rounds == 0 || confirmed.is_empty() || pool.stop_exploiting() {
        return vec![];
    }
    let recipes: String = chains.iter().map(|a| format!("- {}", a.title.replace(" Agent", ""))).collect::<Vec<_>>().join("\n");
    let recipe_block = if recipes.is_empty() { String::new() } else { format!("KNOWN CHAIN RECIPES (apply any that fit):\n{recipes}\n\n") };
    let recon_ctx: String = recon.chars().take(2000).collect();
    let directives = operator_directives(cfg);

    let mut all_new: Vec<Finding> = Vec::new();
    let mut loot: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = confirmed.iter().map(finding_key).collect();

    // Frontier = footholds to expand this round; start with confirmed, best-first.
    let mut frontier: Vec<Finding> = confirmed.to_vec();
    frontier.sort_by(|a, b| sev_rank(&b.severity).cmp(&sev_rank(&a.severity)));

    for round in 1..=max_rounds {
        if pool.stop_exploiting() || frontier.is_empty() {
            break;
        }
        let seeds: Vec<Finding> = frontier.iter().take(CHAIN_SEEDS_PER_ROUND).cloned().collect();
        let _ = tx.send(format!("⛓ attack-chain round {round}/{max_rounds} — expanding {} foothold(s), {} loot item(s)", seeds.len(), loot.len())).await;

        let loot_snapshot = loot.clone();
        let results: Vec<(Vec<Finding>, Vec<String>)> = stream::iter(seeds.into_iter())
            .map(|seed| {
                let (dir, rc, rb, ls, txc) = (directives.clone(), recon_ctx.clone(), recipe_block.clone(), loot_snapshot.clone(), tx.clone());
                async move { chain_from_seed(pool, &cfg.target, &dir, &rc, &rb, &seed, &ls, round, max_rounds, &txc).await }
            })
            .buffer_unordered(4)
            .collect()
            .await;

        // Merge round output: accumulate loot, gather candidate findings.
        let mut round_cands: Vec<Finding> = Vec::new();
        for (fs, lt) in results {
            for l in lt {
                if !loot.iter().any(|x| x.eq_ignore_ascii_case(&l)) { loot.push(l); }
            }
            round_cands.extend(fs);
        }
        // Keep only genuinely NEW findings (unseen key).
        let fresh: Vec<Finding> = dedup_findings(round_cands)
            .into_iter()
            .filter(|f| seen.insert(finding_key(f)))
            .collect();
        if fresh.is_empty() {
            let _ = tx.send("⛓ no new paths this round — chain exhausted".into()).await;
            break;
        }
        // Validate before pivoting further (don't chain off false positives).
        let validated = validate(fresh, pool, VOTE_SYS, cfg.vote_n, tx).await;
        let _ = tx.send(format!("⛓ round {round}: +{} validated finding(s), {} loot item(s) total", validated.len(), loot.len())).await;
        if validated.is_empty() {
            break;
        }
        all_new.extend(validated.clone());
        // Next round expands the freshly-validated footholds, best-first.
        frontier = validated;
        frontier.sort_by(|a, b| sev_rank(&b.severity).cmp(&sev_rank(&a.severity)));
    }
    if !all_new.is_empty() {
        let _ = tx.send(format!("⛓ attack-chaining added {} finding(s) across pivots", all_new.len())).await;
    }
    all_new
}

/// Expand ONE foothold: the agent decides directions, does post-exploitation and
/// pivots, and returns new findings + discovered loot.
async fn chain_from_seed(pool: &ModelPool, target: &str, directives: &str, recon_ctx: &str,
                         recipe_block: &str, seed: &Finding, loot: &[String],
                         round: usize, max: usize, tx: &Sender<String>) -> (Vec<Finding>, Vec<String>) {
    if pool.stop_exploiting() {
        return (vec![], vec![]);
    }
    let loot_block = if loot.is_empty() {
        "(none yet)".to_string()
    } else {
        loot.iter().take(30).map(|l| format!("- {l}")).collect::<Vec<_>>().join("\n")
    };
    let short: String = seed.title.chars().take(28).collect();
    let user = format!(
        "AUTHORIZED engagement on {target}.\n\n{directives}{react}{depth}{safety}{doctrine}\
         FOOTHOLD TO EXPAND (round {round}/{max}):\n- [{}] {} @ {} ({})\n  payload: {}\n  evidence: {}\n\n\
         LOOT GATHERED (reuse it):\n{loot_block}\n\n{recipe_block}RECON:\n{recon_ctx}\n\n\
         From THIS foothold, DECIDE the best directions and PROVE new impact — post-exploitation (loot creds/keys/config/source), credential reuse, privilege escalation (horizontal & vertical), lateral movement to adjacent services/hosts, data exfiltration, and NEW attack surface it exposes. Every claim needs a real tool receipt.\n\n\
         Reply ONLY JSON: {{\"findings\":[{{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}],\"loot\":[\"cred:user:pass@host\",\"token:...\",\"host:10.0.0.5\",\"endpoint:/internal/api\"]}} (empty arrays are fine).",
        seed.severity, seed.title, seed.endpoint, seed.cwe, seed.payload, seed.evidence,
        react = REACT_DOCTRINE, depth = DEPTH_DOCTRINE, safety = SAFETY_DOCTRINE, doctrine = tool_doctrine(pool.mcp_config.is_some()),
    );
    let label = format!("chain:{short}");
    match pool.complete_routed(Task::Exploit, &label, CHAIN_SYS, &user).await {
        Ok((m, text)) => {
            let (f, lt) = extract_chain(&text, "chain");
            if !f.is_empty() || !lt.is_empty() {
                let _ = tx.send(format!("chain[{short}] via {} → {} new finding(s), {} loot", m.label(), f.len(), lt.len())).await;
            }
            (f, lt)
        }
        Err(e) => {
            let _ = tx.send(format!("chain[{short}] failed: {e}")).await;
            (vec![], vec![])
        }
    }
}

/// Parse a chain agent reply into (new findings, loot). Accepts the object form
/// `{"findings":[...],"loot":[...]}` and falls back to a bare findings array.
fn extract_chain(text: &str, agent: &str) -> (Vec<Finding>, Vec<String>) {
    if let (Some(a), Some(b)) = (text.find('{'), text.rfind('}')) {
        if b > a {
            if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(&text[a..=b]) {
                if o.contains_key("findings") {
                    let findings = o.get("findings").map(|v| extract_findings(&v.to_string(), agent)).unwrap_or_default();
                    let loot = o.get("loot").and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    return (findings, loot);
                }
            }
        }
    }
    (extract_findings(text, agent), vec![])
}

// --------------------------------------------------------------------------- shared

const SELECT_SYS: &str = "You are a penetration-test orchestrator. Given recon of a target and a catalog of specialist agents, choose ONLY the agents whose preconditions clearly match the target's attack surface. Be selective. Reply with a JSON array of agent names (strings) drawn exactly from the catalog. No prose.";

/// Ask the model which agents to run for this recon. Returns chosen agent names
/// (empty on failure → caller falls back to RL-ranked agents).
async fn select_agents(pool: &ModelPool, recon: &str, focus: &str, catalog: &[Agent], tx: &Sender<String>) -> Vec<String> {
    let list = catalog
        .iter()
        .map(|a| format!("{} — {} [{}]", a.name, a.title.replace(" Agent", ""), a.cwe))
        .collect::<Vec<_>>()
        .join("\n");
    // Token economy: cap the recon blob fed to the selector.
    let recon_trim: String = recon.chars().take(3000).collect();
    let focus_line = if focus.trim().is_empty() {
        String::new()
    } else {
        format!("OPERATOR FOCUS (strongly prioritise agents for this): {focus}\n\n")
    };
    let user = format!("{focus_line}RECON:\n{recon_trim}\n\nAGENT CATALOG (name — title [cwe]):\n{list}\n\nReturn a JSON array of agent names to run.");
    match pool.complete_routed(Task::Select, "select", SELECT_SYS, &user).await {
        Ok((m, text)) => {
            let names = parse_string_array(&text);
            if names.is_empty() {
                let preview: String = text.chars().take(120).collect();
                let _ = tx.send(format!("agent selection via {} returned no parseable list ({} chars): {}", m.label(), text.len(), preview.replace('\n', " "))).await;
            } else {
                let _ = tx.send(format!("agent selection via {} → {} agent(s) chosen", m.label(), names.len())).await;
            }
            names
        }
        Err(e) => {
            let _ = tx.send(format!("agent selection failed ({e}) — falling back to RL ranking")).await;
            vec![]
        }
    }
}

fn parse_string_array(text: &str) -> Vec<String> {
    match (text.find('['), text.rfind(']')) {
        (Some(a), Some(b)) if b > a => serde_json::from_str::<Vec<String>>(&text[a..=b]).unwrap_or_default(),
        _ => vec![],
    }
}

/// Fallback agent selection when the LLM selector fails: score each agent by
/// keyword overlap between its name/title and the recon text, always seed a
/// black-box baseline of high-yield web classes, and take the top `cap`.
fn heuristic_select(ranked: &[Agent], recon: &str, focus: &str, cap: usize) -> Vec<Agent> {
    const BASELINE: &[&str] = &[
        "sqli_error", "sqli_blind", "sqli_union", "xss_reflected", "xss_stored", "xss_dom",
        "command_injection", "lfi", "path_traversal", "ssrf", "idor", "open_redirect",
        "auth_bypass", "csrf", "ssti", "file_upload", "xxe", "information_disclosure",
        "security_headers", "cors_misconfig",
    ];
    let r = recon.to_lowercase();
    let f = focus.to_lowercase();
    // Recon signal → agent-name substrings. Only agents whose surface the recon
    // actually identified get the signal boost; the rest rely on the baseline.
    let signals: &[(&str, &[&str])] = &[
        ("graphql", &["graphql"]),
        ("jwt", &["jwt"]),
        ("oauth", &["oauth", "oidc", "saml"]),
        ("\"jwt\"", &["jwt"]),
        ("api", &["api_", "bola", "bfla", "idor", "mass_assign", "rate_limit"]),
        ("upload", &["file_upload", "zip_slip"]),
        ("websocket", &["websocket"]),
        ("\"ws\"", &["websocket"]),
        ("graphql", &["graphql"]),
        ("aws", &["aws_", "s3_", "imds", "cloud_"]),
        ("gcp", &["gcp_", "gcs_", "metadata"]),
        ("azure", &["azure_"]),
        ("kubernetes", &["k8s_", "kubelet"]),
        ("docker", &["docker_", "container_"]),
        ("ai_features", &["llm_", "prompt_injection", "rag", "vector_db"]),
        ("chat", &["llm_", "prompt_injection"]),
        ("jinja", &["ssti"]),
        ("flask", &["ssti", "ssrf", "command_injection"]),
        ("php", &["lfi", "rfi", "sqli", "command_injection"]),
        ("template", &["ssti", "csti"]),
        ("redirect", &["open_redirect"]),
        ("login", &["auth_bypass", "brute_force", "sqli", "default_credentials"]),
        ("search", &["xss", "sqli"]),
        ("cache", &["cache", "smuggl"]),
    ];
    let mut scored: Vec<(i32, &Agent)> = ranked
        .iter()
        .map(|a| {
            let mut score = 0;
            if BASELINE.contains(&a.name.as_str()) {
                score += 4;
            }
            // recon-signal mapping: boost agents matching identified surface
            for (sig, names) in signals {
                if r.contains(sig) && names.iter().any(|n| a.name.contains(n)) {
                    score += 6;
                }
            }
            // direct keyword overlap with recon text
            for tok in a.name.split('_') {
                if tok.len() >= 4 && r.contains(tok) {
                    score += 2;
                }
            }
            // operator focus: strongly boost agents matching the requested classes
            if !f.is_empty() {
                let blob = format!("{} {}", a.name, a.title).to_lowercase();
                let hit = ["inject", "sqli", "xss", "ssrf", "ssti", "rce", "command", "lfi", "rfi",
                           "idor", "bola", "bfla", "access", "auth", "privilege", "csrf", "redirect",
                           "deserial", "xxe", "traversal", "upload", "jwt", "secret", "crypto"]
                    .iter()
                    .any(|kw| f.contains(kw) && blob.contains(kw));
                if hit {
                    score += 10;
                }
            }
            (score, a)
        })
        .collect();
    scored.sort_by(|x, y| y.0.cmp(&x.0));
    let mut out: Vec<Agent> = scored.iter().filter(|(s, _)| *s > 0).map(|(_, a)| (*a).clone()).collect();
    if out.is_empty() {
        out = ranked.to_vec();
    }
    out.into_iter().take(cap).collect()
}

async fn validate(candidates: Vec<Finding>, pool: &ModelPool, sys: &str, vote_n: usize, tx: &Sender<String>) -> Vec<Finding> {
    // Prefer a model other than the primary (likely finder) to adjudicate.
    let finder = pool.candidates.first().map(|m| m.label());
    let validated: Vec<Finding> = stream::iter(candidates.into_iter())
        .map(|mut f| {
            let txc = tx.clone();
            let finder = finder.clone();
            async move {
                let q = format!(
                    "Finding: {} | severity {} | {} | at {} | payload {} | evidence {} | impact {}",
                    f.title, f.severity, f.cwe, f.endpoint, f.payload, f.evidence, f.impact
                );
                let (yes, total) = pool.vote(sys, &q, vote_n, finder.as_deref()).await;
                f.validated = crate::pool::quorum_confirmed(&f.severity, yes, total);
                f.votes = format!("{yes}/{total}");
                if f.confidence == 0.0 && total > 0 {
                    f.confidence = yes as f64 / total as f64;
                }
                let _ = txc.send(format!("vote {} → {} ({})", f.title, if f.validated { "CONFIRMED" } else { "rejected" }, f.votes)).await;
                f
            }
        })
        .buffer_unordered(pool.candidates.len().max(2))
        .collect()
        .await;
    validated.into_iter().filter(|f| f.validated).collect()
}

/// Adversarial refutation pass: every confirmed **High/Critical** finding is
/// re-examined by a skeptical panel that tries to prove it's a false positive.
/// A finding that fails to withstand a majority of skeptics is dropped. Lower
/// severities pass through unchanged. Runs only when a real panel exists.
async fn refute_pass(findings: Vec<Finding>, pool: &ModelPool, vote_n: usize, tx: &Sender<String>) -> Vec<Finding> {
    let finder = pool.candidates.first().map(|m| m.label());
    let mut kept = Vec::new();
    for mut f in findings {
        let s = f.severity.to_lowercase();
        let high = s.starts_with("crit") || s.starts_with("high");
        if !high || pool.stop_exploiting() {
            kept.push(f);
            continue;
        }
        let q = format!(
            "Finding: {} | severity {} | {} | at {} | payload {} | evidence {} | impact {}",
            f.title, f.severity, f.cwe, f.endpoint, f.payload, f.evidence, f.impact
        );
        let (yes, total) = pool.vote(REFUTE_SYS, &q, vote_n.max(2), finder.as_deref()).await;
        // Survive on no-response (infra failure) or a surviving majority.
        let survives = total == 0 || yes * 2 > total;
        if survives {
            if total > 0 { f.votes = format!("{} · refute {yes}/{total}", f.votes); }
            kept.push(f);
        } else {
            let _ = tx.send(format!("vote {} → dropped by adversarial refute ({yes}/{total})", f.title)).await;
        }
    }
    kept
}

async fn finish(cfg: RunConfig, _lib: &Library, recon: String, transcript: String, mut findings: Vec<Finding>,
                selected: Vec<Agent>, rl: &mut RlState, tx: Sender<String>) -> RunOutput {
    // --- Grounding gate: no claim without a tool receipt (anti-hallucination) ---
    // White/grey carry source context; black-box is verified empirically.
    let whitebox = cfg.repo.is_some() && cfg.target.starts_with('/');
    let before = findings.len();
    let (kept, demoted) = crate::grounding::gate(findings, &transcript, whitebox);
    findings = kept;
    if demoted > 0 {
        let _ = tx.send(format!("grounding gate: demoted {demoted}/{before} ungrounded claim(s) (no tool receipt)")).await;
    }

    // --- v3.5.2 report-hygiene & exploitation-depth pass ---
    // Calibrate inflated/unproven High-Critical to Medium, flag exposures that
    // were never exploited ("exposed → exploited"), and advise consolidating
    // hygiene findings duplicated across many assets.
    for n in crate::hygiene::calibrate(&mut findings) {
        let _ = tx.send(format!("calibrate: {n}")).await;
    }
    for n in crate::hygiene::depth_audit(&findings) {
        let _ = tx.send(format!("notify: {n}")).await;
    }
    for n in crate::hygiene::hygiene_summary(&findings) {
        let _ = tx.send(format!("notify: {n}")).await;
    }

    // --- POMDP belief: build from grounded findings, report residual uncertainty ---
    let mut wm = crate::belief::WorldModel::new();
    wm.deterministic = whitebox;
    for f in &findings {
        wm.add(&f.id, crate::belief::Kind::Exploit, &f.title, f.confidence.max(0.05).min(0.99));
    }
    let unc = wm.uncertainty(None);
    if !findings.is_empty() {
        let _ = tx.send(format!("belief uncertainty over confirmed findings: {:.2} (0=sharp,1=diffuse)", unc)).await;
    }

    let _ = tx.send(format!("{} validated finding(s)", findings.len())).await;
    // Attribution: stamp provenance into each finding (report + json + copies).
    stamp_attribution(&mut findings);
    // Map findings to OWASP / MITRE / kill-chain stage for the attack graph.
    crate::attack_graph::enrich(&mut findings);

    // RL update: reward agents that produced validated findings; gently decay idle.
    let hit: std::collections::HashMap<&str, f64> = findings.iter().fold(Default::default(), |mut m, f| {
        let e = m.entry(f.agent.as_str()).or_insert(0.0);
        *e = (*e + severity_reward(&f.severity)).min(1.0);
        m
    });
    for a in &selected {
        let r = hit.get(a.name.as_str()).copied().unwrap_or(-0.05);
        rl.update(&a.name, r);
    }
    rl.runs += 1;
    if let Some(p) = &cfg.rl_path {
        rl.save(Path::new(p));
        let _ = tx.send("RL rewards updated".into()).await;
    }

    let artifacts = persist(&cfg, &recon, &transcript, &findings);
    if !artifacts.is_empty() {
        let _ = tx.send(format!("notify: evidence saved → {}", cfg.workdir.clone().unwrap_or_default())).await;
        let _ = tx.send(format!("artifacts saved: {}", artifacts.join(", "))).await;
    }
    // Automatic partial summary (phase complete).
    {
        let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
        for f in &findings { *by.entry(f.severity.as_str()).or_insert(0) += 1; }
        let sev = if by.is_empty() { "none".to_string() }
                  else { by.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
        let _ = tx.send(format!("notify: phase complete — {} validated finding(s) [{}]", findings.len(), sev)).await;
    }

    RunOutput {
        target: cfg.target.clone(),
        workdir: cfg.workdir.clone().unwrap_or_default(),
        candidates: findings.len(),
        findings,
        agents_ran: selected.iter().map(|a| a.name.clone()).collect(),
        recon,
        artifacts,
    }
}

/// Write recon/exploit/findings/report as json+md for downstream reuse.
fn persist(cfg: &RunConfig, recon: &str, transcript: &str, findings: &[Finding]) -> Vec<String> {
    let Some(dir) = &cfg.workdir else { return vec![] };
    let dir = PathBuf::from(dir);
    if std::fs::create_dir_all(&dir).is_err() {
        return vec![];
    }
    let mut written = Vec::new();
    let mut put = |name: &str, content: String| {
        let p = dir.join(name);
        if std::fs::write(&p, content).is_ok() {
            written.push(p.display().to_string());
        }
    };
    put("recon.json", recon.to_string());
    put("recon.md", format!("# Recon — {}\n\n```json\n{}\n```\n", cfg.target, recon));
    if !transcript.is_empty() {
        put("exploitation.md", format!("# Agent transcript — {}\n\n{}", cfg.target, transcript));
    }
    put("findings.json", serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".into()));
    put("findings.md", findings_md(&cfg.target, findings));
    put("report.html", report::html(&cfg.target, findings));
    written
}

fn findings_md(target: &str, findings: &[Finding]) -> String {
    let mut s = format!("# NeuroSploit findings — {}\n\n{} validated finding(s).\n", target, findings.len());
    for (i, f) in findings.iter().enumerate() {
        s.push_str(&format!(
            "\n## {}. [{}] {}\n- agent: `{}`  CWE: {}  CVSS: {}  votes: {}  confidence: {:.2}\n- endpoint: {}\n\n**Payload**\n```\n{}\n```\n\n**Evidence**\n{}\n\n**Impact:** {}\n\n**Remediation:** {}\n",
            i + 1, f.severity, f.title, f.agent, f.cwe, f.cvss, f.votes, f.confidence, f.endpoint, f.payload, f.evidence, f.impact, f.remediation
        ));
    }
    s
}

fn transcript_of(raw: &[(String, String, Vec<Finding>)]) -> String {
    raw.iter().map(|(n, t, f)| format!("## {} ({} candidate)\n\n{}\n", n, f.len(), t)).collect::<Vec<_>>().join("\n")
}

/// Pull a JSON array (or object) of findings out of a model's reply.
///
/// Models are inconsistent about field types — e.g. `confidence` may be a number
/// (0.9), a numeric string ("0.9"), or a word ("High"); `cvss` may be a number or
/// a string. Strict typed deserialization fails the whole batch on any mismatch,
/// so we parse leniently into `Value` and coerce every field.
fn extract_findings(text: &str, agent: &str) -> Vec<Finding> {
    let slice = match (text.find('['), text.rfind(']')) {
        (Some(a), Some(b)) if b > a => &text[a..=b],
        _ => match (text.find('{'), text.rfind('}')) {
            (Some(a), Some(b)) if b > a => &text[a..=b],
            _ => return vec![],
        },
    };
    let val: serde_json::Value = match serde_json::from_str(slice) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let items: Vec<serde_json::Value> = match val {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(_) => vec![val],
        _ => return vec![],
    };
    items
        .into_iter()
        .filter_map(|it| {
            let o = it.as_object()?;
            let title = s(o, "title");
            if title.is_empty() {
                return None;
            }
            Some(Finding {
                id: {
                    let id = s(o, "id");
                    if id.is_empty() {
                        format!("{}-{}", agent, title.chars().take(12).collect::<String>())
                    } else {
                        id
                    }
                },
                agent: agent.to_string(),
                title,
                severity: norm_sev(&s(o, "severity")),
                cwe: s(o, "cwe"),
                cvss: s(o, "cvss"),
                endpoint: s(o, "endpoint"),
                payload: s(o, "payload"),
                evidence: s(o, "evidence"),
                impact: s(o, "impact"),
                remediation: s(o, "remediation"),
                confidence: conf(o.get("confidence")),
                validated: false,
                votes: String::new(),
                ..Default::default()
            })
        })
        .collect()
}

/// Coerce any JSON scalar to a trimmed string.
fn s(o: &serde_json::Map<String, serde_json::Value>, k: &str) -> String {
    match o.get(k) {
        Some(serde_json::Value::String(v)) => v.trim().to_string(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// Accept confidence as number, numeric string, or qualitative word.
fn conf(v: Option<&serde_json::Value>) -> f64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(serde_json::Value::String(t)) => {
            if let Ok(f) = t.trim().parse::<f64>() {
                f
            } else {
                match t.to_lowercase().as_str() {
                    s if s.contains("critical") || s.contains("very high") => 0.97,
                    s if s.contains("high") => 0.9,
                    s if s.contains("med") => 0.6,
                    s if s.contains("low") => 0.3,
                    _ => 0.0,
                }
            }
        }
        _ => 0.0,
    }
}

/// Drop duplicate findings (same CWE + endpoint + lowercased title) that
/// different agents/models may each report, keeping the highest-confidence one.
fn dedup_findings(mut v: Vec<Finding>) -> Vec<Finding> {
    v.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|f| seen.insert(finding_key(f))).collect()
}

fn norm_sev(s: &str) -> String {
    match s.to_lowercase().as_str() {
        x if x.starts_with("crit") => "Critical",
        x if x.starts_with("high") => "High",
        x if x.starts_with("med") => "Medium",
        x if x.starts_with("low") => "Low",
        "" => "Info",
        _ => "Info",
    }
    .to_string()
}

/// Concatenate source files under `root` into a bounded review context.
fn collect_repo_context(root: &Path, max_files: usize, max_bytes: usize) -> String {
    const EXTS: &[&str] = &[
        "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "php", "rb", "c", "cc", "cpp", "h", "hpp",
        "cs", "kt", "swift", "scala", "sh", "sql", "html", "vue", "yml", "yaml", "tf",
    ];
    let mut out = String::new();
    let mut files = 0usize;
    if !root.exists() {
        return out;
    }
    for entry in walkdir::WalkDir::new(root).max_depth(8).into_iter().flatten() {
        if files >= max_files || out.len() >= max_bytes {
            break;
        }
        let path = entry.path();
        let s = path.to_string_lossy();
        if s.contains("/.git/") || s.contains("/node_modules/") || s.contains("/target/") || s.contains("/vendor/") {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !EXTS.contains(&ext) {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();
            let budget = max_bytes.saturating_sub(out.len());
            let take = content.len().min(budget).min(8_000);
            // Char-safe slice: back off to the nearest char boundary so multibyte
            // source files (UTF-8) never panic.
            let mut end = take.min(content.len());
            while end > 0 && !content.is_char_boundary(end) { end -= 1; }
            out.push_str(&format!("\n// ===== file: {} =====\n{}\n", rel, &content[..end]));
            files += 1;
        }
    }
    out
}

const HOST_RECON_SYS: &str = "You are an infrastructure recon specialist on an AUTHORIZED engagement against a HOST/IP. Actively scan with rustscan/nmap (and netexec/smbclient where relevant) to map open ports, services, versions and auth surfaces. Use any provided SSH/Windows credentials to enumerate from inside. Do not ask permission; proceed. Reply with a compact JSON object (host, os, ports, services, auth, ad). No prose.";

const HOST_TOOLING: &str = "TOOLING (best on Kali): nmap/rustscan (ports), netexec/crackmapexec + smbclient (SMB/AD), ssh/sshpass + linpeas (Linux), evil-winrm + winPEAS + impacket (Windows), bloodhound-python/SharpHound (AD), hashcat (offline cracking). Use only supplied credentials; never brute force or run destructive/DoS actions.\n\n";

/// Infrastructure engagement: scan/enumerate an IP/host and run Linux/Windows/AD
/// agents. Mirrors the web pipeline but selects from the `infra` agent set.
pub async fn run_host(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    pool.set_progress(tx.clone());
    let _ = tx.send(format!("HOST · target: {} · {} infra agents · models: {}", cfg.target, lib.infra.len(),
        pool.candidates.iter().map(|m| m.label()).collect::<Vec<_>>().join(", "))).await;

    let recon = if cfg.offline {
        "{}".to_string()
    } else {
        let user = format!("{}{}Target host: {}", operator_directives(&cfg), HOST_TOOLING, cfg.target);
        match pool.complete_routed(Task::Recon, "recon", HOST_RECON_SYS, &user).await {
            Ok((m, t)) => { let _ = tx.send(format!("recon complete via {}", m.label())).await; t }
            Err(e) => { let _ = tx.send(format!("recon failed ({e})")).await; "{}".to_string() }
        }
    };

    let mut rl = cfg.rl_path.as_ref().map(|p| RlState::load(Path::new(p))).unwrap_or_default();
    let mut ranked: Vec<Agent> = lib.infra.clone();
    ranked.sort_by(|a, b| rl.weight(&b.name).partial_cmp(&rl.weight(&a.name)).unwrap_or(std::cmp::Ordering::Equal));
    let cap = if cfg.max_agents > 0 { cfg.max_agents.min(ranked.len()) } else { ranked.len() };
    let focus = cfg.instructions.clone().unwrap_or_default();

    if cfg.offline {
        let selected: Vec<Agent> = ranked.into_iter().take(cap).collect();
        let _ = tx.send(format!("offline: selected {} infra agent(s); no live testing", selected.len())).await;
        let artifacts = persist(&cfg, &recon, "", &[]);
        return RunOutput { target: cfg.target.clone(), workdir: cfg.workdir.clone().unwrap_or_default(), findings: vec![],
            agents_ran: selected.iter().map(|a| a.name.clone()).collect(), candidates: 0, recon, artifacts };
    }

    let chosen = select_agents(pool, &recon, &focus, &ranked, &tx).await;
    let selected: Vec<Agent> = if !chosen.is_empty() {
        let sel: Vec<Agent> = ranked.iter().filter(|a| chosen.iter().any(|c| c == &a.name)).cloned().collect();
        if sel.is_empty() { ranked.iter().take(cap).cloned().collect() } else { sel.into_iter().take(cap).collect() }
    } else {
        ranked.iter().take(cap).cloned().collect()
    };
    let selected: Vec<Agent> = { let mut seen = std::collections::HashSet::new();
        selected.into_iter().filter(|a| seen.insert(a.name.clone())).collect() };
    let _ = tx.send(format!("selected {} infra agent(s): {}", selected.len(),
        selected.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "))).await;

    let target = cfg.target.clone();
    let verbose = cfg.verbose;
    let directives = operator_directives(&cfg);
    let recon_ctx: String = recon.chars().take(3000).collect();
    let raw: Vec<(String, String, Vec<Finding>)> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let target = target.clone();
            let recon = recon_ctx.clone();
            let directives = directives.clone();
            let txc = tx.clone();
            async move {
                if pool.stop_exploiting() { return (ag.name.clone(), String::new(), vec![]); }
                if verbose {
                    let _ = txc.send(format!("  ▶ launching agent: {} ({})", ag.name, ag.title.replace(" Agent", ""))).await;
                }
                let user = format!(
                    "AUTHORIZED host engagement on {target}. Proceed and PROVE each issue with raw tool output.\n\n{directives}{tooling}{react}{safety}{body}\n\nReply ONLY a JSON array of confirmed findings (may be []): {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}.",
                    target = target, directives = directives, tooling = HOST_TOOLING, react = REACT_DOCTRINE, safety = SAFETY_DOCTRINE,
                    body = ag.user.replace("{target}", &target).replace("{recon_json}", &recon),
                );
                match pool.complete_routed(Task::Exploit, &ag.name, &ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("test {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
                        for c in &f {
                            let _ = txc.send(format!("finding: [{}] {} @ {}", c.severity, c.title, c.endpoint)).await;
                            if let Ok(j) = serde_json::to_string(c) { let _ = txc.send(format!("finding_json: {j}")).await; }
                        }
                        (ag.name.clone(), text, f)
                    }
                    Err(e) => { let _ = txc.send(format!("test {} failed: {e}", ag.name)).await;
                        (ag.name.clone(), format!("ERROR: {e}"), vec![]) }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect::<Vec<_>>().await;

    let transcript = transcript_of(&raw);
    let candidates = dedup_findings(raw.iter().flat_map(|(_, _, f)| f.clone()).collect());
    let _ = tx.send(format!("{} candidate finding(s) (deduped) — validating", candidates.len())).await;
    let mut findings = validate(candidates, pool, VOTE_SYS, cfg.vote_n, &tx).await;
    let chained = attack_chain(pool, &cfg, &recon, &findings, &lib.chains, &tx).await;
    findings.extend(chained);
    findings = dedup_findings(findings);
    let findings = refute_pass(findings, pool, cfg.vote_n, &tx).await;
    finish(cfg, lib, recon, transcript, findings, selected, &mut rl, tx).await
}
