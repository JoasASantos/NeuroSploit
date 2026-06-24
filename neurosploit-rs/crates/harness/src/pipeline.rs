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

const RECON_SYS: &str = "You are a web recon specialist on an AUTHORIZED engagement. You have shell tools (curl etc.) — actively fetch the target, enumerate pages/params, and map the real attack surface. Do not ask for permission; proceed. Reply with a compact JSON object (tech, endpoints, params, auth, apis). No prose.";

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
        "A Playwright MCP browser IS available — use it for JS-heavy pages, DOM/JS execution, and to PROVE client-side issues (e.g. XSS firing); capture screenshots as evidence."
    } else {
        "No browser MCP is available — use `curl` (and `wget`) for all HTTP interaction; render/inspect responses directly."
    };
    format!(
        "TOOLING (authorized; best on Kali Linux or the kalilinux/kali-rolling Docker image):\n\
         - HTTP: `curl` (headers, methods, params, cookies), `wget`.\n\
         - Ports/services: `rustscan` if present, else `nmap`; if neither is installed you may \
           install via apt (`apt install -y nmap`), brew, or cargo (`cargo install rustscan`) — \
           otherwise probe common ports with `curl`/`nc`.\n\
         - Content/params: `ffuf`, `gobuster`, `gau`, `katana` when available.\n\
         - {browser}\n\
         Use only what is installed; degrade gracefully. Never run destructive or DoS actions.\n\n"
    )
}
const VOTE_SYS: &str = "You are an adversarial security validator. Decide if the candidate finding is a REAL, reproducible, exploitable vulnerability with proof. Reply with JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}. Default to rejected when uncertain.";
const CODE_VOTE_SYS: &str = "You are an adversarial source-code reviewer. Decide if the reported issue is a REAL vulnerability in the provided code (reachable, exploitable, not a false positive). Reply JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}.";

/// ReAct loop directive: make the agent reason → act with a tool → observe →
/// iterate, instead of one-shot guessing. Keeps it grounded in real evidence.
const REACT_DOCTRINE: &str = "METHOD (ReAct): work in explicit Thought → Action → Observation cycles. \
Each Action runs ONE concrete tool command (e.g. a curl request); read its real Observation before the next Thought. \
Base every claim on an actual observed response — never assume. Stop when you've either proven an issue or exhausted reasonable checks. Be token-efficient: no filler, no repetition.\n\n";

/// Black-box web engagement: recon → parallel exploit → N-model vote → report.
pub async fn run(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
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
    let recon = if cfg.offline {
        let _ = tx.send("recon: offline mode — skipping model calls".into()).await;
        "{}".to_string()
    } else {
        let recon_user = format!("{}{}Target: {}", operator_directives(&cfg), tool_doctrine(pool.mcp_config.is_some()), cfg.target);
        match pool.complete_routed(Task::Recon, RECON_SYS, &recon_user).await {
            Ok((m, t)) => {
                let _ = tx.send(format!("recon complete via {}", m.label())).await;
                if cfg.verbose {
                    let snip: String = t.chars().take(280).collect();
                    let _ = tx.send(format!("  recon> {}", snip.replace('\n', " "))).await;
                }
                t
            }
            Err(e) => {
                let _ = tx.send(format!("recon failed ({e}) — continuing with empty recon")).await;
                "{}".to_string()
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
                if verbose {
                    let _ = txc.send(format!("  ▶ launching agent: {} ({})", ag.name, ag.title.replace(" Agent", ""))).await;
                }
                let user = format!(
                    "AUTHORIZED engagement — you have explicit permission to test {target}. \
                     Do not ask for confirmation — proceed and PROVE each issue.\n\n\
                     {directives}{react}{doctrine}{body}\n\nWhen done, reply with ONLY a JSON array of confirmed findings (may be empty []). \
                     Each item: {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}. \
                     `evidence` must contain the concrete proof (request/response excerpt).",
                    target = target,
                    directives = directives,
                    react = REACT_DOCTRINE,
                    doctrine = tool_doctrine(mcp_on),
                    body = ag.user.replace("{target}", &target).replace("{recon_json}", &recon),
                );
                match pool.complete_routed(Task::Exploit, &ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("exploit {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
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
    let findings = validate(candidates, pool, VOTE_SYS, cfg.vote_n, &tx).await;
    finish(cfg, lib, recon, transcript, findings, selected, &mut rl, tx).await
}

/// White-box engagement: analyse a repository's source for vulnerabilities.
pub async fn run_whitebox(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
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
                match pool.complete(&ag.system, &user).await {
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
    finish(cfg, lib, "{}".into(), transcript, findings, selected, &mut rl, tx).await
}

/// Greybox engagement: review the source code AND exploit the running app in one
/// pipeline — code-review findings become *leads* that guide live exploitation
/// (with credentials/auth so testing is authenticated).
pub async fn run_greybox(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    let repo = cfg.repo.clone().unwrap_or_default();
    let _ = tx.send(format!("GREYBOX · live: {} · repo: {} · {} code agents",
        cfg.target, repo, lib.code.len())).await;

    // ---- 1. Recon the live target -------------------------------------
    let recon = if cfg.offline {
        "{}".to_string()
    } else {
        match pool.complete_routed(Task::Recon, RECON_SYS,
            &format!("{}{}Target: {}", operator_directives(&cfg), tool_doctrine(pool.mcp_config.is_some()), cfg.target)).await {
            Ok((m, t)) => { let _ = tx.send(format!("recon complete via {}", m.label())).await; t }
            Err(e) => { let _ = tx.send(format!("recon failed ({e})")).await; "{}".to_string() }
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
                    match pool.complete_routed(Task::Select, &ag.system, &user).await {
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
                if verbose {
                    let _ = txc.send(format!("  ▶ launching agent: {} ({})", ag.name, ag.title.replace(" Agent", ""))).await;
                }
                let user = format!(
                    "AUTHORIZED greybox engagement on {target} — you also have the source review below. \
                     Proceed and PROVE each issue against the LIVE app.\n\n{directives}{leads}{react}{doctrine}{body}\n\n\
                     Reply ONLY a JSON array of confirmed findings (may be []): \
                     {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}.",
                    target = target, directives = directives, leads = leads,
                    react = REACT_DOCTRINE, doctrine = tool_doctrine(mcp_on),
                    body = ag.user.replace("{target}", &target).replace("{recon_json}", &recon),
                );
                match pool.complete_routed(Task::Exploit, &ag.system, &user).await {
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
    let findings = validate(candidates, pool, VOTE_SYS, cfg.vote_n, &tx).await;
    finish(cfg, lib, recon, transcript, findings, selected, &mut rl, tx).await
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
    match pool.complete_routed(Task::Select, SELECT_SYS, &user).await {
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
                    "Finding: {} | severity {} | {} | at {} | payload {} | evidence {}",
                    f.title, f.severity, f.cwe, f.endpoint, f.payload, f.evidence
                );
                let (yes, total) = pool.vote(sys, &q, vote_n, finder.as_deref()).await;
                f.validated = total > 0 && yes * 2 >= total;
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

async fn finish(cfg: RunConfig, _lib: &Library, recon: String, transcript: String, findings: Vec<Finding>,
                selected: Vec<Agent>, rl: &mut RlState, tx: Sender<String>) -> RunOutput {
    let _ = tx.send(format!("{} validated finding(s)", findings.len())).await;

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
        let _ = tx.send(format!("artifacts saved: {}", artifacts.join(", "))).await;
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
    v.into_iter()
        .filter(|f| {
            let key = format!("{}|{}|{}", f.cwe.to_lowercase(), f.endpoint.to_lowercase(),
                f.title.to_lowercase().chars().take(40).collect::<String>());
            seen.insert(key)
        })
        .collect()
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
            out.push_str(&format!("\n// ===== file: {} =====\n{}\n", rel, &content[..take]));
            files += 1;
        }
    }
    out
}
