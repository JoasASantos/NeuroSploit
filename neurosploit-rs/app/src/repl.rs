//! NeuroSploit v3.5.0 — interactive session (Claude-Code / Codex / Cursor-CLI style).
//!
//! Launched when `neurosploit` runs with no subcommand. A persistent REPL where
//! you pick models, set an API key (or use a subscription login), point at a URL
//! or a repo, configure authentication, and write free-text instructions that
//! steer which agents run and how — e.g. "find injection and broken access
//! control". `/run` then executes the engagement with that configuration.

use harness::{agents, types::Finding, types::RunConfig};
use std::io::Write;
use std::path::Path;

/// A run completed within this interactive session (for /runs, /results, /report).
struct RunRecord {
    id: usize,
    mode: String,
    target: String,
    workdir: String,
    findings: Vec<Finding>,
}

/// Mutable session state edited via slash-commands and consumed by `/run`.
struct Session {
    models: Vec<String>,
    subscription: bool,
    mcp: bool,
    vote_n: usize,
    max_agents: usize,
    offline: bool,
    target: Option<String>,
    repo: Option<String>,
    auth: Option<String>,
    creds: Option<String>,
    instructions: Option<String>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            models: vec!["anthropic:claude-opus-4-8".into()],
            subscription: harness::installed_cli_backends().contains(&"claude"),
            mcp: false,
            vote_n: 3,
            max_agents: 0,
            offline: false,
            target: None,
            repo: None,
            auth: None,
            creds: None,
            instructions: None,
        }
    }
}

const PROMPT: &str = "\x1b[35mneurosploit›\x1b[0m ";

pub async fn repl(base: &Path) -> anyhow::Result<()> {
    let lib = agents::load(base);
    let backends = harness::installed_cli_backends();
    println!("\x1b[1m");
    println!("  ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗");
    println!("  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit v3.5.0");
    println!("  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   interactive harness");
    println!("  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos");
    println!("  ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders");
    println!("  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝\x1b[0m");
    println!("  {} agents loaded · detected logins: {}", lib.total(),
        if backends.is_empty() { "none (use API keys)".into() } else { backends.join(", ") });
    println!("  Type \x1b[36m/help\x1b[0m to get started, \x1b[36m/run\x1b[0m to launch, \x1b[36m/quit\x1b[0m to exit.\n");

    let mut s = Session::default();
    let mut history: Vec<RunRecord> = Vec::new();
    show(&s);

    let stdin = std::io::stdin();
    loop {
        print!("{PROMPT}");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            println!();
            break; // EOF (Ctrl-D)
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A bare line that isn't a command is treated as test instructions.
        if !line.starts_with('/') {
            s.instructions = Some(line.to_string());
            println!("  focus set: {line}");
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let cmd = parts.next().unwrap_or("");
        let arg = parts.next().unwrap_or("").trim();
        match cmd {
            "/help" | "/?" => help(),
            "/show" | "/config" => show(&s),
            "/providers" => {
                for p in harness::providers() {
                    println!("  [{}] {:<14} {}", p.kind, p.key,
                        p.models.iter().map(|m| format!("{}:{}", p.key, m)).collect::<Vec<_>>().join("  "));
                }
            }
            "/model" | "/models" => {
                if arg.is_empty() {
                    println!("  current: {}", s.models.join(", "));
                } else {
                    s.models = arg.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from).collect();
                    println!("  models: {}", s.models.join(", "));
                }
            }
            "/key" => {
                // /key <PROVIDER> <KEY>  → sets the provider's env var for this session
                let mut kp = arg.splitn(2, char::is_whitespace);
                match (kp.next(), kp.next()) {
                    (Some(prov), Some(key)) if !key.trim().is_empty() => {
                        match harness::provider_for(prov) {
                            Some(p) => {
                                std::env::set_var(p.env_key, key.trim());
                                s.subscription = false;
                                println!("  set {} (API mode)", p.env_key);
                            }
                            None => println!("  unknown provider '{prov}' (see /providers)"),
                        }
                    }
                    _ => println!("  usage: /key <provider> <api-key>   e.g. /key anthropic sk-ant-..."),
                }
            }
            "/sub" | "/subscription" => {
                s.subscription = !matches!(arg, "off" | "false" | "0" | "no");
                println!("  subscription: {}", onoff(s.subscription));
            }
            "/target" | "/url" => {
                // target + repo can coexist → greybox.
                let t = if arg.starts_with("http") || arg.is_empty() { arg.to_string() } else { format!("https://{arg}") };
                s.target = if t.is_empty() { None } else { Some(t) };
                println!("  target: {}", s.target.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/repo" => {
                s.repo = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  repo: {}", s.repo.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/auth" => {
                s.auth = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  auth: {}", s.auth.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/creds" => {
                s.creds = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  creds file: {}", s.creds.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/focus" | "/instructions" => {
                s.instructions = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  focus: {}", s.instructions.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/mcp" => {
                s.mcp = !matches!(arg, "off" | "false" | "0" | "no");
                println!("  Playwright MCP: {}", onoff(s.mcp));
            }
            "/offline" => {
                s.offline = !matches!(arg, "off" | "false" | "0" | "no");
                println!("  offline (pipeline self-test): {}", onoff(s.offline));
            }
            "/votes" => { s.vote_n = arg.parse().unwrap_or(s.vote_n); println!("  votes: {}", s.vote_n); }
            "/agents" => { s.max_agents = arg.parse().unwrap_or(s.max_agents); println!("  max agents: {} ", s.max_agents); }
            "/clear" => { print!("\x1b[2J\x1b[H"); }
            "/run" | "/go" => run(base, &s, &mut history).await,
            "/runs" | "/history" => list_runs(&history),
            "/results" => results(&history, arg),
            "/report" => open_report(&history, arg),
            "/status" => run_status(&history, arg),
            "/quit" | "/exit" | "/q" => { println!("  bye."); break; }
            other => println!("  unknown command '{other}' — try /help"),
        }
    }
    Ok(())
}

async fn run(base: &Path, s: &Session, history: &mut Vec<RunRecord>) {
    // repo + target → greybox; repo only → whitebox; target only → black-box.
    enum M { Black(String), White(String), Grey { url: String, repo: String } }
    let m = match (&s.repo, &s.target) {
        (Some(r), Some(t)) => M::Grey { url: t.clone(), repo: r.clone() },
        (Some(r), None) => M::White(r.clone()),
        (None, Some(t)) => M::Black(t.clone()),
        _ => {
            println!("  \x1b[31m✗ set a /target <url> and/or /repo <path> first.\x1b[0m");
            return;
        }
    };
    let primary = match &m {
        M::Black(t) | M::White(t) => t.clone(),
        M::Grey { url, .. } => url.clone(),
    };
    let mut cfg = RunConfig::new(&primary);
    cfg.models = s.models.clone();
    cfg.subscription = s.subscription;
    cfg.vote_n = s.vote_n;
    cfg.max_agents = s.max_agents;
    cfg.verbose = true;
    cfg.offline = s.offline;
    cfg.instructions = s.instructions.clone();
    cfg.auth = s.auth.clone();
    if let M::Grey { repo, .. } = &m {
        cfg.repo = Some(repo.clone());
    }
    crate::apply_creds(&mut cfg, s.creds.as_deref()).await;

    let mode = match &m {
        M::Grey { .. } => "greybox",
        M::White(_) => "white-box",
        M::Black(_) => "black-box",
    };
    let result = match m {
        M::Grey { .. } => crate::run_greybox_engagement(base, cfg, s.mcp).await,
        M::White(_) => crate::run_engagement(base, cfg, false, true).await,
        M::Black(_) => crate::run_engagement(base, cfg, s.mcp, false).await,
    };
    match result {
        Ok(out) => {
            crate::print_findings(&out);
            let id = history.len() + 1;
            println!("  ↳ saved as run #{id} — /results {id} · /report {id} · /status {id}");
            history.push(RunRecord {
                id, mode: mode.into(), target: primary,
                workdir: out.workdir.clone(), findings: out.findings.clone(),
            });
        }
        Err(e) => println!("  \x1b[31m✗ run failed: {e}\x1b[0m"),
    }
}

/// Resolve a run by 1-based index argument; default = most recent.
fn pick<'a>(history: &'a [RunRecord], arg: &str) -> Option<&'a RunRecord> {
    if history.is_empty() {
        println!("  no runs yet this session — /run first.");
        return None;
    }
    if arg.trim().is_empty() {
        return history.last();
    }
    match arg.trim().parse::<usize>() {
        Ok(n) => history.iter().find(|r| r.id == n).or_else(|| {
            println!("  no run #{n} (have 1..{})", history.len()); None
        }),
        Err(_) => { println!("  usage: with a run number, e.g. /results 2"); None }
    }
}

fn sev_counts(f: &[Finding]) -> std::collections::BTreeMap<&str, usize> {
    let mut m = std::collections::BTreeMap::new();
    for x in f { *m.entry(x.severity.as_str()).or_insert(0) += 1; }
    m
}

fn list_runs(history: &[RunRecord]) {
    if history.is_empty() { println!("  no runs yet this session."); return; }
    println!("  ┌─ session runs");
    for r in history {
        let c = sev_counts(&r.findings);
        let sev = if c.is_empty() { "0 findings".to_string() }
                  else { c.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
        println!("  │  #{:<2} {:<9} {:<40} {}", r.id, r.mode, trunc(&r.target, 40), sev);
    }
    println!("  └─ /results <n> · /report <n> · /status <n>");
}

fn results(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    println!("  ── run #{} ({}) — {} ──", r.id, r.mode, r.target);
    if r.findings.is_empty() {
        println!("  (no validated findings)");
        return;
    }
    let mut f = r.findings.clone();
    f.sort_by_key(|x| match x.severity.as_str() {
        "Critical" => 0, "High" => 1, "Medium" => 2, "Low" => 3, _ => 4,
    });
    for x in &f {
        println!("  • [{}] {}", x.severity, x.title);
        println!("      {} · {} · votes {} · conf {:.2}", x.agent, x.cwe, x.votes, x.confidence);
        if !x.endpoint.is_empty() { println!("      @ {}", x.endpoint); }
    }
    println!("  report: /report {}", r.id);
}

fn open_report(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    let dir = Path::new(&r.workdir);
    let pdf = dir.join("report.pdf");
    let html = dir.join("report.html");
    let file = if pdf.is_file() { pdf } else { html };
    if !file.is_file() {
        println!("  no report file in {}", r.workdir);
        return;
    }
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    match std::process::Command::new(opener).arg(&file).spawn() {
        Ok(_) => println!("  opening {}", file.display()),
        Err(_) => println!("  report: {}", file.display()),
    }
}

fn run_status(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    let sp = Path::new(&r.workdir).join("status.json");
    match std::fs::read_to_string(&sp) {
        Ok(txt) => println!("  run #{}: {}", r.id, txt.trim()),
        Err(_) => println!("  run #{}: no status.json ({})", r.id, r.workdir),
    }
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n.saturating_sub(1)]) }
}

fn show(s: &Session) {
    println!("  ┌─ session");
    println!("  │  models   : {}", s.models.join(", "));
    println!("  │  auth mode: {}", if s.subscription { "subscription (CLI login)" } else { "API key" });
    let mode = match (&s.repo, &s.target) {
        (Some(_), Some(_)) => "greybox (code + live)",
        (Some(_), None) => "white-box (code)",
        (None, Some(_)) => "black-box (live)",
        _ => "(set /target and/or /repo)",
    };
    println!("  │  mode     : {mode}");
    println!("  │  target   : {}", s.target.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  repo     : {}", s.repo.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  auth     : {}", s.auth.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  creds    : {}", s.creds.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  focus    : {}", s.instructions.clone().unwrap_or_else(|| "(none — tests everything)".into()));
    println!("  │  mcp      : {}  votes: {}  max-agents: {}", onoff(s.mcp), s.vote_n, s.max_agents);
    println!("  └─ /run to launch");
}

fn help() {
    println!("  Commands:");
    println!("    /model a:b[,c:d]   set model panel (1st primary; rest fail over + vote)");
    println!("    /providers          list providers & models");
    println!("    /key <prov> <key>   set a provider API key (switches to API mode)");
    println!("    /sub on|off         use local subscription login instead of API key");
    println!("    /target <url>       black-box target URL");
    println!("    /repo <path>        analyse a local repo (repo+target = greybox: code + live)");
    println!("    /auth <value>       auth to send (e.g. 'Authorization: Bearer <jwt>' or 'Cookie: s=..')");
    println!("    /creds <file.yaml>  load credentials (jwt/header/cookie/login) for authenticated tests");
    println!("    /focus <text>       steer the tests, e.g. 'injection and broken access control'");
    println!("                        (or just type the instruction with no slash)");
    println!("    /mcp on|off         enable Playwright MCP browser (subscription path)");
    println!("    /offline on|off     pipeline self-test (no model calls)");
    println!("    /votes <n>          validator votes per finding");
    println!("    /agents <n>         cap agents (0 = all matching)");
    println!("    /show               show current session config");
    println!("    /run                launch the engagement");
    println!("    /runs               list runs done this session (history)");
    println!("    /results [n]        show findings of run n (default: last)");
    println!("    /report [n]         open the PDF/HTML report of run n");
    println!("    /status [n]         show status.json of run n");
    println!("    /quit               exit");
    println!();
    println!("  Example:");
    println!("    /model anthropic:claude-opus-4-8");
    println!("    /target http://testphp.vulnweb.com/");
    println!("    find injection and broken access control");
    println!("    /run");
}

fn onoff(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}
