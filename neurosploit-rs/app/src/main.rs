//! NeuroSploit v3.5.1 — interactive harness + CLI (`run` / `whitebox` / `agents` / `models`).

mod repl;
mod tui;

use clap::{Parser, Subcommand};
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig, RunOutput};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "neurosploit",
    version,
    about = "NeuroSploit v3.5.1 — multi-model autonomous pentest harness",
    long_about = "NeuroSploit v3.5.1 — a Rust multi-model harness that drives a pool of LLMs \
(API key or local subscription: Claude/Codex/Gemini/Grok) to autonomously test a target. \
After recon it INTELLIGENTLY selects only the agents matching the discovered surface, runs \
them in parallel, then validates every finding by cross-model voting before reporting.\n\n\
Run with NO arguments for an interactive wizard.\n\n\
EXAMPLES:\n  \
# Black-box against a known test site (subscription, Opus, browser via Playwright if present)\n  \
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp -v\n\n  \
# Black-box via API keys with a multi-model voting panel\n  \
neurosploit run http://testphp.vulnweb.com/ --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3\n\n  \
# White-box source review of a cloned repo (DVWA)\n  \
git clone https://github.com/digininja/DVWA /tmp/DVWA\n  \
neurosploit whitebox /tmp/DVWA --subscription --model anthropic:claude-opus-4-8 -v\n\n  \
# Offline pipeline self-test (no keys/login)\n  \
neurosploit run http://testphp.vulnweb.com/ --offline\n\n\
TIP: run inside Kali Linux (or `docker run -it kalilinux/kali-rolling`) so curl/nmap/rustscan/ffuf are available."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Black-box: recon → intelligent agent selection → exploit → vote → report.
    Run {
        url: String,
        /// Models as provider:model (repeatable). First is primary; rest fail over + vote.
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        /// Use local agentic CLI subscription (Claude/Codex/Gemini/Grok login).
        #[arg(long)]
        subscription: bool,
        /// Enable Playwright MCP (auto-installed if missing; backends that don't
        /// support MCP fall back to their built-in tools).
        #[arg(long)]
        mcp: bool,
        /// Credentials YAML for authenticated testing (jwt/header/cookie/login).
        #[arg(long)]
        creds: Option<String>,
        /// Free-text focus, e.g. "injection and broken access control".
        #[arg(long)]
        focus: Option<String>,
        /// Verbose: log each agent as it launches, recon, and votes.
        #[arg(short, long)]
        verbose: bool,
    },
    /// White-box: analyse a local repository's source code for vulnerabilities.
    Whitebox {
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Greybox: review a repo's source AND exploit the running app together.
    Greybox {
        /// Path to the source repository.
        repo: String,
        /// URL of the running application.
        #[arg(long)]
        url: String,
        #[arg(long = "model")]
        models: Vec<String>,
        /// Credentials YAML for authenticated testing (jwt/header/cookie/login).
        #[arg(long)]
        creds: Option<String>,
        /// Free-text focus, e.g. "injection and broken access control".
        #[arg(long)]
        focus: Option<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(long)]
        mcp: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Mission Control TUI: concurrent panels (header/feed/findings/targets) with
    /// a composer active during the run. Black-box (URL) or, with --repo, greybox.
    Tui {
        url: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        creds: Option<String>,
        #[arg(long)]
        focus: Option<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        subscription: bool,
        #[arg(long)]
        mcp: bool,
    },
    /// Infra/host: scan an IP/host and run Linux/Windows/AD agents. SSH/Windows
    /// credentials come from --creds (creds.yaml ssh:/windows: blocks).
    Host {
        /// Target host or IP.
        target: String,
        #[arg(long = "model")]
        models: Vec<String>,
        /// Credentials YAML (ssh / windows / ad blocks).
        #[arg(long)]
        creds: Option<String>,
        #[arg(long)]
        focus: Option<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show agent library counts.
    Agents,
    /// List providers and models.
    Models,
}

/// Locate the repo root that holds `agents_md/`.
fn find_base() -> PathBuf {
    if let Ok(b) = std::env::var("NEUROSPLOIT_BASE") {
        return PathBuf::from(b);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        for _ in 0..6 {
            if dir.join("agents_md").is_dir() {
                return dir.to_path_buf();
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base = find_base();

    // No subcommand → launch the Claude-Code-style interactive session.
    let cmd = match cli.cmd {
        Some(c) => c,
        None => {
            repl::repl(&base).await?;
            return Ok(());
        }
    };

    match cmd {
        Cmd::Agents => {
            let lib = agents::load(&base);
            println!(
                "{{\"vulns\":{},\"recon\":{},\"code\":{},\"infra\":{},\"chains\":{},\"meta\":{},\"total\":{}}}",
                lib.vulns.len(), lib.recon.len(), lib.code.len(), lib.infra.len(), lib.chains.len(), lib.meta.len(), lib.total()
            );
        }
        Cmd::Models => {
            for p in harness::providers() {
                println!("{:<4} {:<14} {} models  [{}]", p.kind, p.key, p.models.len(), p.label);
                for m in &p.models {
                    println!("      {}:{}", p.key, m);
                }
            }
        }
        Cmd::Run { url, models, max_agents, vote_n, offline, subscription, mcp, creds, focus, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let out = run_engagement(&base, cfg, mcp, false).await?;
            print_findings(&out);
        }
        Cmd::Whitebox { path, models, max_agents, vote_n, offline, subscription, verbose } => {
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
        }
        Cmd::Greybox { repo, url, models, creds, focus, max_agents, vote_n, offline, subscription, mcp, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.repo = Some(repo);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let out = run_greybox_engagement(&base, cfg, mcp).await?;
            print_findings(&out);
        }
        Cmd::Tui { url, models, repo, creds, focus, max_agents, vote_n, subscription, mcp } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.subscription = subscription;
            cfg.instructions = focus;
            cfg.repo = repo.clone();
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let mode = if repo.is_some() { Mode::Grey } else { Mode::Black };
            tui::run(&base, cfg, mcp, mode).await?;
        }
        Cmd::Host { target, models, creds, focus, max_agents, vote_n, offline, subscription, verbose } => {
            let mut cfg = RunConfig::new(&target);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let out = run_mode(&base, cfg, false, Mode::Host).await?;
            print_findings(&out);
        }
    }
    Ok(())
}

// Helpers the TUI module reuses.
pub(crate) fn now_ts_pub() -> u64 { now_ts() }
pub(crate) fn sanitize_pub(s: &str) -> String { sanitize(s) }
pub(crate) fn write_status_pub(workdir: &Path, state: &str, extra: &str) { write_status(workdir, state, extra); }

/// Load a creds.yaml into the run config. Direct material (jwt/header/cookie) is
/// used as-is; a `login:` flow is EXECUTED now (real HTTP) to capture a live
/// session cookie/token. If the auto-login fails, fall back to instructing the
/// agents to authenticate themselves.
pub(crate) async fn apply_creds(cfg: &mut RunConfig, path: Option<&str>) {
    let Some(p) = path else { return };
    let Some(c) = harness::creds::Creds::load(Path::new(p)) else {
        eprintln!("  [!] no usable credentials in {p}");
        return;
    };
    println!("  [*] loaded credentials from {p}");
    if cfg.auth.is_none() {
        cfg.auth = c.auth_header();
    }
    // Host credentials (SSH / Windows-AD) → tell the agents how to authenticate
    // to the host so they can run on-host enumeration / privesc / AD checks.
    if let Some(hi) = c.host_instruction() {
        let base = cfg.instructions.clone().unwrap_or_default();
        cfg.instructions = Some(format!("{hi}\n{base}"));
        println!("  [*] host credentials loaded (SSH/Windows-AD)");
    }
    // No direct material but a login flow → perform it now.
    if cfg.auth.is_none() {
        if let Some(login) = &c.login {
            println!("  [*] auto-login: {} {} ...", login.method, login.url);
            match harness::creds::login(login).await {
                Ok((auth, note)) => {
                    println!("  [*] authenticated — {note}");
                    cfg.auth = Some(auth);
                }
                Err(e) => {
                    eprintln!("  [!] auto-login failed ({e}); agents will attempt to log in themselves");
                    if let Some(instr) = c.login_instruction() {
                        let base = cfg.instructions.clone().unwrap_or_default();
                        cfg.instructions = Some(format!("{instr}\n{base}"));
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mode { Black, White, Grey, Host }

pub(crate) async fn run_greybox_engagement(base: &Path, cfg: RunConfig, mcp: bool) -> anyhow::Result<RunOutput> {
    run_mode(base, cfg, mcp, Mode::Grey).await
}

/// Shared engagement runner for `run` / `whitebox` / the interactive session.
pub(crate) async fn run_engagement(base: &Path, cfg: RunConfig, mcp: bool, whitebox: bool) -> anyhow::Result<RunOutput> {
    run_mode(base, cfg, mcp, if whitebox { Mode::White } else { Mode::Black }).await
}

/// A spawned engagement: the running task, its live event stream, a cancel
/// handle, and the run's output dir. Lets callers drive it blocking (run_mode)
/// or in the background (the REPL), and finalize with `finalize_run`.
pub(crate) struct Spawned {
    pub task: tokio::task::JoinHandle<RunOutput>,
    pub rx: tokio::sync::mpsc::Receiver<String>,
    pub cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub soft: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub workdir: PathBuf,
}

/// Set up + start an engagement (synchronous setup; the work runs in the task).
pub(crate) fn spawn_engagement(base: &Path, mut cfg: RunConfig, mcp: bool, mode: Mode) -> Spawned {
    let lib = agents::load(base);
    let run_id = format!("ns-{}-{}", now_ts(), sanitize(&cfg.target));
    let workdir = base.join("runs").join(&run_id);
    std::fs::create_dir_all(&workdir).ok();
    cfg.workdir = Some(workdir.display().to_string());
    cfg.rl_path = Some(base.join("data").join("rl_state_rs.json").display().to_string());
    write_status(&workdir, "running", &format!("\"target\":{:?}", cfg.target));

    println!("  ┌─ NeuroSploit v3.5.1  ·  by Joas A Santos & Red Team Leaders");
    println!("  │  run id : {run_id}");
    println!("  │  target : {}", cfg.target);
    println!("  │  models : {}", cfg.models.join(", "));
    println!("  │  output : {}", workdir.display());
    if let Mode::Grey = mode {
        println!("  │  repo   : {}", cfg.repo.clone().unwrap_or_default());
    }
    println!("  └─ mode   : {}{}{}",
        match mode { Mode::White => "white-box", Mode::Grey => "greybox", Mode::Host => "host/infra", Mode::Black => "black-box" },
        if cfg.subscription { " · subscription" } else { " · api" },
        if mcp { " · mcp" } else { "" });

    let mcp_config = if mcp && cfg.subscription {
        let providers: Vec<String> = cfg.models.iter().map(|m| ModelRef::parse(m).provider).collect();
        if providers.iter().any(|p| harness::mcp_supported(p)) {
            match harness::ensure_playwright_mcp() {
                Ok(()) => {
                    let extra = base.join("mcp.servers.json");
                    let extra_ref = if extra.is_file() { Some(extra.as_path()) } else { None };
                    match harness::write_mcp_config(&workdir, extra_ref) {
                        Ok(p) => { println!("  [*] Playwright MCP ready → {}", p.display()); Some(p.display().to_string()) }
                        Err(e) => { eprintln!("  [!] MCP config failed: {e}"); None }
                    }
                }
                Err(e) => { eprintln!("  [!] Playwright MCP unavailable ({e}); using built-in tools"); None }
            }
        } else {
            eprintln!("  [!] selected backend(s) don't support MCP; using built-in tools");
            None
        }
    } else { None };

    let refs: Vec<ModelRef> = cfg.models.iter().map(|s| ModelRef::parse(s)).collect();
    let pool = ModelPool::with_auth(refs, cfg.concurrency, cfg.subscription, mcp_config);
    let cancel = pool.cancel_handle();
    let soft = pool.soft_handle();
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(256);
    let task = tokio::spawn(async move {
        match mode {
            Mode::White => harness::run_whitebox(cfg, &lib, &pool, tx).await,
            Mode::Grey => harness::run_greybox(cfg, &lib, &pool, tx).await,
            Mode::Host => harness::run_host(cfg, &lib, &pool, tx).await,
            Mode::Black => harness::run(cfg, &lib, &pool, tx).await,
        }
    });
    Spawned { task, rx, cancel, soft, workdir }
}

/// Absolute file:// URL of a run's report (PDF if present, else HTML).
pub(crate) fn report_url(workdir: &Path) -> String {
    let pdf = workdir.join("report.pdf");
    let f = if pdf.is_file() { pdf } else { workdir.join("report.html") };
    let abs = f.canonicalize().unwrap_or(f);
    format!("file://{}", abs.display())
}

/// Generate a report directly from raw (unvalidated) findings — used by the REPL
/// when the user chooses "report without validating" on /stop.
pub(crate) fn report_raw(target: &str, findings: &[harness::types::Finding], workdir: &Path) {
    let mut fs = findings.to_vec();
    harness::attack_graph::enrich(&mut fs);
    std::fs::write(workdir.join("findings.json"), serde_json::to_string_pretty(&fs).unwrap_or_default()).ok();
    let _ = harness::report::typst_report(target, &fs, workdir);
    write_status(workdir, "stopped-raw", &format!("\"findings\":{}", fs.len()));
}

/// Generate the report + final status for a finished run, ensuring the workdir
/// is always recorded (even on an aborted/partial run).
pub(crate) fn finalize_run(mut out: RunOutput, workdir: &Path) -> RunOutput {
    if out.workdir.is_empty() { out.workdir = workdir.display().to_string(); }
    if out.target.is_empty() {
        out.target = workdir.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    }
    let _ = harness::report::typst_report(&out.target, &out.findings, workdir);
    write_status(workdir, "complete", &format!("\"findings\":{},\"agents_ran\":{}", out.findings.len(), out.agents_ran.len()));
    out
}

async fn run_mode(base: &Path, cfg: RunConfig, mcp: bool, mode: Mode) -> anyhow::Result<RunOutput> {
    let Spawned { mut task, mut rx, cancel, workdir, .. } = spawn_engagement(base, cfg, mcp, mode);
    let printer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await { render_line(&line); }
    });

    let mut cancelled = false;
    let out: RunOutput = tokio::select! {
        r = &mut task => r.unwrap_or_default(),
        _ = tokio::signal::ctrl_c() => {
            cancelled = true;
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            println!("\n  \x1b[33m⏸  stopping — finishing in-flight work… (Ctrl-C again to abort now)\x1b[0m");
            tokio::select! {
                r = &mut task => r.unwrap_or_default(),
                _ = tokio::signal::ctrl_c() => { task.abort(); println!("  \x1b[31m✗ aborted.\x1b[0m"); RunOutput::default() }
            }
        }
    };
    let _ = printer.await;

    // On a graceful stop, ask whether to keep (generate report) or discard.
    if cancelled {
        let keep = ask_yes_no("Generate a report from partial results? [Y/n]");
        if !keep {
            std::fs::remove_dir_all(&workdir).ok();
            write_status(&workdir, "discarded", "");
            println!("  🗑  discarded run {}", workdir.display());
            return Ok(out);
        }
    }

    let out = finalize_run(out, &workdir);
    println!("  ✓ COMPLETE — {} validated finding(s)", out.findings.len());
    println!("  \x1b[36mreport: {}\x1b[0m", report_url(&workdir));
    Ok(out)
}

pub(crate) fn print_findings(out: &RunOutput) {
    println!("\n=== {} validated finding(s) ===", out.findings.len());
    if !out.findings.is_empty() {
        let mut by = std::collections::BTreeMap::new();
        for f in &out.findings { *by.entry(f.severity.as_str()).or_insert(0) += 1; }
        let chips: Vec<String> = by.iter().map(|(k, v)| format!("{k}:{v}")).collect();
        println!("  severity: {}", chips.join("  "));
        println!("\n  \x1b[1mAttack path / kill chain\x1b[0m");
        print!("{}", harness::attack_graph::ascii_killchain(&out.findings));
    }
    let toks = token_summary();
    if !toks.is_empty() {
        println!("\n  {toks}");
    }
    if !out.artifacts.is_empty() {
        println!("  artifacts: {}", out.artifacts.join(", "));
        println!("  (full attack graph rendered in report.html)");
    }
}

fn sanitize(s: &str) -> String {
    let s = s.replace("https://", "").replace("http://", "");
    let mut o: String = s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect();
    o.truncate(40);
    let o = o.trim_matches('_').to_string();
    if o.is_empty() { "target".into() } else { o }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Blocking yes/no prompt (default yes). Used after a graceful Ctrl-C.
fn ask_yes_no(q: &str) -> bool {
    use std::io::Write;
    print!("  {q} ");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    if std::io::stdin().read_line(&mut s).is_err() {
        return true;
    }
    !matches!(s.trim().to_lowercase().as_str(), "n" | "no")
}

// ── Activity-feed renderer ─────────────────────────────────────────────────
// Turns the harness's tagged progress stream into a categorized feed: tool/
// command/file events render as compact cards; everything else as a state line
// with an icon, so it's clear what the AI is doing (no "black box").
const RST: &str = "\x1b[0m";

fn render_line(raw: &str) {
    let mut line = raw.trim_end();
    // Optional "@agent " prefix tags which agent produced the event.
    let mut who = String::new();
    if let Some(stripped) = line.strip_prefix('@') {
        if let Some((label, rest)) = stripped.split_once(' ') {
            who = format!("\x1b[2m[{label}]\x1b[0m ");
            line = rest;
        }
    }
    let (tag, rest) = match line.split_once(": ") {
        Some((t, r)) if matches!(t, "exec" | "danger" | "read" | "edit" | "tool" | "net" | "ai" | "plan" | "tokens" | "notify" | "finding") => (t, r),
        _ => ("", line),
    };
    match tag {
        "notify" => println!("  \x1b[1;36m🔔 {}\x1b[0m", rest.trim()),
        "finding" => println!("  \x1b[1;33m✦ possible finding\x1b[0m {who}{}", rest.trim()),
        "exec" => card(&format!("{who}⌘ command"), rest, "\x1b[33m"),
        "danger" => card(&format!("{who}⚠ DANGEROUS command"), rest, "\x1b[1;31m"),
        "read" => state("📄", "reading", &format!("{who}{rest}"), "\x1b[34m"),
        "edit" => state("✏️", "editing", &format!("{who}{rest}"), "\x1b[35m"),
        "net" => card(&format!("{who}🌐 request"), rest, "\x1b[36m"),
        "tool" => state("🔧", "tool", &format!("{who}{rest}"), "\x1b[35m"),
        "tokens" => { track_tokens(rest); state("🪙", "tokens", &format!("{who}{rest}"), "\x1b[2;33m"); }
        "ai" => state("💬", "", &format!("{who}{rest}"), "\x1b[2m"),
        "plan" => state("🧭", "plan", &format!("{who}{rest}"), "\x1b[36m"),
        _ => render_untagged(line),
    }
}

/// One-line styled rendering of a stream event — used by the background REPL run
/// (via rustyline's external printer) where multi-line cards would fight the
/// prompt. Returns None for events that shouldn't clutter the background feed.
pub(crate) fn render_compact(raw: &str) -> Option<String> {
    let mut line = raw.trim_end();
    let mut who = String::new();
    if let Some(stripped) = line.strip_prefix('@') {
        if let Some((label, rest)) = stripped.split_once(' ') { who = format!("[{label}] "); line = rest; }
    }
    let (tag, rest) = line.split_once(": ").unwrap_or(("", line));
    if tag == "finding_json" { return None; } // captured for /results & /finding, not shown
    let s = match tag {
        "exec" | "danger" => format!("\x1b[33m  ⌘ {who}{}\x1b[0m", trunc1(rest, 110)),
        "net" => format!("\x1b[36m  🌐 {who}{}\x1b[0m", trunc1(rest, 110)),
        "read" => format!("\x1b[34m  📄 {who}{}\x1b[0m", rest),
        "tokens" => { track_tokens(rest); return None; } // counted, shown in /status
        // Candidate finding — color by severity (not all-yellow).
        "finding" => {
            let sev = rest.strip_prefix('[').and_then(|b| b.split_once(']')).map(|(s, _)| s).unwrap_or("");
            format!("  {}✦ {who}{}\x1b[0m", sev_color(sev), rest)
        }
        "notify" => format!("\x1b[1;36m  🔔 {}\x1b[0m", rest),
        "ai" => return None, // skip verbose model chatter in background feed
        _ => {
            let low = line.to_lowercase();
            if low.contains("recon complete") { "\x1b[36m  🔍 recon complete\x1b[0m".into() }
            else if low.contains("selected") && low.contains("agent") { format!("\x1b[36m  🧭 {}\x1b[0m", trunc1(line, 110)) }
            else if low.starts_with("vote") && low.contains("confirmed") { format!("\x1b[1;32m  ✓ {}\x1b[0m", trunc1(line, 110)) }
            else if low.starts_with("exploit") || low.starts_with("test ") || low.contains("launching agent") { format!("\x1b[35m  🧪 {}\x1b[0m", trunc1(line, 110)) }
            else if low.starts_with("vote") { format!("\x1b[2m  · {}\x1b[0m", trunc1(line, 110)) }
            else if low.contains("fail") || low.contains("error") { format!("\x1b[31m  ✗ {}\x1b[0m", trunc1(line, 110)) }
            else { return None; }
        }
    };
    Some(s)
}

/// ANSI color per severity — so confirmed/critical findings stand out instead of
/// everything being yellow.
fn sev_color(sev: &str) -> &'static str {
    match sev.trim() {
        "Critical" => "\x1b[1;31m",  // bold red
        "High"     => "\x1b[38;5;208m", // orange
        "Medium"   => "\x1b[33m",     // yellow
        "Low"      => "\x1b[36m",     // cyan
        _          => "\x1b[37m",     // info/grey
    }
}

fn trunc1(s: &str, n: usize) -> String {
    let one = s.replace('\n', " ");
    if one.chars().count() <= n { one } else { format!("{}…", one.chars().take(n).collect::<String>()) }
}

// Running token/cost total across the engagement (shown in the summary).
static TOK_IN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TOK_OUT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COST_MILLI: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn track_tokens(rest: &str) {
    use std::sync::atomic::Ordering::Relaxed;
    // parse "in=N out=M cost=$X.XXXX"
    for part in rest.split_whitespace() {
        if let Some(v) = part.strip_prefix("in=") { TOK_IN.fetch_add(v.parse().unwrap_or(0), Relaxed); }
        else if let Some(v) = part.strip_prefix("out=") { TOK_OUT.fetch_add(v.parse().unwrap_or(0), Relaxed); }
        else if let Some(v) = part.strip_prefix("cost=$") {
            COST_MILLI.fetch_add((v.parse::<f64>().unwrap_or(0.0) * 1000.0) as u64, Relaxed);
        }
    }
}

/// Render and reset the running token/cost total (called at end of a run).
pub(crate) fn token_summary() -> String {
    use std::sync::atomic::Ordering::Relaxed;
    let i = TOK_IN.swap(0, Relaxed);
    let o = TOK_OUT.swap(0, Relaxed);
    let c = COST_MILLI.swap(0, Relaxed) as f64 / 1000.0;
    if i == 0 && o == 0 && c == 0.0 { return String::new(); }
    format!("🪙 tokens: in={i} out={o} · est. cost ${c:.4}")
}

fn render_untagged(l: &str) {
    let low = l.to_lowercase();
    if l.starts_with("===") {
        println!("\n\x1b[1;35m▌ {}\x1b[0m", l.trim_matches('=').trim());
    } else if low.contains("✓ complete") || low.contains("validated finding(s)") {
        println!("  \x1b[1;32m✓\x1b[0m {l}");
    } else if low.starts_with("recon") {
        state("🔍", "reconning", l.trim_start_matches("recon").trim_start_matches(' '), "\x1b[36m");
    } else if low.contains("selected") || low.contains("agent selection") || low.contains("heuristic") {
        state("🧭", "planning", l, "\x1b[36m");
    } else if low.starts_with("exploit") || low.starts_with("analyze") || low.contains("launching agent") || low.starts_with("review ") {
        state("🧪", "testing", l, "\x1b[35m");
    } else if low.starts_with("vote") {
        if low.contains("confirmed") { state("✓", "validated", l, "\x1b[32m"); }
        else { state("·", "rejected", l, "\x1b[2m"); }
    } else if low.starts_with("chain") {
        state("🔗", "chaining", l, "\x1b[36m");
    } else if low.contains("report") {
        state("📄", "report", l, "\x1b[34m");
    } else if low.contains("fail") || low.contains("error") || low.starts_with('✗') {
        println!("  \x1b[31m✗\x1b[0m {l}");
    } else {
        println!("  \x1b[2m·\x1b[0m {l}");
    }
}

fn state(icon: &str, kind: &str, msg: &str, color: &str) {
    let k = if kind.is_empty() { String::new() } else { format!("{color}{kind}{RST} ") };
    println!("  {icon} {k}{}", msg.trim());
}

/// Compact card for a tool the AI ran (the "tool runner visual").
fn card(title: &str, body: &str, color: &str) {
    let body = body.trim();
    let width = body.chars().count().min(72);
    let bar = "─".repeat(width.max(title.chars().count()) + 2);
    println!("  {color}╭─ {title} {}{RST}", "─".repeat(bar.len().saturating_sub(title.chars().count() + 3)));
    for chunk in wrap(body, 72) {
        println!("  {color}│{RST} {chunk}");
    }
    println!("  {color}╰{}{RST}", bar);
}

fn wrap(s: &str, w: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        if cur.chars().count() + word.chars().count() + 1 > w && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() { cur.push(' '); }
        cur.push_str(word);
    }
    if !cur.is_empty() { out.push(cur); }
    if out.is_empty() { out.push(String::new()); }
    out
}

fn write_status(workdir: &Path, state: &str, extra: &str) {
    let p = workdir.join("status.json");
    let _ = std::fs::write(&p, format!("{{\"state\":\"{state}\",\"ts\":{}{}}}", now_ts(),
        if extra.is_empty() { String::new() } else { format!(",{extra}") }));
}

