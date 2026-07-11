//! NeuroSploit v3.6.3 — interactive harness + CLI (`run` / `whitebox` / `agents` / `models`).

mod repl;
mod tui;

use clap::{Parser, Subcommand};
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig, RunOutput};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "neurosploit",
    version,
    about = "NeuroSploit v3.6.3 — multi-model autonomous pentest harness",
    long_about = "NeuroSploit v3.6.3 — a Rust multi-model harness that drives a pool of LLMs \
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
        /// Attack-chaining rounds (post-exploitation pivots; 0 disables).
        #[arg(long, default_value_t = 2)]
        chain_depth: usize,
        /// Recon intensity 1-4 (1 quick .. 4 exhaustive; installs tools).
        #[arg(long, default_value_t = 3)]
        recon: usize,
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
        /// Open a Jira card per finding (needs the jira integration enabled).
        #[arg(long)]
        jira: bool,
        /// Verbose: log each agent as it launches, recon, and votes.
        #[arg(short, long)]
        verbose: bool,
    },
    /// White-box: analyse a repository's source code for vulnerabilities.
    Whitebox {
        /// Local path, a GitHub URL (https://github.com/owner/repo[.git]) or an
        /// `owner/repo` shorthand — git URLs are cloned automatically.
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        /// Attack-chaining rounds (post-exploitation pivots; 0 disables).
        #[arg(long, default_value_t = 2)]
        chain_depth: usize,
        /// Recon intensity 1-4 (1 quick .. 4 exhaustive; installs tools).
        #[arg(long, default_value_t = 3)]
        recon: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        /// Open a Jira card per finding (needs the jira integration enabled).
        #[arg(long)]
        jira: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Greybox: review a repo's source AND exploit the running app together.
    Greybox {
        /// Source repo: local path, a GitHub URL, or `owner/repo` (cloned if a URL).
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
        /// Attack-chaining rounds (post-exploitation pivots; 0 disables).
        #[arg(long, default_value_t = 2)]
        chain_depth: usize,
        /// Recon intensity 1-4 (1 quick .. 4 exhaustive; installs tools).
        #[arg(long, default_value_t = 3)]
        recon: usize,
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
        /// Attack-chaining rounds (post-exploitation pivots; 0 disables).
        #[arg(long, default_value_t = 2)]
        chain_depth: usize,
        /// Recon intensity 1-4 (1 quick .. 4 exhaustive; installs tools).
        #[arg(long, default_value_t = 3)]
        recon: usize,
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
        /// Attack-chaining rounds (post-exploitation pivots; 0 disables).
        #[arg(long, default_value_t = 2)]
        chain_depth: usize,
        /// Recon intensity 1-4 (1 quick .. 4 exhaustive; installs tools).
        #[arg(long, default_value_t = 3)]
        recon: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// AI/LLM: red-team a live AI agent / LLM app / MCP endpoint (OWASP LLM Top 10 + MCP risks).
    Aitest {
        /// URL of the AI agent / LLM chat or API endpoint.
        url: String,
        #[arg(long = "model")]
        models: Vec<String>,
        /// Auth header for the AI endpoint (e.g. 'Authorization: Bearer <key>').
        #[arg(long)]
        auth: Option<String>,
        /// Free-text focus, e.g. "prompt injection and excessive agency".
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
    /// Audit AI Skills/plugins or exported n8n workflows (white-box .md/.json file or folder).
    Skills {
        /// Path to a skill/plugin/n8n file (.md/.json) or a folder of them.
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Review a GitHub Pull Request's code (clones the PR head, white-box).
    /// Optionally comments back on the PR and/or opens Jira cards per finding.
    Pr {
        /// `owner/repo` or a GitHub URL.
        repo: String,
        /// Pull request number.
        number: u64,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        /// Attack-chaining rounds (post-exploitation pivots; 0 disables).
        #[arg(long, default_value_t = 2)]
        chain_depth: usize,
        /// Recon intensity 1-4 (1 quick .. 4 exhaustive; installs tools).
        #[arg(long, default_value_t = 3)]
        recon: usize,
        #[arg(long)]
        subscription: bool,
        /// Post a summary comment back on the PR (needs github integration on).
        #[arg(long)]
        comment: bool,
        /// Open a Jira card per finding (needs jira integration on).
        #[arg(long)]
        jira: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Watch a GitHub repo branch; white-box review each time a new commit lands.
    Watch {
        /// `owner/repo` or a GitHub URL.
        repo: String,
        #[arg(long, default_value = "main")]
        branch: String,
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 300)]
        interval: u64,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long)]
        subscription: bool,
        #[arg(long)]
        jira: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Manage integrations: `integrations [show|enable|disable] [github|gitlab|jira]`.
    Integrations {
        #[arg(default_value = "show")]
        action: String,
        name: Option<String>,
    },
    /// Show agent library counts.
    Agents,
    /// List providers and models.
    Models,
}

/// Locate the repo root that holds `agents_md/`.
fn find_base() -> PathBuf {
    // 1) Explicit override (set by the installer for a global, run-from-anywhere install).
    if let Ok(b) = std::env::var("NEUROSPLOIT_BASE") {
        if !b.trim().is_empty() {
            return PathBuf::from(b);
        }
    }
    // 2) Walk up from the current directory (running inside a checkout).
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
    // 3) Next to the ACTUAL executable (a global install ships the binary and
    // agents_md/ together). current_exe() resolves the PATH symlink to the real
    // install dir — so `neurosploit` works from any folder without any env var.
    if let Ok(exe) = std::env::current_exe() {
        let real = std::fs::canonicalize(&exe).unwrap_or(exe);
        for cand in [real.parent(), real.parent().and_then(|p| p.parent())].into_iter().flatten() {
            if cand.join("agents_md").is_dir() {
                return cand.to_path_buf();
            }
        }
    }
    // 4) Common install locations (matches setup.sh / install.ps1 defaults).
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for c in [home.join(".neurosploit-app"), home.join(".local/share/neurosploit")] {
            if c.join("agents_md").is_dir() { return c; }
        }
    }
    if let Some(la) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        let c = la.join("NeuroSploit");
        if c.join("agents_md").is_dir() { return c; }
    }
    // 5) Last resort: the build-time layout.
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
                "{{\"vulns\":{},\"recon\":{},\"code\":{},\"infra\":{},\"chains\":{},\"ai\":{},\"meta\":{},\"total\":{}}}",
                lib.vulns.len(), lib.recon.len(), lib.code.len(), lib.infra.len(), lib.chains.len(), lib.ai.len(), lib.meta.len(), lib.total()
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
        Cmd::Run { url, models, max_agents, vote_n, chain_depth, recon, offline, subscription, mcp, creds, focus, jira, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
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
            let ig = harness::integrations::Integrations::load(&repl::proj_dir());
            post_integrations(&ig, &url, &out, jira, false, None).await;
        }
        Cmd::Whitebox { path, models, max_agents, vote_n, chain_depth, recon, offline, subscription, jira, verbose } => {
            let path = resolve_source(&base, &path)?; // local path OR github URL/owner/repo
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
            let ig = harness::integrations::Integrations::load(&repl::proj_dir());
            post_integrations(&ig, &path, &out, jira, false, None).await;
        }
        Cmd::Greybox { repo, url, models, creds, focus, max_agents, vote_n, chain_depth, recon, offline, subscription, mcp, verbose } => {
            let repo = resolve_source(&base, &repo)?; // local path OR github URL/owner/repo
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.repo = Some(repo);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
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
        Cmd::Tui { url, models, repo, creds, focus, max_agents, vote_n, chain_depth, recon, subscription, mcp } => {
            let repo = match repo { Some(r) => Some(resolve_source(&base, &r)?), None => None }; // github URL ok
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
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
        Cmd::Host { target, models, creds, focus, max_agents, vote_n, chain_depth, recon, offline, subscription, verbose } => {
            let mut cfg = RunConfig::new(&target);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
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
        Cmd::Aitest { url, models, auth, focus, max_agents, vote_n, offline, subscription, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            cfg.auth = auth;
            if !models.is_empty() { cfg.models = models; }
            let out = run_mode(&base, cfg, false, Mode::Ai).await?;
            print_findings(&out);
        }
        Cmd::Skills { path, models, vote_n, offline, subscription, verbose } => {
            let path = resolve_source(&base, &path)?; // local path OR github URL
            let mut cfg = RunConfig::new(&path);
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            if !models.is_empty() { cfg.models = models; }
            let out = run_mode(&base, cfg, false, Mode::Skills).await?;
            print_findings(&out);
        }
        Cmd::Pr { repo, number, models, vote_n, chain_depth, recon, subscription, comment, jira, verbose } => {
            let ig = harness::integrations::Integrations::load(&repl::proj_dir());
            let owner_repo = normalize_repo(&repo);
            let path = clone_pr(&base, &ig, &owner_repo, number)?;
            println!("  🔍 white-box review of {owner_repo} PR #{number}");
            let mut cfg = RunConfig::new(&path);
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = Some(format!("This is the code of pull request #{number} of {owner_repo}. Focus on vulnerabilities introduced or touched by this change."));
            if !models.is_empty() { cfg.models = models; }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
            post_integrations(&ig, &format!("{owner_repo}#{number}"), &out, jira, comment, Some((&owner_repo, number))).await;
        }
        Cmd::Watch { repo, branch, interval, models, subscription, jira, verbose } => {
            let ig = harness::integrations::Integrations::load(&repl::proj_dir());
            let owner_repo = normalize_repo(&repo);
            println!("  👀 watching {owner_repo}@{branch} every {interval}s — Ctrl-C to stop");
            let mut last = String::new();
            loop {
                match ig.github_latest_sha(&owner_repo, &branch).await {
                    Ok(sha) if sha != last => {
                        let short = &sha[..7.min(sha.len())];
                        println!("\n  🔔 {} commit {short} on {owner_repo}@{branch} — reviewing",
                            if last.is_empty() { "current" } else { "new" });
                        // fresh clone of the branch tip
                        let dest = base.join("repos").join(sanitize(&format!("{owner_repo}-{branch}")));
                        std::fs::remove_dir_all(&dest).ok();
                        let url = ig.authed_clone_url(&format!("https://github.com/{owner_repo}"));
                        if run_git(&["clone", "--depth", "1", "--branch", &branch, &url, &dest.display().to_string()]).is_ok() {
                            let mut cfg = RunConfig::new(&dest.display().to_string());
                            cfg.subscription = subscription;
                            cfg.verbose = verbose;
                            if !models.is_empty() { cfg.models = models.clone(); }
                            if let Ok(out) = run_engagement(&base, cfg, false, true).await {
                                print_findings(&out);
                                post_integrations(&ig, &format!("{owner_repo}@{short}"), &out, jira, false, None).await;
                            }
                        }
                        last = sha;
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("  watch: {e}"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval.max(15))).await;
            }
        }
        Cmd::Integrations { action, name } => {
            let dir = repl::proj_dir();
            let mut ig = harness::integrations::Integrations::load(&dir);
            match action.as_str() {
                "enable" | "disable" => {
                    let on = action == "enable";
                    match name.as_deref() {
                        Some("github") => ig.github.enabled = on,
                        Some("gitlab") => ig.gitlab.enabled = on,
                        Some("jira") => ig.jira.enabled = on,
                        _ => { eprintln!("  usage: integrations {action} <github|gitlab|jira>"); return Ok(()); }
                    }
                    ig.save(&dir)?;
                    println!("  {} {}", name.unwrap_or_default(), if on { "enabled ✓" } else { "disabled" });
                }
                _ => {
                    println!("  integrations · {}", dir.display());
                    for l in ig.status_lines() { println!("    {l}"); }
                    println!("  toggle: `neurosploit integrations enable github|gitlab|jira` · full setup in the REPL: /integrations");
                }
            }
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
    // Multiple identities/roles → access-control testing (IDOR/BOLA/BFLA/privesc).
    if let Some(ri) = c.roles_instruction() {
        if cfg.auth.is_none() {
            cfg.auth = c.roles.iter().find_map(|r| r.header_line());
        }
        let base = cfg.instructions.clone().unwrap_or_default();
        cfg.instructions = Some(format!("{ri}\n{base}"));
        println!("  [*] {} identities loaded ({}) — access-control testing enabled",
            c.roles.len(), c.roles.iter().map(|r| r.name.clone()).collect::<Vec<_>>().join("/"));
    }
    // Host credentials (SSH / Windows-AD) → tell the agents how to authenticate
    // to the host so they can run on-host enumeration / privesc / AD checks.
    if let Some(hi) = c.host_instruction() {
        let base = cfg.instructions.clone().unwrap_or_default();
        cfg.instructions = Some(format!("{hi}\n{base}"));
        println!("  [*] host credentials loaded (SSH/Windows-AD)");
    }
    // Cloud credentials (AWS / GCP / Azure) → export env for the provider CLIs
    // and tell the agents how to authenticate & what to enumerate.
    let cloud_env = c.cloud_env();
    if !cloud_env.is_empty() {
        for (k, v) in &cloud_env {
            std::env::set_var(k, v);
        }
        let names: Vec<&str> = [
            (!c.cloud.as_ref().map(|x| x.aws_access_key_id.is_empty() && x.aws_profile.is_empty()).unwrap_or(true), "AWS"),
            (!c.cloud.as_ref().map(|x| x.gcp_sa_json.is_empty()).unwrap_or(true), "GCP"),
            (!c.cloud.as_ref().map(|x| x.azure_client_id.is_empty()).unwrap_or(true), "Azure"),
        ].iter().filter(|(on, _)| *on).map(|(_, n)| *n).collect();
        println!("  [*] cloud credentials loaded ({}) — {} env var(s) exported", names.join("/"), cloud_env.len());
        if let Some(ci) = c.cloud_instruction() {
            let base = cfg.instructions.clone().unwrap_or_default();
            cfg.instructions = Some(format!("{ci}\n{base}"));
        }
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
pub(crate) enum Mode { Black, White, Grey, Host, Ai, Skills }

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
    /// Set when the run is parked on token/quota exhaustion (awaiting /continue).
    pub paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Wakes a parked run when the user runs /continue.
    pub resume: std::sync::Arc<tokio::sync::Notify>,
    /// Fallback models pushed by /continue <provider:model> before resuming.
    pub fallback: std::sync::Arc<std::sync::Mutex<Vec<ModelRef>>>,
    pub workdir: PathBuf,
}

/// When running in subscription mode, verify the local CLI is installed AND
/// logged in before the engagement starts — otherwise every agent comes back
/// empty and it looks like "0 findings" when the real cause is auth. Checks the
/// primary model's provider; prints a clear warning (non-fatal).
pub(crate) async fn subscription_preflight(cfg: &RunConfig) {
    if !cfg.subscription || cfg.offline { return; }
    let Some(primary) = cfg.models.first() else { return };
    let provider = ModelRef::parse(primary).provider;
    if harness::models::cli_binary_for(&provider).is_none() { return; }
    print!("  [*] checking {provider} subscription login… ");
    use std::io::Write; let _ = std::io::stdout().flush();
    match harness::models::cli_login_status(&provider).await {
        harness::models::LoginStatus::LoggedIn => println!("\r  [*] {provider} subscription: logged in ✓            "),
        harness::models::LoginStatus::NotLoggedIn => {
            let cli = harness::models::cli_binary_for(&provider).unwrap_or("the CLI");
            println!("\r  \x1b[1;33m[!] {provider} subscription NOT logged in\x1b[0m — run `{cli}` and log in (e.g. `claude` → /login), then retry.");
            println!("      \x1b[2m(without login every agent returns empty — this is usually why a run finds 0.)\x1b[0m");
        }
        harness::models::LoginStatus::NotInstalled => {
            let cli = harness::models::cli_binary_for(&provider).unwrap_or("?");
            println!("\r  \x1b[1;33m[!] subscription CLI `{cli}` for {provider} is not installed\x1b[0m — install it or use an API key (drop --subscription).");
        }
        harness::models::LoginStatus::Unknown => println!("\r  [*] {provider} subscription: login state unknown (continuing)   "),
    }
}

/// Set up + start an engagement (synchronous setup; the work runs in the task).
pub(crate) fn spawn_engagement(base: &Path, mut cfg: RunConfig, mcp: bool, mode: Mode) -> Spawned {
    let lib = agents::load(base);
    let run_id = format!("ns-{}-{}", now_ts(), sanitize(&cfg.target));
    let workdir = base.join("runs").join(&run_id);
    std::fs::create_dir_all(&workdir).ok();
    cfg.workdir = Some(workdir.display().to_string());
    cfg.rl_path = Some(base.join("data").join("rl_state_rs.json").display().to_string());
    // PoC scratch dir: agents write custom exploit scripts here (see doctrine).
    let pocs = workdir.join("pocs");
    std::fs::create_dir_all(&pocs).ok();
    std::env::set_var("NEUROSPLOIT_POCS", pocs.display().to_string());
    // Local intercepting proxy (Burp/ZAP): agents route HTTP through it. Comes
    // from cfg.proxy (REPL /proxy) or the NEUROSPLOIT_PROXY env var (CLI).
    let proxy = cfg.proxy.clone()
        .or_else(|| std::env::var("NEUROSPLOIT_PROXY").ok())
        .filter(|p| !p.trim().is_empty());
    if let Some(p) = proxy {
        std::env::set_var("NEUROSPLOIT_PROXY", &p);
        println!("  │  proxy  : {p} (traffic routed to Burp/ZAP for inspection)");
    }
    // Identifying User-Agent (attribution): cfg.user_agent overrides the default.
    let ua = cfg.user_agent.clone()
        .or_else(|| std::env::var("NEUROSPLOIT_UA").ok())
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(harness::pipeline::default_user_agent);
    std::env::set_var("NEUROSPLOIT_UA", &ua);
    println!("  │  ua     : {ua}");
    write_status(&workdir, "running", &format!("\"target\":{:?}", cfg.target));

    println!("  ┌─ NeuroSploit v3.6.3  ·  by Joas A Santos & Red Team Leaders");
    println!("  │  run id : {run_id}");
    println!("  │  target : {}", cfg.target);
    println!("  │  models : {}", cfg.models.join(", "));
    println!("  │  output : {}", workdir.display());
    if let Mode::Grey = mode {
        println!("  │  repo   : {}", cfg.repo.clone().unwrap_or_default());
    }
    println!("  └─ mode   : {}{}{}",
        match mode { Mode::White => "white-box", Mode::Grey => "greybox", Mode::Host => "host/infra", Mode::Ai => "ai/llm", Mode::Skills => "skills/n8n audit", Mode::Black => "black-box" },
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
    let paused = pool.pause_handle();
    let resume = pool.resume_handle();
    let fallback = pool.fallback_handle();
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(256);
    let task = tokio::spawn(async move {
        match mode {
            Mode::White => harness::run_whitebox(cfg, &lib, &pool, tx).await,
            Mode::Grey => harness::run_greybox(cfg, &lib, &pool, tx).await,
            Mode::Host => harness::run_host(cfg, &lib, &pool, tx).await,
            Mode::Ai => harness::pipeline::run_ai(cfg, &lib, &pool, tx).await,
            Mode::Skills => harness::pipeline::run_skills_audit(cfg, &lib, &pool, tx).await,
            Mode::Black => harness::run(cfg, &lib, &pool, tx).await,
        }
    });
    Spawned { task, rx, cancel, soft, paused, resume, fallback, workdir }
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
    harness::pipeline::stamp_attribution(&mut fs); // provenance travels with raw reports too
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
    subscription_preflight(&cfg).await;
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

/// Resolve a source argument (white-box `path` / grey-box `--repo`) to a local
/// directory. A git URL (`https://…`, `git@…`, `ssh://…`, `*.git`) or a GitHub
/// `owner/repo` shorthand is **cloned** (shallow) into `<base>/repos/<name>` and
/// that path is returned; an existing local path is returned unchanged.
pub(crate) fn resolve_source(base: &Path, arg: &str) -> anyhow::Result<String> {
    let is_url = arg.starts_with("http://") || arg.starts_with("https://")
        || arg.starts_with("git@") || arg.starts_with("ssh://") || arg.ends_with(".git");
    // `owner/repo` GitHub shorthand: no scheme, exactly one slash, not a real path.
    let is_shorthand = !is_url
        && !Path::new(arg).exists()
        && arg.matches('/').count() == 1
        && !arg.starts_with('.') && !arg.starts_with('/') && !arg.starts_with('~')
        && arg.chars().all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c));
    if !is_url && !is_shorthand {
        return Ok(arg.to_string()); // already a local path
    }

    let url = if is_shorthand { format!("https://github.com/{arg}") } else { arg.to_string() };
    let name = sanitize(url.trim_end_matches('/').trim_end_matches(".git").rsplit('/').next().unwrap_or("repo"));
    let repos_dir = base.join("repos");
    std::fs::create_dir_all(&repos_dir).ok();
    let dest = repos_dir.join(&name);

    if dest.join(".git").is_dir() {
        println!("  [*] repo cache hit → {} (delete it to re-clone)", dest.display());
        return Ok(dest.display().to_string());
    }
    // If a GitHub/GitLab integration is enabled, inject its token so PRIVATE
    // repos clone without an interactive prompt (token never printed).
    let ig = harness::integrations::Integrations::load(&repl::proj_dir());
    let clone_url = ig.authed_clone_url(&url);
    let private = clone_url != url;
    println!("  [*] cloning {url}{} → {}", if private { " (private, via token)" } else { "" }, dest.display());
    let status = std::process::Command::new("git")
        .args(["clone", "--depth", "1", &clone_url, &dest.display().to_string()])
        .status()
        .map_err(|e| anyhow::anyhow!("could not start `git clone` (is git installed?): {e}"))?;
    if !status.success() {
        std::fs::remove_dir_all(&dest).ok();
        anyhow::bail!("git clone failed for {url}");
    }
    Ok(dest.display().to_string())
}

/// Normalize a GitHub repo reference to `owner/name`.
fn normalize_repo(s: &str) -> String {
    s.trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .replace("https://github.com/", "")
        .replace("http://github.com/", "")
        .replace("git@github.com:", "")
}

/// Run a git command, returning Ok(()) on success.
fn run_git(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("git").args(args).status()
        .map_err(|e| anyhow::anyhow!("could not run git (is it installed?): {e}"))?;
    if !status.success() { anyhow::bail!("git {:?} failed", args.first().unwrap_or(&"")); }
    Ok(())
}

/// Clone a repo and check out a Pull Request's HEAD (`refs/pull/N/head`).
fn clone_pr(base: &Path, ig: &harness::integrations::Integrations, owner_repo: &str, number: u64) -> anyhow::Result<String> {
    let dest = base.join("repos").join(sanitize(&format!("{owner_repo}-pr{number}")));
    std::fs::create_dir_all(base.join("repos")).ok();
    std::fs::remove_dir_all(&dest).ok(); // always fresh — PR code changes
    let url = ig.authed_clone_url(&format!("https://github.com/{owner_repo}"));
    let private = url.contains('@');
    println!("  [*] cloning {owner_repo}{} + PR #{number} head → {}", if private { " (private)" } else { "" }, dest.display());
    let d = dest.display().to_string();
    run_git(&["clone", "--depth", "1", &url, &d])?;
    run_git(&["-C", &d, "fetch", "--depth", "1", "origin", &format!("pull/{number}/head:pr-{number}")])?;
    run_git(&["-C", &d, "checkout", &format!("pr-{number}")])?;
    Ok(d)
}

/// After a run, optionally open Jira cards and/or comment on a GitHub PR.
async fn post_integrations(
    ig: &harness::integrations::Integrations,
    target: &str,
    out: &RunOutput,
    jira: bool,
    comment: bool,
    gh_pr: Option<(&str, u64)>,
) {
    if jira && ig.jira.enabled && !out.findings.is_empty() {
        let (keys, errs) = ig.jira_cards_for(target, &out.findings).await;
        if !keys.is_empty() { println!("  🪪 Jira cards opened: {}", keys.join(", ")); }
        for e in errs { eprintln!("  jira: {e}"); }
    }
    if comment && ig.github.enabled {
        if let Some((repo, number)) = gh_pr {
            match ig.github_comment(repo, number, &pr_comment_body(out)).await {
                Ok(()) => println!("  💬 commented results on {repo}#{number}"),
                Err(e) => eprintln!("  github comment: {e}"),
            }
        }
    }
}

/// Markdown summary of a run, for a PR comment.
fn pr_comment_body(out: &RunOutput) -> String {
    let mut by = std::collections::BTreeMap::new();
    for f in &out.findings { *by.entry(f.severity.as_str()).or_insert(0) += 1; }
    let chips: Vec<String> = by.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    let mut s = format!(
        "### 🧠 NeuroSploit white-box review\n\n**{} validated finding(s)** — {}\n\n",
        out.findings.len(),
        if chips.is_empty() { "none".into() } else { chips.join(" · ") }
    );
    if out.findings.is_empty() {
        s.push_str("_No vulnerabilities confirmed in the reviewed code._\n");
    } else {
        s.push_str("| Severity | Finding | CWE | Location |\n|---|---|---|---|\n");
        for f in &out.findings {
            s.push_str(&format!("| {} | {} | {} | {} |\n",
                f.severity, f.title.replace('|', "\\|"), f.cwe,
                f.endpoint.replace('|', "\\|")));
        }
        s.push_str("\n_Findings validated by multi-model voting. Authorized testing only._\n");
    }
    s
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
            // Recon / probe activity — SHOW it so a long recon (esp. via a
            // non-streaming CLI like codex) doesn't look frozen.
            if low.starts_with("probe:") { format!("\x1b[36m  🔎 {}\x1b[0m", trunc1(line, 130)) }
            else if low.contains("recon complete") { "\x1b[36m  🔍 recon complete\x1b[0m".into() }
            else if low.starts_with("recon") || low.starts_with("ai-recon") || low.contains("recon round") || low.contains("intensity") { format!("\x1b[36m  🔍 {}\x1b[0m", trunc1(line, 130)) }
            else if low.starts_with("skills audit") || low.starts_with("ai engagement") { format!("\x1b[36m  🤖 {}\x1b[0m", trunc1(line, 130)) }
            else if low.starts_with("loaded ") || low.starts_with("running ") { format!("\x1b[36m  🧭 {}\x1b[0m", trunc1(line, 130)) }
            else if low.contains("selected") && low.contains("agent") { format!("\x1b[36m  🧭 {}\x1b[0m", trunc1(line, 110)) }
            else if low.starts_with("vote") && low.contains("confirmed") { format!("\x1b[1;32m  ✓ {}\x1b[0m", trunc1(line, 110)) }
            else if low.starts_with("exploit") || low.starts_with("test ") || low.starts_with("ai ") || low.starts_with("skill ") || low.contains("launching agent") { format!("\x1b[35m  🧪 {}\x1b[0m", trunc1(line, 110)) }
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

