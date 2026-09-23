//! NeuroSploit v4.1.0 — interactive harness + CLI (`run` / `whitebox` / `agents` / `models`).

mod rectify;
mod repl;
mod tui;

use clap::{Parser, Subcommand};
mod mcp;
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig, RunOutput};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "neurosploit",
    version,
    about = "NeuroSploit v4.1.0 — multi-model autonomous pentest harness",
    long_about = "NeuroSploit v4.1.0 — a Rust multi-model harness that drives a pool of LLMs \
(API key or local subscription: Claude/Codex/Gemini/Grok/OpenCode/Hermes) to autonomously test a target. \
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
    /// Authorization for an interactive session, set before the first command
    /// is typed. The REPL deliberately has no `/`-command that can WIDEN the
    /// grant — a session must not be able to authorize itself — so the ceiling
    /// arrives here, from whoever launched it.
    #[arg(long = "capability-token", global = true)]
    capability_token: Option<String>,
    /// Extra authorized hosts for an interactive session.
    #[arg(long = "session-in-scope", global = true)]
    session_in_scope: Vec<String>,
    /// Environment for an interactive session: lab · development · staging ·
    /// production · ot-production.
    #[arg(long = "session-environment", global = true)]
    session_environment: Option<String>,
    /// Policy profile for an interactive session: web · ot.
    #[arg(long = "session-policy", global = true)]
    session_policy: Option<String>,
    /// Egress: direct · socks5://host:port · http://host:port ·
    /// openvpn:/path.ovpn · ssh://user@bastion[?forward=host:port] ·
    /// cloudflared://host:port. An internal target with no transport is refused
    /// rather than tested against whatever network this host is on. Global, so
    /// an interactive session cannot change its own route mid-engagement.
    #[arg(long = "transport", global = true)]
    transport: Option<String>,
    /// Out-of-band domain (a wildcard pointed at this host). Without it the
    /// blind classes — SSRF, XXE, blind RCE — can only be reported as leads.
    #[arg(long = "oob-domain", global = true)]
    oob_domain: Option<String>,
    /// Where the OOB HTTP listener binds (default 0.0.0.0:8080).
    #[arg(long = "oob-http", global = true)]
    oob_http: Option<String>,
    /// Where the OOB DNS listener binds, when the zone is delegated to us.
    #[arg(long = "oob-dns", global = true)]
    oob_dns: Option<String>,
    /// Inbound SMS: twilio:<sid>:<token>:<number> or webhook:<url>:<number>.
    #[arg(long = "sms", global = true)]
    sms: Option<String>,
    /// Intercepting proxy: burp · caido · zap · mitmproxy · own · own+burp ·
    /// http://host:port. Routes the harness AND agent commands through it.
    #[arg(long = "intercept", global = true)]
    intercept: Option<String>,
    /// Run agent commands inside a container instead of on the host. Bare flag
    /// uses the Kali image; give a value to override (e.g. --sandbox my/img).
    #[arg(long = "sandbox", global = true, num_args = 0..=1, default_missing_value = "")]
    sandbox: Option<String>,
    /// TypeSafe System One as an ADDITIONAL confirmation strategy: on · off ·
    /// auto (default: auto = on when TYPESAFE_API_KEY is set). `off` runs the
    /// exact same pipeline without it, so runs can be compared with/without.
    #[arg(long = "typesafe", global = true)]
    typesafe: Option<String>,
    /// Decision backend for the calibrated System One layer:
    /// typesafe (hosted API, needs TYPESAFE_API_KEY) or laya (local, free,
    /// open-source — downloads the model on first use and keeps evidence on the
    /// box). Default: whichever is configured. See tools/laya_shim.py.
    #[arg(long = "decision-backend", global = true)]
    decision_backend: Option<String>,
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
        /// Use local agentic CLI subscription (Claude/Codex/Gemini/Grok/OpenCode/Hermes login).
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
        /// Engagement objective / context: WHY the test runs and WHAT matters.
        #[arg(long)]
        objective: Option<String>,
        /// Out-of-scope exclusions (hard constraint): hosts/paths/techniques the
        /// agents must not touch. Repeatable or comma/semicolon-separated.
        #[arg(long = "out-of-scope")]
        out_of_scope: Option<String>,
        /// Additional authorized hosts: host · *.domain · 10.0.0.0/24 · https://host/path.
        /// Without this the engagement is authorized against the target and nothing else.
        #[arg(long = "in-scope")]
        in_scope: Vec<String>,
        /// Load the hard scope + guardrails from a YAML file (see
        /// examples/scope.example.yaml). Its `hard` list is the boundary;
        /// --in-scope adds to it and a capability token still caps it.
        #[arg(long = "scope-file")]
        scope_file: Option<String>,
        /// Environment, which scales every risk score: lab · development ·
        /// staging · production · ot-production (aliases: ics, scada).
        #[arg(long = "environment", default_value = "production")]
        environment: String,
        /// Engagement policy profile: web · ot (ot = read-only, paced, with the
        /// dangerous industrial primitives removed).
        #[arg(long = "policy", default_value = "web")]
        policy: String,
        /// How to spend reasoning: eco · balanced · aggressive · unlimited.
        /// Omitted means unlimited — the full run, as before budgets existed.
        #[arg(long = "budget")]
        budget: Option<String>,
        /// Hard ceiling on tokens for the run (0 = none). Independent of
        /// --budget: one says how to spend, the other how much there is.
        #[arg(long = "token-limit")]
        token_limit: Option<u64>,
        /// Cap on findings that receive deep reasoning.
        #[arg(long = "deep-test-limit")]
        deep_test_limit: Option<usize>,
        /// Map the whole surface before investigating anything.
        #[arg(long = "coverage-first")]
        coverage_first: bool,
        /// Investigate a promising lead as soon as it appears.
        #[arg(long = "depth-first")]
        depth_first: bool,
        /// Requests per endpoint family (/api/users/{id} is sampled, not enumerated).
        #[arg(long = "sample-per-route", default_value_t = 3)]
        sample_per_route: usize,
        /// Re-run each finding's PoC after validation; demote any that no
        /// longer reproduces.
        #[arg(long = "revalidate-poc")]
        revalidate_poc: bool,
        /// Map findings onto compliance controls in the report: pci-dss, hipaa,
        /// soc2 (repeatable or comma-separated).
        #[arg(long = "compliance")]
        compliance: Vec<String>,
        /// Open a Jira card per finding (needs the jira integration enabled).
        #[arg(long)]
        jira: bool,
        /// Re-test ONLY these agent(s), skipping recon-based selection — repeatable
        /// or comma/semicolon-separated (e.g. `--only sqli --only cve_hunter`).
        /// Run `neurosploit agents` for the names.
        #[arg(long = "only")]
        only: Vec<String>,
        /// Verbose: log each agent as it launches, recon, and votes.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Run NeuroSploit as an MCP server (stdio) so Claude Code, Codex, Cursor
    /// and other MCP clients can drive it as a set of tools.
    Mcp,
    /// Rebuild a finished run's report artifacts (md · json · html · pdf) from
    /// its findings, without re-running the engagement.
    Rebuild {
        /// Run id (`ns-…`) or a path to the run directory.
        run: String,
    },
    /// Export a run's archived HTTP traffic (from flows.jsonl) as a .http file
    /// for external inspection tools.
    Traffic {
        /// Run id or path.
        run: String,
    },
    /// Verify a finished run's audit trail — the hash chain and, with --anchor,
    /// the signed anchors that catch truncation and silent rebuilds.
    Audit {
        /// Run id (`ns-…`) or path to the run directory.
        run: String,
        /// Also verify anchors (P4): truncation, rebuild and, if a key is set,
        /// anchor signatures.
        #[arg(long = "anchor")]
        anchor: bool,
    },
    /// Compliance mapping: re-frame a finished run's findings against PCI-DSS,
    /// HIPAA or SOC 2 controls.
    Compliance {
        /// Run id (`ns-…`) or path to the run directory.
        run: String,
        /// Frameworks: pci-dss · hipaa · soc2 (repeatable/comma-separated; all if omitted).
        #[arg(long = "framework")]
        framework: Vec<String>,
        /// Include unconfirmed findings (leads) too. Off by default.
        #[arg(long = "include-leads")]
        include_leads: bool,
    },
    /// Re-validate a finished run's PoCs: re-run each finding's recorded proof
    /// and report which still reproduce.
    Poc {
        /// Run id (`ns-…`) or path to the run directory.
        run: String,
        /// Re-runs per finding (a single send can be a fluke).
        #[arg(long = "repeats", default_value_t = 2)]
        repeats: usize,
        /// Write the demoted findings back to findings.json.
        #[arg(long = "apply")]
        apply: bool,
    },
    /// Assemble/print/verify a run's assurance bundle (P1–P5 in one manifest).
    Assurance {
        /// Run id (`ns-…`) or path to the run directory.
        run: String,
        /// Verify the bundle against the run dir (hashes + signature) instead
        /// of assembling a fresh one.
        #[arg(long = "verify")]
        verify: bool,
    },
    /// Manage the Kali sandbox container (up · exec · down).
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// Issue or inspect a signed capability token (the engagement's authorization).
    Capability {
        #[command(subcommand)]
        cmd: CapCmd,
    },
    /// Provenance: which build made an artifact, and does it still match.
    Provenance {
        #[command(subcommand)]
        cmd: ProvCmd,
    },
    /// Internal network / AD attack graph: paths to the crown jewels, and the
    /// one edge worth fixing first.
    Internal {
        /// Graph file (JSON: {"nodes": [...], "edges": [...]}). Omit to start
        /// from the AD scaffold alone.
        #[arg(long = "graph")]
        graph: Option<String>,
        /// Seed the graph with the structure every domain has.
        #[arg(long = "scaffold")]
        scaffold: Option<String>,
        /// Where the attacker starts — the foothold node's id.
        #[arg(long = "from", default_value = "printer")]
        from: String,
        /// Turn the credential→identity→permission→machine loop this many times.
        #[arg(long = "expand", default_value_t = 3)]
        expand: usize,
        /// Print the Mermaid diagram too.
        #[arg(long)]
        mermaid: bool,
        /// Write the expanded graph back out as JSON.
        #[arg(long = "save")]
        save: Option<String>,
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
        /// Re-test ONLY these code agent(s) — repeatable or comma/semicolon-separated.
        #[arg(long = "only")]
        only: Vec<String>,
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
        /// Re-test ONLY these agent(s) — repeatable or comma/semicolon-separated.
        #[arg(long = "only")]
        only: Vec<String>,
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
    /// Mobile / binary: analyse a LOCAL artifact (a binary, APK or IPA) with the
    /// mobile RE agents (Ghidra headless, MobSF, Frida, apktool/jadx).
    Mobile {
        /// Path to the artifact on disk (.apk / .ipa / a binary).
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 1)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(long)]
        focus: Option<String>,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Container: scan an OCI image (repo:tag / tar / Dockerfile) for vulnerable
    /// packages, exposed secrets and misconfigurations, and emit an SBOM
    /// (SPDX + CycloneDX). Uses trivy / grype / syft headless.
    Container {
        /// Image reference, local tar, or Dockerfile path.
        image: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 1)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(long)]
        focus: Option<String>,
        #[arg(short, long)]
        verbose: bool,
    },
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
        /// Block the PR when a confirmed finding is this severity or worse:
        /// critical|high|medium|low. Sets a failing commit status + a
        /// REQUEST_CHANGES review, and exits non-zero so CI fails the check.
        #[arg(long)]
        fail_on: Option<String>,
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
    // 5) A cache the harness populates itself (see ensure_agents). A binary
    // downloaded on its own, with no agents_md/ beside it, lands here.
    if let Some(cache) = agents_cache_dir() {
        if cache.join("agents_md").is_dir() {
            return cache;
        }
    }
    // 6) Last resort: the build-time layout.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Where the harness caches an auto-fetched `agents_md/` (`~/.neurosploit/cache`).
/// Bring up the local Laya decision backend and point the client at it.
///
/// Idempotent: if the shim already answers on its port, we just set the env and
/// return. Otherwise we start `tools/laya_shim.py` (which downloads the model on
/// first run) in the background and wait for it to become ready. `pip install
/// laya` is attempted once if the import is missing. Everything here is optional
/// and only runs when the operator explicitly picks `--decision-backend laya`.
fn ensure_laya_backend() -> Result<(), String> {
    let port = std::env::var("LAYA_SHIM_PORT").unwrap_or_else(|_| "8799".into());
    let endpoint = format!("http://127.0.0.1:{port}/systemone");
    let health = format!("http://127.0.0.1:{port}/health");

    let ready = |url: &str| -> bool {
        std::process::Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", url])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "200")
            .unwrap_or(false)
    };

    if ready(&health) {
        std::env::set_var("NEUROSPLOIT_DECISION_ENDPOINT", &endpoint);
        std::env::set_var("NEUROSPLOIT_DECISION_MODEL", "laya");
        println!("  \x1b[2mdecision backend: laya (already running on :{port})\x1b[0m");
        return Ok(());
    }

    // Locate the shim next to the binary/checkout.
    let shim = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools").join("laya_shim.py"),
        std::env::current_dir().unwrap_or_default().join("neurosploit-rs/tools/laya_shim.py"),
        std::env::current_dir().unwrap_or_default().join("tools/laya_shim.py"),
    ].into_iter().find(|p| p.exists())
        .ok_or_else(|| "laya_shim.py not found (expected under tools/)".to_string())?;

    let py = if std::process::Command::new("python3").arg("--version").output().is_ok() { "python3" } else { "python" };
    // Best-effort install of laya if it is missing.
    let has_laya = std::process::Command::new(py).args(["-c", "import laya"]).output().map(|o| o.status.success()).unwrap_or(false);
    if !has_laya {
        println!("  \x1b[2minstalling laya (first run only)…\x1b[0m");
        let _ = std::process::Command::new(py).args(["-m", "pip", "install", "-q", "laya"]).status();
    }

    println!("  \x1b[2mstarting laya shim (downloads the model on first use)…\x1b[0m");
    std::process::Command::new(py)
        .arg(&shim)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("could not start the shim: {e}"))?;

    // Wait for readiness (model download can take a while on the first run).
    for _ in 0..120 {
        if ready(&health) {
            std::env::set_var("NEUROSPLOIT_DECISION_ENDPOINT", &endpoint);
            std::env::set_var("NEUROSPLOIT_DECISION_MODEL", "laya");
            println!("  \x1b[1;32m✓ laya backend ready\x1b[0m on :{port} — evidence stays local, no API key");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err("laya shim did not become ready in time".into())
}

fn agents_cache_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).map(|h| h.join(".neurosploit").join("cache"))
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from).map(|l| l.join("NeuroSploit").join("cache")))
}

/// Make sure `<base>/agents_md/` exists; if not, fetch it from the pinned
/// release into the cache and use that. The agent library is prompt/markdown,
/// not code, and is fetched over HTTPS from the official repo at this exact
/// version tag. Opt out with NEUROSPLOIT_NO_FETCH=1 (offline/air-gapped).
async fn ensure_agents(base: &Path) -> PathBuf {
    if base.join("agents_md").is_dir() {
        return base.to_path_buf();
    }
    if std::env::var("NEUROSPLOIT_NO_FETCH").ok().as_deref() == Some("1") {
        return base.to_path_buf();
    }
    let Some(cache) = agents_cache_dir() else { return base.to_path_buf() };
    if cache.join("agents_md").is_dir() {
        return cache;
    }
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let url = format!("https://codeload.github.com/JoasASantos/NeuroSploit/tar.gz/refs/tags/{tag}");
    eprintln!("  \x1b[2magents_md/ not found locally — fetching the agent library for {tag} from GitHub…\x1b[0m");
    if let Err(e) = fetch_agents(&url, &cache).await {
        eprintln!("  \x1b[33m⚠ could not fetch agents_md ({e}). Run from a checkout, or set NEUROSPLOIT_BASE to a folder that has agents_md/.\x1b[0m");
        return base.to_path_buf();
    }
    if cache.join("agents_md").is_dir() {
        eprintln!("  \x1b[2m✓ agent library cached at {}\x1b[0m", cache.display());
        cache
    } else {
        base.to_path_buf()
    }
}

/// Download the release tarball and extract only its `agents_md/` into `cache`.
async fn fetch_agents(url: &str, cache: &Path) -> anyhow::Result<()> {
    let bytes = harness::fetch_bytes(url, 120).await?;
    std::fs::create_dir_all(cache)?;
    // Extract with the system tar (no new crate dependency): the tarball's top
    // dir is `NeuroSploit-<version>/`, and we keep only its agents_md subtree.
    let tmp = cache.join(".download.tar.gz");
    std::fs::write(&tmp, &bytes)?;
    let status = std::process::Command::new("tar")
        .arg("-xzf").arg(&tmp)
        .arg("-C").arg(cache)
        .arg("--strip-components=1")
        .arg("--wildcards").arg("*/agents_md")
        .status();
    let _ = std::fs::remove_file(&tmp);
    match status {
        Ok(s) if s.success() && cache.join("agents_md").is_dir() => Ok(()),
        _ => anyhow::bail!("tar extraction failed or agents_md not in the archive"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    let base = ensure_agents(&find_base()).await;

    // Resolve the TypeSafe mode into the env var the pipeline reads, so every
    // run type (and the REPL) honours one control. `off` disables it entirely;
    // `on`/`auto` leave it to key presence. This is what makes with/without
    // TypeSafe an A/B a single flag flips.
    // Decision backend selection is additive: it only sets the endpoint/model
    // env vars the client already reads. `typesafe` (or unset) leaves the hosted
    // default untouched; `laya` points at a local shim and starts it if needed.
    if let Some(be) = cli.decision_backend.as_deref().map(|s| s.trim().to_lowercase()) {
        if be == "laya" {
            if let Err(e) = ensure_laya_backend() {
                eprintln!("  \x1b[33m⚠ laya backend: {e} — falling back to whatever else is configured\x1b[0m");
            }
        }
        // `typesafe` needs no action: the client's defaults already point there.
    }
    match cli.typesafe.as_deref().map(|s| s.trim().to_lowercase()) {
        Some(ref m) if m == "off" || m == "false" || m == "0" => std::env::set_var("NEUROSPLOIT_TYPESAFE", "off"),
        Some(ref m) if m == "on" || m == "true" || m == "1" || m == "auto" => std::env::set_var("NEUROSPLOIT_TYPESAFE", "on"),
        _ => {}
    }

    // No subcommand → launch the Claude-Code-style interactive session.
    let cmd = match cli.cmd.take() {
        Some(c) => c,
        None => {
            // The session's authorization comes from whoever launched it, not
            // from inside it.
            let auth = repl::SessionAuth {
                capability: cli.capability_token.clone().or_else(|| std::env::var("NEUROSPLOIT_CAPABILITY").ok()).filter(|t| !t.trim().is_empty()),
                in_scope: cli.session_in_scope.clone(),
                environment: cli.session_environment.clone(),
                policy: cli.session_policy.clone(),
                transport: cli.transport.clone(),
                oob_domain: cli.oob_domain.clone(),
                oob_http: cli.oob_http.clone(),
                oob_dns: cli.oob_dns.clone(),
                sms: cli.sms.clone(),
            };
            repl::repl(&base, auth).await?;
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
        Cmd::Mcp => { mcp::serve()?; }
        Cmd::Rebuild { run } => {
            // Accept either a path or a bare run id, resolved against the same
            // runs root the engagement wrote to.
            let dir = std::path::PathBuf::from(&run);
            let dir = if dir.is_dir() { dir } else { base.join("runs").join(&run) };
            if !dir.is_dir() {
                anyhow::bail!("no such run directory: {}", dir.display());
            }
            match harness::report::rebuild(&dir) {
                Ok(p) => println!("  report rebuilt → {}", p.display()),
                Err(e) => anyhow::bail!("rebuild failed: {e}"),
            }
        }
        Cmd::Audit { run, anchor } => handle_audit(&base, &run, anchor)?,
        Cmd::Traffic { run } => handle_traffic(&base, &run)?,
        Cmd::Assurance { run, verify } => handle_assurance(&base, &run, verify)?,
        Cmd::Compliance { run, framework, include_leads } => handle_compliance(&base, &run, &framework, include_leads)?,
        Cmd::Poc { run, repeats, apply } => handle_poc(&base, &run, repeats, apply).await?,
        Cmd::Sandbox { cmd } => handle_sandbox(cmd).await?,
        Cmd::Capability { cmd } => handle_capability(cmd)?,
        Cmd::Provenance { cmd } => handle_provenance(cmd)?,
        Cmd::Internal { graph, scaffold, from, expand, mermaid, save } => {
            handle_internal(graph.as_deref(), scaffold.as_deref(), &from, expand, mermaid, save.as_deref())?
        }
        Cmd::Run { url, models, max_agents, vote_n, chain_depth, recon, offline, subscription, mcp, creds, focus, objective, out_of_scope, in_scope, scope_file, environment, policy, budget, token_limit, deep_test_limit, coverage_first, depth_first, sample_per_route, revalidate_poc, compliance, jira, only, verbose } => {
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
            cfg.objective = objective;
            cfg.out_of_scope = out_of_scope;
            cfg.pinned = parse_only(&only);
            if let Some(path) = scope_file.as_deref() {
                let sp = harness::scope::ScopePolicy::from_file(std::path::Path::new(path))
                    .map_err(|e| anyhow::anyhow!("scope-file {path}: {e}"))?;
                if sp.hard.is_empty() {
                    println!("  \x1b[33m⚠ {path} sets no hard scope — nothing would be authorized; ignoring it\x1b[0m");
                } else {
                    println!("  \x1b[2mscope-file: {} host rule(s), {} exclusion(s), rate {}rpm\x1b[0m", sp.hard.len(), sp.exclude.len(), sp.soft.max_requests_per_minute);
                    cfg.scope = sp;
                }
            }
            apply_authorization(&mut cfg, &in_scope, cli.capability_token.clone(), &environment, &policy)?;
            apply_budget(&mut cfg, budget.as_deref(), token_limit, deep_test_limit, coverage_first, depth_first, sample_per_route)?;
            apply_network(&mut cfg, &cli)?;
            cfg.intercept = cli.intercept.clone();
            cfg.sandbox = cli.sandbox.clone();
            cfg.revalidate_poc = revalidate_poc;
            cfg.compliance = revalidate_split(&compliance);
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let out = run_engagement(&base, cfg, mcp, false).await?;
            print_findings(&out);
            if let Some(code) = &out.denied { anyhow::bail!("{code}"); }
            let ig = harness::integrations::Integrations::load(&repl::proj_dir());
            post_integrations(&ig, &url, &out, jira, false, None).await;
        }
        Cmd::Whitebox { path, models, max_agents, vote_n, chain_depth, recon, offline, subscription, jira, only, verbose } => {
            let path = resolve_source(&base, &path)?; // local path OR github URL/owner/repo
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.chain_depth = chain_depth;
            cfg.recon_intensity = recon;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.pinned = parse_only(&only);
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
            let ig = harness::integrations::Integrations::load(&repl::proj_dir());
            post_integrations(&ig, &path, &out, jira, false, None).await;
        }
        Cmd::Greybox { repo, url, models, creds, focus, max_agents, vote_n, chain_depth, recon, offline, subscription, mcp, only, verbose } => {
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
            cfg.pinned = parse_only(&only);
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
        Cmd::Mobile { path, models, max_agents, vote_n, offline, subscription, focus, verbose } => {
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() { cfg.models = models; }
            let out = run_mode(&base, cfg, false, Mode::Mobile).await?;
            print_findings(&out);
        }
        Cmd::Container { image, models, max_agents, vote_n, offline, subscription, focus, verbose } => {
            let mut cfg = RunConfig::new(&image);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() { cfg.models = models; }
            let out = run_mode(&base, cfg, false, Mode::Container).await?;
            print_findings(&out);
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
        Cmd::Pr { repo, number, models, vote_n, chain_depth, recon, subscription, comment, fail_on, jira, verbose } => {
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
            // Security gate: block the PR when a confirmed finding is >= threshold.
            if let Some(thresh) = fail_on.as_deref() {
                let blocked = gate_pr(&ig, &owner_repo, number, &out, thresh).await;
                if blocked {
                    eprintln!("  \x1b[1;31m⛔ PR gate: confirmed finding ≥ {thresh} — blocking (exit 2)\x1b[0m");
                    std::process::exit(2);
                } else {
                    println!("  \x1b[1;32m✓ PR gate: nothing ≥ {thresh} — clear\x1b[0m");
                }
            }
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
                            let mut cfg = RunConfig::new(dest.display().to_string());
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
pub(crate) enum Mode { Black, White, Grey, Host, Ai, Skills, Mobile, Container }

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
    // Credential vault lives in the project's .neurosploit store (persistent),
    // NOT the transient run dir, so secrets are kept in one known place.
    let vault_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".neurosploit").join("vault");
    std::fs::create_dir_all(&vault_dir).ok();
    cfg.vault_dir = Some(vault_dir.display().to_string());
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

    println!("  ┌─ NeuroSploit v4.1.0  ·  by Joas A Santos & Red Team Leaders");
    println!("  │  run id : {run_id}");
    println!("  │  target : {}", cfg.target);
    println!("  │  models : {}", cfg.models.join(", "));
    println!("  │  output : {}", workdir.display());
    println!("  │  vault  : {}/{run_id}.json (created test-account credentials; masked in the report)", vault_dir.display());
    if let Mode::Grey = mode {
        println!("  │  repo   : {}", cfg.repo.clone().unwrap_or_default());
    }
    println!("  └─ mode   : {}{}{}",
        match mode { Mode::White => "white-box", Mode::Grey => "greybox", Mode::Host => "host/infra", Mode::Ai => "ai/llm", Mode::Skills => "skills/n8n audit", Mode::Mobile => "mobile/binary", Mode::Container => "container-scan", Mode::Black => "black-box" },
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
            Mode::Mobile => harness::run_mobile(cfg, &lib, &pool, tx).await,
            Mode::Container => harness::run_container(cfg, &lib, &pool, tx).await,
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
    let _ = harness::report::write_all(target, &fs, workdir); // md + json + html + pdf
    write_status(workdir, "stopped-raw", &format!("\"findings\":{}", fs.len()));
}

/// Generate the report + final status for a finished run, ensuring the workdir
/// is always recorded (even on an aborted/partial run).
pub(crate) fn finalize_run(mut out: RunOutput, workdir: &Path) -> RunOutput {
    if out.workdir.is_empty() { out.workdir = workdir.display().to_string(); }
    if out.target.is_empty() {
        out.target = workdir.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    }
    let _ = harness::report::write_all(&out.target, &out.findings, workdir); // md + json + html + pdf
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
    if let Some(code) = &out.denied {
        eprintln!("\n\x1b[1;31m⛔ RUN REFUSED\x1b[0m — {code}");
        eprintln!("  The target was not authorized. Nothing was tested. See audit.jsonl.");
        return;
    }
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

/// Parse repeated `--only` values into a clean agent allowlist. Accepts repeats
/// and comma/semicolon-separated lists (`--only sqli,xss` == `--only sqli --only xss`).
/// Apply the engagement's authorization to a config: extra scope, the signed
/// grant, the environment (which scales every risk score) and the policy
/// profile.
///
/// The token is verified HERE, before anything runs, so an invalid grant fails
/// at the command line with a readable message instead of halfway through an
/// engagement.
fn apply_authorization(
    cfg: &mut RunConfig,
    in_scope: &[String],
    token: Option<String>,
    environment: &str,
    policy: &str,
) -> anyhow::Result<()> {
    use harness::policy::{EngagementPolicy, Environment};

    let env = Environment::parse(environment).ok_or_else(|| {
        anyhow::anyhow!("unknown environment '{environment}' — use lab, development, staging, production or ot-production")
    })?;
    cfg.policy = match policy.trim().to_lowercase().as_str() {
        "ot" | "ics" | "scada" => EngagementPolicy::ot(),
        "web" | "" => EngagementPolicy::web(env),
        other => anyhow::bail!("unknown policy profile '{other}' — use web or ot"),
    };
    cfg.policy.safety.environment = env;

    if !in_scope.is_empty() {
        // Seed from the target first: adding one host to an empty policy would
        // otherwise leave the target itself out of scope.
        if cfg.scope.hard.is_empty() {
            cfg.scope.allow(&harness::scope::host_of(&cfg.target));
        }
        for entry in in_scope {
            cfg.scope.allow(entry);
        }
    }

    cfg.capability = token.or_else(|| std::env::var("NEUROSPLOIT_CAPABILITY").ok()).filter(|t| !t.trim().is_empty());
    match harness::pipeline::verify_capability(cfg) {
        Ok(Some(cap)) => {
            println!("  \x1b[32m🔏 capability verified\x1b[0m — {}", cap.summary());
            let (_, dropped) = cap.constrain(&cfg.scope);
            if !dropped.is_empty() {
                println!("  \x1b[33m⚠ outside the grant, removed from scope:\x1b[0m {}", dropped.join(", "));
            }
        }
        Ok(None) => {}
        Err(e) => anyhow::bail!("{e}"),
    }
    Ok(())
}

#[derive(Subcommand)]
enum SandboxCmd {
    /// Pull the image and start the container.
    Up {
        /// Image (default kalilinux/kali-rolling).
        #[arg(long)]
        image: Option<String>,
        /// Host path mounted at /work.
        #[arg(long)]
        mount: Option<String>,
    },
    /// Run a command inside the container.
    Exec {
        /// The command line to run.
        command: Vec<String>,
        #[arg(long)]
        image: Option<String>,
    },
    /// Install packages inside the container (e.g. sqlmap ffuf nuclei).
    Install {
        packages: Vec<String>,
    },
    /// Stop and remove the container.
    Down,
}

#[derive(Subcommand)]
enum ProvCmd {
    /// Print this build's fingerprint and the markers it mints.
    Show,
    /// Find NeuroSploit markers in a file — a report, a log, a response body.
    /// Answers "did this come from us?" for a document that arrived from
    /// somewhere else.
    Scan {
        /// File to search.
        path: String,
    },
    /// Check a run's provenance.json against its findings.json.
    Verify {
        /// Run directory (the one holding provenance.json and findings.json).
        dir: String,
    },
}

#[derive(Subcommand)]
enum CapCmd {
    /// Mint a token. Requires the signing key (NEUROSPLOIT_CAPABILITY_KEY),
    /// which is what makes the grant attributable to whoever authorized it.
    Issue {
        /// Hosts this grant covers: host · *.domain · 10.0.0.0/24 · https://host/path.
        #[arg(long = "scope", required = true)]
        scope: Vec<String>,
        /// Carve-outs inside that scope.
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Who authorized it (client contact, ticket, system).
        #[arg(long)]
        issuer: String,
        /// Who it is issued to.
        #[arg(long)]
        subject: String,
        /// Hours until it expires. A grant without an end is a standing
        /// permission nobody remembers issuing.
        #[arg(long, default_value = "72")]
        hours: u64,
        /// Strongest permitted action: read · enumerate · authenticate ·
        /// probe-exploit · write · disruptive.
        #[arg(long = "max-action", default_value = "probe-exploit")]
        max_action: String,
        /// Ceiling on effective_risk.
        #[arg(long = "max-risk", default_value = "3.5")]
        max_risk: f64,
        /// lab · development · staging · production · ot-production.
        #[arg(long, default_value = "production")]
        environment: String,
        /// Engagement reference (SOW, ticket).
        #[arg(long, default_value = "")]
        reference: String,
    },
    /// Verify a token and print what it grants.
    Verify {
        token: String,
    },
}

/// Signing key for run manifests. Separate from the capability key: one
/// authorizes an engagement, the other attests to its output.
fn provenance_key() -> Option<Vec<u8>> {
    std::env::var("NEUROSPLOIT_PROVENANCE_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes())
}

fn handle_internal(
    graph: Option<&str>,
    scaffold: Option<&str>,
    from: &str,
    expand: usize,
    mermaid: bool,
    save: Option<&str>,
) -> anyhow::Result<()> {
    use harness::internal::InternalGraph;
    let mut g = match (graph, scaffold) {
        (Some(path), _) => {
            let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
            let mut loaded: InternalGraph = serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("{path} is not an internal graph: {e}"))?;
            // A loaded graph plus the scaffold: the domain's built-in structure
            // is true whether or not the operator typed it out.
            if let Some(domain) = scaffold {
                let base = harness::internal::ad_scaffold(domain);
                for n in base.nodes {
                    loaded.add(n);
                }
                for e in base.edges {
                    loaded.link(e);
                }
            }
            loaded
        }
        (None, Some(domain)) => harness::internal::ad_scaffold(domain),
        (None, None) => anyhow::bail!("nothing to work with — pass --graph <file.json> or --scaffold <domain>"),
    };
    if !g.has(from) {
        anyhow::bail!(
            "no node `{from}` in the graph — known nodes: {}",
            g.nodes.iter().map(|n| n.id.clone()).collect::<Vec<_>>().join(", ")
        );
    }
    let turns = g.expand(expand);
    println!("  \x1b[2mcredential loop turned {turns} time(s)\x1b[0m");
    print!("  {}", g.summary(from));

    let proven = g.paths(from, true);
    let all = g.paths(from, false);
    if proven.is_empty() && !all.is_empty() {
        println!("  \x1b[33mno path was walked end to end — {} hypothesis(es) to test next:\x1b[0m", all.len());
        for p in all.iter().take(5) {
            for a in &p.assumptions {
                println!("    · {a}");
            }
        }
    }
    let gaps = g.detection_gaps();
    if !gaps.is_empty() {
        println!("  \x1b[2m{} proven hop(s) with no detection answer — untested, not unmonitored\x1b[0m", gaps.len());
    }
    if mermaid {
        println!("\n{}", g.mermaid());
    }
    if let Some(path) = save {
        std::fs::write(path, serde_json::to_string_pretty(&g)?)?;
        println!("  saved {path}");
    }
    Ok(())
}

fn resolve_run(base: &std::path::Path, run: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = std::path::PathBuf::from(run);
    let dir = if dir.is_dir() { dir } else { base.join("runs").join(run) };
    if !dir.is_dir() {
        anyhow::bail!("no such run directory: {}", dir.display());
    }
    Ok(dir)
}

fn load_findings(dir: &std::path::Path) -> anyhow::Result<Vec<harness::types::Finding>> {
    let text = std::fs::read_to_string(dir.join("findings.json"))
        .map_err(|e| anyhow::anyhow!("no findings.json in {}: {e}", dir.display()))?;
    Ok(serde_json::from_str(&text)?)
}

fn handle_assurance(base: &std::path::Path, run: &str, verify: bool) -> anyhow::Result<()> {
    let dir = resolve_run(base, run)?;
    let key = std::env::var("NEUROSPLOIT_PROVENANCE_KEY").ok().filter(|k| !k.trim().is_empty()).map(|k| k.into_bytes());
    if verify {
        let text = std::fs::read_to_string(dir.join("assurance.json"))
            .map_err(|e| anyhow::anyhow!("no assurance.json in {}: {e}", dir.display()))?;
        let bundle: harness::assurance::Bundle = serde_json::from_str(&text)?;
        match bundle.verify(&dir, key.as_deref()) {
            Ok(()) => println!("  \x1b[1;32m✓ assurance bundle verified\x1b[0m — {} artifact(s){}", bundle.artifacts.iter().filter(|a| a.present).count(), if key.is_some() { ", signature valid" } else { " (signature NOT checked)" }),
            Err(e) => { println!("  \x1b[1;31m✗ {e}\x1b[0m"); anyhow::bail!("assurance verification failed"); }
        }
    } else {
        let bundle = harness::assurance::Bundle::build(&dir);
        let bundle = match &key { Some(k) => bundle.sign(k), None => bundle };
        let out = dir.join("assurance.json");
        std::fs::write(&out, serde_json::to_string_pretty(&bundle)?)?;
        print!("\n{}", bundle.summary());
        println!("  \x1b[2mbundle hash {} · saved → {}\x1b[0m", &bundle.bundle_hash[..16.min(bundle.bundle_hash.len())], out.display());
    }
    Ok(())
}

fn handle_traffic(base: &std::path::Path, run: &str) -> anyhow::Result<()> {
    let dir = resolve_run(base, run)?;
    let flows = std::fs::read_to_string(dir.join("flows.jsonl"))
        .map_err(|e| anyhow::anyhow!("no flows.jsonl in {} (was the run started with --intercept own?): {e}", dir.display()))?;
    let mut out = String::from("# NeuroSploit HTTP traffic archive\n# One exchange per block; bodies are not captured for tunnelled HTTPS.\n\n");
    let mut n = 0usize;
    for line in flows.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(x) => x, Err(_) => continue };
        let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("GET");
        let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
        let status = v.get("status").and_then(|x| x.as_u64()).unwrap_or(0);
        let ct = v.get("content_type").and_then(|x| x.as_str()).unwrap_or("");
        out.push_str(&format!("### {method} {url}\n=> HTTP {status} {ct}\n\n"));
        n += 1;
    }
    let dest = dir.join("traffic.http");
    std::fs::write(&dest, out)?;
    println!("  exported {n} exchange(s) -> {}", dest.display());
    Ok(())
}

fn handle_audit(base: &std::path::Path, run: &str, anchor: bool) -> anyhow::Result<()> {
    let dir = resolve_run(base, run)?;
    let log = harness::audit::AuditLog::open(dir.join("audit.jsonl"));
    if anchor {
        // A provenance key verifies anchor signatures too; without it we still
        // catch truncation and rebuilds by hash, and say the sigs are unchecked.
        let key = std::env::var("NEUROSPLOIT_PROVENANCE_KEY").ok().filter(|k| !k.trim().is_empty()).map(|k| k.into_bytes());
        match log.verify_anchored(key.as_deref()) {
            Ok(rep) => {
                println!("  \x1b[1;32m✓ audit chain intact\x1b[0m — {} record(s)", rep.records);
                println!("  \x1b[1;32m✓ {} anchor(s) consistent\x1b[0m{}", rep.anchors, if rep.signed { " (signatures verified)" } else { " (signatures NOT checked — set NEUROSPLOIT_PROVENANCE_KEY)" });
            }
            Err(e) => {
                println!("  \x1b[1;31m✗ {e}\x1b[0m");
                anyhow::bail!("audit verification failed");
            }
        }
    } else {
        match log.verify() {
            Ok(n) => println!("  \x1b[1;32m✓ audit chain intact\x1b[0m — {n} record(s). (Add --anchor to check truncation/rebuild.)"),
            Err(e) => { println!("  \x1b[1;31m✗ {e}\x1b[0m"); anyhow::bail!("audit verification failed"); }
        }
    }
    Ok(())
}

fn handle_compliance(base: &std::path::Path, run: &str, frameworks: &[String], include_leads: bool) -> anyhow::Result<()> {
    use harness::compliance::{map_findings, Framework};
    let dir = resolve_run(base, run)?;
    let findings = load_findings(&dir)?;
    let wanted: Vec<Framework> = if frameworks.is_empty() {
        Framework::all().to_vec()
    } else {
        frameworks.iter().flat_map(|v| v.split([',', ';'])).filter_map(|f| Framework::parse(f.trim())).collect()
    };
    if wanted.is_empty() {
        anyhow::bail!("no recognised framework — use pci-dss, hipaa or soc2");
    }
    for fw in wanted {
        let report = map_findings(&findings, fw, !include_leads);
        let md = report.to_markdown();
        let out = dir.join(format!("compliance-{}.md", fw.as_str()));
        std::fs::write(&out, &md)?;
        println!("\n{}", md);
        println!("  \x1b[2msaved → {}\x1b[0m", out.display());
    }
    Ok(())
}

async fn handle_poc(base: &std::path::Path, run: &str, repeats: usize, apply: bool) -> anyhow::Result<()> {
    let dir = resolve_run(base, run)?;
    let mut findings = load_findings(&dir)?;
    // Scope the replay to the hosts the findings are on — a re-validation run
    // must not reach past where the engagement was authorized.
    let target = findings.iter().map(|f| harness::scope::host_of(&f.endpoint)).find(|h| !h.is_empty()).unwrap_or_default();
    let policy = harness::scope::ScopePolicy::for_target(&format!("https://{target}"));
    let validator = harness::poc::PocValidator::new(policy).with_repeats(repeats);
    println!("  re-validating {} finding(s)…", findings.len());
    let results = validator.validate_all(&findings).await;
    for r in &results {
        let color = match r.reproduction {
            harness::poc::Reproduction::Reproduced => "1;32",
            harness::poc::Reproduction::Gone => "1;31",
            harness::poc::Reproduction::Changed => "1;33",
            harness::poc::Reproduction::Unverifiable => "2",
        };
        println!("  \x1b[{color}m{:<13}\x1b[0m {}", r.reproduction.as_str(), r.detail);
    }
    println!("\n  {}", harness::poc::summary(&results));
    if apply {
        let by_id: std::collections::HashMap<&str, &harness::poc::PocResult> = results.iter().map(|r| (r.finding_id.as_str(), r)).collect();
        for f in findings.iter_mut() {
            if let Some(r) = by_id.get(f.id.as_str()) {
                harness::poc::apply(f, r);
            }
        }
        std::fs::write(dir.join("findings.json"), serde_json::to_string_pretty(&findings)?)?;
        println!("  \x1b[2mwrote demotions back to findings.json — run `neurosploit rebuild {run}` to refresh the report\x1b[0m");
    }
    Ok(())
}

async fn handle_sandbox(cmd: SandboxCmd) -> anyhow::Result<()> {
    use harness::sandbox::{Sandbox, SandboxConfig};
    let mk = |image: Option<String>, mount: Option<String>| -> anyhow::Result<Sandbox> {
        let mut sc = SandboxConfig::default();
        if let Some(i) = image { sc = sc.with_image(&i); }
        if let Some(m) = mount { sc = sc.mounting(&m); }
        Sandbox::new(sc).map_err(|e| anyhow::anyhow!(e))
    };
    match cmd {
        SandboxCmd::Up { image, mount } => {
            let sb = mk(image, mount)?;
            println!("  {} runtime", sb.runtime().bin());
            match sb.ensure().await {
                Ok(msg) => println!("  \x1b[1;32m✓\x1b[0m {msg}"),
                Err(e) => anyhow::bail!(e),
            }
        }
        SandboxCmd::Exec { command, image } => {
            let sb = mk(image, None)?;
            let line = command.join(" ");
            if line.trim().is_empty() { anyhow::bail!("nothing to run"); }
            let r = sb.exec(&line).await.map_err(|e| anyhow::anyhow!(e))?;
            print!("{}", r.stdout);
            eprint!("{}", r.stderr);
            if r.timed_out { anyhow::bail!("command timed out"); }
            std::process::exit(r.code);
        }
        SandboxCmd::Install { packages } => {
            if packages.is_empty() { anyhow::bail!("name at least one package"); }
            let sb = mk(None, None)?;
            let refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
            println!("  installing {} in the sandbox…", refs.join(", "));
            let r = sb.install(&refs).await.map_err(|e| anyhow::anyhow!(e))?;
            if r.ok() { println!("  \x1b[1;32m✓ installed\x1b[0m"); } else { eprintln!("{}", r.stderr); anyhow::bail!("install failed"); }
        }
        SandboxCmd::Down => {
            let sb = mk(None, None)?;
            sb.teardown().await;
            println!("  container removed");
        }
    }
    Ok(())
}

fn handle_provenance(cmd: ProvCmd) -> anyhow::Result<()> {
    use harness::provenance::{Manifest, Provenance, SIGIL};
    match cmd {
        ProvCmd::Show => {
            let p = Provenance::process();
            println!("  \x1b[1mbuild\x1b[0m      {}", p.build);
            println!("  \x1b[1mversion\x1b[0m    {}", p.version);
            println!("  \x1b[1mcustomer\x1b[0m   {}", p.customer.clone().unwrap_or_else(|| "(none — set NEUROSPLOIT_CUSTOMER_ID for a per-customer build)".into()));
            println!("  \x1b[1mtag\x1b[0m        {}", p.tag());
            println!("  \x1b[1msample\x1b[0m     {}", p.marker("xss"));
            println!("  \x1b[2msigil {SIGIL} — grep for it to find every trace at once\x1b[0m");
            println!("  \x1b[2msigning:   {}\x1b[0m", if provenance_key().is_some() { "NEUROSPLOIT_PROVENANCE_KEY set — manifests are signed" } else { "no key — manifests name the build but cannot prove it" });
        }
        ProvCmd::Scan { path } => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
            let marks = Provenance::extract(&text);
            if marks.is_empty() {
                println!("  no NeuroSploit markers in {path}");
                return Ok(());
            }
            println!("  {} marker(s) in {path}:", marks.len());
            for m in &marks {
                println!("    {m}");
            }
            // A marker carrying this build's fingerprint came from this binary;
            // one that does not still came from NeuroSploit, just elsewhere.
            let mine = marks.iter().filter(|m| m.contains(&Provenance::process().build[..6])).count();
            println!("  \x1b[2m{mine} of them minted by this build ({}), the rest by another\x1b[0m", Provenance::process().build);
        }
        ProvCmd::Verify { dir } => {
            let dir = std::path::Path::new(&dir);
            let manifest: Manifest = serde_json::from_str(
                &std::fs::read_to_string(dir.join("provenance.json"))
                    .map_err(|e| anyhow::anyhow!("no provenance.json in {}: {e}", dir.display()))?,
            )?;
            let findings: Vec<harness::types::Finding> = serde_json::from_str(
                &std::fs::read_to_string(dir.join("findings.json"))
                    .map_err(|e| anyhow::anyhow!("no findings.json in {}: {e}", dir.display()))?,
            )?;
            println!("  engine   {} {} · build {}", manifest.engine, manifest.version, manifest.build);
            println!("  run      {} · {} finding(s) claimed", manifest.run, manifest.findings);
            match provenance_key() {
                Some(k) => match manifest.verify(&k, &findings) {
                    Ok(()) => println!("  \x1b[1;32m✓ signature valid and findings match the manifest\x1b[0m"),
                    Err(e) => {
                        println!("  \x1b[1;31m✗ {e}\x1b[0m");
                        anyhow::bail!("provenance verification failed");
                    }
                },
                None => {
                    // Without the key the structure can still be checked, which
                    // catches an edited finding set even though it cannot catch
                    // a forged manifest. Say which of the two this is.
                    let actual = harness::provenance::structural_signature(&findings);
                    if actual == manifest.structure {
                        println!("  \x1b[33m~ findings match the manifest's structure, but no NEUROSPLOIT_PROVENANCE_KEY is set — the manifest itself is unverified\x1b[0m");
                    } else {
                        println!("  \x1b[1;31m✗ findings do not match the manifest: {actual} vs {}\x1b[0m", manifest.structure);
                        anyhow::bail!("provenance verification failed");
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_capability(cmd: CapCmd) -> anyhow::Result<()> {
    use harness::capability::{key_from_env, Capability};
    use harness::policy::{ActionKind, Environment};

    let key = key_from_env().ok_or_else(|| {
        anyhow::anyhow!("no signing key — set NEUROSPLOIT_CAPABILITY_KEY or NEUROSPLOIT_CAPABILITY_KEY_FILE")
    })?;
    match cmd {
        CapCmd::Issue { scope, exclude, issuer, subject, hours, max_action, max_risk, environment, reference } => {
            let env = Environment::parse(&environment)
                .ok_or_else(|| anyhow::anyhow!("unknown environment '{environment}'"))?;
            let action = match max_action.trim().to_lowercase().replace('_', "-").as_str() {
                "read" => ActionKind::Read,
                "enumerate" => ActionKind::Enumerate,
                "authenticate" => ActionKind::Authenticate,
                "probe-exploit" | "exploit" => ActionKind::ProbeExploit,
                "write" => ActionKind::Write,
                "disruptive" => ActionKind::Disruptive,
                other => anyhow::bail!("unknown action '{other}'"),
            };
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let cap = Capability {
                id: format!("cap-{now:x}"),
                issuer,
                subject,
                scope,
                exclude,
                environment: env,
                max_action: action,
                max_risk,
                expires_at: now + hours * 3600,
                not_before: 0,
                reference,
            };
            println!("{}", cap.issue(&key));
            eprintln!("  \x1b[2m{}\x1b[0m", cap.summary());
        }
        CapCmd::Verify { token } => match Capability::verify(&token, &key) {
            Ok(c) => {
                println!("  \x1b[32m🔏 verified\x1b[0m — {}", c.summary());
                println!("{}", serde_json::to_string_pretty(&c).unwrap_or_default());
            }
            Err(e) => anyhow::bail!("{e}"),
        },
    }
    Ok(())
}

/// Translate the budget flags into a configuration.
///
/// Omitting them all leaves `Budget::default()`, which is unlimited — the run
/// behaves exactly as it did before any of this existed. A budget is something
/// an operator opts into, never a silent cap on a run they asked for in full.
fn apply_budget(
    cfg: &mut RunConfig,
    mode: Option<&str>,
    token_limit: Option<u64>,
    deep_test_limit: Option<usize>,
    coverage_first: bool,
    depth_first: bool,
    sample_per_route: usize,
) -> anyhow::Result<()> {
    use harness::budget::{Budget, Mode, Order};
    if mode.is_none() && token_limit.is_none() && deep_test_limit.is_none() && !coverage_first && !depth_first {
        cfg.budget.sample_per_route = sample_per_route.max(1);
        return Ok(());
    }
    let m = match mode {
        Some(s) => Mode::parse(s).ok_or_else(|| anyhow::anyhow!("unknown budget '{s}' — use eco, balanced, aggressive or unlimited"))?,
        // A token ceiling with no strategy still needs one to spend under.
        None => Mode::Balanced,
    };
    let mut b = Budget::with_mode(m);
    if let Some(t) = token_limit {
        b.token_limit = t;
    }
    if let Some(d) = deep_test_limit {
        b.max_deep_tests = d;
    }
    if coverage_first && depth_first {
        anyhow::bail!("--coverage-first and --depth-first are opposites; pick one");
    }
    b.order = if depth_first { Order::DepthFirst } else { Order::CoverageFirst };
    b.sample_per_route = sample_per_route.max(1);
    println!("  \x1b[2mbudget: {}\x1b[0m", b.summary());
    cfg.budget = b;
    Ok(())
}

/// Egress route, out-of-band channel and inbound SMS.
///
/// The transport spec is parsed here rather than at run time so a typo fails
/// on the command line instead of three minutes into an engagement.
fn apply_network(cfg: &mut RunConfig, cli: &Cli) -> anyhow::Result<()> {
    let (transport, oob_domain, oob_http, oob_dns, sms) = (
        cli.transport.clone(),
        cli.oob_domain.clone(),
        cli.oob_http.clone(),
        cli.oob_dns.clone(),
        cli.sms.clone(),
    );
    if let Some(spec) = transport {
        let egress = harness::transport::Egress::parse(&spec).map_err(|e| anyhow::anyhow!(e))?;
        println!("  \x1b[2megress: {}\x1b[0m", egress.label());
        cfg.transport = Some(spec);
    }
    if let Some(d) = oob_domain {
        if !d.contains('.') {
            anyhow::bail!("--oob-domain needs a real domain whose wildcard points at this host");
        }
        println!("  \x1b[2mout-of-band: *.{d}\x1b[0m");
        cfg.oob_domain = Some(d);
    }
    for (val, label) in [(&oob_http, "--oob-http"), (&oob_dns, "--oob-dns")] {
        if let Some(v) = val {
            v.parse::<std::net::SocketAddr>()
                .map_err(|_| anyhow::anyhow!("{label} must be host:port, got `{v}`"))?;
        }
    }
    cfg.oob_http = oob_http;
    cfg.oob_dns = oob_dns;
    cfg.sms = sms;
    Ok(())
}

/// Split comma/semicolon-joined framework names into a flat, lowercased list.
fn revalidate_split(vals: &[String]) -> Vec<String> {
    vals.iter()
        .flat_map(|v| v.split([',', ';']))
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_only(vals: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in vals {
        for part in v.split([',', ';']) {
            let name = part.trim();
            if !name.is_empty() && !out.iter().any(|x| x == name) {
                out.push(name.to_string());
            }
        }
    }
    out
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
/// Enforce the PR security gate. Sets a GitHub commit status (success/failure)
/// on the PR head and, when it trips, submits a REQUEST_CHANGES review so branch
/// protection blocks the merge. Best-effort on the API calls (a token may be
/// absent locally); returns whether the gate tripped so the caller can exit 2.
async fn gate_pr(
    ig: &harness::integrations::Integrations,
    owner_repo: &str,
    number: u64,
    out: &RunOutput,
    threshold: &str,
) -> bool {
    use harness::integrations as gi;
    let tripped = gi::gate_trips(&out.findings, threshold);
    if ig.github.enabled {
        let (state, desc) = if tripped {
            ("failure", format!("Confirmed finding ≥ {threshold} — merge blocked by NeuroSploit"))
        } else {
            ("success", "No confirmed finding at/above the gate threshold".to_string())
        };
        // Attach the status to the PR head SHA (looked up from the API).
        match ig.github_pr_head_sha(owner_repo, number).await {
            Ok(sha) => {
                if let Err(e) = ig.github_set_status(owner_repo, &sha, state, "neurosploit/security", &desc, None).await {
                    eprintln!("  github status: {e}");
                }
            }
            Err(e) => eprintln!("  github PR head lookup: {e}"),
        }
        if tripped {
            let body = format!("## ⛔ NeuroSploit security gate\n\nBlocking this PR: a **confirmed** finding is **{threshold}** or worse.\n\n{}", pr_comment_body(out));
            if let Err(e) = ig.github_pr_review(owner_repo, number, "REQUEST_CHANGES", &body).await {
                eprintln!("  github review: {e}");
            }
        }
    }
    tripped
}

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

