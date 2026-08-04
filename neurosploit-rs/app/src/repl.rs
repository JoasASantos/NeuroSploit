//! NeuroSploit v3.6.7 — interactive session (Claude-Code / Codex / Cursor-CLI style).
//!
//! Launched when `neurosploit` runs with no subcommand. A persistent REPL with
//! real line editing (arrow-key history recall, Ctrl-A/E/K, paste), model
//! selection (arrow-key multi-select), API-key configuration based on the chosen
//! models, target/repo/auth/instructions, run history, and reports.

use dialoguer::{theme::ColorfulTheme, MultiSelect};
use harness::{agents, models::ModelRef, types::Finding, types::RunConfig};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::FileHistory;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Cmd, CompletionType, Config, Context, Editor, ExternalPrinter, Helper, KeyEvent};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Live state of a background run, updated from the engagement stream so the
/// composer can answer /status while the runner works.
struct RunLive {
    target: String,
    mode: &'static str,
    phase: String,
    started: Instant,
    findings: Vec<(String, String)>, // sev, title (summary)
    full: Vec<Finding>,              // full candidate findings (PoC, evidence) for /finding
    commands: Vec<String>,           // full untruncated commands for /expand & Ctrl+O
    agents: usize,
    agents_done: usize,
    last: String,                    // last meaningful activity line (sign of life)
    lines: usize,                    // total streamed lines (activity counter)
    feed: Vec<String>,               // recent raw activity lines for /logs (capped)
}
impl RunLive {
    /// progress fraction in [0,1] (agents completed / total selected).
    fn progress(&self) -> f64 {
        if self.agents == 0 { return 0.0; }
        (self.agents_done as f64 / self.agents as f64).clamp(0.0, 1.0)
    }
    fn bar(&self, width: usize) -> String {
        let filled = (self.progress() * width as f64).round() as usize;
        format!("[{}{}] {}/{} ({:.0}%)",
            "█".repeat(filled), "░".repeat(width.saturating_sub(filled)),
            self.agents_done, self.agents, self.progress() * 100.0)
    }
    fn ingest(&mut self, line: &str) {
        let low = line.to_lowercase();
        self.lines += 1;
        // Keep a compact activity trail for /logs and the /status sign-of-life.
        // Streamed agent events are tagged "@label <event>": keep the actionable
        // ones (commands, net, tools, file edits, phases) so the operator sees
        // exactly what each agent is running — drop only long model reasoning
        // (ai:), token telemetry (tokens:), and machine JSON (finding_json:).
        let payload = line.strip_prefix('@')
            .and_then(|r| r.split_once(' ').map(|(_, rest)| rest))
            .unwrap_or(line);
        let plow = payload.to_lowercase();
        if !low.starts_with("finding_json:") && !plow.starts_with("ai:") && !plow.starts_with("tokens:") {
            let clean: String = line.chars().take(160).collect();
            self.last = clean.clone();
            self.feed.push(clean);
            if self.feed.len() > 200 { self.feed.remove(0); }
        }
        if low.contains("token/quota exhausted") || low.contains("run is paused") { self.phase = "paused (quota)".into(); }
        else if low.contains("resumed — retrying") { self.phase = "exploiting".into(); }
        else if low.starts_with("recon") || low.starts_with("ai-recon") || low.contains("recon round") || low.contains("intensity") || low.starts_with("probe:") { self.phase = "recon".into(); }
        else if low.contains("selected") && low.contains("agent") {
            self.phase = "planning".into();
            if let Some(n) = line.split_whitespace().find_map(|t| t.parse::<usize>().ok()) { self.agents = n; }
        }
        else if low.starts_with("exploit") || low.starts_with("test ") || low.contains("launching agent") { self.phase = "exploiting".into(); }
        else if low.starts_with("vote") || low.contains("validating") { self.phase = "validating".into(); }
        else if low.starts_with("chain") { self.phase = "chaining".into(); }
        else if low.contains("phase complete") || low.contains("validated finding(s)") { self.phase = "complete".into(); }
        // count completed agents (each emits "... via <model> → N candidate(s)")
        if low.contains("candidate(s)") && (low.starts_with("exploit ") || low.starts_with("test ") || low.starts_with("analyze ") || low.starts_with("review ")) {
            self.agents_done += 1;
        }
        if let Some(rest) = line.strip_prefix("finding: ") {
            if let Some(b) = rest.strip_prefix('[') {
                if let Some((sev, tail)) = b.split_once(']') {
                    let title = tail.trim().split(" @ ").next().unwrap_or(tail.trim());
                    self.findings.push((sev.to_string(), title.to_string()));
                }
            }
        }
        // Full candidate finding (with PoC/evidence) for /results & /finding.
        if let Some(j) = line.strip_prefix("finding_json: ") {
            if let Ok(f) = serde_json::from_str::<Finding>(j) { self.full.push(f); }
        }
        // Full untruncated command for /expand & Ctrl+O.
        let cmd_part = line.strip_prefix('@').and_then(|s| s.split_once(' ').map(|(_, r)| r)).unwrap_or(line);
        if let Some(c) = cmd_part.strip_prefix("exec: ").or_else(|| cmd_part.strip_prefix("danger: ")) {
            self.commands.push(c.to_string());
            if self.commands.len() > 100 { self.commands.remove(0); }
        }
    }
}

/// What to do when the user stops a run.
#[derive(Clone, Copy, PartialEq)]
enum StopMode { Run, Validate, Raw, Discard }

/// A run executing in the background of the REPL.
struct ActiveRun {
    live: Arc<Mutex<RunLive>>,
    cancel: Arc<AtomicBool>,
    soft: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    choice: Arc<Mutex<StopMode>>,
    /// Set when the run is parked on token/quota exhaustion (awaiting /continue).
    paused: Arc<AtomicBool>,
    /// Wakes the parked run when the user runs /continue.
    resume: Arc<tokio::sync::Notify>,
    /// Fallback models to try first, pushed by /continue <provider:model>.
    fallback: Arc<Mutex<Vec<ModelRef>>>,
    /// Suppress live background printing while a full-screen picker (dialoguer)
    /// is open, so the two don't fight over the terminal and corrupt it. The
    /// stream is still ingested (feed/checkpoint), just not printed meanwhile.
    quiet: Arc<AtomicBool>,
}

/// On-disk checkpoint of an in-flight run's findings/commands, written live so a
/// run survives quitting/crashing — recovered into /runs on the next launch.
#[derive(Serialize, Deserialize, Clone, Default)]
struct LiveCheckpoint {
    target: String,
    mode: String,
    phase: String,
    workdir: String,
    findings: Vec<Finding>,
    commands: Vec<String>,
}

/// All slash-commands, for Tab completion.
const COMMANDS: &[&str] = &[
    "/help", "/onboard", "/show", "/config", "/providers", "/model", "/key", "/sub", "/target",
    "/repo", "/auth", "/creds", "/focus", "/objective", "/scope-out", "/attach", "/context", "/mcp", "/offline",
    "/votes", "/chain", "/recon", "/tempmail", "/timeout", "/proxy", "/burp", "/ua", "/agents", "/theme", "/clear", "/run", "/stop", "/continue", "/runs", "/results", "/report",
    "/status", "/logs", "/diff", "/retest", "/validate", "/finding", "/expand", "/integrations", "/quit",
];

/// rustyline helper: Tab-completes `/commands` and `@filesystem-paths`,
/// and supports multiline input (a line ending with `\` continues).
struct NsHelper;

impl Completer for NsHelper {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let head = &line[..pos];
        // current "word" = text after the last whitespace
        let start = head.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
        let word = &head[start..];
        if let Some(p) = word.strip_prefix('@') {
            return Ok((start, complete_path(p)));
        }
        if word.starts_with('/') || (start == 0 && word.is_empty()) {
            let cands = COMMANDS.iter()
                .filter(|c| c.starts_with(word))
                .map(|c| Pair { display: c.to_string(), replacement: format!("{c} ") })
                .collect();
            return Ok((start, cands));
        }
        Ok((start, vec![]))
    }
}

fn complete_path(prefix: &str) -> Vec<Pair> {
    let (dir, frag) = match prefix.rfind('/') {
        Some(i) => (&prefix[..=i], &prefix[i + 1..]),
        None => ("", prefix),
    };
    let read_dir = if dir.is_empty() { ".".to_string() } else { dir.to_string() };
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&read_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(frag) {
                let is_dir = e.path().is_dir();
                let full = format!("@{dir}{name}{}", if is_dir { "/" } else { "" });
                out.push(Pair { display: format!("{name}{}", if is_dir { "/" } else { "" }), replacement: full });
            }
        }
    }
    out.truncate(40);
    out
}

impl Hinter for NsHelper { type Hint = String; }
impl Highlighter for NsHelper {
    // Color the prompt for display only. rustyline measures the ORIGINAL (plain)
    // prompt for cursor width, so adding ANSI here does NOT break line editing —
    // unlike embedding escapes in the prompt string passed to readline().
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> std::borrow::Cow<'b, str> {
        if prompt.trim_start().starts_with("neurosploit") {
            std::borrow::Cow::Owned(format!("\x1b[35m{prompt}\x1b[0m"))
        } else {
            std::borrow::Cow::Borrowed(prompt)
        }
    }
}
impl Validator for NsHelper {
    fn validate(&self, ctx: &mut ValidationContext<'_>) -> rustyline::Result<ValidationResult> {
        if ctx.input().ends_with('\\') {
            Ok(ValidationResult::Incomplete) // multiline: backslash continues
        } else {
            Ok(ValidationResult::Valid(None))
        }
    }
}
impl Helper for NsHelper {}

/// A run completed within this session (persisted to disk for /runs across sessions).
#[derive(Serialize, Deserialize, Clone)]
struct RunRecord {
    id: usize,
    mode: String,
    target: String,
    workdir: String,
    findings: Vec<Finding>,
}

struct Session {
    models: Vec<String>,
    subscription: bool,
    mcp: bool,
    vote_n: usize,
    max_agents: usize,
    chain_depth: usize,
    recon_intensity: usize,
    /// Opt-in disposable email (mail.tm) for register flows needing a confirmation code.
    temp_email: bool,
    /// Idle guardrail: stop a run if no NEW finding lands in this many seconds
    /// (0 = disabled). Set in minutes via `/timeout <mins>`.
    idle_secs: u64,
    /// Local intercepting proxy (Burp/ZAP), e.g. http://127.0.0.1:8080.
    proxy: Option<String>,
    /// Identifying User-Agent for NeuroSploit traffic (None = default UA).
    user_agent: Option<String>,
    offline: bool,
    target: Option<String>,
    repo: Option<String>,
    auth: Option<String>,
    /// Named identities for multi-role access-control testing (name, header line).
    roles: Vec<(String, String)>,
    creds: Option<String>,
    instructions: Option<String>,
    /// Engagement objective / rules-of-engagement context (why + what matters).
    objective: Option<String>,
    /// Explicit out-of-scope exclusions the agents must not touch.
    out_of_scope: Option<String>,
    attachments: Vec<String>,
    color: bool,
    /// Engagement scope from onboarding: web | infra | cloud | ai | skills.
    scope: &'static str,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            models: vec!["anthropic:claude-opus-4-8".into()],
            subscription: harness::installed_cli_backends().contains(&"claude"),
            mcp: false,
            vote_n: 3,
            max_agents: 0,
            chain_depth: 2,
            recon_intensity: 3,
            temp_email: false,
            idle_secs: 300, // 5-minute idle guardrail by default
            proxy: None,
            user_agent: None,
            offline: false,
            target: None,
            repo: None,
            auth: None,
            roles: Vec::new(),
            creds: None,
            instructions: None,
            objective: None,
            out_of_scope: None,
            attachments: Vec::new(),
            color: true,
            scope: "web",
        }
    }
}

/// Line reader: full rustyline editing (Tab-complete, history, multiline) when
/// interactive, plain stdin when piped.
enum Reader {
    Rl(Box<Editor<NsHelper, FileHistory>>, std::path::PathBuf),
    Plain(std::io::Stdin),
}

impl Reader {
    fn new(_base: &Path) -> Reader {
        if std::io::stdin().is_terminal() {
            // List completion → @path shows a file/folder menu (Claude-Code-style).
            let cfg = Config::builder().auto_add_history(false)
                .completion_type(CompletionType::List).build();
            if let Ok(mut ed) = Editor::<NsHelper, FileHistory>::with_config(cfg) {
                ed.set_helper(Some(NsHelper));
                // Ctrl+O pre-fills /expand to dump the last full (untruncated) commands.
                ed.bind_sequence(KeyEvent::ctrl('o'), Cmd::Insert(1, "/expand".to_string()));
                let hist = proj_dir().join("history.txt");
                let _ = ed.load_history(&hist);
                return Reader::Rl(Box::new(ed), hist);
            }
        }
        Reader::Plain(std::io::stdin())
    }

    /// An external printer that can write *above* the prompt from another task —
    /// this is what lets a background run stream live while you keep typing.
    fn external_printer(&mut self) -> Option<Box<dyn ExternalPrinter + Send>> {
        match self {
            Reader::Rl(ed, _) => ed.create_external_printer().ok().map(|p| Box::new(p) as Box<dyn ExternalPrinter + Send>),
            Reader::Plain(_) => None,
        }
    }

    /// Returns None to exit (EOF / Ctrl-D), Some(line) otherwise. Ctrl-C cancels
    /// the current line (returns an empty string) instead of exiting.
    /// `prompt` is the dynamic context bar + prompt to show.
    fn read(&mut self, prompt: &str) -> Option<String> {
        match self {
            Reader::Rl(ed, hist) => match ed.readline(prompt) {
                Ok(l) => {
                    // Join multiline input: a trailing `\` continued the line.
                    let l = l.replace("\\\n", " ").replace('\n', " ");
                    if !l.trim().is_empty() {
                        let _ = ed.add_history_entry(l.as_str());
                        let _ = ed.save_history(hist);
                    }
                    Some(l)
                }
                Err(ReadlineError::Interrupted) => Some(CTRL_C.to_string()), // Ctrl-C → confirm in loop
                Err(_) => None,                                          // Ctrl-D / error: exit
            },
            Reader::Plain(stdin) => {
                use std::io::Write;
                print!("{prompt}");
                std::io::stdout().flush().ok();
                let mut s = String::new();
                match stdin.read_line(&mut s) {
                    Ok(0) | Err(_) => None,
                    Ok(_) => Some(s),
                }
            }
        }
    }
}

// The blocking (piped, no external printer) fallback holds the history
// MutexGuard across `run().await` on purpose — run() mutates that history for
// the whole async operation and no other task contends for it there.
#[allow(clippy::await_holding_lock)]
pub async fn repl(base: &Path) -> anyhow::Result<()> {
    let lib = agents::load(base);
    let backends = harness::installed_cli_backends();
    println!("\x1b[1m");
    println!("  ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗");
    println!("  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit v3.6.7");
    println!("  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   interactive harness");
    println!("  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos");
    println!("  ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders");
    println!("  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝\x1b[0m");
    println!("  {} agents loaded · detected logins: {}", lib.total(),
        if backends.is_empty() { "none (use API keys)".into() } else { backends.join(", ") });
    println!("  Type \x1b[36m/help\x1b[0m to start, \x1b[36m/run\x1b[0m to launch, \x1b[36m/quit\x1b[0m to exit. (↑/↓ recalls commands)");
    println!("  \x1b[2mOr just describe it in any language:\x1b[0m \x1b[36mtesta https://loja.com com opus, foco em SQLi, roda\x1b[0m\n");

    let mut s = Session::default();
    let resumed = load_session(&mut s);
    // Shared so a background run's forwarder task can append to it.
    let history: Arc<Mutex<Vec<RunRecord>>> = Arc::new(Mutex::new(load_runs(base)));
    let past = history.lock().unwrap().len();
    if resumed || past > 0 {
        println!("  ↻ resumed project session from {} — {} past run(s)", proj_dir().display(), past);
    }
    // A recovered interrupted run, carried in memory so `/continue` can relaunch
    // the engagement on the same target with these findings folded forward.
    let mut resumable: Option<(String, Vec<Finding>)> = None;
    // Recover an interrupted run (REPL was quit/crashed mid-engagement): its
    // live findings were checkpointed to disk — fold them into /runs so
    // /results, /finding and /report still work.
    if let Some(cp) = load_checkpoint() {
        if !cp.findings.is_empty() {
            let wd = std::path::PathBuf::from(&cp.workdir);
            std::fs::create_dir_all(&wd).ok();
            crate::report_raw(&cp.target, &cp.findings, &wd); // materialize a report so /report works
            let mut h = history.lock().unwrap();
            let id = h.len() + 1;
            h.push(RunRecord { id, mode: cp.mode.clone(), target: cp.target.clone(), workdir: cp.workdir.clone(), findings: cp.findings.clone() });
            save_runs(base, &h);
            println!("  \x1b[1;33m↻ recovered interrupted run on {} — {} finding(s) saved as run #{}\x1b[0m (/results {id} · /report {id})",
                cp.target, cp.findings.len(), id);
            println!("  \x1b[36m  ↳ /continue to keep testing this target — the {} finding(s) carry forward\x1b[0m", cp.findings.len());
            resumable = Some((cp.target.clone(), cp.findings.clone()));
        }
        clear_checkpoint();
    }
    println!();
    let mut reader = Reader::new(base);
    let mut active: Option<ActiveRun> = None;
    let mut queue: Vec<String> = Vec::new(); // remaining targets for a multi-target /run
    // First-launch onboarding: pick scope (web/infra/cloud/ai/skills) → box → setup.
    if s.target.is_none() && s.repo.is_none() && std::io::stdin().is_terminal() {
        onboarding(&mut s);
    }
    show(&s);

    loop {
        // Multi-target queue: when the current run finishes, auto-start the next.
        if !queue.is_empty() && active.as_ref().map(|a| a.done.load(Ordering::Relaxed)).unwrap_or(true) {
            let next = queue.remove(0);
            println!("\n  \x1b[1;35m▶ next target\x1b[0m ({} left): {next}", queue.len());
            active = start_background(base, &s, &mut reader, history.clone(), Some(&next), vec![]).await;
        }
        println!("{}", context_prompt(&s)); // dim context line above the prompt
        let Some(line) = reader.read(PROMPT) else { println!("\n  bye."); break };
        // Ctrl-C → confirm before doing anything drastic (don't lose a live run).
        if line == CTRL_C {
            let run_active = active.as_ref().map(|a| !a.done.load(Ordering::Relaxed)).unwrap_or(false);
            if run_active {
                println!("  \x1b[33m⚠ a test is running.\x1b[0m  [\x1b[36ms\x1b[0m] stop & validate/report · [\x1b[36mq\x1b[0m] quit (keep the run's findings) · [enter] keep running");
                match ask_line("  choice [s/q/enter]:").trim() {
                    "s" | "stop" => {
                        if let Some(a) = &active {
                            *a.choice.lock().unwrap() = StopMode::Validate;
                            a.soft.store(true, Ordering::Relaxed);
                            println!("  ⏸ stopping — validating what was found, then reporting…");
                        }
                    }
                    "q" | "quit" => {
                        if let Some(a) = &active { a.cancel.store(true, Ordering::Relaxed); }
                        save_session(&s); println!("  session saved → {} · findings checkpointed. bye.", proj_dir().display()); break;
                    }
                    _ => println!("  (keep running — /status to check, /stop to halt)"),
                }
            } else {
                match ask_line("  exit NeuroSploit? [y/N]:").trim().to_lowercase().as_str() {
                    "y" | "yes" | "q" => { save_session(&s); println!("  session saved → {} · bye.", proj_dir().display()); break; }
                    _ => {}
                }
            }
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Natural-language input (no leading '/'): interpret it, configure the
        // session hands-free, and — if the phrase asked to run — fall through to
        // the /run handler. Hybrid: a zero-token deterministic parse handles the
        // common shapes; anything ambiguous is resolved by the model (any language).
        let (cmd, arg): (String, String) = if line.starts_with('/') {
            let mut parts = line.splitn(2, char::is_whitespace);
            (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").trim().to_string())
        } else {
            let attached = expand_ats(line, &mut s);
            if attached > 0 { println!("  ({attached} @attachment(s) added to context)"); }
            match handle_nl(line, &mut s).await {
                Some(c) => (c.to_string(), String::new()), // "/run" or "/stop"
                None => continue,
            }
        };
        let (cmd, arg) = (cmd.as_str(), arg.as_str());
        match cmd {
            "/help" | "/?" => help(),
            "/show" | "/config" => show(&s),
            "/providers" => {
                for p in harness::providers() {
                    println!("  [{}] {:<14} {}", p.kind, p.key,
                        p.models.iter().map(|m| format!("{}:{}", p.key, m)).collect::<Vec<_>>().join("  "));
                }
            }
            "/onboard" | "/scope" => onboarding(&mut s),
            "/model" | "/models" => {
                if arg.is_empty() {
                    pick_models(&mut s);
                } else {
                    s.models = arg.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from).collect();
                    println!("  models: {}", s.models.join(", "));
                }
                // If a run is paused on exhaustion, queue the newly-chosen models
                // as its fallback so a plain /continue picks them up.
                if let Some(a) = &active {
                    if a.paused.load(Ordering::Relaxed) {
                        let mut fb = a.fallback.lock().unwrap();
                        for id in &s.models { fb.push(ModelRef::parse(id)); }
                        println!("  \x1b[2m↪ queued for the paused run — /continue to resume on these model(s)\x1b[0m");
                    }
                }
            }
            "/key" => key_cmd(&mut s, arg, &mut reader),
            "/sub" | "/subscription" => {
                s.subscription = !matches!(arg, "off" | "false" | "0" | "no");
                println!("  subscription: {}", onoff(s.subscription));
            }
            "/target" | "/url" => {
                if arg.is_empty() { println!("  target: {}", s.target.clone().unwrap_or_else(|| "(none) — set with /target <url[,url2,...]>, clear with /target clear".into())); }
                else if arg == "clear" { s.target = None; println!("  target cleared"); }
                else {
                    // Accept one URL or a comma-separated list; normalize each.
                    let ts: Vec<String> = arg.split(',').map(|x| x.trim()).filter(|x| !x.is_empty())
                        .map(|x| if x.starts_with("http") { x.to_string() } else { format!("https://{x}") })
                        .collect();
                    s.target = Some(ts.join(","));
                    if ts.len() > 1 { println!("  targets ({}): {}", ts.len(), ts.join(", ")); println!("  \x1b[2m/run tests them sequentially, one report each\x1b[0m"); }
                    else { println!("  target: {}", ts.first().cloned().unwrap_or_default()); }
                }
            }
            "/timeout" | "/idle" => {
                if arg.is_empty() {
                    if s.idle_secs == 0 { println!("  idle guardrail: off — set minutes with /timeout <n> (0 disables)"); }
                    else { println!("  idle guardrail: stop if no new finding in {} min — /timeout <n> (0 disables)", s.idle_secs / 60); }
                } else {
                    let mins: u64 = arg.trim().parse().unwrap_or(s.idle_secs / 60);
                    s.idle_secs = mins.saturating_mul(60);
                    if mins == 0 { println!("  idle guardrail: off"); }
                    else { println!("  idle guardrail: stop if no new finding in {mins} min"); }
                }
            }
            "/ua" | "/useragent" => {
                match arg {
                    "" => println!("  user-agent: {}  \x1b[2m(identifies NeuroSploit traffic)\x1b[0m",
                        s.user_agent.clone().unwrap_or_else(harness::pipeline::default_user_agent)),
                    "default" | "reset" => { s.user_agent = None; println!("  user-agent reset to default (NeuroSploit)"); }
                    u => { s.user_agent = Some(u.to_string()); println!("  user-agent: {u}"); }
                }
            }
            "/proxy" | "/burp" => {
                match arg {
                    "" => println!("  proxy: {}", s.proxy.clone().unwrap_or_else(|| "(none) — route traffic to Burp/ZAP with /proxy <url>, e.g. /proxy http://127.0.0.1:8080".into())),
                    "off" | "clear" | "none" => { s.proxy = None; println!("  proxy cleared — traffic goes direct"); }
                    "on" => { s.proxy = Some("http://127.0.0.1:8080".into()); println!("  proxy: http://127.0.0.1:8080 (default Burp) — agents route curl through it"); }
                    u => { let p = if u.starts_with("http") { u.to_string() } else { format!("http://{u}") };
                           s.proxy = Some(p.clone()); println!("  proxy: {p} — agents route HTTP through it so you can inspect/replay in Burp"); }
                }
            }
            "/repo" => {
                if arg.is_empty() { println!("  repo: {}", s.repo.clone().unwrap_or_else(|| "(none) — set with /repo <path | github-url | owner/repo>, clear with /repo clear".into())); }
                else if arg == "clear" { s.repo = None; println!("  repo cleared"); }
                else {
                    // Accept a local path OR a GitHub URL / owner-repo shorthand (cloned on set).
                    match crate::resolve_source(base, arg) {
                        Ok(p) => { s.repo = Some(p.clone()); println!("  repo: {p}"); }
                        Err(e) => println!("  \x1b[31mcould not resolve repo: {e}\x1b[0m"),
                    }
                }
            }
            "/auth" => {
                if arg.is_empty() {
                    match s.auth.clone() {
                        Some(a) => println!("  auth: {a}"),
                        None => println!("  auth: (none) — /auth <header> · or roles: /auth admin <hdr> · /auth user <hdr>"),
                    }
                    for (n, v) in &s.roles { println!("    role {n}: {v}"); }
                    if s.roles.len() >= 2 { println!("  \x1b[2m{} identities → access-control testing (IDOR/BOLA/BFLA) on /run\x1b[0m", s.roles.len()); }
                }
                else if arg == "clear" { s.auth = None; s.roles.clear(); println!("  auth + roles cleared"); }
                else {
                    // "<role> <value>" if the first token is a bare identifier (no ':').
                    let mut it = arg.splitn(2, char::is_whitespace);
                    let first = it.next().unwrap_or("");
                    let rest = it.next().unwrap_or("").trim();
                    let is_role = !first.contains(':') && !rest.is_empty()
                        && first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                    if is_role {
                        let val = normalize_auth(rest);
                        s.roles.retain(|(n, _)| n != first);
                        s.roles.push((first.to_string(), val.clone()));
                        if s.auth.is_none() { s.auth = Some(val); } // first role also = primary session
                        println!("  role '{first}' set ({} identit{}) — test both scenarios on /run", s.roles.len(), if s.roles.len() == 1 { "y" } else { "ies" });
                    } else {
                        s.auth = Some(arg.to_string()); println!("  auth set: {arg}");
                    }
                }
            }
            "/creds" => {
                if arg.is_empty() { println!("  creds file: {}", s.creds.clone().unwrap_or_else(|| "(none) — set with /creds <file.yaml>".into())); }
                else if arg == "clear" { s.creds = None; println!("  creds cleared"); }
                else { s.creds = Some(arg.to_string()); println!("  creds file: {arg}"); }
            }
            "/focus" | "/instructions" => {
                if arg == "clear" { s.instructions = None; println!("  focus cleared"); continue; }
                if arg.is_empty() { println!("  focus: {}", s.instructions.clone().unwrap_or_else(|| "(none)".into())); continue; }
                s.instructions = Some(arg.to_string());
                println!("  focus: {}", s.instructions.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/objective" | "/goal" | "/objectives" => {
                if arg == "clear" { s.objective = None; println!("  objective cleared"); continue; }
                if arg.is_empty() {
                    println!("  objective: {}", s.objective.clone().unwrap_or_else(|| "(none) — set the engagement goal/context with /objective <text>".into()));
                    continue;
                }
                s.objective = Some(arg.to_string());
                println!("  objective set — steers what agents prioritise and what counts as impact");
            }
            "/scope-out" | "/outofscope" | "/oos" | "/exclude" => {
                if arg == "clear" { s.out_of_scope = None; println!("  out-of-scope cleared"); continue; }
                if arg.is_empty() {
                    println!("  out-of-scope: {}", s.out_of_scope.clone().unwrap_or_else(|| "(none) — exclude hosts/paths/techniques with /scope-out <text>".into()));
                    continue;
                }
                // Append to any existing exclusions rather than overwrite (comma-joined).
                s.out_of_scope = Some(match &s.out_of_scope {
                    Some(prev) if !prev.trim().is_empty() => format!("{prev}; {arg}"),
                    _ => arg.to_string(),
                });
                println!("  out-of-scope: {}  \x1b[2m(hard constraint — agents skip these)\x1b[0m", s.out_of_scope.clone().unwrap_or_default());
            }
            "/attach" => { let n = attach_path(arg.trim_start_matches('@'), &mut s); if n > 0 { println!("  attached ({} total)", s.attachments.len()); } }
            "/context" => {
                if s.attachments.is_empty() { println!("  no attachments — add with @path or /attach <path>"); }
                else { println!("  context attachments ({}):", s.attachments.len());
                    for a in &s.attachments { println!("    • {}", a.lines().next().unwrap_or("").trim_start_matches("// ")); } }
            }
            "/theme" => {
                s.color = !matches!(arg, "off" | "mono" | "no-color" | "plain");
                println!("  theme: {}", if s.color { "color" } else { "mono" });
            }
            "/mcp" => { s.mcp = !matches!(arg, "off" | "false" | "0" | "no"); println!("  Playwright MCP: {}", onoff(s.mcp)); }
            "/offline" => { s.offline = !matches!(arg, "off" | "false" | "0" | "no"); println!("  offline: {}", onoff(s.offline)); }
            "/integrations" | "/integration" => integrations_cmd(arg),
            "/votes" => { s.vote_n = arg.parse().unwrap_or(s.vote_n); println!("  votes: {}", s.vote_n); }
            "/chain" => {
                if arg.is_empty() { println!("  attack-chain depth: {} (0 disables) — set with /chain <n>", s.chain_depth); }
                else { s.chain_depth = arg.parse().unwrap_or(s.chain_depth); println!("  attack-chain depth: {}", s.chain_depth); }
            }
            "/recon" => {
                let lvl = |n: usize| ["", "quick", "standard", "deep", "exhaustive"].get(n).copied().unwrap_or("deep");
                if arg.is_empty() { println!("  recon intensity: {} ({}) — set with /recon <1-4>  [1 quick · 2 standard · 3 deep · 4 exhaustive]", s.recon_intensity, lvl(s.recon_intensity)); }
                else { s.recon_intensity = arg.parse::<usize>().unwrap_or(s.recon_intensity).clamp(1, 4); println!("  recon intensity: {} ({}) — more rounds, more enumeration, auto-installs tools", s.recon_intensity, lvl(s.recon_intensity)); }
            }
            "/tempmail" | "/temp-email" => {
                match arg.trim() {
                    "on" | "true" | "1" => { s.temp_email = true; println!("  temp-email: \x1b[32mon\x1b[0m — register flows may use the free mail.tm inbox to read a confirmation code"); }
                    "off" | "false" | "0" => { s.temp_email = false; println!("  temp-email: \x1b[2moff\x1b[0m — a register step that requires email confirmation is reported as a blocker"); }
                    _ => println!("  temp-email: {} — /tempmail on|off (opt-in disposable inbox for register confirmation)", if s.temp_email { "\x1b[32mon\x1b[0m" } else { "\x1b[2moff\x1b[0m" }),
                }
            }
            "/agents" => {
                if arg == "list" || arg == "ls" {
                    let lib = agents::load(base);
                    println!("  agent library ({} total):", lib.total());
                    println!("    vulns {} · code {} · infra/cloud {} · recon {} · chains {} · meta {}",
                        lib.vulns.len(), lib.code.len(), lib.infra.len(), lib.recon.len(), lib.chains.len(), lib.meta.len());
                } else if arg.is_empty() {
                    println!("  max agents: {} (0 = all) — set with /agents <n>, or /agents list for counts", s.max_agents);
                } else {
                    s.max_agents = arg.parse().unwrap_or(s.max_agents); println!("  max agents: {}", s.max_agents);
                }
            }
            "/clear" => { print!("\x1b[2J\x1b[H"); }
            "/run" | "/go" => {
                if active.as_ref().map(|a| !a.done.load(Ordering::Relaxed)).unwrap_or(false) {
                    println!("  a run is already active — /status to check, /stop to halt it.");
                } else {
                    resumable = None; // a fresh /run supersedes any recovered interrupted run
                    save_session(&s);
                    // Multiple comma-separated targets → run sequentially (queue the rest).
                    let targets = session_targets(&s);
                    let (first, rest): (Option<String>, Vec<String>) = if targets.len() > 1 {
                        (Some(targets[0].clone()), targets[1..].to_vec())
                    } else { (None, Vec::new()) };
                    queue = rest;
                    if !queue.is_empty() {
                        println!("  \x1b[1;35m▶ multi-target\x1b[0m: {} URLs — running sequentially", targets.len());
                    }
                    match start_background(base, &s, &mut reader, history.clone(), first.as_deref(), vec![]).await {
                        Some(a) => { active = Some(a); println!("  \x1b[1;35m▶ running in background\x1b[0m — keep typing · \x1b[36m/status\x1b[0m · \x1b[36m/stop\x1b[0m"); }
                        None => { // no external printer (piped) → blocking fallback
                            let mut h = history.lock().unwrap();
                            run(base, &s, &mut h).await; save_runs(base, &h);
                            queue.clear();
                        }
                    }
                }
            }
            "/stop" => {
                match &active {
                    Some(a) if !a.done.load(Ordering::Relaxed) => {
                        println!("  \x1b[1mStop the run — choose:\x1b[0m");
                        println!("    \x1b[36m1\x1b[0m  validate the findings found so far, then report  \x1b[2m(recommended)\x1b[0m");
                        println!("    \x1b[36m2\x1b[0m  report NOW without validating (raw findings)");
                        println!("    \x1b[36m3\x1b[0m  discard (no report)");
                        let ans = ask_line("  choice [1/2/3]:");
                        match ans.trim() {
                            "2" => { *a.choice.lock().unwrap() = StopMode::Raw; a.cancel.store(true, Ordering::Relaxed);
                                     println!("  ⏹ stopping — generating a RAW report from what was found…"); }
                            "3" => { *a.choice.lock().unwrap() = StopMode::Discard; a.cancel.store(true, Ordering::Relaxed);
                                     println!("  🗑 stopping — discarding this run."); }
                            _   => { *a.choice.lock().unwrap() = StopMode::Validate; a.soft.store(true, Ordering::Relaxed);
                                     println!("  ⏸ stopping exploitation — validating what was found, then reporting…"); }
                        }
                    }
                    _ => println!("  no active run."),
                }
            }
            "/continue" | "/resume" => {
                let paused = active.as_ref().map(|a| a.paused.load(Ordering::Relaxed)).unwrap_or(false);
                let working = active.as_ref().map(|a| !a.done.load(Ordering::Relaxed)).unwrap_or(false);
                if paused {
                    let a = active.as_ref().unwrap();
                    if !arg.is_empty() {
                        let m = ModelRef::parse(arg);
                        println!("  \x1b[1;35m▶ resuming with fallback model\x1b[0m {}:{}", m.provider, m.model);
                        a.fallback.lock().unwrap().push(m);
                    } else {
                        println!("  \x1b[1;35m▶ resuming\x1b[0m — retrying with the current model(s).");
                    }
                    a.paused.store(false, Ordering::Relaxed);
                    a.resume.notify_waiters();
                } else if working {
                    println!("  run is not paused — it's still working. /status to check.");
                } else if let Some((tgt, prior)) = resumable.take() {
                    // Continue an interrupted run: relaunch on the same target, carry
                    // the prior findings forward, and steer agents to extend coverage
                    // rather than re-report what was already found.
                    if s.target.is_none() && s.repo.is_none() { s.target = Some(tgt.clone()); }
                    let titles: Vec<String> = prior.iter().map(|f| format!("[{}] {}", f.severity, f.title)).collect();
                    let carry = format!(
                        "CONTINUE a prior interrupted engagement on this same target. These {} finding(s) are \
                         ALREADY confirmed — do NOT re-report them; instead widen coverage: chase untested \
                         endpoints/params/methods, try new agent classes, and chain from these where possible: {}",
                        prior.len(), titles.join("; "));
                    s.instructions = Some(match &s.instructions {
                        Some(prev) if !prev.trim().is_empty() => format!("{prev}\n\n{carry}"),
                        _ => carry,
                    });
                    println!("  \x1b[1;35m▶ continuing interrupted run\x1b[0m on {tgt} — {} prior finding(s) carried forward", prior.len());
                    match start_background(base, &s, &mut reader, history.clone(), None, prior).await {
                        Some(a) => { active = Some(a); println!("  \x1b[1;35m▶ running in background\x1b[0m — keep typing · \x1b[36m/status\x1b[0m · \x1b[36m/stop\x1b[0m"); }
                        None => {
                            let mut h = history.lock().unwrap();
                            run(base, &s, &mut h).await; save_runs(base, &h);
                        }
                    }
                } else {
                    println!("  no paused or interrupted run. (a run pauses on token/quota exhaustion; an interrupted run is offered for /continue at launch)");
                }
            }
            "/runs" | "/history" => list_runs(&history.lock().unwrap()),
            "/diff" | "/changed" => diff_runs(&history.lock().unwrap()),
            "/retest" => {
                let h = history.lock().unwrap();
                if let Some(r) = pick(&h, arg) {
                    if r.target.starts_with('/') { s.repo = Some(r.target.clone()); s.target = None; }
                    else { s.target = Some(r.target.clone()); }
                    let titles: Vec<String> = r.findings.iter().map(|f| f.title.clone()).collect();
                    if !titles.is_empty() {
                        s.instructions = Some(format!("RETEST — re-verify whether these prior findings are now fixed: {}", titles.join("; ")));
                    }
                    println!("  ↻ retest set up for {} ({} prior finding(s)) — /run to launch", r.target, titles.len());
                }
            }
            "/validate" | "/revalidate" => {
                // Re-run false-positive validation (voting + adversarial refute) on
                // a recovered/past run's findings WITHOUT re-testing the target.
                let (target, workdir, cands) = {
                    let h = history.lock().unwrap();
                    match pick(&h, arg) {
                        Some(r) => (r.target.clone(), r.workdir.clone(), r.findings.clone()),
                        None => { continue; }
                    }
                };
                if cands.is_empty() { println!("  that run has no findings to validate."); continue; }
                if s.offline { println!("  \x1b[31mvalidation needs a model — turn /offline off (and set a model/login).\x1b[0m"); continue; }
                println!("  \x1b[1;35m▶ validating {} finding(s) from {}\x1b[0m (voting + adversarial refute)…", cands.len(), target);
                let refs: Vec<ModelRef> = s.models.iter().map(|m| ModelRef::parse(m)).collect();
                let pool = harness::pool::ModelPool::with_auth(refs, 3, s.subscription, None);
                let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
                let vote_n = s.vote_n;
                let task = tokio::spawn(async move { harness::pipeline::revalidate(cands, &pool, vote_n, tx).await });
                while let Some(line) = rx.recv().await {
                    if let Some(out) = crate::render_compact(&line) { println!("{out}"); }
                }
                let validated = task.await.unwrap_or_default();
                // Persist: rewrite the run's findings + report, save history.
                {
                    let mut h = history.lock().unwrap();
                    if let Some(r) = h.iter_mut().find(|r| r.workdir == workdir || (arg.trim().parse::<usize>().ok() == Some(r.id))) {
                        r.findings = validated.clone();
                    }
                    save_runs(base, &h);
                }
                if !workdir.is_empty() {
                    crate::report_raw(&target, &validated, std::path::Path::new(&workdir));
                }
                println!("  \x1b[1;32m✓ validation complete — {} finding(s) confirmed\x1b[0m · report refreshed · /results to browse", validated.len());
            }
            "/results" => {
                // With an explicit run number, or piped stdin → plain print.
                if !arg.is_empty() || !std::io::stdin().is_terminal() {
                    results(&history.lock().unwrap(), arg);
                } else {
                    // Interactive: ALWAYS show the run/test picker (target → vuln →
                    // detail, Esc back). Includes the live run (if any) at the top so
                    // you can browse every test, not just the current one.
                    let mut runs: Vec<RunRecord> = Vec::new();
                    if let Some(a) = &active {
                        if !a.done.load(Ordering::Relaxed) {
                            let l = a.live.lock().unwrap();
                            runs.push(RunRecord {
                                id: 0, mode: format!("{} ▶live", l.mode), target: l.target.clone(),
                                workdir: String::new(), findings: l.full.clone(),
                            });
                        }
                    }
                    runs.extend(history.lock().unwrap().iter().rev().cloned()); // newest-first
                    // Silence live background output while the full-screen picker is
                    // open (they'd corrupt each other); restore + point to /logs after.
                    let live_now = active.as_ref().map(|a| { a.quiet.store(true, Ordering::Relaxed); !a.done.load(Ordering::Relaxed) }).unwrap_or(false);
                    browse_results(&runs);
                    if let Some(a) = &active { a.quiet.store(false, Ordering::Relaxed); }
                    if live_now { println!("  \x1b[2m(run still streaming in background — /logs for what happened while browsing)\x1b[0m"); }
                }
            }
            "/finding" | "/findings" => {
                // Build the finding pool: live run if active, else a past run.
                let pool: Vec<Finding> = match &active {
                    Some(a) if arg.is_empty() && !a.done.load(Ordering::Relaxed) => a.live.lock().unwrap().full.clone(),
                    _ => { let h = history.lock().unwrap(); pick(&h, arg).map(|r| r.findings.clone()).unwrap_or_default() }
                };
                if let Some(a) = &active { a.quiet.store(true, Ordering::Relaxed); }
                finding_detail(&pool);
                if let Some(a) = &active { a.quiet.store(false, Ordering::Relaxed); }
            }
            "/expand" | "/full" => {
                // Show full untruncated commands from the active run.
                match &active {
                    Some(a) => {
                        let l = a.live.lock().unwrap();
                        let n: usize = arg.trim().parse().unwrap_or(5);
                        let cmds = &l.commands;
                        if cmds.is_empty() { println!("  no commands captured yet."); }
                        else {
                            println!("  ── last {} command(s) (full) ──", n.min(cmds.len()));
                            for c in cmds.iter().rev().take(n).rev() { println!("  \x1b[33m$ {c}\x1b[0m"); }
                        }
                    }
                    None => println!("  no active run — /expand shows full commands while a run streams."),
                }
            }
            "/report" => {
                if let Some(a) = &active { a.quiet.store(true, Ordering::Relaxed); }
                open_report(&history.lock().unwrap(), arg);
                if let Some(a) = &active { a.quiet.store(false, Ordering::Relaxed); }
            }
            "/status" => {
                // Live status if a run is active, else a past run's status.json.
                match &active {
                    Some(a) if arg.is_empty() && !a.done.load(Ordering::Relaxed) => {
                        let l = a.live.lock().unwrap();
                        let el = l.started.elapsed().as_secs();
                        let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
                        for (sv, _) in &l.findings { *by.entry(sv.as_str()).or_insert(0) += 1; }
                        let sev = if by.is_empty() { "0".into() } else { by.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
                        println!("  \x1b[1m▶ live\x1b[0m {} ({}) · phase \x1b[36m{}\x1b[0m · {:02}:{:02} · {} finding(s) [{}]",
                            l.target, l.mode, l.phase, el / 60, el % 60, l.full.len(), sev);
                        if a.paused.load(Ordering::Relaxed) {
                            println!("    \x1b[1;33m⏸ PAUSED — token/quota exhausted. /continue to resume, or /model <provider:model> then /continue to switch.\x1b[0m");
                        }
                        // Progress: a real bar once agents are selected; otherwise show the pre-exploit phase.
                        if l.agents > 0 { println!("    progress \x1b[36m{}\x1b[0m · {} cmd(s) · {} activity line(s)", l.bar(24), l.commands.len(), l.lines); }
                        else { println!("    \x1b[2m{} — no agents selected yet · {} cmd(s) · {} activity line(s)\x1b[0m", l.phase, l.commands.len(), l.lines); }
                        // Sign of life: the latest activity line (so a long recon isn't a black box).
                        if !l.last.is_empty() { println!("    \x1b[2mlast:\x1b[0m {}", trunc(&l.last, 116)); }
                        for x in l.full.iter().rev().take(5) { println!("    ✦ [{}] {} \x1b[2m({})\x1b[0m", x.severity, x.title, x.endpoint); }
                        println!("    \x1b[2m/logs — recent activity · /results — browse findings\x1b[0m");
                    }
                    _ => run_status(&history.lock().unwrap(), arg),
                }
            }
            "/logs" | "/log" | "/feed" => {
                match &active {
                    Some(a) if !a.done.load(Ordering::Relaxed) => {
                        let n: usize = arg.trim().parse().unwrap_or(25);
                        let l = a.live.lock().unwrap();
                        if l.feed.is_empty() { println!("  (no activity yet — the run is starting/reconning)"); }
                        else {
                            println!("  ── recent activity (last {} of {} lines) ──", n.min(l.feed.len()), l.lines);
                            for line in l.feed.iter().rev().take(n).rev() {
                                if let Some(out) = crate::render_compact(line) { println!("{out}"); }
                                else { println!("    \x1b[2m{}\x1b[0m", trunc(line, 116)); }
                            }
                        }
                    }
                    _ => println!("  no active run — /logs shows the live activity feed while a run streams."),
                }
            }
            "/quit" | "/exit" | "/q" => {
                if active.as_ref().map(|a| !a.done.load(Ordering::Relaxed)).unwrap_or(false) {
                    if let Some(a) = &active { a.cancel.store(true, Ordering::Relaxed); }
                    println!("  ⏸ a run is active — requested stop; quitting.");
                }
                save_session(&s); println!("  session saved → {} · bye.", proj_dir().display()); break;
            }
            other => println!("  unknown command '{other}' — try /help"),
        }
    }
    Ok(())
}

/// Arrow-key multi-select of models from the catalog (interactive terminals only).
/// Onboarding wizard: pick WHAT you're testing (scope) → box type → set it up.
/// Sets s.scope + target/repo/creds hints so a plain `/run` does the right thing.
fn onboarding(s: &mut Session) {
    if !std::io::stdin().is_terminal() { return; }
    let cats = [
        "Web & API              (a website / REST / GraphQL — black/grey/white-box)",
        "Infrastructure & Networks  (an IP / host — Linux / Windows / Active Directory)",
        "Cloud                  (AWS / GCP / Azure account via creds.yaml)",
        "AI Agents & LLMs       (a live AI/LLM/MCP endpoint, OWASP LLM Top 10)",
        "AI Skills / Plugins / n8n  (audit exported files — white-box)",
        "Skip — I'll configure manually",
    ];
    let ci = match dialoguer::Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What are you testing? (onboarding — Esc to skip)")
        .items(&cats).default(0).interact_opt() {
        Ok(Some(i)) => i, _ => { println!("  (skipped onboarding — /onboard to run it again)"); return; }
    };
    match ci {
        0 => { // Web & API
            let boxes = ["Black-box (only a URL)", "White-box (source code)", "Grey-box (URL + source code)"];
            let bi = dialoguer::Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Box type").items(&boxes).default(0).interact_opt().ok().flatten().unwrap_or(0);
            s.scope = "web";
            if bi == 0 || bi == 2 {
                let u = ask_line("  Target URL:"); if !u.trim().is_empty() {
                    let u = if u.starts_with("http") { u.trim().to_string() } else { format!("https://{}", u.trim()) };
                    s.target = Some(u);
                }
            }
            if bi == 1 || bi == 2 {
                let p = ask_line("  Source repo (path or GitHub URL):"); if !p.trim().is_empty() { s.repo = Some(p.trim().to_string()); }
            }
            println!("  ✓ web ({}) — /run to launch (add /auth, /creds, /focus as needed).",
                ["black-box","white-box","grey-box"][bi.min(2)]);
        }
        1 => { // Infra
            s.scope = "infra";
            let t = ask_line("  Target host/IP:"); if !t.trim().is_empty() { s.target = Some(t.trim().to_string()); }
            let c = ask_line("  creds.yaml path (ssh:/windows: blocks) [enter to skip]:"); if !c.trim().is_empty() { s.creds = Some(c.trim().to_string()); }
            println!("  ✓ infra/host — /run to launch (Linux/Windows/AD agents).");
        }
        2 => { // Cloud
            s.scope = "cloud";
            let t = ask_line("  Cloud account label / target:"); s.target = Some(if t.trim().is_empty() { "cloud-account".into() } else { t.trim().to_string() });
            let c = ask_line("  creds.yaml path (aws:/gcp:/azure: blocks):"); if !c.trim().is_empty() { s.creds = Some(c.trim().to_string()); }
            println!("  ✓ cloud — set aws:/gcp:/azure: in creds.yaml, then /run.");
        }
        3 => { // AI live
            s.scope = "ai";
            let u = ask_line("  AI agent / LLM / MCP endpoint URL:"); if !u.trim().is_empty() {
                let u = if u.starts_with("http") { u.trim().to_string() } else { format!("https://{}", u.trim()) };
                s.target = Some(u);
            }
            let a = ask_line("  Auth header for the endpoint [enter to skip]:"); if !a.trim().is_empty() { s.auth = Some(normalize_auth(a.trim())); }
            println!("  ✓ ai/llm — /run tests OWASP LLM Top 10 + MCP against the endpoint.");
        }
        4 => { // Skills / n8n audit (white-box files)
            s.scope = "skills";
            let p = ask_line("  Skill/plugin/n8n file or folder (.md/.json):"); if !p.trim().is_empty() { s.repo = Some(p.trim().to_string()); }
            println!("  ✓ skills/n8n audit — /run audits the exported definition(s).");
        }
        _ => { s.scope = "web"; println!("  (manual setup — use /target /repo /creds /auth then /run)"); }
    }
    // Optional: capture engagement objective + out-of-scope. Both feed the agent
    // prompts as context (objective) and a hard constraint (out-of-scope). Empty
    // input skips — nothing is required to /run.
    let obj = ask_line("  Objective / context for this test [enter to skip]:");
    if !obj.trim().is_empty() {
        s.objective = Some(obj.trim().to_string());
        println!("  ✓ objective set — steers what agents prioritise.");
    }
    let oos = ask_line("  Out of scope — hosts/paths/techniques to EXCLUDE [enter to skip]:");
    if !oos.trim().is_empty() {
        s.out_of_scope = Some(oos.trim().to_string());
        println!("  ✓ out-of-scope set — agents will skip these (hard constraint).");
    }
}

fn pick_models(s: &mut Session) {
    if !std::io::stdin().is_terminal() {
        println!("  current: {} (use /model <provider:model,...> to set)", s.models.join(", "));
        return;
    }
    let mut ids: Vec<String> = Vec::new();
    for p in harness::providers() {
        for m in &p.models {
            ids.push(format!("{}:{}", p.key, m));
        }
    }
    let defaults: Vec<bool> = ids.iter().map(|id| s.models.contains(id)).collect();
    match MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select models (space toggles, ↑/↓ moves, enter confirms)")
        .items(&ids)
        .defaults(&defaults)
        .interact_opt()
    {
        Ok(Some(idx)) if !idx.is_empty() => {
            s.models = idx.into_iter().map(|i| ids[i].clone()).collect();
            println!("  models: {}", s.models.join(", "));
        }
        _ => println!("  models unchanged: {}", s.models.join(", ")),
    }
}

/// Configure API keys based on the selected models: `/key` lists the providers
/// your models need (set/missing) and prompts for missing ones; `/key <prov> <key>`
/// sets one directly.
fn key_cmd(s: &mut Session, arg: &str, reader: &mut Reader) {
    if !arg.is_empty() {
        let mut kp = arg.splitn(2, char::is_whitespace);
        if let (Some(prov), Some(key)) = (kp.next(), kp.next()) {
            set_key(prov, key.trim(), s);
        } else {
            println!("  usage: /key <provider> <api-key>   e.g. /key anthropic sk-ant-...");
        }
        return;
    }
    // No arg → walk the providers required by the selected models.
    let provs: Vec<String> = s.models.iter()
        .map(|m| m.split(':').next().unwrap_or("").to_string())
        .collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    println!("  API keys for your selected models:");
    for prov in &provs {
        let Some(p) = harness::provider_for(prov) else { continue };
        let set = std::env::var(p.env_key).map(|v| !v.is_empty()).unwrap_or(false);
        let mark = if set { "✓ set" } else { "✗ missing" };
        println!("    {prov:<12} {} ({})", mark, p.env_key);
    }
    if std::io::stdin().is_terminal() {
        for prov in &provs {
            let Some(p) = harness::provider_for(prov) else { continue };
            if std::env::var(p.env_key).map(|v| !v.is_empty()).unwrap_or(false) {
                continue;
            }
            if let Reader::Rl(ed, _) = reader {
                match ed.readline(&format!("  paste {prov} key (blank to skip): ")) {
                    Ok(k) if !k.trim().is_empty() => set_key(prov, k.trim(), s),
                    _ => {}
                }
            }
        }
    } else {
        println!("  (set with /key <provider> <key> or export {{ENV}} before launch)");
    }
}

fn set_key(prov: &str, key: &str, s: &mut Session) {
    match harness::provider_for(prov) {
        Some(p) => {
            std::env::set_var(p.env_key, key);
            s.subscription = false;
            println!("  set {} (API mode)", p.env_key);
        }
        None => println!("  unknown provider '{prov}' (see /providers)"),
    }
}

async fn run(base: &Path, s: &Session, history: &mut Vec<RunRecord>) {
    enum M { Black(String), White(String), Grey { url: String, repo: String } }
    let m = match (&s.repo, &s.target) {
        (Some(r), Some(t)) => M::Grey { url: t.clone(), repo: r.clone() },
        (Some(r), None) => M::White(r.clone()),
        (None, Some(t)) => M::Black(t.clone()),
        _ => { println!("  \x1b[31m✗ set a /target <url> and/or /repo <path> first.\x1b[0m"); return; }
    };
    let primary = match &m {
        M::Black(t) | M::White(t) => t.clone(),
        M::Grey { url, .. } => url.clone(),
    };
    let mut cfg = RunConfig::new(&primary);
    cfg.models = s.models.clone();
    cfg.subscription = s.subscription;
    cfg.vote_n = s.vote_n;
    cfg.chain_depth = s.chain_depth;
    cfg.recon_intensity = s.recon_intensity;
    cfg.temp_email = s.temp_email;
    cfg.proxy = s.proxy.clone();
    cfg.user_agent = s.user_agent.clone();
    cfg.max_agents = s.max_agents;
    cfg.verbose = true;
    cfg.offline = s.offline;
    // Fold @attachments (scope files / stack traces) into the instruction context.
    cfg.instructions = match (s.instructions.clone(), s.attachments.is_empty()) {
        (instr, true) => instr,
        (instr, false) => {
            let ctx = s.attachments.join("\n\n");
            Some(format!("{}\n\nATTACHED CONTEXT:\n{ctx}", instr.unwrap_or_default()))
        }
    };
    cfg.objective = s.objective.clone();
    cfg.out_of_scope = s.out_of_scope.clone();
    cfg.auth = s.auth.clone();
    // Multiple /auth identities → prepend the access-control (IDOR/BOLA/BFLA) directive.
    if let Some(rd) = roles_directive(&s.roles) {
        let base = cfg.instructions.clone().unwrap_or_default();
        cfg.instructions = Some(format!("{rd}{base}"));
    }
    if let M::Grey { repo, .. } = &m {
        cfg.repo = Some(repo.clone());
    }
    crate::apply_creds(&mut cfg, s.creds.as_deref()).await;

    let mode = match &m { M::Grey { .. } => "greybox", M::White(_) => "white-box", M::Black(_) => "black-box" };
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
            history.push(RunRecord { id, mode: mode.into(), target: primary, workdir: out.workdir.clone(), findings: out.findings.clone() });
        }
        Err(e) => println!("  \x1b[31m✗ run failed: {e}\x1b[0m"),
    }
}

/// Launch an engagement in the BACKGROUND: it streams live via the editor's
/// external printer while the REPL keeps accepting commands (/status, /stop).
/// Returns None when no external printer is available (piped) → caller blocks.
async fn start_background(base: &Path, s: &Session, reader: &mut Reader,
                          history: Arc<Mutex<Vec<RunRecord>>>, target_override: Option<&str>,
                          seed: Vec<Finding>) -> Option<ActiveRun> {
    // `target_override` runs one specific URL (used by the multi-target queue).
    let ov = target_override.map(|t| t.to_string());
    // The onboarding scope steers infra/cloud/ai/skills; otherwise web black/white/grey.
    let (target, mode_s, mode_e, mcp) = match s.scope {
        "infra" | "cloud" => match ov.as_ref().or(s.target.as_ref()) {
            Some(t) => (t.clone(), if s.scope == "cloud" { "cloud" } else { "host/infra" }, crate::Mode::Host, false),
            None => { println!("  \x1b[31m✗ set a /target <ip|host|cloud-account> first (and /creds).\x1b[0m"); return None; }
        },
        "ai" => match ov.as_ref().or(s.target.as_ref()) {
            Some(t) => (t.clone(), "ai/llm", crate::Mode::Ai, false),
            None => { println!("  \x1b[31m✗ set the AI endpoint with /target <url> first.\x1b[0m"); return None; }
        },
        "skills" => match s.repo.as_ref().or(s.target.as_ref()) {
            Some(p) => (p.clone(), "skills/n8n", crate::Mode::Skills, false),
            None => { println!("  \x1b[31m✗ set the skill/n8n file or folder with /repo <path> first.\x1b[0m"); return None; }
        },
        _ => match (&s.repo, ov.as_ref().or(s.target.as_ref())) {
            (Some(_), Some(t)) => (t.clone(), "greybox", crate::Mode::Grey, s.mcp),
            (Some(r), None) => (r.clone(), "white-box", crate::Mode::White, false),
            (None, Some(t)) => (t.clone(), "black-box", crate::Mode::Black, s.mcp),
            _ => { println!("  \x1b[31m✗ set a /target <url> and/or /repo <path> first.\x1b[0m"); return None; }
        },
    };
    let idle_secs = s.idle_secs;
    let mut cfg = RunConfig::new(&target);
    cfg.models = s.models.clone();
    cfg.subscription = s.subscription;
    cfg.vote_n = s.vote_n;
    cfg.chain_depth = s.chain_depth;
    cfg.recon_intensity = s.recon_intensity;
    cfg.temp_email = s.temp_email;
    cfg.proxy = s.proxy.clone();
    cfg.user_agent = s.user_agent.clone();
    cfg.max_agents = s.max_agents;
    cfg.verbose = true;
    cfg.offline = s.offline;
    cfg.instructions = if s.attachments.is_empty() { s.instructions.clone() }
        else { Some(format!("{}\n\nATTACHED CONTEXT:\n{}", s.instructions.clone().unwrap_or_default(), s.attachments.join("\n\n"))) };
    cfg.objective = s.objective.clone();
    cfg.out_of_scope = s.out_of_scope.clone();
    cfg.auth = s.auth.clone();
    if matches!(mode_e, crate::Mode::Grey) { cfg.repo = s.repo.clone(); }
    crate::apply_creds(&mut cfg, s.creds.as_deref()).await;
    crate::subscription_preflight(&cfg).await; // warn early if the CLI isn't logged in

    let mut printer = reader.external_printer()?; // None on piped stdin → blocking fallback
    let sp = crate::spawn_engagement(base, cfg, mcp, mode_e);

    let live = Arc::new(Mutex::new(RunLive {
        target: target.clone(), mode: mode_s, phase: "starting".into(),
        started: Instant::now(), findings: vec![], full: vec![], commands: vec![],
        agents: 0, agents_done: 0, last: String::new(), lines: 0, feed: vec![],
    }));
    let cancel = sp.cancel.clone();
    let soft = sp.soft.clone();
    let paused = sp.paused.clone();
    let resume = sp.resume.clone();
    let fallback = sp.fallback.clone();
    let done = Arc::new(AtomicBool::new(false));
    let choice = Arc::new(Mutex::new(StopMode::Run));
    let quiet = Arc::new(AtomicBool::new(false));
    let soft_task = soft.clone(); // idle guardrail triggers a soft-stop (validate)
    let cancel_task = cancel.clone();
    let quiet_task = quiet.clone();
    let sub_mcp = s.subscription && mcp; // for the "browser/tools never engaged" diagnostic
    let (live2, done2, hist2, choice2) = (live.clone(), done.clone(), history, choice.clone());

    tokio::spawn(async move {
        let crate::Spawned { task, mut rx, workdir, .. } = sp;
        let mut last_saved = 0usize;
        let mut last_activity = Instant::now(); // last sign of PROGRESS (any activity)
        let mut idle_fired = false;
        let mut tool_events = 0usize; // exec/net/read/browser activity seen
        let mut exploiting = false;   // guardrail only arms once exploitation starts
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    let Some(line) = maybe else { break };
                    live2.lock().unwrap().ingest(&line);
                    let low = line.to_lowercase();
                    if line.contains("exec:") || line.contains("net:") || line.contains("read:") || line.contains("browser") { tool_events += 1; }
                    // ANY streamed line is progress → reset the idle clock (a long
                    // recon or active tool use must NOT count as idle).
                    last_activity = Instant::now();
                    // Exploitation has begun once agents launch / vote — only then arm the guardrail.
                    if low.contains("launching agent") || low.starts_with("exploit ") || low.starts_with("test ")
                        || low.starts_with("ai ") || low.starts_with("skill ") || low.starts_with("vote") { exploiting = true; }
                    // Don't print into the terminal while a full-screen picker is
                    // open (it would corrupt the picker); the line is still in the
                    // feed for /logs once the picker closes.
                    if !quiet_task.load(Ordering::Relaxed) {
                        if let Some(out) = crate::render_compact(&line) { let _ = printer.print(out); }
                    }
                    // Checkpoint on each new finding.
                    let snap = {
                        let l = live2.lock().unwrap();
                        if l.full.len() != last_saved {
                            last_saved = l.full.len();
                            Some(LiveCheckpoint {
                                target: l.target.clone(), mode: l.mode.into(), phase: l.phase.clone(),
                                workdir: workdir.display().to_string(),
                                findings: l.full.clone(), commands: l.commands.clone(),
                            })
                        } else { None }
                    };
                    if let Some(c) = snap { save_checkpoint(&c); }
                }
                _ = ticker.tick() => {
                    // Idle guardrail: only after exploitation started AND no activity
                    // (not just no finding) within the window → soft-stop & validate.
                    // Recon never trips it — it streams progress lines that reset the clock.
                    if idle_secs > 0 && !idle_fired && exploiting && last_activity.elapsed().as_secs() >= idle_secs
                        && !soft_task.load(Ordering::Relaxed) && !cancel_task.load(Ordering::Relaxed) {
                        idle_fired = true;
                        *choice2.lock().unwrap() = StopMode::Validate;
                        soft_task.store(true, Ordering::Relaxed);
                        let _ = printer.print(format!(
                            "\x1b[33m⏹ idle guardrail: no activity in {} min — stopping & validating what was found\x1b[0m",
                            idle_secs / 60));
                    }
                }
            }
        }
        let task_out = task.await.unwrap_or_default();
        let mode_choice = *choice2.lock().unwrap();

        // Diagnostic: subscription + MCP but the agents never ran a single tool/
        // browser action → the CLI almost certainly isn't logged in (or the MCP
        // didn't engage), which is why nothing was found.
        if sub_mcp && tool_events == 0 {
            let _ = printer.print("\x1b[1;33m[!] no browser/tool activity was observed this run — the subscription CLI is likely NOT logged in (run `claude` → /login) or the Playwright MCP didn't start. That's usually why a run finds 0.\x1b[0m".to_string());
        }

        if mode_choice == StopMode::Discard {
            std::fs::remove_dir_all(&workdir).ok();
            clear_checkpoint();
            let _ = printer.print(format!("\x1b[33m🗑 run discarded — {}\x1b[0m", workdir.display()));
            done2.store(true, Ordering::Relaxed);
            return;
        }

        // Raw → report from the unvalidated candidates we captured live.
        let (mut findings, validated_word) = if mode_choice == StopMode::Raw {
            let raw = live2.lock().unwrap().full.clone();
            crate::report_raw(&target, &raw, &workdir);
            (raw, "unvalidated")
        } else {
            let out = crate::finalize_run(task_out, &workdir);
            (out.findings, "validated")
        };
        // Continued run (/continue on an interrupted run): fold the carried-forward
        // prior findings back in (dedup by title+endpoint) and rewrite the report
        // so the merged run shows everything found across both sessions.
        if !seed.is_empty() {
            findings = merge_findings(seed.clone(), findings);
            crate::report_raw(&target, &findings, &workdir);
        }

        let id = {
            let mut h = hist2.lock().unwrap();
            let id = h.len() + 1;
            h.push(RunRecord { id, mode: mode_s.into(), target, workdir: workdir.display().to_string(), findings: findings.clone() });
            if let Ok(j) = serde_json::to_string_pretty(&*h) { std::fs::write(proj_dir().join("runs.json"), j).ok(); }
            id
        };
        clear_checkpoint(); // run is now a completed RunRecord
        let _ = printer.print(format!(
            "\x1b[1;32m◀ run #{id} done — {} {} finding(s)\x1b[0m · /results {id} · /finding",
            findings.len(), validated_word));
        let _ = printer.print(format!("\x1b[36m  report: {}\x1b[0m", crate::report_url(&workdir)));
        done2.store(true, Ordering::Relaxed);
    });
    Some(ActiveRun { live, cancel, soft, done, choice, paused, resume, fallback, quiet })
}

/// Merge two finding sets, deduping by (title, endpoint) — used to carry a prior
/// interrupted run's findings forward into a continued run without duplicating.
fn merge_findings(prior: Vec<Finding>, mut fresh: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashSet;
    let key = |f: &Finding| format!("{}|{}", f.title.trim().to_lowercase(), f.endpoint.trim().to_lowercase());
    let seen: HashSet<String> = fresh.iter().map(key).collect();
    for p in prior {
        if !seen.contains(&key(&p)) { fresh.push(p); }
    }
    fresh
}

/// Project-local store: `<cwd>/.neurosploit/` so each project keeps its own
/// session, run history and command history (resume on reopen). No DB needed —
/// it's structured state, not semantic search.
pub(crate) fn proj_dir() -> std::path::PathBuf {
    let d = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")).join(".neurosploit");
    std::fs::create_dir_all(&d).ok();
    d
}
fn runs_path(_base: &Path) -> std::path::PathBuf { proj_dir().join("runs.json") }
fn load_runs(_base: &Path) -> Vec<RunRecord> {
    std::fs::read_to_string(runs_path(_base)).ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}
fn save_runs(_base: &Path, history: &[RunRecord]) {
    let p = runs_path(_base);
    if let Ok(j) = serde_json::to_string_pretty(history) { std::fs::write(p, j).ok(); }
}

/// Live-run checkpoint file (one in-flight run at a time).
fn checkpoint_path() -> std::path::PathBuf { proj_dir().join("active_run.json") }
fn save_checkpoint(c: &LiveCheckpoint) {
    if let Ok(j) = serde_json::to_string_pretty(c) { std::fs::write(checkpoint_path(), j).ok(); }
}
fn clear_checkpoint() { std::fs::remove_file(checkpoint_path()).ok(); }
fn load_checkpoint() -> Option<LiveCheckpoint> {
    std::fs::read_to_string(checkpoint_path()).ok().and_then(|t| serde_json::from_str(&t).ok())
}

/// Persistable snapshot of the session config (resume across restarts).
#[derive(Serialize, Deserialize, Default)]
struct Snapshot {
    models: Vec<String>,
    subscription: bool,
    mcp: bool,
    vote_n: usize,
    max_agents: usize,
    target: Option<String>,
    repo: Option<String>,
    auth: Option<String>,
    creds: Option<String>,
    instructions: Option<String>,
    #[serde(default)]
    objective: Option<String>,
    #[serde(default)]
    out_of_scope: Option<String>,
}
fn session_path() -> std::path::PathBuf { proj_dir().join("session.json") }
fn save_session(s: &Session) {
    let snap = Snapshot {
        models: s.models.clone(), subscription: s.subscription, mcp: s.mcp,
        vote_n: s.vote_n, max_agents: s.max_agents, target: s.target.clone(),
        repo: s.repo.clone(), auth: s.auth.clone(), creds: s.creds.clone(),
        instructions: s.instructions.clone(),
        objective: s.objective.clone(), out_of_scope: s.out_of_scope.clone(),
    };
    if let Ok(j) = serde_json::to_string_pretty(&snap) { std::fs::write(session_path(), j).ok(); }
}
fn load_session(s: &mut Session) -> bool {
    let Ok(txt) = std::fs::read_to_string(session_path()) else { return false };
    let Ok(snap) = serde_json::from_str::<Snapshot>(&txt) else { return false };
    if !snap.models.is_empty() { s.models = snap.models; }
    s.subscription = snap.subscription; s.mcp = snap.mcp;
    if snap.vote_n > 0 { s.vote_n = snap.vote_n; }
    s.max_agents = snap.max_agents;
    s.target = snap.target; s.repo = snap.repo; s.auth = snap.auth;
    s.creds = snap.creds; s.instructions = snap.instructions;
    s.objective = snap.objective; s.out_of_scope = snap.out_of_scope;
    true
}

fn pick<'a>(history: &'a [RunRecord], arg: &str) -> Option<&'a RunRecord> {
    if history.is_empty() { println!("  no runs yet — /run first."); return None; }
    if arg.trim().is_empty() { return history.last(); }
    match arg.trim().parse::<usize>() {
        Ok(n) => history.iter().find(|r| r.id == n).or_else(|| { println!("  no run #{n} (have 1..{})", history.len()); None }),
        Err(_) => { println!("  usage: /results <run-number>"); None }
    }
}

fn sev_counts(f: &[Finding]) -> std::collections::BTreeMap<&str, usize> {
    let mut m = std::collections::BTreeMap::new();
    for x in f { *m.entry(x.severity.as_str()).or_insert(0) += 1; }
    m
}

fn list_runs(history: &[RunRecord]) {
    if history.is_empty() { println!("  no runs yet."); return; }
    println!("  ┌─ runs (this + past sessions)");
    for r in history {
        let c = sev_counts(&r.findings);
        let sev = if c.is_empty() { "0 findings".into() } else { c.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
        println!("  │  #{:<2} {:<9} {:<38} {}", r.id, r.mode, trunc(&r.target, 38), sev);
    }
    println!("  └─ /results <n> · /report <n> · /status <n>");
}

fn results(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    println!("  ── run #{} ({}) — {} ──", r.id, r.mode, r.target);
    if r.findings.is_empty() { println!("  (no validated findings)"); return; }
    let mut f = r.findings.clone();
    f.sort_by_key(|x| match x.severity.as_str() { "Critical" => 0, "High" => 1, "Medium" => 2, "Low" => 3, _ => 4 });
    for x in &f {
        println!("  • [{}] {}", x.severity, x.title);
        println!("      {} · {} · votes {} · conf {:.2}", x.agent, x.cwe, x.votes, x.confidence);
        if !x.endpoint.is_empty() { println!("      @ {}", x.endpoint); }
    }
    println!("  report: /report {}", r.id);
}

fn open_report(history: &[RunRecord], arg: &str) {
    if history.is_empty() { println!("  no runs yet — /run first."); return; }
    // No arg + multiple runs + interactive → let the user pick which report.
    let chosen: Option<&RunRecord> = if arg.trim().is_empty() && history.len() > 1 && std::io::stdin().is_terminal() {
        let items: Vec<String> = history.iter().map(|r| {
            let c = sev_counts(&r.findings);
            let sev = if c.is_empty() { "0 findings".into() } else { c.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
            format!("#{} {:<9} {:<40} [{}]", r.id, r.mode, trunc(&r.target, 40), sev)
        }).collect();
        match dialoguer::Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a report to open (↑/↓, enter, Esc)")
            .items(&items).default(items.len() - 1).interact_opt() {
            Ok(Some(i)) => history.get(i),
            _ => return,
        }
    } else {
        pick(history, arg)
    };
    let Some(r) = chosen else { return };
    let dir = Path::new(&r.workdir);
    let pdf = dir.join("report.pdf");
    let file = if pdf.is_file() { pdf } else { dir.join("report.html") };
    if !file.is_file() { println!("  no report file in {}", r.workdir); return; }
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    match std::process::Command::new(opener).arg(&file).spawn() {
        Ok(_) => println!("  opening {}", file.display()),
        Err(_) => println!("  report: {}", file.display()),
    }
}

/// What changed between the last two runs (by finding title).
fn diff_runs(history: &[RunRecord]) {
    if history.len() < 2 {
        println!("  need at least 2 runs to diff (/runs).");
        return;
    }
    let prev = &history[history.len() - 2];
    let cur = &history[history.len() - 1];
    let set = |r: &RunRecord| r.findings.iter().map(|f| f.title.clone()).collect::<std::collections::HashSet<_>>();
    let (a, b) = (set(prev), set(cur));
    println!("  ── what changed: run #{} → #{} ({} → {}) ──", prev.id, cur.id, prev.findings.len(), cur.findings.len());
    for t in b.difference(&a) { println!("  \x1b[32m+ new\x1b[0m   {t}"); }
    for t in a.difference(&b) { println!("  \x1b[31m- gone\x1b[0m  {t}"); }
    if a == b { println!("  (no change in finding titles)"); }
}

fn sev_rank(s: &str) -> u8 {
    match s { "Critical" => 0, "High" => 1, "Medium" => 2, "Low" => 3, _ => 4 }
}

/// Read one line synchronously (for the /stop choice prompt).
/// `/integrations` — show / enable / disable / setup GitHub, GitLab, Jira.
fn integrations_cmd(arg: &str) {
    let dir = proj_dir();
    let mut ig = harness::integrations::Integrations::load(&dir);
    let mut parts = arg.splitn(2, char::is_whitespace);
    let sub = parts.next().unwrap_or("").trim();
    let name = parts.next().unwrap_or("").trim();
    match sub {
        "" | "show" | "status" => {
            println!("  \x1b[1mintegrations\x1b[0m · {}", dir.display());
            for l in ig.status_lines() { println!("    {l}"); }
            println!("  \x1b[2m/integrations enable|disable <github|gitlab|jira>  ·  /integrations setup <jira|gitlab|github>\x1b[0m");
            println!("  \x1b[2mtokens come from env vars (never stored): GITHUB_TOKEN · GITLAB_TOKEN · JIRA_EMAIL + JIRA_API_TOKEN\x1b[0m");
        }
        "enable" | "disable" => {
            let on = sub == "enable";
            match name {
                "github" => ig.github.enabled = on,
                "gitlab" => ig.gitlab.enabled = on,
                "jira" => ig.jira.enabled = on,
                _ => { println!("  usage: /integrations {sub} <github|gitlab|jira>"); return; }
            }
            let _ = ig.save(&dir);
            println!("  {name} {}", if on { "enabled ✓" } else { "disabled" });
        }
        "setup" => match name {
            "jira" => {
                let base = ask_line("  Jira base URL (https://your-org.atlassian.net):");
                if !base.trim().is_empty() { ig.jira.base_url = base.trim().trim_end_matches('/').to_string(); }
                let proj = ask_line("  Jira project key (e.g. SEC):");
                if !proj.trim().is_empty() { ig.jira.project_key = proj.trim().to_string(); }
                let it = ask_line("  Issue type [Bug]:");
                if !it.trim().is_empty() { ig.jira.issue_type = it.trim().to_string(); }
                ig.jira.enabled = true;
                let _ = ig.save(&dir);
                println!("  ✓ jira configured (project {}, {}). Now export {} and {} in your shell.",
                    ig.jira.project_key, ig.jira.base_url, ig.jira.email_env, ig.jira.token_env);
            }
            "gitlab" => {
                let b = ask_line("  GitLab base [https://gitlab.com]:");
                if !b.trim().is_empty() { ig.gitlab.base = b.trim().trim_end_matches('/').to_string(); }
                ig.gitlab.enabled = true;
                let _ = ig.save(&dir);
                println!("  ✓ gitlab enabled (base {}). Export {} (PAT with read_repository).", ig.gitlab.base, ig.gitlab.token_env);
            }
            "github" => {
                let a = ask_line("  GitHub API base [https://api.github.com] (change for GHE):");
                if !a.trim().is_empty() { ig.github.api = a.trim().trim_end_matches('/').to_string(); }
                ig.github.enabled = true;
                let _ = ig.save(&dir);
                println!("  ✓ github enabled (api {}). Export {} (PAT with repo scope).", ig.github.api, ig.github.token_env);
            }
            _ => println!("  usage: /integrations setup <jira|gitlab|github>"),
        },
        _ => println!("  usage: /integrations [show | enable <name> | disable <name> | setup <name>]"),
    }
}

fn ask_line(prompt: &str) -> String {
    use std::io::Write;
    print!("{prompt} ");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s
}

/// Arrow-key selection menu over findings; prints EVERYTHING about the chosen one
/// (command/PoC, evidence, impact, remediation, votes, confidence).
fn finding_detail(pool: &[Finding]) {
    if pool.is_empty() { println!("  no findings to inspect yet."); return; }
    let mut f = pool.to_vec();
    f.sort_by_key(|x| sev_rank(&x.severity));
    let items: Vec<String> = f.iter().map(|x| format!("[{}] {} — {}", x.severity, x.title, x.cwe)).collect();
    let idx = if std::io::stdin().is_terminal() {
        match dialoguer::Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a finding (↑/↓, enter)").items(&items).default(0).interact_opt() {
            Ok(Some(i)) => i, _ => return,
        }
    } else { 0 };
    print_finding_detail(&f[idx]);
}

/// Full detail card for one finding.
fn print_finding_detail(x: &Finding) {
    println!("\n  ┌─ \x1b[1m{}\x1b[0m", x.title);
    println!("  │  severity   : {}", x.severity);
    println!("  │  cwe / cvss : {} · {}", x.cwe, x.cvss);
    println!("  │  agent      : {}", x.agent);
    println!("  │  endpoint   : {}", x.endpoint);
    println!("  │  votes/conf : {} · {:.2}", x.votes, x.confidence);
    println!("  ├─ \x1b[33mPayload / PoC\x1b[0m");
    for l in x.payload.lines() { println!("  │  {l}"); }
    println!("  ├─ \x1b[36mEvidence (tool output)\x1b[0m");
    for l in x.evidence.lines() { println!("  │  {l}"); }
    println!("  ├─ Impact");
    for l in x.impact.lines() { println!("  │  {l}"); }
    println!("  ├─ Remediation");
    for l in x.remediation.lines() { println!("  │  {l}"); }
    println!("  └─────");
}

/// Interactive results browser: pick a target/run → pick a vulnerability → see
/// full detail. Esc steps back a level (vuln list → target list → exit to REPL).
fn browse_results(history: &[RunRecord]) {
    if history.is_empty() { println!("  no runs yet — /run first."); return; }
    if !std::io::stdin().is_terminal() { results(history, ""); return; }
    loop {
        // Level 1 — pick a run/target.
        let run_items: Vec<String> = history.iter().map(|r| {
            let c = sev_counts(&r.findings);
            let sev = if c.is_empty() { "0".into() } else { c.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
            let id = if r.id == 0 { "live".to_string() } else { format!("#{}", r.id) };
            format!("{:<5} {:<14} {:<40} [{}]", id, r.mode, trunc(&r.target, 40), sev)
        }).collect();
        let ri = match dialoguer::Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Results — select a test/run (↑/↓, enter · Esc returns to the session)")
            .items(&run_items).default(0).interact_opt() {
            Ok(Some(i)) => i,
            _ => { println!("  ← back to session"); return; }
        };
        let r = &history[ri];
        if r.findings.is_empty() {
            println!("  {} — no findings yet.", if r.id == 0 { "live run".into() } else { format!("run #{}", r.id) });
            continue;
        }
        let mut f = r.findings.clone();
        f.sort_by_key(|x| sev_rank(&x.severity));
        // Level 2 — pick a vulnerability (Esc → back to target list).
        loop {
            let items: Vec<String> = f.iter().map(|x| format!("[{}] {} — {}", x.severity, x.title, x.cwe)).collect();
            let fi = match dialoguer::Select::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("#{} {} — select a vulnerability (Esc = back)", r.id, trunc(&r.target, 36)))
                .items(&items).default(0).interact_opt() {
                Ok(Some(i)) => i,
                _ => break, // Esc → back to target list
            };
            print_finding_detail(&f[fi]);
            // Enter → back to the vuln list; Esc → back to the target list.
            if let Ok(None) = dialoguer::Select::with_theme(&ColorfulTheme::default())
                .with_prompt("↵ back to vulnerabilities · Esc = back to targets")
                .items(&["back"]).default(0).interact_opt() { break }
        }
    }
}

fn run_status(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    match std::fs::read_to_string(Path::new(&r.workdir).join("status.json")) {
        Ok(txt) => println!("  run #{}: {}", r.id, txt.trim()),
        Err(_) => println!("  run #{}: no status.json ({})", r.id, r.workdir),
    }
}

fn show(s: &Session) {
    let mode = match s.scope {
        "infra" => "infra/host (Linux/Windows/AD)",
        "cloud" => "cloud (AWS/GCP/Azure)",
        "ai" => "ai/llm (OWASP LLM Top 10 + MCP)",
        "skills" => "skills/n8n audit (white-box files)",
        _ => match (&s.repo, &s.target) {
            (Some(_), Some(_)) => "greybox (code + live)",
            (Some(_), None) => "white-box (code)",
            (None, Some(_)) => "black-box (live)",
            _ => "(set /target and/or /repo — or /onboard)",
        },
    };
    println!("  ┌─ session");
    println!("  │  scope    : {} \x1b[2m(/onboard to change)\x1b[0m", s.scope);
    println!("  │  models   : {}", s.models.join(", "));
    println!("  │  auth mode: {}", if s.subscription { "subscription (CLI login)" } else { "API key" });
    println!("  │  mode     : {mode}");
    println!("  │  target   : {}", s.target.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  repo     : {}", s.repo.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  auth     : {}", s.auth.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  creds    : {}", s.creds.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  proxy    : {}", s.proxy.clone().unwrap_or_else(|| "(none — /proxy for Burp/ZAP)".into()));
    println!("  │  user-agent: {}", s.user_agent.clone().unwrap_or_else(|| "NeuroSploit (default)".into()));
    println!("  │  focus    : {}", s.instructions.clone().unwrap_or_else(|| "(none — tests everything)".into()));
    println!("  │  objective: {}", s.objective.clone().unwrap_or_else(|| "(none — /objective <goal/context>)".into()));
    println!("  │  out-scope: {}", s.out_of_scope.clone().unwrap_or_else(|| "(none — /scope-out <exclusions>)".into()));
    println!("  │  opts     : mcp={} offline={} votes={} recon={} chain-depth={} max-agents={} idle-stop={} temp-email={}",
        onoff(s.mcp), onoff(s.offline), s.vote_n, s.recon_intensity, s.chain_depth, s.max_agents,
        if s.idle_secs == 0 { "off".to_string() } else { format!("{}m", s.idle_secs / 60) }, onoff(s.temp_email));
    // Integrations at a glance (see /integrations for detail).
    {
        let ig = harness::integrations::Integrations::load(&proj_dir());
        let on: Vec<&str> = [(ig.github.enabled, "github"), (ig.gitlab.enabled, "gitlab"), (ig.jira.enabled, "jira")]
            .iter().filter(|(e, _)| *e).map(|(_, n)| *n).collect();
        println!("  │  integr.  : {}", if on.is_empty() { "(none — /integrations)".into() } else { on.join(", ") });
    }
    // API-key status for the providers your selected models need.
    if !s.subscription {
        let provs: std::collections::BTreeSet<String> = s.models.iter()
            .map(|m| m.split(':').next().unwrap_or("").to_string()).collect();
        let mut keys = Vec::new();
        for p in &provs {
            if let Some(pr) = harness::provider_for(p) {
                let set = std::env::var(pr.env_key).map(|v| !v.is_empty()).unwrap_or(false);
                keys.push(format!("{p}={}", if set { "✓" } else { "✗" }));
            }
        }
        if !keys.is_empty() { println!("  │  api keys : {}", keys.join("  ")); }
    }
    println!("  └─ /run to launch  ·  edit with /target /repo /auth /creds /focus /model");
}

fn help() {
    let h = |c: &str, d: &str| println!("    \x1b[36m{c:<20}\x1b[0m {d}");
    println!("\n  \x1b[1mNeuroSploit REPL — commands\x1b[0m");

    println!("\n  \x1b[2mNATURAL LANGUAGE (any language — just type, no slash)\x1b[0m");
    println!("    e.g. \x1b[36mtesta https://loja.com com opus, foco em SQLi, fora de escopo /admin, usa burp, roda\x1b[0m");
    println!("    \x1b[2msets target/models/focus/objective/out-of-scope + toggles (burp·browser·votes·recon),\x1b[0m");
    println!("    \x1b[2mand can launch or stop — hands-free. Ambiguous phrasing falls back to the model.\x1b[0m");

    println!("\n  \x1b[2mTARGET & SCOPE\x1b[0m");
    h("/onboard",           "guided setup: pick scope (web · infra · cloud · ai/llm · skills/n8n)");
    h("/target <url[,..]>", "black-box target / AI endpoint / host (comma-separated = multi-target)");
    h("/repo <path|url>",   "source repo (greybox) OR skill/n8n file/folder to audit (skills scope)");
    h("/auth <value>",      "auth header (Bearer/cookie/key). Roles: /auth admin <hdr> · /auth user <hdr>");
    h("/creds <file.yaml>", "creds: jwt/header/cookie/login + ssh/windows + aws/gcp/azure + roles");
    h("/focus <text>",      "steer the tests (or just type the instruction)");
    h("/objective <text>",  "engagement goal/context — shapes what agents prioritise & count as impact");
    h("/scope-out <text>",  "out-of-scope exclusions — hard constraint, agents skip these (clear to reset)");
    h("@path @dir @f:1-20", "attach a file/folder/line-range to context (Tab → menu)");
    h("/attach <path>",     "attach a file/folder to context");
    h("/context",           "list current attachments");

    println!("\n  \x1b[2mMODELS & AUTH\x1b[0m");
    h("/model [a:b,..]",    "set models (no arg → arrow-key multi-select)");
    h("/providers",         "list providers & models");
    h("/key [prov key]",    "configure API keys for your models (no arg → guided)");
    h("/sub on|off",        "use local subscription login instead of an API key");

    println!("\n  \x1b[2mRUN & MONITOR\x1b[0m");
    h("/run",               "launch (runs in the BACKGROUND — keep typing)");
    h("/status [n]",        "live progress + findings while running (or a past run #)");
    h("/logs [n]",          "recent activity feed of the running test (recon/tools/findings)");
    h("/stop",              "stop: [1] validate+report  [2] raw report now  [3] discard");
    h("/continue",          "resume a paused (token/quota) OR a recovered interrupted run — carries findings forward");
    h("/results [n]",       "browse findings (target → vuln → detail; Esc = back)");
    h("/finding [n]",       "pick a finding and see its command + PoC + evidence");
    h("/report [n]",        "open a run's report (menu if several)");
    h("/runs",              "list all runs");
    h("/diff",              "what changed vs the last run");
    h("/retest [n]",        "re-verify a past run's findings (re-runs the test)");
    h("/validate [n]",      "false-positive validate a recovered/past run (no re-test)");

    println!("\n  \x1b[2mINTEGRATIONS\x1b[0m");
    h("/integrations",      "show · enable/disable github|gitlab|jira · setup <name>");

    println!("\n  \x1b[2mOPTIONS\x1b[0m");
    h("/mcp on|off",        "Playwright MCP browser (prove client-side issues)");
    h("/offline on|off",    "pipeline self-test (no API keys / no model calls)");
    h("/votes <n>",         "number of validator votes per finding");
    h("/chain <n>",         "attack-chain depth (post-exploitation pivots; 0 = off)");
    h("/recon <1-4>",       "recon intensity: 1 quick · 2 standard · 3 deep · 4 exhaustive (installs tools)");
    h("/tempmail on|off",   "opt-in disposable inbox (mail.tm) to read a register confirmation code");
    h("/timeout <min>",     "idle guardrail: stop if no new finding in <min> (0 = off)");
    h("/proxy <url>|off",   "route agent HTTP through Burp/ZAP  (/burp = default :8080)");
    h("/ua <string>",       "identifying User-Agent for NeuroSploit traffic (default = NeuroSploit)");
    h("/agents <n>|list",   "cap agents to run · `list` shows library counts");
    h("/theme color|mono",  "toggle colored output");
    h("/show",              "show the current session config");
    h("/clear",             "clear the screen");
    h("/quit",              "save session and exit");

    println!("\n  \x1b[2mMODES — black-box: set /target · white-box: set /repo · grey-box: set BOTH /repo + /target · host: /target <ip> + /creds\x1b[0m");
    println!("  \x1b[2mFindings are checkpointed live to .neurosploit/ — quit/crash mid-run and they're recovered into /runs next launch.\x1b[0m");
    println!("  \x1b[2mIf tokens/quota run out the run PAUSES (state kept) — /continue to resume, or switch with /model then /continue.\x1b[0m");
    println!("  \x1b[2m↑/↓ history · Tab completes commands & @paths · Ctrl-A/E/K edit · Ctrl-O full cmd · \\ for multiline\x1b[0m\n");
}

// ===== Natural-language command interpreter (hybrid) =====

/// A parsed engagement intent extracted from a natural-language line.
#[derive(Default)]
struct Intent {
    target: Option<String>,
    repo: Option<String>,
    models: Vec<String>,
    focus: Option<String>,
    objective: Option<String>,
    out_of_scope: Option<String>,
    auth: Option<String>,
    scope: Option<&'static str>,
    // Toggles/knobs the user can ask for in words.
    mcp: Option<bool>,          // "usa navegador/browser", "ativa mcp"
    proxy: Option<String>,      // "manda pro burp", "usa proxy 127.0.0.1:8080"
    subscription: Option<bool>, // "usa minha assinatura/login"
    vote_n: Option<usize>,      // "3 votos", "5 votes"
    recon: Option<usize>,       // "recon profundo/exaustivo", "recon 4"
    run: bool,
    stop: bool,                 // "para", "stop", "cancela"
}

impl Intent {
    fn is_empty(&self) -> bool {
        self.target.is_none() && self.repo.is_none() && self.models.is_empty()
            && self.focus.is_none() && self.objective.is_none() && self.out_of_scope.is_none()
            && self.auth.is_none() && self.scope.is_none()
            && self.mcp.is_none() && self.proxy.is_none() && self.subscription.is_none()
            && self.vote_n.is_none() && self.recon.is_none() && !self.run && !self.stop
    }
    /// Fill any field this intent is missing from `other` (deterministic wins).
    fn merge_from(&mut self, other: Intent) {
        if self.target.is_none() { self.target = other.target; }
        if self.repo.is_none() { self.repo = other.repo; }
        if self.models.is_empty() { self.models = other.models; }
        if self.focus.is_none() { self.focus = other.focus; }
        if self.objective.is_none() { self.objective = other.objective; }
        if self.out_of_scope.is_none() { self.out_of_scope = other.out_of_scope; }
        if self.auth.is_none() { self.auth = other.auth; }
        if self.scope.is_none() { self.scope = other.scope; }
        if self.mcp.is_none() { self.mcp = other.mcp; }
        if self.proxy.is_none() { self.proxy = other.proxy; }
        if self.subscription.is_none() { self.subscription = other.subscription; }
        if self.vote_n.is_none() { self.vote_n = other.vote_n; }
        if self.recon.is_none() { self.recon = other.recon; }
        self.run = self.run || other.run;
        self.stop = self.stop || other.stop;
    }
}

/// Resolve a natural-language line into session config. Deterministic fast-path
/// first (0 tokens); if the phrase is ambiguous and a model is available, ask it
/// to structure the request (works in any language). Returns a follow-up command
/// to execute ("/run" or "/stop"), or None when it only reconfigured.
async fn handle_nl(line: &str, s: &mut Session) -> Option<&'static str> {
    let (mut intent, confident) = parse_intent_fast(line);
    if !confident && !s.offline {
        if let Some(mi) = parse_intent_model(line, s).await {
            intent.merge_from(mi);
        }
    }
    if intent.is_empty() {
        // Nothing structured found → treat the whole line as focus (old behavior).
        s.instructions = Some(line.to_string());
        println!("  focus set: {line}");
        return None;
    }
    apply_intent(s, intent)
}

/// Apply an intent to the session, print a summary, and return the follow-up
/// command ("/run" | "/stop") or None.
fn apply_intent(s: &mut Session, intent: Intent) -> Option<&'static str> {
    let mut set = Vec::new();
    if let Some(t) = intent.target {
        let t = if t.starts_with("http") || t.contains("://") { t } else { format!("https://{t}") };
        s.target = Some(t.clone()); set.push(format!("target={t}"));
    }
    if let Some(r) = intent.repo { s.repo = Some(r.clone()); set.push(format!("repo={r}")); }
    if !intent.models.is_empty() {
        let m = resolve_model_aliases(&intent.models);
        if !m.is_empty() { s.models = m.clone(); set.push(format!("models={}", m.join(","))); }
    }
    if let Some(sc) = intent.scope { s.scope = sc; set.push(format!("scope={sc}")); }
    if let Some(f) = intent.focus { s.instructions = Some(f.clone()); set.push(format!("focus=\"{f}\"")); }
    if let Some(o) = intent.objective { s.objective = Some(o.clone()); set.push(format!("objective=\"{o}\"")); }
    if let Some(x) = intent.out_of_scope { s.out_of_scope = Some(x.clone()); set.push(format!("out-of-scope=\"{x}\"")); }
    if let Some(a) = intent.auth { let a = normalize_auth(&a); s.auth = Some(a.clone()); set.push("auth set".into()); let _ = a; }
    if let Some(b) = intent.mcp { s.mcp = b; set.push(format!("mcp={}", onoff(b))); }
    if let Some(p) = intent.proxy {
        let p = if p.starts_with("http") { p } else { format!("http://{p}") };
        s.proxy = Some(p.clone()); set.push(format!("proxy={p}"));
    }
    if let Some(b) = intent.subscription { s.subscription = b; set.push(format!("subscription={}", onoff(b))); }
    if let Some(v) = intent.vote_n { s.vote_n = v; set.push(format!("votes={v}")); }
    if let Some(r) = intent.recon { s.recon_intensity = r.clamp(1, 4); set.push(format!("recon={}", s.recon_intensity)); }
    if set.is_empty() && !intent.stop {
        println!("  \x1b[2m(understood — nothing to change)\x1b[0m");
    } else if !set.is_empty() {
        println!("  \x1b[36m⇢ configured\x1b[0m {}", set.join(" · "));
    }
    if intent.stop {
        println!("  \x1b[1;33m⏸ stopping\x1b[0m …");
        return Some("/stop");
    }
    if intent.run {
        if s.target.is_none() && s.repo.is_none() {
            println!("  \x1b[33m! set a target/repo first — nothing to run yet.\x1b[0m");
            return None;
        }
        println!("  \x1b[1;35m▶ launching\x1b[0m …");
        return Some("/run");
    }
    None
}

/// Deterministic, zero-token parse for the common phrasings (PT/EN/ES). Returns
/// `(intent, confident)`; `confident=false` means hand off to the model.
fn parse_intent_fast(line: &str) -> (Intent, bool) {
    let mut it = Intent::default();
    let low = line.to_lowercase();

    // URL or bare host.
    if let Some(u) = find_url(line) {
        if u.contains("://") || looks_like_host(&u) { it.target = Some(u); }
    }
    // Model shorthands present anywhere.
    for alias in ["opus", "sonnet", "haiku", "gpt", "chatgpt", "gemini", "grok"] {
        if word_present(&low, alias) && !it.models.iter().any(|m| m == alias) {
            it.models.push(alias.to_string());
        }
    }
    // Run verbs (any of the three languages).
    const RUN_VERBS: &[&str] = &[
        "run", "test", "scan", "go", "launch", "execute",
        "roda", "rode", "rodar", "testa", "teste", "testar", "escaneia", "escanear",
        "executa", "executar", "varre", "varrer", "analisa", "analise", "ataca", "atacar",
        "prueba", "probar", "escanea", "ejecuta", "corre", "lanza", "lanzar",
    ];
    if RUN_VERBS.iter().any(|v| word_present(&low, v)) { it.run = true; }
    // Stop verbs.
    const STOP_VERBS: &[&str] = &["stop", "para", "pare", "parar", "cancel", "cancela", "cancelar", "aborta", "abortar", "halt", "detén", "detener", "para tudo"];
    if STOP_VERBS.iter().any(|v| word_present(&low, v)) { it.stop = true; }

    // Spoken toggles/knobs (PT/EN/ES). Only set when clearly mentioned.
    if word_present(&low, "burp") || low.contains("intercept") { it.proxy = Some("http://127.0.0.1:8080".into()); }
    if low.contains("browser") || low.contains("navegador") || low.contains("navegou") || low.contains("playwright") || word_present(&low, "mcp") {
        it.mcp = Some(!(low.contains("sem navegador") || low.contains("no browser") || low.contains("sin navegador")));
    }
    if low.contains("assinatura") || low.contains("subscription") || low.contains("meu login") || low.contains("mi cuenta") || low.contains("suscripción") {
        it.subscription = Some(true);
    }
    // "3 votos" / "5 votes" / "2 votos de validação".
    if let Some(n) = number_before_any(&low, &["voto", "votos", "vote", "votes"]) { it.vote_n = Some(n as usize); }
    // Recon depth: explicit number 1-4 or a qualitative word.
    if let Some(n) = number_before_any(&low, &["recon"]) { if (1..=4).contains(&n) { it.recon = Some(n as usize); } }
    if it.recon.is_none() && low.contains("recon") {
        if low.contains("exausti") || low.contains("exhaust") { it.recon = Some(4); }
        else if low.contains("profund") || low.contains("deep") || low.contains("profundo") { it.recon = Some(3); }
        else if low.contains("rápid") || low.contains("rapid") || low.contains("quick") || low.contains("quick") { it.recon = Some(1); }
    }

    // Keyworded clauses: split on commas/semicolons and classify each chunk.
    let mut residue = 0usize;
    for chunk in line.split([',', ';', '\n']) {
        let c = chunk.trim();
        if c.is_empty() { continue; }
        let cl = c.to_lowercase();
        if let Some(rest) = after_any(&cl, c, &["fora de escopo", "fora do escopo", "out of scope", "out-of-scope", "fuera de alcance", "não teste", "nao teste", "não testar", "nao testar", "don't test", "do not test", "exclua", "excluir", "excluye"]) {
            if !rest.is_empty() { it.out_of_scope = Some(join_opt(it.out_of_scope.take(), rest)); continue; }
        }
        if let Some(rest) = after_any(&cl, c, &["objetivo", "objective", "meta", "contexto", "context", "goal"]) {
            if !rest.is_empty() { it.objective = Some(rest.to_string()); continue; }
        }
        if let Some(rest) = after_any(&cl, c, &["foco em", "foca em", "foco", "focus on", "focus", "enfoque en", "enfoque", "concentre em", "concentra em", "prioriza", "priorize"]) {
            if !rest.is_empty() { it.focus = Some(join_opt(it.focus.take(), rest)); continue; }
        }
        if let Some(rest) = after_any(&cl, c, &["auth", "authorization", "cookie", "bearer", "token", "header"]) {
            if !rest.is_empty() { it.auth = Some(c.to_string()); let _ = rest; continue; }
        }
        // Chunk that carried the URL / model / run verb is accounted for.
        let carried = it.target.as_deref().map(|t| c.contains(t.trim_start_matches("https://").trim_start_matches("http://")) || cl.contains("http")).unwrap_or(false)
            || RUN_VERBS.iter().any(|v| word_present(&cl, v))
            || ["opus","sonnet","haiku","gpt","chatgpt","gemini","grok"].iter().any(|a| word_present(&cl, a));
        if !carried { residue += c.split_whitespace().count(); }
    }
    // Confident when we structured something and no meaningful unclassified words remain.
    let confident = !it.is_empty() && residue <= 2;
    (it, confident)
}

/// Ask the configured model to structure a free-form request into JSON. Any
/// language. Returns None on any failure (caller falls back gracefully).
async fn parse_intent_model(line: &str, s: &Session) -> Option<Intent> {
    let refs: Vec<ModelRef> = s.models.iter().map(|m| ModelRef::parse(m)).collect();
    if refs.is_empty() { return None; }
    let pool = harness::pool::ModelPool::with_auth(refs, 1, s.subscription, None);
    let sys = "You convert a penetration tester's natural-language request (in ANY language) \
        into a compact JSON object that configures a scan. Keys (include ONLY those the user \
        expressed): target (url or host), repo (path/github), models (array of short names like \
        opus/sonnet/gpt/gemini/grok), focus (what to prioritise), objective (goal/context), \
        out_of_scope (exclusions), auth (header/cookie/token verbatim), scope (one of web|infra|cloud|ai|skills), \
        run (true only if the user clearly asked to start/execute now). Reply with ONLY the JSON object, no prose.";
    let user = format!("Request: {line}");
    let (_, text) = pool.complete(sys, &user).await.ok()?;
    let slice = {
        let a = text.find('{')?; let b = text.rfind('}')?;
        if b > a { &text[a..=b] } else { return None }
    };
    let v: serde_json::Value = serde_json::from_str(slice).ok()?;
    let o = v.as_object()?;
    let gs = |k: &str| o.get(k).and_then(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
    let mut it = Intent {
        target: gs("target"),
        repo: gs("repo"),
        focus: gs("focus"),
        objective: gs("objective"),
        out_of_scope: gs("out_of_scope"),
        auth: gs("auth"),
        run: o.get("run").and_then(|x| x.as_bool()).unwrap_or(false),
        ..Default::default()
    };
    if let Some(sc) = gs("scope") {
        it.scope = match sc.as_str() {
            "web" => Some("web"), "infra" => Some("infra"), "cloud" => Some("cloud"),
            "ai" => Some("ai"), "skills" => Some("skills"), _ => None,
        };
    }
    match o.get("models") {
        Some(serde_json::Value::Array(a)) => {
            for m in a { if let Some(t) = m.as_str() { if !t.trim().is_empty() { it.models.push(t.trim().to_string()); } } }
        }
        Some(serde_json::Value::String(t)) if !t.trim().is_empty() => it.models.push(t.trim().to_string()),
        _ => {}
    }
    if it.is_empty() { None } else { Some(it) }
}

/// Map short model names (opus/gpt/gemini/...) to concrete `provider:model` ids
/// from the catalog. Passes through anything already in `provider:model` form.
fn resolve_model_aliases(names: &[String]) -> Vec<String> {
    let catalog: Vec<String> = harness::providers().into_iter()
        .flat_map(|p| p.models.iter().map(move |m| format!("{}:{}", p.key, m)).collect::<Vec<_>>())
        .collect();
    let mut out = Vec::new();
    for n in names {
        let nl = n.to_lowercase();
        if nl.contains(':') { out.push(n.clone()); continue; } // already provider:model
        let needle = match nl.as_str() { "chatgpt" => "gpt", other => other };
        if let Some(id) = catalog.iter().find(|id| id.to_lowercase().contains(needle)) {
            if !out.contains(id) { out.push(id.clone()); }
        }
    }
    out
}

/// First http(s) URL or bare `host[/path]` token in the line.
fn find_url(line: &str) -> Option<String> {
    for tok in line.split_whitespace() {
        let t = tok.trim_matches(|c: char| ",;\"'()[]".contains(c));
        if t.starts_with("http://") || t.starts_with("https://") { return Some(t.to_string()); }
    }
    for tok in line.split_whitespace() {
        let t = tok.trim_matches(|c: char| ",;\"'()[]".contains(c));
        if looks_like_host(t) { return Some(t.to_string()); }
    }
    None
}

/// Heuristic: `something.tld` (optionally with a path), not a bare sentence word.
fn looks_like_host(t: &str) -> bool {
    let host = t.split('/').next().unwrap_or(t);
    if !host.contains('.') || host.starts_with('.') || host.ends_with('.') { return false; }
    let tld = host.rsplit('.').next().unwrap_or("");
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Whole-word membership check (avoids matching "go" inside "google").
fn word_present(hay_low: &str, word: &str) -> bool {
    hay_low.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == word)
}

/// If `chunk_low` starts with (or contains) any keyword, return the ORIGINAL-case
/// remainder after the keyword.
fn after_any<'a>(chunk_low: &str, chunk_orig: &'a str, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(pos) = chunk_low.find(k) {
            let end = pos + k.len();
            let rest = chunk_orig[end..].trim_start_matches([':', ' ', '=', '-']).trim();
            return Some(rest);
        }
    }
    None
}

fn join_opt(prev: Option<String>, add: &str) -> String {
    match prev {
        Some(p) if !p.trim().is_empty() => format!("{p}; {add}"),
        _ => add.to_string(),
    }
}

/// First integer that appears immediately before any of `keys` (e.g. "3 votos"
/// with keys ["votos"] → 3), scanning token pairs. Returns None if not found.
fn number_before_any(low: &str, keys: &[&str]) -> Option<u64> {
    let toks: Vec<&str> = low.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).collect();
    for w in toks.windows(2) {
        if keys.iter().any(|k| w[1].starts_with(k)) {
            if let Ok(n) = w[0].parse::<u64>() { return Some(n); }
        }
    }
    // Also "recon 4" (number AFTER the key).
    for w in toks.windows(2) {
        if keys.iter().any(|k| w[0].starts_with(k)) {
            if let Ok(n) = w[1].parse::<u64>() { return Some(n); }
        }
    }
    None
}

/// Scan a line for @path tokens, attach each referenced file/dir to context.
fn expand_ats(line: &str, s: &mut Session) -> usize {
    let mut n = 0;
    for tok in line.split_whitespace() {
        if let Some(p) = tok.strip_prefix('@') {
            n += attach_path(p, s);
        }
    }
    n
}

/// Attach a file's content (capped) or a directory listing to session context.
/// Supports @file, @folder, and @file:LINE / @file:START-END.
fn attach_path(spec: &str, s: &mut Session) -> usize {
    if spec.is_empty() { return 0; }
    let (path, range) = match spec.split_once(':') {
        Some((p, r)) => (p, Some(r)),
        None => (spec, None),
    };
    let pb = Path::new(path);
    if pb.is_dir() {
        let mut items: Vec<String> = std::fs::read_dir(pb).map(|rd| rd.flatten()
            .map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();
        items.sort();
        s.attachments.push(format!("// dir {path}:\n{}", items.join("\n")));
        println!("  + folder {path} ({} entries)", items.len());
        return 1;
    }
    match std::fs::read_to_string(pb) {
        Ok(content) => {
            let body = match range.and_then(parse_range) {
                Some((a, b)) => content.lines().enumerate()
                    .filter(|(i, _)| *i + 1 >= a && *i < b)
                    .map(|(_, l)| l).collect::<Vec<_>>().join("\n"),
                None => content.chars().take(8000).collect(),
            };
            println!("  + file {spec} ({} bytes)", body.len());
            s.attachments.push(format!("// file {spec}:\n{body}"));
            1
        }
        Err(_) => { println!("  \x1b[31m✗ cannot read @{spec}\x1b[0m"); 0 }
    }
}

fn parse_range(r: &str) -> Option<(usize, usize)> {
    match r.split_once('-') {
        Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
        None => { let n: usize = r.trim().parse().ok()?; Some((n, n)) }
    }
}

/// Context/status bar shown above the prompt — model · cwd · mode/target,
/// e.g.  "claude-opus-4-8 · /opt/projeto · black-box▸target".
fn context_prompt(s: &Session) -> String {
    let model = s.models.first().map(|m| m.split(':').next_back().unwrap_or(m)).unwrap_or("?");
    let auth = if s.subscription { "sub" } else { "api" };
    let cwd = std::env::current_dir().ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".into());
    let mode = match (&s.repo, &s.target) {
        (Some(_), Some(_)) => "greybox",
        (Some(_), None) => "white-box",
        (None, Some(_)) => "black-box",
        _ => "idle",
    };
    let tgt = s.target.clone().or_else(|| s.repo.clone()).unwrap_or_default();
    let tgt = if tgt.is_empty() { String::new() } else { format!("▸{}", tgt.replace("https://", "").replace("http://", "")) };
    // Dim context line, printed ABOVE the prompt (not part of the readline prompt,
    // so its ANSI/newline never corrupts rustyline's cursor math).
    format!("\x1b[2m{model} {auth} · {cwd} · {mode}{tgt}\x1b[0m")
}

/// The actual readline prompt — plain text so rustyline measures its width
/// correctly; color is applied by the Highlighter, not embedded here.
const PROMPT: &str = "neurosploit› ";

/// Sentinel returned by the reader on Ctrl-C so the loop can confirm before
/// exiting (instead of losing an active run to a stray interrupt).
const CTRL_C: &str = "\u{0}__ctrl_c__";

/// Turn a role value into a header line: a full `Header: value` is used as-is;
/// a bare token becomes `Authorization: Bearer <token>`.
fn normalize_auth(v: &str) -> String {
    let v = v.trim();
    if v.contains(':') { v.to_string() } else { format!("Authorization: Bearer {v}") }
}

/// Build the multi-role access-control directive from the session roles (mirrors
/// creds.yaml roles). Empty when fewer than 2 identities.
fn roles_directive(roles: &[(String, String)]) -> Option<String> {
    if roles.len() < 2 { return None; }
    let list = roles.iter().map(|(n, v)| format!("  - {n} → send `{v}`")).collect::<Vec<_>>().join("\n");
    Some(format!(
        "MULTI-ROLE ACCESS CONTROL — you have {} identities:\n{list}\n\
         Authenticate as EACH identity (send its header on every request). Test broken access control ACROSS roles and \
         compare authorized vs unauthorized:\n\
         - BOLA/IDOR: as a low-privilege role capture your own object IDs, then read/modify another role's objects by ID.\n\
         - BFLA: call admin-only functions/endpoints/HTTP methods with a low-privilege role's session.\n\
         - Privilege escalation: mass-assignment of role/permission fields, or reaching admin routes.\n\
         Prove each with the two requests (authorized role succeeds, unauthorized role should be denied but isn't). \
         Read-only proof; mask any PII.\n\n",
        roles.len()))
}

/// Split the session target into one or more URLs (comma-separated list).
fn session_targets(s: &Session) -> Vec<String> {
    s.target.as_deref().map(|t| t.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default()
}

fn onoff(b: bool) -> &'static str { if b { "on" } else { "off" } }
fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() }
    else { format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>()) }
}

#[cfg(test)]
mod nl_tests {
    use super::*;

    #[test]
    fn fast_parse_pt_target_model_run() {
        let (it, conf) = parse_intent_fast("testa https://loja.com com opus");
        assert!(conf);
        assert_eq!(it.target.as_deref(), Some("https://loja.com"));
        assert!(it.models.contains(&"opus".to_string()));
        assert!(it.run);
    }

    #[test]
    fn fast_parse_clauses_focus_and_scope() {
        let (it, _) = parse_intent_fast("scan loja.com, foco em SQLi e IDOR, fora de escopo /admin, roda");
        assert_eq!(it.target.as_deref(), Some("loja.com"));
        assert_eq!(it.focus.as_deref(), Some("SQLi e IDOR"));
        assert_eq!(it.out_of_scope.as_deref(), Some("/admin"));
        assert!(it.run);
    }

    #[test]
    fn fast_parse_english_and_spanish_run_verbs() {
        assert!(parse_intent_fast("run against example.com").0.run);
        assert!(parse_intent_fast("prueba example.org enfoque en XSS").0.run);
    }

    #[test]
    fn ambiguous_freeform_not_confident() {
        // No URL, no verb, vague -> defer to model.
        let (_it, conf) = parse_intent_fast("da uma olhada naquele site da firma quando puder");
        assert!(!conf);
    }

    #[test]
    fn host_heuristic_rejects_plain_words() {
        assert!(find_url("focar em sqli agora").is_none());
        assert_eq!(find_url("check testphp.vulnweb.com now").as_deref(), Some("testphp.vulnweb.com"));
    }

    #[test]
    fn model_alias_resolves_to_catalog_id() {
        let ids = resolve_model_aliases(&["opus".to_string()]);
        assert!(ids.iter().all(|i| i.contains(':')));
        assert!(ids.iter().any(|i| i.to_lowercase().contains("opus")));
    }

    #[test]
    fn fast_parse_spoken_toggles() {
        let (it, _) = parse_intent_fast("testa loja.com com opus, usa burp, 5 votos, recon profundo, roda");
        assert_eq!(it.proxy.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(it.vote_n, Some(5));
        assert_eq!(it.recon, Some(3));
        assert!(it.run);
    }

    #[test]
    fn fast_parse_stop_and_browser() {
        assert!(parse_intent_fast("para tudo agora").0.stop);
        assert_eq!(parse_intent_fast("usa o navegador").0.mcp, Some(true));
        assert_eq!(parse_intent_fast("recon 4 em example.com").0.recon, Some(4));
    }

}
