//! NeuroSploit v3.5.2 — interactive session (Claude-Code / Codex / Cursor-CLI style).
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
        if low.contains("token/quota exhausted") || low.contains("run is paused") { self.phase = "paused (quota)".into(); }
        else if low.contains("resumed — retrying") { self.phase = "exploiting".into(); }
        else if low.contains("recon complete") { self.phase = "recon".into(); }
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
    "/help", "/show", "/config", "/providers", "/model", "/key", "/sub", "/target",
    "/repo", "/auth", "/creds", "/focus", "/attach", "/context", "/mcp", "/offline",
    "/votes", "/agents", "/theme", "/clear", "/run", "/stop", "/continue", "/runs", "/results", "/report",
    "/status", "/diff", "/retest", "/quit",
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
impl Highlighter for NsHelper {}
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
    offline: bool,
    target: Option<String>,
    repo: Option<String>,
    auth: Option<String>,
    creds: Option<String>,
    instructions: Option<String>,
    attachments: Vec<String>,
    color: bool,
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
            attachments: Vec::new(),
            color: true,
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
                Err(ReadlineError::Interrupted) => Some(String::new()), // Ctrl-C: cancel line
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

pub async fn repl(base: &Path) -> anyhow::Result<()> {
    let lib = agents::load(base);
    let backends = harness::installed_cli_backends();
    println!("\x1b[1m");
    println!("  ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗");
    println!("  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit v3.5.2");
    println!("  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   interactive harness");
    println!("  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos");
    println!("  ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders");
    println!("  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝\x1b[0m");
    println!("  {} agents loaded · detected logins: {}", lib.total(),
        if backends.is_empty() { "none (use API keys)".into() } else { backends.join(", ") });
    println!("  Type \x1b[36m/help\x1b[0m to start, \x1b[36m/run\x1b[0m to launch, \x1b[36m/quit\x1b[0m to exit. (↑/↓ recalls commands)\n");

    let mut s = Session::default();
    let resumed = load_session(&mut s);
    // Shared so a background run's forwarder task can append to it.
    let history: Arc<Mutex<Vec<RunRecord>>> = Arc::new(Mutex::new(load_runs(base)));
    let past = history.lock().unwrap().len();
    if resumed || past > 0 {
        println!("  ↻ resumed project session from {} — {} past run(s)", proj_dir().display(), past);
    }
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
        }
        clear_checkpoint();
    }
    println!();
    let mut reader = Reader::new(base);
    let mut active: Option<ActiveRun> = None;
    show(&s);

    loop {
        let Some(line) = reader.read(&context_prompt(&s)) else { println!("\n  bye."); break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('/') {
            let attached = expand_ats(line, &mut s);
            s.instructions = Some(line.to_string());
            println!("  focus set: {line}");
            if attached > 0 { println!("  ({attached} @attachment(s) added to context)"); }
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
                if arg.is_empty() { println!("  target: {}", s.target.clone().unwrap_or_else(|| "(none) — set with /target <url>, clear with /target clear".into())); }
                else if arg == "clear" { s.target = None; println!("  target cleared"); }
                else { let t = if arg.starts_with("http") { arg.to_string() } else { format!("https://{arg}") };
                       s.target = Some(t.clone()); println!("  target: {t}"); }
            }
            "/repo" => {
                if arg.is_empty() { println!("  repo: {}", s.repo.clone().unwrap_or_else(|| "(none) — set with /repo <path>, clear with /repo clear".into())); }
                else if arg == "clear" { s.repo = None; println!("  repo cleared"); }
                else { s.repo = Some(arg.to_string()); println!("  repo: {arg}"); }
            }
            "/auth" => {
                if arg.is_empty() { println!("  auth: {}", s.auth.clone().unwrap_or_else(|| "(none) — set with /auth <header>, clear with /auth clear".into())); }
                else if arg == "clear" { s.auth = None; println!("  auth cleared"); }
                else { s.auth = Some(arg.to_string()); println!("  auth set: {arg}"); }
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
            "/votes" => { s.vote_n = arg.parse().unwrap_or(s.vote_n); println!("  votes: {}", s.vote_n); }
            "/agents" => { s.max_agents = arg.parse().unwrap_or(s.max_agents); println!("  max agents: {}", s.max_agents); }
            "/clear" => { print!("\x1b[2J\x1b[H"); }
            "/run" | "/go" => {
                if active.as_ref().map(|a| !a.done.load(Ordering::Relaxed)).unwrap_or(false) {
                    println!("  a run is already active — /status to check, /stop to halt it.");
                } else {
                    save_session(&s);
                    match start_background(base, &s, &mut reader, history.clone()).await {
                        Some(a) => { active = Some(a); println!("  \x1b[1;35m▶ running in background\x1b[0m — keep typing · \x1b[36m/status\x1b[0m · \x1b[36m/stop\x1b[0m"); }
                        None => { // no external printer (piped) → blocking fallback
                            let mut h = history.lock().unwrap();
                            run(base, &s, &mut h).await; save_runs(base, &h);
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
                match &active {
                    Some(a) if a.paused.load(Ordering::Relaxed) => {
                        if !arg.is_empty() {
                            let m = ModelRef::parse(arg);
                            println!("  \x1b[1;35m▶ resuming with fallback model\x1b[0m {}:{}", m.provider, m.model);
                            a.fallback.lock().unwrap().push(m);
                        } else {
                            println!("  \x1b[1;35m▶ resuming\x1b[0m — retrying with the current model(s).");
                        }
                        a.paused.store(false, Ordering::Relaxed);
                        a.resume.notify_waiters();
                    }
                    Some(a) if !a.done.load(Ordering::Relaxed) => println!("  run is not paused — it's still working. /status to check."),
                    _ => println!("  no paused run. (a run pauses automatically if your tokens/quota run out)"),
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
            "/results" => {
                // Live findings while a run is active (no arg), else a past run.
                match &active {
                    Some(a) if arg.is_empty() && !a.done.load(Ordering::Relaxed) => {
                        let l = a.live.lock().unwrap();
                        println!("  ▶ live — {} possible finding(s) so far ({})", l.full.len(), l.phase);
                        let mut f = l.full.clone();
                        f.sort_by_key(|x| sev_rank(&x.severity));
                        for x in &f { println!("  • [{}] {} \x1b[2m({} · {})\x1b[0m", x.severity, x.title, x.agent, x.endpoint); }
                        if !f.is_empty() { println!("  \x1b[2m/finding — pick one to see the command & PoC\x1b[0m"); }
                    }
                    _ => results(&history.lock().unwrap(), arg),
                }
            }
            "/finding" | "/findings" => {
                // Build the finding pool: live run if active, else a past run.
                let pool: Vec<Finding> = match &active {
                    Some(a) if arg.is_empty() && !a.done.load(Ordering::Relaxed) => a.live.lock().unwrap().full.clone(),
                    _ => { let h = history.lock().unwrap(); pick(&h, arg).map(|r| r.findings.clone()).unwrap_or_default() }
                };
                finding_detail(&pool);
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
            "/report" => open_report(&history.lock().unwrap(), arg),
            "/status" => {
                // Live status if a run is active, else a past run's status.json.
                match &active {
                    Some(a) if arg.is_empty() && !a.done.load(Ordering::Relaxed) => {
                        let l = a.live.lock().unwrap();
                        let el = l.started.elapsed().as_secs();
                        let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
                        for (sv, _) in &l.findings { *by.entry(sv.as_str()).or_insert(0) += 1; }
                        let sev = if by.is_empty() { "0".into() } else { by.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
                        println!("  \x1b[1m▶ live\x1b[0m {} ({}) · phase {} · {:02}:{:02} · {} possible finding(s) [{}]",
                            l.target, l.mode, l.phase, el / 60, el % 60, l.findings.len(), sev);
                        if a.paused.load(Ordering::Relaxed) {
                            println!("    \x1b[1;33m⏸ PAUSED — token/quota exhausted. /continue to resume, or /model <provider:model> then /continue to switch.\x1b[0m");
                        }
                        if l.agents > 0 { println!("    progress \x1b[36m{}\x1b[0m", l.bar(24)); }
                        for (sv, t) in l.findings.iter().rev().take(5) { println!("    ✦ [{sv}] {t}"); }
                    }
                    _ => run_status(&history.lock().unwrap(), arg),
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
    cfg.auth = s.auth.clone();
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
                          history: Arc<Mutex<Vec<RunRecord>>>) -> Option<ActiveRun> {
    let (target, mode_s, mode_e, mcp) = match (&s.repo, &s.target) {
        (Some(_), Some(t)) => (t.clone(), "greybox", crate::Mode::Grey, s.mcp),
        (Some(r), None) => (r.clone(), "white-box", crate::Mode::White, false),
        (None, Some(t)) => (t.clone(), "black-box", crate::Mode::Black, s.mcp),
        _ => { println!("  \x1b[31m✗ set a /target <url> and/or /repo <path> first.\x1b[0m"); return None; }
    };
    let mut cfg = RunConfig::new(&target);
    cfg.models = s.models.clone();
    cfg.subscription = s.subscription;
    cfg.vote_n = s.vote_n;
    cfg.max_agents = s.max_agents;
    cfg.verbose = true;
    cfg.offline = s.offline;
    cfg.instructions = if s.attachments.is_empty() { s.instructions.clone() }
        else { Some(format!("{}\n\nATTACHED CONTEXT:\n{}", s.instructions.clone().unwrap_or_default(), s.attachments.join("\n\n"))) };
    cfg.auth = s.auth.clone();
    if matches!(mode_e, crate::Mode::Grey) { cfg.repo = s.repo.clone(); }
    crate::apply_creds(&mut cfg, s.creds.as_deref()).await;

    let mut printer = reader.external_printer()?; // None on piped stdin → blocking fallback
    let sp = crate::spawn_engagement(base, cfg, mcp, mode_e);

    let live = Arc::new(Mutex::new(RunLive {
        target: target.clone(), mode: mode_s, phase: "starting".into(),
        started: Instant::now(), findings: vec![], full: vec![], commands: vec![],
        agents: 0, agents_done: 0,
    }));
    let cancel = sp.cancel.clone();
    let soft = sp.soft.clone();
    let paused = sp.paused.clone();
    let resume = sp.resume.clone();
    let fallback = sp.fallback.clone();
    let done = Arc::new(AtomicBool::new(false));
    let choice = Arc::new(Mutex::new(StopMode::Run));
    let (live2, done2, hist2, choice2) = (live.clone(), done.clone(), history, choice.clone());

    tokio::spawn(async move {
        let crate::Spawned { task, mut rx, workdir, .. } = sp;
        let mut last_saved = 0usize;
        while let Some(line) = rx.recv().await {
            live2.lock().unwrap().ingest(&line);
            if let Some(out) = crate::render_compact(&line) { let _ = printer.print(out); }
            // Checkpoint live findings to disk whenever a new one lands, so the
            // run survives a quit/crash and is recovered on next launch.
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
        let task_out = task.await.unwrap_or_default();
        let mode_choice = *choice2.lock().unwrap();

        if mode_choice == StopMode::Discard {
            std::fs::remove_dir_all(&workdir).ok();
            clear_checkpoint();
            let _ = printer.print(format!("\x1b[33m🗑 run discarded — {}\x1b[0m", workdir.display()));
            done2.store(true, Ordering::Relaxed);
            return;
        }

        // Raw → report from the unvalidated candidates we captured live.
        let (findings, validated_word) = if mode_choice == StopMode::Raw {
            let raw = live2.lock().unwrap().full.clone();
            crate::report_raw(&target, &raw, &workdir);
            (raw, "unvalidated")
        } else {
            let out = crate::finalize_run(task_out, &workdir);
            (out.findings, "validated")
        };

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
    Some(ActiveRun { live, cancel, soft, done, choice, paused, resume, fallback })
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
}
fn session_path() -> std::path::PathBuf { proj_dir().join("session.json") }
fn save_session(s: &Session) {
    let snap = Snapshot {
        models: s.models.clone(), subscription: s.subscription, mcp: s.mcp,
        vote_n: s.vote_n, max_agents: s.max_agents, target: s.target.clone(),
        repo: s.repo.clone(), auth: s.auth.clone(), creds: s.creds.clone(),
        instructions: s.instructions.clone(),
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
    let Some(r) = pick(history, arg) else { return };
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
    let x = &f[idx];
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

fn run_status(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    match std::fs::read_to_string(Path::new(&r.workdir).join("status.json")) {
        Ok(txt) => println!("  run #{}: {}", r.id, txt.trim()),
        Err(_) => println!("  run #{}: no status.json ({})", r.id, r.workdir),
    }
}

fn show(s: &Session) {
    let mode = match (&s.repo, &s.target) {
        (Some(_), Some(_)) => "greybox (code + live)",
        (Some(_), None) => "white-box (code)",
        (None, Some(_)) => "black-box (live)",
        _ => "(set /target and/or /repo)",
    };
    println!("  ┌─ session");
    println!("  │  models   : {}", s.models.join(", "));
    println!("  │  auth mode: {}", if s.subscription { "subscription (CLI login)" } else { "API key" });
    println!("  │  mode     : {mode}");
    println!("  │  target   : {}", s.target.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  repo     : {}", s.repo.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  auth     : {}", s.auth.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  creds    : {}", s.creds.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  focus    : {}", s.instructions.clone().unwrap_or_else(|| "(none — tests everything)".into()));
    println!("  │  opts     : mcp={} offline={} votes={} max-agents={}", onoff(s.mcp), onoff(s.offline), s.vote_n, s.max_agents);
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

    println!("\n  \x1b[2mTARGET & SCOPE\x1b[0m");
    h("/target <url>",      "black-box target URL");
    h("/repo <path>",       "analyse a repo (repo + target = greybox: code + live)");
    h("/auth <value>",      "auth header, e.g. 'Authorization: Bearer <jwt>' (no arg = show)");
    h("/creds <file.yaml>", "credentials: jwt/header/cookie/login + ssh/windows");
    h("/focus <text>",      "steer the tests (or just type the instruction)");
    h("@path @dir @f:1-20", "attach a file/folder/line-range to context (Tab → menu)");
    h("/attach /context",   "attach a path · list attachments");

    println!("\n  \x1b[2mMODELS & AUTH\x1b[0m");
    h("/model [a:b,..]",    "set models (no arg → arrow-key multi-select)");
    h("/providers",         "list providers & models");
    h("/key [prov key]",    "configure API keys for your models (no arg → guided)");
    h("/sub on|off",        "use local subscription login instead of an API key");

    println!("\n  \x1b[2mRUN & MONITOR\x1b[0m");
    h("/run",               "launch (runs in the BACKGROUND — keep typing)");
    h("/status",            "live progress + findings while running (or a past run #)");
    h("/stop",              "stop: [1] validate+report  [2] raw report now  [3] discard");
    h("/continue",          "resume a run paused on token/quota (change /model first to switch)");
    h("/runs",              "list runs · /results [n] · /report [n]");
    h("/diff /retest [n]",  "what changed vs last run · re-verify a past run");

    println!("\n  \x1b[2mOPTIONS\x1b[0m");
    h("/mcp on|off",        "Playwright MCP browser    /offline on|off  self-test");
    h("/votes <n>",         "validator votes           /agents <n>  cap agents");
    h("/theme color|mono",  "/show (config)            /clear        /quit");

    println!("\n  \x1b[2mMODES — black-box: set /target · white-box: set /repo · grey-box: set BOTH /repo + /target · host: /target <ip> + /creds\x1b[0m");
    println!("  \x1b[2mFindings are checkpointed live to .neurosploit/ — quit/crash mid-run and they're recovered into /runs next launch.\x1b[0m");
    println!("  \x1b[2mIf tokens/quota run out the run PAUSES (state kept) — /continue to resume, or switch with /model then /continue.\x1b[0m");
    println!("  \x1b[2m↑/↓ history · Tab completes commands & @paths · Ctrl-A/E/K edit · Ctrl-O full cmd · \\ for multiline\x1b[0m\n");
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
                    .filter(|(i, _)| *i + 1 >= a && *i + 1 <= b)
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
    format!(
        "\x1b[2m{model} {auth} · {cwd} · {mode}{tgt}\x1b[0m\n\x1b[35mneurosploit›\x1b[0m "
    )
}

fn onoff(b: bool) -> &'static str { if b { "on" } else { "off" } }
fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() }
    else { format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>()) }
}
