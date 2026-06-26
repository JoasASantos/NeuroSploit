//! NeuroSploit v3.5.2 — TUI "Mission Control" mode.
//!
//! Concurrent panels that update live while the engagement runs in the
//! background, with a composer input that stays active during execution:
//!
//!   ┌ status header (target · mode · phase · elapsed · tokens · findings) ┐
//!   │ live activity feed              │ findings (live)                   │
//!   │  (recon/exploit/tool/command)   ├───────────────────────────────────┤
//!   │                                 │ targets / queue                   │
//!   └ composer: ask 'summary', 'pause', 'errors', or notes … ────────────┘
//!
//! The engagement runs as a tokio task streaming tagged events over an mpsc
//! channel; the UI drains them each tick. The composer answers locally
//! (summary / what-found / errors / pause) WITHOUT stopping the runner.

use crate::Mode;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::{execute, terminal};
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use std::collections::VecDeque;
use std::io::stdout;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

struct Ui {
    target: String,
    models: String,
    mode: &'static str,
    phase: String,
    started: Instant,
    feed: VecDeque<String>,
    findings: Vec<(String, String, String)>, // sev, title, endpoint
    targets: Vec<(String, String)>,          // host, state
    tin: u64,
    tout: u64,
    cost: f64,
    input: String,
    filter_errors: bool,
    done: bool,
    paused: bool,
}

impl Ui {
    fn new(target: &str, models: &str, mode: &'static str) -> Self {
        let host = target.replace("https://", "").replace("http://", "");
        let host = host.split('/').next().unwrap_or(&host).to_string();
        Ui {
            target: target.into(), models: models.into(), mode,
            phase: "starting".into(), started: Instant::now(),
            feed: VecDeque::new(), findings: vec![],
            targets: vec![(host, "🔄 running".into())],
            tin: 0, tout: 0, cost: 0.0, input: String::new(),
            filter_errors: false, done: false, paused: false,
        }
    }

    fn ingest(&mut self, raw: String) {
        let line = raw.trim_end().to_string();
        let low = line.to_lowercase();
        // phase tracking
        if low.contains("recon") { self.phase = "🔍 recon".into(); }
        else if low.contains("planning") || low.contains("selected") || low.contains("selection") { self.phase = "🧭 planning".into(); }
        else if low.starts_with("exploit") || low.contains("launching agent") || low.starts_with("analyze") { self.phase = "🧪 exploiting".into(); }
        else if low.starts_with("vote") || low.contains("validating") { self.phase = "✓ validating".into(); }
        else if low.starts_with("chain") { self.phase = "🔗 chaining".into(); }
        else if low.contains("phase complete") || low.contains("validated finding(s)") { self.phase = "✓ complete".into(); }

        // live findings
        if let Some(rest) = line.strip_prefix("finding: ") {
            // "[sev] title @ endpoint"
            if let Some(b) = rest.strip_prefix('[') {
                if let Some((sev, tail)) = b.split_once(']') {
                    let (title, ep) = tail.trim().split_once(" @ ").unwrap_or((tail.trim(), ""));
                    self.findings.push((sev.to_string(), title.to_string(), ep.to_string()));
                    self.note_target_from(ep);
                }
            }
            return;
        }
        // token telemetry
        if let Some(rest) = line.strip_prefix("@").and_then(|s| s.split_once(' ')).map(|(_, r)| r).filter(|r| r.starts_with("tokens:")).or_else(|| line.strip_prefix("tokens: ").map(|_| line.as_str())) {
            for part in rest.split_whitespace() {
                if let Some(v) = part.strip_prefix("in=") { self.tin += v.parse().unwrap_or(0); }
                else if let Some(v) = part.strip_prefix("out=") { self.tout += v.parse().unwrap_or(0); }
                else if let Some(v) = part.strip_prefix("cost=$") { self.cost += v.parse().unwrap_or(0.0); }
            }
        }
        let is_err = low.contains("fail") || low.contains("error") || low.starts_with('✗');
        if self.filter_errors && !is_err { return; }
        self.feed.push_back(line);
        while self.feed.len() > 500 { self.feed.pop_front(); }
    }

    fn note_target_from(&mut self, endpoint: &str) {
        let host = endpoint.replace("https://", "").replace("http://", "");
        let host = host.split('/').next().unwrap_or("").to_string();
        if !host.is_empty() && !self.targets.iter().any(|(h, _)| h == &host) {
            self.targets.push((host, "🔄 testing".into()));
        }
    }

    /// Composer command (local, non-blocking). Returns feed lines to show.
    fn composer(&mut self, cmd: &str) -> Vec<String> {
        let c = cmd.trim().to_lowercase();
        match c.as_str() {
            "" => vec![],
            "pause" | "/pause" | "stop" | "/stop" => { self.paused = true; vec!["⏸ pausing — finishing in-flight work, no new agents".into()] }
            "errors" | "/errors" => { self.filter_errors = !self.filter_errors; vec![format!("filter errors: {}", self.filter_errors)] }
            "clear" | "/clear" => { self.feed.clear(); vec![] }
            "summary" | "/summary" | "what" | "o que" | "resumo" => self.summary(),
            "findings" | "/findings" => self.summary(),
            "quit" | "/quit" | "exit" => { self.done = true; vec![] }
            other => vec![format!("noted: {other}")],
        }
    }

    fn summary(&self) -> Vec<String> {
        let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
        for (s, _, _) in &self.findings { *by.entry(s.as_str()).or_insert(0) += 1; }
        let sev = if by.is_empty() { "0".into() } else { by.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
        let mut out = vec![format!("── partial summary: {} finding(s) [{}] · phase {} ──", self.findings.len(), sev, self.phase)];
        for (s, t, _) in self.findings.iter().rev().take(5) { out.push(format!("  • [{s}] {t}")); }
        out
    }
}

/// Run the Mission-Control TUI for an engagement.
pub async fn run(base: &Path, mut cfg: RunConfig, mcp: bool, mode: Mode) -> anyhow::Result<()> {
    let lib = agents::load(base);
    let run_id = format!("ns-{}-{}", crate::now_ts_pub(), crate::sanitize_pub(&cfg.target));
    let workdir = base.join("runs").join(&run_id);
    std::fs::create_dir_all(&workdir).ok();
    cfg.workdir = Some(workdir.display().to_string());
    cfg.rl_path = Some(base.join("data").join("rl_state_rs.json").display().to_string());
    cfg.verbose = true;

    let mcp_config = if mcp && cfg.subscription {
        harness::ensure_playwright_mcp().ok().and_then(|_| harness::write_mcp_config(&workdir, None).ok())
            .map(|p| p.display().to_string())
    } else { None };

    let refs: Vec<ModelRef> = cfg.models.iter().map(|s| ModelRef::parse(s)).collect();
    let pool = ModelPool::with_auth(refs, cfg.concurrency, cfg.subscription, mcp_config);
    let cancel = pool.cancel_handle();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(512);
    let models = cfg.models.join(", ");
    let mode_s = match mode { Mode::White => "white-box", Mode::Grey => "greybox", Mode::Host => "host/infra", Mode::Black => "black-box" };
    let target_s = cfg.target.clone();

    // ---- terminal setup FIRST: on a non-TTY this errors before we spawn any
    // live engagement, so we never detach a running task. ----
    terminal::enable_raw_mode()?;
    execute!(stdout(), terminal::EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut ui = Ui::new(&target_s, &models, mode_s);

    let mut task = tokio::spawn(async move {
        match mode {
            Mode::White => harness::run_whitebox(cfg, &lib, &pool, tx).await,
            Mode::Grey => harness::run_greybox(cfg, &lib, &pool, tx).await,
            Mode::Host => harness::run_host(cfg, &lib, &pool, tx).await,
            Mode::Black => harness::run(cfg, &lib, &pool, tx).await,
        }
    });

    let out;
    loop {
        // drain engagement events
        while let Ok(line) = rx.try_recv() { ui.ingest(line); }
        // engagement finished?
        if task.is_finished() {
            ui.done = true;
            ui.phase = "✓ complete".into();
            if let Some((_, st)) = ui.targets.get_mut(0) { *st = "✅ done".into(); }
        }
        draw(&mut term, &ui)?;

        // input (100ms tick keeps the UI live while the runner works)
        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(k) = event::read()? {
                let ctrl_c = k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c');
                match k.code {
                    KeyCode::Esc => { cancel.store(true, Ordering::Relaxed); if ui.done { break; } ui.paused = true; }
                    KeyCode::Char('c') if ctrl_c => { cancel.store(true, Ordering::Relaxed); if ui.done { break; } ui.paused = true; }
                    KeyCode::Enter => {
                        let line = std::mem::take(&mut ui.input);
                        if matches!(line.trim(), "quit" | "/quit" | "exit") && ui.done { break; }
                        let lines = ui.composer(&line);
                        if ui.paused { cancel.store(true, Ordering::Relaxed); }
                        for l in lines { ui.feed.push_back(l); }
                    }
                    KeyCode::Backspace => { ui.input.pop(); }
                    KeyCode::Char(c) => { ui.input.push(c); }
                    _ => {}
                }
            }
        }
        if ui.done && task.is_finished() && ui.input.is_empty() {
            // brief grace so the final frame is visible; exit on next Esc/Enter handled above
        }
    }

    out = (&mut task).await.unwrap_or_default();

    // ---- restore terminal ----
    execute!(stdout(), terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    // generate report unless discarded; print a plain summary after leaving the TUI
    match harness::report::typst_report(&out.target, &out.findings, &workdir) {
        Ok(p) => println!("  report → {}", p.display()),
        Err(_) => {}
    }
    crate::write_status_pub(&workdir, if cancel.load(Ordering::Relaxed) { "stopped" } else { "complete" }, "");
    println!("  ✓ {} validated finding(s) · {}", out.findings.len(), workdir.display());
    Ok(())
}

fn sevstyle(s: &str) -> Style {
    match s {
        "Critical" => Style::new().fg(Color::Red).bold(),
        "High" => Style::new().fg(Color::Rgb(251, 146, 60)),
        "Medium" => Style::new().fg(Color::Yellow),
        "Low" => Style::new().fg(Color::Cyan),
        _ => Style::new().fg(Color::Gray),
    }
}

fn draw(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>, ui: &Ui) -> anyhow::Result<()> {
    term.draw(|f| {
        let root = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Min(5),    // body
            Constraint::Length(3), // composer
        ]).split(f.area());

        // ── header ──
        let el = ui.started.elapsed().as_secs();
        let accent = Style::new().fg(Color::Rgb(139, 92, 246)).bold();
        let header = Line::from(vec![
            Span::styled(" 🧠 NeuroSploit ", accent),
            Span::raw(format!("│ {} ", ui.target)),
            Span::styled(format!("│ {} ", ui.mode), Style::new().fg(Color::Magenta)),
            Span::styled(format!("│ {} ", short_models(&ui.models)), Style::new().fg(Color::DarkGray)),
            Span::styled(format!("│ {} ", ui.phase), Style::new().fg(Color::Cyan)),
            Span::raw(format!("│ {:02}:{:02} ", el / 60, el % 60)),
            Span::styled(format!("│ {} findings ", ui.findings.len()), Style::new().fg(Color::Yellow)),
            Span::raw(format!("│ 🪙 {}/{} ${:.3} ", ui.tin, ui.tout, ui.cost)),
            if ui.paused { Span::styled("│ ⏸ stopping ", Style::new().fg(Color::Red)) } else { Span::raw("") },
        ]);
        f.render_widget(Paragraph::new(header).block(Block::default().borders(Borders::ALL)
            .title(" Mission Control ").border_style(accent)), root[0]);

        // ── body: feed | (findings / targets) ──
        let body = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).split(root[1]);

        let feed_h = body[0].height.saturating_sub(2) as usize;
        let feed: Vec<ListItem> = ui.feed.iter().rev().take(feed_h).rev()
            .map(|l| ListItem::new(feed_span(l))).collect();
        f.render_widget(List::new(feed).block(Block::default().borders(Borders::ALL)
            .title(format!(" Activity{} ", if ui.filter_errors { " [errors]" } else { "" }))), body[0]);

        let right = Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).split(body[1]);
        let finds: Vec<ListItem> = ui.findings.iter().rev().take(right[0].height.saturating_sub(2) as usize)
            .map(|(s, t, _)| ListItem::new(Line::from(vec![
                Span::styled(format!("[{s}] "), sevstyle(s)), Span::raw(t.clone())]))).collect();
        f.render_widget(List::new(finds).block(Block::default().borders(Borders::ALL)
            .title(format!(" Findings ({}) ", ui.findings.len()))), right[0]);

        let tg: Vec<ListItem> = ui.targets.iter()
            .map(|(h, st)| ListItem::new(format!("{st}  {h}"))).collect();
        f.render_widget(List::new(tg).block(Block::default().borders(Borders::ALL).title(" Targets ")), right[1]);

        // ── composer ──
        let hint = if ui.done { "engagement done — type quit/Esc to exit · summary" }
                   else { "composer (runner active): summary · pause · errors · clear · or a note" };
        let comp = Paragraph::new(Line::from(vec![
            Span::styled("› ", accent), Span::raw(&ui.input),
            Span::styled("▏", Style::new().fg(Color::Rgb(139, 92, 246))),
        ])).block(Block::default().borders(Borders::ALL).title(format!(" {hint} "))).wrap(Wrap { trim: false });
        f.render_widget(comp, root[2]);
    })?;
    Ok(())
}

fn short_models(m: &str) -> String {
    // show just the first model's name, compactly
    m.split(',').next().unwrap_or(m).split(':').next_back().unwrap_or(m).trim().to_string()
}

fn feed_span(l: &str) -> Line<'static> {
    let low = l.to_lowercase();
    let (color, s) = if l.starts_with("finding:") || l.contains("possible finding") { (Color::Yellow, l) }
        else if l.starts_with("notify:") || l.contains('🔔') { (Color::Cyan, l) }
        else if low.contains("fail") || low.contains("error") || l.starts_with('✗') { (Color::Red, l) }
        else if low.contains("exec:") || low.contains("command") || low.contains("curl") { (Color::Rgb(230, 180, 100), l) }
        else if low.contains("recon") || low.contains("vote") || low.contains("chain") { (Color::Cyan, l) }
        else { (Color::Gray, l) };
    Line::from(Span::styled(s.to_string(), Style::new().fg(color)))
}
