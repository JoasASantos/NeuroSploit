//! NeuroSploit as an MCP server.
//!
//! Speaks the Model Context Protocol over stdio (JSON-RPC 2.0, line-delimited),
//! so Claude Code, Codex, Cursor and any MCP client can drive NeuroSploit as a
//! set of tools. It does not re-implement the harness: each tool shells out to
//! the same `neurosploit` binary the operator already uses, so behaviour,
//! authorization and safety are identical to the CLI.
//!
//! Exposed tools:
//!   - `neurosploit_run`        launch an engagement (returns the run id + summary)
//!   - `neurosploit_list_runs`  list finished runs
//!   - `neurosploit_findings`   read a run's findings.json
//!   - `neurosploit_report`     read a run's markdown report
//!   - `neurosploit_rebuild`    rebuild a run's report from its findings
//!   - `neurosploit_internal`   internal/AD attack-graph analysis
//!   - `neurosploit_compliance` map a run onto PCI-DSS / HIPAA / SOC 2
//!
//! Kept dependency-free: JSON-RPC framing is hand-rolled over stdin/stdout with
//! serde_json, and tools run via std::process::Command.

use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the MCP server loop until stdin closes.
pub fn serve() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let exe = std::env::current_exe().unwrap_or_else(|_| "neurosploit".into());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // ignore malformed frames
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        // Notifications (no id) get no response.
        let response = match method {
            "initialize" => Some(ok(id, json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "neurosploit", "version": env!("CARGO_PKG_VERSION") }
            }))),
            "tools/list" => Some(ok(id, json!({ "tools": tool_list() }))),
            "tools/call" => Some(handle_call(id, &req, &exe)),
            "ping" => Some(ok(id, json!({}))),
            m if m.starts_with("notifications/") => None,
            _ if id.is_some() => Some(err(id, -32601, "method not found")),
            _ => None,
        };

        if let Some(resp) = response {
            let s = serde_json::to_string(&resp)?;
            writeln!(out, "{s}")?;
            out.flush()?;
        }
    }
    Ok(())
}

fn ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}
fn err(id: Option<Value>, code: i64, msg: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

/// The tool catalogue advertised to the client.
fn tool_list() -> Value {
    json!([
        {
            "name": "neurosploit_run",
            "description": "Launch a NeuroSploit engagement against an authorized target. Black-box by default. Returns the run id, the finding summary, and the report path. Only test targets you are authorized to test.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "URL or host, e.g. https://app.example.com" },
                    "mode": { "type": "string", "enum": ["run","whitebox","greybox","host"], "description": "Engagement mode (default run)" },
                    "model": { "type": "string", "description": "provider:model, e.g. anthropic:claude-opus-4-8" },
                    "subscription": { "type": "boolean", "description": "Use the local CLI login instead of an API key" },
                    "focus": { "type": "string", "description": "What to prioritise" },
                    "scope_file": { "type": "string", "description": "Path to a scope YAML (hard boundary)" },
                    "sandbox": { "type": "boolean", "description": "Run tool commands in the Kali container" },
                    "typesafe": { "type": "string", "enum": ["on","off","auto"] },
                    "max_agents": { "type": "integer" }
                },
                "required": ["target"]
            }
        },
        { "name": "neurosploit_list_runs", "description": "List finished NeuroSploit runs (ids and targets).", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "neurosploit_findings", "description": "Read a finished run's findings as JSON.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string", "description": "Run id or path" } }, "required": ["run"] } },
        { "name": "neurosploit_report", "description": "Read a finished run's Markdown report.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] } },
        { "name": "neurosploit_rebuild", "description": "Rebuild a run's report artifacts from its findings (no model calls).", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] } },
        { "name": "neurosploit_sarif", "description": "Emit SARIF 2.1.0 for a finished run (report.sarif) so CI code-scanning can ingest the findings.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] } },
        { "name": "neurosploit_internal", "description": "Internal-network / Active Directory attack-graph analysis: paths to crown jewels and the choke point to fix first.", "inputSchema": { "type": "object", "properties": { "graph": { "type": "string", "description": "Path to a graph JSON" }, "scaffold": { "type": "string", "description": "Domain to scaffold, e.g. corp.local" }, "from": { "type": "string", "description": "Foothold node id" } } } },
        { "name": "neurosploit_compliance", "description": "Map a finished run's findings onto PCI-DSS, HIPAA or SOC 2 controls.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" }, "framework": { "type": "string", "enum": ["pci-dss","hipaa","soc2"] } }, "required": ["run"] } },
        { "name": "neurosploit_container", "description": "Scan an OCI container image (repo:tag / tar / Dockerfile) for vulnerable packages, secrets, misconfig and emit an SBOM.", "inputSchema": { "type": "object", "properties": { "image": { "type": "string" }, "model": { "type": "string" }, "subscription": { "type": "boolean" } }, "required": ["image"] } }
    ])
}

/// Dispatch a `tools/call`.
fn handle_call(id: Option<Value>, req: &Value, exe: &std::path::Path) -> Value {
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let a = params.get("arguments").cloned().unwrap_or(json!({}));
    let s = |k: &str| a.get(k).and_then(|v| v.as_str()).map(|x| x.to_string());
    let b = |k: &str| a.get(k).and_then(|v| v.as_bool()).unwrap_or(false);

    let mut argv: Vec<String> = Vec::new();
    match name {
        "neurosploit_run" => {
            let Some(target) = s("target") else { return tool_err(id, "target is required") };
            argv.push(s("mode").unwrap_or_else(|| "run".into()));
            argv.push(target);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if let Some(sf) = s("scope_file") { argv.push("--scope-file".into()); argv.push(sf); }
            if b("sandbox") { argv.push("--sandbox".into()); }
            if let Some(ts) = s("typesafe") { argv.push("--typesafe".into()); argv.push(ts); }
            if let Some(n) = a.get("max_agents").and_then(|v| v.as_i64()) { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            argv.push("-v".into());
        }
        "neurosploit_list_runs" => { argv.push("runs".into()); }
        "neurosploit_findings" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            return read_run_file(id, &run, "findings.json");
        }
        "neurosploit_report" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            return read_run_file(id, &run, "report.md");
        }
        "neurosploit_rebuild" => { let Some(run) = s("run") else { return tool_err(id, "run is required") }; argv.push("rebuild".into()); argv.push(run); }
        "neurosploit_sarif" => { let Some(run) = s("run") else { return tool_err(id, "run is required") }; argv.push("sarif".into()); argv.push(run); }
        "neurosploit_internal" => {
            argv.push("internal".into());
            if let Some(g) = s("graph") { argv.push("--graph".into()); argv.push(g); }
            if let Some(sc) = s("scaffold") { argv.push("--scaffold".into()); argv.push(sc); }
            if let Some(fr) = s("from") { argv.push("--from".into()); argv.push(fr); }
        }
        "neurosploit_container" => {
            let Some(image) = s("image") else { return tool_err(id, "image is required") };
            argv.push("container".into()); argv.push(image);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            argv.push("-v".into());
        }
        "neurosploit_compliance" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("compliance".into()); argv.push(run);
            if let Some(fw) = s("framework") { argv.push("--framework".into()); argv.push(fw); }
        }
        _ => return tool_err(id, &format!("unknown tool: {name}")),
    }

    // `runs` subcommand doesn't exist as a bare CLI verb; list from the runs dir.
    if name == "neurosploit_list_runs" {
        return list_runs(id);
    }

    let out = std::process::Command::new(exe).args(&argv).output();
    match out {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                text.push_str("\n--- stderr ---\n");
                text.push_str(&stderr);
            }
            tool_text(id, &strip_ansi(&text))
        }
        Err(e) => tool_err(id, &format!("failed to run neurosploit: {e}")),
    }
}

fn read_run_file(id: Option<Value>, run: &str, file: &str) -> Value {
    let base = std::env::current_dir().unwrap_or_default();
    let dir = if std::path::Path::new(run).is_dir() { std::path::PathBuf::from(run) } else { base.join("runs").join(run) };
    match std::fs::read_to_string(dir.join(file)) {
        Ok(s) => tool_text(id, &s),
        Err(e) => tool_err(id, &format!("cannot read {}/{file}: {e}", dir.display())),
    }
}

fn list_runs(id: Option<Value>) -> Value {
    let base = std::env::current_dir().unwrap_or_default().join("runs");
    let mut names: Vec<String> = std::fs::read_dir(&base)
        .map(|rd| rd.filter_map(|e| e.ok()).filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().to_string()).collect())
        .unwrap_or_default();
    names.sort();
    names.reverse();
    tool_text(id, &if names.is_empty() { "no runs found".into() } else { names.join("\n") })
}

fn tool_text(id: Option<Value>, text: &str) -> Value {
    // Cap the payload so a huge report doesn't blow the client's context.
    let capped: String = text.chars().take(60_000).collect();
    ok(id, json!({ "content": [ { "type": "text", "text": capped } ], "isError": false }))
}
fn tool_err(id: Option<Value>, msg: &str) -> Value {
    ok(id, json!({ "content": [ { "type": "text", "text": msg } ], "isError": true }))
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') { chars.next(); while let Some(&n) = chars.peek() { chars.next(); if n.is_ascii_alphabetic() { break; } } }
            continue;
        }
        out.push(c);
    }
    out
}
