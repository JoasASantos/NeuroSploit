//! NeuroSploit as an MCP server.
//!
//! Speaks the Model Context Protocol over stdio (JSON-RPC 2.0, line-delimited),
//! so Claude Code, Codex, Cursor, Windsurf and any MCP client can drive
//! NeuroSploit as a set of tools.  It does not re-implement the harness: each
//! tool shells out to the same `neurosploit` binary the operator already uses,
//! so behaviour, authorization and safety are identical to the CLI.
//!
//! Exposed tools:
//!   - neurosploit_run           launch a black-box engagement
//!   - neurosploit_whitebox      white-box source review
//!   - neurosploit_greybox       grey-box (source + running app)
//!   - neurosploit_host          infra/host scan (Linux/Windows/AD)
//!   - neurosploit_aitest        AI/LLM red-teaming (OWASP LLM Top 10)
//!   - neurosploit_mobile        mobile binary analysis (APK/IPA)
//!   - neurosploit_container     OCI container scan + SBOM
//!   - neurosploit_skills        skill/plugin/n8n audit
//!   - neurosploit_pr            GitHub PR security review
//!   - neurosploit_internal      internal/AD attack-graph analysis
//!   - neurosploit_list_runs     list finished runs
//!   - neurosploit_findings      read a run's findings.json
//!   - neurosploit_report        read a run's markdown report
//!   - neurosploit_rebuild       rebuild report from findings
//!   - neurosploit_sarif         emit SARIF 2.1.0
//!   - neurosploit_compliance    map findings onto PCI-DSS/HIPAA/SOC2
//!   - neurosploit_graph         attack graph (web + internal)
//!   - neurosploit_audit         verify audit trail
//!   - neurosploit_poc           re-validate PoCs
//!   - neurosploit_traffic       export HTTP traffic
//!   - neurosploit_assurance     assurance bundle
//!   - neurosploit_agents        list the agent library
//!   - neurosploit_models        list providers and models
//!   - neurosploit_import_collection  validate/preview a collection (file or dir)
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
            Err(_) => continue,
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

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

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------

fn tool_list() -> Value {
    json!([
        {
            "name": "neurosploit_run",
            "description": "Launch a NeuroSploit black-box engagement against an authorized target. Returns the run id, finding summary, and report path. Only test targets you are authorized to test.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target":       { "type": "string", "description": "URL or host, e.g. https://app.example.com" },
                    "model":        { "type": "string", "description": "provider:model, e.g. anthropic:claude-opus-4-8" },
                    "subscription": { "type": "boolean", "description": "Use the local CLI login instead of an API key" },
                    "focus":        { "type": "string", "description": "What to prioritise" },
                    "objective":    { "type": "string", "description": "Engagement goal / context" },
                    "scope_file":   { "type": "string", "description": "Path to a scope YAML (hard boundary)" },
                    "collection":   { "type": "string", "description": "API collection file or directory (Postman/OpenAPI/HAR, JSON)" },
                    "sandbox":      { "type": "boolean", "description": "Run tool commands in the Kali container" },
                    "typesafe":     { "type": "string", "enum": ["on","off","auto"] },
                    "max_agents":   { "type": "integer" },
                    "quick":        { "type": "boolean", "description": "Economy preset: light recon, fewer agents, lower cost" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "neurosploit_whitebox",
            "description": "White-box: analyse a repository's source code for vulnerabilities. Accepts a local path, GitHub URL, or owner/repo shorthand.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path":         { "type": "string", "description": "Local path, GitHub URL, or owner/repo" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "focus":        { "type": "string" },
                    "research":     { "type": "boolean", "description": "Hunt novel CVE-reportable bugs" },
                    "max_agents":   { "type": "integer" },
                    "quick":        { "type": "boolean" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "neurosploit_greybox",
            "description": "Greybox: review source AND exploit the running app together.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo":         { "type": "string", "description": "Source repo (local path, GitHub URL, or owner/repo)" },
                    "url":          { "type": "string", "description": "URL of the running application" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "creds":        { "type": "string", "description": "Credentials YAML path" },
                    "focus":        { "type": "string" },
                    "collection":   { "type": "string", "description": "API collection file or directory" },
                    "research":     { "type": "boolean" },
                    "max_agents":   { "type": "integer" },
                    "quick":        { "type": "boolean" }
                },
                "required": ["repo", "url"]
            }
        },
        {
            "name": "neurosploit_host",
            "description": "Infra/host: scan an IP/host and run Linux/Windows/AD agents. SSH/Windows credentials come from --creds.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target":       { "type": "string", "description": "IP or hostname" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "creds":        { "type": "string", "description": "Credentials YAML (ssh/windows/ad blocks)" },
                    "focus":        { "type": "string" },
                    "max_agents":   { "type": "integer" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "neurosploit_aitest",
            "description": "AI/LLM red-team: test a live AI agent / LLM app / MCP endpoint (OWASP LLM Top 10 + MCP risks).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url":          { "type": "string", "description": "URL of the AI agent / LLM endpoint" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "auth":         { "type": "string", "description": "Auth header for the AI endpoint" },
                    "focus":        { "type": "string" },
                    "max_agents":   { "type": "integer" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "neurosploit_mobile",
            "description": "Mobile/binary: analyse a local artifact (APK/IPA/binary) with mobile RE agents (Ghidra, MobSF, Frida, apktool/jadx).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path":         { "type": "string", "description": "Path to the artifact (.apk/.ipa/binary)" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "focus":        { "type": "string" },
                    "max_agents":   { "type": "integer" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "neurosploit_container",
            "description": "Scan an OCI container image (repo:tag / tar / Dockerfile) for vulnerable packages, secrets, misconfig and emit an SBOM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "image":        { "type": "string", "description": "Image reference, local tar, or Dockerfile path" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "focus":        { "type": "string" }
                },
                "required": ["image"]
            }
        },
        {
            "name": "neurosploit_skills",
            "description": "Audit AI skills/plugins or exported n8n workflows (white-box .md/.json file or folder).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path":         { "type": "string", "description": "Path to a skill/plugin/n8n file or folder" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "neurosploit_pr",
            "description": "Review a GitHub Pull Request's code for security vulnerabilities. Optionally comments back on the PR.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo":         { "type": "string", "description": "owner/repo or GitHub URL" },
                    "number":       { "type": "integer", "description": "Pull request number" },
                    "model":        { "type": "string" },
                    "subscription": { "type": "boolean" },
                    "comment":      { "type": "boolean", "description": "Post a summary comment back on the PR" },
                    "fail_on":      { "type": "string", "enum": ["critical","high","medium","low"], "description": "Block PR at this severity or worse" },
                    "jira":         { "type": "boolean", "description": "Open a Jira card per finding" }
                },
                "required": ["repo", "number"]
            }
        },
        {
            "name": "neurosploit_internal",
            "description": "Internal-network / Active Directory attack-graph analysis: paths to crown jewels and the choke point to fix first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "graph":    { "type": "string", "description": "Path to a graph JSON" },
                    "scaffold": { "type": "string", "description": "Domain to scaffold, e.g. corp.local" },
                    "from":     { "type": "string", "description": "Foothold node id" }
                }
            }
        },
        { "name": "neurosploit_list_runs", "description": "List finished NeuroSploit runs (ids and targets).", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "neurosploit_findings", "description": "Read a finished run's findings as JSON.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string", "description": "Run id or path" } }, "required": ["run"] } },
        { "name": "neurosploit_report", "description": "Read a finished run's Markdown report.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] } },
        { "name": "neurosploit_rebuild", "description": "Rebuild a run's report artifacts from its findings (no model calls).", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] } },
        { "name": "neurosploit_sarif", "description": "Emit SARIF 2.1.0 for a finished run so CI code-scanning can ingest the findings.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] } },
        { "name": "neurosploit_compliance", "description": "Map a finished run's findings onto PCI-DSS, HIPAA or SOC 2 controls.", "inputSchema": { "type": "object", "properties": { "run": { "type": "string" }, "framework": { "type": "string", "enum": ["pci-dss","hipaa","soc2"] } }, "required": ["run"] } },
        {
            "name": "neurosploit_graph",
            "description": "Attack graph for a finished run: attack chains with severity, next moves, Cypher export. With --push merges into Neo4j.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run":      { "type": "string", "description": "Run id or path" },
                    "internal": { "type": "string", "description": "Internal-network graph JSON to merge" },
                    "push":     { "type": "boolean", "description": "Push to Neo4j" },
                    "top":      { "type": "integer", "description": "How many chains to print (default 5)" }
                },
                "required": ["run"]
            }
        },
        {
            "name": "neurosploit_audit",
            "description": "Verify a finished run's audit trail — the hash chain and, with --anchor, the signed anchors.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run":    { "type": "string" },
                    "anchor": { "type": "boolean", "description": "Also verify anchors (P4)" }
                },
                "required": ["run"]
            }
        },
        {
            "name": "neurosploit_poc",
            "description": "Re-validate a finished run's PoCs: re-run each finding's proof and report which still reproduce.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run":     { "type": "string" },
                    "repeats": { "type": "integer", "description": "Re-runs per finding (default 2)" },
                    "apply":   { "type": "boolean", "description": "Write demoted findings back" },
                    "only":    { "type": "string", "description": "Re-test only this finding id" }
                },
                "required": ["run"]
            }
        },
        {
            "name": "neurosploit_traffic",
            "description": "Export a run's archived HTTP traffic as a .http file for external inspection.",
            "inputSchema": { "type": "object", "properties": { "run": { "type": "string" } }, "required": ["run"] }
        },
        {
            "name": "neurosploit_assurance",
            "description": "Assemble or verify a run's assurance bundle (P1-P5 manifest).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run":    { "type": "string" },
                    "verify": { "type": "boolean", "description": "Verify instead of assembling" }
                },
                "required": ["run"]
            }
        },
        { "name": "neurosploit_agents", "description": "List the NeuroSploit agent library (names, categories, counts).", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "neurosploit_models", "description": "List available providers and models.", "inputSchema": { "type": "object", "properties": {} } },
        {
            "name": "neurosploit_import_collection",
            "description": "Validate and preview an API collection (Postman/OpenAPI/Swagger/HAR). Accepts a single JSON file or a directory of .json files. Returns the parsed endpoint list.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to a collection file or a directory of .json collection files" }
                },
                "required": ["path"]
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

fn handle_call(id: Option<Value>, req: &Value, exe: &std::path::Path) -> Value {
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let a = params.get("arguments").cloned().unwrap_or(json!({}));
    let s = |k: &str| a.get(k).and_then(|v| v.as_str()).map(|x| x.to_string());
    let b = |k: &str| a.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let i = |k: &str| a.get(k).and_then(|v| v.as_i64());

    let mut argv: Vec<String> = Vec::new();
    match name {
        // ---- engagements ----------------------------------------------------
        "neurosploit_run" => {
            let Some(target) = s("target") else { return tool_err(id, "target is required") };
            argv.push("run".into()); argv.push(target);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if let Some(o) = s("objective") { argv.push("--objective".into()); argv.push(o); }
            if let Some(sf) = s("scope_file") { argv.push("--scope-file".into()); argv.push(sf); }
            if let Some(c) = s("collection") { argv.push("--collection".into()); argv.push(c); }
            if b("sandbox") { argv.push("--sandbox".into()); }
            if let Some(ts) = s("typesafe") { argv.push("--typesafe".into()); argv.push(ts); }
            if let Some(n) = i("max_agents") { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            if b("quick") { argv.push("--quick".into()); }
            argv.push("-v".into());
        }
        "neurosploit_whitebox" => {
            let Some(path) = s("path") else { return tool_err(id, "path is required") };
            argv.push("whitebox".into()); argv.push(path);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if b("research") { argv.push("--research".into()); }
            if let Some(n) = i("max_agents") { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            if b("quick") { argv.push("--quick".into()); }
            argv.push("-v".into());
        }
        "neurosploit_greybox" => {
            let Some(repo) = s("repo") else { return tool_err(id, "repo is required") };
            let Some(url) = s("url") else { return tool_err(id, "url is required") };
            argv.push("greybox".into()); argv.push(repo);
            argv.push("--url".into()); argv.push(url);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(c) = s("creds") { argv.push("--creds".into()); argv.push(c); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if let Some(col) = s("collection") { argv.push("--collection".into()); argv.push(col); }
            if b("research") { argv.push("--research".into()); }
            if let Some(n) = i("max_agents") { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            if b("quick") { argv.push("--quick".into()); }
            argv.push("-v".into());
        }
        "neurosploit_host" => {
            let Some(target) = s("target") else { return tool_err(id, "target is required") };
            argv.push("host".into()); argv.push(target);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(c) = s("creds") { argv.push("--creds".into()); argv.push(c); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if let Some(n) = i("max_agents") { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            argv.push("-v".into());
        }
        "neurosploit_aitest" => {
            let Some(url) = s("url") else { return tool_err(id, "url is required") };
            argv.push("aitest".into()); argv.push(url);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(auth) = s("auth") { argv.push("--auth".into()); argv.push(auth); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if let Some(n) = i("max_agents") { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            argv.push("-v".into());
        }
        "neurosploit_mobile" => {
            let Some(path) = s("path") else { return tool_err(id, "path is required") };
            argv.push("mobile".into()); argv.push(path);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            if let Some(n) = i("max_agents") { argv.push("--max-agents".into()); argv.push(n.to_string()); }
            argv.push("-v".into());
        }
        "neurosploit_container" => {
            let Some(image) = s("image") else { return tool_err(id, "image is required") };
            argv.push("container".into()); argv.push(image);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if let Some(f) = s("focus") { argv.push("--focus".into()); argv.push(f); }
            argv.push("-v".into());
        }
        "neurosploit_skills" => {
            let Some(path) = s("path") else { return tool_err(id, "path is required") };
            argv.push("skills".into()); argv.push(path);
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            argv.push("-v".into());
        }
        "neurosploit_pr" => {
            let Some(repo) = s("repo") else { return tool_err(id, "repo is required") };
            let Some(number) = i("number") else { return tool_err(id, "number is required") };
            argv.push("pr".into()); argv.push(repo); argv.push(number.to_string());
            if let Some(m) = s("model") { argv.push("--model".into()); argv.push(m); }
            if b("subscription") { argv.push("--subscription".into()); }
            if b("comment") { argv.push("--comment".into()); }
            if let Some(fo) = s("fail_on") { argv.push("--fail-on".into()); argv.push(fo); }
            if b("jira") { argv.push("--jira".into()); }
            argv.push("-v".into());
        }
        "neurosploit_internal" => {
            argv.push("internal".into());
            if let Some(g) = s("graph") { argv.push("--graph".into()); argv.push(g); }
            if let Some(sc) = s("scaffold") { argv.push("--scaffold".into()); argv.push(sc); }
            if let Some(fr) = s("from") { argv.push("--from".into()); argv.push(fr); }
        }

        // ---- post-run tools -------------------------------------------------
        "neurosploit_list_runs" => return list_runs(id),
        "neurosploit_findings" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            return read_run_file(id, &run, "findings.json");
        }
        "neurosploit_report" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            return read_run_file(id, &run, "report.md");
        }
        "neurosploit_rebuild" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("rebuild".into()); argv.push(run);
        }
        "neurosploit_sarif" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("sarif".into()); argv.push(run);
        }
        "neurosploit_compliance" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("compliance".into()); argv.push(run);
            if let Some(fw) = s("framework") { argv.push("--framework".into()); argv.push(fw); }
        }
        "neurosploit_graph" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("graph".into()); argv.push(run);
            if let Some(ig) = s("internal") { argv.push("--internal".into()); argv.push(ig); }
            if b("push") { argv.push("--push".into()); }
            if let Some(t) = i("top") { argv.push("--top".into()); argv.push(t.to_string()); }
        }
        "neurosploit_audit" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("audit".into()); argv.push(run);
            if b("anchor") { argv.push("--anchor".into()); }
        }
        "neurosploit_poc" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("poc".into()); argv.push(run);
            if let Some(r) = i("repeats") { argv.push("--repeats".into()); argv.push(r.to_string()); }
            if b("apply") { argv.push("--apply".into()); }
            if let Some(o) = s("only") { argv.push("--only".into()); argv.push(o); }
            argv.push("--json".into());
        }
        "neurosploit_traffic" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("traffic".into()); argv.push(run);
        }
        "neurosploit_assurance" => {
            let Some(run) = s("run") else { return tool_err(id, "run is required") };
            argv.push("assurance".into()); argv.push(run);
            if b("verify") { argv.push("--verify".into()); }
        }

        // ---- info -----------------------------------------------------------
        "neurosploit_agents" => { argv.push("agents".into()); }
        "neurosploit_models" => { argv.push("models".into()); }

        // ---- collection preview ---------------------------------------------
        "neurosploit_import_collection" => {
            let Some(path) = s("path") else { return tool_err(id, "path is required") };
            return import_collection(id, &path);
        }

        _ => return tool_err(id, &format!("unknown tool: {name}")),
    }

    run_cli(id, exe, &argv)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_cli(id: Option<Value>, exe: &std::path::Path, argv: &[String]) -> Value {
    let out = std::process::Command::new(exe).args(argv).output();
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

fn import_collection(id: Option<Value>, path: &str) -> Value {
    match harness::collection::parse_path(path) {
        Ok(eps) => {
            let kind = if std::path::Path::new(path).is_dir() { "directory" } else { "file" };
            let mut lines = vec![format!("Parsed {kind} {path}: {} endpoint(s)\n", eps.len())];
            for (i, ep) in eps.iter().enumerate().take(200) {
                if ep.note.is_empty() {
                    lines.push(format!("  {}. {} {}", i + 1, ep.method, ep.url));
                } else {
                    lines.push(format!("  {}. {} {}  ({})", i + 1, ep.method, ep.url, ep.note));
                }
            }
            if eps.len() > 200 {
                lines.push(format!("  … and {} more", eps.len() - 200));
            }
            tool_text(id, &lines.join("\n"))
        }
        Err(e) => tool_err(id, &format!("{e}")),
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
