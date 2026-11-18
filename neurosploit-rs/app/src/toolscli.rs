//! `neurosploit tools …` — run real security tools from the 200+ catalog and
//! manage MCP tool servers. Thin CLI over `harness::toolbox`, so the CLI, MCP
//! surface, agent loop and web console share one runner and one audit trail.

use clap::Subcommand;
use serde_json::{json, Value};

use harness::toolbox::{
    self, mcp_catalog, ToolRunConfig, ToolSpec,
};

#[derive(Subcommand)]
pub enum ToolsCmd {
    /// List the toolbox catalog (optionally one category).
    List {
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Search by id/name/binary/tag/description.
    Search {
        query: String,
        #[arg(long)]
        json: bool,
    },
    /// Show one tool's full descriptor.
    Info {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Check whether tool(s) are installed and report versions.
    Check {
        id: Option<String>,
        /// Check every catalog entry (slow: one `which` per tool).
        #[arg(long)]
        all: bool,
        /// Check inside the Kali sandbox.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        sandbox: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Run a catalog tool against a target.
    Run {
        id: String,
        #[arg(long, default_value = "")]
        target: String,
        /// Override the catalog usage, e.g. '-sV -p 22,80,443'.
        #[arg(long, allow_hyphen_values = true)]
        args: Option<String>,
        /// Run inside the Kali sandbox instead of the host.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        sandbox: Option<String>,
        #[arg(long, default_value_t = 300)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Install a tool (explicit opt-in, host or sandbox).
    Install {
        id: String,
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        sandbox: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Recommended toolchains per engagement mode.
    Profiles {
        #[arg(long)]
        json: bool,
    },
    /// MCP tool-server catalog and local configuration.
    Mcp {
        #[command(subcommand)]
        cmd: ToolsMcpCmd,
    },
}

#[derive(Subcommand)]
pub enum ToolsMcpCmd {
    /// List curated MCP servers and which are configured locally.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Add a curated MCP server to ./mcp.servers.json (used by --mcp runs).
    Add { name: String },
    /// Remove an MCP server from ./mcp.servers.json.
    Remove { name: String },
    /// Print the JSON config snippet for an MCP server.
    Json { name: String },
    /// Check the server's command/binary (or HTTP URL) without starting a run.
    Test {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the local mcp.servers.json path and contents.
    Path {
        #[arg(long)]
        json: bool,
    },
}

pub async fn handle(cmd: ToolsCmd) -> anyhow::Result<()> {
    match cmd {
        ToolsCmd::List { category, json } => {
            let items: Vec<&ToolSpec> = toolbox::all()
                .iter()
                .filter(|t| category.as_deref().map(|c| t.category.eq_ignore_ascii_case(c)).unwrap_or(true))
                .collect();
            if json {
                print_json(&json!(items));
            } else {
                for t in &items {
                    println!(
                        "{:<24} {:<10} {:<18} {}",
                        t.id, t.category, t.binary, t.description
                    );
                }
                println!("\n{} tool(s)", items.len());
                if category.is_none() {
                    for (c, n) in toolbox::categories() {
                        println!("  {c:<12} {n}");
                    }
                }
            }
        }
        ToolsCmd::Search { query, json } => {
            let items = toolbox::search(&query);
            if json {
                print_json(&json!(items));
            } else {
                for t in &items {
                    println!("{:<24} {:<10} {}", t.id, t.category, t.description);
                }
                println!("\n{} match(es)", items.len());
            }
        }
        ToolsCmd::Info { id, json } => {
            let t = toolbox::find(&id)
                .ok_or_else(|| anyhow::anyhow!("unknown tool '{id}' — try `neurosploit tools search {id}`"))?;
            if json {
                print_json(&json!(t));
            } else {
                print_tool(t);
            }
        }
        ToolsCmd::Check {
            id,
            all,
            sandbox,
            json,
        } => {
            let specs: Vec<&ToolSpec> = if all {
                toolbox::all().iter().collect()
            } else if let Some(id) = id {
                vec![toolbox::find(&id).ok_or_else(|| anyhow::anyhow!("unknown tool '{id}'"))?]
            } else {
                return Err(anyhow::anyhow!("give a tool id or --all"));
            };
            let cfg = ToolRunConfig {
                sandbox: sandbox.clone(),
                ..Default::default()
            };
            let mut out = Vec::new();
            for spec in specs {
                match toolbox::check(spec, &cfg).await {
                    Ok(c) => {
                        if !json {
                            println!(
                                "{} {} {}",
                                if c.installed { "✓" } else { "✗" },
                                c.tool,
                                if c.installed { format!("— {}", c.version) } else { format!("— {}", c.install_hint) }
                            );
                        }
                        out.push(json!(c));
                    }
                    Err(e) => {
                        if !json {
                            println!("✗ {} — {e}", spec.id);
                        }
                        out.push(json!({"tool": spec.id, "installed": false, "error": e}));
                    }
                }
            }
            if json {
                print_json(&json!(out));
            }
        }
        ToolsCmd::Run {
            id,
            target,
            args,
            sandbox,
            timeout,
            json,
        } => {
            let cfg = ToolRunConfig {
                sandbox,
                provision: std::env::var("NEUROSPLOIT_PROVISION").ok().as_deref() == Some("1"),
                timeout_secs: Some(timeout),
                ..Default::default()
            };
            let run = toolbox::run(&id, args.as_deref(), &target, &cfg)
                .await
                .map_err(anyhow::Error::msg)?;
            if json {
                print_json(&json!(run));
            } else {
                println!("$ {}", run.command);
                println!(
                    "{} · exit {} · {} ms{}",
                    run.name,
                    run.code,
                    run.duration_ms,
                    if run.timed_out { " · TIMED OUT" } else { "" }
                );
                if !run.stdout.trim().is_empty() {
                    println!("--- stdout ---\n{}", run.stdout);
                }
                if !run.stderr.trim().is_empty() {
                    println!("--- stderr ---\n{}", run.stderr);
                }
            }
        }
        ToolsCmd::Install { id, sandbox, json } => {
            let spec = toolbox::find(&id).ok_or_else(|| anyhow::anyhow!("unknown tool '{id}'"))?;
            let cfg = ToolRunConfig {
                sandbox,
                provision: true,
                ..Default::default()
            };
            let (ok, version) = toolbox::install(spec, &cfg).await.map_err(anyhow::Error::msg)?;
            if json {
                print_json(&json!({"ok": ok, "tool": spec.id, "version": version}));
            } else {
                println!("✓ {} installed {version}", spec.id);
            }
        }
        ToolsCmd::Profiles { json } => {
            let mut out = Vec::new();
            for mode in ["run", "host", "ad", "cloud", "container", "mobile", "binary", "aitest"] {
                let ids = toolbox::mode_plan(mode);
                out.push(json!({"mode": mode, "tools": ids}));
                if !json {
                    println!("{mode:<10} {}", ids.join(", "));
                }
            }
            if json {
                print_json(&json!(out));
            }
        }
        ToolsCmd::Mcp { cmd } => handle_mcp(cmd).await?,
    }
    Ok(())
}

async fn handle_mcp(cmd: ToolsMcpCmd) -> anyhow::Result<()> {
    let base = std::env::current_dir().unwrap_or_default();
    match cmd {
        ToolsMcpCmd::List { json } => {
            let path = mcp_catalog::servers_path(&base);
            let configured: Vec<String> = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .map(|v| {
                    let obj = v.get("mcpServers").cloned().unwrap_or(v);
                    obj.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default()
                })
                .unwrap_or_default();
            let mut out = Vec::new();
            for s in mcp_catalog::all() {
                out.push(json!({
                    "name": s.name,
                    "description": s.description,
                    "transport": s.transport,
                    "command": s.command,
                    "args": s.args,
                    "url": s.url,
                    "configured": configured.iter().any(|c| c == &s.name),
                    "install": s.install,
                    "notes": s.notes,
                }));
            }
            if json {
                print_json(&json!({"servers": out, "config": path}));
            } else {
                println!("MCP servers (config: {})", path.display());
                for v in &out {
                    println!(
                        "{} {:<12} {:<6} {}{}",
                        if v["configured"].as_bool().unwrap_or(false) { "✓" } else { "·" },
                        v["name"].as_str().unwrap_or(""),
                        v["transport"].as_str().unwrap_or(""),
                        v["description"].as_str().unwrap_or(""),
                        if v["configured"].as_bool().unwrap_or(false) { "  [configured]" } else { "" }
                    );
                }
                println!("\nAdd with: neurosploit tools mcp add nmap");
            }
        }
        ToolsMcpCmd::Add { name } => {
            let path = mcp_catalog::add_to_file(&base, &name).map_err(anyhow::Error::msg)?;
            println!("✓ {name} added to {}", path.display());
            println!("  Next run: neurosploit run <target> --subscription --mcp --model <model>");
        }
        ToolsMcpCmd::Remove { name } => {
            let removed = mcp_catalog::remove_from_file(&base, &name).map_err(anyhow::Error::msg)?;
            println!("{} {name}", if removed { "✓ removed" } else { "· not configured:" });
        }
        ToolsMcpCmd::Json { name } => {
            let spec = mcp_catalog::find(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown MCP server '{name}'"))?;
            print_json(&json!({ "mcpServers": { spec.name.clone(): spec.config() } }));
        }
        ToolsMcpCmd::Test { name, json } => {
            let spec = mcp_catalog::find(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown MCP server '{name}'"))?;
            let (ok, detail) = test_mcp(&spec).await;
            if json {
                print_json(&json!({"ok": ok, "server": spec.name, "detail": detail}));
            } else {
                println!("{} {} — {}", if ok { "✓" } else { "✗" }, spec.name, detail);
            }
        }
        ToolsMcpCmd::Path { json } => {
            let path = mcp_catalog::servers_path(&base);
            let body = std::fs::read_to_string(&path).unwrap_or_else(|_| "{}".into());
            if json {
                print_json(&json!({"path": path, "content": body}));
            } else {
                println!("{}", path.display());
                println!("{body}");
            }
        }
    }
    Ok(())
}

async fn test_mcp(spec: &mcp_catalog::McpServerSpec) -> (bool, String) {
    if spec.transport == "http" {
        let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(4)).build() {
            Ok(c) => c,
            Err(e) => return (false, e.to_string()),
        };
        return match client.get(&spec.url).send().await {
            Ok(r) => (r.status().is_success() || r.status().is_client_error(), format!("HTTP {}", r.status())),
            Err(e) => (false, format!("{}: {e}", spec.url)),
        };
    }
    if spec.command.trim().is_empty() {
        return (false, "no command configured (edit mcp.servers.json)".into());
    }
    let found = tokio::process::Command::new("which")
        .arg(&spec.command)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if found {
        (true, format!("{} found on PATH", spec.command))
    } else {
        (
            false,
            format!(
                "{} not found — {}",
                spec.command,
                spec.install
                    .iter()
                    .next()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .unwrap_or_else(|| "install it manually".into())
            ),
        )
    }
}

fn print_tool(t: &ToolSpec) {
    println!("{} — {}", t.id, t.name);
    println!("  category : {}", t.category);
    println!("  binary   : {}", t.binary);
    println!("  usage    : {}", t.usage);
    println!("  tags     : {}", t.tags.join(", "));
    if t.intrusive {
        println!("  intrusive: yes — actively probes the target");
    }
    if t.requires_root {
        println!("  root     : may require root/CAP_NET_RAW");
    }
    if let Some(m) = &t.mcp {
        println!("  mcp      : {m}");
    }
    if t.install.is_empty() {
        println!("  install  : manual (put `{}` on PATH)", t.binary);
    } else {
        for (k, v) in &t.install {
            println!("  install  : {k}: {v}");
        }
    }
}

fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into())
    );
}
