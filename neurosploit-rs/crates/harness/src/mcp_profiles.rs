//! Pre-configured MCP tool profiles for different testing modes.
//!
//! Each [`Profile`] maps to a curated set of MCP tools, server configuration,
//! and prompt context appropriate for a specific engagement type (web, mobile,
//! binary analysis, etc.). Profiles integrate with the MCP hot-reload system
//! in `mcp_hot_reload.rs` to swap tool sets at runtime.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Profile enum
// ---------------------------------------------------------------------------

/// Supported testing profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    Web,
    MobileAndroid,
    MobileIos,
    BinaryAnalysis,
    BurpSuite,
    CobaltStrike,
    TurtleC2,
    Infra,
    Ad,
    Cloud,
    Kali,
    Nmap,
    Full,
    Custom(String),
}

// ---------------------------------------------------------------------------
// TurtleC2 install dir
// ---------------------------------------------------------------------------

/// Locate the local TurtleC2 MCP server package (contains `server.py` +
/// the `.env` with teamserver connection and operator credentials).
pub fn turtlec2_dir() -> String {
    for base in [
        std::env::var("TURTLEC2_MCP_DIR").unwrap_or_default(),
        format!("{}/tools/TurtleC2-MCP-Server", std::env::var("HOME").unwrap_or_default()),
    ] {
        if !base.is_empty() && PathBuf::from(&base).is_dir() {
            return base;
        }
    }
    "tools/TurtleC2-MCP-Server".into()
}

// ---------------------------------------------------------------------------
// McpProfile
// ---------------------------------------------------------------------------

/// A fully-resolved MCP profile ready for activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpProfile {
    /// Human-readable name.
    pub name: String,
    /// One-line description of the profile's purpose.
    pub description: String,
    /// MCP server name to register via hot-reload.
    pub server_name: String,
    /// Tool names relevant to this profile.
    pub tools: Vec<String>,
    /// Server configuration JSON passed to `add_server()`.
    pub config: Value,
}

// ---------------------------------------------------------------------------
// Profile -> McpProfile
// ---------------------------------------------------------------------------

/// Return the preset [`McpProfile`] for the given profile variant.
pub fn profile(p: &Profile) -> McpProfile {
    match p {
        Profile::Web => McpProfile {
            name: "Web".into(),
            description: "Playwright-based web application testing".into(),
            server_name: "playwright".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "npx",
                "args": ["-y", "@anthropic-ai/mcp-playwright"],
                "env": {}
            }),
        },
        Profile::MobileAndroid => McpProfile {
            name: "Mobile Android".into(),
            description: "REA-powered APK / Android binary analysis".into(),
            server_name: "rea".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "rea",
                "args": ["--mode", "android"],
                "env": {}
            }),
        },
        Profile::MobileIos => McpProfile {
            name: "Mobile iOS".into(),
            description: "REA-powered IPA / iOS binary analysis".into(),
            server_name: "rea".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "rea",
                "args": ["--mode", "ios"],
                "env": {}
            }),
        },
        Profile::BinaryAnalysis => McpProfile {
            name: "Binary Analysis".into(),
            description: "REA-powered native binary reverse engineering".into(),
            server_name: "rea".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "rea",
                "args": ["--mode", "binary"],
                "env": {}
            }),
        },
        Profile::BurpSuite => McpProfile {
            name: "Burp Suite".into(),
            description: "Burp Suite REST API integration (placeholder)".into(),
            server_name: "burpsuite".into(),
            tools: tool_allowlist(p),
            config: json!({
                "base_url": "http://127.0.0.1:1337/v0.1",
                "api_key": "",
                "env": {}
            }),
        },
        // Official Cobalt Strike MCP (github.com/Cobalt-Strike/cobaltstrike-mcp-server).
        // It is an HTTP-transport MCP served by the team server (Cobalt Strike
        // 4.13+), not a stdio child — point `CS_MCP_URL` at it (default
        // http://teamserver:50051/mcp) and keep the credentials in the env.
        Profile::CobaltStrike => McpProfile {
            name: "Cobalt Strike".into(),
            description: "Cobalt Strike team-server C2 via the official HTTP MCP".into(),
            server_name: "cobaltstrike".into(),
            tools: tool_allowlist(p),
            config: json!({
                "transport": "http",
                "url": "http://teamserver:50051/mcp",
                "env": {
                    "CS_MCP_URL": "https://localhost:50443",
                    "CS_MCP_USERNAME": "mcp",
                    "CS_MCP_PASSWORD": "",
                    "CS_MCP_VERIFY_SSL": "false"
                }
            }),
        },
        // TurtleC2 teamserver via its Python MCP server (stdio child). The
        // server loads its own .env (teamserver host/port, operator creds)
        // from its package directory, so no secrets are embedded here.
        Profile::TurtleC2 => McpProfile {
            name: "TurtleC2".into(),
            description: "TurtleC2 teamserver C2 via the local stdio MCP server".into(),
            server_name: "turtlec2".into(),
            tools: tool_allowlist(p),
            config: {
                let mut cfg = json!({
                    "command": "uv",
                    "args": ["--directory", turtlec2_dir(), "run", "server.py"],
                    "env": {}
                });
                if !PathBuf::from(turtlec2_dir()).is_dir() {
                    cfg = json!({});
                }
                cfg
            },
        },
        Profile::Infra => McpProfile {
            name: "Infra".into(),
            description: "Network/infra testing with an Nmap MCP server".into(),
            server_name: "nmap".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "npx",
                "args": ["-y", "gc-nmap-mcp"],
                "env": { "NMAP_PATH": "nmap" }
            }),
        },
        Profile::Ad => McpProfile {
            name: "Active Directory".into(),
            description: "AD assessment with a Kali MCP tool server".into(),
            server_name: "kali".into(),
            tools: tool_allowlist(p),
            config: json!({ "command": "kali-mcp", "args": [], "env": {} }),
        },
        Profile::Cloud => McpProfile {
            name: "Cloud".into(),
            description: "Cloud/container assessment (Kali MCP for cloud CLIs)".into(),
            server_name: "kali".into(),
            tools: tool_allowlist(p),
            config: json!({ "command": "kali-mcp", "args": [], "env": {} }),
        },
        Profile::Kali => McpProfile {
            name: "Kali".into(),
            description: "Full Kali Linux MCP tool server (80+ tools)".into(),
            server_name: "kali".into(),
            tools: tool_allowlist(p),
            config: json!({ "command": "kali-mcp", "args": [], "env": {} }),
        },
        Profile::Nmap => McpProfile {
            name: "Nmap".into(),
            description: "Nmap MCP server for port/service discovery".into(),
            server_name: "nmap".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "npx",
                "args": ["-y", "gc-nmap-mcp"],
                "env": { "NMAP_PATH": "nmap" }
            }),
        },
        Profile::Full => McpProfile {
            name: "Full".into(),
            description: "Playwright browser plus external tool servers via --mcp-server".into(),
            server_name: "playwright".into(),
            tools: tool_allowlist(p),
            config: json!({
                "command": "npx",
                "args": ["-y", "@playwright/mcp@latest", "--headless", "--isolated"],
                "env": {}
            }),
        },
        Profile::Custom(ref name) => McpProfile {
            name: format!("Custom: {name}"),
            description: format!("User-defined custom profile '{name}'"),
            server_name: name.clone(),
            tools: Vec::new(),
            config: json!({}),
        },
    }
}

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

/// List every built-in profile with a short description.
pub fn all_profiles() -> Vec<(Profile, &'static str)> {
    vec![
        (Profile::Web, "Playwright-based web application testing"),
        (
            Profile::MobileAndroid,
            "REA-powered APK / Android binary analysis",
        ),
        (
            Profile::MobileIos,
            "REA-powered IPA / iOS binary analysis",
        ),
        (
            Profile::BinaryAnalysis,
            "REA-powered native binary reverse engineering",
        ),
        (
            Profile::BurpSuite,
            "Burp Suite REST API integration (placeholder)",
        ),
        (
            Profile::CobaltStrike,
            "Cobalt Strike team-server C2 via the official HTTP MCP",
        ),
        (
            Profile::TurtleC2,
            "TurtleC2 teamserver C2 via the local stdio MCP server",
        ),
        (Profile::Infra, "Network/infra testing with Nmap MCP"),
        (Profile::Ad, "Active Directory testing with Kali MCP"),
        (Profile::Cloud, "Cloud/container tooling via Kali MCP"),
        (Profile::Kali, "Full Kali Linux MCP tool server"),
        (Profile::Nmap, "Nmap MCP server"),
        (Profile::Full, "Playwright + external tool servers"),
    ]
}

// ---------------------------------------------------------------------------
// Tool allow-lists
// ---------------------------------------------------------------------------

/// Return the MCP tool names relevant to `p`.
pub fn tool_allowlist(p: &Profile) -> Vec<String> {
    let names: &[&str] = match p {
        Profile::Web => &[
            "browser_navigate",
            "browser_click",
            "browser_fill_form",
            "browser_snapshot",
            "browser_take_screenshot",
            "browser_press_key",
            "browser_type",
            "browser_select_option",
            "browser_hover",
            "browser_tabs",
            "browser_navigate_back",
            "browser_evaluate",
            "browser_console_messages",
            "browser_network_requests",
            "browser_find",
            "browser_wait_for",
        ],
        Profile::MobileAndroid => &[
            "open_binary",
            "extract_artifact",
            "batch_decompile",
            "search_strings",
            "analyze_javascript_application",
            "survey_binary",
            "list_strings",
            "inspect_artifact",
        ],
        Profile::MobileIos => &[
            "inspect_macho",
            "inspect_plist",
            "inspect_signature",
            "analyze_swift_types",
            "extract_artifact",
            "decode_interface_builder",
            "inspect_asset_catalog",
        ],
        Profile::BinaryAnalysis => &[
            "open_binary",
            "survey_binary",
            "batch_decompile",
            "trace_data_flow",
            "build_call_path",
            "search_strings",
            "procedure_pseudo_code",
            "procedure_assembly",
            "get_call_graph",
            "list_procedures",
        ],
        Profile::BurpSuite => &[
            "scan",
            "get_issues",
            "proxy_history",
            "send_to_repeater",
        ],
        Profile::CobaltStrike => &[
            "cs_list_beacons",
            "cs_list_commands",
            "cs_execute_command",
            "cs_list_command_executions",
            "cs_read_command_output",
            "cs_list_artifacts",
            "cs_upload_artifact",
            "cs_list_downloads",
            "cs_fetch_download",
            "cs_list_screenshots",
            "cs_fetch_screenshot",
            "cs_get_team_server",
        ],
        Profile::TurtleC2 => &[
            "list_agents",
            "agent_info",
            "agent_console",
            "agent_command",
            "agent_profile",
            "execute_shell",
            "execute_powershell",
            "execute_raw",
            "run_process",
            "list_task_history",
            "jobs_list",
            "jobs_kill",
            "aux_run",
            "aux_list",
            "aux_job_output",
            "upload_file",
            "download_file",
            "list_downloads",
            "get_downloaded_file",
            "list_listeners",
            "list_tunnels",
            "port_forward",
            "reverse_port_forward",
            "stop_tunnel",
            "webdelivery_add",
            "webdelivery_list",
            "list_credentials",
            "loot_list",
            "list_targets",
            "list_processes",
            "kill_process",
            "tag_agent",
            "set_agent_sleep",
            "build",
            "workspace_list",
            "workspace_create",
            "workspace_findings",
            "workspace_finding_add",
            "workspace_export",
            "log_finding",
            "save_writeup",
            "view_session_notes",
        ],
        Profile::Infra | Profile::Nmap => &[
            "do-nmap", "nmap_scan", "nmap_service_scan", "nmap_vuln_scan",
            "nmap_os_detect", "nmap_ping_sweep",
        ],
        Profile::Ad => &[
            "netexec", "enum4linux_ng", "ldapsearch", "smbclient", "rpcclient",
            "impacket", "kerbrute", "certipy", "bloodhound",
        ],
        Profile::Cloud => &[
            "trivy", "prowler", "scoutsuite", "checkov", "kube_bench", "kube_hunter",
            "cloud_enum", "s3scanner",
        ],
        Profile::Kali | Profile::Full => &[
            "nmap", "sqlmap", "nikto", "gobuster", "ffuf", "nuclei", "whatweb",
            "httpx_probe", "hydra", "john", "searchsploit", "enum4linux", "smbclient",
        ],
        Profile::Custom(_) => &[],
    };
    names.iter().map(|s| (*s).to_string()).collect()
}

// ---------------------------------------------------------------------------
// Prompt context
// ---------------------------------------------------------------------------

/// Return context text to inject into agent prompts for `p`.
pub fn prompt_context(p: &Profile) -> String {
    let tools = tool_allowlist(p);
    let tool_list = tools.join(", ");

    match p {
        Profile::Web => format!(
            "You are operating in WEB testing mode. \
             Use Playwright MCP tools to interact with the target web application. \
             Available tools: {tool_list}. \
             Prefer snapshots over screenshots for speed; use screenshots only \
             when visual verification is required."
        ),
        Profile::MobileAndroid => format!(
            "You are operating in MOBILE ANDROID testing mode. \
             Use REA MCP tools to analyze APK files and Android binaries. \
             Available tools: {tool_list}. \
             Start by opening the binary, then survey its structure before \
             diving into decompilation."
        ),
        Profile::MobileIos => format!(
            "You are operating in MOBILE iOS testing mode. \
             Use REA MCP tools to analyze IPA files and iOS binaries. \
             Available tools: {tool_list}. \
             Check the Mach-O header, plist, and code signature before \
             inspecting Swift types and Interface Builder files."
        ),
        Profile::BinaryAnalysis => format!(
            "You are operating in BINARY ANALYSIS mode. \
             Use REA MCP tools for native binary reverse engineering. \
             Available tools: {tool_list}. \
             Open the binary, survey it, then trace data flow and call paths \
             to identify interesting code paths."
        ),
        Profile::BurpSuite => format!(
            "You are operating in BURP SUITE mode. \
             Use the Burp Suite REST API to drive scans and inspect results. \
             Available tools: {tool_list}. \
             Note: this profile is a placeholder; ensure the Burp REST API \
             is running before invoking tools."
        ),
        Profile::CobaltStrike => format!(
            "You are operating in COBALT STRIKE mode through the official team-server MCP. \
             Available tools: {tool_list}. Use cs_list_beacons to establish the current session \
             inventory before acting, cs_execute_command to run one authorized command at a time, \
             and cs_read_command_output for the receipt. Every action is attributable to the \
             engagement — stay inside the authorized hosts, never run destructive or \
             persistence-changing commands unless the operator explicitly approved them, \
             and put the raw command output into the finding evidence."
        ),
        Profile::TurtleC2 => format!(
            "You are operating in TURTLEC2 mode through the local teamserver MCP. \
             Available tools: {tool_list}. Use list_agents to establish the current session \
             inventory, agent_info for a session's host details, and agent_command to run one \
             authorized command at a time — list_task_history then shows the receipt; \
             agent_console drives an interactive session. Pivoting uses port_forward / \
             reverse_port_forward and list_tunnels; staging uses webdelivery_add; \
             evidence and bookkeeping use log_finding, workspace_finding_add, \
             workspace_findings, save_writeup and view_session_notes; collected material is \
             readable via list_credentials, loot_list, list_downloads and \
             get_downloaded_file; payload generation is build. Every action is attributable \
             to the engagement — stay inside the authorized hosts, never run destructive or \
             persistence-changing commands unless the operator explicitly approved them, \
             and put the raw command output into the finding evidence."
        ),
        Profile::Infra => format!(
            "You are operating in INFRA/NETWORK testing mode. Use the Nmap MCP server for \
             host discovery, port/service identification and NSE checks. Available tools: {tool_list}. \
             Keep scans targeted and within the authorized scope; prefer -sV over full-range scans."
        ),
        Profile::Ad => format!(
            "You are operating in ACTIVE DIRECTORY testing mode. Use the Kali MCP server for \
             SMB/LDAP/Kerberos enumeration, credential validation and authenticated checks. \
             Available tools: {tool_list}. Reuse credentials already proven in the engagement; \
             never brute-force or run destructive actions."
        ),
        Profile::Cloud => format!(
            "You are operating in CLOUD/CONTAINER testing mode. Use the Kali MCP server for \
             cloud CLIs and container scanners. Available tools: {tool_list}. Read-only discovery \
             first; never delete/modify cloud resources."
        ),
        Profile::Kali | Profile::Full => format!(
            "You are operating in TOOLBOX mode with a Kali Linux MCP server. Real pentest tools are \
             available as MCP tools: {tool_list}. Prefer the right tool over hand-rolled scripts; \
             stay in scope and avoid destructive/DoS actions."
        ),
        Profile::Nmap => format!(
            "You are operating in NMAP mode. Use the Nmap MCP server for port/service discovery. \
             Available tools: {tool_list}. Keep scans targeted and authorized."
        ),
        Profile::Custom(ref name) => format!(
            "You are operating with the custom profile '{name}'. \
             No predefined tools are configured; add tools via the \
             McpProfile struct before activating."
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_have_non_empty_tools() {
        for (p, _desc) in all_profiles() {
            let mcp = profile(&p);
            assert!(
                !mcp.tools.is_empty(),
                "Profile {:?} must have at least one tool",
                p
            );
        }
    }

    #[test]
    fn prompt_context_mentions_tools() {
        for (p, _desc) in all_profiles() {
            let ctx = prompt_context(&p);
            let tools = tool_allowlist(&p);
            for tool in &tools {
                assert!(
                    ctx.contains(tool),
                    "Prompt context for {:?} should mention tool '{}'",
                    p,
                    tool
                );
            }
        }
    }

    #[test]
    fn all_profiles_covers_every_variant() {
        let listed: Vec<Profile> = all_profiles().into_iter().map(|(p, _)| p).collect();

        // Every built-in variant must appear in all_profiles().
        let expected = vec![
            Profile::Web,
            Profile::MobileAndroid,
            Profile::MobileIos,
            Profile::BinaryAnalysis,
            Profile::BurpSuite,
            Profile::CobaltStrike,
            Profile::TurtleC2,
            Profile::Infra,
            Profile::Ad,
            Profile::Cloud,
            Profile::Kali,
            Profile::Nmap,
            Profile::Full,
        ];

        for variant in &expected {
            assert!(
                listed.contains(variant),
                "all_profiles() is missing {:?}",
                variant
            );
        }

        // Custom is intentionally excluded from the catalogue.
        assert!(
            !listed.contains(&Profile::Custom("x".into())),
            "Custom should not appear in all_profiles()"
        );
    }
}
