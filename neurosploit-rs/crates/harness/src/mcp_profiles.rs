//! Pre-configured MCP tool profiles for different testing modes.
//!
//! Each [`Profile`] maps to a curated set of MCP tools, server configuration,
//! and prompt context appropriate for a specific engagement type (web, mobile,
//! binary analysis, etc.). Profiles integrate with the MCP hot-reload system
//! in `mcp_hot_reload.rs` to swap tool sets at runtime.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    Custom(String),
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
