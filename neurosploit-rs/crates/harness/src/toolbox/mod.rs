//! Toolbox: run real security tools, not only curl/scripts.
//!
//! The toolbox is an add-on layer over the harness:
//!  * a 200+ entry catalog (`tools/toolbox.json`, embedded) of web, network,
//!    Active Directory, cloud, container, mobile, binary, forensics and AI
//!    tooling;
//!  * a scope/constraint-aware runner (host or Kali sandbox) with optional,
//!    explicit provisioning;
//!  * MCP server templates (nmap, Kali, Playwright, Burp, REA, NeuroSploit);
//!  * CLI/MCP/web surfaces plus an opt-in agent tool loop.
//!
//! Nothing runs unless the operator or an explicitly enabled agent asks for it.
//! Existing recon/exploit behaviour is unchanged when the feature is not used.

pub mod catalog;
pub mod mcp_catalog;
pub mod runner;

pub use catalog::{all, categories, find, mode_plan, prompt_summary, search, ToolSpec};
pub use mcp_catalog::{McpServerSpec, add_to_file, remove_from_file, servers_path};
pub use runner::{check, install, run, ToolCheck, ToolRun, ToolRunConfig};

/// Prompt doctrine injected when `--tools` / agent tools are enabled.
pub fn doctrine() -> String {
    format!(
        "TOOLBOX (authorized; {} real tools are available through NeuroSploit, not only curl):\n\
         - Discover: `neurosploit tools search <term> --json`; inspect: `neurosploit tools info <id> --json`.\n\
         - Check: `neurosploit tools check <id> --json` (installed/version; no scan).\n\
         - Run: `neurosploit tools run <id> --target <host-or-url> [--args '<flags>'] --json`.\n\
         - Provision (explicit): `neurosploit tools install <id> --json`; or add `--provision` to run.\n\
         - Sandbox: add `--sandbox` (Kali container) when you do not want host tooling.\n\
         - MCP servers: `neurosploit tools mcp list`; add nmap/kali/playwright with `tools mcp add <name>`.\n\
         - Key examples: `tools run rustscan --target 10.0.0.5`; `tools run nmap --target 10.0.0.5 --args '-sV -p 22,80,443'`;\n\
           `tools run httpx --target https://app`; `tools run nuclei --target https://app --args '-severity critical,high -silent'`;\n\
           `tools run ffuf --target https://app --args '-u https://app/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt'`;\n\
           `tools run netexec --target 10.0.0.10 --args 'smb 10.0.0.10 --shares'`;\n\
           `tools run bloodhound_python --target dc.corp.local --args '-d corp.local -u user -p pass -c All'`.\n\
         Rules: stay in scope; never run destructive/DoS tools; prefer targeted flags; provision only with explicit opt-in;\n\
         report the exact command, exit code and output/evidence in findings. On subscription/CLI agents you may also\n\
         call the same `neurosploit tools` verbs directly; when MCP is enabled use the `neurosploit_tool_*` tools.\n\n"
        ,
        catalog::all().len()
    )
}

/// A compact catalog block for the opt-in agent tool loop. Kept small so it does
/// not crowd the specialist playbooks.
pub fn agent_catalog(mode: &str) -> String {
    let mut out = String::from("TOOLBOX CATALOG (id — description):\n");
    let plan = mode_plan(mode);
    for id in &plan {
        if let Some(t) = find(id) {
            out.push_str(&format!("- {} [{}] {} — {}\n", t.id, t.category, t.name, t.description));
        }
    }
    out.push_str("\nOther categories are available via `neurosploit tools search <term>`.\n");
    out
}
