//! Execution layer for the toolbox.
//!
//! One place resolves a catalog ID into a command, checks scope and operator
//! constraints, detects/provisions the binary, runs it (host or Kali sandbox),
//! caps output, records an audit line, and returns structured JSON. The CLI,
//! the agent tool loop and the MCP tools all call this — never `sh -c` from a
//! prompt directly.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::catalog::{find, ToolSpec};
use crate::constraints::ConstraintSet;
use crate::sandbox::{Sandbox, SandboxConfig};
use crate::scope::ScopePolicy;

const OUTPUT_CAP: usize = 256 * 1024;
const DEFAULT_TIMEOUT: u64 = 300;
const INSTALL_TIMEOUT: u64 = 300;

#[derive(Debug, Clone, Default)]
pub struct ToolRunConfig {
    /// Kali/container image. `Some("")` uses the default image.
    pub sandbox: Option<String>,
    /// Explicit opt-in: install the tool when missing.
    pub provision: bool,
    pub timeout_secs: Option<u64>,
    /// Directory for `toolbox-audit.jsonl` and run artifacts.
    pub audit_dir: Option<PathBuf>,
    /// Engagement scope. `None` means the operator invoked the tool directly.
    pub scope: Option<ScopePolicy>,
    pub constraints: ConstraintSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRun {
    pub tool: String,
    pub name: String,
    pub category: String,
    pub command: String,
    pub target: String,
    pub installed: bool,
    pub provisioned: bool,
    pub code: i32,
    pub timed_out: bool,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCheck {
    pub tool: String,
    pub name: String,
    pub binary: String,
    pub category: String,
    pub installed: bool,
    pub version: String,
    pub install_hint: String,
    pub intrusive: bool,
    pub requires_root: bool,
}

pub fn install_hint(spec: &ToolSpec) -> String {
    if let Some((kind, pkg)) = spec.install.iter().next() {
        format!("neurosploit tools install {}  ({kind}: {pkg})", spec.id)
    } else {
        format!("install `{}` manually and put it on PATH", spec.binary)
    }
}

fn sandbox_for(cfg: &ToolRunConfig) -> Result<Option<Sandbox>, String> {
    let Some(image) = cfg.sandbox.as_deref() else { return Ok(None) };
    let mut sc = SandboxConfig::default();
    if !image.trim().is_empty() {
        sc = sc.with_image(image);
    }
    Sandbox::new(sc).map(Some)
}

async fn host_has(binary: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(binary)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn installer_command(kind: &str, pkg: &str) -> Option<String> {
    match kind {
        "apt" => Some(format!(
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkg}"
        )),
        "pipx" => Some(format!("pipx install --force {pkg}")),
        "go" => Some(format!("GOBIN=/usr/local/bin go install {pkg}@latest")),
        "cargo" => Some(format!("cargo install --locked {pkg}")),
        "npm" => Some(format!("npm install -g {pkg}")),
        "gem" => Some(format!("gem install --no-document {pkg}")),
        "docker" => Some(format!("docker pull {pkg}")),
        _ => None,
    }
}

async fn run_shell(command: &str, timeout_secs: u64, sandbox: Option<&Sandbox>) -> Result<(i32, String, String, bool), String> {
    if let Some(sb) = sandbox {
        let out = sb.exec(command).await?;
        return Ok((out.code, out.stdout, out.stderr, out.timed_out));
    }
    let fut = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(Duration::from_secs(timeout_secs), fut).await {
        Ok(Ok(out)) => Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            false,
        )),
        Ok(Err(e)) => Err(format!("spawn failed: {e}")),
        Err(_) => Ok((124, String::new(), format!("timed out after {timeout_secs}s"), true)),
    }
}

fn clip(mut s: String) -> String {
    if s.len() > OUTPUT_CAP {
        s.truncate(OUTPUT_CAP);
        s.push_str("\n[truncated by NeuroSploit toolbox]");
    }
    s
}

fn substitute(template: &str, target: &str) -> Result<String, String> {
    let host = if target.trim().is_empty() {
        String::new()
    } else {
        crate::scope::host_of(target)
    };
    let needs_target = template.contains("{target}") || template.contains("{host}") || template.contains("{url}");
    if needs_target && target.trim().is_empty() {
        return Err("this tool needs a target (use --target or pass concrete args)".into());
    }
    let out = template
        .replace("{target}", target)
        .replace("{host}", &host)
        .replace("{url}", target);
    if out.contains('{') {
        return Err(format!(
            "unresolved placeholder in command: {out}\nPass explicit `--args` for templates that need credentials/domains."
        ));
    }
    Ok(out)
}

fn scope_allows(scope: Option<&ScopePolicy>, target: &str) -> Result<(), String> {
    let Some(scope) = scope else { return Ok(()) };
    if scope.hard.is_empty() || target.trim().is_empty() {
        return Ok(());
    }
    let probe = if target.contains("://") {
        target.to_string()
    } else {
        format!("https://{}", target.trim())
    };
    if !scope.in_hard_scope(&probe) {
        return Err(format!("target '{target}' is outside the engagement's hard scope"));
    }
    Ok(())
}

fn audit(cfg: &ToolRunConfig, run: &ToolRun) {
    let dir = cfg
        .audit_dir
        .clone()
        .or_else(|| std::env::var_os("NEUROSPLOIT_TOOLBOX_DIR").map(PathBuf::from))
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".neurosploit")
                .join("toolbox")
        });
    let _ = std::fs::create_dir_all(&dir);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let rec = json!({
        "ts": ts,
        "tool": run.tool,
        "command": run.command,
        "target": run.target,
        "code": run.code,
        "timed_out": run.timed_out,
        "duration_ms": run.duration_ms,
        "stdout_len": run.stdout.len(),
        "stderr_len": run.stderr.len(),
    });
    let path = dir.join("toolbox-audit.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(Path::new(&path)) {
        let _ = writeln!(f, "{rec}");
    }
}

/// Detect a tool and (when allowed) provision it. Returns whether it is now
/// available.
pub async fn ensure_installed(
    spec: &ToolSpec,
    cfg: &ToolRunConfig,
    sandbox: Option<&Sandbox>,
) -> Result<(bool, bool), String> {
    let installed = if let Some(sb) = sandbox {
        sb.exec(&format!("command -v {}", shell_quote(&spec.binary)))
            .await?
            .code
            == 0
    } else {
        host_has(&spec.binary).await
    };
    if installed {
        return Ok((true, false));
    }
    if !cfg.provision {
        return Ok((false, false));
    }
    let mut last_err = String::new();
    for (kind, pkg) in &spec.install {
        let Some(cmd) = installer_command(kind, pkg) else { continue };
        let (code, out, err, timed) = run_shell(&cmd, INSTALL_TIMEOUT, sandbox).await?;
        if code == 0 && !timed {
            let now = if let Some(sb) = sandbox {
                sb.exec(&format!("command -v {}", shell_quote(&spec.binary)))
                    .await?
                    .code
                    == 0
            } else {
                host_has(&spec.binary).await
            };
            if now {
                return Ok((true, true));
            }
            last_err = format!("{kind} install succeeded but `{}` is still not on PATH", spec.binary);
        } else {
            last_err = format!(
                "{kind} install failed (code {code}): {}",
                err.lines().last().unwrap_or(&out).trim()
            );
        }
    }
    if last_err.is_empty() {
        last_err = install_hint(spec);
    }
    Err(format!("could not provision '{}': {last_err}", spec.id))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Check availability + version without running a scan.
pub async fn check(spec: &ToolSpec, cfg: &ToolRunConfig) -> Result<ToolCheck, String> {
    let sb = sandbox_for(cfg)?;
    if let Some(s) = &sb {
        s.ensure().await?;
    }
    let installed = if let Some(s) = &sb {
        s.exec(&format!("command -v {}", shell_quote(&spec.binary)))
            .await?
            .code
            == 0
    } else {
        host_has(&spec.binary).await
    };
    let mut version = String::new();
    if installed {
        let cmd = format!("{} --version 2>&1 | head -n 1", shell_quote(&spec.binary));
        if let Ok((_, out, _, _)) = run_shell(&cmd, 8, sb.as_ref()).await {
            version = out.trim().chars().take(160).collect();
        }
    }
    Ok(ToolCheck {
        tool: spec.id.clone(),
        name: spec.name.clone(),
        binary: spec.binary.clone(),
        category: spec.category.clone(),
        installed,
        version,
        install_hint: install_hint(spec),
        intrusive: spec.intrusive,
        requires_root: spec.requires_root,
    })
}

/// Install a tool explicitly (operator asked for it).
pub async fn install(spec: &ToolSpec, cfg: &ToolRunConfig) -> Result<(bool, String), String> {
    let sb = sandbox_for(cfg)?;
    if let Some(s) = &sb {
        s.ensure().await?;
    }
    let mut cfg = cfg.clone();
    cfg.provision = true;
    match ensure_installed(spec, &cfg, sb.as_ref()).await {
        Ok((true, _)) => {
            let chk = check(spec, &cfg).await?;
            Ok((true, chk.version))
        }
        Ok((false, _)) => Err(install_hint(spec)),
        Err(e) => Err(e),
    }
}

/// Run a catalog tool.
pub async fn run(
    tool_id: &str,
    args: Option<&str>,
    target: &str,
    cfg: &ToolRunConfig,
) -> Result<ToolRun, String> {
    let spec = find(tool_id).ok_or_else(|| format!("unknown tool '{tool_id}' (try `neurosploit tools search {tool_id}`)"))?;
    scope_allows(cfg.scope.as_ref(), target)?;

    let cmd = match args.map(|a| a.trim()).filter(|a| !a.is_empty()) {
        Some(a) => {
            let a = substitute(a, target)?;
            let mut cmd = format!("{} {}", spec.binary, a);
            // Convenience: a bare flag list (e.g. "-Pn -p 443") plus --target
            // appends the target. A full command (contains "://" or the target)
            // is left untouched.
            if !target.trim().is_empty() && !a.contains("://") && !a.contains(target) {
                cmd.push(' ');
                cmd.push_str(target);
            }
            cmd
        }
        None => substitute(&spec.usage, target)?,
    };
    if let Some(c) = cfg.constraints.check_command(&cmd) {
        return Err(format!("operator constraint blocked this command: {}", c.text));
    }

    let sb = sandbox_for(cfg)?;
    if let Some(s) = &sb {
        s.ensure().await?;
    }
    let (installed, provisioned) = ensure_installed(spec, cfg, sb.as_ref()).await?;
    if !installed {
        return Err(format!(
            "tool '{}' is not installed — {} (or pass --provision)",
            spec.id,
            install_hint(spec)
        ));
    }

    let started = Instant::now();
    let timeout = cfg.timeout_secs.unwrap_or(DEFAULT_TIMEOUT).max(1);
    let (code, stdout, stderr, timed_out) = run_shell(&cmd, timeout, sb.as_ref()).await?;
    let run = ToolRun {
        tool: spec.id.clone(),
        name: spec.name.clone(),
        category: spec.category.clone(),
        command: cmd,
        target: target.to_string(),
        installed,
        provisioned,
        code,
        timed_out,
        duration_ms: started.elapsed().as_millis(),
        stdout: clip(stdout),
        stderr: clip(stderr),
    };
    audit(cfg, &run);
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_handles_targets() {
        assert_eq!(substitute("nmap {target}", "https://example.com").unwrap(), "nmap https://example.com");
        assert_eq!(substitute("nmap {host}", "https://example.com:8443/x").unwrap(), "nmap example.com");
        assert!(substitute("nmap {target}", "").is_err());
        assert!(substitute("hydra {user}", "10.0.0.5").is_err());
    }

    #[test]
    fn install_hints_and_commands() {
        let nmap = find("nmap").unwrap();
        assert!(install_hint(nmap).contains("nmap"));
        assert!(installer_command("apt", "nmap").unwrap().contains("apt-get"));
        assert!(installer_command("go", "github.com/x/y").unwrap().contains("go install"));
    }

    #[tokio::test]
    async fn unknown_tool_is_an_error() {
        let cfg = ToolRunConfig::default();
        assert!(run("__nope__", None, "", &cfg).await.is_err());
    }
}
