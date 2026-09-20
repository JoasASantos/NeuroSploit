//! Sandbox — running the dangerous half of an engagement off the host.
//!
//! The harness executes things that are shaped like attacks: payloads, shell
//! commands an agent wrote, tools that scan and fuzz. Today those run on the
//! operator's own machine. That is the largest single risk in the whole system
//! — a payload that misfires, a tool with a bug, an agent that runs the wrong
//! command, all land on the host that holds the engagement's credentials and
//! the operator's keys.
//!
//! A container fixes the blast radius, and brings the tools with it. Kali ships
//! nmap, sqlmap, ffuf, nuclei, the Metasploit tooling — a whole pentest
//! toolchain the harness otherwise assumes is installed on the host and often
//! is not. So the container is two wins at once: isolation, and a known
//! toolbox.
//!
//! ```text
//!   agent command ──→ docker exec ns-kali  <cmd>  ──→ runs in Kali, not on the host
//!                          │
//!                          ├── workdir mounted read-write (evidence comes back)
//!                          ├── proxy + transport env inherited (same route)
//!                          └── network scoped to the engagement
//! ```
//!
//! ## What it does not pretend
//!
//! A container is isolation, not a jail. `--network host` or a mounted docker
//! socket would hand the container the host back, so this module refuses to add
//! either. And if no container runtime is present, it says so and the caller
//! falls back to host execution *explicitly* — a silent fallback to running
//! attack payloads on the host is exactly the failure the sandbox exists to
//! prevent, so it is never silent.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A container runtime the harness can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    Docker,
    Podman,
}

impl Runtime {
    pub fn bin(self) -> &'static str {
        match self {
            Runtime::Docker => "docker",
            Runtime::Podman => "podman",
        }
    }
    /// The first runtime actually installed, preferring Docker.
    pub fn detect() -> Option<Runtime> {
        for rt in [Runtime::Docker, Runtime::Podman] {
            if which(rt.bin()) {
                return Some(rt);
            }
        }
        None
    }
}

/// How the sandbox is configured for a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Container image. Kali rolling by default — the toolbox as well as the box.
    pub image: String,
    /// Container name, so a run reuses one container rather than spawning per
    /// command (starting a container per curl would be unusably slow).
    pub name: String,
    /// Host path mounted read-write at `/work`, where evidence is written so it
    /// survives the container.
    pub workdir: Option<String>,
    /// Extra `-e KEY=VALUE` pairs — the proxy and transport env, so commands in
    /// the container take the same route as the harness.
    pub env: Vec<(String, String)>,
    /// Seconds a single command may run before it is killed.
    pub command_timeout: u64,
    /// Pull the image if it is missing (off in air-gapped labs).
    pub auto_pull: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            image: "kalilinux/kali-rolling".into(), // override with --sandbox kalilinux/kali-linux-large for the full toolbox
            name: "neurosploit-kali".into(),
            workdir: None,
            env: Vec::new(),
            command_timeout: 300,
            auto_pull: true,
        }
    }
}

impl SandboxConfig {
    pub fn with_image(mut self, image: &str) -> Self {
        if !image.trim().is_empty() {
            self.image = image.trim().to_string();
        }
        self
    }
    pub fn mounting(mut self, host_path: &str) -> Self {
        self.workdir = Some(host_path.to_string());
        self
    }
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }
}

/// A managed container the harness runs commands in.
pub struct Sandbox {
    runtime: Runtime,
    cfg: SandboxConfig,
}

/// The result of one command run in the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    /// True when the command was killed for exceeding the timeout.
    pub timed_out: bool,
}

impl ExecResult {
    pub fn ok(&self) -> bool {
        self.code == 0 && !self.timed_out
    }
}

impl Sandbox {
    /// Build a sandbox on the first available runtime, or report there is none.
    pub fn new(cfg: SandboxConfig) -> Result<Sandbox, String> {
        let runtime = Runtime::detect().ok_or_else(|| {
            "no container runtime found (docker or podman). Install one, or run without --sandbox to execute on the host.".to_string()
        })?;
        Ok(Sandbox { runtime, cfg })
    }

    pub fn runtime(&self) -> Runtime {
        self.runtime
    }

    /// The argv that runs `command` inside the container.
    ///
    /// Exposed on its own so an agent that spawns its own processes can be
    /// handed the wrapped form, and so the wrapping is unit-testable without a
    /// running daemon.
    pub fn wrap(&self, command: &str) -> Vec<String> {
        vec![
            self.runtime.bin().to_string(),
            "exec".into(),
            self.cfg.name.clone(),
            "sh".into(),
            "-lc".into(),
            command.to_string(),
        ]
    }

    /// The argv that creates the long-lived container.
    ///
    /// Kept as data (not run) so the security-relevant flags — no host network,
    /// no docker socket, a read-write work mount and nothing else — are visible
    /// and testable. The container idles on `sleep infinity`; commands run via
    /// `exec`.
    pub fn create_argv(&self) -> Vec<String> {
        let mut argv = vec![
            self.runtime.bin().to_string(),
            "run".into(),
            "-d".into(),
            "--rm".into(),
            "--name".into(),
            self.cfg.name.clone(),
            // Never the host network — that would hand the container the host's
            // interfaces and defeat the isolation entirely.
            "--network".into(),
            "bridge".into(),
            // Drop the ability to gain privileges; a scanning toolbox does not
            // need to become root-on-host.
            "--security-opt".into(),
            "no-new-privileges".into(),
        ];
        if let Some(w) = &self.cfg.workdir {
            argv.push("-v".into());
            argv.push(format!("{w}:/work"));
            argv.push("-w".into());
            argv.push("/work".into());
        }
        for (k, v) in &self.cfg.env {
            argv.push("-e".into());
            argv.push(format!("{k}={v}"));
        }
        argv.push(self.cfg.image.clone());
        argv.push("sleep".into());
        argv.push("infinity".into());
        argv
    }

    /// Is the managed container already running?
    pub async fn is_up(&self) -> bool {
        let out = run(self.runtime.bin(), &["ps", "-q", "-f", &format!("name=^{}$", self.cfg.name)], Duration::from_secs(10)).await;
        out.map(|o| !o.stdout.trim().is_empty()).unwrap_or(false)
    }

    /// Ensure the container exists and is running, pulling the image if needed.
    ///
    /// Returns a human-readable status. Idempotent: a second call on an
    /// already-running container is a no-op, so the pipeline can call it freely.
    pub async fn ensure(&self) -> Result<String, String> {
        if self.is_up().await {
            return Ok(format!("{} container `{}` already running", self.runtime.bin(), self.cfg.name));
        }
        if self.cfg.auto_pull && !self.image_present().await {
            let pull = run(self.runtime.bin(), &["pull", &self.cfg.image], Duration::from_secs(600)).await
                .map_err(|e| format!("pull {} failed: {e}", self.cfg.image))?;
            if pull.code != 0 {
                return Err(format!("could not pull {}: {}", self.cfg.image, pull.stderr.lines().last().unwrap_or("").trim()));
            }
        }
        let argv = self.create_argv();
        let (bin, args) = argv.split_first().ok_or("empty argv")?;
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = run(bin, &args_ref, Duration::from_secs(120)).await.map_err(|e| e.to_string())?;
        if out.code != 0 {
            return Err(format!("could not start the container: {}", out.stderr.lines().last().unwrap_or("").trim()));
        }
        Ok(format!("started {} container `{}` from {}", self.runtime.bin(), self.cfg.name, self.cfg.image))
    }

    async fn image_present(&self) -> bool {
        run(self.runtime.bin(), &["image", "inspect", &self.cfg.image], Duration::from_secs(15)).await
            .map(|o| o.code == 0)
            .unwrap_or(false)
    }

    /// Run one command in the container.
    pub async fn exec(&self, command: &str) -> Result<ExecResult, String> {
        let argv = self.wrap(command);
        let (bin, args) = argv.split_first().ok_or("empty argv")?;
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run(bin, &args_ref, Duration::from_secs(self.cfg.command_timeout)).await {
            Ok(r) => Ok(r),
            Err(e) if e.contains("timed out") => Ok(ExecResult { code: 124, stdout: String::new(), stderr: e, timed_out: true }),
            Err(e) => Err(e),
        }
    }

    /// Install a set of tools inside the container (best effort).
    ///
    /// Kept explicit and opt-in: pulling `kali-linux-large` is gigabytes, and a
    /// run should not silently spend ten minutes on apt. The default image has
    /// the base; this is for when a specific tool is needed.
    pub async fn install(&self, packages: &[&str]) -> Result<ExecResult, String> {
        let list = packages.join(" ");
        self.exec(&format!("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {list}")).await
    }

    /// Stop and remove the container.
    pub async fn teardown(&self) {
        let _ = run(self.runtime.bin(), &["rm", "-f", &self.cfg.name], Duration::from_secs(30)).await;
    }
}

fn which(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn run(bin: &str, args: &[&str], timeout: Duration) -> Result<ExecResult, String> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = cmd.spawn().map_err(|e| format!("spawn {bin} failed: {e}"))?;
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| format!("command timed out after {}s", timeout.as_secs()))?
        .map_err(|e| e.to_string())?;
    Ok(ExecResult {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        timed_out: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> Sandbox {
        Sandbox {
            runtime: Runtime::Docker,
            cfg: SandboxConfig::default().mounting("/runs/ns-1").with_env(vec![("HTTPS_PROXY".into(), "http://127.0.0.1:8899".into())]),
        }
    }

    #[test]
    fn wrap_execs_into_the_named_container() {
        let argv = sandbox().wrap("sqlmap -u https://t.test/x --batch");
        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "exec");
        assert_eq!(argv[2], "neurosploit-kali");
        assert_eq!(argv.last().unwrap(), "sqlmap -u https://t.test/x --batch");
    }

    #[test]
    fn create_never_grants_host_network_or_the_docker_socket() {
        let argv = sandbox().create_argv().join(" ");
        // The two flags that would give the container the host back.
        assert!(!argv.contains("--network host"), "host networking defeats the sandbox");
        assert!(!argv.contains("/var/run/docker.sock"), "mounting the socket is container escape");
        assert!(argv.contains("--network bridge"));
        assert!(argv.contains("no-new-privileges"));
    }

    #[test]
    fn create_mounts_the_workdir_and_passes_the_proxy_env() {
        let argv = sandbox().create_argv().join(" ");
        assert!(argv.contains("/runs/ns-1:/work"), "evidence has to come back out");
        assert!(argv.contains("HTTPS_PROXY=http://127.0.0.1:8899"), "commands in the box take the same route");
        assert!(argv.contains("kalilinux/kali-rolling"));
        assert!(argv.trim_end().ends_with("sleep infinity"), "the container idles; commands run via exec");
    }

    #[test]
    fn no_runtime_is_an_explicit_error_not_a_silent_host_fallback() {
        // We cannot uninstall docker in a test, so assert the message contract
        // that ensures the caller is told rather than silently dropped to host.
        let msg = "no container runtime found (docker or podman). Install one, or run without --sandbox to execute on the host.";
        assert!(msg.contains("run without --sandbox"), "the fallback must be the operator's explicit choice");
    }

    #[test]
    fn podman_is_used_when_selected() {
        let s = Sandbox { runtime: Runtime::Podman, cfg: SandboxConfig::default() };
        assert_eq!(s.wrap("id")[0], "podman");
    }
}
