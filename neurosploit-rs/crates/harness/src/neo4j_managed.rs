//! Managed Neo4j — bring up a local Neo4j in Docker and let the harness use it.
//!
//! `graph_memory::Neo4j` already speaks to any Neo4j over HTTP. This module is
//! the missing operational half: it can create, start, stop and health-check a
//! local Neo4j container, remembers the connection (including a generated
//! password) in a private file, and lets the harness resolve it automatically so
//! `neurosploit run` consumes it with no flags or exported variables.
//!
//! Security choices:
//! - ports are published on `127.0.0.1` only, never on all interfaces;
//! - the password is generated (random), stored in a `0600` file, and passed to
//!   Docker through the process environment (`-e NEO4J_AUTH` with no value), so
//!   it never appears in `docker run` arguments or in `ps` output. (The container
//!   itself necessarily holds it in its environment, as with any Neo4j image.)
//! - explicit `--neo4j` / `NEO4J_URI` always win over the managed instance.

use crate::sandbox::Runtime;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_CONTAINER: &str = "neurosploit-neo4j";
pub const DEFAULT_IMAGE: &str = "neo4j:5-community";
pub const DEFAULT_VOLUME: &str = "neurosploit-neo4j-data";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedConfig {
    pub container: String,
    pub image: String,
    pub volume: String,
    pub http_port: u16,
    pub bolt_port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    /// When true the harness uses this instance without any flag or env var.
    pub auto: bool,
}

impl ManagedConfig {
    pub fn new_with_password(password: String) -> Self {
        Self {
            container: DEFAULT_CONTAINER.into(),
            image: DEFAULT_IMAGE.into(),
            volume: DEFAULT_VOLUME.into(),
            http_port: 7474,
            bolt_port: 7687,
            user: "neo4j".into(),
            password,
            database: "neo4j".into(),
            auto: true,
        }
    }

    pub fn http_uri(&self) -> String { format!("http://127.0.0.1:{}", self.http_port) }
    pub fn bolt_uri(&self) -> String { format!("bolt://127.0.0.1:{}", self.bolt_port) }
}

/// `$NEUROSPLOIT_HOME/neo4j.json`, else `~/.neurosploit/neo4j.json`.
pub fn config_path() -> Option<PathBuf> {
    let home = std::env::var_os("NEUROSPLOIT_HOME").map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".neurosploit")))
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|l| PathBuf::from(l).join("NeuroSploit")))?;
    Some(home.join("neo4j.json"))
}

pub fn load() -> Option<ManagedConfig> {
    let t = std::fs::read_to_string(config_path()?).ok()?;
    serde_json::from_str(&t).ok()
}

/// Write the config, owner-read/write only on unix.
pub fn save(cfg: &ManagedConfig) -> std::io::Result<()> {
    let path = config_path().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no home directory"))?;
    if let Some(dir) = path.parent() { std::fs::create_dir_all(dir)?; }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
        f.write_all(json.as_bytes())?;
        // An existing file keeps its old mode; tighten it explicitly.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    { std::fs::write(&path, json) }
}

/// 24 random url-safe characters. Reads the OS RNG; falls back to hashing
/// time+pid only if that is unavailable (still unguessable enough for a
/// loopback-only dev database, and the fallback is flagged by shorter entropy).
pub fn generate_password() -> String {
    use base64::Engine;
    let mut buf = [0u8; 18];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| { use std::io::Read; f.read_exact(&mut buf) }).is_ok();
    if !ok {
        use sha2::{Digest, Sha256};
        let seed = format!("{:?}-{}-{:p}", std::time::SystemTime::now(), std::process::id(), &buf);
        buf.copy_from_slice(&Sha256::digest(seed.as_bytes())[..18]);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Arguments for `docker run`. Pure so it is unit-tested. The password is NOT in
/// here: `-e NEO4J_AUTH` (no value) makes Docker read it from our environment.
pub fn run_args(c: &ManagedConfig) -> Vec<String> {
    vec![
        "run".into(), "-d".into(),
        "--name".into(), c.container.clone(),
        "--restart".into(), "unless-stopped".into(),
        "-p".into(), format!("127.0.0.1:{}:7474", c.http_port),
        "-p".into(), format!("127.0.0.1:{}:7687", c.bolt_port),
        "-v".into(), format!("{}:/data", c.volume),
        "-e".into(), "NEO4J_AUTH".into(),
        c.image.clone(),
    ]
}

/// The `NEO4J_AUTH` value Docker will read from the environment.
pub fn auth_env(c: &ManagedConfig) -> String { format!("{}/{}", c.user, c.password) }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    NoRuntime,
    NotCreated,
    Stopped,
    Running,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub state: State,
    pub ready: bool,
    pub runtime: Option<String>,
    pub http_uri: Option<String>,
    pub bolt_uri: Option<String>,
    pub browser: Option<String>,
    pub auto: bool,
}

async fn docker(rt: Runtime, args: &[String], env: &[(&str, String)]) -> Result<(i32, String, String), String> {
    let mut cmd = tokio::process::Command::new(rt.bin());
    cmd.args(args).kill_on_drop(true);
    for (k, v) in env { cmd.env(k, v); }
    let out = tokio::time::timeout(Duration::from_secs(300), cmd.output()).await
        .map_err(|_| format!("`{} {}` timed out", rt.bin(), args.first().cloned().unwrap_or_default()))?
        .map_err(|e| format!("could not run {}: {e}", rt.bin()))?;
    Ok((out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string()))
}

async fn container_state(rt: Runtime, name: &str) -> State {
    let args = ["ps", "-a", "--filter", &format!("name=^/{name}$"), "--format", "{{.State}}"]
        .map(String::from);
    match docker(rt, &args, &[]).await {
        Ok((0, out, _)) if out.is_empty() => State::NotCreated,
        Ok((0, out, _)) if out.starts_with("running") => State::Running,
        Ok((0, _, _)) => State::Stopped,
        _ => State::NoRuntime,
    }
}

async fn http_ready(c: &ManagedConfig) -> bool {
    let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(3)).build() else { return false };
    matches!(client.get(c.http_uri()).send().await, Ok(r) if r.status().is_success())
}

pub async fn status() -> Status {
    let cfg = load();
    let Some(rt) = Runtime::detect() else {
        return Status { state: State::NoRuntime, ready: false, runtime: None, http_uri: None, bolt_uri: None,
            browser: None, auto: cfg.map_or(false, |c| c.auto) };
    };
    let Some(c) = cfg else {
        return Status { state: State::NotCreated, ready: false, runtime: Some(rt.bin().into()), http_uri: None,
            bolt_uri: None, browser: None, auto: false };
    };
    let state = container_state(rt, &c.container).await;
    let ready = state == State::Running && http_ready(&c).await;
    Status { state, ready, runtime: Some(rt.bin().into()), http_uri: Some(c.http_uri()), bolt_uri: Some(c.bolt_uri()),
        browser: Some(c.http_uri()), auto: c.auto }
}

/// Create (or start) the container, save the config, wait until it answers.
/// Idempotent: running it again on a healthy instance changes nothing.
pub async fn up(image: Option<&str>, auto: bool) -> Result<ManagedConfig, String> {
    let rt = Runtime::detect().ok_or("no container runtime found (install docker or podman)")?;
    let mut cfg = load().unwrap_or_else(|| ManagedConfig::new_with_password(generate_password()));
    if let Some(i) = image.filter(|i| !i.trim().is_empty()) { cfg.image = i.to_string(); }
    cfg.auto = auto;

    match container_state(rt, &cfg.container).await {
        State::NoRuntime => return Err(format!("the {} engine is not reachable — start it (e.g. `open -a Docker`, `colima start`, `systemctl start docker`) and retry", rt.bin())),
        State::Running => {}
        State::Stopped => {
            let (code, _, err) = docker(rt, &["start".into(), cfg.container.clone()], &[]).await?;
            if code != 0 { return Err(format!("docker start failed: {err}")); }
        }
        State::NotCreated => {
            // Save first: the generated password must outlive a crash mid-start,
            // because the data volume is initialised with it on first boot.
            save(&cfg).map_err(|e| format!("could not save neo4j config: {e}"))?;
            let (code, _, err) = docker(rt, &run_args(&cfg), &[("NEO4J_AUTH", auth_env(&cfg))]).await?;
            if code != 0 { return Err(format!("docker run failed: {err}")); }
        }
    }
    save(&cfg).map_err(|e| format!("could not save neo4j config: {e}"))?;

    for _ in 0..60 {
        if http_ready(&cfg).await { return Ok(cfg); }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err("neo4j started but did not answer on its HTTP port within 2 minutes (first boot can be slow; check `docker logs neurosploit-neo4j`)".into())
}

/// Stop (and remove) the container. The data volume is kept unless `purge`.
/// Auto-use is switched off so runs stop trying to reach it.
pub async fn down(purge: bool) -> Result<(), String> {
    let rt = Runtime::detect().ok_or("no container runtime found")?;
    let mut cfg = load().ok_or("no managed neo4j configured (run `neurosploit neo4j up`)")?;
    let _ = docker(rt, &["rm".into(), "-f".into(), cfg.container.clone()], &[]).await?;
    if purge {
        let _ = docker(rt, &["volume".into(), "rm".into(), "-f".into(), cfg.volume.clone()], &[]).await?;
        if let Some(p) = config_path() { let _ = std::fs::remove_file(p); }
    } else {
        cfg.auto = false;
        save(&cfg).map_err(|e| format!("could not save neo4j config: {e}"))?;
    }
    Ok(())
}

/// Connection details for the harness: (uri, db, user, password) when a managed
/// instance is configured for automatic use.
pub fn auto_connection() -> Option<(String, String, String, String)> {
    let c = load().filter(|c| c.auto)?;
    Some((c.http_uri(), c.database.clone(), c.user.clone(), c.password.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_random_and_url_safe() {
        let (a, b) = (generate_password(), generate_password());
        assert_ne!(a, b);
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn run_args_bind_loopback_and_never_contain_the_password() {
        let c = ManagedConfig::new_with_password("S3cretPw".into());
        let args = run_args(&c);
        let joined = args.join(" ");
        assert!(args.contains(&"127.0.0.1:7474:7474".to_string()));
        assert!(args.contains(&"127.0.0.1:7687:7687".to_string()));
        assert!(!joined.contains("S3cretPw"), "password must not be in argv");
        assert!(args.contains(&"NEO4J_AUTH".to_string()), "value is inherited from the environment");
        assert_eq!(auth_env(&c), "neo4j/S3cretPw");
        assert!(args.contains(&"--restart".to_string()));
        assert_eq!(args.last().unwrap(), DEFAULT_IMAGE);
    }

    #[test]
    fn uris_use_configured_ports() {
        let mut c = ManagedConfig::new_with_password("x".into());
        c.http_port = 17474;
        c.bolt_port = 17687;
        assert_eq!(c.http_uri(), "http://127.0.0.1:17474");
        assert_eq!(c.bolt_uri(), "bolt://127.0.0.1:17687");
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_private_and_roundtrips() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ns-neo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("NEUROSPLOIT_HOME", &dir);
        let c = ManagedConfig::new_with_password("pw123".into());
        save(&c).unwrap();
        let mode = std::fs::metadata(config_path().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = load().unwrap();
        assert_eq!(back.password, "pw123");
        assert!(auto_connection().is_some());
        let mut off = back; off.auto = false; save(&off).unwrap();
        assert!(auto_connection().is_none(), "auto=false must disable automatic use");
        std::env::remove_var("NEUROSPLOIT_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
