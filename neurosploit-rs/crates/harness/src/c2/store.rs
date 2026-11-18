use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tokio::sync::RwLock;

use super::{C2State, STATE_VERSION};

pub(crate) struct C2Store {
    pub(crate) dir: PathBuf,
    pub(crate) state: RwLock<C2State>,
}

impl C2Store {
    pub(crate) fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(dir.join("payloads"))?;
        let path = dir.join("state.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<C2State>(&bytes) {
                Ok(mut s) => {
                    if s.version == 0 {
                        s.version = STATE_VERSION;
                    }
                    s
                }
                Err(_) => {
                    let backup = dir.join(format!("state.corrupt-{}.json", super::now_ms()));
                    let _ = std::fs::rename(&path, &backup);
                    C2State::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => C2State::default(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            state: RwLock::new(state),
        })
    }

    pub(crate) async fn snapshot(&self) -> C2State {
        self.state.read().await.clone()
    }

    async fn save_locked(&self, state: &C2State) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(state)?;
        write_private(&self.dir.join("state.json"), &bytes)
    }

    pub(crate) async fn mutate<R>(&self, f: impl FnOnce(&mut C2State) -> R) -> R {
        let mut guard = self.state.write().await;
        let out = f(&mut guard);
        if let Err(e) = self.save_locked(&guard).await {
            eprintln!("[c2] could not persist state: {e}");
        }
        out
    }

    pub(crate) fn audit(&self, action: &str, detail: Value) {
        let rec = json!({
            "ts": super::now_ms(),
            "action": action,
            "detail": detail,
        });
        let line = format!("{rec}\n");
        let _ = append_private(&self.dir.join("audit.jsonl"), line.as_bytes());
    }
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path)
}

fn append_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Scope / guardrails
// ---------------------------------------------------------------------------

pub(crate) fn host_matches_allowlist(host: &str, patterns: &[String]) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    patterns.iter().any(|p| {
        let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
        if p.is_empty() {
            return false;
        }
        if let Some(suffix) = p.strip_prefix("*.") {
            return h == suffix || h.ends_with(&format!(".{suffix}"));
        }
        if let Some(suffix) = p.strip_prefix('.') {
            return h == suffix || h.ends_with(&format!(".{suffix}"));
        }
        h == p
    })
}

pub(crate) fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub(crate) async fn host_is_internal(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return private_ip(ip);
    }
    match tokio::net::lookup_host(format!("{h}:80")).await {
        Ok(addrs) => {
            let mut any = false;
            for a in addrs {
                any = true;
                if !private_ip(a.ip()) {
                    return false;
                }
            }
            any
        }
        Err(_) => false,
    }
}

pub(crate) fn host_of_url(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return None;
    }
    u.host_str().map(|s| s.to_string())
}

pub(crate) async fn ensure_target_allowed(state: &C2State, url_or_host: &str) -> Result<String, String> {
    if !state.policy.enabled {
        return Err(
            "C2/WebShell is disabled — enable it explicitly first: neurosploit c2 enable --authorization <ref>"
                .into(),
        );
    }
    let host = if url_or_host.contains("://") {
        host_of_url(url_or_host).ok_or_else(|| "invalid URL (only http/https)".to_string())?
    } else {
        url_or_host.trim().to_string()
    };
    if host.is_empty() {
        return Err("target host is empty".into());
    }
    if host_matches_allowlist(&host, &state.policy.allowed_hosts) {
        return Ok(host);
    }
    if state.policy.allow_public_targets {
        return Ok(host);
    }
    if host_is_internal(&host).await {
        return Ok(host);
    }
    Err(format!(
        "host '{host}' is not internal and not in the C2 allow-list — add it with `neurosploit c2 enable --host {host}` (or `--allow-public` for an explicitly authorized external target)"
    ))
}

pub(crate) fn check_command(state: &C2State, command: &str) -> Result<(), String> {
    for pat in &state.policy.command_deny_regex {
        if let Ok(re) = regex::Regex::new(pat) {
            if re.is_match(command) {
                return Err(format!("command denied by OPSEC rule: {pat}"));
            }
        }
    }
    Ok(())
}
