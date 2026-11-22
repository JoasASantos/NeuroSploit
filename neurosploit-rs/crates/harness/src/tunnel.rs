//! Public tunnels for callbacks and shells — ngrok, with a local HTTP sink.
//!
//! An out-of-band listener that only exists on `127.0.0.1` proves nothing:
//! the target cannot reach it. A tunnel gives that listener a public URL
//! without opening a port on the operator's router. ngrok is the smallest
//! option: the operator supplies an authtoken once (`NGROK_AUTHTOKEN`), and
//! this module starts `ngrok http <port>`, discovers the assigned URL from
//! ngrok's local API, and serves a tiny request sink on that port so blind
//! callbacks are recorded instead of merely accepted.
//!
//! The sink is intentionally dumb. It writes one JSON line per request
//! (`peer`, method, path, headers, bounded body excerpt) and answers `ok`.
//! That is enough to prove SSRF/XXE/blind-RCE egress and to receive a
//! webshell's check-in without embedding any target-specific logic here.
//!
//! Secrets: the authtoken is passed to the child through the environment, not
//! argv, and is never logged. The tunnel is opt-in; without `NGROK_AUTHTOKEN`
//! (or `--authtoken`) nothing starts.

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug)]
pub struct TunnelConfig {
    /// Local port the sink listens on and ngrok forwards to.
    pub port: u16,
    /// Bind address for the sink (default 127.0.0.1).
    pub bind: String,
    pub authtoken: Option<String>,
    pub region: Option<String>,
    /// Reserved/custom domain, when the ngrok plan provides one.
    pub domain: Option<String>,
    /// Run the local HTTP sink. Off only when the caller already serves it.
    pub serve: bool,
}

impl TunnelConfig {
    pub fn from_env(port: Option<u16>) -> Self {
        let port = port
            .or_else(|| std::env::var("NEUROSPLOIT_TUNNEL_PORT").ok().and_then(|v| v.trim().parse().ok()))
            .unwrap_or(8080);
        Self {
            port,
            bind: std::env::var("NEUROSPLOIT_TUNNEL_BIND").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "127.0.0.1".into()),
            authtoken: env_first(&["NGROK_AUTHTOKEN", "NGROK_AUTH_TOKEN", "NEUROSPLOIT_NGROK_AUTHTOKEN"]),
            region: std::env::var("NGROK_REGION").ok().filter(|s| !s.trim().is_empty()),
            domain: std::env::var("NGROK_DOMAIN").ok().filter(|s| !s.trim().is_empty()),
            serve: true,
        }
    }
}

fn env_first(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| std::env::var(k).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

/// The ngrok binary, if installed. A missing binary is a clear, actionable
/// error — never a silent "tunnel unavailable".
pub fn ngrok_bin() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join("ngrok");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub struct Tunnel {
    pub public_url: String,
    pub local_port: u16,
    child: tokio::process::Child,
}

impl Tunnel {
    pub fn stop(mut self) {
        let _ = self.child.start_kill();
    }
}

/// Start ngrok and wait for the public URL (up to ~20s).
pub async fn start(config: &TunnelConfig) -> anyhow::Result<Tunnel> {
    let bin = ngrok_bin().ok_or_else(|| anyhow::anyhow!(
        "ngrok is not installed or not on PATH — install it (https://ngrok.com/download) and set NGROK_AUTHTOKEN"
    ))?;
    let token = config.authtoken.clone().ok_or_else(|| anyhow::anyhow!(
        "no ngrok authtoken — set NGROK_AUTHTOKEN (or pass --authtoken)"
    ))?;

    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("http")
        .arg(config.port.to_string())
        .arg("--log=stdout")
        .arg("--log-format=json")
        .env("NGROK_AUTHTOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(r) = &config.region {
        cmd.arg("--region").arg(r);
    }
    if let Some(d) = &config.domain {
        cmd.arg("--domain").arg(d);
    }
    let child = cmd.spawn().map_err(|e| anyhow::anyhow!("could not start ngrok: {e}"))?;

    // ngrok exposes the assigned URL on its local API. Poll it rather than
    // scraping stdout, which changes between versions.
    let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build()?;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(resp) = client.get("http://127.0.0.1:4040/api/tunnels").send().await {
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                if let Some(url) = pick_public_url(&v) {
                    return Ok(Tunnel { public_url: url, local_port: config.port, child });
                }
            }
        }
    }
    let mut t = Tunnel { public_url: String::new(), local_port: config.port, child };
    t.stop();
    anyhow::bail!("ngrok started but no public URL appeared on 127.0.0.1:4040 — check the authtoken and `ngrok diagnose`")
}

fn pick_public_url(v: &serde_json::Value) -> Option<String> {
    let tunnels = v.get("tunnels")?.as_array()?;
    tunnels
        .iter()
        .filter_map(|t| t.get("public_url").and_then(|u| u.as_str()))
        .find(|u| u.starts_with("https://"))
        .or_else(|| tunnels.iter().find_map(|t| t.get("public_url").and_then(|u| u.as_str())))
        .map(String::from)
}

/// Bind the sink, walking forward from the preferred port when it is taken.
///
/// A busy 8080 is normal (another OOB listener, a dev server, a previous
/// tunnel). Failing the whole command for it was needless: try the next 100
/// ports and report the one that was actually used. `preferred == 0` asks the
/// OS to assign one.
pub async fn bind_sink(bind: &str, preferred: u16) -> anyhow::Result<(tokio::net::TcpListener, u16)> {
    let mut last = None;
    for offset in 0..100u16 {
        let port = if preferred == 0 { 0 } else { preferred.saturating_add(offset) };
        match tokio::net::TcpListener::bind((bind, port)).await {
            Ok(l) => {
                let actual = l.local_addr().map(|a| a.port()).unwrap_or(port);
                return Ok((l, actual));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    last = Some(e);
                    continue;
                }
                return Err(anyhow::anyhow!("cannot bind {bind}:{port} — {e}"));
            }
        }
    }
    Err(anyhow::anyhow!(
        "no free port in {bind}:{preferred}..{} — {}",
        preferred.saturating_add(99),
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Serve the callback sink on an already-bound listener. One JSON line per
/// request, `ok` response; runs forever.
pub async fn serve_on(listener: tokio::net::TcpListener, log_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(log_dir)?;
    let log = log_dir.join("callbacks.jsonl");
    loop {
        let Ok((mut sock, peer)) = listener.accept().await else { continue };
        let path = log.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let n = match sock.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => 0,
            };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut lines = req.lines();
            let first = lines.next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");
            let headers: Vec<&str> = lines.take_while(|l| !l.trim().is_empty()).collect();
            let excerpt = crate::limits::clip(&req, 8 * 1024);
            let rec = json!({
                "at": now_ms(),
                "peer": peer.to_string(),
                "method": method,
                "target": target,
                "headers": headers,
                "excerpt": excerpt,
            });
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = writeln!(f, "{}", rec);
            }
            let body = b"ok";
            let _ = sock.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            ).as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        });
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Start the sink and the tunnel, print the public URL, and run until Ctrl-C.
pub async fn run(mut config: TunnelConfig) -> anyhow::Result<()> {
    if config.serve {
        let (listener, actual) = bind_sink(&config.bind, config.port).await?;
        if actual != config.port {
            println!("  \x1b[33mport {} was busy — using {}\x1b[0m", config.port, actual);
        }
        config.port = actual;
        let dir = std::env::temp_dir().join("neurosploit-tunnel");
        tokio::spawn(async move {
            if let Err(e) = serve_on(listener, &dir).await {
                eprintln!("  \x1b[31mtunnel sink: {e}\x1b[0m");
            }
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let tunnel = start(&config).await?;
    println!("  \x1b[32mngrok tunnel\x1b[0m → {}", tunnel.public_url);
    println!("  local sink        → http://{}:{}", config.bind, config.port);
    println!("  callbacks log     → {}", std::env::temp_dir().join("neurosploit-tunnel").join("callbacks.jsonl").display());
    println!("  use the public URL as --oob-domain. Ctrl-C stops the tunnel.");
    tokio::signal::ctrl_c().await.ok();
    tunnel.stop();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_https_tunnel_first() {
        let v = json!({ "tunnels": [
            { "public_url": "http://a.ngrok.io" },
            { "public_url": "https://b.ngrok.io" }
        ]});
        assert_eq!(pick_public_url(&v).as_deref(), Some("https://b.ngrok.io"));
    }

    #[test]
    fn missing_tunnels_is_none() {
        assert!(pick_public_url(&json!({})).is_none());
    }
}
