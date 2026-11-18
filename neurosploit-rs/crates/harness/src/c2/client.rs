use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::c2_dir;

#[derive(Serialize, Deserialize)]
struct ControlInfo {
    port: u16,
    token: String,
    pid: u32,
    started_at: i64,
}

fn control_path(dir: &Path) -> std::path::PathBuf {
    dir.join("control.json")
}

fn read_control(dir: &Path) -> Option<ControlInfo> {
    let bytes = std::fs::read(control_path(dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn ping(port: u16) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(700))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    matches!(
        client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await,
        Ok(r) if r.status().is_success()
    )
}

/// Ensure the control daemon is running, starting it detached if needed.
pub async fn ensure_daemon() -> Result<(u16, String), String> {
    let dir = c2_dir();
    if let Some(info) = read_control(&dir) {
        if ping(info.port).await {
            return Ok((info.port, info.token));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let lock = dir.join("daemon.lock");
    let mut waited = 0;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Some(info) = read_control(&dir) {
                    if ping(info.port).await {
                        let _ = std::fs::remove_file(&lock);
                        return Ok((info.port, info.token));
                    }
                }
                waited += 1;
                if waited > 40 {
                    let _ = std::fs::remove_file(&lock);
                    waited = 0;
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(e) => return Err(format!("cannot lock daemon startup: {e}")),
        }
    }
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("c2")
        .arg("daemon")
        .arg("--port")
        .arg("0")
        .arg("--dir")
        .arg(&dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.spawn().map_err(|e| format!("start C2 daemon: {e}"))?;
    for _ in 0..80 {
        if let Some(info) = read_control(&dir) {
            if ping(info.port).await {
                let _ = std::fs::remove_file(&lock);
                return Ok((info.port, info.token));
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let _ = std::fs::remove_file(&lock);
    Err("C2 daemon did not start in time".into())
}

/// Authenticated call against the local control API.
pub async fn control_request(
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let (port, token) = ensure_daemon().await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("http://127.0.0.1:{port}{path}");
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    }
    .header("X-Control-Token", &token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("control daemon: {e}"))?;
    let status = resp.status();
    let v: Value = resp
        .json()
        .await
        .map_err(|e| format!("control daemon response: {e}"))?;
    if !status.is_success() {
        let msg = v
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("request failed");
        return Err(msg.to_string());
    }
    Ok(v)
}
