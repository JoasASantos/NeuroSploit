//! `neurosploit c2 …` and `neurosploit webshell …` command surface.
//!
//! Every verb is a thin client of the local C2 control daemon, which owns
//! listeners, sessions, tasks and WebShell connections. That keeps the CLI,
//! the MCP tools, the REPL and the web console on one implementation and one
//! audit trail. The daemon is auto-started on first use (loopback only).

use clap::Subcommand;
use serde_json::{json, Value};
use std::path::PathBuf;


// ---------------------------------------------------------------------------
// C2
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum C2Cmd {
    /// Run the local control daemon in the foreground (auto-started on demand).
    Daemon {
        /// Control port (0 = ephemeral).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// State directory (default: .neurosploit/c2).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show policy, listeners, sessions, tasks, webshells and recent events.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Enable C2 for this engagement. Requires an authorization reference.
    Enable {
        /// SOW / ticket / bug-bounty URL authorizing this work.
        #[arg(long)]
        authorization: String,
        /// Allow persistence tasks on implants.
        #[arg(long)]
        persistence: bool,
        /// Allow lateral-movement and upload tasks.
        #[arg(long)]
        lateral: bool,
        /// Allow targets outside private address space (explicit opt-in).
        #[arg(long)]
        allow_public: bool,
        /// Extra authorized host/domain (repeatable).
        #[arg(long = "host")]
        hosts: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Disable C2 and stop every listener.
    Disable {
        #[arg(long)]
        json: bool,
    },
    /// Update the stored policy without re-enabling.
    Policy {
        #[arg(long)]
        authorized_by: Option<String>,
        #[arg(long)]
        persistence: Option<bool>,
        #[arg(long)]
        lateral: Option<bool>,
        #[arg(long)]
        allow_public: Option<bool>,
        #[arg(long = "host")]
        hosts: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Listener management.
    Listener {
        #[command(subcommand)]
        cmd: ListenerCmd,
    },
    /// Session management.
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },
    /// Task management.
    Task {
        #[command(subcommand)]
        cmd: TaskCmd,
    },
    /// Payload generation.
    Payload {
        #[command(subcommand)]
        cmd: PayloadCmd,
    },
    /// Recent audit events from the C2 module.
    Events {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum ListenerCmd {
    /// List listeners.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Create an HTTP beacon listener (not started yet).
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "127.0.0.1")]
        bind_host: String,
        #[arg(long, default_value_t = 8443)]
        bind_port: u16,
        /// Host the implant should call back to (defaults to bind_host).
        #[arg(long)]
        callback_host: Option<String>,
        #[arg(long, default_value_t = 5)]
        sleep: u32,
        #[arg(long, default_value_t = 0)]
        jitter: u32,
        #[arg(long)]
        json: bool,
    },
    /// Start a listener.
    Start {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Stop a listener.
    Stop {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Delete a listener and its sessions/tasks.
    Delete {
        id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum SessionCmd {
    /// List sessions.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one session.
    Get {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Change the beacon sleep/jitter for a session.
    Sleep {
        id: String,
        #[arg(long, default_value_t = 5)]
        seconds: u32,
        #[arg(long, default_value_t = 0)]
        jitter: u32,
        #[arg(long)]
        json: bool,
    },
    /// Attach an operator note.
    Note {
        id: String,
        #[arg(long)]
        note: String,
        #[arg(long)]
        json: bool,
    },
    /// Mark a session killed and cancel its queued tasks.
    Kill {
        id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum TaskCmd {
    /// List tasks (optionally by session/status).
    List {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Execute a shell command on a session.
    Exec {
        #[arg(long)]
        session: String,
        #[arg(long)]
        command: String,
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Install the generated persistence command (requires persistence policy).
    Persist {
        #[arg(long)]
        session: String,
        /// auto · cron · bashrc · systemd · schtasks · registry
        #[arg(long, default_value = "auto")]
        method: String,
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Run a lateral-movement command (requires lateral policy).
    Lateral {
        #[arg(long)]
        session: String,
        #[arg(long)]
        command: String,
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Enqueue an arbitrary task type with a JSON payload.
    Enqueue {
        #[arg(long)]
        session: String,
        #[arg(long = "type")]
        task_type: String,
        /// JSON object payload, e.g. '{"path":"/etc"}'.
        #[arg(long, default_value = "{}")]
        payload: String,
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Show a task and its output.
    Get {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Wait for a task to complete.
    Wait {
        id: String,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Cancel a queued task.
    Cancel {
        id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum PayloadCmd {
    /// Generate a WebShell file (php, aspx, asp, jsp).
    Webshell {
        #[arg(long, default_value = "php")]
        shell_type: String,
        #[arg(long, default_value = "ns_pass")]
        password: String,
        #[arg(long, default_value = "pass")]
        pass_param: String,
        #[arg(long, default_value = "cmd")]
        cmd_param: String,
        #[arg(long)]
        filename: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Generate a C2 beacon (bash, python, powershell, php).
    Beacon {
        #[arg(long)]
        listener: String,
        #[arg(long, default_value = "bash")]
        kind: String,
        /// Override the callback host embedded in the payload.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        filename: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Generate a one-shot check-in command.
    Oneliner {
        #[arg(long)]
        listener: String,
        #[arg(long)]
        json: bool,
    },
    /// List generated payloads.
    List {
        #[arg(long)]
        json: bool,
    },
}

// ---------------------------------------------------------------------------
// WebShell
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum WebshellCmd {
    /// List saved WebShell connections.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Save a WebShell connection.
    Add {
        #[arg(long)]
        url: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "")]
        password: String,
        #[arg(long, default_value = "php")]
        shell_type: String,
        #[arg(long, default_value = "POST")]
        method: String,
        #[arg(long, default_value = "cmd")]
        cmd_param: String,
        #[arg(long, default_value = "pass")]
        pass_param: String,
        /// auto · linux · windows
        #[arg(long, default_value = "auto")]
        os: String,
        #[arg(long, default_value = "auto")]
        encoding: String,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long)]
        json: bool,
    },
    /// Update a saved connection (only the supplied fields change).
    Update {
        id: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        shell_type: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        cmd_param: Option<String>,
        #[arg(long)]
        pass_param: Option<String>,
        #[arg(long)]
        os: Option<String>,
        #[arg(long)]
        encoding: Option<String>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Delete a saved connection.
    Delete {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Probe a connection, detect the target OS and whoami.
    Test {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Execute a command through a saved WebShell.
    Exec {
        #[arg(long)]
        id: String,
        #[arg(long)]
        command: String,
        #[arg(long)]
        json: bool,
    },
    /// File operation through a saved WebShell.
    File {
        #[arg(long)]
        id: String,
        /// list · read · write · upload · delete · mkdir · rename
        #[arg(long)]
        action: String,
        #[arg(long, default_value = ".")]
        path: String,
        #[arg(long, default_value = "")]
        content: String,
        #[arg(long)]
        target_path: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn handle_c2(cmd: C2Cmd) -> anyhow::Result<()> {
    match cmd {
        C2Cmd::Daemon { port, dir } => {
            let dir = dir.unwrap_or_else(harness::c2::c2_dir);
            harness::c2::run_daemon(dir, port).await?;
        }
        C2Cmd::Status { json } => {
            let v = req("GET", "/api/status", None).await?;
            if json {
                print_json(&v);
            } else {
                print_status(&v);
            }
        }
        C2Cmd::Enable {
            authorization,
            persistence,
            lateral,
            allow_public,
            hosts,
            json,
        } => {
            let body = json!({
                "authorization": authorization,
                "persistence": persistence,
                "lateral": lateral,
                "allow_public": allow_public,
                "hosts": hosts,
            });
            let v = req("POST", "/api/enable", Some(body)).await?;
            if json {
                print_json(&v);
            } else {
                print_policy(v.get("policy"));
            }
        }
        C2Cmd::Disable { json } => {
            let v = req("POST", "/api/disable", None).await?;
            if json {
                print_json(&v);
            } else {
                println!("C2 disabled; listeners stopped.");
            }
        }
        C2Cmd::Policy {
            authorized_by,
            persistence,
            lateral,
            allow_public,
            hosts,
            json,
        } => {
            let mut body = json!({});
            if let Some(v) = authorized_by {
                body["authorized_by"] = json!(v);
            }
            if let Some(v) = persistence {
                body["allow_persistence"] = json!(v);
            }
            if let Some(v) = lateral {
                body["allow_lateral"] = json!(v);
            }
            if let Some(v) = allow_public {
                body["allow_public_targets"] = json!(v);
            }
            if !hosts.is_empty() {
                body["allowed_hosts"] = json!(hosts);
            }
            let v = req("POST", "/api/policy", Some(body)).await?;
            if json {
                print_json(&v);
            } else {
                print_policy(v.get("policy"));
            }
        }
        C2Cmd::Listener { cmd } => handle_listener(cmd).await?,
        C2Cmd::Session { cmd } => handle_session(cmd).await?,
        C2Cmd::Task { cmd } => handle_task(cmd).await?,
        C2Cmd::Payload { cmd } => handle_payload(cmd).await?,
        C2Cmd::Events { limit, json } => {
            let v = req("GET", &format!("/api/events?limit={limit}"), None).await?;
            if json {
                print_json(&v);
            } else if let Some(events) = v.get("events").and_then(|e| e.as_array()) {
                for e in events {
                    println!(
                        "{} [{}] {} — {}",
                        e.get("ts").and_then(|v| v.as_i64()).unwrap_or(0),
                        e.get("level").and_then(|v| v.as_str()).unwrap_or("info"),
                        e.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                        e.get("message").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
    }
    Ok(())
}

async fn handle_listener(cmd: ListenerCmd) -> anyhow::Result<()> {
    match cmd {
        ListenerCmd::List { json } => {
            let v = req("GET", "/api/listeners", None).await?;
            if json {
                print_json(&v);
            } else if let Some(items) = v.get("listeners").and_then(|x| x.as_array()) {
                for l in items {
                    println!(
                        "{:<22} {:<16} {:<28} {}",
                        l.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        l.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        format!(
                            "{}:{}",
                            l.get("bind_host").and_then(|v| v.as_str()).unwrap_or(""),
                            l.get("bind_port").and_then(|v| v.as_u64()).unwrap_or(0)
                        ),
                        l.get("name").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        ListenerCmd::Create {
            name,
            bind_host,
            bind_port,
            callback_host,
            sleep,
            jitter,
            json,
        } => {
            let body = json!({
                "name": name,
                "bind_host": bind_host,
                "bind_port": bind_port,
                "callback_host": callback_host.unwrap_or_default(),
                "sleep_seconds": sleep,
                "jitter_percent": jitter,
            });
            let v = req("POST", "/api/listeners", Some(body)).await?;
            if json {
                print_json(&v);
            } else {
                print_listener(v.get("listener"));
            }
        }
        ListenerCmd::Start { id, json } => {
            let v = req("POST", &format!("/api/listeners/{id}/start"), None).await?;
            if json { print_json(&v) } else { print_listener(v.get("listener")); }
        }
        ListenerCmd::Stop { id, json } => {
            let v = req("POST", &format!("/api/listeners/{id}/stop"), None).await?;
            if json { print_json(&v) } else { println!("Listener {id} stopped."); }
        }
        ListenerCmd::Delete { id, json } => {
            let v = req("DELETE", &format!("/api/listeners/{id}"), None).await?;
            if json { print_json(&v) } else { println!("Listener {id} deleted."); }
        }
    }
    Ok(())
}

async fn handle_session(cmd: SessionCmd) -> anyhow::Result<()> {
    match cmd {
        SessionCmd::List { json } => {
            let v = req("GET", "/api/sessions", None).await?;
            if json {
                print_json(&v);
            } else if let Some(items) = v.get("sessions").and_then(|x| x.as_array()) {
                for s in items {
                    println!(
                        "{:<22} {:<8} {:<28} {}@{} ip={} note={}",
                        s.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        s.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        format!(
                            "{} {}",
                            s.get("hostname").and_then(|v| v.as_str()).unwrap_or("?"),
                            s.get("os").and_then(|v| v.as_str()).unwrap_or("")
                        ),
                        s.get("username").and_then(|v| v.as_str()).unwrap_or("?"),
                        s.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("?"),
                        s.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("?"),
                        s.get("note").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        SessionCmd::Get { id, json } => {
            let v = req("GET", &format!("/api/sessions/{id}"), None).await?;
            if json {
                print_json(&v);
            } else if let Some(s) = v.get("session") {
                println!(
                    "{}  {}@{} ({}/{}) ip={} status={} sleep={}s note={}",
                    s.get("id").and_then(|x| x.as_str()).unwrap_or(""),
                    s.get("username").and_then(|x| x.as_str()).unwrap_or("?"),
                    s.get("hostname").and_then(|x| x.as_str()).unwrap_or("?"),
                    s.get("os").and_then(|x| x.as_str()).unwrap_or("?"),
                    s.get("arch").and_then(|x| x.as_str()).unwrap_or("?"),
                    s.get("internal_ip").and_then(|x| x.as_str()).unwrap_or("?"),
                    s.get("status").and_then(|x| x.as_str()).unwrap_or("?"),
                    s.get("sleep_seconds").and_then(|x| x.as_u64()).unwrap_or(0),
                    s.get("note").and_then(|x| x.as_str()).unwrap_or(""),
                );
            }
        }
        SessionCmd::Sleep {
            id,
            seconds,
            jitter,
            json,
        } => {
            let v = req(
                "POST",
                &format!("/api/sessions/{id}/sleep"),
                Some(json!({"seconds": seconds, "jitter": jitter})),
            )
            .await?;
            if json { print_json(&v) } else { print_task(v.get("task")); }
        }
        SessionCmd::Note { id, note, json } => {
            let v = req(
                "POST",
                &format!("/api/sessions/{id}/note"),
                Some(json!({"note": note})),
            )
            .await?;
            if json { print_json(&v) } else { println!("Session note updated."); }
        }
        SessionCmd::Kill { id, json } => {
            let v = req("DELETE", &format!("/api/sessions/{id}"), None).await?;
            if json { print_json(&v) } else { println!("Session {id} killed."); }
        }
    }
    Ok(())
}

async fn handle_task(cmd: TaskCmd) -> anyhow::Result<()> {
    match cmd {
        TaskCmd::List {
            session,
            status,
            json,
        } => {
            let mut path = String::from("/api/tasks");
            let mut q = Vec::new();
            if let Some(s) = session {
                q.push(format!("session_id={}", urlencode(&s)));
            }
            if let Some(s) = status {
                q.push(format!("status={}", urlencode(&s)));
            }
            if !q.is_empty() {
                path.push('?');
                path.push_str(&q.join("&"));
            }
            let v = req("GET", &path, None).await?;
            if json {
                print_json(&v);
            } else if let Some(items) = v.get("tasks").and_then(|x| x.as_array()) {
                for t in items {
                    println!(
                        "{:<22} {:<10} {:<10} {} → {}",
                        t.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        t.get("task_type").and_then(|v| v.as_str()).unwrap_or(""),
                        t.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        t.get("session_id").and_then(|v| v.as_str()).unwrap_or(""),
                        t.get("error").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        TaskCmd::Exec {
            session,
            command,
            wait,
            timeout,
            json,
        } => enqueue_task(&session, "exec", json!({"command": command}), wait, timeout, json).await?,
        TaskCmd::Persist {
            session,
            method,
            wait,
            timeout,
            json,
        } => enqueue_task(&session, "persist", json!({"method": method}), wait, timeout, json).await?,
        TaskCmd::Lateral {
            session,
            command,
            wait,
            timeout,
            json,
        } => enqueue_task(&session, "lateral", json!({"command": command}), wait, timeout, json).await?,
        TaskCmd::Enqueue {
            session,
            task_type,
            payload,
            wait,
            timeout,
            json,
        } => {
            let payload: Value = serde_json::from_str(&payload)
                .map_err(|e| anyhow::anyhow!("--payload must be a JSON object: {e}"))?;
            enqueue_task(&session, &task_type, payload, wait, timeout, json).await?;
        }
        TaskCmd::Get { id, json } => {
            let v = req("GET", &format!("/api/tasks/{id}"), None).await?;
            if json { print_json(&v) } else { print_task(v.get("task")); }
        }
        TaskCmd::Wait { id, timeout, json } => {
            let v = req("GET", &format!("/api/tasks/{id}/wait?timeout={timeout}"), None).await?;
            if json { print_json(&v) } else { print_task(v.get("task")); }
        }
        TaskCmd::Cancel { id, json } => {
            let v = req("POST", &format!("/api/tasks/{id}/cancel"), None).await?;
            if json { print_json(&v) } else { println!("Task {id} cancelled."); }
        }
    }
    Ok(())
}

async fn enqueue_task(
    session: &str,
    task_type: &str,
    payload: Value,
    wait: bool,
    timeout: u64,
    json: bool,
) -> anyhow::Result<()> {
    let v = req(
        "POST",
        "/api/tasks",
        Some(json!({"session_id": session, "task_type": task_type, "payload": payload, "source": "ai"})),
    )
    .await?;
    let id = v
        .pointer("/task/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return Err(anyhow::anyhow!("daemon did not return a task id"));
    }
    if wait {
        let done = req("GET", &format!("/api/tasks/{id}/wait?timeout={timeout}"), None).await?;
        if json { print_json(&done) } else { print_task(done.get("task")); }
    } else if json {
        print_json(&v);
    } else {
        println!("task {id} queued — follow with `neurosploit c2 task wait {id}`");
    }
    Ok(())
}

async fn handle_payload(cmd: PayloadCmd) -> anyhow::Result<()> {
    match cmd {
        PayloadCmd::Webshell {
            shell_type,
            password,
            pass_param,
            cmd_param,
            filename,
            json,
        } => {
            let v = req(
                "POST",
                "/api/payloads/webshell",
                Some(json!({"shell_type": shell_type, "password": password, "pass_param": pass_param, "cmd_param": cmd_param, "filename": filename})),
            )
            .await?;
            if json { print_json(&v) } else { print_payload(&v); }
        }
        PayloadCmd::Beacon {
            listener,
            kind,
            host,
            filename,
            json,
        } => {
            let v = req(
                "POST",
                "/api/payloads/beacon",
                Some(json!({"listener_id": listener, "kind": kind, "host": host, "filename": filename})),
            )
            .await?;
            if json { print_json(&v) } else { print_payload(&v); }
        }
        PayloadCmd::Oneliner { listener, json } => {
            let v = req(
                "POST",
                "/api/payloads/oneliner",
                Some(json!({"listener_id": listener})),
            )
            .await?;
            if json { print_json(&v) } else { print_payload(&v); }
        }
        PayloadCmd::List { json } => {
            let v = req("GET", "/api/payloads", None).await?;
            if json {
                print_json(&v);
            } else if let Some(items) = v.get("payloads").and_then(|x| x.as_array()) {
                for p in items {
                    println!(
                        "{}  {:<10} {:>8} bytes  {}",
                        p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        p.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                        p.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                        p.get("note").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn handle_webshell(cmd: WebshellCmd) -> anyhow::Result<()> {
    match cmd {
        WebshellCmd::List { json } => {
            let v = req("GET", "/api/webshells", None).await?;
            if json {
                print_json(&v);
            } else if let Some(items) = v.get("webshells").and_then(|x| x.as_array()) {
                for w in items {
                    println!(
                        "{}  {:<28} {:<8} {:<8} {}",
                        w.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        w.get("url").and_then(|v| v.as_str()).unwrap_or(""),
                        w.get("shell_type").and_then(|v| v.as_str()).unwrap_or(""),
                        w.get("method").and_then(|v| v.as_str()).unwrap_or(""),
                        w.get("name").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        WebshellCmd::Add {
            url,
            name,
            password,
            shell_type,
            method,
            cmd_param,
            pass_param,
            os,
            encoding,
            note,
            json,
        } => {
            let v = req(
                "POST",
                "/api/webshells",
                Some(json!({
                    "url": url, "name": name.unwrap_or_default(), "password": password,
                    "shell_type": shell_type, "method": method, "cmd_param": cmd_param,
                    "pass_param": pass_param, "os": os, "encoding": encoding, "note": note,
                })),
            )
            .await?;
            if json { print_json(&v) } else { print_webshell(v.get("webshell")); }
        }
        WebshellCmd::Update {
            id,
            url,
            name,
            password,
            shell_type,
            method,
            cmd_param,
            pass_param,
            os,
            encoding,
            note,
            json,
        } => {
            let mut body = json!({});
            let mut set = |k: &str, val: Option<String>| {
                if let Some(v) = val {
                    body[k] = json!(v);
                }
            };
            set("url", url);
            set("name", name);
            set("password", password);
            set("shell_type", shell_type);
            set("method", method);
            set("cmd_param", cmd_param);
            set("pass_param", pass_param);
            set("os", os);
            set("encoding", encoding);
            set("note", note);
            let v = req("PUT", &format!("/api/webshells/{id}"), Some(body)).await?;
            if json { print_json(&v) } else { print_webshell(v.get("webshell")); }
        }
        WebshellCmd::Delete { id, json } => {
            let v = req("DELETE", &format!("/api/webshells/{id}"), None).await?;
            if json { print_json(&v) } else { println!("WebShell {id} deleted."); }
        }
        WebshellCmd::Test { id, json } => {
            let v = req("POST", &format!("/api/webshells/{id}/test"), None).await?;
            if json {
                print_json(&v);
            } else {
                println!(
                    "ok={} http={} os={}\n{}",
                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                    v.get("http_status").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("detected_os").and_then(|x| x.as_str()).unwrap_or("?"),
                    v.get("output").and_then(|x| x.as_str()).unwrap_or("")
                );
            }
        }
        WebshellCmd::Exec { id, command, json } => {
            let v = req(
                "POST",
                &format!("/api/webshells/{id}/exec"),
                Some(json!({"command": command})),
            )
            .await?;
            if json {
                print_json(&v);
            } else {
                println!(
                    "http={} ok={}\n{}",
                    v.get("http_status").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                    v.get("output").and_then(|x| x.as_str()).unwrap_or("")
                );
            }
        }
        WebshellCmd::File {
            id,
            action,
            path,
            content,
            target_path,
            json,
        } => {
            let v = req(
                "POST",
                &format!("/api/webshells/{id}/file"),
                Some(json!({"action": action, "path": path, "content": content, "target_path": target_path})),
            )
            .await?;
            if json {
                print_json(&v);
            } else {
                println!(
                    "http={} ok={}\n{}",
                    v.get("http_status").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                    v.get("output").and_then(|x| x.as_str()).unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

async fn req(method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
    harness::c2::control_request(method, path, body)
        .await
        .map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into())
    );
}

fn print_policy(p: Option<&Value>) {
    let Some(p) = p else {
        println!("(no policy)");
        return;
    };
    println!(
        "enabled={} authorization={:?} persistence={} lateral={} allow_public={} hosts={:?}",
        p.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        p.get("authorized_by").and_then(|v| v.as_str()).unwrap_or(""),
        p.get("allow_persistence").and_then(|v| v.as_bool()).unwrap_or(false),
        p.get("allow_lateral").and_then(|v| v.as_bool()).unwrap_or(false),
        p.get("allow_public_targets").and_then(|v| v.as_bool()).unwrap_or(false),
        p.get("allowed_hosts").cloned().unwrap_or(json!([])),
    );
}

fn print_listener(l: Option<&Value>) {
    let Some(l) = l else {
        println!("(no listener)");
        return;
    };
    println!(
        "{}  {}:{}  status={}  callback={}  sleep={}s",
        l.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        l.get("bind_host").and_then(|v| v.as_str()).unwrap_or(""),
        l.get("bind_port").and_then(|v| v.as_u64()).unwrap_or(0),
        l.get("status").and_then(|v| v.as_str()).unwrap_or(""),
        l.get("callback_host").and_then(|v| v.as_str()).unwrap_or(""),
        l.get("sleep_seconds").and_then(|v| v.as_u64()).unwrap_or(0),
    );
}

fn print_task(t: Option<&Value>) {
    let Some(t) = t else {
        println!("(no task)");
        return;
    };
    println!(
        "{}  {}  status={}",
        t.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        t.get("task_type").and_then(|v| v.as_str()).unwrap_or(""),
        t.get("status").and_then(|v| v.as_str()).unwrap_or("")
    );
    if let Some(out) = t.get("output").and_then(|v| v.as_str()) {
        if !out.is_empty() {
            println!("--- output ---\n{out}");
        }
    }
    if let Some(err) = t.get("error").and_then(|v| v.as_str()) {
        if !err.is_empty() {
            println!("--- error ---\n{err}");
        }
    }
}

fn print_payload(v: &Value) {
    if let Some(content) = v.get("content").and_then(|x| x.as_str()) {
        println!(
            "{} ({}) → {}",
            v.get("name").and_then(|x| x.as_str()).unwrap_or("payload"),
            v.get("kind").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("path").and_then(|x| x.as_str()).unwrap_or("")
        );
        println!("--- content ---\n{content}");
    } else if let Some(one) = v.get("oneliner").and_then(|x| x.as_str()) {
        println!("{one}");
    } else {
        print_json(v);
    }
}

fn print_webshell(w: Option<&Value>) {
    let Some(w) = w else {
        println!("(no webshell)");
        return;
    };
    println!(
        "{}  {}  {}  {}  password_set={}",
        w.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        w.get("url").and_then(|v| v.as_str()).unwrap_or(""),
        w.get("shell_type").and_then(|v| v.as_str()).unwrap_or(""),
        w.get("method").and_then(|v| v.as_str()).unwrap_or(""),
        w.get("password_set").and_then(|v| v.as_bool()).unwrap_or(false)
    );
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn print_status(v: &Value) {
    print_policy(v.get("policy"));
    if let Some(items) = v.get("listeners").and_then(|x| x.as_array()) {
        println!("\nlisteners ({}):", items.len());
        for l in items {
            print_listener(Some(l));
        }
    }
    if let Some(items) = v.get("sessions").and_then(|x| x.as_array()) {
        println!("\nsessions ({}):", items.len());
        for s in items {
            println!(
                "{}  {:<8} {}@{} ({}/{}) ip={} sup={}",
                s.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                s.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                s.get("username").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("hostname").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("os").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("arch").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false),
            );
        }
    }
    if let Some(items) = v.get("webshells").and_then(|x| x.as_array()) {
        println!("\nwebshells ({}):", items.len());
        for w in items {
            print_webshell(Some(w));
        }
    }
    if let Some(items) = v.get("tasks").and_then(|x| x.as_array()) {
        let open = items
            .iter()
            .filter(|t| {
                matches!(
                    t.get("status").and_then(|v| v.as_str()),
                    Some("queued") | Some("sent")
                )
            })
            .count();
        println!("\ntasks: {} total, {} queued/sent", items.len(), open);
    }
}
