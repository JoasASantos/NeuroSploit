//! Axum web dashboard for the v3.4.0 harness.

use axum::{
    extract::{Path, State},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use harness::{agents, models::ModelRef, pool::ModelPool, report, types::RunConfig};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct RunState {
    log: Vec<String>,
    done: bool,
    result: Option<Value>,
    report: Option<String>,
}

pub struct AppState {
    base: PathBuf,
    runs: Mutex<HashMap<String, RunState>>,
}

pub async fn serve(base: PathBuf, port: u16) -> anyhow::Result<()> {
    let state = Arc::new(AppState { base, runs: Mutex::new(HashMap::new()) });
    let app = Router::new()
        .route("/", get(index))
        .route("/api/info", get(info))
        .route("/api/agents", get(agents_list))
        .route("/api/models", get(models_list))
        .route("/api/run", post(run))
        .route("/api/status/:id", get(status))
        .route("/report/:id", get(report_html))
        .with_state(state);

    let addr = format!("127.0.0.1:{port}");
    println!("NeuroSploit v3.4.0 dashboard → http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn info(State(st): State<Arc<AppState>>) -> Json<Value> {
    let lib = agents::load(&st.base);
    let provs: Vec<Value> = harness::providers()
        .iter()
        .map(|p| json!({"key": p.key, "label": p.label, "kind": p.kind, "models": p.models}))
        .collect();
    Json(json!({
        "version": "3.4.0",
        "agents": {"vulns": lib.vulns.len(), "meta": lib.meta.len(), "total": lib.total()},
        "providers": provs,
        "cli_backends": harness::installed_cli_backends(),
    }))
}

async fn agents_list(State(st): State<Arc<AppState>>) -> Json<Value> {
    let lib = agents::load(&st.base);
    let v: Vec<Value> = lib
        .vulns
        .iter()
        .chain(lib.meta.iter())
        .map(|a| json!({"name": a.name, "title": a.title, "cwe": a.cwe, "kind": a.kind}))
        .collect();
    Json(json!({ "agents": v }))
}

async fn models_list() -> Json<Value> {
    let provs: Vec<Value> = harness::providers()
        .iter()
        .map(|p| json!({"key": p.key, "label": p.label, "kind": p.kind, "models": p.models}))
        .collect();
    Json(json!({ "providers": provs }))
}

fn norm(u: &str) -> String {
    if u.starts_with("http") {
        u.to_string()
    } else {
        format!("https://{u}")
    }
}

async fn run(State(st): State<Arc<AppState>>, Json(body): Json<Value>) -> Json<Value> {
    let id = uuid::Uuid::new_v4().to_string();
    st.runs
        .lock()
        .unwrap()
        .insert(id.clone(), RunState { log: vec![], done: false, result: None, report: None });

    let st2 = st.clone();
    let id2 = id.clone();
    tokio::spawn(async move {
        let base = st2.base.clone();

        let mut targets: Vec<String> = Vec::new();
        if let Some(arr) = body.get("targets").and_then(|v| v.as_array()) {
            for t in arr {
                if let Some(s) = t.as_str() {
                    if !s.trim().is_empty() {
                        targets.push(norm(s.trim()));
                    }
                }
            }
        }
        if targets.is_empty() {
            if let Some(u) = body.get("url").and_then(|v| v.as_str()) {
                if !u.trim().is_empty() {
                    targets.push(norm(u.trim()));
                }
            }
        }
        let models: Vec<String> = body
            .get("models")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let vote_n = body.get("vote_n").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
        let max_agents = body.get("max_agents").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let offline = body.get("offline").and_then(|v| v.as_bool()).unwrap_or(false);
        let subscription = body.get("subscription").and_then(|v| v.as_bool()).unwrap_or(false);

        let lib = agents::load(&base);
        let refs: Vec<ModelRef> = if models.is_empty() {
            vec![ModelRef::parse("anthropic:claude-opus-4-8")]
        } else {
            models.iter().map(|s| ModelRef::parse(s)).collect()
        };
        let pool = ModelPool::with_auth(refs, 8, subscription);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
        let stf = st2.clone();
        let idf = id2.clone();
        let fwd = tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if let Ok(mut g) = stf.runs.lock() {
                    if let Some(r) = g.get_mut(&idf) {
                        r.log.push(line);
                    }
                }
            }
        });

        let mut all_findings = Vec::new();
        let mut all_ran = Vec::new();
        for url in &targets {
            let mut cfg = RunConfig::new(url);
            cfg.models = if models.is_empty() {
                vec!["anthropic:claude-opus-4-8".into()]
            } else {
                models.clone()
            };
            cfg.vote_n = vote_n;
            cfg.max_agents = max_agents;
            cfg.offline = offline;
            cfg.subscription = subscription;
            let _ = tx.send(format!("=== target: {url} ===")).await;
            let out = harness::run(cfg, &lib, &pool, tx.clone()).await;
            all_findings.extend(out.findings);
            all_ran.extend(out.agents_ran);
        }
        drop(tx);
        let _ = fwd.await;

        let report_html = report::html(targets.first().map(|s| s.as_str()).unwrap_or(""), &all_findings);
        let result = json!({"findings": all_findings, "agents_ran": all_ran, "targets": targets});
        if let Ok(mut g) = st2.runs.lock() {
            if let Some(r) = g.get_mut(&id2) {
                r.result = Some(result);
                r.report = Some(report_html);
                r.done = true;
            }
        }
    });

    Json(json!({ "run_id": id }))
}

async fn status(Path(id): Path<String>, State(st): State<Arc<AppState>>) -> Json<Value> {
    let g = st.runs.lock().unwrap();
    match g.get(&id) {
        Some(r) => Json(json!({"log": r.log, "done": r.done, "result": r.result, "has_report": r.report.is_some()})),
        None => Json(json!({"error": "unknown run"})),
    }
}

async fn report_html(Path(id): Path<String>, State(st): State<Arc<AppState>>) -> Html<String> {
    let g = st.runs.lock().unwrap();
    Html(g.get(&id).and_then(|r| r.report.clone()).unwrap_or_else(|| "<h1>no report</h1>".into()))
}
