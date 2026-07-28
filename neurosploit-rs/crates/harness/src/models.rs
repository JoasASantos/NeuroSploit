use anyhow::{anyhow, Result};
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// A model provider exposing an OpenAI-compatible `/chat/completions` endpoint.
#[derive(Clone, Debug, Serialize)]
pub struct Provider {
    pub key: &'static str,
    pub label: &'static str,
    pub base_url: &'static str,
    pub env_key: &'static str,
    /// "cli" (also drivable by an agentic CLI) | "api"
    pub kind: &'static str,
    pub models: Vec<&'static str>,
}

/// The full provider registry. Every entry speaks the OpenAI chat schema
/// (Anthropic, xAI, NVIDIA NIM, DeepSeek, Mistral, Qwen, Groq, Together,
/// OpenRouter, Gemini-compat, Ollama).
pub fn providers() -> Vec<Provider> {
    vec![
        Provider { key: "anthropic", label: "Anthropic Claude", base_url: "https://api.anthropic.com/v1", env_key: "ANTHROPIC_API_KEY", kind: "cli",
            models: vec!["claude-opus-5", "claude-sonnet-5", "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"] },
        Provider { key: "openai", label: "OpenAI (ChatGPT)", base_url: "https://api.openai.com/v1", env_key: "OPENAI_API_KEY", kind: "cli",
            models: vec!["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex", "gpt-5.2", "gpt-5.1", "gpt-5.1-codex", "o4"] },
        Provider { key: "xai", label: "xAI Grok", base_url: "https://api.x.ai/v1", env_key: "XAI_API_KEY", kind: "cli",
            models: vec!["grok-4.5", "grok-4", "grok-4-fast"] },
        Provider { key: "gemini", label: "Google Gemini", base_url: "https://generativelanguage.googleapis.com/v1beta/openai", env_key: "GEMINI_API_KEY", kind: "cli",
            models: vec!["gemini-3-pro", "gemini-2.5-pro", "gemini-2.5-flash"] },
        Provider { key: "nvidia_nim", label: "NVIDIA NIM", base_url: "https://integrate.api.nvidia.com/v1", env_key: "NVIDIA_NIM_API_KEY", kind: "api",
            models: vec!["nvidia/llama-3.3-nemotron-super-49b-v1", "deepseek-ai/deepseek-r1", "qwen/qwen2.5-coder-32b-instruct"] },
        Provider { key: "deepseek", label: "DeepSeek", base_url: "https://api.deepseek.com/v1", env_key: "DEEPSEEK_API_KEY", kind: "api",
            models: vec!["deepseek-reasoner", "deepseek-chat"] },
        Provider { key: "mistral", label: "Mistral", base_url: "https://api.mistral.ai/v1", env_key: "MISTRAL_API_KEY", kind: "api",
            models: vec!["mistral-large-latest", "codestral-latest"] },
        Provider { key: "qwen", label: "Qwen (DashScope)", base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", env_key: "DASHSCOPE_API_KEY", kind: "api",
            models: vec!["qwen-max", "qwen2.5-coder-32b-instruct", "qwq-plus"] },
        Provider { key: "groq", label: "Groq", base_url: "https://api.groq.com/openai/v1", env_key: "GROQ_API_KEY", kind: "api",
            models: vec!["llama-3.3-70b-versatile", "qwen-2.5-coder-32b"] },
        Provider { key: "together", label: "Together AI", base_url: "https://api.together.xyz/v1", env_key: "TOGETHER_API_KEY", kind: "api",
            models: vec!["Qwen/Qwen2.5-Coder-32B-Instruct", "deepseek-ai/DeepSeek-R1", "meta-llama/Llama-3.3-70B-Instruct-Turbo"] },
        // Moonshot AI (Kimi). OpenAI-compatible; use api.moonshot.cn for the CN endpoint.
        Provider { key: "moonshot", label: "Moonshot AI (Kimi)", base_url: "https://api.moonshot.ai/v1", env_key: "MOONSHOT_API_KEY", kind: "api",
            models: vec!["kimi-k3", "kimi-k2", "moonshot-v1-128k", "moonshot-v1-32k"] },
        // LiteLLM proxy (OpenAI-compatible). Point at your gateway with
        // LITELLM_BASE_URL (default http://localhost:4000/v1); key = LITELLM_API_KEY.
        // Use `litellm:<any-model-the-proxy-routes>` — model names pass through.
        Provider { key: "litellm", label: "LiteLLM (proxy)", base_url: "http://localhost:4000/v1", env_key: "LITELLM_API_KEY", kind: "api",
            models: vec!["gpt-4o", "claude-3-7-sonnet", "gemini/gemini-2.5-pro"] },
        Provider { key: "openrouter", label: "OpenRouter", base_url: "https://openrouter.ai/api/v1", env_key: "OPENROUTER_API_KEY", kind: "api",
            models: vec!["anthropic/claude-opus-4-8", "qwen/qwen-2.5-coder-32b-instruct", "deepseek/deepseek-r1", "meta-llama/llama-3.3-70b-instruct"] },
        // Azure OpenAI (OpenAI-compatible). Set AZURE_OPENAI_ENDPOINT (e.g.
        // https://<resource>.openai.azure.com), optionally AZURE_OPENAI_API_VERSION
        // (default 2024-10-21), and use `azure:<your-deployment-name>` as the model.
        // base_url is resolved from the endpoint at call time; auth uses an api-key header.
        Provider { key: "azure", label: "Azure OpenAI", base_url: "", env_key: "AZURE_OPENAI_API_KEY", kind: "api",
            models: vec!["gpt-4o", "gpt-4o-mini", "gpt-5.1", "o4-mini"] },
        Provider { key: "ollama", label: "Ollama (local)", base_url: "http://localhost:11434/v1", env_key: "OLLAMA_API_KEY", kind: "api",
            models: vec!["qwen2.5-coder:32b", "qwq:32b", "deepseek-r1:32b", "llama3.3:70b"] },
    ]
}

pub fn provider_for(key: &str) -> Option<Provider> {
    providers().into_iter().find(|p| p.key == key)
}

/// Resolve a provider's API key from the environment, honoring common aliases.
/// For Gemini we also accept `GOOGLE_API_KEY` (Google's standard env var name)
/// when `GEMINI_API_KEY` is unset.
fn resolve_key(p: &Provider) -> String {
    let mut k = std::env::var(p.env_key).unwrap_or_default();
    if k.is_empty() && p.key == "gemini" {
        k = std::env::var("GOOGLE_API_KEY").unwrap_or_default();
    }
    k
}

/// A `provider:model` selection.
#[derive(Clone, Debug)]
pub struct ModelRef {
    pub provider: String,
    pub model: String,
}

impl ModelRef {
    pub fn parse(s: &str) -> ModelRef {
        match s.split_once(':') {
            Some((p, m)) => ModelRef { provider: p.to_string(), model: m.to_string() },
            None => ModelRef { provider: "anthropic".into(), model: s.to_string() },
        }
    }
    pub fn label(&self) -> String {
        format!("{}:{}", self.provider, self.model)
    }
}

/// OpenAI-compatible chat client shared across the model pool.
#[derive(Clone)]
pub struct ChatClient {
    http: reqwest::Client,
}

impl ChatClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        ChatClient { http }
    }

    /// One chat completion. Errors (missing key, network, non-2xx) propagate so
    /// the pool can fail over to the next candidate model.
    pub async fn chat(&self, m: &ModelRef, system: &str, user: &str) -> Result<String> {
        let p = provider_for(&m.provider)
            .ok_or_else(|| anyhow!("unknown provider '{}'", m.provider))?;
        let key = resolve_key(&p);
        if key.is_empty() && p.key != "ollama" && p.key != "litellm" {
            let hint = if p.key == "gemini" { format!("{} (or GOOGLE_API_KEY)", p.env_key) } else { p.env_key.to_string() };
            return Err(anyhow!("no API key ({}) for provider '{}'", hint, p.key));
        }
        // Azure OpenAI uses a per-resource endpoint + deployment + api-version,
        // and authenticates with an `api-key` header instead of Bearer.
        let azure = p.key == "azure";
        let url = if azure {
            let endpoint = std::env::var("AZURE_OPENAI_ENDPOINT").unwrap_or_default();
            if endpoint.is_empty() {
                return Err(anyhow!("set AZURE_OPENAI_ENDPOINT (e.g. https://<resource>.openai.azure.com) for the azure provider"));
            }
            let ver = std::env::var("AZURE_OPENAI_API_VERSION").unwrap_or_else(|_| "2024-10-21".to_string());
            // `model` is the Azure DEPLOYMENT name (use `azure:<deployment>`).
            format!("{}/openai/deployments/{}/chat/completions?api-version={}",
                endpoint.trim_end_matches('/'), m.model, ver)
        } else {
            // Allow an env base-URL override (LiteLLM gateway, self-hosted proxies, …).
            let base = match p.key {
                "litellm" => std::env::var("LITELLM_BASE_URL").unwrap_or_else(|_| p.base_url.to_string()),
                "ollama" => std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| p.base_url.to_string()),
                _ => p.base_url.to_string(),
            };
            format!("{}/chat/completions", base.trim_end_matches('/'))
        };
        let body = serde_json::json!({
            "model": m.model,
            "max_tokens": 4096,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ]
        });
        let mut req = self.http.post(&url).json(&body);
        if !key.is_empty() {
            if azure { req = req.header("api-key", &key); } else { req = req.bearer_auth(&key); }
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("{} returned {}: {}", p.key, status, truncate(&text, 200)));
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| anyhow!("no content in response"))?;
        Ok(content.to_string())
    }
}

impl ChatClient {
    /// Complete via a locally-installed **agentic CLI subscription** (Claude
    /// Code / Codex / Grok / Gemini) instead of an API key. This uses the user's
    /// logged-in subscription, so no provider key is required.
    ///
    /// When `mcp_config` is set (a path to an `.mcp.json`), Claude/Codex run with
    /// the MCP servers enabled and tool autonomy, so agents can actually drive
    /// **Playwright** (browse, execute JS, screenshot) during execution.
    pub async fn chat_cli(
        &self,
        label: &str,
        provider: &str,
        model: &str,
        system: &str,
        user: &str,
        mcp_config: Option<&str>,
        progress: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<String> {
        let bin = cli_binary_for(provider)
            .ok_or_else(|| anyhow!("no CLI/subscription backend for provider '{}'", provider))?;
        let prompt = format!("{system}\n\n{user}");

        // Claude Code can stream structured events (tools, commands, files) which
        // we surface live as a categorized activity feed, attributed to `label`.
        if bin == "claude" {
            return self.chat_claude_stream(label, model, &prompt, mcp_config, progress).await;
        }
        // Codex exec streams JSONL events (`--json`): commands it runs, agent
        // messages, file changes, token usage. Surface them live so recon and
        // exploitation are visible tool-by-tool instead of a silent black box.
        if bin == "codex" {
            return self.chat_codex_stream(label, model, &prompt, mcp_config, progress).await;
        }

        let mut cmd = Command::new(bin);
        match bin {
            // Codex non-interactive exec (uses the ChatGPT/Codex login), prompt on stdin.
            "codex" => {
                cmd.arg("exec").arg("--model").arg(model)
                    .arg("--dangerously-bypass-approvals-and-sandbox");
                // Codex takes MCP servers as `-c mcp_servers.<name>....` TOML
                // overrides, NOT a config-file path. Read our .mcp.json and inject
                // each server's command/args so the browser MCP actually loads.
                if let Some(mcp) = mcp_config {
                    for (name, cmdline, args) in mcp_servers_from(mcp) {
                        cmd.arg("-c").arg(format!("mcp_servers.{name}.command={cmdline}"));
                        cmd.arg("-c").arg(format!("mcp_servers.{name}.args={args}"));
                    }
                }
                cmd.arg("-");
            }
            // Google Gemini CLI (uses the Gemini subscription login).
            "gemini" => {
                cmd.arg("-m").arg(model);
            }
            // Grok CLI, prompt on stdin (best-effort flags).
            "grok" => {
                cmd.arg("--model").arg(model);
            }
            _ => {}
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| anyhow!("spawn {} failed: {}", bin, e))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await?;
            // Drop closes stdin so the CLI processes the prompt and exits.
        }
        // Cap a single agentic CLI turn so a stuck tool-loop can't hang the run.
        let out = match tokio::time::timeout(Duration::from_secs(600), child.wait_with_output()).await {
            Ok(r) => r?,
            Err(_) => return Err(anyhow!("{} subscription CLI timed out after 600s", bin)),
        };
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            // The CLI often writes the real reason (rate limit, auth) to stdout,
            // not stderr — surface both plus the exit code so the error isn't blank.
            let detail = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else if !stdout.is_empty() {
                stdout.clone()
            } else {
                "no output".to_string()
            };
            // Agentic CLIs (esp. `codex exec` in bypass-sandbox mode) exit
            // non-zero when a tool/command they ran internally returned non-zero
            // (e.g. a curl/nmap that failed) — even though they produced a valid
            // final answer. Treat that as success and use the output; only fail
            // hard on a genuine auth/rate/quota error or when there's no output.
            let low = format!("{stdout}\n{stderr}").to_lowercase();
            let hard = ["not logged in", "please log in", "please login", "run /login",
                "unauthorized", "not authenticated", "invalid api key", "no api key",
                "rate limit", "429", "quota", "credit balance", "usage limit"]
                .iter().any(|k| low.contains(k));
            if !stdout.is_empty() && !hard {
                return Ok(stdout);
            }
            return Err(anyhow!(
                "{} subscription CLI exit {}: {}",
                bin,
                out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                truncate(&detail, 240)
            ));
        }
        if stdout.is_empty() {
            return Err(anyhow!("{} subscription CLI returned empty output", bin));
        }
        Ok(stdout)
    }

    /// Drive Claude Code with `--output-format stream-json` and surface its
    /// activity as a live, categorized feed (states, tools, commands, files).
    /// Tagged events are sent to `progress`; the final assistant text is returned.
    async fn chat_claude_stream(
        &self,
        label: &str,
        model: &str,
        prompt: &str,
        mcp_config: Option<&str>,
        progress: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<String> {
        let mut cmd = Command::new("claude");
        cmd.arg("-p").arg("--model").arg(model)
            .arg("--output-format").arg("stream-json").arg("--verbose")
            .arg("--dangerously-skip-permissions")
            .env("IS_SANDBOX", "1");
        if let Some(mcp) = mcp_config {
            cmd.arg("--mcp-config").arg(mcp);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| anyhow!("spawn claude failed: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await?;
        }
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        let mut lines = BufReader::new(stdout).lines();
        // Tag every streamed event with the agent label so the feed is attributable.
        let lbl = if label.is_empty() { String::new() } else { format!("@{label} ") };
        let emit = |s: String| {
            if let Some(tx) = &progress {
                let _ = tx.try_send(format!("{lbl}{s}"));
            }
        };

        let mut result = String::new();
        let mut had_err = String::new();
        let read = async {
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                match v.get("type").and_then(|t| t.as_str()) {
                    Some("assistant") => {
                        if let Some(content) = v.pointer("/message/content").and_then(|c| c.as_array()) {
                            for blk in content {
                                match blk.get("type").and_then(|t| t.as_str()) {
                                    Some("text") => {
                                        if let Some(t) = blk.get("text").and_then(|x| x.as_str()) {
                                            let t = t.trim();
                                            if !t.is_empty() {
                                                emit(format!("ai: {}", truncate(t, 240)));
                                            }
                                        }
                                    }
                                    Some("tool_use") => {
                                        let name = blk.get("name").and_then(|x| x.as_str()).unwrap_or("tool");
                                        let input = blk.get("input");
                                        emit(tool_event(name, input));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Some("result") => {
                        if let Some(r) = v.get("result").and_then(|x| x.as_str()) {
                            result = r.to_string();
                        }
                        // Token/cost telemetry from the final result event.
                        let ti = v.pointer("/usage/input_tokens").and_then(|x| x.as_u64());
                        let to = v.pointer("/usage/output_tokens").and_then(|x| x.as_u64());
                        let cost = v.get("total_cost_usd").and_then(|x| x.as_f64());
                        if ti.is_some() || to.is_some() || cost.is_some() {
                            emit(format!("tokens: in={} out={} cost=${:.4}",
                                ti.unwrap_or(0), to.unwrap_or(0), cost.unwrap_or(0.0)));
                        }
                        if v.get("is_error").and_then(|x| x.as_bool()).unwrap_or(false) {
                            had_err = v.get("result").and_then(|x| x.as_str()).unwrap_or("error").to_string();
                        }
                    }
                    _ => {}
                }
            }
        };
        // Bound the whole streamed turn.
        if tokio::time::timeout(Duration::from_secs(900), read).await.is_err() {
            return Err(anyhow!("claude stream timed out after 900s"));
        }
        let _ = child.wait().await;
        if !had_err.is_empty() && result.is_empty() {
            return Err(anyhow!("claude: {}", truncate(&had_err, 240)));
        }
        if result.is_empty() {
            return Err(anyhow!("claude stream produced no result"));
        }
        Ok(result)
    }

    /// Drive `codex exec --json` and surface its JSONL event stream as a live,
    /// categorized activity feed (commands, agent messages, file changes, MCP
    /// tool calls, token usage). The final agent message is returned as the
    /// result. Mirrors `chat_claude_stream` so Codex runs are just as visible.
    async fn chat_codex_stream(
        &self,
        label: &str,
        model: &str,
        prompt: &str,
        mcp_config: Option<&str>,
        progress: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<String> {
        let mut cmd = Command::new("codex");
        cmd.arg("exec").arg("--json").arg("--model").arg(model)
            .arg("--dangerously-bypass-approvals-and-sandbox");
        if let Some(mcp) = mcp_config {
            for (name, cmdline, args) in mcp_servers_from(mcp) {
                cmd.arg("-c").arg(format!("mcp_servers.{name}.command={cmdline}"));
                cmd.arg("-c").arg(format!("mcp_servers.{name}.args={args}"));
            }
        }
        cmd.arg("-");
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| anyhow!("spawn codex failed: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await?;
            // Drop closes stdin so Codex processes the prompt and exits.
        }
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;
        let mut lines = BufReader::new(stdout).lines();
        let lbl = if label.is_empty() { String::new() } else { format!("@{label} ") };
        let emit = |s: String| {
            if let Some(tx) = &progress {
                let _ = tx.try_send(format!("{lbl}{s}"));
            }
        };

        // Last agent_message is the model's final answer; keep every one so a
        // run that ends on a tool call still returns the most recent reasoning.
        let mut result = String::new();
        let read = async {
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match ty {
                    "item.started" | "item.completed" => {
                        let Some(item) = v.get("item") else { continue };
                        let itype = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        match itype {
                            "command_execution" => {
                                // Only announce on start (avoid double lines); note failures on completion.
                                let c = item.get("command").and_then(|x| x.as_str()).unwrap_or("");
                                // Strip the `/bin/sh -lc '...'` wrapper Codex adds.
                                let c = c.strip_prefix("/bin/sh -lc ").map(|s| s.trim_matches('\'')).unwrap_or(c);
                                if ty == "item.started" {
                                    let danger = c.contains("rm -rf") || c.contains("mkfs")
                                        || c.contains(":(){") || c.contains("dd if=") || c.contains("> /dev/");
                                    emit(format!("{}: {}", if danger { "danger" } else { "exec" }, truncate(c, 200)));
                                } else if let Some(code) = item.get("exit_code").and_then(|x| x.as_i64()) {
                                    if code != 0 {
                                        emit(format!("exec: (exit {code}) {}", truncate(c, 120)));
                                    }
                                }
                            }
                            "agent_message" => {
                                if let Some(t) = item.get("text").and_then(|x| x.as_str()) {
                                    let t = t.trim();
                                    if !t.is_empty() {
                                        if ty == "item.completed" { result = t.to_string(); }
                                        emit(format!("ai: {}", truncate(t, 240)));
                                    }
                                }
                            }
                            "file_change" | "patch" => {
                                let p = item.get("path").and_then(|x| x.as_str())
                                    .or_else(|| item.get("file").and_then(|x| x.as_str())).unwrap_or("file");
                                emit(format!("edit: {p}"));
                            }
                            "mcp_tool_call" => {
                                let name = item.get("tool").and_then(|x| x.as_str())
                                    .or_else(|| item.get("name").and_then(|x| x.as_str())).unwrap_or("mcp");
                                emit(format!("tool: {name}"));
                            }
                            "web_search" => {
                                let q = item.get("query").and_then(|x| x.as_str()).unwrap_or("");
                                emit(format!("net: search {}", truncate(q, 100)));
                            }
                            _ => {}
                        }
                    }
                    "turn.completed" => {
                        let ti = v.pointer("/usage/input_tokens").and_then(|x| x.as_u64());
                        let to = v.pointer("/usage/output_tokens").and_then(|x| x.as_u64());
                        if ti.is_some() || to.is_some() {
                            emit(format!("tokens: in={} out={}", ti.unwrap_or(0), to.unwrap_or(0)));
                        }
                    }
                    _ => {}
                }
            }
        };
        // Bound the whole streamed turn (matches the buffered path's cap).
        if tokio::time::timeout(Duration::from_secs(900), read).await.is_err() {
            return Err(anyhow!("codex stream timed out after 900s"));
        }
        let status = child.wait().await.ok();
        // Drain stderr for auth/rate diagnostics if we got nothing usable.
        if result.is_empty() {
            let mut errbuf = String::new();
            let mut el = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = el.next_line().await {
                if !errbuf.is_empty() { errbuf.push('\n'); }
                errbuf.push_str(&l);
                if errbuf.len() > 2000 { break; }
            }
            let low = errbuf.to_lowercase();
            let hard = ["not logged in", "please log in", "please login", "run /login",
                "unauthorized", "not authenticated", "invalid api key", "no api key",
                "rate limit", "429", "quota", "credit balance", "usage limit"]
                .iter().any(|k| low.contains(k));
            let code = status.and_then(|s| s.code()).map(|c| c.to_string()).unwrap_or_else(|| "signal".into());
            if hard || !errbuf.trim().is_empty() {
                return Err(anyhow!("codex subscription CLI exit {}: {}", code, truncate(errbuf.trim(), 240)));
            }
            return Err(anyhow!("codex stream produced no result"));
        }
        Ok(result)
    }
}

/// Categorise a Claude tool_use block into a tagged activity-feed event.
fn tool_event(name: &str, input: Option<&serde_json::Value>) -> String {
    let s = |k: &str| input.and_then(|i| i.get(k)).and_then(|x| x.as_str()).unwrap_or("");
    match name {
        "Bash" => {
            let c = s("command");
            let danger = c.contains("rm -rf") || c.contains("mkfs") || c.contains(":(){")
                || c.contains("dd if=") || c.contains("> /dev/");
            format!("{}: {}", if danger { "danger" } else { "exec" }, truncate(c, 200))
        }
        "Read" => format!("read: {}", s("file_path")),
        "Write" | "Edit" => format!("edit: {}", s("file_path")),
        "Grep" => format!("tool: grep {}", truncate(s("pattern"), 80)),
        "Glob" => format!("tool: glob {}", truncate(s("pattern"), 80)),
        "WebFetch" => format!("net: fetch {}", s("url")),
        n if n.contains("playwright") || n.contains("browser") => {
            let url = s("url");
            format!("net: browser {}{}", n.rsplit('_').next().unwrap_or(n), if url.is_empty() { String::new() } else { format!(" {url}") })
        }
        other => format!("tool: {other}"),
    }
}

/// Parse an `.mcp.json` (`{ "mcpServers": { name: { command, args } } }`) into
/// `(name, command, args_json)` tuples — used to inject servers into Codex's
/// `-c mcp_servers.*` TOML overrides (Codex has no config-file flag).
fn mcp_servers_from(path: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let Ok(txt) = std::fs::read_to_string(path) else { return out };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) else { return out };
    let servers = v.get("mcpServers").cloned().unwrap_or(v);
    if let Some(obj) = servers.as_object() {
        for (name, s) in obj {
            let command = s.get("command").and_then(|c| c.as_str()).unwrap_or("").to_string();
            if command.is_empty() { continue; }
            let args = s.get("args").cloned().unwrap_or(serde_json::json!([]));
            out.push((name.clone(), command, args.to_string()));
        }
    }
    out
}

/// Map a provider to its local agentic CLI binary (subscription backend).
pub fn cli_binary_for(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("claude"),
        "openai" => Some("codex"),
        "xai" => Some("grok"),
        "gemini" => Some("gemini"),
        _ => None,
    }
}

/// Is `name` an executable found on PATH?
pub fn binary_in_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Which subscription CLI backends are installed locally.
pub fn installed_cli_backends() -> Vec<&'static str> {
    ["claude", "codex", "grok", "gemini"].into_iter().filter(|b| binary_in_path(b)).collect()
}

/// Login state of a subscription CLI backend.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginStatus {
    NotInstalled,
    LoggedIn,
    NotLoggedIn,
    Unknown, // installed but couldn't determine (timeout / weird output)
}

/// Check whether a subscription CLI is installed AND logged in, by sending it a
/// trivial prompt and inspecting the reply. Cheap (a few tokens) and bounded by a
/// short timeout. Detects the common "not authenticated / please login / no
/// credit" errors so the operator is warned before a whole run comes back empty.
pub async fn cli_login_status(provider: &str) -> LoginStatus {
    let Some(bin) = cli_binary_for(provider) else { return LoginStatus::NotInstalled };
    if !binary_in_path(bin) { return LoginStatus::NotInstalled; }
    let mut cmd = Command::new(bin);
    match bin {
        "claude" => { cmd.arg("-p").arg("--output-format").arg("text").arg("--dangerously-skip-permissions"); }
        "codex" => { cmd.arg("exec").arg("--dangerously-bypass-approvals-and-sandbox").arg("-"); }
        _ => { cmd.arg("-p"); } // grok / gemini: prompt on stdin
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = match cmd.spawn() { Ok(c) => c, Err(_) => return LoginStatus::Unknown };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"Reply with exactly: OK").await;
    }
    let out = match tokio::time::timeout(Duration::from_secs(45), child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        _ => return LoginStatus::Unknown,
    };
    let text = format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).to_lowercase();
    let auth_err = ["not logged in", "please log in", "please login", "run /login", "authenticate",
        "authentication", "unauthorized", "not authenticated", "no credit", "credit balance",
        "invalid api key", "no api key", "sign in", "session expired", "logged out"];
    if auth_err.iter().any(|k| text.contains(k)) {
        return LoginStatus::NotLoggedIn;
    }
    if out.status.success() && text.contains("ok") {
        return LoginStatus::LoggedIn;
    }
    // Produced *some* non-auth output → almost certainly usable.
    if out.status.success() && !text.trim().is_empty() {
        return LoginStatus::LoggedIn;
    }
    LoginStatus::Unknown
}

/// Does this provider's agentic CLI accept a Playwright MCP config?
/// Claude Code and Codex do; Gemini/Grok CLIs don't take an MCP-config flag, so
/// they fall back to their own built-in tools.
pub fn mcp_supported(provider: &str) -> bool {
    matches!(provider, "anthropic" | "openai")
}

/// Best-effort ensure the Playwright MCP server is available locally. Requires
/// `npx`; pre-warms `@playwright/mcp` so the first agent call isn't a cold start.
/// Returns Err with a clear reason when it can't be provisioned (caller then
/// degrades to built-in tools).
pub fn ensure_playwright_mcp() -> Result<()> {
    if !binary_in_path("npx") {
        return Err(anyhow!("npx (Node.js) not found — install Node to use Playwright MCP"));
    }
    // `npx -y @playwright/mcp@latest --help` installs the package into the npx
    // cache on first run; ignore non-zero exit (some versions lack --help) as long
    // as the package resolves.
    let out = std::process::Command::new("npx")
        .args(["-y", "@playwright/mcp@latest", "--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if let Err(e) = out {
        return Err(anyhow!("could not provision @playwright/mcp via npx: {e}"));
    }
    // Ensure the Chromium browser the MCP server drives is actually installed —
    // otherwise the FIRST browser action fails/hangs and the agent gives up with
    // no findings (a very common "MCP doesn't execute" cause). Best-effort,
    // skippable via NEUROSPLOIT_SKIP_BROWSER_INSTALL=1; non-fatal on failure.
    if std::env::var("NEUROSPLOIT_SKIP_BROWSER_INSTALL").ok().as_deref() != Some("1") {
        let _ = std::process::Command::new("npx")
            .args(["-y", "playwright", "install", "chromium"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    Ok(())
}

/// Write an `.mcp.json` into `dir` (Playwright by default) and return its path,
/// so the agentic CLI can drive a real browser during execution. If
/// `extra_servers` points at a JSON file shaped like `{ "mcpServers": {...} }`
/// (or just `{...}` of servers), those servers are MERGED in — letting users
/// plug additional MCP tools into the pipeline to potentiate testing.
pub fn write_mcp_config(dir: &std::path::Path, extra_servers: Option<&std::path::Path>) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let mut servers = serde_json::json!({
        "playwright": { "command": "npx", "args": ["-y", "@playwright/mcp@latest", "--headless", "--isolated"] }
    });
    if let Some(extra) = extra_servers {
        if let Ok(txt) = std::fs::read_to_string(extra) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                let add = v.get("mcpServers").cloned().unwrap_or(v);
                if let (Some(dst), Some(src)) = (servers.as_object_mut(), add.as_object()) {
                    for (k, val) in src {
                        dst.insert(k.clone(), val.clone());
                    }
                }
            }
        }
    }
    let cfg = serde_json::json!({ "mcpServers": servers });
    let path = dir.join(".mcp.json");
    std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap_or_default())?;
    Ok(path)
}

impl Default for ChatClient {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(s: &str, n: usize) -> String {
    // Truncate by CHARACTERS, never bytes — slicing `&s[..n]` panics when `n`
    // lands inside a multi-byte char (e.g. '—'). That panic was crashing agent
    // tasks and silently dropping their findings.
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
