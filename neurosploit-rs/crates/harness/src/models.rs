use anyhow::{anyhow, Result};
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
            models: vec!["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"] },
        Provider { key: "openai", label: "OpenAI", base_url: "https://api.openai.com/v1", env_key: "OPENAI_API_KEY", kind: "cli",
            models: vec!["gpt-5.1", "o4"] },
        Provider { key: "xai", label: "xAI Grok", base_url: "https://api.x.ai/v1", env_key: "XAI_API_KEY", kind: "cli",
            models: vec!["grok-4", "grok-4-fast"] },
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
        Provider { key: "openrouter", label: "OpenRouter", base_url: "https://openrouter.ai/api/v1", env_key: "OPENROUTER_API_KEY", kind: "api",
            models: vec!["anthropic/claude-opus-4-8", "qwen/qwen-2.5-coder-32b-instruct", "deepseek/deepseek-r1", "meta-llama/llama-3.3-70b-instruct"] },
        Provider { key: "ollama", label: "Ollama (local)", base_url: "http://localhost:11434/v1", env_key: "OLLAMA_API_KEY", kind: "api",
            models: vec!["qwen2.5-coder:32b", "qwq:32b", "deepseek-r1:32b", "llama3.3:70b"] },
    ]
}

pub fn provider_for(key: &str) -> Option<Provider> {
    providers().into_iter().find(|p| p.key == key)
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
        let key = std::env::var(p.env_key).unwrap_or_default();
        if key.is_empty() && p.key != "ollama" {
            return Err(anyhow!("no API key ({}) for provider '{}'", p.env_key, p.key));
        }
        let url = format!("{}/chat/completions", p.base_url.trim_end_matches('/'));
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
            req = req.bearer_auth(&key);
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
    /// Code / Codex / Grok) instead of an API key. This uses the user's logged-in
    /// subscription, so no provider key is required.
    pub async fn chat_cli(&self, provider: &str, model: &str, system: &str, user: &str) -> Result<String> {
        let bin = cli_binary_for(provider)
            .ok_or_else(|| anyhow!("no CLI/subscription backend for provider '{}'", provider))?;
        let prompt = format!("{system}\n\n{user}");
        let mut cmd = Command::new(bin);
        match bin {
            // Claude Code headless print mode (uses the Claude subscription login).
            "claude" => {
                cmd.arg("-p").arg("--model").arg(model);
            }
            // Codex non-interactive exec (uses the ChatGPT/Codex login), prompt on stdin.
            "codex" => {
                cmd.arg("exec").arg("--model").arg(model).arg("-");
            }
            // Grok CLI, prompt on stdin (best-effort flags).
            "grok" => {
                cmd.arg("--model").arg(model);
            }
            _ => {}
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| anyhow!("spawn {} failed: {}", bin, e))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await?;
            // Drop closes stdin so the CLI processes the prompt and exits.
        }
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            return Err(anyhow!("{} subscription CLI failed: {}", bin, truncate(&String::from_utf8_lossy(&out.stderr), 200)));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

/// Map a provider to its local agentic CLI binary (subscription backend).
pub fn cli_binary_for(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("claude"),
        "openai" => Some("codex"),
        "xai" => Some("grok"),
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
    ["claude", "codex", "grok"].into_iter().filter(|b| binary_in_path(b)).collect()
}

impl Default for ChatClient {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
