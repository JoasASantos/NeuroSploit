use crate::models::{cli_binary_for, ChatClient, ModelRef};
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// A pool of candidate models with a global concurrency cap and provider
/// failover. The same panel of models is reused for validator voting.
///
/// `subscription = true` routes each model through its local agentic CLI
/// (Claude Code / Codex / Grok login) instead of an HTTP API key.
pub struct ModelPool {
    client: ChatClient,
    sem: Arc<Semaphore>,
    pub candidates: Vec<ModelRef>,
    pub subscription: bool,
}

impl ModelPool {
    pub fn new(models: Vec<ModelRef>, concurrency: usize) -> Self {
        Self::with_auth(models, concurrency, false)
    }

    pub fn with_auth(models: Vec<ModelRef>, concurrency: usize, subscription: bool) -> Self {
        let concurrency = concurrency.max(1);
        ModelPool {
            client: ChatClient::new(),
            sem: Arc::new(Semaphore::new(concurrency)),
            candidates: if models.is_empty() {
                vec![ModelRef::parse("anthropic:claude-opus-4-8")]
            } else {
                models
            },
            subscription,
        }
    }

    /// One completion for a model, via subscription CLI or HTTP API.
    async fn one(&self, m: &ModelRef, system: &str, user: &str) -> Result<String> {
        if self.subscription && cli_binary_for(&m.provider).is_some() {
            return self.client.chat_cli(&m.provider, &m.model, system, user).await;
        }
        self.client.chat(m, system, user).await
    }

    /// Complete a prompt, trying each candidate model until one succeeds.
    /// Returns the model that answered and its text.
    pub async fn complete(&self, system: &str, user: &str) -> Result<(ModelRef, String)> {
        let _permit = self.sem.acquire().await.expect("semaphore closed");
        let mut last = anyhow!("no candidate models");
        for m in &self.candidates {
            match self.one(m, system, user).await {
                Ok(text) => return Ok((m.clone(), text)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Ask up to `n` distinct models the same yes/no validation question and
    /// return (confirmations, total_votes). A model answering "yes"/"confirmed"
    /// counts as a confirmation. Used to cut false positives.
    pub async fn vote(&self, system: &str, user: &str, n: usize) -> (usize, usize) {
        let panel: Vec<ModelRef> = self.candidates.iter().take(n.max(1)).cloned().collect();
        let mut confirmed = 0usize;
        let mut total = 0usize;
        for m in &panel {
            let _permit = match self.sem.acquire().await {
                Ok(p) => p,
                Err(_) => break,
            };
            if let Ok(text) = self.one(m, system, user).await {
                total += 1;
                let t = text.to_lowercase();
                if t.contains("\"verdict\": \"confirmed\"")
                    || t.trim_start().starts_with("yes")
                    || t.contains("confirmed: true")
                    || t.contains("is_real\": true")
                {
                    confirmed += 1;
                }
            }
        }
        (confirmed, total)
    }
}
