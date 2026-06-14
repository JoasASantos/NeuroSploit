"""
Model registry for NeuroSploit v3.3.0.

Maps logical providers to their latest models and the env vars / base URLs the
agentic CLI backends need. Includes the NVIDIA NIM provider added in PR #28.

The engine itself does not call these APIs directly — the chosen CLI backend
(Claude Code / Codex / Grok) does. This registry is what the launcher uses to
present choices and to export the right environment to the backend process.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Model:
    id: str
    label: str
    context: int = 200_000
    notes: str = ""


@dataclass(frozen=True)
class Provider:
    key: str
    label: str
    env_keys: List[str]                 # accepted API-key env var names
    base_url: Optional[str] = None      # OpenAI-compatible base URL, if any
    base_url_env: Optional[str] = None  # env var the backend reads for base URL
    models: List[Model] = field(default_factory=list)
    subscription: bool = False          # uses a CLI subscription rather than an API key


PROVIDERS: Dict[str, Provider] = {
    # --- Anthropic (latest Claude family; default) -------------------------
    "anthropic": Provider(
        key="anthropic", label="Anthropic Claude",
        env_keys=["ANTHROPIC_API_KEY"],
        models=[
            Model("claude-opus-4-8", "Claude Opus 4.8", 1_000_000, "Most capable; deep multi-step pentest reasoning"),
            Model("claude-sonnet-4-6", "Claude Sonnet 4.6", 1_000_000, "Balanced cost/quality default"),
            Model("claude-haiku-4-5", "Claude Haiku 4.5", 200_000, "Fast/cheap recon and triage"),
        ],
    ),
    # --- OpenAI ------------------------------------------------------------
    "openai": Provider(
        key="openai", label="OpenAI",
        env_keys=["OPENAI_API_KEY"],
        models=[
            Model("gpt-5.1", "GPT-5.1", 400_000, "Strong general reasoning"),
            Model("o4", "o4", 200_000, "Deliberate reasoning for validation"),
        ],
    ),
    # --- xAI Grok ----------------------------------------------------------
    "xai": Provider(
        key="xai", label="xAI Grok",
        env_keys=["XAI_API_KEY", "GROK_API_KEY"],
        base_url="https://api.x.ai/v1", base_url_env="OPENAI_BASE_URL",
        models=[
            Model("grok-4", "Grok 4", 256_000, "Fast agentic execution"),
            Model("grok-4-fast", "Grok 4 Fast", 128_000, "Low-latency triage"),
        ],
    ),
    # --- NVIDIA NIM (PR #28) ----------------------------------------------
    # OpenAI-compatible endpoint at integrate.api.nvidia.com; keys are `nvapi-...`.
    "nvidia_nim": Provider(
        key="nvidia_nim", label="NVIDIA NIM",
        env_keys=["NVIDIA_NIM_API_KEY", "NVIDIA_API_KEY"],
        base_url="https://integrate.api.nvidia.com/v1", base_url_env="OPENAI_BASE_URL",
        models=[
            Model("nvidia/llama-3.3-nemotron-super-49b-v1", "Nemotron Super 49B", 128_000, "NIM hosted reasoning"),
            Model("deepseek-ai/deepseek-r1", "DeepSeek-R1 (NIM)", 128_000, "Strong reasoning via NIM"),
            Model("qwen/qwen2.5-coder-32b-instruct", "Qwen2.5 Coder 32B (NIM)", 128_000, "Code/exploit oriented"),
        ],
    ),
    # --- Google Gemini -----------------------------------------------------
    "gemini": Provider(
        key="gemini", label="Google Gemini",
        env_keys=["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        models=[
            Model("gemini-2.5-pro", "Gemini 2.5 Pro", 1_000_000, "Large context recon"),
            Model("gemini-2.5-flash", "Gemini 2.5 Flash", 1_000_000, "Fast/cheap"),
        ],
    ),
    # --- OpenRouter (aggregator) ------------------------------------------
    "openrouter": Provider(
        key="openrouter", label="OpenRouter",
        env_keys=["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1", base_url_env="OPENAI_BASE_URL",
        models=[Model("anthropic/claude-opus-4-8", "Opus 4.8 (OpenRouter)", 1_000_000)],
    ),
    # --- Local Ollama ------------------------------------------------------
    "ollama": Provider(
        key="ollama", label="Ollama (local)",
        env_keys=[],
        base_url="http://localhost:11434/v1", base_url_env="OPENAI_BASE_URL",
        models=[
            Model("qwen2.5-coder:32b", "Qwen2.5 Coder 32B (local)", 32_000),
            Model("llama3.3:70b", "Llama 3.3 70B (local)", 128_000),
        ],
    ),
    # --- Subscription via Claude Code CLI (no API key needed) -------------
    "claude_subscription": Provider(
        key="claude_subscription", label="Claude subscription (via Claude Code login)",
        env_keys=[], subscription=True,
        models=[
            Model("claude-opus-4-8", "Claude Opus 4.8 (subscription)", 1_000_000),
            Model("claude-sonnet-4-6", "Claude Sonnet 4.6 (subscription)", 1_000_000),
        ],
    ),
}

DEFAULT_PROVIDER = "anthropic"


def get_provider(key: str) -> Optional[Provider]:
    return PROVIDERS.get(key)


def list_models(provider_key: str) -> List[Model]:
    p = PROVIDERS.get(provider_key)
    return list(p.models) if p else []


def resolve_env(provider_key: str, model_id: str) -> Dict[str, str]:
    """Return the env vars a backend needs for this provider/model selection."""
    import os
    env: Dict[str, str] = {}
    p = PROVIDERS.get(provider_key)
    if not p:
        return env
    if p.base_url and p.base_url_env:
        env[p.base_url_env] = p.base_url
    for k in p.env_keys:
        if os.getenv(k):
            env[k] = os.environ[k]
            break
    env["NEUROSPLOIT_MODEL"] = model_id
    env["NEUROSPLOIT_PROVIDER"] = provider_key
    return env
