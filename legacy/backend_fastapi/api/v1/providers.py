"""
NeuroSploit v3 - Providers API

REST endpoints for managing LLM providers and accounts.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class ConnectRequest(BaseModel):
    label: str = "Manual API Key"
    credential: str
    credential_type: str = "api_key"
    model_override: Optional[str] = None


@router.get("")
async def list_providers():
    """List all providers with their accounts and status."""
    from backend.core.smart_router import get_registry
    registry = get_registry()
    if not registry:
        return {"enabled": False, "providers": []}

    providers = []
    for p in registry.get_all_providers():
        accounts = []
        for a in p.accounts.values():
            accounts.append({
                "id": a.id,
                "label": a.label,
                "source": a.source,
                "credential_type": a.credential_type,
                "is_active": a.is_active,
                "tokens_used": a.tokens_used,
                "last_used": a.last_used,
                "expires_at": a.expires_at,
                "model_override": a.model_override,
            })
        providers.append({
            "id": p.id,
            "name": p.name,
            "auth_type": p.auth_type,
            "api_format": p.api_format,
            "tier": p.tier,
            "default_model": p.default_model,
            "accounts": accounts,
            "connected": any(
                a.is_active and a.id in registry._credentials
                for a in p.accounts.values()
            ),
            "enabled": getattr(p, "enabled", True),
        })

    return {"enabled": True, "providers": providers}


@router.get("/status")
async def providers_status():
    """Get quota and usage summary."""
    from backend.core.smart_router import get_router
    router_instance = get_router()
    if not router_instance:
        return {"enabled": False}
    return {"enabled": True, **router_instance.get_status()}


@router.post("/{provider_id}/detect")
async def detect_cli_token(provider_id: str):
    """Auto-detect CLI token for a specific provider."""
    from backend.core.smart_router import get_registry, get_extractor
    registry = get_registry()
    extractor = get_extractor()
    if not registry or not extractor:
        raise HTTPException(400, "Smart Router not enabled")

    token = extractor.detect(provider_id)
    if not token:
        return {"detected": False, "message": f"No CLI token found for {provider_id}"}

    # Add to registry
    acct_id = registry.add_account(
        provider_id=provider_id,
        label=token.label,
        credential=token.token,
        credential_type=token.credential_type,
        source="cli_detect",
        refresh_token=token.refresh_token,
        expires_at=token.expires_at,
    )

    return {
        "detected": True,
        "account_id": acct_id,
        "label": token.label,
        "credential_type": token.credential_type,
        "has_refresh_token": token.refresh_token is not None,
        "expires_at": token.expires_at,
    }


@router.post("/{provider_id}/connect")
async def connect_provider(provider_id: str, req: ConnectRequest):
    """Manually add an API key or credential."""
    from backend.core.smart_router import get_registry
    registry = get_registry()
    if not registry:
        raise HTTPException(400, "Smart Router not enabled")

    acct_id = registry.add_account(
        provider_id=provider_id,
        label=req.label,
        credential=req.credential,
        credential_type=req.credential_type,
        source="manual",
        model_override=req.model_override,
    )
    if not acct_id:
        raise HTTPException(404, f"Unknown provider: {provider_id}")

    return {"success": True, "account_id": acct_id}


@router.delete("/{provider_id}/accounts/{account_id}")
async def remove_account(provider_id: str, account_id: str):
    """Remove an account from a provider."""
    from backend.core.smart_router import get_registry
    registry = get_registry()
    if not registry:
        raise HTTPException(400, "Smart Router not enabled")

    success = registry.remove_account(provider_id, account_id)
    if not success:
        raise HTTPException(404, "Account not found")
    return {"success": True}


@router.post("/test/{provider_id}/{account_id}")
async def test_connection(provider_id: str, account_id: str):
    """Test connectivity for a specific account."""
    from backend.core.smart_router import get_router
    router_instance = get_router()
    if not router_instance:
        raise HTTPException(400, "Smart Router not enabled")

    success, message = await router_instance.test_account(provider_id, account_id)
    return {"success": success, "message": message}


# Known models per provider for dropdown selection
PROVIDER_MODELS = {
    "claude_code": [
        "claude-opus-4-6-20250918",
        "claude-sonnet-4-6-20250918",
        "claude-sonnet-4-5-20250929",
        "claude-haiku-4-5-20251001",
        "claude-sonnet-4-20250514",
        "claude-opus-4-20250514",
        "claude-haiku-4-20250514",
    ],
    "kiro": [
        "claude-opus-4-6-20250918",
        "claude-sonnet-4-6-20250918",
        "claude-sonnet-4-5-20250929",
        "claude-haiku-4-5-20251001",
        "claude-sonnet-4-20250514",
        "claude-opus-4-20250514",
        "claude-haiku-4-20250514",
    ],
    "anthropic": [
        "claude-opus-4-6-20250918",
        "claude-sonnet-4-6-20250918",
        "claude-sonnet-4-5-20250929",
        "claude-haiku-4-5-20251001",
        "claude-sonnet-4-20250514",
        "claude-opus-4-20250514",
        "claude-haiku-4-20250514",
        "claude-3-5-sonnet-20241022",
    ],
    "codex_cli": [
        "gpt-4o",
        "gpt-4o-mini",
        "o3-mini",
        "o4-mini",
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-nano",
    ],
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "o3-mini",
        "o4-mini",
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-nano",
    ],
    "gemini_cli": [
        "gemini-3.0-pro",
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
    ],
    "gemini": [
        "gemini-3.0-pro",
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
    ],
    "cursor": [
        "cursor-fast",
        "cursor-small",
        "gpt-4o",
        "claude-sonnet-4-6-20250918",
        "claude-sonnet-4-5-20250929",
    ],
    "copilot": [
        "gpt-4o",
        "gpt-4o-mini",
        "claude-sonnet-4-6-20250918",
        "claude-sonnet-4-5-20250929",
    ],
    "openrouter": [
        "anthropic/claude-opus-4-6",
        "anthropic/claude-sonnet-4-6",
        "anthropic/claude-sonnet-4-5",
        "anthropic/claude-haiku-4-5",
        "anthropic/claude-sonnet-4",
        "anthropic/claude-opus-4",
        "openai/gpt-4o",
        "google/gemini-3.0-pro",
        "google/gemini-2.5-pro",
        "google/gemini-2.5-flash",
        "meta-llama/llama-4-maverick",
        "deepseek/deepseek-r1",
    ],
    "together": [
        "meta-llama/Llama-3-70b-chat-hf",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "deepseek-ai/DeepSeek-R1",
        "Qwen/Qwen2.5-72B-Instruct-Turbo",
    ],
    "fireworks": [
        "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "accounts/fireworks/models/deepseek-r1",
    ],
    "iflow": ["kimi-k2"],
    "qwen_code": ["qwen3-coder", "qwen-max"],
    "ollama": ["llama3", "llama3.2", "mistral", "codellama", "deepseek-r1"],
    "lmstudio": ["local-model"],
}


@router.get("/available-models")
async def available_models():
    """Get list of available provider+model combinations for selection dropdowns."""
    from backend.core.smart_router import get_registry
    registry = get_registry()
    if not registry:
        return {"models": []}

    models = []
    for p in registry.get_all_providers():
        active = registry.get_active_accounts(p.id)
        if not active:
            continue
        models.append({
            "provider_id": p.id,
            "provider_name": p.name,
            "default_model": p.default_model,
            "tier": p.tier,
            "available_models": PROVIDER_MODELS.get(p.id, [p.default_model]),
        })

    # Sort by tier (paid first) then name
    models.sort(key=lambda m: (m["tier"], m["provider_name"]))
    return {"models": models}


@router.post("/detect-all")
async def detect_all_tokens():
    """Scan all CLI tools for available tokens."""
    from backend.core.smart_router import get_registry, get_extractor
    registry = get_registry()
    extractor = get_extractor()
    if not registry or not extractor:
        raise HTTPException(400, "Smart Router not enabled")

    tokens = extractor.detect_all()
    results = []
    for token in tokens:
        acct_id = registry.add_account(
            provider_id=token.provider_id,
            label=token.label,
            credential=token.token,
            credential_type=token.credential_type,
            source="cli_detect",
            refresh_token=token.refresh_token,
            expires_at=token.expires_at,
        )
        results.append({
            "provider_id": token.provider_id,
            "label": token.label,
            "account_id": acct_id,
        })

    return {
        "detected_count": len(results),
        "results": results,
    }


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/{provider_id}/toggle")
async def toggle_provider(provider_id: str, req: ToggleRequest):
    """Enable or disable a provider. Disabled providers are skipped by the router."""
    from backend.core.smart_router import get_registry
    registry = get_registry()
    if not registry:
        raise HTTPException(400, "Smart Router not enabled")

    success = registry.toggle_provider(provider_id, req.enabled)
    if not success:
        raise HTTPException(404, f"Unknown provider: {provider_id}")

    return {"success": True, "provider_id": provider_id, "enabled": req.enabled}


# Whitelist of env keys that can be modified via UI
ALLOWED_ENV_KEYS = {
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "NIM_API_KEY", "NIM_MODEL", "NIM_BASE_URL",
    "OPENROUTER_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY",
    "OLLAMA_HOST", "LMSTUDIO_HOST",
    "ENABLE_SMART_ROUTER", "ENABLE_REASONING", "ENABLE_CVE_HUNT",
    "ENABLE_MULTI_AGENT", "ENABLE_RESEARCHER_AI",
    "NVD_API_KEY", "GITHUB_TOKEN", "TOKEN_BUDGET",
}


class EnvUpdateRequest(BaseModel):
    key: str
    value: str


@router.get("/env")
async def get_env_keys():
    """Get current values of allowed env keys (masked for secrets)."""
    import os
    result = {}
    for key in sorted(ALLOWED_ENV_KEYS):
        val = os.getenv(key, "")
        if val and "KEY" in key and key not in ("ENABLE_SMART_ROUTER", "ENABLE_REASONING",
                                                  "ENABLE_CVE_HUNT", "ENABLE_MULTI_AGENT",
                                                  "ENABLE_RESEARCHER_AI", "TOKEN_BUDGET"):
            # Mask API keys: show first 8 and last 4 chars
            if len(val) > 16:
                result[key] = val[:8] + "..." + val[-4:]
            else:
                result[key] = "****"
        else:
            result[key] = val
    return {"env": result, "allowed_keys": sorted(ALLOWED_ENV_KEYS)}


@router.post("/env")
async def update_env_key(req: EnvUpdateRequest):
    """Update an env var and persist to .env file."""
    import os
    from pathlib import Path

    if req.key not in ALLOWED_ENV_KEYS:
        raise HTTPException(400, f"Key '{req.key}' is not in the allowed whitelist")

    # Update in-process env
    os.environ[req.key] = req.value

    # Persist to .env file
    env_path = Path(__file__).parent.parent.parent.parent / ".env"
    try:
        lines = []
        found = False
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                stripped = line.strip()
                if stripped.startswith(f"{req.key}=") or stripped.startswith(f"# {req.key}="):
                    lines.append(f"{req.key}={req.value}")
                    found = True
                else:
                    lines.append(line)
        if not found:
            lines.append(f"{req.key}={req.value}")
        env_path.write_text("\n".join(lines) + "\n")
    except Exception as e:
        # Still updated in-process even if file write failed
        return {"success": True, "persisted": False, "error": str(e)}

    return {"success": True, "persisted": True}
