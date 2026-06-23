"""
NeuroSploit v3 - Provider Registry

Central registry of 20 LLM providers + their accounts.
Persists metadata to data/providers.json (credentials stay in-memory only).
"""

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PROVIDERS_FILE = Path(__file__).parent.parent.parent.parent / "data" / "providers.json"


@dataclass
class Account:
    id: str
    label: str
    source: str  # "manual" | "cli_detect" | "env_var"
    credential_type: str  # "api_key" | "oauth"
    created_at: str = ""
    last_used: Optional[str] = None
    tokens_used: int = 0
    is_active: bool = True
    expires_at: Optional[float] = None  # Unix timestamp for OAuth tokens
    model_override: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "Account":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Provider:
    id: str
    name: str
    auth_type: str  # "api_key" | "oauth"
    api_format: str  # "anthropic" | "openai_compat" | "gemini" | "ollama"
    base_url: str
    tier: int  # 1=subscription/paid, 2=cheap, 3=free
    default_model: str
    accounts: Dict[str, Account] = field(default_factory=dict)
    env_key: Optional[str] = None  # e.g. "ANTHROPIC_API_KEY"
    enabled: bool = True  # UI toggle: disabled providers are skipped by router

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["accounts"] = {k: v.to_dict() if isinstance(v, Account) else v for k, v in self.accounts.items()}
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> "Provider":
        accounts_raw = data.pop("accounts", {})
        accounts = {}
        for k, v in accounts_raw.items():
            if isinstance(v, dict):
                accounts[k] = Account.from_dict(v)
            else:
                accounts[k] = v
        filtered = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(accounts=accounts, **filtered)


# Default provider definitions
DEFAULT_PROVIDERS: List[Dict] = [
    # === NVIDIA NIM Provider (Tier 2 - Free) ===
    {
        "id": "nim", "name": "NVIDIA NIM", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://integrate.api.nvidia.com/v1",
        "tier": 2, "default_model": os.getenv("NIM_MODEL", "openai/gpt-oss-120b"),
        "env_key": "NIM_API_KEY",
    },
    # === OAuth Providers (Tier 1 - Subscription) ===
    {
        "id": "claude_code", "name": "Claude Code", "auth_type": "oauth",
        "api_format": "anthropic", "base_url": "https://api.anthropic.com",
        "tier": 1, "default_model": "claude-sonnet-4-20250514",
    },
    {
        "id": "codex_cli", "name": "OpenAI Codex CLI", "auth_type": "oauth",
        "api_format": "openai_compat", "base_url": "https://api.openai.com/v1",
        "tier": 1, "default_model": "gpt-4o",
    },
    {
        "id": "gemini_cli", "name": "Gemini CLI", "auth_type": "oauth",
        "api_format": "gemini_code_assist", "base_url": "https://cloudcode-pa.googleapis.com",
        "tier": 1, "default_model": "gemini-2.5-flash",
    },
    {
        "id": "cursor", "name": "Cursor", "auth_type": "oauth",
        "api_format": "openai_compat", "base_url": "https://api2.cursor.sh/v1",
        "tier": 1, "default_model": "cursor-fast",
    },
    {
        "id": "copilot", "name": "GitHub Copilot", "auth_type": "oauth",
        "api_format": "openai_compat", "base_url": "https://api.githubcopilot.com",
        "tier": 1, "default_model": "gpt-4o",
    },
    {
        "id": "iflow", "name": "iFlow AI", "auth_type": "oauth",
        "api_format": "openai_compat", "base_url": "https://api.iflow.ai/v1",
        "tier": 1, "default_model": "kimi-k2",
    },
    {
        "id": "qwen_code", "name": "Qwen Code", "auth_type": "oauth",
        "api_format": "openai_compat", "base_url": "https://chat.qwen.ai/api/v1",
        "tier": 1, "default_model": "qwen3-coder",
    },
    {
        "id": "kiro", "name": "Kiro AI", "auth_type": "oauth",
        "api_format": "anthropic", "base_url": "https://api.anthropic.com",
        "tier": 1, "default_model": "claude-sonnet-4-20250514",
    },
    # === API Key Providers (Tier 1 - Paid) ===
    {
        "id": "anthropic", "name": "Anthropic", "auth_type": "api_key",
        "api_format": "anthropic", "base_url": "https://api.anthropic.com",
        "tier": 1, "default_model": "claude-sonnet-4-20250514",
        "env_key": "ANTHROPIC_API_KEY",
    },
    {
        "id": "openai", "name": "OpenAI", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://api.openai.com/v1",
        "tier": 1, "default_model": "gpt-4o",
        "env_key": "OPENAI_API_KEY",
    },
    {
        "id": "gemini", "name": "Gemini", "auth_type": "api_key",
        "api_format": "gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "tier": 1, "default_model": "gemini-2.5-flash",
        "env_key": "GEMINI_API_KEY",
    },
    {
        "id": "openrouter", "name": "OpenRouter", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://openrouter.ai/api/v1",
        "tier": 1, "default_model": "anthropic/claude-sonnet-4-20250514",
        "env_key": "OPENROUTER_API_KEY",
    },
    # === API Key Providers (Tier 2 - Cheap) ===
    {
        "id": "glm", "name": "GLM (Zhipu AI)", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "tier": 2, "default_model": "glm-4-flash",
        "env_key": "GLM_API_KEY",
    },
    {
        "id": "kimi", "name": "Kimi (Moonshot)", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://api.moonshot.cn/v1",
        "tier": 2, "default_model": "moonshot-v1-8k",
        "env_key": "KIMI_API_KEY",
    },
    {
        "id": "minimax", "name": "Minimax", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://api.minimax.chat/v1",
        "tier": 2, "default_model": "abab6.5-chat",
        "env_key": "MINIMAX_API_KEY",
    },
    {
        "id": "together", "name": "Together AI", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://api.together.xyz/v1",
        "tier": 2, "default_model": "meta-llama/Llama-3-70b-chat-hf",
        "env_key": "TOGETHER_API_KEY",
    },
    {
        "id": "fireworks", "name": "Fireworks AI", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "https://api.fireworks.ai/inference/v1",
        "tier": 2, "default_model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "env_key": "FIREWORKS_API_KEY",
    },
    # === Local Providers (Tier 3 - Free/Self-hosted) ===
    {
        "id": "ollama", "name": "Ollama", "auth_type": "api_key",
        "api_format": "ollama", "base_url": "http://localhost:11434",
        "tier": 3, "default_model": "llama3",
        "env_key": "OLLAMA_API_KEY",
    },
    {
        "id": "lmstudio", "name": "LM Studio", "auth_type": "api_key",
        "api_format": "openai_compat", "base_url": "http://localhost:1234/v1",
        "tier": 3, "default_model": "local-model",
        "env_key": "LMSTUDIO_API_KEY",
    },
]


class ProviderRegistry:
    """Central registry for LLM providers and their accounts.

    Metadata persists to data/providers.json.
    Credentials are kept IN-MEMORY ONLY for security (re-extracted from CLI on startup).
    """

    def __init__(self):
        self._providers: Dict[str, Provider] = {}
        self._credentials: Dict[str, str] = {}  # acct_id -> credential (IN-MEMORY)
        self._refresh_tokens: Dict[str, str] = {}  # acct_id -> refresh_token (IN-MEMORY)
        self._seed_defaults()
        self._load()
        self._seed_env_credentials()
        self._restore_cli_credentials()

    # ── Seeding ──────────────────────────────────────────────

    def _seed_defaults(self):
        """Register built-in provider definitions."""
        for pdef in DEFAULT_PROVIDERS:
            pid = pdef["id"]
            if pid not in self._providers:
                self._providers[pid] = Provider(
                    id=pid,
                    name=pdef["name"],
                    auth_type=pdef["auth_type"],
                    api_format=pdef["api_format"],
                    base_url=pdef["base_url"],
                    tier=pdef["tier"],
                    default_model=pdef["default_model"],
                    env_key=pdef.get("env_key"),
                )

    def _seed_env_credentials(self):
        """Auto-load credentials from environment variables."""
        for pid, provider in self._providers.items():
            if not provider.env_key:
                continue
            value = os.getenv(provider.env_key, "").strip()
            if not value:
                continue
            # Check if we already have an env_var account
            existing = [a for a in provider.accounts.values() if a.source == "env_var"]
            if existing:
                acct = existing[0]
                # Update credential in memory
                self._credentials[acct.id] = value
                # Reactivate if deactivated — env key is set, it should be active
                if not acct.is_active:
                    acct.is_active = True
                    logger.info(f"SmartRouter: Reactivated {acct.label} (env key present)")
                continue
            # Create new env_var account
            acct_id = f"acct_{uuid.uuid4().hex[:8]}"
            acct = Account(
                id=acct_id,
                label=f"{provider.name} (env)",
                source="env_var",
                credential_type="api_key",
            )
            provider.accounts[acct_id] = acct
            self._credentials[acct_id] = value
            logger.info(f"SmartRouter: Loaded {provider.env_key} for {provider.name}")
        self._save()

    def _restore_cli_credentials(self):
        """Re-extract CLI tokens on startup for cli_detect accounts.

        CLI tokens are never persisted to disk. On restart, we re-detect
        them from the CLI tools (same files TokenExtractor reads).
        Also reactivates accounts that were deactivated due to expired tokens.
        """
        try:
            from .token_extractor import TokenExtractor
            extractor = TokenExtractor()
        except ImportError:
            return

        restored = 0
        for pid, provider in self._providers.items():
            cli_accounts = [a for a in provider.accounts.values() if a.source == "cli_detect"]
            if not cli_accounts:
                continue

            # Try to re-extract token for this provider
            token = extractor.detect(pid)
            if not token:
                logger.debug(f"SmartRouter: No CLI token found for {provider.name}")
                continue

            # Update the first cli_detect account (remove duplicates)
            primary = cli_accounts[0]
            self._credentials[primary.id] = token.token
            if token.refresh_token:
                self._refresh_tokens[primary.id] = token.refresh_token

            # Update expires_at (token_extractor may have parsed it from the credential file)
            if token.expires_at:
                primary.expires_at = token.expires_at
            elif primary.expires_at is None and token.credential_type == "oauth":
                # OAuth tokens without expiry — assume 1 hour from now as a hint
                # so the TokenRefresher will check and refresh them
                import time as _time
                primary.expires_at = _time.time() + 3600
                logger.debug(f"SmartRouter: Set default 1h expiry for {primary.label}")

            # Reactivate if it was deactivated (token may have been refreshed externally)
            if not primary.is_active:
                primary.is_active = True
                logger.info(f"SmartRouter: Reactivated {primary.label} (fresh token found)")

            # Remove duplicate cli_detect accounts (keep only primary)
            for dup in cli_accounts[1:]:
                del provider.accounts[dup.id]
                self._credentials.pop(dup.id, None)
                self._refresh_tokens.pop(dup.id, None)
                logger.info(f"SmartRouter: Removed duplicate account {dup.id} for {provider.name}")

            restored += 1
            logger.info(
                f"SmartRouter: Restored CLI credential for {provider.name} "
                f"(token={'***' + token.token[-8:]}, refresh={'yes' if token.refresh_token else 'no'}, "
                f"expires={primary.expires_at})"
            )

        if restored:
            self._save()
            logger.info(f"SmartRouter: Restored {restored} CLI provider(s)")

    # ── CRUD ─────────────────────────────────────────────────

    def add_account(
        self,
        provider_id: str,
        label: str,
        credential: str,
        credential_type: str = "api_key",
        source: str = "manual",
        refresh_token: Optional[str] = None,
        expires_at: Optional[float] = None,
        model_override: Optional[str] = None,
    ) -> Optional[str]:
        """Add a new account to a provider. Returns account ID or None."""
        provider = self._providers.get(provider_id)
        if not provider:
            logger.warning(f"SmartRouter: Unknown provider {provider_id}")
            return None

        # Deduplicate: if a cli_detect account already exists, update it instead
        if source == "cli_detect":
            existing = [a for a in provider.accounts.values() if a.source == "cli_detect"]
            if existing:
                acct = existing[0]
                self._credentials[acct.id] = credential
                if refresh_token:
                    self._refresh_tokens[acct.id] = refresh_token
                acct.expires_at = expires_at
                acct.is_active = True
                self._save()
                logger.info(f"SmartRouter: Updated existing CLI account {acct.label} for {provider.name}")
                return acct.id

        acct_id = f"acct_{uuid.uuid4().hex[:8]}"
        acct = Account(
            id=acct_id,
            label=label,
            source=source,
            credential_type=credential_type,
            expires_at=expires_at,
            model_override=model_override,
        )
        provider.accounts[acct_id] = acct
        self._credentials[acct_id] = credential
        if refresh_token:
            self._refresh_tokens[acct_id] = refresh_token

        self._save()
        logger.info(f"SmartRouter: Added account {label} to {provider.name}")
        return acct_id

    def remove_account(self, provider_id: str, account_id: str) -> bool:
        """Remove an account from a provider."""
        provider = self._providers.get(provider_id)
        if not provider or account_id not in provider.accounts:
            return False

        del provider.accounts[account_id]
        self._credentials.pop(account_id, None)
        self._refresh_tokens.pop(account_id, None)
        self._save()
        logger.info(f"SmartRouter: Removed account {account_id} from {provider.name}")
        return True

    def get_credential(self, account_id: str) -> Optional[str]:
        """Get credential for an account (from memory only)."""
        return self._credentials.get(account_id)

    def get_refresh_token(self, account_id: str) -> Optional[str]:
        """Get refresh token for an account (from memory only)."""
        return self._refresh_tokens.get(account_id)

    def update_credential(
        self,
        account_id: str,
        new_credential: str,
        new_expires_at: Optional[float] = None,
    ):
        """Update credential (and optionally expiry) for an account."""
        self._credentials[account_id] = new_credential
        # Update expiry on the account object
        for provider in self._providers.values():
            if account_id in provider.accounts:
                provider.accounts[account_id].expires_at = new_expires_at
                self._save()
                break

    def deactivate_account(self, account_id: str):
        """Mark account as inactive (e.g., on 401/403)."""
        for provider in self._providers.values():
            if account_id in provider.accounts:
                provider.accounts[account_id].is_active = False
                self._save()
                logger.warning(f"SmartRouter: Deactivated account {account_id}")
                break

    def reactivate_account(self, account_id: str) -> bool:
        """Re-activate a deactivated account (e.g., after token refresh)."""
        for provider in self._providers.values():
            if account_id in provider.accounts:
                acct = provider.accounts[account_id]
                if not acct.is_active:
                    acct.is_active = True
                    self._save()
                    logger.info(f"SmartRouter: Reactivated account {account_id}")
                return True
        return False

    # ── Queries ──────────────────────────────────────────────

    def get_active_accounts(self, provider_id: str) -> List[Account]:
        """Get all active accounts for a provider."""
        provider = self._providers.get(provider_id)
        if not provider:
            return []
        return [
            a for a in provider.accounts.values()
            if a.is_active and a.id in self._credentials
        ]

    def get_provider(self, provider_id: str) -> Optional[Provider]:
        """Get a provider by ID."""
        return self._providers.get(provider_id)

    def get_providers_by_tier(self, tier: int) -> List[Provider]:
        """Get all providers in a tier that have active accounts."""
        return [
            p for p in self._providers.values()
            if p.tier == tier and self.get_active_accounts(p.id)
        ]

    def get_all_providers(self) -> List[Provider]:
        """Get all registered providers."""
        return list(self._providers.values())

    def toggle_provider(self, provider_id: str, enabled: bool) -> bool:
        """Enable or disable a provider. Disabled providers are skipped by the router."""
        provider = self._providers.get(provider_id)
        if not provider:
            return False
        provider.enabled = enabled
        self._save()
        logger.info(f"Provider {provider_id} {'enabled' if enabled else 'disabled'}")
        return True

    def get_all_status(self) -> List[Dict]:
        """Get status summary for all providers (for API/UI)."""
        result = []
        for p in self._providers.values():
            active = self.get_active_accounts(p.id)
            total_tokens = sum(a.tokens_used for a in p.accounts.values())
            result.append({
                "id": p.id,
                "name": p.name,
                "auth_type": p.auth_type,
                "api_format": p.api_format,
                "tier": p.tier,
                "default_model": p.default_model,
                "accounts_total": len(p.accounts),
                "accounts_active": len(active),
                "total_tokens_used": total_tokens,
                "connected": len(active) > 0,
                "enabled": getattr(p, "enabled", True),
            })
        return result

    def record_usage(self, account_id: str, tokens: int):
        """Record token usage for an account."""
        for provider in self._providers.values():
            if account_id in provider.accounts:
                provider.accounts[account_id].tokens_used += tokens
                provider.accounts[account_id].last_used = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                )
                # Save periodically (every 10th call to avoid I/O spam)
                if provider.accounts[account_id].tokens_used % 10000 < tokens:
                    self._save()
                break

    # ── Persistence ──────────────────────────────────────────

    def _save(self):
        """Save provider metadata to JSON (NO credentials)."""
        try:
            PROVIDERS_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {
                pid: p.to_dict()
                for pid, p in self._providers.items()
            }
            tmp = PROVIDERS_FILE.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(data, f, indent=2, default=str)
            tmp.rename(PROVIDERS_FILE)
        except Exception as e:
            logger.warning(f"SmartRouter: Failed to save providers: {e}")

    def _load(self):
        """Load provider metadata from JSON, merge with defaults."""
        if not PROVIDERS_FILE.exists():
            return
        try:
            with open(PROVIDERS_FILE) as f:
                data = json.load(f)
            for pid, pdata in data.items():
                if pid in self._providers:
                    # Merge accounts from disk into existing provider
                    saved_accounts = pdata.get("accounts", {})
                    for aid, adata in saved_accounts.items():
                        if isinstance(adata, dict):
                            self._providers[pid].accounts[aid] = Account.from_dict(adata)
                else:
                    # Unknown provider from disk - load it
                    self._providers[pid] = Provider.from_dict(pdata)
            logger.info(f"SmartRouter: Loaded {len(data)} providers from disk")
        except Exception as e:
            logger.warning(f"SmartRouter: Failed to load providers: {e}")
