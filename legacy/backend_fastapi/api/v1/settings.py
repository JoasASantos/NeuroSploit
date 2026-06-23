"""
NeuroSploit v3 - Settings API Endpoints
"""
import os
import re
import time
from pathlib import Path
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, text
from pydantic import BaseModel

from backend.db.database import get_db, engine
from backend.models import Scan, Target, Endpoint, Vulnerability, VulnerabilityTest, Report

router = APIRouter()

# Path to .env file (project root)
ENV_FILE_PATH = Path(__file__).parent.parent.parent.parent / ".env"


def _update_env_file(updates: Dict[str, str]) -> bool:
    """
    Update key=value pairs in the .env file without breaking formatting.
    - If the key exists (even commented out), update its value
    - If the key doesn't exist, append it
    - Preserves comments and blank lines
    """
    if not ENV_FILE_PATH.exists():
        return False

    try:
        lines = ENV_FILE_PATH.read_text().splitlines()
        updated_keys = set()

        new_lines = []
        for line in lines:
            stripped = line.strip()
            matched = False

            for key, value in updates.items():
                # Match: KEY=..., # KEY=..., #KEY=...
                pattern = rf'^#?\s*{re.escape(key)}\s*='
                if re.match(pattern, stripped):
                    # Replace with uncommented key=value
                    new_lines.append(f"{key}={value}")
                    updated_keys.add(key)
                    matched = True
                    break

            if not matched:
                new_lines.append(line)

        # Append any keys that weren't found in existing file
        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={value}")

        # Write back with trailing newline
        ENV_FILE_PATH.write_text("\n".join(new_lines) + "\n")
        return True
    except Exception as e:
        print(f"Warning: Failed to update .env file: {e}")
        return False


class SettingsUpdate(BaseModel):
    """Settings update schema"""
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    nim_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    together_api_key: Optional[str] = None
    fireworks_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = None
    lmstudio_base_url: Optional[str] = None
    max_concurrent_scans: Optional[int] = None
    aggressive_mode: Optional[bool] = None
    default_scan_type: Optional[str] = None
    recon_enabled_by_default: Optional[bool] = None
    enable_model_routing: Optional[bool] = None
    enable_knowledge_augmentation: Optional[bool] = None
    enable_browser_validation: Optional[bool] = None
    max_output_tokens: Optional[int] = None
    # Notifications
    enable_notifications: Optional[bool] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_from_number: Optional[str] = None
    twilio_to_number: Optional[str] = None
    notification_severity_filter: Optional[str] = None


class SettingsResponse(BaseModel):
    """Settings response schema"""
    llm_provider: str = "claude"
    llm_model: str = ""
    has_anthropic_key: bool = False
    has_openai_key: bool = False
    has_nim_key: bool = False
    has_openrouter_key: bool = False
    has_gemini_key: bool = False
    has_together_key: bool = False
    has_fireworks_key: bool = False
    ollama_base_url: str = ""
    lmstudio_base_url: str = ""
    max_concurrent_scans: int = 3
    aggressive_mode: bool = False
    default_scan_type: str = "full"
    recon_enabled_by_default: bool = True
    enable_model_routing: bool = False
    enable_knowledge_augmentation: bool = False
    enable_browser_validation: bool = False
    max_output_tokens: Optional[int] = None
    # Notifications
    enable_notifications: bool = False
    has_discord_webhook: bool = False
    has_telegram_bot: bool = False
    has_twilio_credentials: bool = False
    notification_severity_filter: str = "critical,high"


class ModelInfo(BaseModel):
    """Info about an available LLM model"""
    provider: str
    model_id: str
    display_name: str
    size: Optional[str] = None
    context_length: Optional[int] = None
    is_local: bool = False


class ModelCatalogResponse(BaseModel):
    """Response from model catalog endpoint"""
    provider: str
    models: List[ModelInfo]
    available: bool
    error: Optional[str] = None


def _load_settings_from_env() -> dict:
    """
    Load settings from environment variables / .env file on startup.
    This ensures settings persist across server restarts and browser sessions.
    """
    from dotenv import load_dotenv
    # Re-read .env file to pick up disk-persisted values
    if ENV_FILE_PATH.exists():
        load_dotenv(ENV_FILE_PATH, override=True)

    def _env_bool(key: str, default: bool = False) -> bool:
        val = os.getenv(key, "").strip().lower()
        if val in ("true", "1", "yes"):
            return True
        if val in ("false", "0", "no"):
            return False
        return default

    def _env_int(key: str, default=None):
        val = os.getenv(key, "").strip()
        if val:
            try:
                return int(val)
            except ValueError:
                pass
        return default

    # Detect provider from which keys are set
    provider = "claude"
    if os.getenv("NIM_API_KEY"):
        provider = "nim"
    elif os.getenv("ANTHROPIC_API_KEY"):
        provider = "claude"
    elif os.getenv("OPENAI_API_KEY"):
        provider = "openai"
    elif os.getenv("OPENROUTER_API_KEY"):
        provider = "openrouter"

    return {
        "llm_provider": provider,
        "llm_model": os.getenv("DEFAULT_LLM_MODEL", ""),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
        "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
        "nim_api_key": os.getenv("NIM_API_KEY", ""),
        "openrouter_api_key": os.getenv("OPENROUTER_API_KEY", ""),
        "gemini_api_key": os.getenv("GEMINI_API_KEY", ""),
        "together_api_key": os.getenv("TOGETHER_API_KEY", ""),
        "fireworks_api_key": os.getenv("FIREWORKS_API_KEY", ""),
        "ollama_base_url": os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_URL", "")),
        "lmstudio_base_url": os.getenv("LMSTUDIO_BASE_URL", os.getenv("LMSTUDIO_URL", "")),
        "max_concurrent_scans": _env_int("MAX_CONCURRENT_SCANS", 3),
        "aggressive_mode": _env_bool("AGGRESSIVE_MODE", False),
        "default_scan_type": os.getenv("DEFAULT_SCAN_TYPE", "full"),
        "recon_enabled_by_default": _env_bool("RECON_ENABLED_BY_DEFAULT", True),
        "enable_model_routing": _env_bool("ENABLE_MODEL_ROUTING", False),
        "enable_knowledge_augmentation": _env_bool("ENABLE_KNOWLEDGE_AUGMENTATION", False),
        "enable_browser_validation": _env_bool("ENABLE_BROWSER_VALIDATION", False),
        "max_output_tokens": _env_int("MAX_OUTPUT_TOKENS", None),
        # Notifications
        "enable_notifications": _env_bool("ENABLE_NOTIFICATIONS", False),
        "discord_webhook_url": os.getenv("DISCORD_WEBHOOK_URL", ""),
        "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
        "twilio_account_sid": os.getenv("TWILIO_ACCOUNT_SID", ""),
        "twilio_auth_token": os.getenv("TWILIO_AUTH_TOKEN", ""),
        "twilio_from_number": os.getenv("TWILIO_FROM_NUMBER", ""),
        "twilio_to_number": os.getenv("TWILIO_TO_NUMBER", ""),
        "notification_severity_filter": os.getenv("NOTIFICATION_SEVERITY_FILTER", "critical,high"),
    }


# Load settings from .env on module import (server start)
_settings = _load_settings_from_env()


@router.get("", response_model=SettingsResponse)
async def get_settings():
    """Get current settings"""
    import os
    return SettingsResponse(
        llm_provider=_settings["llm_provider"],
        llm_model=_settings.get("llm_model", ""),
        has_anthropic_key=bool(_settings["anthropic_api_key"] or os.getenv("ANTHROPIC_API_KEY")),
        has_openai_key=bool(_settings["openai_api_key"] or os.getenv("OPENAI_API_KEY")),
        has_nim_key=bool(_settings.get("nim_api_key") or os.getenv("NIM_API_KEY")),
        has_openrouter_key=bool(_settings["openrouter_api_key"] or os.getenv("OPENROUTER_API_KEY")),
        has_gemini_key=bool(_settings.get("gemini_api_key") or os.getenv("GEMINI_API_KEY")),
        has_together_key=bool(_settings.get("together_api_key") or os.getenv("TOGETHER_API_KEY")),
        has_fireworks_key=bool(_settings.get("fireworks_api_key") or os.getenv("FIREWORKS_API_KEY")),
        ollama_base_url=_settings.get("ollama_base_url", ""),
        lmstudio_base_url=_settings.get("lmstudio_base_url", ""),
        max_concurrent_scans=_settings["max_concurrent_scans"],
        aggressive_mode=_settings["aggressive_mode"],
        default_scan_type=_settings["default_scan_type"],
        recon_enabled_by_default=_settings["recon_enabled_by_default"],
        enable_model_routing=_settings["enable_model_routing"],
        enable_knowledge_augmentation=_settings["enable_knowledge_augmentation"],
        enable_browser_validation=_settings["enable_browser_validation"],
        max_output_tokens=_settings["max_output_tokens"],
        # Notifications
        enable_notifications=_settings.get("enable_notifications", False),
        has_discord_webhook=bool(_settings.get("discord_webhook_url")),
        has_telegram_bot=bool(_settings.get("telegram_bot_token") and _settings.get("telegram_chat_id")),
        has_twilio_credentials=bool(
            _settings.get("twilio_account_sid") and _settings.get("twilio_auth_token")
            and _settings.get("twilio_from_number") and _settings.get("twilio_to_number")
        ),
        notification_severity_filter=_settings.get("notification_severity_filter", "critical,high"),
    )


@router.put("", response_model=SettingsResponse)
async def update_settings(settings_data: SettingsUpdate):
    """Update settings - persists to memory, env vars, AND .env file"""
    env_updates: Dict[str, str] = {}

    if settings_data.llm_provider is not None:
        _settings["llm_provider"] = settings_data.llm_provider

    if settings_data.llm_model is not None:
        _settings["llm_model"] = settings_data.llm_model
        os.environ["DEFAULT_LLM_MODEL"] = settings_data.llm_model
        env_updates["DEFAULT_LLM_MODEL"] = settings_data.llm_model

    if settings_data.anthropic_api_key is not None:
        _settings["anthropic_api_key"] = settings_data.anthropic_api_key
        if settings_data.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key
            env_updates["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key

    if settings_data.openai_api_key is not None:
        _settings["openai_api_key"] = settings_data.openai_api_key
        if settings_data.openai_api_key:
            os.environ["OPENAI_API_KEY"] = settings_data.openai_api_key
            env_updates["OPENAI_API_KEY"] = settings_data.openai_api_key

    if settings_data.nim_api_key is not None:
        _settings["nim_api_key"] = settings_data.nim_api_key
        if settings_data.nim_api_key:
            os.environ["NIM_API_KEY"] = settings_data.nim_api_key
            env_updates["NIM_API_KEY"] = settings_data.nim_api_key

    if settings_data.openrouter_api_key is not None:
        _settings["openrouter_api_key"] = settings_data.openrouter_api_key
        if settings_data.openrouter_api_key:
            os.environ["OPENROUTER_API_KEY"] = settings_data.openrouter_api_key
            env_updates["OPENROUTER_API_KEY"] = settings_data.openrouter_api_key

    if settings_data.gemini_api_key is not None:
        _settings["gemini_api_key"] = settings_data.gemini_api_key
        if settings_data.gemini_api_key:
            os.environ["GEMINI_API_KEY"] = settings_data.gemini_api_key
            env_updates["GEMINI_API_KEY"] = settings_data.gemini_api_key

    if settings_data.together_api_key is not None:
        _settings["together_api_key"] = settings_data.together_api_key
        if settings_data.together_api_key:
            os.environ["TOGETHER_API_KEY"] = settings_data.together_api_key
            env_updates["TOGETHER_API_KEY"] = settings_data.together_api_key

    if settings_data.fireworks_api_key is not None:
        _settings["fireworks_api_key"] = settings_data.fireworks_api_key
        if settings_data.fireworks_api_key:
            os.environ["FIREWORKS_API_KEY"] = settings_data.fireworks_api_key
            env_updates["FIREWORKS_API_KEY"] = settings_data.fireworks_api_key

    if settings_data.ollama_base_url is not None:
        _settings["ollama_base_url"] = settings_data.ollama_base_url
        if settings_data.ollama_base_url:
            os.environ["OLLAMA_BASE_URL"] = settings_data.ollama_base_url
            env_updates["OLLAMA_BASE_URL"] = settings_data.ollama_base_url

    if settings_data.lmstudio_base_url is not None:
        _settings["lmstudio_base_url"] = settings_data.lmstudio_base_url
        if settings_data.lmstudio_base_url:
            os.environ["LMSTUDIO_BASE_URL"] = settings_data.lmstudio_base_url
            env_updates["LMSTUDIO_BASE_URL"] = settings_data.lmstudio_base_url

    if settings_data.max_concurrent_scans is not None:
        _settings["max_concurrent_scans"] = settings_data.max_concurrent_scans

    if settings_data.aggressive_mode is not None:
        _settings["aggressive_mode"] = settings_data.aggressive_mode

    if settings_data.default_scan_type is not None:
        _settings["default_scan_type"] = settings_data.default_scan_type

    if settings_data.recon_enabled_by_default is not None:
        _settings["recon_enabled_by_default"] = settings_data.recon_enabled_by_default

    if settings_data.enable_model_routing is not None:
        _settings["enable_model_routing"] = settings_data.enable_model_routing
        val = str(settings_data.enable_model_routing).lower()
        os.environ["ENABLE_MODEL_ROUTING"] = val
        env_updates["ENABLE_MODEL_ROUTING"] = val

    if settings_data.enable_knowledge_augmentation is not None:
        _settings["enable_knowledge_augmentation"] = settings_data.enable_knowledge_augmentation
        val = str(settings_data.enable_knowledge_augmentation).lower()
        os.environ["ENABLE_KNOWLEDGE_AUGMENTATION"] = val
        env_updates["ENABLE_KNOWLEDGE_AUGMENTATION"] = val

    if settings_data.enable_browser_validation is not None:
        _settings["enable_browser_validation"] = settings_data.enable_browser_validation
        val = str(settings_data.enable_browser_validation).lower()
        os.environ["ENABLE_BROWSER_VALIDATION"] = val
        env_updates["ENABLE_BROWSER_VALIDATION"] = val

    if settings_data.max_output_tokens is not None:
        _settings["max_output_tokens"] = settings_data.max_output_tokens
        if settings_data.max_output_tokens:
            os.environ["MAX_OUTPUT_TOKENS"] = str(settings_data.max_output_tokens)
            env_updates["MAX_OUTPUT_TOKENS"] = str(settings_data.max_output_tokens)

    # Notifications
    if settings_data.enable_notifications is not None:
        _settings["enable_notifications"] = settings_data.enable_notifications
        val = str(settings_data.enable_notifications).lower()
        os.environ["ENABLE_NOTIFICATIONS"] = val
        env_updates["ENABLE_NOTIFICATIONS"] = val

    if settings_data.discord_webhook_url is not None:
        _settings["discord_webhook_url"] = settings_data.discord_webhook_url
        os.environ["DISCORD_WEBHOOK_URL"] = settings_data.discord_webhook_url
        env_updates["DISCORD_WEBHOOK_URL"] = settings_data.discord_webhook_url

    if settings_data.telegram_bot_token is not None:
        _settings["telegram_bot_token"] = settings_data.telegram_bot_token
        os.environ["TELEGRAM_BOT_TOKEN"] = settings_data.telegram_bot_token
        env_updates["TELEGRAM_BOT_TOKEN"] = settings_data.telegram_bot_token

    if settings_data.telegram_chat_id is not None:
        _settings["telegram_chat_id"] = settings_data.telegram_chat_id
        os.environ["TELEGRAM_CHAT_ID"] = settings_data.telegram_chat_id
        env_updates["TELEGRAM_CHAT_ID"] = settings_data.telegram_chat_id

    if settings_data.twilio_account_sid is not None:
        _settings["twilio_account_sid"] = settings_data.twilio_account_sid
        os.environ["TWILIO_ACCOUNT_SID"] = settings_data.twilio_account_sid
        env_updates["TWILIO_ACCOUNT_SID"] = settings_data.twilio_account_sid

    if settings_data.twilio_auth_token is not None:
        _settings["twilio_auth_token"] = settings_data.twilio_auth_token
        os.environ["TWILIO_AUTH_TOKEN"] = settings_data.twilio_auth_token
        env_updates["TWILIO_AUTH_TOKEN"] = settings_data.twilio_auth_token

    if settings_data.twilio_from_number is not None:
        _settings["twilio_from_number"] = settings_data.twilio_from_number
        os.environ["TWILIO_FROM_NUMBER"] = settings_data.twilio_from_number
        env_updates["TWILIO_FROM_NUMBER"] = settings_data.twilio_from_number

    if settings_data.twilio_to_number is not None:
        _settings["twilio_to_number"] = settings_data.twilio_to_number
        os.environ["TWILIO_TO_NUMBER"] = settings_data.twilio_to_number
        env_updates["TWILIO_TO_NUMBER"] = settings_data.twilio_to_number

    if settings_data.notification_severity_filter is not None:
        _settings["notification_severity_filter"] = settings_data.notification_severity_filter
        os.environ["NOTIFICATION_SEVERITY_FILTER"] = settings_data.notification_severity_filter
        env_updates["NOTIFICATION_SEVERITY_FILTER"] = settings_data.notification_severity_filter

    # Persist to .env file on disk
    if env_updates:
        _update_env_file(env_updates)

    # Reload notification config if any notification-related fields changed
    try:
        from backend.core.notification_manager import notification_manager
        notification_manager.reload_config()
    except ImportError:
        pass

    return await get_settings()


@router.post("/notifications/test/{channel}")
async def test_notification_channel(channel: str):
    """Send a test notification to a specific channel (discord, telegram, whatsapp)."""
    try:
        from backend.core.notification_manager import notification_manager
        result = await notification_manager.test_channel(channel)
        return result
    except ImportError:
        raise HTTPException(500, "Notification manager not available")


@router.post("/clear-database")
async def clear_database(db: AsyncSession = Depends(get_db)):
    """Clear all data from the database (reset to fresh state)"""
    try:
        # Delete in correct order to respect foreign key constraints
        await db.execute(delete(VulnerabilityTest))
        await db.execute(delete(Vulnerability))
        await db.execute(delete(Endpoint))
        await db.execute(delete(Report))
        await db.execute(delete(Target))
        await db.execute(delete(Scan))
        await db.commit()

        return {
            "message": "Database cleared successfully",
            "status": "success"
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to clear database: {str(e)}")


@router.get("/stats")
async def get_database_stats(db: AsyncSession = Depends(get_db)):
    """Get database statistics"""
    from sqlalchemy import func

    scans_count = (await db.execute(select(func.count()).select_from(Scan))).scalar() or 0
    vulns_count = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar() or 0
    endpoints_count = (await db.execute(select(func.count()).select_from(Endpoint))).scalar() or 0
    reports_count = (await db.execute(select(func.count()).select_from(Report))).scalar() or 0

    return {
        "scans": scans_count,
        "vulnerabilities": vulns_count,
        "endpoints": endpoints_count,
        "reports": reports_count
    }


@router.get("/tools")
async def get_installed_tools():
    """Check which security tools are installed"""
    import asyncio
    import shutil

    # Complete list of 40+ tools
    tools = {
        "recon": [
            "subfinder", "amass", "assetfinder", "chaos", "uncover",
            "dnsx", "massdns", "puredns", "cero", "tlsx", "cdncheck"
        ],
        "web_discovery": [
            "httpx", "httprobe", "katana", "gospider", "hakrawler",
            "gau", "waybackurls", "cariddi", "getJS", "gowitness"
        ],
        "fuzzing": [
            "ffuf", "gobuster", "dirb", "dirsearch", "wfuzz", "arjun", "paramspider"
        ],
        "vulnerability_scanning": [
            "nuclei", "nikto", "sqlmap", "xsstrike", "dalfox", "crlfuzz"
        ],
        "port_scanning": [
            "nmap", "naabu", "rustscan"
        ],
        "utilities": [
            "gf", "qsreplace", "unfurl", "anew", "uro", "jq"
        ],
        "tech_detection": [
            "whatweb", "wafw00f"
        ],
        "exploitation": [
            "hydra", "medusa", "john", "hashcat"
        ],
        "network": [
            "curl", "wget", "dig", "whois"
        ]
    }

    results = {}
    total_installed = 0
    total_tools = 0

    for category, tool_list in tools.items():
        results[category] = {}
        for tool in tool_list:
            total_tools += 1
            # Check if tool exists in PATH
            is_installed = shutil.which(tool) is not None
            results[category][tool] = is_installed
            if is_installed:
                total_installed += 1

    return {
        "tools": results,
        "summary": {
            "total": total_tools,
            "installed": total_installed,
            "missing": total_tools - total_installed,
            "percentage": round((total_installed / total_tools) * 100, 1)
        }
    }


# --- Model Catalog ---

# Cache for model catalog queries (60-second TTL)
_model_cache: Dict[str, dict] = {}
_model_cache_time: Dict[str, float] = {}
MODEL_CACHE_TTL = 60  # seconds

# Common cloud models for dropdown suggestions
CLOUD_MODELS = {
    "claude": [
        {"model_id": "claude-opus-4-6-20250918", "display_name": "Claude Opus 4.6", "context_length": 1000000},
        {"model_id": "claude-sonnet-4-6-20250918", "display_name": "Claude Sonnet 4.6", "context_length": 1000000},
        {"model_id": "claude-sonnet-4-5-20250929", "display_name": "Claude Sonnet 4.5", "context_length": 200000},
        {"model_id": "claude-haiku-4-5-20251001", "display_name": "Claude Haiku 4.5", "context_length": 200000},
        {"model_id": "claude-sonnet-4-20250514", "display_name": "Claude Sonnet 4", "context_length": 200000},
        {"model_id": "claude-opus-4-20250514", "display_name": "Claude Opus 4", "context_length": 200000},
    ],
    "openai": [
        {"model_id": "gpt-4o", "display_name": "GPT-4o", "context_length": 128000},
        {"model_id": "gpt-4o-mini", "display_name": "GPT-4o Mini", "context_length": 128000},
        {"model_id": "gpt-4.1", "display_name": "GPT-4.1", "context_length": 1047576},
        {"model_id": "gpt-4.1-mini", "display_name": "GPT-4.1 Mini", "context_length": 1047576},
        {"model_id": "o3-mini", "display_name": "O3 Mini", "context_length": 200000},
    ],
    "gemini": [
        {"model_id": "gemini-pro", "display_name": "Gemini Pro", "context_length": 30720},
        {"model_id": "gemini-1.5-pro", "display_name": "Gemini 1.5 Pro", "context_length": 1048576},
        {"model_id": "gemini-1.5-flash", "display_name": "Gemini 1.5 Flash", "context_length": 1048576},
        {"model_id": "gemini-2.0-flash", "display_name": "Gemini 2.0 Flash", "context_length": 1048576},
    ],
    "together": [
        {"model_id": "meta-llama/Llama-3.3-70B-Instruct-Turbo", "display_name": "Llama 3.3 70B", "context_length": 131072},
        {"model_id": "Qwen/Qwen2.5-72B-Instruct-Turbo", "display_name": "Qwen 2.5 72B", "context_length": 32768},
        {"model_id": "deepseek-ai/DeepSeek-R1", "display_name": "DeepSeek R1", "context_length": 65536},
        {"model_id": "mistralai/Mixtral-8x22B-Instruct-v0.1", "display_name": "Mixtral 8x22B", "context_length": 65536},
    ],
    "fireworks": [
        {"model_id": "accounts/fireworks/models/llama-v3p3-70b-instruct", "display_name": "Llama 3.3 70B", "context_length": 131072},
        {"model_id": "accounts/fireworks/models/qwen2p5-72b-instruct", "display_name": "Qwen 2.5 72B", "context_length": 32768},
        {"model_id": "accounts/fireworks/models/deepseek-r1", "display_name": "DeepSeek R1", "context_length": 65536},
    ],
    "codex": [
        {"model_id": "codex-mini-latest", "display_name": "Codex Mini", "context_length": 192000},
    ],
    "nim": [
        {"model_id": "openai/gpt-oss-120b", "display_name": "NVIDIA GPT-OSS 120B", "context_length": 32768},
        {"model_id": "meta/llama-3.1-70b-instruct", "display_name": "Llama 3.1 70B (NIM)", "context_length": 32768},
        {"model_id": "meta/llama-3.1-405b-instruct", "display_name": "Llama 3.1 405B (NIM)", "context_length": 32768},
    ],
}


@router.get("/models/{provider}", response_model=ModelCatalogResponse)
async def get_provider_models(provider: str):
    """Get available models for a specific provider.

    For local providers (ollama, lmstudio), queries the running service.
    For cloud providers, returns common model suggestions.
    For openrouter, queries the API for available models.
    """
    import aiohttp

    # Check cache
    now = time.time()
    if provider in _model_cache and (now - _model_cache_time.get(provider, 0)) < MODEL_CACHE_TTL:
        return ModelCatalogResponse(**_model_cache[provider])

    if provider == "ollama":
        result = await _get_ollama_models()
    elif provider == "lmstudio":
        result = await _get_lmstudio_models()
    elif provider == "openrouter":
        result = await _get_openrouter_models()
    elif provider in CLOUD_MODELS:
        result = {
            "provider": provider,
            "models": [
                ModelInfo(
                    provider=provider,
                    model_id=m["model_id"],
                    display_name=m["display_name"],
                    context_length=m.get("context_length"),
                    is_local=False,
                ).dict()
                for m in CLOUD_MODELS[provider]
            ],
            "available": True,
            "error": None,
        }
    else:
        raise HTTPException(400, f"Unknown provider: {provider}")

    # Cache the result
    _model_cache[provider] = result
    _model_cache_time[provider] = now

    return ModelCatalogResponse(**result)


async def _get_ollama_models() -> dict:
    """Query Ollama for installed models."""
    import aiohttp
    ollama_url = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_URL", "http://localhost:11434"))
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{ollama_url}/api/tags",
                timeout=aiohttp.ClientTimeout(total=3)
            ) as resp:
                if resp.status != 200:
                    return {"provider": "ollama", "models": [], "available": False, "error": f"HTTP {resp.status}"}
                data = await resp.json()
                models = []
                for m in data.get("models", []):
                    name = m.get("name", "")
                    size_bytes = m.get("size", 0)
                    size_str = f"{size_bytes / 1e9:.1f}B" if size_bytes else None
                    details = m.get("details", {})
                    models.append(ModelInfo(
                        provider="ollama",
                        model_id=name,
                        display_name=name,
                        size=size_str,
                        context_length=details.get("context_length"),
                        is_local=True,
                    ).dict())
                return {"provider": "ollama", "models": models, "available": True, "error": None}
    except Exception as e:
        return {"provider": "ollama", "models": [], "available": False, "error": str(e)}


async def _get_lmstudio_models() -> dict:
    """Query LM Studio for loaded models."""
    import aiohttp
    lmstudio_url = os.getenv("LMSTUDIO_BASE_URL", os.getenv("LMSTUDIO_URL", "http://localhost:1234"))
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{lmstudio_url}/v1/models",
                timeout=aiohttp.ClientTimeout(total=3)
            ) as resp:
                if resp.status != 200:
                    return {"provider": "lmstudio", "models": [], "available": False, "error": f"HTTP {resp.status}"}
                data = await resp.json()
                models = []
                for m in data.get("data", []):
                    model_id = m.get("id", "")
                    models.append(ModelInfo(
                        provider="lmstudio",
                        model_id=model_id,
                        display_name=model_id,
                        is_local=True,
                    ).dict())
                return {"provider": "lmstudio", "models": models, "available": True, "error": None}
    except Exception as e:
        return {"provider": "lmstudio", "models": [], "available": False, "error": str(e)}


async def _get_openrouter_models() -> dict:
    """Query OpenRouter for available models."""
    import aiohttp
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    try:
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://openrouter.ai/api/v1/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status != 200:
                    return {"provider": "openrouter", "models": [], "available": False, "error": f"HTTP {resp.status}"}
                data = await resp.json()
                models = []
                for m in data.get("data", [])[:100]:  # Limit to 100 models
                    model_id = m.get("id", "")
                    name = m.get("name", model_id)
                    ctx = m.get("context_length")
                    models.append(ModelInfo(
                        provider="openrouter",
                        model_id=model_id,
                        display_name=name,
                        context_length=ctx,
                        is_local=False,
                    ).dict())
                return {"provider": "openrouter", "models": models, "available": True, "error": None}
    except Exception as e:
        return {"provider": "openrouter", "models": [], "available": False, "error": str(e)}
