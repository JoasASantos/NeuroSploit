"""
NeuroSploit v3 - Configuration
"""
import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""

    # Application
    APP_NAME: str = "NeuroSploit v3"
    APP_VERSION: str = "3.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/neurosploit.db"

    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    SCANS_DIR: Path = DATA_DIR / "scans"
    PROMPTS_DIR: Path = BASE_DIR / "prompts"

    # LLM Settings
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    NIM_API_KEY: Optional[str] = os.getenv("NIM_API_KEY")
    NIM_BASE_URL: str = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
    OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY")
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    AZURE_OPENAI_API_KEY: Optional[str] = os.getenv("AZURE_OPENAI_API_KEY")
    AZURE_OPENAI_ENDPOINT: Optional[str] = os.getenv("AZURE_OPENAI_ENDPOINT")
    AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
    AZURE_OPENAI_DEPLOYMENT: Optional[str] = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    TOGETHER_API_KEY: Optional[str] = os.getenv("TOGETHER_API_KEY")
    FIREWORKS_API_KEY: Optional[str] = os.getenv("FIREWORKS_API_KEY")
    DEFAULT_LLM_PROVIDER: str = "claude"
    DEFAULT_LLM_MODEL: str = "claude-sonnet-4-20250514"
    MAX_OUTPUT_TOKENS: Optional[int] = None
    ENABLE_MODEL_ROUTING: bool = False

    # Feature Flags
    ENABLE_KNOWLEDGE_AUGMENTATION: bool = False
    ENABLE_BROWSER_VALIDATION: bool = False
    ENABLE_VULN_AGENTS: bool = False
    VULN_AGENT_CONCURRENCY: int = 10
    ENABLE_SMART_ROUTER: bool = False

    # RAG (Retrieval-Augmented Generation)
    ENABLE_RAG: bool = True  # Enabled by default (zero deps, uses BM25)
    RAG_BACKEND: str = "auto"  # "auto", "chromadb", "tfidf", "bm25"

    # External Methodology File (injected into all LLM calls)
    METHODOLOGY_FILE: Optional[str] = None  # Path to .md methodology file

    # CLI Agent (AI CLI tools inside Kali sandbox)
    ENABLE_CLI_AGENT: bool = False  # Feature flag (default: disabled)
    CLI_AGENT_MAX_RUNTIME: int = 1800  # Max runtime in seconds (default: 30 min)
    CLI_AGENT_DEFAULT_PROVIDER: str = "claude_code"  # Default CLI provider

    # Codex LLM
    CODEX_API_KEY: Optional[str] = os.getenv("CODEX_API_KEY")

    # Scan Settings
    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_TIMEOUT: int = 30
    MAX_REQUESTS_PER_SECOND: int = 10

    # CORS
    CORS_ORIGINS: list = ["http://localhost:3000", "http://127.0.0.1:3000"]

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()

# Ensure directories exist
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
settings.SCANS_DIR.mkdir(parents=True, exist_ok=True)
