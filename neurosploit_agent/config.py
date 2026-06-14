"""Configuration & paths for NeuroSploit v3.3.0."""

import os
from dataclasses import dataclass, field
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(*parts) -> str:
    return os.path.join(ROOT, *parts)


@dataclass
class RunConfig:
    target: str
    scope: str = ""
    rules_of_engagement: str = "Authorized, non-destructive testing only. No DoS unless explicitly permitted. Stay strictly in scope."
    backend: str = "claude"            # claude | codex | grok
    provider: str = "anthropic"        # see models.PROVIDERS
    model: str = "claude-opus-4-8"
    autonomous: bool = True
    collaborator: str = ""             # OOB callback host for blind vuln proof
    use_rl: bool = True
    use_mcp: bool = True
    max_agents: int = 0                # 0 = no cap (backend prioritises)
    timeout: int = 7200
    dry_run: bool = False
    workdir: str = field(default="")

    def resolved_workdir(self) -> str:
        return self.workdir or _p("results", _slug(self.target))


def _slug(url: str) -> str:
    s = url.replace("https://", "").replace("http://", "")
    return "".join(c if c.isalnum() else "_" for c in s).strip("_")[:60] or "target"


PATHS = {
    "agents": _p("agents_md"),
    "results": _p("results"),
    "reports": _p("reports"),
    "data": _p("data"),
    "logs": _p("logs"),
    "rl_state": _p("data", "rl_state.json"),
}


def ensure_dirs():
    for k in ("results", "reports", "data", "logs"):
        os.makedirs(PATHS[k], exist_ok=True)
