"""
MCP bridge for NeuroSploit v3.3.0.

Generates the MCP server configuration the agentic CLI backend loads so the
autonomous run can drive a real browser (Playwright) and any extra MCP tooling.
Playwright lets agents render SPAs, execute JS, capture DOM/network/screenshots
and confirm client-side execution (XSS/CSTI) — turning "the payload reflected"
into "the payload executed", which is what the validator agents demand.
"""

import json
import os
import shutil
from typing import Dict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def playwright_server() -> Dict:
    """Prefer a local @playwright/mcp; fall back to npx on demand."""
    return {
        "command": "npx",
        "args": ["-y", "@playwright/mcp@latest", "--headless", "--isolated"],
    }


def build_mcp_config(extra: Dict[str, Dict] | None = None) -> Dict:
    servers = {"playwright": playwright_server()}
    if extra:
        servers.update(extra)
    return {"mcpServers": servers}


def write_mcp_config(workdir: str, extra: Dict[str, Dict] | None = None) -> str:
    """Write a `.mcp.json` into the run workdir and return its path.

    Claude Code auto-loads `.mcp.json` from the working directory; Codex/Grok
    accept an explicit config path (see backends.py).
    """
    cfg = build_mcp_config(extra)
    path = os.path.join(workdir, ".mcp.json")
    os.makedirs(workdir, exist_ok=True)
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2)
    return path


def playwright_available() -> bool:
    """Best-effort check that Playwright MCP can be launched."""
    return shutil.which("npx") is not None
