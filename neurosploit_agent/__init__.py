"""
NeuroSploit v3.3.0 — Autonomous MD-Agent Engine.

A lean orchestration layer that turns a URL into an autonomous penetration test:
it composes a master prompt from the curated `agents_md/` markdown library and
hands execution to a locally-installed agentic CLI backend (Claude Code, Codex,
or Grok CLI), augmented with Playwright MCP, and learns across runs via a
reinforcement-learning reward loop.

This package replaces the legacy Python orchestration (`neurosploit.py` + heavy
`core/` agents), which now lives under `legacy/` for reference.
"""

__version__ = "3.3.0"
__all__ = ["__version__"]
