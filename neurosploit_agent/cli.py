"""
NeuroSploit v3.3.0 — terminal launcher.

Two ways in:

    neurosploit                      # interactive: prompts for URL + choices
    neurosploit run https://t.example --backend claude --model claude-opus-4-8

The interactive flow asks for a URL, lets you pick from the agentic CLI backends
actually installed on this machine (Claude Code / Codex / Grok, or a Claude
subscription), picks a model, then launches the autonomous engagement.
"""

import argparse
import sys

from . import backends, models
from .config import RunConfig
from .orchestrator import run_engagement

BANNER = r"""
   _   _                      ____        _       _ _
  | \ | | ___ _   _ _ __ ___ / ___|_ __ | | ___ (_) |_
  |  \| |/ _ \ | | | '__/ _ \\___ \| '_ \| |/ _ \| | __|
  | |\  |  __/ |_| | | | (_) |___) | |_) | | (_) | | |_
  |_| \_|\___|\__,_|_|  \___/|____/| .__/|_|\___/|_|\__|
        v3.3.0  Autonomous MD-Agent Engine
                                   |_|
"""


def _progress(msg: str):
    print(f"  [*] {msg}", flush=True)


def _choose(prompt, options, default_idx=0):
    for i, (key, label) in enumerate(options):
        mark = "*" if i == default_idx else " "
        print(f"   {mark} {i + 1}) {label}")
    raw = input(f"{prompt} [{default_idx + 1}]: ").strip()
    if not raw:
        return options[default_idx][0]
    try:
        return options[int(raw) - 1][0]
    except (ValueError, IndexError):
        print("   invalid choice, using default")
        return options[default_idx][0]


def interactive() -> int:
    print(BANNER)
    installed = backends.detect()
    if not installed:
        print("  [!] No agentic CLI backend found (claude / codex / grok).")
        print("      Install one: Claude Code, Codex CLI, or Grok CLI, then re-run.")
        return 2
    print(f"  Detected backends: {', '.join(b.label + ' (' + b.version() + ')' for b in installed)}\n")

    target = input("  Target URL: ").strip()
    if not target:
        print("  [!] A target URL is required.")
        return 2
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    scope = input(f"  In-scope hosts [default: {target}]: ").strip() or target
    collaborator = input("  OOB collaborator host (optional, for blind/SSRF proof): ").strip()

    backend_key = _choose("  Choose backend", [(b.key, f"{b.label}  [{b.version()}]") for b in installed])

    # Provider/model: map backend → sensible provider, then pick a model.
    prov_for_backend = {"claude": "anthropic", "codex": "openai", "grok": "xai"}
    provider = prov_for_backend.get(backend_key, "anthropic")
    sub = input("  Use Claude subscription (login) instead of an API key? [y/N]: ").strip().lower()
    if sub == "y" and backend_key == "claude":
        provider = "claude_subscription"
    model_opts = [(m.id, f"{m.label}  ({m.context // 1000}k ctx)  {m.notes}")
                  for m in models.list_models(provider)] or [("", "backend default")]
    model = _choose("  Choose model", model_opts)

    cfg = RunConfig(target=target, scope=scope, backend=backend_key,
                    provider=provider, model=model, collaborator=collaborator)
    print()
    _progress(f"Starting autonomous engagement against {target}")
    result = run_engagement(cfg, progress=_progress)
    _summary(result)
    return 0 if result["returncode"] == 0 else 1


def _summary(result):
    print("\n  ── Engagement complete ─────────────────────────────")
    print(f"   Workdir : {result['workdir']}")
    print(f"   Findings: {len(result['findings'])} validated")
    by_sev = {}
    for f in result["findings"]:
        by_sev[f.get("severity", "?")] = by_sev.get(f.get("severity", "?"), 0) + 1
    if by_sev:
        print("   By severity: " + ", ".join(f"{k}={v}" for k, v in by_sev.items()))
    print(f"   Report  : reports/  |  Raw: {result['workdir']}/findings.json")
    print("  ────────────────────────────────────────────────────")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="neurosploit",
                                     description="NeuroSploit v3.3.0 autonomous MD-agent pentest engine")
    sub = parser.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="run an engagement against a URL")
    r.add_argument("url")
    r.add_argument("--backend", default=None, help="claude | codex | grok (default: first installed)")
    r.add_argument("--provider", default=None)
    r.add_argument("--model", default=None)
    r.add_argument("--scope", default="")
    r.add_argument("--collaborator", default="")
    r.add_argument("--no-rl", action="store_true")
    r.add_argument("--no-mcp", action="store_true")
    r.add_argument("--max-agents", type=int, default=0)
    r.add_argument("--dry-run", action="store_true", help="compose prompt + show command without executing the backend")

    sub.add_parser("backends", help="list detected CLI backends")
    sub.add_parser("agents", help="show agent library counts")

    args = parser.parse_args(argv)

    if args.cmd is None:
        try:
            return interactive()
        except (KeyboardInterrupt, EOFError):
            print("\n  aborted.")
            return 130

    if args.cmd == "backends":
        for b in backends.detect():
            print(f"  {b.key:8} {b.label:14} {b.version()}")
        if not backends.detect():
            print("  none installed (claude / codex / grok)")
        return 0

    if args.cmd == "agents":
        from .agent_loader import AgentLibrary
        print(AgentLibrary().counts())
        return 0

    if args.cmd == "run":
        url = args.url if args.url.startswith(("http://", "https://")) else "https://" + args.url
        backend = args.backend or (backends.detect()[0].key if backends.detect() else "claude")
        prov_for_backend = {"claude": "anthropic", "codex": "openai", "grok": "xai"}
        provider = args.provider or prov_for_backend.get(backend, "anthropic")
        model = args.model or (models.list_models(provider)[0].id if models.list_models(provider) else "")
        cfg = RunConfig(target=url, scope=args.scope or url, backend=backend,
                        provider=provider, model=model, collaborator=args.collaborator,
                        use_rl=not args.no_rl, use_mcp=not args.no_mcp,
                        max_agents=args.max_agents, dry_run=args.dry_run)
        print(BANNER)
        result = run_engagement(cfg, progress=_progress)
        _summary(result)
        return 0 if result["returncode"] == 0 else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
