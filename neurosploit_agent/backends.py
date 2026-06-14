"""
Agentic CLI backends for NeuroSploit v3.3.0.

NeuroSploit does not embed its own agent loop — it delegates autonomous
execution to whichever agentic coding CLI is installed locally:

  * Claude Code  (`claude`)  — also the path for a Claude *subscription*
  * Codex CLI    (`codex`)
  * Grok CLI     (`grok`)

Each backend is driven headlessly: we pass the composed master prompt, a working
directory (with `.mcp.json` for Playwright), and provider env, and let the CLI
run the test autonomously to completion. The engine then reads the artifacts the
run wrote to `results/`.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Backend:
    key: str
    label: str
    binary: str
    # builds argv given (prompt_file, workdir, model). Prompt is passed via file
    # to avoid arg-length limits and shell-escaping issues.
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def version(self) -> str:
        try:
            out = subprocess.run([self.binary, "--version"], capture_output=True,
                                 text=True, timeout=15)
            return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else "?"
        except Exception:
            return "?"

    def build_argv(self, prompt_file: str, workdir: str, model: str,
                   autonomous: bool, mcp_config: Optional[str]) -> List[str]:
        raise NotImplementedError


@dataclass
class ClaudeBackend(Backend):
    def build_argv(self, prompt_file, workdir, model, autonomous, mcp_config):
        # Headless "print" mode reads the prompt from stdin (caller pipes the file).
        argv = [self.binary, "-p", "--output-format", "stream-json", "--verbose"]
        if model:
            argv += ["--model", model]
        if mcp_config:
            argv += ["--mcp-config", mcp_config]
        if autonomous:
            # Full autonomy for an authorized engagement in an isolated workdir.
            argv += ["--dangerously-skip-permissions"]
        return argv

    stdin_prompt: bool = True


@dataclass
class CodexBackend(Backend):
    def build_argv(self, prompt_file, workdir, model, autonomous, mcp_config):
        # `codex exec` runs non-interactively to completion.
        argv = [self.binary, "exec", "--cd", workdir]
        if model:
            argv += ["--model", model]
        if autonomous:
            argv += ["--dangerously-bypass-approvals-and-sandbox"]
        if mcp_config:
            argv += ["--config", f"mcp_config_file={mcp_config}"]
        argv += ["-"]  # read prompt from stdin
        return argv

    stdin_prompt: bool = True


@dataclass
class GrokBackend(Backend):
    def build_argv(self, prompt_file, workdir, model, autonomous, mcp_config):
        # grok-cli headless/print form.
        argv = [self.binary, "--prompt-file", prompt_file, "--workdir", workdir]
        if model:
            argv += ["--model", model]
        if mcp_config:
            argv += ["--mcp-config", mcp_config]
        if autonomous:
            argv += ["--yolo"]
        return argv

    stdin_prompt: bool = False


REGISTRY: Dict[str, Backend] = {
    "claude": ClaudeBackend("claude", "Claude Code", "claude"),
    "codex": CodexBackend("codex", "Codex CLI", "codex"),
    "grok": GrokBackend("grok", "Grok CLI", "grok"),
}


def detect() -> List[Backend]:
    """Return installed backends, in preference order."""
    order = ["claude", "codex", "grok"]
    return [REGISTRY[k] for k in order if REGISTRY[k].available()]


def get(key: str) -> Optional[Backend]:
    return REGISTRY.get(key)


@dataclass
class RunResult:
    backend: str
    returncode: int
    log_path: str
    workdir: str


def run(backend: Backend, prompt: str, workdir: str, model: str = "",
        autonomous: bool = True, mcp_config: Optional[str] = None,
        env: Optional[Dict[str, str]] = None, timeout: int = 7200,
        dry_run: bool = False) -> RunResult:
    """Execute a backend against the composed prompt and stream logs to disk."""
    os.makedirs(workdir, exist_ok=True)
    prompt_file = os.path.join(workdir, "master_prompt.md")
    open(prompt_file, "w", encoding="utf-8").write(prompt)
    log_path = os.path.join(workdir, "backend.log")

    argv = backend.build_argv(prompt_file, workdir, model, autonomous, mcp_config)
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    if dry_run:
        open(log_path, "w").write("DRY RUN\n" + " ".join(argv) + "\n")
        return RunResult(backend.key, 0, log_path, workdir)

    stdin_data = prompt if getattr(backend, "stdin_prompt", False) else None
    with open(log_path, "w", encoding="utf-8") as logf:
        proc = subprocess.run(
            argv, input=stdin_data, stdout=logf, stderr=subprocess.STDOUT,
            cwd=workdir, env=full_env, text=True, timeout=timeout,
        )
    return RunResult(backend.key, proc.returncode, log_path, workdir)
