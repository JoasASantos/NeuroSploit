"""
Agent loader for NeuroSploit v3.3.0.

Discovers and parses the curated `agents_md/` markdown library, builds a
searchable index, and produces an RL-weighted, recon-aware ordering of which
specialist agents the orchestrator should run for a given target.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS_DIR = os.path.join(ROOT, "agents_md")

# Recon-signal → keyword hints used to pre-select agents. The CLI backend does
# the final, intelligent selection; this just narrows the candidate set so we
# do not dump 200 playbooks into every prompt.
SIGNAL_HINTS: Dict[str, List[str]] = {
    "graphql": ["graphql"],
    "jwt": ["jwt"],
    "oauth": ["oauth", "oidc", "saml"],
    "ai_features": ["llm_", "prompt_injection", "ai_", "vector_db", "ml_model", "rag"],
    "cloud": ["aws_", "gcp_", "azure_", "s3_", "gcs_", "cloud_", "imds", "metadata", "terraform", "ecr", "helm", "serverless", "k8s", "kubelet", "docker_socket", "container_escape"],
    "rest": ["api_", "rest_", "mass_assignment", "bola", "bfla", "idor"],
    "ws": ["websocket", "ws_"],
    "upload": ["file_upload", "zip_slip", "xxe", "deserial", "pickle", "yaml"],
    "template": ["ssti", "csti", "template", "ssi", "esi"],
    "cache_proxy": ["cache", "smuggl", "desync", "h2c", "hop_by_hop", "proxy", "response_splitting"],
}


@dataclass
class Agent:
    name: str
    path: str
    title: str
    kind: str                      # "vuln" | "meta"
    user_prompt: str = ""
    system_prompt: str = ""
    cwe: str = ""
    severity: str = ""
    tags: List[str] = field(default_factory=list)


def _parse(path: str, kind: str) -> Agent:
    text = open(path, encoding="utf-8", errors="replace").read()
    name = os.path.splitext(os.path.basename(path))[0]
    title_m = re.search(r"^#\s+(.+?)\s*$", text, re.M)
    title = title_m.group(1).strip() if title_m else name
    up = re.search(r"##\s*User Prompt\s*\n(.*?)(?=\n##\s|\Z)", text, re.S)
    sp = re.search(r"##\s*System Prompt\s*\n(.*?)(?=\n##\s|\Z)", text, re.S)
    cwe_m = re.search(r"(CWE-\d+)", text)
    sev_m = re.search(r"Severity:\s*([A-Za-z]+)", text)
    return Agent(
        name=name, path=path, title=title, kind=kind,
        user_prompt=(up.group(1).strip() if up else ""),
        system_prompt=(sp.group(1).strip() if sp else ""),
        cwe=(cwe_m.group(1) if cwe_m else ""),
        severity=(sev_m.group(1) if sev_m else ""),
        tags=[name],
    )


class AgentLibrary:
    def __init__(self, base: str = AGENTS_DIR):
        self.base = base
        self.vulns: Dict[str, Agent] = {}
        self.meta: Dict[str, Agent] = {}
        self._load()

    def _load(self):
        vdir, mdir = os.path.join(self.base, "vulns"), os.path.join(self.base, "meta")
        for d, kind, store in ((vdir, "vuln", self.vulns), (mdir, "meta", self.meta)):
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if fn.endswith(".md"):
                    a = _parse(os.path.join(d, fn), kind)
                    store[a.name] = a

    # -- selection ---------------------------------------------------------
    def candidates_for(self, recon: Optional[dict]) -> List[str]:
        """Return vuln-agent names whose preconditions plausibly match recon.

        With no recon (or a generic target) we return all vuln agents and let
        the backend prioritise. With recon signals we narrow to the relevant
        subset plus a baseline of always-run web agents.
        """
        if not recon:
            return list(self.vulns.keys())
        wanted: set = set()
        signals = _signals_from_recon(recon)
        for sig in signals:
            for kw in SIGNAL_HINTS.get(sig, []):
                wanted.update(n for n in self.vulns if kw in n)
        # Always include core web classes regardless of recon.
        baseline = ["xss_reflected", "xss_stored", "xss_dom", "sqli_error", "sqli_blind",
                    "ssrf", "idor", "csrf", "open_redirect", "command_injection",
                    "lfi", "path_traversal", "auth_bypass", "security_headers",
                    "information_disclosure", "cors_misconfig"]
        wanted.update(n for n in baseline if n in self.vulns)
        return sorted(wanted) if wanted else list(self.vulns.keys())

    def ranked(self, recon: Optional[dict], weights: Dict[str, float]) -> List[str]:
        cands = self.candidates_for(recon)
        return sorted(cands, key=lambda n: weights.get(n, 0.5), reverse=True)

    def index_markdown(self, names: List[str], weights: Dict[str, float]) -> str:
        """Compact catalog (name — title — CWE — weight) for the master prompt."""
        rows = []
        for n in names:
            a = self.vulns.get(n)
            if not a:
                continue
            rows.append(f"- `{n}` — {a.title} [{a.cwe or 'CWE-?'}] (priority {weights.get(n, 0.5):.2f})")
        return "\n".join(rows)

    def render(self, name: str, target: str, recon_json: str = "{}", collaborator: str = "") -> str:
        a = self.vulns.get(name) or self.meta.get(name)
        if not a:
            raise KeyError(name)
        body = open(a.path, encoding="utf-8", errors="replace").read()
        return (body.replace("{target}", target)
                    .replace("{recon_json}", recon_json)
                    .replace("{collaborator}", collaborator))

    def counts(self) -> Dict[str, int]:
        return {"vulns": len(self.vulns), "meta": len(self.meta),
                "total": len(self.vulns) + len(self.meta)}


def _signals_from_recon(recon: dict) -> List[str]:
    sigs: List[str] = []
    apis = recon.get("apis", {}) or {}
    if apis.get("graphql"):
        sigs.append("graphql")
    if apis.get("rest"):
        sigs.append("rest")
    if apis.get("ws"):
        sigs.append("ws")
    if recon.get("ai_features"):
        sigs.append("ai_features")
    if (recon.get("cloud", {}) or {}).get("provider") or (recon.get("cloud", {}) or {}).get("metadata_surface"):
        sigs.append("cloud")
    auth = recon.get("auth", {}) or {}
    if auth.get("session") == "jwt":
        sigs.append("jwt")
    if auth.get("oauth"):
        sigs.append("oauth")
    tech = recon.get("tech", {}) or {}
    blob = " ".join(str(v) for v in tech.values()).lower()
    if any(t in blob for t in ("flask", "jinja", "twig", "freemarker", "velocity", "thymeleaf")):
        sigs.append("template")
    if tech.get("waf") or tech.get("http2"):
        sigs.append("cache_proxy")
    # Generic surfaces always worth a look.
    sigs += ["upload", "cache_proxy"]
    return list(dict.fromkeys(sigs))


if __name__ == "__main__":
    lib = AgentLibrary()
    print(lib.counts())
