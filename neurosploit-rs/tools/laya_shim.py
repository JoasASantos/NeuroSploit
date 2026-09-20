#!/usr/bin/env python3
"""
Laya decision-backend shim for NeuroSploit.

Laya (https://github.com/NandhaKishorM/laya) is a local, open-source System One
decision engine with the same primitives as TypeSafe (choice / score / noul).
It ships as a Python library with no server, so this shim exposes it over the
exact HTTP contract NeuroSploit already speaks to TypeSafe:

    POST /systemone
    { "model": "...", "state": <any>, "questions": { "<id>": {type, instructions, criteria} } }
    -> { "answers": { "<id>": { choice|score|noul, probabilities, confidence } } }

Point NeuroSploit at it with:
    --decision-backend laya          (starts/uses http://127.0.0.1:8799)
or manually:
    NEUROSPLOIT_DECISION_ENDPOINT=http://127.0.0.1:8799/systemone \
    NEUROSPLOIT_DECISION_MODEL=laya neurosploit run ... --typesafe on

The Laya model is downloaded automatically on first use (Hugging Face cache),
so nothing is bundled and the whole thing stays optional. No API key, and the
engagement's evidence never leaves the machine.

Dependencies (installed on demand by NeuroSploit when you pick the laya backend,
or by hand):  pip install laya

Zero third-party deps here beyond laya itself — the HTTP server is stdlib.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("LAYA_SHIM_HOST", "127.0.0.1")
PORT = int(os.environ.get("LAYA_SHIM_PORT", "8799"))

# Lazy, so `--help`/import never pays the model-load cost.
_agent = None
_load_error = None


def _get_agent():
    """Load Laya once. First call downloads the model into the HF cache."""
    global _agent, _load_error
    if _agent is not None or _load_error is not None:
        return _agent
    try:
        import laya  # noqa
        # Router picks the right checkpoint (English / multilingual) per input.
        try:
            from laya import Router
            _agent = Router(preload=True)
            _agent_kind = "router"
        except Exception:
            _agent = laya.load(os.environ.get("LAYA_MODEL", "convaiinnovations/laya"))
            _agent_kind = "single"
        sys.stderr.write(f"[laya-shim] model ready ({_agent_kind})\n")
        sys.stderr.flush()
    except Exception as e:  # noqa
        _load_error = str(e)
        sys.stderr.write(f"[laya-shim] failed to load laya: {e}\n")
    return _agent


def _evaluate(model, state, questions):
    """Run Laya over the questions and normalise to the TypeSafe answer shape."""
    agent = _get_agent()
    if agent is None:
        raise RuntimeError(f"laya unavailable: {_load_error}")

    # Laya takes the state as text plus the questions map; accept dict or str.
    text = state if isinstance(state, str) else json.dumps(state, ensure_ascii=False)

    # Laya's own call surface varies by version; try the documented ones in order.
    raw = None
    for call in (
        lambda: agent.evaluate(text, questions),
        lambda: agent(text, questions),
        lambda: agent.decide(text, questions),
    ):
        try:
            raw = call()
            break
        except (AttributeError, TypeError):
            continue
    if raw is None:
        raise RuntimeError("no compatible laya call surface (evaluate/__call__/decide)")

    answers_in = raw.get("answers", raw) if isinstance(raw, dict) else {}
    answers = {}
    for qid, q in questions.items():
        a = answers_in.get(qid, {}) if isinstance(answers_in, dict) else {}
        qtype = q.get("type")
        out = {}
        if qtype == "choice":
            out["choice"] = a.get("choice")
            out["probabilities"] = a.get("probabilities", {}) or {}
            out["confidence"] = a.get("confidence")
        elif qtype == "score":
            out["score"] = a.get("score")
            out["probabilities"] = a.get("probabilities", {}) or {}
            out["confidence"] = a.get("confidence")
        elif qtype == "noul":
            out["noul"] = a.get("noul")
        answers[qid] = out
    return {"model": model or "laya", "answers": answers}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # health / readiness
        if self.path.rstrip("/") in ("/health", "/healthz", ""):
            ready = _get_agent() is not None
            self._send(200 if ready else 503, {"ready": ready, "backend": "laya", "error": _load_error})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/systemone":
            return self._send(404, {"error": "post to /systemone"})
        try:
            n = int(self.headers.get("content-length", "0"))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:  # noqa
            return self._send(400, {"error": f"bad request: {e}"})
        try:
            self._send(200, _evaluate(req.get("model"), req.get("state"), req.get("questions", {})))
        except Exception as e:  # noqa
            self._send(500, {"error": str(e)})

    def log_message(self, *a):  # quiet
        pass


def main():
    # Warm the model up front so the first real request isn't the one that waits
    # on a multi-hundred-MB download.
    sys.stderr.write(f"[laya-shim] loading model (first run downloads it)…\n")
    sys.stderr.flush()
    _get_agent()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write(f"[laya-shim] listening on http://{HOST}:{PORT}/systemone\n")
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
