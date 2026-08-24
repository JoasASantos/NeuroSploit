# NeuroSploit v4.0.0 — web console

A browser UI for the `neurosploit` CLI harness: a 5-step engagement wizard (Asset → Scope & Auth
→ Leads → Model & Run → Review), a live structured findings view with a generative attack-path
graph, run history, an Auth & Keys menu, and a real REPL — all driven by spawning the actual CLI
binary, never a reimplementation of harness logic.

- **Asset** — pick black/white/grey-box, host/infra, or AI/LLM, set the target or repo.
- **Scope & Auth** — objective, focus, out-of-scope, and a link into the Auth & Keys menu.
- **Leads** — the categorized agent picker (435 agents auto-classified) + custom leads.
- **Model & Run** — pick a provider/model from the live catalog, API-key vs. subscription auth
  mode, votes/chain-depth/recon intensity.
- **Review** — confirm the plan, then `Start Exploitation` spawns the real CLI.
- **Auth & Keys** (one menu, 🔑 in the sidebar) — target auth header + named roles for
  IDOR/BOLA/BFLA testing, per-provider API keys (kept in server memory only, never on disk), and
  an explicit `creds.yaml` path override.
- **Generative Attack Path Chaining** — findings are grouped into kill-chain columns
  (recon → initial-access → execution → privesc → lateral → exfil → impact) with chained findings
  linked back to their parent, built live as findings stream in.
- **Real REPL underneath run/whitebox/greybox** — the wizard scripts an actual interactive
  `neurosploit` session instead of a one-shot CLI call, so it keeps reading stdin while the
  engagement streams. The Activity log tab grows a `❭` prompt box to send `/status`, `/stop`,
  `/continue`, or a plain-language instruction mid-run. `host`/`aitest`/`skills` stay one-shot
  (their onboarding scope picker can't be scripted over piped stdin).

```bash
cd neurosploit-rs && cargo build --release   # build the CLI once
node web/server.js                            # → http://localhost:4173
```

Zero npm dependencies (Node ≥18, built-ins only: `http`, `child_process`, `events`, `fs`).

API reference: [`API.md`](./API.md).

## Layout

```
web/
├── server.js         backend: static server + agents_md/runs reader + CLI process manager
├── public/
│   ├── index.html     SPA shell
│   ├── style.css       lead-board / live-run / REPL drawer styling
│   └── app.js          client logic (fetch + EventSource, no framework)
├── API.md
└── package.json
```
