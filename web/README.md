# NeuroSploit v4.0.0 — web console

A browser UI for the `neurosploit` CLI harness: a lead board (categorized agent picker + custom
leads → `Start Exploitation`), a live structured findings view, run history, and a real REPL —
all driven by spawning the actual CLI binary, never a reimplementation of harness logic.

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
