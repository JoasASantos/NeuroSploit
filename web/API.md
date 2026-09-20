# NeuroSploit Web Console — API reference

Backend: `web/server.js` (Node, zero external dependencies). It does three things:

1. Serves the SPA in `web/public/`.
2. Reads `agents_md/` and `runs/` from the repo root to build the lead board and run history.
3. Shells out to the compiled `neurosploit` CLI binary (`neurosploit-rs/target/release/neurosploit`)
   for every exploitation run and for the REPL — the web UI never reimplements harness logic,
   it only drives the real CLI and parses its stdout.

Base URL: `http://localhost:4173` (override with `PORT` or `NEUROSPLOIT_WEB_PORT`).

All responses are JSON unless noted. All endpoints are same-origin; there is no auth layer —
run this only on a trusted machine/network, same trust model as the CLI itself.

---

## Meta

### `GET /api/meta`

Server/version info.

```json
{ "version": "4.1.0", "binary": "/opt/neurosploit-rs/neurosploit-rs/target/release/neurosploit", "root": "/opt/neurosploit-rs" }
```

---

## Agents / lead board

### `GET /api/agents`

Reads every `agents_md/{vulns,ai,infra,code,chains,recon,meta}/*.md`, extracts `name` (filename
stem), `title` (first `# heading`), `cwe` (first `CWE-\d+` match), `kind` (source directory), and
classifies each into a UI category (`category`) via a keyword taxonomy (Business Logic, Broken
Access Control, Injection, Cross-Site Scripting, LLM Application, Auth & Session, SSRF & Network,
API & GraphQL, Cloud & Infra, Client-Side, Cryptography, Rate Limiting & DoS, Cache & CDN,
Recon & Fingerprint, Linux Host, Windows Host, Attack Chains, Code Review, Recon, Other).
`meta/` (orchestration/doctrine agents) is loaded but excluded from `categories` — those aren't
selectable "leads". Cached in-memory for 5s.

```json
{
  "total": 435,
  "agents": [ { "id": "sqli_error", "name": "sqli_error", "title": "SQL Injection (Error-Based) Specialist Agent", "cwe": "CWE-89", "kind": "vuln", "category": "Injection" } ],
  "categories": [ { "category": "Business Logic", "agents": [ /* Agent[] */ ] } ]
}
```

An agent's `id`/`name` is exactly what the CLI's `--only <name>` flag expects (see `neurosploit agents`).

---

## Providers / models / API keys

### `GET /api/providers`

Static mirror of `crates/harness/src/models.rs` `providers()` — every provider the harness
supports, its models, and whether it's usable via a local CLI subscription login (`kind: "cli"`)
or API key only (`kind: "api"`).

```json
[ { "key": "anthropic", "label": "Anthropic Claude", "kind": "cli", "models": ["claude-opus-5", "..."] } ]
```

### `GET /api/keys`

Which providers currently have an API key set **in this server process's memory** (booleans only
— never the value):

```json
[ { "provider": "anthropic", "set": true }, { "provider": "openai", "set": false } ]
```

### `POST /api/keys`

Body `{ "provider": "anthropic", "key": "sk-..." }`. Stores the key in an in-memory `Map` —
**never written to disk**, lost on server restart. Every subsequent `/api/exploit` and `/api/repl`
child process is spawned with `<provider>.envKey` set from this store (merged over `process.env`).
Omitting `key` (or passing an empty string) clears it. 400 on an unknown provider.

### `DELETE /api/keys/:provider`

Clears one provider's key.

---

## Runs (history)

### `GET /api/runs`

Lists `runs/ns-*` directories, newest first, with a summary read from each run's
`meta.json` / `status.json` / `findings.json`.

```json
[ { "id": "ns-1787504238-testphp_vulnweb_com", "ts": 1787504238, "name": "Keystone – Digital Banking", "target": "http://testphp.vulnweb.com/", "state": "running", "findings": 3, "severities": { "High": 1, "Medium": 2 }, "hasReport": false } ]
```

`state` mirrors the CLI's `status.json`: `running` | `complete` | `stopped-raw` | `discarded` | `unknown`.

### `GET /api/runs/:id`

Full detail for one run: `{ id, name, meta, status, findings, assets }` (`name` is the engagement
name set in the wizard, `""` if this run predates that or was started outside the web console). `findings` is the raw
`findings.json` array (see [Finding shape](#finding-shape) below). `assets` lists which generated
files exist (`report.html`, `report.pdf`, `report.md`, `recon.md`, `exploitation.md`).

### `GET /api/runs/:id/asset/:path`

Serves a file from that run's workdir (e.g. `report.html`, `report.pdf`, `evidence/foo.png`).
Path-traversal-guarded (resolved path must stay under the run dir). Use this to embed/open the
generated report from the browser.

---

## Exploitation jobs (live runs)

Starting a job spawns `neurosploit <mode> <target> [flags...] --verbose` as a child process and
parses its stdout/stderr line-by-line into structured events — the same signal the interactive
REPL's status line uses (phase, agent counts, findings, report path).

### `POST /api/exploit`

Body:

```jsonc
{
  "mode": "run",            // run | whitebox | greybox | host | aitest | skills
  "name": "Keystone – Digital Banking",  // engagement name — required by the wizard UI
  "target": "https://example.com",   // required for run/host/aitest/greybox
  "repo": "owner/repo",      // required for whitebox; source repo for greybox
  "models": ["anthropic:claude-opus-4-8"],  // optional, repeatable in the CLI
  "votes": 3,                // --vote-n
  "chainDepth": 2,           // --chain-depth
  "recon": 3,                // --recon (1-4)
  "maxAgents": 0,            // --max-agents (0 = all)
  "subscription": false,     // --subscription
  "offline": false,          // --offline
  "mcp": false,              // --mcp
  "creds": "creds.yaml",     // --creds
  "focus": "injection and business logic",   // --focus
  "objective": "pre-launch review of checkout",  // --objective
  "outOfScope": "staging.example.com",           // --out-of-scope
  "agents": ["sqli_error", "idor"],  // --only <name>, repeated — the lead-board selection
  "auth": "Authorization: Bearer <token>",  // target auth header — see Target auth below
  "roles": [{ "name": "admin", "header": "Authorization: Bearer ..." }],  // multi-identity access-control testing
}
```

### Target auth (`auth` / `roles`)

If `creds` is omitted and either `auth` or `roles` is set, the server writes a minimal
`creds.yaml`-compatible file (matching `neurosploit-rs/creds.example.yaml`'s schema) to
`os.tmpdir()/neurosploit-web/<job-id>.creds.yaml` and passes it via `--creds`. An explicit `creds`
path always wins over `auth`/`roles`. These ephemeral files are not cleaned up automatically —
they live in the OS temp dir, never in the repo.

`name` is not a harness/CLI concept — the server persists a `runId -> name` map to
`.neurosploit/web-engagement-names.json` (keyed on the CLI's own run id, captured from its
"run id : ns-…" log line) so `/api/runs` and `/api/runs/:id` can label a run by its engagement
name, surviving a server restart.

Response: `{ "id": "<job-uuid>" }`. This `id` is the **web job id**, not the run id — the CLI's own
`ns-<timestamp>-<target>` run id is discovered from its own log line and exposed as `runId` in the
job snapshot once the engagement starts writing to `runs/`.

If `agents` is empty, no `--only` flag is passed and the harness falls back to its normal
recon-driven agent selection (the intelligent default) — the lead board's "0 selected" state is a
valid, meaningful choice, not an error.

### `GET /api/exploit`

List all jobs known to this server process (in-memory; lost on restart) as snapshots (see below).

### `GET /api/exploit/:id`

One job's current snapshot:

```json
{
  "id": "d98f51ad-...", "target": "http://testphp.vulnweb.com/",
  "runId": "ns-1787504238-testphp_vulnweb_com",
  "phase": "exploiting", "findings": [ /* Finding[] */ ],
  "agents": 245, "agentsDone": 12, "done": false, "exitCode": null,
  "reportUrl": null, "startedAt": 1787504238594
}
```

`phase` tracks the same lifecycle the REPL's `/status` shows: `starting → recon → planning →
exploiting → validating → chaining → complete`, or `paused (quota)` / `paused (auth)` if the
harness parks the run (token/quota exhaustion or auth failure — findings are preserved either way).

### `POST /api/exploit/:id/stop`

Sends `SIGINT` to the child process — identical to pressing Ctrl-C in the terminal. The harness's
own graceful-stop logic decides whether to keep partial findings.

### `GET /api/exploit/:id/events` (Server-Sent Events)

Live stream. On connect, replays every buffered event so a reconnecting client doesn't miss
history, then streams new ones. Named SSE events:

| event      | data                                  | meaning |
|------------|---------------------------------------|---------|
| `log`      | `{ "type": "log", "line": "..." }`    | one stdout/stderr line (ANSI stripped) |
| `finding`  | `{ "type": "finding", "finding": {…} }` | a `finding_json:` line, parsed |
| `snapshot` | job snapshot (see above)              | phase/progress update |
| `done`     | job snapshot with `done: true`        | process exited; stream closes |

Client example:

```js
const es = new EventSource(`/api/exploit/${id}/events`);
es.addEventListener('finding', (e) => console.log(JSON.parse(e.data).finding));
es.addEventListener('done', () => es.close());
```

---

## REPL sessions

Spawns the CLI with **no subcommand** — the same interactive session `neurosploit` launches from
a terminal — and pipes stdin/stdout. Because stdin isn't a TTY, the CLI's `Reader::Plain` path
takes over: it prints each prompt to stdout then reads one line at a time from stdin, so it works
perfectly over a plain pipe. This is a real harness process; every `/command` (`/run`, `/status`,
`/stop`, `/model`, `/target`, natural-language input, etc.) behaves exactly as it would in a
terminal.

### `POST /api/repl`

Starts a session. Response: `{ "id": "<session-uuid>" }`.

### `POST /api/repl/:id/input`

Body: `{ "line": "/status" }` — writes `line + "\n"` to the child's stdin — or `{ "data": "..." }`
to write bytes verbatim (what the browser terminal sends, newline included). A `data` payload
containing `\u0003` (Ctrl-C) is delivered as `SIGINT` to the child instead of being written:
without a tty in between, nothing else turns that byte into an interrupt. Responds `409` once the
session's stdin has closed.

### `POST /api/repl/:id/stop`

Sends `SIGTERM` to the session's child process.

### `GET /api/repl/:id/events` (SSE)

| event   | data                    | meaning |
|---------|-------------------------|---------|
| `data`  | `{ "chunk": "..." }`   | raw stdout/stderr chunk, ANSI **preserved**, not line-buffered |
| `close` | `{}`                    | child process exited |

Replays the session's buffered output (capped at the last ~512 KB) on connect, same as the exploit
stream. Chunks are decoded with a streaming UTF-8 decoder, so a multi-byte character split across
two reads still arrives intact — the browser feeds them straight into xterm.js.

---

## Finding shape

Findings are exactly the harness's `harness::types::Finding` struct (see
`neurosploit-rs/crates/harness/src/types.rs`), serialized as JSON — the web UI does not transform
or rename any field:

```ts
{
  id: string, agent: string, title: string, severity: string, cwe: string, cvss: string,
  endpoint: string, payload: string, evidence: string, impact: string, remediation: string,
  confidence: number, validated: boolean, votes: string,
  owasp: string, mitre: string, stage: string, exploitability: string, business_impact: string,
  chains_from: string[], auth_context: string, account: string, secret: string,
  review_status: string, review_reason: string, screenshots: string[],
}
```

---

## Running it

```bash
cd neurosploit-rs && cargo build --release   # once, or after a harness change
node web/server.js                            # http://localhost:4173
```

`PORT` (or `NEUROSPLOIT_WEB_PORT`) overrides the port. The server auto-locates the compiled binary
under `neurosploit-rs/target/{release,debug}/neurosploit` relative to the repo root; if neither
exists, `/api/exploit` and `/api/repl` return a 500 with a build hint.
