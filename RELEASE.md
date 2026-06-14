# NeuroSploit v3.3.0 — Release Notes

**Release Date:** June 2026
**Codename:** Autonomous MD-Agent Engine
**License:** MIT

---

## TL;DR

NeuroSploit's pentest agent has been **re-modeled into an autonomous,
markdown-driven engine**. You give it a URL; it composes a master prompt from a
curated library of **213 markdown agents** and drives a locally-installed
**agentic CLI backend** (Claude Code / Codex / Grok CLI, or a Claude
subscription) to run the engagement end-to-end — with **Playwright MCP** for
proof-of-execution and a **reinforcement-learning** loop that adapts agent
selection across runs. The old Python orchestration was retired to `legacy/`.

## Highlights

- **New engine `neurosploit_agent/`** + `./neurosploit` terminal launcher.
  Interactive (`./neurosploit`) or one-shot (`./neurosploit run <url>`).
- **213-agent markdown library (`agents_md/`)**: **196 vulnerability
  specialists** (now covering LLM/AI, cloud/K8s, modern API/auth, advanced
  injection, protocol smuggling, logic/crypto/supply-chain) + **17 meta-agents**.
- **Meta-agents for quality**: `recon`, `exploit_validator`,
  `false_positive_filter`, `severity_assessor`, `impact_evaluator`, `reporter`,
  and `rl_feedback` — the pipeline validates and adversarially refutes every
  candidate before it can become a finding.
- **Pluggable agentic CLI backends** with auto-detection: Claude Code, Codex,
  Grok CLI; **subscription mode** via Claude Code login.
- **Playwright MCP** wired in (`.mcp.json`) so agents prove client-side execution
  (XSS/CSTI) and capture DOM/network/screenshots instead of trusting reflection.
- **Reinforcement learning** (`neurosploit_agent/rl.py` + `meta/rl_feedback.md`):
  bounded per-agent weights with per-tech-stack affinity, persisted to
  `data/rl_state.json`.
- **Latest model registry** (`neurosploit_agent/models.py`): Anthropic Claude
  4.x, OpenAI, xAI Grok, Gemini, OpenRouter, Ollama, and **NVIDIA NIM** (PR #28,
  OpenAI-compatible `integrate.api.nvidia.com`, `nvapi-` keys).
- **Data-driven agent builder** `scripts/build_agents.py` for extending the
  library without boilerplate.

## Breaking changes

- The monolithic `neurosploit.py` orchestrator and Python agent classes moved to
  `legacy/` and are no longer the supported entrypoint. Use `./neurosploit`.
- Primary agent library moved from `prompts/agents/` to `agents_md/` (originals
  preserved; meta/role prompts split into `agents_md/meta/`).

## Upgrade notes

1. Install at least one agentic CLI: Claude Code, Codex, or Grok CLI.
2. `npx` (Node) is required for Playwright MCP.
3. Copy `.env.example` → `.env`; set a provider key (or use Claude subscription).
4. `./neurosploit backends` to confirm detection, then `./neurosploit`.

---

# NeuroSploit v3.0.0 — Release Notes

**Release Date:** February 2026
**Codename:** Autonomous Pentester
**License:** MIT

---

## Overview

NeuroSploit v3 is a ground-up overhaul of the AI-powered penetration testing platform. This release transforms the tool from a scanner into an autonomous pentesting agent — capable of reasoning, adapting strategy in real-time, chaining exploits, validating findings with anti-hallucination safeguards, and executing tools inside isolated Kali Linux containers.

### By the Numbers

| Metric | Count |
|--------|-------|
| Vulnerability types supported | 100 |
| Payload libraries | 107 |
| Total payloads | 477+ |
| Kali sandbox tools | 55 |
| Backend core modules | 63 Python files |
| Backend core code | 37,546 lines |
| Autonomous agent | 7,592 lines |
| AI decision prompts | 100 (per-vuln-type) |
| Anti-hallucination prompts | 12 composable templates |
| Proof-of-execution rules | 100 (per-vuln-type) |
| Known CVE signatures | 400 |
| EOL version checks | 19 |
| WAF signatures | 16 |
| WAF bypass techniques | 12 |
| Exploit chain rules | 10+ |
| Frontend pages | 14 |
| API endpoints | 111+ |
| LLM providers supported | 6 |

---

## Architecture

```
                      +---------------------+
                      |   React/TypeScript   |
                      |     Frontend (14p)   |
                      +----------+----------+
                                 |
                           WebSocket + REST
                                 |
                      +----------v----------+
                      |   FastAPI Backend    |
                      |   14 API routers     |
                      +----------+----------+
                                 |
              +---------+--------+--------+---------+
              |         |        |        |         |
         +----v---+ +---v----+ +v------+ +v------+ +v--------+
         | LLM    | | Vuln   | | Agent | | Kali  | | Report  |
         | Manager| | Engine | | Core  | |Sandbox| | Engine  |
         | 6 provs| | 100typ | |7592 ln| | 55 tl | | 2 fmts  |
         +--------+ +--------+ +-------+ +-------+ +---------+
```

**Stack:** Python 3.10+ / FastAPI / SQLAlchemy (async) / React 18 / TypeScript / Tailwind CSS / Vite / Docker

---

## Core Engine: 100 Vulnerability Types

The vulnerability engine covers 100 distinct vulnerability types organized in 10 categories with dedicated testers, payloads, AI prompts, and proof-of-execution rules for each.

### Categories & Types

| Category | Types | Examples |
|----------|-------|---------|
| **Injection** | 12 | SQLi (error, union, blind, time-based), Command Injection, SSTI, NoSQL, LDAP, XPath, Expression Language, HTTP Parameter Pollution |
| **XSS** | 3 | Reflected, Stored (two-phase form+display), DOM-based |
| **Authentication** | 7 | Auth Bypass, JWT Manipulation, Session Fixation, Weak Password, Default Credentials, 2FA Bypass, OAuth Misconfig |
| **Authorization** | 5 | IDOR, BOLA, BFLA, Privilege Escalation, Mass Assignment, Forced Browsing |
| **Client-Side** | 9 | CORS, Clickjacking, Open Redirect, DOM Clobbering, PostMessage, WebSocket Hijack, Prototype Pollution, CSS Injection, Tabnabbing |
| **File Access** | 5 | LFI, RFI, Path Traversal, XXE, File Upload |
| **Request Forgery** | 3 | SSRF, SSRF Cloud (AWS/GCP/Azure metadata), CSRF |
| **Infrastructure** | 7 | Security Headers, SSL/TLS, HTTP Methods, Directory Listing, Debug Mode, Exposed Admin, Exposed API Docs, Insecure Cookies |
| **Advanced** | 9 | Race Condition, Business Logic, Rate Limit Bypass, Type Juggling, Timing Attack, Host Header Injection, HTTP Smuggling, Cache Poisoning, CRLF |
| **Data Exposure** | 6 | Sensitive Data, Information Disclosure, API Key Exposure, Source Code Disclosure, Backup Files, Version Disclosure |
| **Cloud & Supply Chain** | 6 | S3 Misconfig, Cloud Metadata, Subdomain Takeover, Vulnerable Dependency, Container Escape, Serverless Misconfig |

### Injection Routing

Every vulnerability type is routed to the correct injection point:

- **Parameter injection** (default): SQLi, XSS, IDOR, SSRF, etc.
- **Header injection**: CRLF, Host Header, HTTP Smuggling
- **Body injection**: XXE
- **Path injection**: Path Traversal, LFI
- **Both (param + path)**: LFI, directory traversal variants

### XSS Pipeline (Reflected)

The reflected XSS engine is a multi-stage pipeline:

1. **Canary probe** — unique marker per endpoint+param to detect reflection
2. **Context analysis** — 8 contexts: html_body, attribute_value, script_string, script_block, html_comment, url_context, style_context, event_handler
3. **Filter detection** — batch probe to map allowed/blocked chars, tags, events
4. **AI payload generation** — LLM generates context-aware bypass payloads
5. **Escalation payloads** — WAF/encoding bypass variants
6. **Testing** — up to 30 payloads per param with per-payload dedup
7. **Browser validation** — Playwright popup/cookie/DOM/event verification (optional)

### POST Form Support

- HTML forms detected during recon with method, action, all input fields (including `<select>`, `<textarea>`, hidden fields)
- POST form testing includes **all form fields** (CSRF tokens, hidden inputs) — not just the parameter under test
- Redirect following for POST responses (search forms that redirect to results)
- Full HTTP method support: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD

---

## Autonomous Agent Architecture

### 3-Stream Parallel Auto-Pentest

The agent runs 3 concurrent streams via `asyncio.gather()`:

```
Stream 1: Recon          Stream 2: Junior Tester      Stream 3: Tool Runner
  - Crawl target           - Immediate target test       - Nuclei + Naabu
  - Extract forms           - Consume endpoint queue      - AI-selected tools
  - JS analysis             - 3 payloads/endpoint         - Dynamic install
  - Deep fingerprint        - AI-prioritized types        - Process findings
  - Push to queue           - Skip tested types           - Feed back to recon
        |                         |                             |
        +----------+--------------+-----------------------------+
                   |
            Deep Analysis (50-75%)
            Researcher AI (75%)    ← NEW
            Finalization (75-100%)
```

### Reasoning Engine (ReACT)

AI reasoning at strategic checkpoints (50%, 75%):

- **Think**: analyze situation, available data, findings so far
- **Plan**: recommend next actions, prioritize vuln types
- **Reflect**: evaluate results, adjust strategy

Token budget tracking with graceful degradation:
- 0-60% budget: full AI (reasoning + verification + enhancement)
- 60-80%: reduced (skip enhancement)
- 80-95%: minimal (verification only)
- 95%+: technical only (no AI calls)

### Strategy Adaptation

- **Dead endpoint detection**: skip after 5+ consecutive errors
- **Diminishing returns**: reduce testing on low-yield endpoints
- **Priority recomputation**: re-rank vuln types based on results
- **Pattern propagation**: IDOR on `/users/1` automatically queues `/orders/1`, `/accounts/1`
- **Checkpoint refinement**: at 30%/60%/90% refine attack strategy

### Exploit Chaining

10+ chain rules for multi-step attack paths:

- SSRF -> Internal service access -> Data extraction
- SQLi -> Database-specific escalation (MySQL, PostgreSQL, MSSQL)
- XSS -> Session hijacking -> Account takeover
- LFI -> Source code disclosure -> Credential extraction
- Auth bypass -> Privilege escalation -> Admin access

AI-driven chain discovery during finalization phase.

---

## Validation & Anti-Hallucination Pipeline

### 4-Layer Verification

Every finding passes through 4 independent verification layers before confirmation:

```
Finding Signal
    |
    v
[1] Negative Controls  — Send benign/empty probes. Same response = false positive (-60 penalty)
    |
    v
[2] Proof of Execution — Per-vuln-type proof checks (25+ methods). XSS: context analyzer.
    |                      SSRF: metadata markers. SQLi: DB error patterns. Score 0-60.
    v
[3] AI Interpretation  — LLM analyzes with anti-hallucination system prompt + per-type
    |                      proof requirements. Speculative language rejected.
    v
[4] Confidence Scorer  — Numeric 0-100 score. >=90 confirmed, >=60 likely, <60 rejected.
    |
    v
ValidationJudge (sole authority for finding approval)
```

### Anti-Hallucination System Prompts

12 composable anti-hallucination prompt templates injected into all 17 LLM call sites:

| Prompt | Purpose |
|--------|---------|
| `anti_hallucination` | Core: never claim vuln without concrete proof |
| `anti_scanner` | Don't behave like a scanner — reason like a pentester |
| `negative_controls` | Explain control test methodology |
| `think_like_pentester` | Manual testing mindset |
| `proof_of_execution` | What constitutes real proof per vuln type |
| `frontend_backend_correlation` | Don't confuse client-side vs server-side |
| `multi_phase_tests` | Two-phase testing (submit + verify) |
| `final_judgment` | Conservative final decision framework |
| `confidence_score` | Numeric scoring calibration |
| `anti_severity_inflation` | Don't inflate severity |
| `operational_humility` | Acknowledge uncertainty |
| `access_control_intelligence` | Data comparison, not status code diff |

100 per-vuln-type proof requirements (e.g., SSRF requires metadata content, not just status diff).

### Cross-Validation

- `_cross_validate_ai_claim()` — independent check for XSS, SQLi, SSRF, IDOR, open redirect, CRLF, XXE, NoSQL
- `_evidence_in_response()` — verify AI claim matches actual HTTP response
- Speculative language rejection ("might be", "could be", "possibly")
- Default `False` — findings rejected unless positively proven

### Access Control Intelligence

- BOLA/BFLA/IDOR use **data comparison** methodology (not status code diff)
- JSON field comparison between authenticated user responses
- Adaptive TP/FP learning across scans (9 patterns, 6 known FP patterns)
- Access control types auto-inject specialized prompts

---

## Kali Sandbox & Tool Execution

### Container-Per-Scan Architecture

Each scan gets its own isolated Kali Linux Docker container:

```
ContainerPool (global coordinator)
    |
    +-- Scan A: KaliSandbox (neurosploit-kali-abc123)
    |       +-- nuclei, naabu, httpx (pre-installed)
    |       +-- wpscan (installed on-demand)
    |       +-- sqlmap (installed on-demand)
    |
    +-- Scan B: KaliSandbox (neurosploit-kali-def456)
    |       +-- nuclei, httpx (pre-installed)
    |       +-- dirsearch (installed on-demand)
    |
    +-- max_concurrent, TTL, orphan cleanup
```

### 55 Security Tools

| Category | Count | Examples |
|----------|-------|---------|
| Pre-installed (Go) | 11 | nuclei, naabu, httpx, subfinder, katana, dnsx, ffuf, gobuster, dalfox, waybackurls, uncover |
| Pre-installed (APT) | 5 | nmap, nikto, sqlmap, masscan, whatweb |
| Pre-installed (System) | 12 | curl, wget, git, python3, pip3, go, jq, dig, whois, openssl, netcat, bash |
| APT on-demand | 15 | wpscan, dirb, hydra, john, hashcat, sslscan, amass, enum4linux, dnsrecon, fierce, crackmapexec |
| Go on-demand | 4 | gau, gitleaks, anew, httprobe |
| Pip on-demand | 8 | dirsearch, wfuzz, arjun, wafw00f, sslyze, commix, trufflehog, retire |

### Dynamic Tool Engine

- AI selects tools based on detected tech stack
- On-demand install → execute → collect results → cleanup
- Tool output parsed and converted to structured findings
- Results fed back into recon context for deeper testing

### Researcher AI Agent

Hypothesis-driven 0-day discovery agent with Kali sandbox access:

```
Observe (recon data + existing findings)
    |
    v
Hypothesize (AI generates targeted hypotheses)
    |          - Logic flaws, race conditions
    v          - CVE-based attacks, misconfigurations
Plan Tools (AI selects from 55+ tools)
    |
    v
Execute in Sandbox (isolated Kali container)
    |
    v
Analyze Results (AI verdicts: confirmed/rejected)
    |
    v
Loop (max 15 hypotheses, 30 tool executions, 5 iterations)
```

Enabled via: `ENABLE_RESEARCHER_AI=true` + per-scan checkbox in frontend.

---

## Intelligence Modules

### CVE Hunter

- Extracts software versions from headers, meta tags, error pages, JS files
- Searches NVD API (NIST National Vulnerability Database)
- Searches GitHub for public exploit PoCs
- Correlates CVEs with detected versions
- Optional API keys for higher rate limits

### Banner Analyzer

- 400 known vulnerable version signatures
- 19 end-of-life version categories
- Instant version-to-CVE mapping without API calls
- AI-assisted analysis for unknown versions

### Deep Recon

- JavaScript file crawling for API endpoints, secrets, route definitions
- Sitemap.xml and robots.txt parsing
- OpenAPI/Swagger schema discovery and enumeration
- Deep fingerprinting from multiple sources

### Endpoint Classifier

8 endpoint type categories with risk scoring:

| Type | Risk Weight | Priority Vulns |
|------|-------------|----------------|
| Admin | 0.95 | auth_bypass, privilege_escalation, default_credentials |
| Auth | 0.90 | auth_bypass, brute_force, weak_password |
| Upload | 0.85 | file_upload, xxe, path_traversal |
| API | 0.80 | idor, bola, bfla, jwt_manipulation, mass_assignment |
| Data | 0.75 | idor, bola, mass_assignment, data_exposure |
| Search | 0.70 | sqli_error, xss_reflected, nosql_injection |

### Parameter Analyzer

8 semantic categories for smart parameter prioritization:

- ID params (`id`, `uid`, `user_id`) -> IDOR, BOLA
- File params (`file`, `path`, `include`) -> LFI, Path Traversal
- URL params (`url`, `redirect`, `callback`) -> SSRF, Open Redirect
- Query params (`q`, `search`, `filter`) -> SQLi, XSS
- Auth params (`token`, `jwt`, `session`) -> JWT Manipulation, Auth Bypass
- Code params (`cmd`, `exec`, `template`) -> Command Injection, SSTI

### Payload Mutator

14 mutation strategies for WAF/filter bypass:

- Double encoding, Unicode escape, case variation
- Null byte injection, comment injection, concat bypass
- Hex encoding, newline/tab bypass, charset bypass
- Failure analysis: adapts strategy based on observed response patterns

### WAF Detection & Bypass

- 16 WAF signatures (Cloudflare, AWS WAF, Akamai, Imperva, F5, Sucuri, etc.)
- Passive detection (response headers) + active probing
- 12 bypass techniques per WAF type
- Auto-applied when WAF detected

---

## Request Infrastructure

### Resilient Request Engine

- Automatic retry with exponential backoff
- Rate limiting (requests/second configurable)
- Circuit breaker (open after N consecutive failures, half-open probe, close on success)
- Adaptive timeouts (increase on slow responses)
- Per-domain rate tracking

### Auth Manager

- Multi-user session management
- Login form detection and auto-authentication
- Cookie, Bearer, Basic, Header auth types
- Session refresh on expiry

---

## Multi-Agent Orchestration (Experimental)

Optional replacement for the 3-stream architecture. 5 specialist agents with handoff coordination:

| Agent | Budget | Responsibility |
|-------|--------|----------------|
| ReconAgent | 20% | Deep crawl, JS analysis, API enum, fingerprinting |
| ExploitAgent | 35% | Classify endpoints, prioritize params, test, mutate, validate |
| ValidatorAgent | 20% | Independent re-test, different payloads, reproducibility |
| CVEHunterAgent | 10% | Version extraction, NVD search, GitHub exploit search |
| ReportAgent | 15% | Finding enhancement, PoC generation, report creation |

3-phase pipeline: Parallel (Recon + CVE) -> Sequential (Exploit) -> Parallel (Validator + Report)

Enable: `ENABLE_MULTI_AGENT=true` in `.env`

---

## Frontend

### 14 Pages

| Page | Route | Description |
|------|-------|-------------|
| Home | `/` | Dashboard with stats, activity feed, severity charts |
| Auto Pentest | `/auto` | 3-stream display, live findings, AI reports, Kali checkbox |
| Scan Details | `/scan/:id` | Findings with validation badges, confidence scores, pause/resume/stop |
| New Scan | `/scan/new` | Quick/Full/Custom scan configuration |
| Reports | `/reports` | Report listing with HTML/PDF/JSON download |
| Report View | `/report/:id` | Interactive report viewer |
| Terminal Agent | `/terminal` | AI chat + command execution interface |
| Vuln Lab | `/vuln-lab` | Per-type challenge testing (100 types, 11 categories) |
| Task Library | `/tasks` | Reusable pentest task templates |
| Scheduler | `/scheduler` | Cron/interval scheduling with CRUD |
| Settings | `/settings` | LLM providers, model routing, feature toggles |
| Sandbox Dashboard | `/sandbox` | Kali container monitoring, tool status |
| Agent Status | `/agent/:id` | Real-time agent progress and logs |
| Realtime Task | `/realtime` | Live interactive testing session |

### Key UI Features

- **Real-time WebSocket updates**: live scan progress, findings, logs
- **Confidence badges**: green (>=90), yellow (>=60), red (<60) with breakdown details
- **Validation Pipeline display**: proof of execution, negative controls, scoring breakdown
- **Pause/Resume/Stop**: scan control with 5 internal checkpoints
- **Manual validation**: confirm/reject AI decisions
- **Screenshot evidence**: inline per-finding in PoC section
- **Rejected findings viewer**: expandable section with rejection reasons

---

## Report Generation

### Two Report Engines

| Engine | Format | Style |
|--------|--------|-------|
| Professional | HTML | Dark theme, collapsible findings, click-to-zoom screenshots, severity charts |
| OHVR | HTML | Observation-Hypothesis-Validation-Result methodology, PoC code blocks |

Both engines support:
- Executive summary (AI-generated)
- Severity breakdown with visual charts
- Per-finding: description, PoC, exploitation code, **inline screenshots**, impact, remediation, references
- Rejected findings section (AI-rejected, pending manual review)
- JSON export for programmatic consumption

### Screenshot Placement

Screenshots are embedded **inline within each vulnerability's PoC section** — directly associated with the finding they evidence. No separate gallery at the end.

```
Vulnerability Finding
  +-- Description
  +-- Proof of Concept
  |     +-- Observation
  |     +-- Hypothesis
  |     +-- Validation (payload + request)
  |     +-- Exploitation Code
  |     +-- Visual Evidence (screenshots)  <-- HERE
  |     +-- Result (impact)
  +-- Remediation
  +-- References
```

---

## Cross-Scan Learning

### Execution History

- Tracks attack success/failure across all scans
- Records: tech_stack + vuln_type + target + success rate
- `get_priority_types(tech_stack)` — returns types ranked by historical success
- Auto-influences AI prompts and testing priority in future scans
- Bounded storage (500 records, auto-save every 20)

### Access Control Learner

- Adaptive true-positive / false-positive pattern learning
- 9 detection patterns, 6 known FP patterns
- Influences ValidationJudge scoring in subsequent scans

---

## LLM Provider Support

| Provider | Models | Config |
|----------|--------|--------|
| Anthropic Claude | claude-3.5-sonnet, claude-3-opus, claude-3-haiku | `ANTHROPIC_API_KEY` |
| OpenAI | gpt-4o, gpt-4-turbo, gpt-3.5-turbo | `OPENAI_API_KEY` |
| Google Gemini | gemini-pro, gemini-1.5-pro | `GEMINI_API_KEY` |
| OpenRouter | Any model via unified API | `OPENROUTER_API_KEY` |
| Ollama | Any local model (llama, mistral, etc.) | `OLLAMA_BASE_URL` |
| LM Studio | Any local model | `LMSTUDIO_BASE_URL` |

### Model Routing

Optional task-type routing to different LLM profiles:

| Task Type | Recommended |
|-----------|-------------|
| Reasoning | High-capability (Claude Opus, GPT-4) |
| Analysis | Medium (Claude Sonnet, GPT-4-turbo) |
| Generation | Medium (Sonnet, GPT-4-turbo) |
| Validation | High-capability for accuracy |
| Default | Configurable |

Enable: `ENABLE_MODEL_ROUTING=true` with profiles in `config/config.json`

---

## Configuration

### Environment Variables

```bash
# LLM API Keys (at least one required)
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
OPENROUTER_API_KEY=

# Local LLM (no key needed)
#OLLAMA_BASE_URL=http://localhost:11434
#LMSTUDIO_BASE_URL=http://localhost:1234

# Feature Flags
ENABLE_MODEL_ROUTING=false
ENABLE_KNOWLEDGE_AUGMENTATION=false
ENABLE_BROWSER_VALIDATION=false
ENABLE_REASONING=true
ENABLE_CVE_HUNT=true
ENABLE_MULTI_AGENT=false
ENABLE_RESEARCHER_AI=true

# Optional API Keys
#NVD_API_KEY=
#GITHUB_TOKEN=

# Token Budget (comment out for unlimited)
#TOKEN_BUDGET=100000

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/neurosploit.db

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

---

## Installation

### Backend

```bash
cd /opt/NeuroSploitv2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API key(s)
```

### Frontend

```bash
cd frontend
npm install
npm run build
```

### Kali Sandbox (Optional)

```bash
docker build -f docker/Dockerfile.kali -t neurosploit-kali:latest docker/
```

### Run

```bash
# Backend (serves frontend static files too)
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Or development mode (frontend hot reload)
cd frontend && npm run dev  # Port 3000
python -m uvicorn backend.main:app --reload --port 8000
```

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.10+ | 3.12 |
| Node.js | 18+ | 20 LTS |
| Docker | 24+ | Latest (for Kali sandbox) |
| RAM | 4 GB | 8 GB |
| Disk | 2 GB | 5 GB (with Kali image) |

### Backend Dependencies

- **Framework**: FastAPI, Uvicorn, Pydantic
- **Database**: SQLAlchemy (async), aiosqlite
- **HTTP**: aiohttp
- **LLM**: anthropic, openai
- **Reports**: Jinja2, WeasyPrint
- **Scheduling**: APScheduler
- **Optional**: playwright, docker, mcp

### Frontend Dependencies

- **UI**: React 18, TypeScript, Tailwind CSS
- **State**: Zustand
- **HTTP**: Axios
- **Realtime**: Socket.IO Client
- **Charts**: Recharts
- **Icons**: Lucide React
- **Build**: Vite

---

## Known Limitations

- Anthropic API budget limits cause scan interruption — set a fallback provider in `.env`
- Multi-agent orchestration (`ENABLE_MULTI_AGENT`) is experimental
- Playwright browser validation requires Python 3.10+ and Chromium
- MCP server requires Python 3.10+
- Container-per-scan requires Docker daemon running
- Token budget tracking is approximate (estimates, not exact counts)
- CLI report (`neurosploit.py`) does not embed screenshots (backend reports do)

---

## File Structure

```
NeuroSploitv2/
+-- backend/
|   +-- api/v1/              # 14 API routers (111+ endpoints)
|   +-- core/                # 63 Python modules (37,546 lines)
|   |   +-- vuln_engine/     # 100-type vulnerability engine
|   |   |   +-- registry.py          # 100 vuln info + 100 tester classes
|   |   |   +-- payload_generator.py # 107 libraries, 477+ payloads
|   |   |   +-- ai_prompts.py        # 100 per-type AI decision prompts
|   |   |   +-- system_prompts.py    # 12 anti-hallucination templates
|   |   |   +-- testers/             # 12 tester modules
|   |   +-- autonomous_agent.py      # Main agent (7,592 lines)
|   |   +-- researcher_agent.py      # 0-day discovery AI
|   |   +-- reasoning_engine.py      # ReACT think/plan/reflect
|   |   +-- validation_judge.py      # Finding approval authority
|   |   +-- confidence_scorer.py     # Numeric 0-100 scoring
|   |   +-- proof_of_execution.py    # Per-type proof checks
|   |   +-- negative_control.py      # False positive detection
|   |   +-- request_engine.py        # Retry, rate limit, circuit breaker
|   |   +-- waf_detector.py          # 16 signatures, 12 bypasses
|   |   +-- strategy_adapter.py      # Dead endpoints, priority recompute
|   |   +-- chain_engine.py          # 10+ exploit chain rules
|   |   +-- exploit_generator.py     # AI-enhanced PoC generation
|   |   +-- cve_hunter.py            # NVD + GitHub exploit search
|   |   +-- deep_recon.py            # JS crawling, sitemap, API enum
|   |   +-- banner_analyzer.py       # 400 known CVEs, 19 EOL versions
|   |   +-- endpoint_classifier.py   # 8 types + risk scoring
|   |   +-- param_analyzer.py        # 8 semantic categories
|   |   +-- payload_mutator.py       # 14 mutation strategies
|   |   +-- xss_validator.py         # Playwright browser validation
|   |   +-- xss_context_analyzer.py  # 8 context detection
|   |   +-- auth_manager.py          # Multi-user session management
|   |   +-- token_budget.py          # Budget tracking + degradation
|   |   +-- agent_tasks.py           # Priority queue task manager
|   |   +-- agent_orchestrator.py    # Multi-agent coordinator
|   |   +-- specialist_agents.py     # 5 specialist agents
|   |   +-- execution_history.py     # Cross-scan learning
|   |   +-- access_control_learner.py# TP/FP adaptive learning
|   |   +-- report_generator.py      # Professional HTML reports
|   |   +-- report_engine/           # OHVR report engine
|   +-- models/              # 8 SQLAlchemy ORM models
|   +-- config.py            # Pydantic settings
|   +-- main.py              # FastAPI app entry
+-- frontend/
|   +-- src/
|   |   +-- pages/           # 14 React pages
|   |   +-- components/      # Reusable UI components
|   |   +-- services/        # API client + WebSocket
|   |   +-- store/           # Zustand state management
|   |   +-- types/           # TypeScript interfaces
+-- core/
|   +-- llm_manager.py       # 6-provider LLM routing
|   +-- tool_registry.py     # 55 security tools
|   +-- kali_sandbox.py      # Per-scan container management
|   +-- container_pool.py    # Global container coordinator
|   +-- sandbox_manager.py   # Sandbox abstraction layer
+-- docker/
|   +-- Dockerfile.kali      # Multi-stage Kali Linux image
|   +-- Dockerfile.backend   # Backend service
|   +-- Dockerfile.frontend  # Frontend builder
+-- config/
|   +-- config.json          # Profiles, roles, tools, routing
+-- data/
|   +-- vuln_knowledge_base.json  # 100 vulnerability entries
+-- neurosploit.py           # CLI entry point
+-- .env.example             # Environment template
```
