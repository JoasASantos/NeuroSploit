#!/usr/bin/env node
'use strict';
/**
 * NeuroSploit v4.0.0 — web console backend.
 *
 * Zero-dependency Node HTTP server that:
 *  - serves the static SPA in ./public
 *  - reads agents_md/ to build the "lead board" (agent/category picker)
 *  - reads runs/ to build run history + structured findings
 *  - spawns the compiled `neurosploit` CLI binary for exploitation runs and
 *    streams its stdout (parsed into structured events) over SSE
 *  - spawns the interactive `neurosploit` REPL (no subcommand) as a child
 *    process and pipes stdin/stdout so the browser gets a REAL REPL
 *    connected to the CLI harness — not a reimplementation.
 */

const http = require('node:http');
const fs = require('node:fs');
const fsp = fs.promises;
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { StringDecoder } = require('node:string_decoder');

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const WEB_DIR = __dirname;
const ROOT = path.resolve(WEB_DIR, '..'); // repo root — holds agents_md/, runs/
const AGENTS_DIR = path.join(ROOT, 'agents_md');
const RUNS_DIR = path.join(ROOT, 'runs');
const NAMES_FILE = path.join(ROOT, '.neurosploit', 'web-engagement-names.json');

// Engagement names are set by the operator in the wizard before launch (not
// something the CLI/harness knows about) — persisted here as runId -> name so
// the sidebar/run history can label a run by its engagement name across
// restarts, not just by target/run-id.
const engagementNames = new Map();
try {
  const raw = JSON.parse(fs.readFileSync(NAMES_FILE, 'utf8'));
  for (const [k, v] of Object.entries(raw)) engagementNames.set(k, v);
} catch { /* no file yet — fine */ }

function saveEngagementName(runId, name) {
  if (!runId || !name) return;
  engagementNames.set(runId, name);
  fsp.mkdir(path.dirname(NAMES_FILE), { recursive: true })
    .then(() => fsp.writeFile(NAMES_FILE, JSON.stringify(Object.fromEntries(engagementNames), null, 2)))
    .catch(() => {});
}
const PUBLIC_DIR = path.join(WEB_DIR, 'public');

function findBinary() {
  const candidates = [
    path.join(ROOT, 'neurosploit-rs', 'target', 'release', 'neurosploit'),
    path.join(ROOT, 'neurosploit-rs', 'target', 'debug', 'neurosploit'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}
const BIN = findBinary();

const PORT = Number(process.env.NEUROSPLOIT_WEB_PORT || process.env.PORT || 4173);

// ---------------------------------------------------------------------------
// Providers — mirrors crates/harness/src/models.rs `providers()`. Kept as a
// literal table (not parsed from CLI output) so `kind` ("cli" = usable via a
// locally-installed agentic CLI subscription login, "api" = key-only) and
// `envKey` (the environment variable the harness reads for that provider)
// are available without shelling out. Keep this in sync when models.rs adds
// a provider.
// ---------------------------------------------------------------------------

const PROVIDERS = [
  { key: 'anthropic', label: 'Anthropic Claude', kind: 'cli', envKey: 'ANTHROPIC_API_KEY',
    models: ['claude-opus-5', 'claude-sonnet-5', 'claude-opus-4-8', 'claude-sonnet-4-6', 'claude-haiku-4-5'] },
  { key: 'openai', label: 'OpenAI (ChatGPT)', kind: 'cli', envKey: 'OPENAI_API_KEY',
    models: ['gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.3-codex', 'gpt-5.2', 'gpt-5.1', 'gpt-5.1-codex', 'o4'] },
  { key: 'xai', label: 'xAI Grok', kind: 'cli', envKey: 'XAI_API_KEY',
    models: ['grok-4.5', 'grok-4', 'grok-4-fast'] },
  { key: 'gemini', label: 'Google Gemini', kind: 'cli', envKey: 'GEMINI_API_KEY',
    models: ['gemini-3-pro', 'gemini-2.5-pro', 'gemini-2.5-flash'] },
  { key: 'opencode', label: 'OpenCode Zen', kind: 'cli', envKey: 'OPENCODE_API_KEY',
    models: ['claude-opus-5', 'claude-sonnet-5', 'gpt-5.6-sol', 'gpt-5.5', 'gemini-3-pro', 'grok-4.5', 'deepseek-v4-pro', 'qwen3.7-max', 'kimi-k3'] },
  { key: 'nous', label: 'Nous Research (Hermes)', kind: 'cli', envKey: 'NOUS_API_KEY',
    models: ['Hermes-4-405B', 'Hermes-4-70B', 'DeepHermes-3-Mistral-24B-Preview'] },
  { key: 'nvidia_nim', label: 'NVIDIA NIM', kind: 'api', envKey: 'NVIDIA_NIM_API_KEY',
    models: ['nvidia/llama-3.3-nemotron-super-49b-v1', 'deepseek-ai/deepseek-r1', 'qwen/qwen2.5-coder-32b-instruct'] },
  { key: 'deepseek', label: 'DeepSeek', kind: 'api', envKey: 'DEEPSEEK_API_KEY',
    models: ['deepseek-reasoner', 'deepseek-chat'] },
  { key: 'mistral', label: 'Mistral', kind: 'api', envKey: 'MISTRAL_API_KEY',
    models: ['mistral-large-latest', 'codestral-latest'] },
  { key: 'qwen', label: 'Qwen (DashScope)', kind: 'api', envKey: 'DASHSCOPE_API_KEY',
    models: ['qwen-max', 'qwen2.5-coder-32b-instruct', 'qwq-plus'] },
  { key: 'groq', label: 'Groq', kind: 'api', envKey: 'GROQ_API_KEY',
    models: ['llama-3.3-70b-versatile', 'qwen-2.5-coder-32b'] },
  { key: 'together', label: 'Together AI', kind: 'api', envKey: 'TOGETHER_API_KEY',
    models: ['Qwen/Qwen2.5-Coder-32B-Instruct', 'deepseek-ai/DeepSeek-R1', 'meta-llama/Llama-3.3-70B-Instruct-Turbo'] },
  { key: 'moonshot', label: 'Moonshot AI (Kimi)', kind: 'api', envKey: 'MOONSHOT_API_KEY',
    models: ['kimi-k3', 'kimi-k2', 'moonshot-v1-128k', 'moonshot-v1-32k'] },
  { key: 'litellm', label: 'LiteLLM (proxy)', kind: 'api', envKey: 'LITELLM_API_KEY',
    models: ['gpt-4o', 'claude-3-7-sonnet', 'gemini/gemini-2.5-pro'] },
  { key: 'openrouter', label: 'OpenRouter', kind: 'api', envKey: 'OPENROUTER_API_KEY',
    models: ['anthropic/claude-opus-4-8', 'qwen/qwen-2.5-coder-32b-instruct', 'deepseek/deepseek-r1', 'meta-llama/llama-3.3-70b-instruct'] },
  { key: 'azure', label: 'Azure OpenAI', kind: 'api', envKey: 'AZURE_OPENAI_API_KEY',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-5.1', 'o4-mini'] },
  { key: 'ollama', label: 'Ollama (local)', kind: 'api', envKey: 'OLLAMA_API_KEY',
    models: ['qwen2.5-coder:32b', 'qwq:32b', 'deepseek-r1:32b', 'llama3.3:70b'] },
  { key: 'llamacpp', label: 'llama.cpp (local)', kind: 'api', envKey: 'LLAMACPP_API_KEY',
    models: ['qwen2.5-coder-32b-instruct', 'dolphin-2.9-llama3-70b', 'deepseek-r1-distill-qwen-32b', 'llama-3.3-70b-instruct'] },
];

// In-memory only — never written to disk. Cleared on server restart.
const apiKeys = new Map(); // provider key -> secret

function envOverrides() {
  const env = {};
  for (const [key, secret] of apiKeys) {
    const p = PROVIDERS.find((x) => x.key === key);
    if (p && secret) env[p.envKey] = secret;
  }
  return env;
}

/// Build a minimal creds.yaml-compatible file (see neurosploit-rs/creds.example.yaml)
/// from a raw auth header and/or named roles, so the CLI's --creds flag can be
/// used to carry web-entered auth material without a real file on disk.
function buildCredsYaml({ auth, roles }) {
  const lines = ['# generated by the NeuroSploit web console — ephemeral, not committed'];
  if (auth) lines.push(`header: ${JSON.stringify(auth)}`);
  for (const r of roles || []) {
    if (!r?.name || !r?.header) continue;
    const safe = String(r.name).replace(/[^a-zA-Z0-9_-]/g, '_');
    lines.push(`${safe}:`, `  header: ${JSON.stringify(r.header)}`);
  }
  return lines.join('\n') + '\n';
}

async function materializeCreds(body, jobId) {
  if (body.creds) return body.creds; // explicit file path on disk wins
  if (!body.auth && !(body.roles || []).length) return undefined;
  const dir = path.join(os.tmpdir(), 'neurosploit-web');
  await fsp.mkdir(dir, { recursive: true });
  const file = path.join(dir, `${jobId}.creds.yaml`);
  await fsp.writeFile(file, buildCredsYaml(body));
  return file;
}

// ---------------------------------------------------------------------------
// Agent library — read agents_md/{vulns,ai,infra,code,chains,recon,meta}/*.md
// and classify each into a lead category the UI can group + toggle.
// ---------------------------------------------------------------------------

const KIND_DIRS = {
  vulns: 'vuln',
  ai: 'ai',
  infra: 'infra',
  code: 'code',
  chains: 'chain',
  recon: 'recon',
  meta: 'meta',
};

// Ordered classifier: first matching rule wins. Mirrors the vocabulary used
// throughout agents_md/ so every agent lands in a sensible bucket for the
// lead board (screenshot-style category groups).
const CATEGORY_RULES = [
  [/^(llm_|mcp_|n8n_|redteam_|skill_|prompt_injection|ml_model_inversion|vector_db_injection)/, 'LLM Application'],
  [/^(xss_|dom_xss|blind_xss|mutation_xss|dom_clobbering|postmessage_vulnerability)/, 'Cross-Site Scripting'],
  [/^(jwt_|oauth_|oidc_|saml_|session_fixation|mfa_bypass|two_factor|twofa_|captcha_bypass|brute_force|default_credentials|weak_password|weak_jwt_secret|login_sqli_bypass|timing_side_channel_auth|timing_attack|refresh_token_abuse|auth_bypass|password_reset_poisoning)/, 'Auth & Session'],
  [/^(idor|bola|bfla|access_control_bypass|privilege_escalation|forced_browsing|authenticated_surface_exploit|exposed_admin_panel|spa_hidden_admin|mass_assignment|register_privilege_mass_assign|api_excessive_data|excessive_data_exposure|account_takeover_chain)/, 'Broken Access Control'],
  [/^(business_logic|spa_business_logic|coupon_logic_abuse|price_manipulation|workflow_step_skip|race_condition|idempotency_key_abuse|account_registration_and_forms)/, 'Business Logic'],
  [/^(sqli_|nosql_injection|ldap_injection|xpath_injection|xslt_injection|ssti|command_injection|log_injection|crlf_injection|header_injection|email_injection|smtp_injection|soap_injection|orm_injection|expression_language_injection|graphql_injection|css_injection|html_injection|csv_injection|formula_injection_excel|dangling_markup_injection|client_side_template_injection|server_side_prototype_pollution|prototype_pollution|xxe|path_traversal|^lfi$|^rfi$|zip_slip|log4shell_jndi|pickle_deserialization|insecure_deserialization|yaml_deserialization|type_juggling)/, 'Injection'],
  [/^(ssrf|gcp_metadata_ssrf|azure_imds_exposure|aws_imds_v2_bypass|host_header_injection|http_smuggling|http_desync|http2_request_smuggling|h2c_smuggling|reverse_proxy_path_confusion|websocket_)/, 'SSRF & Network'],
  [/^(graphql_|api_rate_limiting|rest_api_versioning|api_key_exposure|exposed_api_docs|spa_api_discovery|param_miner|parameter_pollution|grpc_reflection_exposure|api_bola)/, 'API & GraphQL'],
  [/^(aws_|azure_|gcp_|s3_bucket|gcs_bucket_misconfig|k8s_|docker_socket_exposure|container_escape|cloud_|terraform_state_exposure|helm_secret_exposure|ecr_public_exposure|serverless_|ci_cd_secret_leak|ad_)/, 'Cloud & Infra'],
  [/^(clickjacking|tabnabbing|cors_misconfig|insecure_cookie_flags|security_headers|subdomain_takeover|open_redirect|second_order_redirect|oauth_open_redirect_chain|csrf)/, 'Client-Side'],
  [/^(weak_encryption|weak_hashing|weak_random|padding_oracle|ecb_pattern_leak|ssl_issues|cleartext_transmission)/, 'Cryptography'],
  [/^(rate_limit|graphql_dos|regex_dos|range_header_dos|web_cache_poisoning_dos|llm_model_dos)/, 'Rate Limiting & DoS'],
  [/^(cache_poisoning|cdn_cache_key_poisoning|web_cache_deception|insecure_cdn|byte_range_cache|edge_side_includes)/, 'Cache & CDN'],
  [/^(cve_|eol_|version_disclosure|wordpress_audit|joomla_audit|drupal_audit|cms_|outdated_|dependency_confusion|typosquatting_package|vulnerable_dependency|git_exposed_repo|git_svn_exposure_app|source_code_disclosure|backup_file_exposure|env_file_exposure|debug_mode|aspnet_|appserver_exposure|misconfig_|iis_|information_disclosure|sensitive_data_exposure|directory_listing)/, 'Recon & Fingerprint'],
  [/^linux_/, 'Linux Host'],
  [/^windows_/, 'Windows Host'],
];

function classify(name, kind) {
  if (name.startsWith('custom_')) return 'Custom Leads'; // generated via /api/leads/generate
  if (kind === 'chain') return 'Attack Chains';
  if (kind === 'recon') return 'Recon';
  if (kind === 'code') return 'Code Review';
  if (kind === 'meta') return 'Meta & Reporting';
  if (kind === 'ai') return 'LLM Application';
  for (const [re, cat] of CATEGORY_RULES) {
    if (re.test(name)) return cat;
  }
  return 'Other';
}

function extractTitle(text, fallback) {
  const m = text.match(/^#\s+(.+?)\s*$/m);
  return m ? m[1].trim() : fallback;
}
function extractCwe(text) {
  const m = text.match(/CWE-\d+/);
  return m ? m[0] : '';
}

let agentCache = null;
let agentCacheAt = 0;

async function loadAgents() {
  const now = Date.now();
  if (agentCache && now - agentCacheAt < 5000) return agentCache;

  const agents = [];
  for (const [dir, kind] of Object.entries(KIND_DIRS)) {
    const full = path.join(AGENTS_DIR, dir);
    let entries = [];
    try {
      entries = await fsp.readdir(full);
    } catch {
      continue;
    }
    for (const file of entries) {
      if (!file.endsWith('.md')) continue;
      const name = file.slice(0, -3);
      const text = await fsp.readFile(path.join(full, file), 'utf8').catch(() => '');
      agents.push({
        id: name,
        name,
        title: extractTitle(text, name),
        cwe: extractCwe(text),
        kind,
        category: classify(name, kind),
      });
    }
  }
  agents.sort((a, b) => a.name.localeCompare(b.name));

  const byCategory = new Map();
  for (const a of agents) {
    if (!byCategory.has(a.category)) byCategory.set(a.category, []);
    byCategory.get(a.category).push(a);
  }
  // Selectable leads only (exclude meta/orchestration from the pentest board —
  // they're internal doctrine agents, not testable "leads").
  const LEAD_ORDER = [
    'Custom Leads',
    'Business Logic', 'Broken Access Control', 'Injection', 'Cross-Site Scripting',
    'LLM Application', 'Auth & Session', 'SSRF & Network', 'API & GraphQL',
    'Cloud & Infra', 'Client-Side', 'Cryptography', 'Rate Limiting & DoS',
    'Cache & CDN', 'Recon & Fingerprint', 'Linux Host', 'Windows Host',
    'Attack Chains', 'Code Review', 'Recon', 'Other',
  ];
  const categories = LEAD_ORDER
    .filter((c) => byCategory.has(c) && c !== 'Meta & Reporting')
    .map((c) => ({ category: c, agents: byCategory.get(c) }));

  agentCache = { total: agents.length, agents, categories };
  agentCacheAt = now;
  return agentCache;
}

// ---------------------------------------------------------------------------
// Custom leads — "+ Custom lead" generates a REAL specialist-agent markdown
// file (same format agents_md/vulns/*.md uses) via the `claude` CLI on the
// operator's Anthropic subscription, so a custom lead is an actual pinnable
// agent, not just free text folded into --focus. Mirrors the exact one-shot
// invocation harness::models::cli_login_status() uses for the same CLI.
// ---------------------------------------------------------------------------

const GEN_MODEL = 'claude-opus-4-8'; // matches Session::default() in app/src/repl.rs
const GEN_TIMEOUT_MS = 90_000;

function slugify(s) {
  return (s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40) || 'lead';
}

function buildSkillGenPrompt(description) {
  return `Write ONE new security-testing specialist-agent file for this custom lead, in EXACTLY this markdown shape and nothing else — no code fences around the whole thing, no preamble, no explanation, just the file content starting at the first line:

# <Short Title> Agent
## User Prompt
You are testing **{target}** for <the specific vulnerability class this lead targets>.
**Recon Context:**
{recon_json}
**METHODOLOGY:**
### 1. <step name>
- <concrete technique>
### 2. <step name>
- <concrete technique>
(as many numbered steps as the vuln class actually needs — terse, technical, no filler)
### Report
\`\`\`
FINDING:
- Title: ...
- Severity: ...
- CWE: CWE-<pick the single most fitting CWE number>
- Endpoint: [URL]
- Evidence: ...
- Impact: ...
- Remediation: ...
\`\`\`
## System Prompt
<one paragraph: the agent's persona plus the ONE calibration rule that stops it from reporting a finding without real proof>

The operator's custom lead request, verbatim: "${description}"

Match the doctrine style of NeuroSploit's other agents_md/vulns/*.md files: terse, technical, no marketing language, one CWE, a real report template.

Do not use any tools (no file writes, no bash, no search) — this is a pure text-completion task. Respond with ONLY the markdown file content above, nothing before it and nothing after it.`;
}

function generateCustomLead(description) {
  return new Promise((resolve, reject) => {
    if (!binaryOnPath('claude')) {
      return reject(new Error("claude CLI not found on PATH — install Claude Code and run `claude` to log in first"));
    }
    // No --dangerously-skip-permissions here: this is a pure text-completion
    // call (no bash/file tools needed), and granting tool access made claude
    // try to write the file itself and narrate doing so instead of just
    // returning text — see buildSkillGenPrompt()'s explicit "no tools" line.
    const child = spawn('claude', ['-p', '--model', GEN_MODEL, '--output-format', 'text'], { env: process.env });
    let out = '', err = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('generation timed out')); }, GEN_TIMEOUT_MS);
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    child.on('error', (e) => { clearTimeout(timer); reject(new Error(`claude CLI failed to start: ${e.message}`)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (!out.trim()) return reject(new Error(err.trim() || `claude exited ${code} with no output — is it logged in? run \`claude\` once to check.`));
      resolve(out);
    });
    child.stdin.write(buildSkillGenPrompt(description));
    child.stdin.end();
  });
}

function binaryOnPath(bin) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  return dirs.some((d) => { try { return fs.existsSync(path.join(d, bin)); } catch { return false; } });
}

// ---------------------------------------------------------------------------
// Runs — read runs/<id>/{meta,status,findings}.json
// ---------------------------------------------------------------------------

async function readJsonSafe(p, fallback) {
  try {
    return JSON.parse(await fsp.readFile(p, 'utf8'));
  } catch {
    return fallback;
  }
}

async function listRuns() {
  let ids = [];
  try {
    ids = (await fsp.readdir(RUNS_DIR)).filter((d) => d.startsWith('ns-'));
  } catch {
    return [];
  }
  const runs = await Promise.all(ids.map(async (id) => {
    const dir = path.join(RUNS_DIR, id);
    const [meta, status, findings] = await Promise.all([
      readJsonSafe(path.join(dir, 'meta.json'), {}),
      readJsonSafe(path.join(dir, 'status.json'), {}),
      readJsonSafe(path.join(dir, 'findings.json'), []),
    ]);
    const tsMatch = id.match(/^ns-(\d+)-/);
    const ts = tsMatch ? Number(tsMatch[1]) : 0;
    const sevCount = {};
    for (const f of findings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1;
    return {
      id,
      ts,
      name: engagementNames.get(id) || '',
      target: status.target || meta.target || id.replace(/^ns-\d+-/, ''),
      state: status.state || 'unknown',
      findings: findings.length,
      severities: sevCount,
      hasReport: fs.existsSync(path.join(dir, 'report.html')) || fs.existsSync(path.join(dir, 'report.pdf')),
    };
  }));
  runs.sort((a, b) => b.ts - a.ts);
  return runs;
}

/// Flat aggregate over every run for the dashboard.
///
/// Returns per-finding tuples rather than a computed risk number: the FAIR
/// estimate depends on assumptions (contact frequency, loss magnitude per
/// severity) that belong to the operator, not to this server, so the browser
/// computes it from parameters the operator can see and change.
async function stats() {
  let ids = [];
  try {
    ids = (await fsp.readdir(RUNS_DIR)).filter((d) => d.startsWith('ns-'));
  } catch {
    return { runs: [], findings: [], generated: Date.now() };
  }
  const runs = [];
  const findings = [];
  await Promise.all(ids.map(async (id) => {
    const dir = path.join(RUNS_DIR, id);
    const [status, fs_] = await Promise.all([
      readJsonSafe(path.join(dir, 'status.json'), {}),
      readJsonSafe(path.join(dir, 'findings.json'), []),
    ]);
    const meta = await readJsonSafe(path.join(dir, 'meta.json'), {});
    const tsMatch = id.match(/^ns-(\d+)-/);
    const ts = status.ts || (tsMatch ? Number(tsMatch[1]) : 0);
    const target = status.target || meta.target || id.replace(/^ns-\d+-/, '');
    runs.push({
      id,
      ts,
      name: engagementNames.get(id) || '',
      target,
      state: status.state || 'unknown',
      agentsRan: status.agents_ran || 0,
      findings: fs_.length,
    });
    for (const f of fs_) {
      findings.push({
        runId: id,
        target,
        ts,
        severity: f.severity || 'Info',
        cwe: f.cwe || '',
        owasp: f.owasp || '',
        stage: f.stage || '',
        agent: f.agent || '',
        title: f.title || '',
        exploitability: f.exploitability || '',
        confidence: typeof f.confidence === 'number' ? f.confidence : 0,
        reviewStatus: f.review_status || '',
      });
    }
  }));
  runs.sort((a, b) => b.ts - a.ts);
  return { runs, findings, generated: Date.now() };
}

async function runDetail(id) {
  const dir = safeRunDir(id);
  if (!dir) return null;
  const [meta, status, findings] = await Promise.all([
    readJsonSafe(path.join(dir, 'meta.json'), {}),
    readJsonSafe(path.join(dir, 'status.json'), {}),
    readJsonSafe(path.join(dir, 'findings.json'), []),
  ]);
  const assets = ['report.html', 'report.pdf', 'report.md', 'recon.md', 'exploitation.md', 'audit.jsonl', 'graph.json']
    .filter((f) => fs.existsSync(path.join(dir, f)));
  const pocs = await fsp.readdir(path.join(dir, 'pocs')).catch(() => []);
  return { id, name: engagementNames.get(id) || '', meta, status, findings, assets, pocs };
}

function safeRunDir(id) {
  if (!/^[a-zA-Z0-9_.-]+$/.test(id)) return null;
  const dir = path.join(RUNS_DIR, id);
  if (!dir.startsWith(RUNS_DIR)) return null;
  return dir;
}

// ---------------------------------------------------------------------------
// Exploitation jobs — spawn `neurosploit <mode> <target> --only ... -v`
// and parse its stdout into structured live state (mirrors app/src/repl.rs
// RunLive::ingest so the web UI gets the same phases/findings the TUI does).
// ---------------------------------------------------------------------------

const jobs = new Map(); // id -> Job

class Job extends EventEmitter {
  constructor(id, cmd, args, target, name) {
    super();
    this.id = id;
    this.cmd = cmd;
    this.args = args;
    this.target = target || '';
    this.name = name || '';
    this.pinnedAgents = [];
    this.runId = null; // ns-<ts>-<target> workdir basename, once known
    this.phase = 'starting';
    this.findings = [];
    this.feed = [];
    this.agents = 0;
    this.agentsDone = 0;
    this.done = false;
    this.exitCode = null;
    this.reportUrl = null;
    this.startedAt = Date.now();
    this.child = null;
  }
  push(evt) {
    this.feed.push(evt);
    if (this.feed.length > 2000) this.feed.shift();
    this.emit('event', evt);
  }
  snapshot() {
    return {
      id: this.id,
      target: this.target,
      name: this.name,
      pinnedAgents: this.pinnedAgents,
      interactive: !!this.repl,
      runId: this.runId,
      phase: this.phase,
      findings: this.findings,
      agents: this.agents,
      agentsDone: this.agentsDone,
      done: this.done,
      exitCode: this.exitCode,
      reportUrl: this.reportUrl,
      startedAt: this.startedAt,
    };
  }
}

const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;
function stripAnsi(s) { return s.replace(ANSI_RE, ''); }

function ingestLine(job, rawLine) {
  const line = stripAnsi(rawLine);
  const low = line.toLowerCase();
  job.push({ type: 'log', line });

  if (low.includes('paused by operator')) job.phase = 'paused (operator)';
  else if (low.includes('resumed by operator') || low.includes('▶ resumed')) job.phase = 'running';
  else if (low.includes('token/quota exhausted') || low.includes('run is paused')) job.phase = 'paused (quota)';
  else if (low.includes('authentication failed') || low.includes('circuit breaker')) job.phase = 'paused (auth)';
  else if (low.startsWith('recon') || low.startsWith('ai-recon') || low.includes('recon round') || low.startsWith('probe:')) job.phase = 'recon';
  else if (low.includes('selected') && low.includes('agent')) {
    job.phase = 'planning';
    const n = line.split(/\s+/).map(Number).find((x) => Number.isFinite(x));
    if (n) job.agents = n;
  } else if (low.startsWith('exploit') || low.startsWith('test ') || low.includes('launching agent')) job.phase = 'exploiting';
  else if (low.startsWith('vote') || low.includes('validating')) job.phase = 'validating';
  else if (low.startsWith('chain')) job.phase = 'chaining';
  else if (low.includes('phase complete') || low.includes('validated finding(s)')) {
    job.phase = 'complete';
    // A REPL-backed job's child process doesn't exit when the engagement
    // finishes (the session stays open for /report, /continue, another
    // /run, ...) — so 'done' has to come from content, not process exit.
    if (job.repl && !job.done) { job.done = true; job.push({ type: 'done', exitCode: 0 }); }
  }

  if (/candidate\(s\)/.test(low) && /^(exploit |test |analyze |review )/.test(low)) job.agentsDone += 1;

  const fj = line.match(/^finding_json:\s*(.+)$/);
  if (fj) {
    try {
      const finding = JSON.parse(fj[1]);
      job.findings.push(finding);
      job.push({ type: 'finding', finding });
    } catch { /* ignore malformed line */ }
  }

  const rep = line.match(/report:\s*(file:\/\/\S+)/);
  if (rep) job.reportUrl = rep[1];

  const rid = line.match(/run id\s*:\s*(\S+)/);
  if (rid) { job.runId = rid[1]; saveEngagementName(job.runId, job.name); }
}

function buildArgs(body) {
  const mode = body.mode || 'run';
  const args = [mode];
  if (mode === 'run' || mode === 'host' || mode === 'aitest') {
    args.push(body.target);
  } else if (mode === 'whitebox' || mode === 'skills') {
    args.push(body.repo || body.target);
  } else if (mode === 'greybox') {
    args.push(body.repo);
    args.push('--url', body.target);
  }
  for (const m of body.models || []) args.push('--model', m);
  if (body.votes) args.push('--vote-n', String(body.votes));
  if (body.chainDepth !== undefined) args.push('--chain-depth', String(body.chainDepth));
  if (body.recon) args.push('--recon', String(body.recon));
  if (body.maxAgents) args.push('--max-agents', String(body.maxAgents));
  if (body.offline) args.push('--offline');
  if (body.subscription) args.push('--subscription');
  if (body.mcp) args.push('--mcp');
  if (body.creds) args.push('--creds', body.creds);
  if (body.focus) args.push('--focus', body.focus);
  if (body.objective) args.push('--objective', body.objective);
  if (body.outOfScope) args.push('--out-of-scope', body.outOfScope);
  // Budget: omitted entirely means the full run, exactly as before budgets
  // existed — the web console never caps a run the operator didn't cap.
  if (body.budget && body.budget !== 'unlimited') args.push('--budget', body.budget);
  if (body.tokenLimit) args.push('--token-limit', String(body.tokenLimit));
  if (body.deepTestLimit) args.push('--deep-test-limit', String(body.deepTestLimit));
  if (body.order === 'depth-first') args.push('--depth-first');
  else if (body.order === 'coverage-first') args.push('--coverage-first');
  if (body.samplePerRoute) args.push('--sample-per-route', String(body.samplePerRoute));
  if (body.transport && body.transport !== 'direct') args.push('--transport', body.transport);
  if (body.oobDomain) args.push('--oob-domain', body.oobDomain);
  if (body.oobHttp) args.push('--oob-http', body.oobHttp);
  if (body.oobDns) args.push('--oob-dns', body.oobDns);
  if (body.sms) args.push('--sms', body.sms);
  if (body.intercept && body.intercept !== 'off') args.push('--intercept', body.intercept);
  if (body.sandbox) args.push('--sandbox', body.sandbox === 'default' ? '' : body.sandbox);
  if (body.revalidatePoc) args.push('--revalidate-poc');
  for (const fw of body.compliance || []) args.push('--compliance', fw);
  // Authorization: the signed grant caps the scope, the extra in-scope entries
  // can only narrow within it, and the environment scales every risk score.
  for (const entry of body.inScope || []) args.push('--in-scope', entry);
  if (body.capability) args.push('--capability-token', body.capability);
  if (body.environment) args.push('--environment', body.environment);
  if (body.policyProfile) args.push('--policy', body.policyProfile);
  for (const a of body.agents || []) args.push('--only', a);
  args.push('--verbose');
  return args;
}

async function startJob(body) {
  if (!BIN) throw new Error('neurosploit binary not found — run `cargo build --release` in neurosploit-rs/');
  const id = crypto.randomUUID();
  const credsPath = await materializeCreds(body, id);
  const args = buildArgs({ ...body, creds: credsPath });
  const job = new Job(id, BIN, args, body.repo || body.target || '', body.name || '');
  job.pinnedAgents = body.agents || [];
  jobs.set(id, job);

  const child = spawn(BIN, args, { cwd: ROOT, env: { ...process.env, ...envOverrides() } });
  job.child = child;
  let buf = '';
  const onData = (chunk) => {
    buf += chunk.toString('utf8');
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (line.length) ingestLine(job, line);
    }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  child.on('close', (code) => {
    if (buf.trim()) ingestLine(job, buf);
    job.done = true;
    job.exitCode = code;
    job.phase = job.phase === 'paused (quota)' || job.phase === 'paused (auth)' ? job.phase : 'complete';
    job.push({ type: 'done', exitCode: code });
  });
  child.on('error', (err) => {
    job.done = true;
    job.push({ type: 'log', line: `[web] failed to start neurosploit: ${err.message}` });
    job.push({ type: 'done', exitCode: -1 });
  });
  return job;
}

/// Turn the wizard's config into the REPL commands that produce the same
/// engagement (`/target`/`/repo` → `/model` → toggles → `/only` → `/run`).
/// `/only` is what makes this equivalent to the CLI's `--only` — REPL had no
/// such command before this feature (added to app/src/repl.rs alongside it).
/// Flags that apply to every mode, including the REPL-backed one. The REPL
/// takes them as argv because a `/`-command for an authorization ceiling would
/// let the session widen its own grant mid-run.
function authArgs(body) {
  const args = [];
  for (const entry of body.inScope || []) args.push('--in-scope', entry);
  if (body.capability) args.push('--capability-token', body.capability);
  if (body.environment) args.push('--environment', body.environment);
  if (body.policyProfile) args.push('--policy', body.policyProfile);
  // Egress and the OOB channel are launcher-level, like the grant: a session
  // must not be able to re-route its own traffic once it is running.
  if (body.transport && body.transport !== 'direct') args.push('--transport', body.transport);
  if (body.oobDomain) args.push('--oob-domain', body.oobDomain);
  if (body.oobHttp) args.push('--oob-http', body.oobHttp);
  if (body.oobDns) args.push('--oob-dns', body.oobDns);
  if (body.sms) args.push('--sms', body.sms);
  if (body.intercept && body.intercept !== 'off') args.push('--intercept', body.intercept);
  if (body.sandbox) args.push('--sandbox', body.sandbox === 'default' ? '' : body.sandbox);
  if (body.revalidatePoc) args.push('--revalidate-poc');
  for (const fw of body.compliance || []) args.push('--compliance', fw);
  if (body.budget && body.budget !== 'unlimited') args.push('--budget', body.budget);
  if (body.tokenLimit) args.push('--token-limit', String(body.tokenLimit));
  if (body.deepTestLimit) args.push('--deep-test-limit', String(body.deepTestLimit));
  if (body.order === 'depth-first') args.push('--depth-first');
  else if (body.order === 'coverage-first') args.push('--coverage-first');
  if (body.samplePerRoute) args.push('--sample-per-route', String(body.samplePerRoute));
  return args;
}

function buildReplScript(body) {
  const lines = [];
  if (body.mode === 'whitebox') lines.push(`/repo ${body.repo || body.target}`);
  else {
    if (body.target) lines.push(`/target ${body.target}`);
    if (body.mode === 'greybox' && body.repo) lines.push(`/repo ${body.repo}`);
  }
  if ((body.models || []).length) lines.push(`/model ${body.models.join(',')}`);
  lines.push(`/sub ${body.subscription ? 'on' : 'off'}`);
  lines.push(`/mcp ${body.mcp ? 'on' : 'off'}`);
  if (body.votes) lines.push(`/votes ${body.votes}`);
  if (body.chainDepth !== undefined) lines.push(`/chain ${body.chainDepth}`);
  if (body.recon) lines.push(`/recon ${body.recon}`);
  if (body.focus) lines.push(`/focus ${body.focus}`);
  if (body.objective) lines.push(`/objective ${body.objective}`);
  if (body.outOfScope) lines.push(`/scope-out ${body.outOfScope}`);
  if (body.creds) lines.push(`/creds ${body.creds}`);
  lines.push((body.agents || []).length ? `/only ${body.agents.join(',')}` : '/only clear');
  lines.push('/run');
  return lines;
}

/// Same job abstraction as startJob(), but driven through a REAL interactive
/// REPL session instead of a one-shot `neurosploit run ...` subprocess — the
/// engagement streams identically (same underlying pipeline, same tagged
/// lines), but the session KEEPS reading stdin while it runs, so the web UI
/// can send more input mid-run (natural language, /status, /stop, /continue)
/// via POST /api/exploit/:id/input. Only run/whitebox/greybox support this —
/// host/aitest/skills need onboarding's scope picker, which is an interactive
/// arrow-key menu that skips itself entirely over a piped stdin.
async function startJobViaRepl(body) {
  if (!BIN) throw new Error('neurosploit binary not found — run `cargo build --release` in neurosploit-rs/');
  const id = crypto.randomUUID();
  const credsPath = await materializeCreds(body, id);
  const script = buildReplScript({ ...body, creds: credsPath });
  const auth = authArgs(body);
  const job = new Job(id, BIN, auth, body.repo || body.target || '', body.name || '');
  job.pinnedAgents = body.agents || [];
  job.repl = true;
  jobs.set(id, job);

  // The REPL session inherits the engagement's authorization from argv, so the
  // ceiling is set before the first command is scripted into it.
  const child = spawn(BIN, auth, { cwd: ROOT, env: { ...process.env, ...envOverrides() } });
  job.child = child;
  let buf = '';
  const onData = (chunk) => {
    buf += chunk.toString('utf8');
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (line.length) ingestLine(job, line);
    }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  // The REPL process itself exiting (e.g. after /quit) is ALSO a valid done
  // signal, in addition to the content-based one in ingestLine().
  child.on('close', (code) => {
    if (buf.trim()) ingestLine(job, buf);
    if (!job.done) { job.done = true; job.push({ type: 'done', exitCode: code }); }
    job.exitCode = code;
  });
  child.on('error', (err) => {
    job.done = true;
    job.push({ type: 'log', line: `[web] failed to start neurosploit: ${err.message}` });
    job.push({ type: 'done', exitCode: -1 });
  });
  for (const line of script) child.stdin.write(line + '\n');
  return job;
}

// ---------------------------------------------------------------------------
// REPL sessions — spawn `neurosploit` with no subcommand (Reader::Plain kicks
// in over a piped stdin) and forward stdin/stdout verbatim: a real REPL.
//
// The stream is NOT ANSI-stripped: the browser renders it in xterm.js, which
// is the same terminal emulator a local shell would drive, so colour, cursor
// moves and the harness's own spinners arrive intact. Stripping here would
// hand the emulator a degraded copy of what the CLI actually printed.
// ---------------------------------------------------------------------------

const replSessions = new Map();

class ReplSession extends EventEmitter {
  constructor(id, child) {
    super();
    this.id = id;
    this.child = child;
    this.done = false;
    this.buffer = [];
    this.bytes = 0;
  }
  push(chunk) {
    this.buffer.push(chunk);
    this.bytes += chunk.length;
    // Bound the replay buffer by size, not chunk count: one chunk can be a
    // single keystroke echo or a whole recon dump, so counting chunks caps
    // memory nowhere near where it's meant to.
    while (this.bytes > 512_000 && this.buffer.length > 1) {
      this.bytes -= this.buffer.shift().length;
    }
    this.emit('data', chunk);
  }
}

function startRepl() {
  if (!BIN) throw new Error('neurosploit binary not found — run `cargo build --release` in neurosploit-rs/');
  const id = crypto.randomUUID();
  const child = spawn(BIN, [], {
    cwd: ROOT,
    // Without TERM the harness assumes a dumb terminal and drops colour; the
    // browser side is a full xterm, so say so.
    env: { ...process.env, ...envOverrides(), TERM: 'xterm-256color' },
  });
  const session = new ReplSession(id, child);
  replSessions.set(id, session);
  // One decoder per stream: a chunk boundary can land mid-UTF-8-sequence, and
  // decoding each chunk independently would emit replacement characters.
  const decOut = new StringDecoder('utf8');
  const decErr = new StringDecoder('utf8');
  child.stdout.on('data', (c) => session.push(decOut.write(c)));
  child.stderr.on('data', (c) => session.push(decErr.write(c)));
  child.on('close', (code) => {
    session.done = true;
    session.push(`\r\n\x1b[2m[repl session ended, exit code ${code}]\x1b[0m\r\n`);
    session.emit('close');
  });
  child.on('error', (err) => {
    session.done = true;
    session.push(`\r\n\x1b[31m[failed to start neurosploit: ${err.message}]\x1b[0m\r\n`);
    session.emit('close');
  });
  return session;
}

// ---------------------------------------------------------------------------
// Tiny HTTP plumbing (no framework)
// ---------------------------------------------------------------------------

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 5_000_000) req.destroy(); });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function sseInit(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(':ok\n\n');
}
function sseSend(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.pdf': 'application/pdf',
  '.md': 'text/plain; charset=utf-8',
};

async function serveStatic(req, res, urlPath) {
  let rel = urlPath === '/' ? '/index.html' : urlPath;
  const full = path.join(PUBLIC_DIR, rel);
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end(); return; }
  try {
    const data = await fsp.readFile(full);
    const ext = path.extname(full);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('not found');
  }
}

async function serveRunAsset(req, res, id, rest) {
  const dir = safeRunDir(id);
  if (!dir) { res.writeHead(400); res.end(); return; }
  const full = path.join(dir, rest);
  if (!full.startsWith(dir)) { res.writeHead(403); res.end(); return; }
  try {
    const data = await fsp.readFile(full);
    const ext = path.extname(full);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('not found');
  }
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;

  try {
    // ---- static ----
    if (req.method === 'GET' && !p.startsWith('/api/')) {
      return serveStatic(req, res, p);
    }

    // ---- agents / lead board ----
    if (req.method === 'GET' && p === '/api/agents') {
      return sendJson(res, 200, await loadAgents());
    }
    if (req.method === 'POST' && p === '/api/leads/generate') {
      const body = await readBody(req);
      const description = (body.description || '').trim();
      if (!description) return sendJson(res, 400, { error: 'description is required' });
      let raw;
      try {
        raw = await generateCustomLead(description);
      } catch (e) {
        return sendJson(res, 502, { error: e.message });
      }
      // Defensive: discard any wrapper text before the first '# ' heading —
      // a model with tool access sometimes narrates ("I'll write the file
      // now...") before the actual content despite being told not to.
      const titleIdx = raw.search(/^#\s+/m);
      if (titleIdx === -1) {
        return sendJson(res, 502, { error: 'generation did not return a well-formed agent file', raw: raw.slice(0, 800) });
      }
      const clean = raw.slice(titleIdx).trim();
      const titleMatch = clean.match(/^#\s+(.+?)\s*$/m);
      if (!titleMatch || !/##\s*User Prompt/i.test(clean) || !/##\s*System Prompt/i.test(clean)) {
        return sendJson(res, 502, { error: 'generation did not return a well-formed agent file', raw: raw.slice(0, 800) });
      }
      const slug = `custom_${slugify(titleMatch[1])}`;
      await fsp.writeFile(path.join(AGENTS_DIR, 'vulns', `${slug}.md`), clean + '\n');
      agentCache = null; // force a fresh read so the new lead shows up immediately
      const { agents } = await loadAgents();
      const created = agents.find((a) => a.id === slug);
      return sendJson(res, 200, { agent: created, raw: clean });
    }

    // ---- runs ----
    if (req.method === 'GET' && p === '/api/runs') {
      return sendJson(res, 200, await listRuns());
    }
    let m = p.match(/^\/api\/runs\/([^/]+)$/);
    if (req.method === 'GET' && m) {
      const detail = await runDetail(decodeURIComponent(m[1]));
      if (!detail) return sendJson(res, 404, { error: 'run not found' });
      return sendJson(res, 200, detail);
    }
    m = p.match(/^\/api\/runs\/([^/]+)\/asset\/(.+)$/);
    if (req.method === 'GET' && m) {
      return serveRunAsset(req, res, decodeURIComponent(m[1]), decodeURIComponent(m[2]));
    }

    // ---- exploitation jobs ----
    if (req.method === 'GET' && p === '/api/exploit') {
      return sendJson(res, 200, [...jobs.values()].map((j) => j.snapshot()));
    }
    if (req.method === 'POST' && p === '/api/exploit') {
      const body = await readBody(req);
      // run/whitebox/greybox go through a real REPL session so the operator
      // can keep sending it input while it streams; host/aitest/skills need
      // the onboarding scope picker (an interactive menu that only works on
      // a real TTY), so they stay on the plain one-shot CLI subprocess.
      const replCapable = ['run', 'whitebox', 'greybox'].includes(body.mode || 'run');
      const job = replCapable ? await startJobViaRepl(body) : await startJob(body);
      return sendJson(res, 200, { id: job.id, interactive: !!job.repl });
    }
    m = p.match(/^\/api\/exploit\/([^/]+)$/);
    if (req.method === 'GET' && m) {
      const job = jobs.get(m[1]);
      if (!job) return sendJson(res, 404, { error: 'job not found' });
      return sendJson(res, 200, job.snapshot());
    }
    m = p.match(/^\/api\/exploit\/([^/]+)\/stop$/);
    if (req.method === 'POST' && m) {
      const job = jobs.get(m[1]);
      if (!job) return sendJson(res, 404, { error: 'job not found' });
      if (job.repl && job.child?.stdin?.writable) {
        // The REPL's own graceful stop: /stop then choose "1" — validate
        // what's found so far, then report. Plain SIGINT doesn't map to
        // anything here (no signal handler in the REPL's own input loop).
        job.child.stdin.write('/stop\n1\n');
      } else {
        job.child?.kill('SIGINT');
      }
      return sendJson(res, 200, { ok: true });
    }
    // Pause / resume / report-where-it-stopped. All three are REPL commands,
    // so they only exist on a REPL-backed job — a one-shot CLI subprocess has
    // no stdin listener to take them.
    m = p.match(/^\/api\/exploit\/([^/]+)\/(pause|continue|report)$/);
    if (req.method === 'POST' && m) {
      const job = jobs.get(m[1]);
      if (!job) return sendJson(res, 404, { error: 'job not found' });
      if (!job.repl || !job.child?.stdin?.writable) {
        return sendJson(res, 409, { error: 'this job is not an interactive session — pause/continue/report need a REPL-backed run (run, whitebox or greybox)' });
      }
      const cmd = { pause: '/pause', continue: '/continue', report: '/report' }[m[2]];
      job.child.stdin.write(cmd + '\n');
      if (m[2] === 'pause') job.phase = 'paused (operator)';
      else if (m[2] === 'continue' && job.phase.startsWith('paused')) job.phase = 'resuming';
      return sendJson(res, 200, { ok: true, sent: cmd });
    }

    // The whole log, as text — for downloading or pasting into a ticket.
    m = p.match(/^\/api\/exploit\/([^/]+)\/log$/);
    if (req.method === 'GET' && m) {
      const job = jobs.get(m[1]);
      if (!job) return sendJson(res, 404, { error: 'job not found' });
      const body = job.feed.filter((e) => e.type === 'log').map((e) => e.line).join('\n') + '\n';
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'content-disposition': `attachment; filename="neurosploit-${job.runId || job.id}.log"`,
      });
      return res.end(body);
    }

    m = p.match(/^\/api\/exploit\/([^/]+)\/input$/);
    if (req.method === 'POST' && m) {
      const job = jobs.get(m[1]);
      if (!job) return sendJson(res, 404, { error: 'job not found' });
      if (!job.repl || !job.child?.stdin?.writable) {
        return sendJson(res, 409, { error: 'this job is not an interactive session (host/aitest/skills engagements run non-interactively)' });
      }
      const body = await readBody(req);
      job.child.stdin.write(String(body.line ?? '') + '\n');
      return sendJson(res, 200, { ok: true });
    }
    m = p.match(/^\/api\/exploit\/([^/]+)\/events$/);
    if (req.method === 'GET' && m) {
      const job = jobs.get(m[1]);
      if (!job) { res.writeHead(404); return res.end(); }
      sseInit(res);
      // replay what already happened
      for (const evt of job.feed) sseSend(res, evt.type, evt);
      sseSend(res, 'snapshot', job.snapshot());
      if (job.done) { sseSend(res, 'done', job.snapshot()); res.end(); return; }
      const onEvt = (evt) => sseSend(res, evt.type, evt);
      job.on('event', onEvt);
      const ping = setInterval(() => res.write(':ping\n\n'), 20000);
      req.on('close', () => { job.off('event', onEvt); clearInterval(ping); });
      return;
    }

    // ---- REPL (real CLI harness session) ----
    if (req.method === 'POST' && p === '/api/repl') {
      const session = startRepl();
      return sendJson(res, 200, { id: session.id });
    }
    m = p.match(/^\/api\/repl\/([^/]+)\/input$/);
    if (req.method === 'POST' && m) {
      const session = replSessions.get(m[1]);
      if (!session) return sendJson(res, 404, { error: 'session not found' });
      const body = await readBody(req);
      // `data` is raw (whatever the terminal captured); `line` is the older
      // line-oriented form and still gets its newline appended here.
      const raw = body.data != null ? String(body.data) : String(body.line ?? '') + '\n';
      // Ctrl-C over a pipe is not a signal — nothing turns byte 0x03 into
      // SIGINT when there is no tty in between, so the interrupt has to be
      // delivered explicitly or it would silently do nothing.
      if (raw.includes('\x03')) {
        session.child.kill('SIGINT');
        return sendJson(res, 200, { ok: true, signalled: 'SIGINT' });
      }
      if (!session.child.stdin.writable) return sendJson(res, 409, { error: 'session has ended' });
      session.child.stdin.write(raw);
      return sendJson(res, 200, { ok: true });
    }
    m = p.match(/^\/api\/repl\/([^/]+)\/stop$/);
    if (req.method === 'POST' && m) {
      const session = replSessions.get(m[1]);
      if (!session) return sendJson(res, 404, { error: 'session not found' });
      session.child.kill('SIGTERM');
      return sendJson(res, 200, { ok: true });
    }
    m = p.match(/^\/api\/repl\/([^/]+)\/events$/);
    if (req.method === 'GET' && m) {
      const session = replSessions.get(m[1]);
      if (!session) { res.writeHead(404); return res.end(); }
      sseInit(res);
      for (const chunk of session.buffer) sseSend(res, 'data', { chunk });
      if (session.done) { sseSend(res, 'close', {}); res.end(); return; }
      const onData = (chunk) => sseSend(res, 'data', { chunk });
      const onClose = () => { sseSend(res, 'close', {}); res.end(); };
      session.on('data', onData);
      session.on('close', onClose);
      const ping = setInterval(() => res.write(':ping\n\n'), 20000);
      req.on('close', () => { session.off('data', onData); session.off('close', onClose); clearInterval(ping); });
      return;
    }

    // ---- report rebuild (generate/refresh the PDF for a finished run) ----
    m = p.match(/^\/api\/runs\/([^/]+)\/report$/);
    if (req.method === 'POST' && m) {
      const id = decodeURIComponent(m[1]);
      const dir = safeRunDir(id);
      if (!dir || !fs.existsSync(dir)) return sendJson(res, 404, { error: 'run not found' });
      if (!BIN) return sendJson(res, 500, { error: 'neurosploit binary not found — run `cargo build --release` in neurosploit-rs/' });
      // The harness owns report generation (Typst template, severity ordering,
      // the evidence sections); shelling out to it keeps one implementation
      // instead of a second, drifting one in JavaScript.
      const out = await new Promise((resolve) => {
        const child = spawn(BIN, ['rebuild', dir], { cwd: ROOT, env: { ...process.env, ...envOverrides() } });
        let buf = '';
        child.stdout.on('data', (c) => { buf += c.toString('utf8'); });
        child.stderr.on('data', (c) => { buf += c.toString('utf8'); });
        child.on('close', (code) => resolve({ code, buf }));
        child.on('error', (e) => resolve({ code: -1, buf: e.message }));
      });
      const built = ['report.pdf', 'report.html', 'report.md', 'report.json'].filter((f) => fs.existsSync(path.join(dir, f)));
      if (out.code !== 0 && !built.includes('report.pdf')) {
        return sendJson(res, 502, { error: stripAnsi(out.buf).trim() || 'rebuild failed', built });
      }
      return sendJson(res, 200, {
        ok: true,
        built,
        // Typst is optional; saying so beats handing back a link to a file that
        // was never produced.
        pdf: built.includes('report.pdf'),
        note: built.includes('report.pdf') ? '' : 'PDF needs the `typst` binary on PATH — the HTML and Markdown reports were rebuilt.',
      });
    }

    // ---- aggregate stats for the dashboard ----
    if (req.method === 'GET' && p === '/api/stats') {
      return sendJson(res, 200, await stats());
    }

    if (req.method === 'GET' && p === '/api/meta') {
      return sendJson(res, 200, { version: '4.0.0', binary: BIN, root: ROOT });
    }

    // ---- providers / API keys (in-memory only, never persisted) ----
    if (req.method === 'GET' && p === '/api/providers') {
      return sendJson(res, 200, PROVIDERS.map(({ key, label, kind, models }) => ({ key, label, kind, models })));
    }
    if (req.method === 'GET' && p === '/api/keys') {
      return sendJson(res, 200, PROVIDERS.map((pr) => ({ provider: pr.key, set: apiKeys.has(pr.key) && !!apiKeys.get(pr.key) })));
    }
    if (req.method === 'POST' && p === '/api/keys') {
      const body = await readBody(req);
      if (!body.provider || !PROVIDERS.some((pr) => pr.key === body.provider)) {
        return sendJson(res, 400, { error: 'unknown provider' });
      }
      if (body.key) apiKeys.set(body.provider, body.key);
      else apiKeys.delete(body.provider);
      return sendJson(res, 200, { ok: true });
    }
    m = p.match(/^\/api\/keys\/([^/]+)$/);
    if (req.method === 'DELETE' && m) {
      apiKeys.delete(decodeURIComponent(m[1]));
      return sendJson(res, 200, { ok: true });
    }

    sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    sendJson(res, 500, { error: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`NeuroSploit v4.0.0 web console → http://localhost:${PORT}`);
  console.log(`  binary : ${BIN || '(not found — build neurosploit-rs first)'}`);
  console.log(`  agents : ${AGENTS_DIR}`);
  console.log(`  runs   : ${RUNS_DIR}`);
});
