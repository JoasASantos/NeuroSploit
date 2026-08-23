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
const path = require('node:path');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const WEB_DIR = __dirname;
const ROOT = path.resolve(WEB_DIR, '..'); // repo root — holds agents_md/, runs/
const AGENTS_DIR = path.join(ROOT, 'agents_md');
const RUNS_DIR = path.join(ROOT, 'runs');
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

async function runDetail(id) {
  const dir = safeRunDir(id);
  if (!dir) return null;
  const [meta, status, findings] = await Promise.all([
    readJsonSafe(path.join(dir, 'meta.json'), {}),
    readJsonSafe(path.join(dir, 'status.json'), {}),
    readJsonSafe(path.join(dir, 'findings.json'), []),
  ]);
  const assets = ['report.html', 'report.pdf', 'report.md', 'recon.md', 'exploitation.md']
    .filter((f) => fs.existsSync(path.join(dir, f)));
  return { id, meta, status, findings, assets };
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
  constructor(id, cmd, args, target) {
    super();
    this.id = id;
    this.cmd = cmd;
    this.args = args;
    this.target = target || '';
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

  if (low.includes('token/quota exhausted') || low.includes('run is paused')) job.phase = 'paused (quota)';
  else if (low.includes('authentication failed') || low.includes('circuit breaker')) job.phase = 'paused (auth)';
  else if (low.startsWith('recon') || low.startsWith('ai-recon') || low.includes('recon round') || low.startsWith('probe:')) job.phase = 'recon';
  else if (low.includes('selected') && low.includes('agent')) {
    job.phase = 'planning';
    const n = line.split(/\s+/).map(Number).find((x) => Number.isFinite(x));
    if (n) job.agents = n;
  } else if (low.startsWith('exploit') || low.startsWith('test ') || low.includes('launching agent')) job.phase = 'exploiting';
  else if (low.startsWith('vote') || low.includes('validating')) job.phase = 'validating';
  else if (low.startsWith('chain')) job.phase = 'chaining';
  else if (low.includes('phase complete') || low.includes('validated finding(s)')) job.phase = 'complete';

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
  if (rid) job.runId = rid[1];
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
  for (const a of body.agents || []) args.push('--only', a);
  args.push('--verbose');
  return args;
}

function startJob(body) {
  if (!BIN) throw new Error('neurosploit binary not found — run `cargo build --release` in neurosploit-rs/');
  const id = crypto.randomUUID();
  const args = buildArgs(body);
  const job = new Job(id, BIN, args, body.repo || body.target || '');
  jobs.set(id, job);

  const child = spawn(BIN, args, { cwd: ROOT, env: process.env });
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

// ---------------------------------------------------------------------------
// REPL sessions — spawn `neurosploit` with no subcommand (Reader::Plain kicks
// in over a piped stdin) and forward stdin/stdout verbatim: a real REPL.
// ---------------------------------------------------------------------------

const replSessions = new Map();

class ReplSession extends EventEmitter {
  constructor(id, child) {
    super();
    this.id = id;
    this.child = child;
    this.done = false;
    this.buffer = [];
  }
  push(chunk) {
    this.buffer.push(chunk);
    if (this.buffer.length > 5000) this.buffer.shift();
    this.emit('data', chunk);
  }
}

function startRepl() {
  if (!BIN) throw new Error('neurosploit binary not found — run `cargo build --release` in neurosploit-rs/');
  const id = crypto.randomUUID();
  const child = spawn(BIN, [], { cwd: ROOT, env: process.env });
  const session = new ReplSession(id, child);
  replSessions.set(id, session);
  const onData = (chunk) => session.push(stripAnsi(chunk.toString('utf8')));
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  child.on('close', (code) => {
    session.done = true;
    session.push(`\n[repl session ended, exit code ${code}]\n`);
    session.emit('close');
  });
  child.on('error', (err) => {
    session.done = true;
    session.push(`\n[failed to start neurosploit: ${err.message}]\n`);
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
      const job = startJob(body);
      return sendJson(res, 200, { id: job.id });
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
      job.child?.kill('SIGINT');
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
      session.child.stdin.write(String(body.line ?? '') + '\n');
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

    if (req.method === 'GET' && p === '/api/meta') {
      return sendJson(res, 200, { version: '4.0.0', binary: BIN, root: ROOT });
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
