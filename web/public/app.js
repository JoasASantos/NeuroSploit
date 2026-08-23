'use strict';
/* NeuroSploit v4.0.0 — web console frontend. Vanilla JS, no build step. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const MODE_LABELS = {
  run: { target: 'Target URL', help: 'The application to test.', showRepo: false, placeholder: 'https://target.example.com' },
  whitebox: { target: 'Source repo / path', help: "A GitHub URL, owner/repo shorthand, or a local path — cloned automatically if it's remote.", showRepo: false, placeholder: 'owner/repo' },
  greybox: { target: 'Target URL', help: 'The running application to exploit, alongside the source repo below.', showRepo: true, placeholder: 'https://target.example.com' },
  host: { target: 'Target host / IP', help: 'Runs Linux / Windows / Active Directory agents.', showRepo: false, placeholder: '10.0.0.10' },
  aitest: { target: 'AI endpoint URL', help: 'A live AI agent, LLM chat, or MCP endpoint (OWASP LLM Top 10).', showRepo: false, placeholder: 'https://target.example.com/chat' },
};

const STEP_COUNT = 5;

const state = {
  theme: localStorage.getItem('ns-theme') || 'light',
  step: 0,
  mode: 'run',
  categories: [],
  selected: new Set(),
  customLeads: [],
  filter: 'all',
  search: '',
  providers: [],
  auth: { header: '', roles: [] },
  credsPath: '',
  keys: [],
  runs: [],
  currentJob: null,
  currentDetailId: null,
  detailPoll: null,
  replId: null, replEs: null,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${path} → ${res.status}`);
  }
  return res.headers.get('content-type')?.includes('json') ? res.json() : res.text();
}
function sevRank(sev) {
  const s = (sev || '').toLowerCase();
  if (s.includes('crit')) return 0;
  if (s.includes('high')) return 1;
  if (s.includes('med')) return 2;
  if (s.includes('low')) return 3;
  return 4;
}
function sevClass(sev) {
  return ['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info'][sevRank(sev)];
}
function show(el, on) { if (el) el.hidden = !on; }
function toast(msg) { console.log('[ns]', msg); }

// ---------------------------------------------------------------------------
// theme
// ---------------------------------------------------------------------------

function applyTheme() {
  document.documentElement.setAttribute('data-theme', state.theme);
  $('#btnThemeToggle').textContent = state.theme === 'dark' ? '☀' : '☾';
  $('#btnThemeToggle').title = state.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
}
$('#btnThemeToggle').addEventListener('click', () => {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('ns-theme', state.theme);
  applyTheme();
});

// ---------------------------------------------------------------------------
// wizard — step navigation
// ---------------------------------------------------------------------------

function goToStep(n) {
  state.step = Math.max(0, Math.min(STEP_COUNT - 1, n));
  $$('.step-tab').forEach((tab, i) => {
    tab.classList.toggle('active', i === state.step);
    tab.classList.toggle('done', i < state.step);
  });
  $$('.wizard-panel').forEach((panel) => show(panel, Number(panel.dataset.panel) === state.step));
  show($('#btnStepBack'), state.step > 0);
  show($('#btnStepNext'), state.step < STEP_COUNT - 1);
  show($('#btnLaunch'), state.step === STEP_COUNT - 1);
  if (state.step === STEP_COUNT - 1) renderReview();
  updateWizardSummary();
}

function validateStep(n) {
  if (n === 0) {
    if (!$('#fieldName').value.trim()) { alert('Name the engagement first — it identifies this run in the sidebar and history.'); $('#fieldName').focus(); return false; }
    const target = $('#fieldTarget').value.trim();
    if (!target) { alert(`${MODE_LABELS[state.mode].target} is required.`); return false; }
    if (state.mode === 'greybox' && !$('#fieldRepo').value.trim()) { alert('Source repo is required for grey-box.'); return false; }
  }
  return true;
}

$('#btnStepNext').addEventListener('click', () => { if (validateStep(state.step)) goToStep(state.step + 1); });
$('#btnStepBack').addEventListener('click', () => goToStep(state.step - 1));
$$('.step-tab').forEach((tab) => tab.addEventListener('click', () => {
  const n = Number(tab.dataset.step);
  if (n <= state.step || validateStep(state.step)) goToStep(n);
}));

function updateWizardSummary() {
  const name = $('#fieldName').value.trim() || '(unnamed)';
  const target = $('#fieldTarget').value.trim() || '(not set)';
  $('#wizardSummary').innerHTML = `Step ${state.step + 1} of ${STEP_COUNT} · <b>${esc(name)}</b> · ${esc(state.mode)} · ${esc(target)}`;
}
$('#fieldName').addEventListener('input', updateWizardSummary);

// mode tiles
function selectMode(mode) {
  state.mode = mode;
  $$('.mode-tile').forEach((t) => t.classList.toggle('selected', t.dataset.mode === mode));
  const cfg = MODE_LABELS[mode];
  $('#targetLabel').textContent = cfg.target;
  $('#targetHelp').textContent = cfg.help;
  $('#fieldTarget').placeholder = cfg.placeholder;
  show($('#fieldRepoGroup'), cfg.showRepo);
  updateWizardSummary();
}
$$('.mode-tile').forEach((tile) => tile.addEventListener('click', () => selectMode(tile.dataset.mode)));
$('#fieldTarget').addEventListener('input', updateWizardSummary);

// ---------------------------------------------------------------------------
// agents / lead board (step 3)
// ---------------------------------------------------------------------------

async function loadAgents() {
  const data = await api('/api/agents');
  state.categories = data.categories;
  renderBoard();
}

function renderBoard() {
  const root = $('#categories');
  root.innerHTML = '';
  for (const group of state.categories) {
    const selCount = group.agents.filter((a) => state.selected.has(a.id)).length;
    const card = document.createElement('div');
    card.className = 'cat-card';
    card.innerHTML = `
      <div class="cat-head">
        <label class="switch">
          <input type="checkbox" class="cat-toggle" ${selCount === group.agents.length ? 'checked' : ''} />
          <span class="track"></span><span class="thumb"></span>
        </label>
        <span class="cat-name">${esc(group.category)}</span>
        <span class="cat-count">${selCount} / ${group.agents.length}</span>
        <span class="caret">▾</span>
      </div>
      <div class="agent-rows"></div>
    `;
    const rows = card.querySelector('.agent-rows');
    for (const a of group.agents) {
      const row = document.createElement('div');
      row.className = 'agent-row';
      row.dataset.id = a.id;
      row.dataset.title = (a.title + ' ' + a.name).toLowerCase();
      row.innerHTML = `
        <label class="switch">
          <input type="checkbox" class="agent-toggle" data-id="${esc(a.id)}" ${state.selected.has(a.id) ? 'checked' : ''} />
          <span class="track"></span><span class="thumb"></span>
        </label>
        <span class="agent-title">${esc(a.title)}</span>
        ${a.cwe ? `<span class="agent-cwe">${esc(a.cwe)}</span>` : ''}
      `;
      rows.appendChild(row);
    }
    card.querySelector('.cat-head').addEventListener('click', (e) => {
      if (e.target.closest('.switch')) return;
      card.classList.toggle('collapsed');
    });
    card.querySelector('.cat-toggle').addEventListener('change', (e) => {
      const on = e.target.checked;
      for (const a of group.agents) { if (on) state.selected.add(a.id); else state.selected.delete(a.id); }
      renderBoard();
    });
    rows.querySelectorAll('.agent-toggle').forEach((input) => {
      input.addEventListener('change', (e) => {
        const id = e.target.dataset.id;
        if (e.target.checked) state.selected.add(id); else state.selected.delete(id);
        renderBoard();
      });
    });
    root.appendChild(card);
  }
  updateChips();
  applyFilters();
}

function allAgents() { return state.categories.flatMap((g) => g.agents); }

function updateChips() {
  const total = allAgents().length;
  $('#chipAll').textContent = total;
  $('#chipSelected').textContent = state.selected.size;
  $('#chipExcluded').textContent = total - state.selected.size;
}

function applyFilters() {
  const q = state.search.trim().toLowerCase();
  $$('.agent-row').forEach((row) => {
    const isSel = state.selected.has(row.dataset.id);
    let visible = true;
    if (state.filter === 'selected') visible = isSel;
    if (state.filter === 'excluded') visible = !isSel;
    if (visible && q) visible = row.dataset.title.includes(q);
    row.classList.toggle('hidden-by-search', !visible);
  });
  $$('.cat-card').forEach((card) => {
    const anyVisible = $$('.agent-row', card).some((r) => !r.classList.contains('hidden-by-search'));
    card.style.display = anyVisible ? '' : 'none';
  });
}

$$('.chip').forEach((chip) => chip.addEventListener('click', () => {
  $$('.chip').forEach((c) => c.classList.remove('chip-active'));
  chip.classList.add('chip-active');
  state.filter = chip.dataset.filter;
  applyFilters();
}));
$('#leadSearch').addEventListener('input', (e) => { state.search = e.target.value; applyFilters(); });

function renderCustomLeads() {
  const root = $('#customLeadsList');
  root.innerHTML = state.customLeads.map((text, i) => `
    <div class="custom-lead-chip"><span>${esc(text)}</span><span class="x" data-i="${i}">✕</span></div>
  `).join('');
  $$('.custom-lead-chip .x', root).forEach((x) => x.addEventListener('click', () => {
    state.customLeads.splice(Number(x.dataset.i), 1);
    renderCustomLeads();
  }));
}
$('#btnCustomLead').addEventListener('click', () => {
  const text = prompt('Describe the custom lead (free text — becomes agent focus context):');
  if (text && text.trim()) { state.customLeads.push(text.trim()); renderCustomLeads(); }
});

// ---------------------------------------------------------------------------
// providers / model (step 4)
// ---------------------------------------------------------------------------

async function loadProviders() {
  state.providers = await api('/api/providers');
  const sel = $('#fieldProvider');
  sel.innerHTML = state.providers.map((p) => `<option value="${esc(p.key)}">${esc(p.label)} (${p.kind === 'cli' ? 'API or subscription' : 'API key only'})</option>`).join('');
  sel.addEventListener('change', onProviderChange);
  onProviderChange();
}
function onProviderChange() {
  const p = state.providers.find((x) => x.key === $('#fieldProvider').value) || state.providers[0];
  const modelSel = $('#fieldModelSelect');
  modelSel.innerHTML = (p?.models || []).map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
  const subBtn = $('#authModeToggle button[data-mode="subscription"]');
  const supportsSub = p?.kind === 'cli';
  subBtn.disabled = !supportsSub;
  subBtn.title = supportsSub ? '' : `${p?.label} has no local CLI subscription mode — API key only.`;
  if (!supportsSub) setAuthMode('api');
  updateAuthModeHelp();
}
function setAuthMode(mode) {
  $$('#authModeToggle button').forEach((b) => b.classList.toggle('selected', b.dataset.mode === mode));
  state.authMode = mode;
  updateAuthModeHelp();
}
function updateAuthModeHelp() {
  const p = state.providers.find((x) => x.key === $('#fieldProvider').value);
  $('#authModeHelp').textContent = state.authMode === 'subscription'
    ? `Uses the locally logged-in ${p?.label || ''} CLI on this machine — no API key needed.`
    : `Uses the API key set for ${p?.label || 'this provider'} in Auth & Keys.`;
}
$$('#authModeToggle button').forEach((b) => b.addEventListener('click', () => { if (!b.disabled) setAuthMode(b.dataset.mode); }));
state.authMode = 'api';

// ---------------------------------------------------------------------------
// review (step 5)
// ---------------------------------------------------------------------------

function renderReview() {
  const target = $('#fieldTarget').value.trim();
  const repo = $('#fieldRepo').value.trim();
  const provider = $('#fieldProvider').value;
  const model = $('#fieldModelSelect').value;
  const items = [
    { k: 'Engagement name', v: $('#fieldName').value.trim() || '(not set)' },
    { k: 'Mode', v: state.mode },
    { k: MODE_LABELS[state.mode].target, v: target || '(not set)', mono: true },
    ...(MODE_LABELS[state.mode].showRepo ? [{ k: 'Source repo', v: repo || '(not set)', mono: true }] : []),
    { k: 'Model', v: `${provider}:${model}` },
    { k: 'Auth mode', v: state.authMode === 'subscription' ? 'Subscription (local CLI)' : 'API key' },
    { k: 'Leads selected', v: `${state.selected.size} of ${allAgents().length}${state.selected.size === 0 ? ' — auto (recon-driven)' : ''}` },
    { k: 'Custom leads', v: String(state.customLeads.length) },
    { k: 'Votes / chain / recon', v: `${$('#fieldVotes').value} / ${$('#fieldChain').value} / ${$('#fieldRecon').value}` },
    { k: 'Target auth', v: state.auth.header ? 'header set' : (state.auth.roles.length ? `${state.auth.roles.length} role(s)` : 'none') },
  ];
  $('#reviewGrid').innerHTML = items.map((it) => `
    <div class="review-item"><div class="k">${esc(it.k)}</div><div class="v${it.mono ? ' mono' : ''}">${esc(it.v)}</div></div>
  `).join('');
}

// ---------------------------------------------------------------------------
// launch
// ---------------------------------------------------------------------------

$('#btnLaunch').addEventListener('click', startExploitation);

async function startExploitation() {
  if (!validateStep(0)) { goToStep(0); return; }
  const mode = state.mode;
  const name = $('#fieldName').value.trim();
  const target = $('#fieldTarget').value.trim();
  const repo = $('#fieldRepo').value.trim();
  const provider = $('#fieldProvider').value;
  const model = $('#fieldModelSelect').value;
  const focusParts = [$('#fieldFocus').value.trim(), ...state.customLeads].filter(Boolean);

  const body = {
    mode,
    name,
    target: mode === 'whitebox' ? undefined : target,
    repo: mode === 'whitebox' ? target : (repo || undefined),
    models: provider && model ? [`${provider}:${model}`] : [],
    votes: Number($('#fieldVotes').value) || 3,
    chainDepth: Number($('#fieldChain').value),
    recon: Number($('#fieldRecon').value),
    subscription: state.authMode === 'subscription',
    mcp: $('#fieldMcp').checked,
    agents: [...state.selected],
    focus: focusParts.join('; ') || undefined,
    objective: $('#fieldObjective').value.trim() || undefined,
    outOfScope: $('#fieldOutOfScope').value.trim() || undefined,
    auth: state.auth.header || undefined,
    roles: state.auth.roles.length ? state.auth.roles : undefined,
    creds: state.credsPath || undefined,
  };

  $('#btnLaunch').disabled = true;
  $('#btnLaunch').textContent = 'Starting…';
  try {
    const { id } = await api('/api/exploit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    attachLiveJob(id, body.target || body.repo, name);
  } catch (e) {
    alert('Failed to start: ' + e.message);
  } finally {
    $('#btnLaunch').disabled = false;
    $('#btnLaunch').textContent = 'Start Exploitation →';
  }
}

// ---------------------------------------------------------------------------
// live run view
// ---------------------------------------------------------------------------

function bindRunTabs(scopeEl) {
  $$('.run-tab', scopeEl).forEach((tab) => tab.addEventListener('click', () => {
    $$('.run-tab', scopeEl).forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    $$('.run-tab-panel', scopeEl).forEach((p) => show(p, p.dataset.tabpanel === tab.dataset.tab));
  }));
}
bindRunTabs($('#liveView'));
bindRunTabs($('#detailView'));

function attachLiveJob(id, target, name) {
  if (state.currentJob?.es) state.currentJob.es.close();
  state.currentJob = { id, es: null, findings: [], target, name, phase: 'starting', agents: 0, agentsDone: 0, reportUrl: null, runId: null };

  show($('#wizardView'), false);
  show($('#detailView'), false);
  show($('#liveView'), true);
  $('#liveTarget').textContent = name || target || '—';
  $('#liveTargetSub').textContent = name ? target : '';
  $('#livePhase').textContent = 'starting';
  $('#phaseDot').style.background = '';
  $('#liveFindingsTable tbody').innerHTML = '';
  $('#liveAttackPath').innerHTML = '';
  $('#logList').innerHTML = '';
  $('#liveFindingsCount').textContent = '0';
  show($('#liveFindingsEmpty'), true);
  $('#progressFill').style.width = '0%';
  $('#progressLabel').textContent = '0 / 0 agents';
  show($('#btnOpenReport'), false);

  const es = new EventSource(`/api/exploit/${id}/events`);
  state.currentJob.es = es;
  es.addEventListener('log', (e) => appendLog(JSON.parse(e.data).line));
  es.addEventListener('finding', (e) => addFinding(JSON.parse(e.data).finding));
  es.addEventListener('snapshot', (e) => applySnapshot(JSON.parse(e.data)));
  es.addEventListener('done', (e) => { applySnapshot(JSON.parse(e.data)); es.close(); refreshRuns(); });
  es.onerror = () => { /* EventSource auto-retries; the server replays its buffer on reconnect */ };
}

function appendLog(line) {
  const div = document.createElement('div');
  div.className = 'log-line';
  div.textContent = line;
  const list = $('#logList');
  list.appendChild(div);
  list.scrollTop = list.scrollHeight;
}

function findingRow(f) {
  return `<tr>
    <td><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></td>
    <td>${esc(f.title)}</td>
    <td class="col-endpoint" title="${esc(f.endpoint)}">${esc(f.endpoint)}</td>
    <td>${esc(f.cwe)}</td>
    <td>${esc(f.agent)}</td>
    <td class="col-conf">${f.confidence ? f.confidence.toFixed(2) : '—'}</td>
  </tr>`;
}

function addFinding(f) {
  state.currentJob.findings.push(f);
  $('#liveFindingsTable tbody').insertAdjacentHTML('beforeend', findingRow(f));
  $('#liveFindingsCount').textContent = state.currentJob.findings.length;
  show($('#liveFindingsEmpty'), false);
  renderAttackPath($('#liveAttackPath'), state.currentJob.findings);
}

function applySnapshot(snap) {
  $('#livePhase').textContent = snap.phase;
  state.currentJob.runId = snap.runId;
  $('#progressLabel').textContent = `${snap.agentsDone} / ${snap.agents || '?'} agents`;
  if (snap.agents) $('#progressFill').style.width = `${Math.min(100, (snap.agentsDone / snap.agents) * 100)}%`;
  if (snap.reportUrl && snap.runId) {
    $('#btnOpenReport').href = `/api/runs/${snap.runId}/asset/report.html`;
    show($('#btnOpenReport'), true);
  }
  if (snap.done) $('#phaseDot').classList.add('static');
}

$('#btnStopRun').addEventListener('click', async () => {
  if (!state.currentJob) return;
  await api(`/api/exploit/${state.currentJob.id}/stop`, { method: 'POST' });
});
$('#btnBackToBoard').addEventListener('click', () => { show($('#liveView'), false); show($('#wizardView'), true); });
$('#btnDetailBack').addEventListener('click', () => { clearInterval(state.detailPoll); show($('#detailView'), false); show($('#wizardView'), true); });
$('#btnNewEngagement').addEventListener('click', () => { clearInterval(state.detailPoll); show($('#detailView'), false); show($('#liveView'), false); show($('#wizardView'), true); });

// ---------------------------------------------------------------------------
// Generative Attack Path Chaining
// ---------------------------------------------------------------------------

const KILL_CHAIN_STAGES = ['recon', 'initial-access', 'execution', 'privesc', 'lateral', 'exfil', 'impact'];

function renderAttackPath(container, findings) {
  if (!findings.length) {
    container.innerHTML = '<div class="attackpath-empty">The attack path builds automatically as findings chain together — nothing confirmed yet.</div>';
    return;
  }
  const byId = new Map(findings.map((f) => [f.id, f]));
  const hasStages = findings.some((f) => f.stage);
  let groups;
  if (hasStages) {
    groups = KILL_CHAIN_STAGES
      .map((stage) => ({ label: stage.replace('-', ' '), items: findings.filter((f) => (f.stage || '') === stage) }))
      .filter((g) => g.items.length);
    const other = findings.filter((f) => !f.stage);
    if (other.length) groups.push({ label: 'unstaged', items: other });
  } else {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    groups = order
      .map((sev) => ({ label: sev, items: findings.filter((f) => (f.severity || '').toLowerCase().includes(sev)) }))
      .filter((g) => g.items.length);
  }
  container.innerHTML = `
    ${!hasStages ? '<div class="field-help" style="margin-bottom:8px;">No kill-chain stage data yet — grouped by severity.</div>' : ''}
    <div class="attackpath">
      ${groups.map((g, i) => `
        ${i > 0 ? '<div class="ap-arrow">→</div>' : ''}
        <div class="ap-stage">
          <div class="ap-stage-head">${esc(g.label)} (${g.items.length})</div>
          ${g.items.map((f) => `
            <div class="ap-node ${sevClass(f.severity)}">
              <div class="t">${esc(f.title)}</div>
              <div class="m">${esc(f.mitre || f.owasp || f.cwe || '')}</div>
              ${(f.chains_from || []).length ? `<div class="chain-from">⤷ chains from ${(f.chains_from).map((cid) => esc(byId.get(cid)?.title || cid)).join(', ')}</div>` : ''}
            </div>
          `).join('')}
        </div>
      `).join('')}
    </div>
  `;
}

// ---------------------------------------------------------------------------
// sidebar — runs history
// ---------------------------------------------------------------------------

async function refreshRuns() {
  try { state.runs = await api('/api/runs'); } catch { state.runs = []; }
  renderSidebar();
}

const PHASE_ORDER = { starting: 0, recon: 0, planning: 1, exploiting: 2, validating: 2, chaining: 2, complete: 3 };
function stepClassFor(phase, step) {
  const order = ['recon', 'planning', 'exploiting', 'remediation'];
  if (step === 'remediation') return 'pending'; // not automated yet
  const idx = PHASE_ORDER[phase] ?? 0;
  const stepIdx = order.indexOf(step);
  if (stepIdx < idx) return 'done';
  if (stepIdx === idx) return 'active';
  return 'pending';
}

function renderSidebar() {
  const root = $('#sbGroups');
  root.innerHTML = '';
  const running = state.runs.filter((r) => r.state === 'running');
  const completed = state.runs.filter((r) => r.state !== 'running');
  const groups = [{ label: 'Running', items: running }, { label: 'Completed', items: completed }];

  for (const g of groups) {
    const wrap = document.createElement('div');
    wrap.className = 'sb-group';
    wrap.innerHTML = `<div class="sb-group-head"><span class="caret">▾</span><span>${g.label}</span><span class="count">${g.items.length}</span></div><div class="sb-items"></div>`;
    wrap.querySelector('.sb-group-head').addEventListener('click', () => wrap.classList.toggle('collapsed'));
    const items = wrap.querySelector('.sb-items');
    for (const r of g.items) {
      const btn = document.createElement('button');
      btn.className = 'sb-run' + (state.currentDetailId === r.id ? ' active' : '');
      btn.innerHTML = `<span class="name">${esc(r.name || r.target)}</span><span class="sub">${r.name ? esc(r.target) + ' · ' : ''}${r.findings} finding(s)</span>`;
      btn.addEventListener('click', () => openRun(r));
      items.appendChild(btn);
      const isThisJob = r.state === 'running' && state.currentJob && r.id === state.currentJob.runId;
      if (isThisJob) {
        const steps = document.createElement('div');
        steps.className = 'sb-steps';
        steps.innerHTML = ['recon', 'planning', 'exploiting', 'remediation'].map((s) =>
          `<div class="sb-step ${stepClassFor($('#livePhase').textContent, s)}">${s[0].toUpperCase() + s.slice(1)}</div>`).join('');
        items.appendChild(steps);
      }
    }
    root.appendChild(wrap);
  }
}

function openRun(run) {
  state.currentDetailId = run.id;
  if (run.state === 'running' && state.currentJob && run.id === state.currentJob.runId) {
    show($('#wizardView'), false); show($('#detailView'), false); show($('#liveView'), true);
    renderSidebar();
    return;
  }
  show($('#wizardView'), false); show($('#liveView'), false); show($('#detailView'), true);
  loadDetail(run.id);
  renderSidebar();
}

async function loadDetail(id) {
  clearInterval(state.detailPoll);
  const detail = await api(`/api/runs/${encodeURIComponent(id)}`);
  const target = detail.status?.target || detail.meta?.target || id;
  $('#detailTarget').textContent = detail.name || target;
  $('#detailTargetSub').textContent = detail.name ? target : '';
  $('#detailState').textContent = detail.status?.state || 'unknown';
  $('#detailFindingsCount').textContent = detail.findings.length;
  const tbody = $('#detailFindingsTable tbody');
  tbody.innerHTML = detail.findings.map(findingRow).join('');
  show($('#detailFindingsEmpty'), detail.findings.length === 0);
  renderAttackPath($('#detailAttackPath'), detail.findings);
  const reportLink = $('#detailOpenReport');
  if (detail.assets.includes('report.html')) {
    reportLink.href = `/api/runs/${encodeURIComponent(id)}/asset/report.html`;
    show(reportLink, true);
  } else show(reportLink, false);
  if (detail.status?.state === 'running') state.detailPoll = setInterval(() => loadDetail(id), 4000);
}

// ---------------------------------------------------------------------------
// Auth & Keys modal
// ---------------------------------------------------------------------------

function openAuthModal() {
  show($('#authModal'), true);
  renderRoleList();
  $('#credsPath').value = state.credsPath;
  refreshKeyStatus();
}
['#btnOpenAuth', '#btnOpenAuth2', '#btnOpenAuth3'].forEach((sel) => $(sel)?.addEventListener('click', openAuthModal));
$('#btnCloseAuth').addEventListener('click', () => show($('#authModal'), false));
$('#authModal').addEventListener('click', (e) => { if (e.target.id === 'authModal') show($('#authModal'), false); });

$$('.modal-tab').forEach((tab) => tab.addEventListener('click', () => {
  $$('.modal-tab').forEach((t) => t.classList.remove('active'));
  tab.classList.add('active');
  $$('.modal-panel').forEach((p) => show(p, p.dataset.mpanel === tab.dataset.mtab));
}));

$('#authHeader').addEventListener('input', (e) => { state.auth.header = e.target.value.trim(); });
$('#authHeader').value = state.auth.header;
$('#credsPath').addEventListener('input', (e) => { state.credsPath = e.target.value.trim(); });

function renderRoleList() {
  const root = $('#roleList');
  root.innerHTML = state.auth.roles.map((r, i) => `
    <div class="role-row">
      <input class="role-name" data-i="${i}" data-f="name" placeholder="role name" value="${esc(r.name)}" />
      <input data-i="${i}" data-f="header" placeholder="Authorization: Bearer ..." value="${esc(r.header)}" />
      <button class="icon-btn" data-i="${i}" data-remove>✕</button>
    </div>
  `).join('');
  $$('input[data-f]', root).forEach((inp) => inp.addEventListener('input', (e) => {
    state.auth.roles[Number(e.target.dataset.i)][e.target.dataset.f] = e.target.value;
  }));
  $$('[data-remove]', root).forEach((btn) => btn.addEventListener('click', () => {
    state.auth.roles.splice(Number(btn.dataset.i), 1);
    renderRoleList();
  }));
}
$('#btnAddRole').addEventListener('click', () => { state.auth.roles.push({ name: '', header: '' }); renderRoleList(); });

async function refreshKeyStatus() {
  try { state.keys = await api('/api/keys'); } catch { state.keys = []; }
  const root = $('#providerKeyList');
  root.innerHTML = state.providers.map((p) => {
    const set = state.keys.find((k) => k.provider === p.key)?.set;
    return `
      <div class="provider-row">
        <span class="dot ${set ? 'set' : ''}"></span>
        <span class="p-name">${esc(p.label)}</span>
        <span class="p-kind">${p.kind === 'cli' ? 'cli+api' : 'api only'}</span>
        <input type="password" data-provider="${esc(p.key)}" placeholder="${set ? '•••••••• (set — enter to replace)' : 'paste API key'}" />
        <button class="btn btn-sm" data-save="${esc(p.key)}">Save</button>
      </div>
    `;
  }).join('');
  $$('[data-save]', root).forEach((btn) => btn.addEventListener('click', async () => {
    const provider = btn.dataset.save;
    const input = root.querySelector(`input[data-provider="${provider}"]`);
    const key = input.value.trim();
    if (!key) return;
    await api('/api/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider, key }) });
    input.value = '';
    refreshKeyStatus();
  }));
}

// ---------------------------------------------------------------------------
// REPL drawer — real CLI harness session
// ---------------------------------------------------------------------------

function openReplDrawer() { show($('#replDrawer'), true); if (!state.replId) startRepl(); }

async function startRepl() {
  $('#replOutput').textContent = '';
  const { id } = await api('/api/repl', { method: 'POST' });
  state.replId = id;
  const es = new EventSource(`/api/repl/${id}/events`);
  state.replEs = es;
  es.addEventListener('data', (e) => {
    const { chunk } = JSON.parse(e.data);
    const out = $('#replOutput');
    out.appendChild(document.createTextNode(chunk));
    out.scrollTop = out.scrollHeight;
  });
  es.addEventListener('close', () => es.close());
}

$('#fabRepl').addEventListener('click', openReplDrawer);
$('#btnOpenRepl').addEventListener('click', openReplDrawer);
$('#btnReplClose').addEventListener('click', () => show($('#replDrawer'), false));
$('#btnReplRestart').addEventListener('click', async () => {
  if (state.replId) await api(`/api/repl/${state.replId}/stop`, { method: 'POST' }).catch(() => {});
  state.replEs?.close();
  state.replId = null;
  startRepl();
});
$('#replInput').addEventListener('keydown', async (e) => {
  if (e.key !== 'Enter') return;
  const line = e.target.value;
  e.target.value = '';
  const out = $('#replOutput');
  const echo = document.createElement('span');
  echo.className = 'repl-echo';
  echo.textContent = `❭ ${line}\n`;
  out.appendChild(echo);
  out.scrollTop = out.scrollHeight;
  if (!state.replId) await startRepl();
  await api(`/api/repl/${state.replId}/input`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ line }) });
});

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

async function boot() {
  applyTheme();
  selectMode('run');
  goToStep(0);
  renderCustomLeads();
  const meta = await api('/api/meta').catch(() => ({}));
  $('#sbVersion').textContent = `v${meta.version || '4.0.0'}`;
  await Promise.all([loadAgents(), loadProviders()]);
  await refreshRuns();
  setInterval(refreshRuns, 6000);
}
boot();
