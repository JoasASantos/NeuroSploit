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
  expandedCats: new Set(),
  providers: [],
  auth: { header: '', roles: [] },
  credsPath: '',
  keys: [],
  runs: [],
  currentJob: null,
  currentDetailId: null,
  detailPoll: null,
  // Findings tables (live + past run) share one sort/filter model so the two
  // views can't drift into behaving differently.
  tables: {
    live: { sort: 'severity', dir: 1, query: '', sev: null },
    detail: { sort: 'severity', dir: 1, query: '', sev: null },
  },
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

// Failures used to surface through `alert()`, which blocks the page and hides
// the very screen the operator needs to fix. Toasts stay out of the way and
// let several messages stack during a run.
function toast(msg, kind = 'info', ms = 5000) {
  const root = $('#toasts');
  if (!root) return;
  const el = document.createElement('div');
  el.className = `toast toast-${kind}`;
  el.textContent = msg;
  el.addEventListener('click', () => el.remove());
  root.appendChild(el);
  if (ms) setTimeout(() => el.remove(), ms);
  return el;
}

function fieldError(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg || '';
  show(el, !!msg);
}
function clearFieldErrors() { $$('.field-error').forEach((el) => { el.textContent = ''; el.hidden = true; }); }

function timeAgo(ts) {
  if (!ts) return '';
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// theme
// ---------------------------------------------------------------------------

function applyTheme() {
  document.documentElement.setAttribute('data-theme', state.theme);
  $('#btnThemeToggle').textContent = state.theme === 'dark' ? '☀' : '☾';
  $('#btnThemeToggle').title = state.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
  // xterm paints into a canvas and doesn't inherit CSS variables — it has to
  // be told the palette changed.
  if (term.xterm) term.xterm.options.theme = termColors();
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

// Errors land next to the field they belong to. A modal alert forced the
// operator to dismiss the message before they could see (or fix) the input it
// was about — and lost it entirely once dismissed.
function validateStep(n) {
  if (n !== 0) return true;
  clearFieldErrors();
  let firstBad = null;
  if (!$('#fieldName').value.trim()) {
    fieldError('#errName', 'Name the engagement — this is how it is labelled in the sidebar and run history.');
    firstBad = firstBad || '#fieldName';
  }
  if (!$('#fieldTarget').value.trim()) {
    fieldError('#errTarget', `${MODE_LABELS[state.mode].target} is required.`);
    firstBad = firstBad || '#fieldTarget';
  }
  if (state.mode === 'greybox' && !$('#fieldRepo').value.trim()) {
    fieldError('#errRepo', 'Grey-box tests the running app against its source — the repo is required.');
    firstBad = firstBad || '#fieldRepo';
  }
  if (firstBad) { $(firstBad).focus(); return false; }
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
$('#fieldName').addEventListener('input', () => { updateWizardSummary(); fieldError('#errName', ''); });
$('#fieldTarget').addEventListener('input', () => fieldError('#errTarget', ''));
$('#fieldRepo').addEventListener('input', () => fieldError('#errRepo', ''));

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
    // 412 leads across ~30 categories: expanded by default that is a wall of
    // switches you have to scroll past to reach anything. Collapsed keeps the
    // whole taxonomy on one screen; a search auto-expands what it matches.
    const open = state.expandedCats.has(group.category);
    card.className = 'cat-card' + (open ? '' : ' collapsed');
    card.dataset.category = group.category;
    card.innerHTML = `
      <div class="cat-head">
        <label class="switch">
          <input type="checkbox" class="cat-toggle" ${selCount === group.agents.length ? 'checked' : ''} />
          <span class="track"></span><span class="thumb"></span>
        </label>
        <span class="cat-name">${esc(group.category)}</span>
        <span class="cat-match" hidden></span>
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
      const nowCollapsed = card.classList.toggle('collapsed');
      if (nowCollapsed) state.expandedCats.delete(group.category);
      else state.expandedCats.add(group.category);
    });
    const catToggle = card.querySelector('.cat-toggle');
    // A partial selection (some but not all agents on) must look "partial",
    // not "off" — an unchecked master switch reads as "category disabled"
    // even when most of its agents are still on. Indeterminate = the middle
    // state; clicking it from there selects everything (browser default).
    catToggle.indeterminate = selCount > 0 && selCount < group.agents.length;
    catToggle.addEventListener('change', (e) => {
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
  const narrowing = !!q || state.filter !== 'all';
  $$('.agent-row').forEach((row) => {
    const isSel = state.selected.has(row.dataset.id);
    let visible = true;
    if (state.filter === 'selected') visible = isSel;
    if (state.filter === 'excluded') visible = !isSel;
    if (visible && q) visible = row.dataset.title.includes(q);
    row.classList.toggle('hidden-by-search', !visible);
  });
  let anyCardVisible = false;
  $$('.cat-card').forEach((card) => {
    const shown = $$('.agent-row', card).filter((r) => !r.classList.contains('hidden-by-search'));
    card.style.display = shown.length ? '' : 'none';
    if (shown.length) anyCardVisible = true;
    // A search that matches leads inside a collapsed category has to open it —
    // otherwise the hit count changes and nothing visibly happens.
    if (narrowing && shown.length) card.classList.remove('collapsed');
    else if (!narrowing && !state.expandedCats.has(card.dataset.category)) card.classList.add('collapsed');
    const count = card.querySelector('.cat-match');
    if (count) {
      count.textContent = narrowing ? `${shown.length} match${shown.length === 1 ? '' : 'es'}` : '';
      count.hidden = !narrowing;
    }
  });
  show($('#leadsEmpty'), !anyCardVisible);
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
    <div class="custom-lead-chip"><span>${esc(text)}</span><span class="x" data-i="${i}" title="Remove">✕</span></div>
  `).join('');
  // An empty list still occupied a gap the size of a card; hide it outright.
  show(root, state.customLeads.length > 0);
  $$('.custom-lead-chip .x', root).forEach((x) => x.addEventListener('click', () => {
    state.customLeads.splice(Number(x.dataset.i), 1);
    renderCustomLeads();
  }));
}

// `prompt()` gave a one-line box with no room to describe a lead, no way to
// see the wizard behind it, and no place to report a generation failure.
function openLeadModal() {
  $('#leadDesc').value = '';
  fieldError('#errLead', '');
  show($('#leadModal'), true);
  $('#leadDesc').focus();
}
function closeLeadModal() { show($('#leadModal'), false); }
$('#btnCustomLead').addEventListener('click', openLeadModal);
$('#btnCloseLead').addEventListener('click', closeLeadModal);
$('#btnLeadCancel').addEventListener('click', closeLeadModal);
$('#leadModal').addEventListener('click', (e) => { if (e.target.id === 'leadModal') closeLeadModal(); });
$('#leadDesc').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) $('#btnLeadGenerate').click();
});
$('#btnLeadGenerate').addEventListener('click', async () => {
  const text = $('#leadDesc').value.trim();
  if (!text) { fieldError('#errLead', 'Describe what the lead should test.'); return; }
  const btn = $('#btnLeadGenerate');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Generating…';
  try {
    const { agent } = await api('/api/leads/generate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ description: text }),
    });
    await loadAgents(); // re-read agents_md/ so the new file appears in its category
    state.selected.add(agent.id);
    renderBoard();
    closeLeadModal();
    toast(`Generated and pinned: ${agent.title}`, 'ok');
  } catch (e) {
    // Fall back to the old behavior — fold the raw text into --focus context
    // — so a missing/logged-out Claude CLI doesn't lose the operator's intent.
    state.customLeads.push(text);
    renderCustomLeads();
    closeLeadModal();
    toast(`Couldn't generate a skill (${e.message}) — kept as a focus hint instead.`, 'warn', 8000);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
});
$('#btnExpandAll').addEventListener('click', () => {
  const anyCollapsed = $$('.cat-card').some((c) => c.classList.contains('collapsed'));
  state.expandedCats = anyCollapsed ? new Set(state.categories.map((g) => g.category)) : new Set();
  $$('.cat-card').forEach((c) => c.classList.toggle('collapsed', !anyCollapsed));
  $('#btnExpandAll').textContent = anyCollapsed ? 'Collapse all' : 'Expand all';
});
$('#btnSelectAll').addEventListener('click', () => {
  // Respects the current search/filter — selects only what's visible, so a
  // filtered view ("sql") + Select all pins just those leads, not all 412.
  const visible = state.search.trim() ? allAgents().filter((a) => (a.title + ' ' + a.name).toLowerCase().includes(state.search.trim().toLowerCase())) : allAgents();
  visible.forEach((a) => state.selected.add(a.id));
  renderBoard();
});
$('#btnClearAll').addEventListener('click', () => {
  const visible = state.search.trim() ? allAgents().filter((a) => (a.title + ' ' + a.name).toLowerCase().includes(state.search.trim().toLowerCase())) : allAgents();
  visible.forEach((a) => state.selected.delete(a.id));
  renderBoard();
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
    attachLiveJob(id, body.target || body.repo, name, body.agents);
  } catch (e) {
    toast(`Failed to start: ${e.message}`, 'error', 9000);
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

const ACTIVE_JOB_KEY = 'ns-active-job';

function attachLiveJob(id, target, name, pinnedAgents) {
  if (state.currentJob?.es) state.currentJob.es.close();
  clearInterval(state.currentJob?.pocPoll);
  state.currentJob = {
    id, es: null, findings: [], target, name, phase: 'starting', agents: 0, agentsDone: 0,
    reportUrl: null, runId: null, pinnedAgents: pinnedAgents || [], pocs: [], pocPoll: null,
  };
  localStorage.setItem(ACTIVE_JOB_KEY, id);

  show($('#wizardView'), false);
  show($('#detailView'), false);
  show($('#liveView'), true);
  $('#liveTarget').textContent = name || target || '—';
  $('#liveTargetSub').textContent = name ? target : '';
  $('#livePhase').textContent = 'starting';
  $('#phaseDot').style.background = '';
  $('#phaseDot').classList.remove('static');
  $('#liveAttackPath').innerHTML = '';
  $('#logList').innerHTML = '';
  state.tables.live.sev = null;
  state.tables.live.query = '';
  $('#liveFindingSearch').value = '';
  renderFindings('live');
  $('#progressBar').classList.add('indeterminate');
  $('#progressFill').style.width = '0%';
  $('#progressLabel').textContent = '0 / ? agents';
  updatePinnedLine();
  show($('#btnOpenReport'), false);
  show($('#sendPromptRow'), false);
  show($('#sendPromptHelp'), false);
  termSyncTargets();

  const es = new EventSource(`/api/exploit/${id}/events`);
  state.currentJob.es = es;
  es.addEventListener('log', (e) => appendLog(JSON.parse(e.data).line));
  es.addEventListener('finding', (e) => addFinding(JSON.parse(e.data).finding));
  es.addEventListener('snapshot', (e) => applySnapshot(JSON.parse(e.data)));
  es.addEventListener('done', (e) => {
    applySnapshot(JSON.parse(e.data));
    es.close();
    clearInterval(state.currentJob.pocPoll);
    refreshRuns();
  });
  es.onerror = () => { /* EventSource auto-retries; the server replays its buffer on reconnect */ };

  // PoC scripts land in runs/<id>/pocs/ during the run — poll for them once
  // the CLI's own run id is known (see applySnapshot), so the finding modal
  // can offer a generated PoC as soon as one exists, not just after the run
  // finishes.
  state.currentJob.pocPoll = setInterval(async () => {
    if (!state.currentJob?.runId) return;
    try {
      const detail = await api(`/api/runs/${state.currentJob.runId}`);
      state.currentJob.pocs = detail.pocs || [];
    } catch { /* run dir not written yet */ }
  }, 5000);
}

function updatePinnedLine() {
  const n = state.currentJob?.pinnedAgents?.length || 0;
  $('#livePinned').textContent = n
    ? `${n} pinned lead(s): ${state.currentJob.pinnedAgents.join(', ')}`
    : 'auto — recon-driven agent selection (no leads pinned)';
}

// Resume a live view across a page reload: the server-side job outlives the
// browser tab, so re-attaching just reconnects SSE — the server replays its
// full event buffer (log + findings) on connect.
async function tryResumeActiveJob() {
  const id = localStorage.getItem(ACTIVE_JOB_KEY);
  if (!id) return false;
  try {
    const snap = await api(`/api/exploit/${id}`);
    attachLiveJob(id, snap.target, snap.name, snap.pinnedAgents);
    return true;
  } catch {
    localStorage.removeItem(ACTIVE_JOB_KEY); // job no longer exists (server restarted, etc.)
    return false;
  }
}

function appendLog(line) {
  const div = document.createElement('div');
  div.className = 'log-line';
  div.textContent = line;
  const list = $('#logList');
  list.appendChild(div);
  list.scrollTop = list.scrollHeight;
  // When the terminal is attached to this engagement it is the same stream —
  // mirror it there so the operator types and reads in one place.
  if (term.mode === 'job' && term.xterm) termWrite(line + '\r\n');
}

// Only run/whitebox/greybox jobs are REPL-backed (interactive: true) — the
// session keeps reading stdin while the engagement streams, so this is a
// real command line into the SAME process, not a fire-and-forget note.
$('#sendPromptInput').addEventListener('keydown', async (e) => {
  if (e.key !== 'Enter' || !state.currentJob) return;
  const line = e.target.value;
  if (!line.trim()) return;
  e.target.value = '';
  const div = document.createElement('div');
  div.className = 'log-line log-echo';
  div.textContent = `❭ ${line}`;
  const list = $('#logList');
  list.appendChild(div);
  list.scrollTop = list.scrollHeight;
  try {
    await api(`/api/exploit/${state.currentJob.id}/input`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ line }),
    });
  } catch (err) {
    appendLog(`[web] couldn't send: ${err.message}`);
  }
});

function findingRow(f, idx) {
  return `<tr data-idx="${idx}">
    <td><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></td>
    <td>${esc(f.title)}</td>
    <td class="col-endpoint" title="${esc(f.endpoint)}">${esc(f.endpoint)}</td>
    <td class="col-cwe">${esc(f.cwe)}</td>
    <td class="col-agent">${esc(f.agent)}</td>
    <td class="col-conf">${f.confidence ? f.confidence.toFixed(2) : '—'}</td>
  </tr>`;
}

// ---------------------------------------------------------------------------
// findings table — sort / filter / severity summary
//
// The table used to render in whatever order the harness emitted findings,
// which puts a LOW above a CRITICAL and makes a 27-row result unreadable.
// Sorting defaults to severity so the worst finding is the first thing on
// screen, and the summary doubles as a one-click severity filter.
// ---------------------------------------------------------------------------

const TABLES = {
  live: { tbody: '#liveFindingsTable tbody', table: '#liveFindingsTable', empty: '#liveFindingsEmpty', count: '#liveFindingsCount', summary: '#liveSevSummary', search: '#liveFindingSearch' },
  detail: { tbody: '#detailFindingsTable tbody', table: '#detailFindingsTable', empty: '#detailFindingsEmpty', count: '#detailFindingsCount', summary: '#detailSevSummary', search: '#detailFindingSearch' },
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function tableFindings(which) {
  return which === 'live' ? (state.currentJob?.findings || []) : (state.detailFindings || []);
}

function renderFindings(which) {
  const cfg = TABLES[which];
  const t = state.tables[which];
  const all = tableFindings(which);
  const q = t.query.trim().toLowerCase();

  // Carry the original index: the row click handler looks the finding up by
  // position in the unsorted array.
  let rows = all.map((f, idx) => ({ f, idx }));
  if (t.sev) rows = rows.filter(({ f }) => SEV_ORDER[sevRank(f.severity)] === t.sev);
  if (q) rows = rows.filter(({ f }) => `${f.title} ${f.endpoint} ${f.cwe} ${f.agent} ${f.severity}`.toLowerCase().includes(q));

  const key = t.sort;
  rows.sort((a, b) => {
    let cmp;
    if (key === 'severity') cmp = sevRank(a.f.severity) - sevRank(b.f.severity) || (b.f.confidence || 0) - (a.f.confidence || 0);
    else if (key === 'confidence') cmp = (b.f.confidence || 0) - (a.f.confidence || 0);
    else cmp = String(a.f[key] || '').localeCompare(String(b.f[key] || ''));
    return cmp * t.dir;
  });

  $(cfg.tbody).innerHTML = rows.map(({ f, idx }) => findingRow(f, idx)).join('');
  $(cfg.count).textContent = all.length;
  show($(cfg.empty), rows.length === 0);
  $(cfg.empty).textContent = all.length && !rows.length
    ? 'No finding matches this filter.'
    : (which === 'live' ? 'No validated findings yet.' : 'No validated findings.');

  const counts = {};
  for (const f of all) { const s = SEV_ORDER[sevRank(f.severity)]; counts[s] = (counts[s] || 0) + 1; }
  $(cfg.summary).innerHTML = SEV_ORDER.filter((s) => counts[s]).map((s) => `
    <button class="sev-pill sev-${s}${t.sev === s ? ' picked' : ''}" data-sev="${s}" title="${t.sev === s ? 'Show all severities' : `Show only ${s}`}">${s} <b>${counts[s]}</b></button>
  `).join('') || '<span class="field-help">No findings yet.</span>';
  $$(`${cfg.summary} .sev-pill`).forEach((btn) => btn.addEventListener('click', () => {
    t.sev = t.sev === btn.dataset.sev ? null : btn.dataset.sev;
    renderFindings(which);
  }));

  $$(`${cfg.table} thead th`).forEach((th) => th.classList.toggle('sorted', th.dataset.sort === key));
  $$(`${cfg.table} thead th`).forEach((th) => th.dataset.dir = th.dataset.sort === key ? (t.dir > 0 ? 'asc' : 'desc') : '');
}

for (const [which, cfg] of Object.entries(TABLES)) {
  $(cfg.search).addEventListener('input', (e) => { state.tables[which].query = e.target.value; renderFindings(which); });
  $$(`${cfg.table} thead th[data-sort]`).forEach((th) => {
    th.addEventListener('click', () => {
      const t = state.tables[which];
      if (t.sort === th.dataset.sort) t.dir *= -1; else { t.sort = th.dataset.sort; t.dir = 1; }
      renderFindings(which);
    });
  });
}

// Click any finding row (live or past-run) to open the full detail modal —
// evidence/impact/remediation/chain plus any PoC script the run wrote.
function bindFindingTableClicks(tbodySel, getFindings, getRunId, getPocs) {
  $(tbodySel).addEventListener('click', (e) => {
    const tr = e.target.closest('tr');
    if (!tr) return;
    const f = getFindings()[Number(tr.dataset.idx)];
    if (f) openFindingModal(f, getPocs(), getRunId());
  });
}
bindFindingTableClicks('#liveFindingsTable tbody', () => state.currentJob?.findings || [], () => state.currentJob?.runId, () => state.currentJob?.pocs || []);
bindFindingTableClicks('#detailFindingsTable tbody', () => state.detailFindings || [], () => state.currentDetailId, () => state.detailPocs || []);

function addFinding(f) {
  state.currentJob.findings.push(f);
  renderFindings('live');
  renderAttackPath($('#liveAttackPath'), state.currentJob.findings, state.currentJob.target);
}

function applySnapshot(snap) {
  $('#livePhase').textContent = snap.phase;
  state.currentJob.runId = snap.runId;
  state.currentJob.interactive = !!snap.interactive;
  show($('#sendPromptRow'), snap.interactive && !snap.done);
  show($('#sendPromptHelp'), snap.interactive && !snap.done);
  if (snap.pinnedAgents?.length && !state.currentJob.pinnedAgents.length) {
    state.currentJob.pinnedAgents = snap.pinnedAgents;
    updatePinnedLine();
  }
  $('#progressLabel').textContent = `${snap.agentsDone} / ${snap.agents || '?'} agents`;
  $('#progressBar').classList.toggle('indeterminate', !snap.agents);
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
function leaveLiveJob() {
  localStorage.removeItem(ACTIVE_JOB_KEY);
  clearInterval(state.currentJob?.pocPoll);
  state.currentJob?.es?.close();
  state.currentJob = null;
  termSyncTargets();
}
$('#btnBackToBoard').addEventListener('click', () => { leaveLiveJob(); show($('#liveView'), false); show($('#wizardView'), true); });
$('#btnDetailBack').addEventListener('click', () => { clearInterval(state.detailPoll); show($('#detailView'), false); show($('#wizardView'), true); });
$('#btnNewEngagement').addEventListener('click', () => { leaveLiveJob(); clearInterval(state.detailPoll); show($('#detailView'), false); show($('#liveView'), false); show($('#wizardView'), true); });

// ---------------------------------------------------------------------------
// Generative Attack Path Chaining
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Finding detail modal — full evidence/impact/remediation + any PoC script
// ---------------------------------------------------------------------------

function openFindingModal(f, pocs, runId) {
  $('#fmSev').className = `sev ${sevClass(f.severity)}`;
  $('#fmSev').textContent = f.severity || 'info';
  $('#fmTitle').textContent = f.title || '(untitled finding)';

  const meta = [
    ['CWE', f.cwe], ['CVSS', f.cvss], ['OWASP', f.owasp], ['MITRE', f.mitre],
    ['Stage', f.stage], ['Exploitability', f.exploitability],
    ['Confidence', f.confidence ? f.confidence.toFixed(2) : ''], ['Votes', f.votes],
    ['Review status', f.review_status], ['Auth context', f.auth_context],
    ['Account', f.account], ['Agent', f.agent],
  ];
  $('#fmMeta').innerHTML = meta.map(([k, v]) =>
    `<div class="review-item"><div class="k">${esc(k)}</div><div class="v mono">${esc(v || '—')}</div></div>`).join('');

  // The report footer ("Identified and validated by NeuroSploit...") gets
  // baked into impact/business_impact by the reporter — strip it from every
  // field so it doesn't repeat per-section, and surface it once at the
  // bottom of the modal instead.
  const ATTRIBUTION_RE = /Identified and validated by NeuroSploit[\s\S]*?Red Team Leaders\.?/i;
  let attributed = false;
  const clean = (text) => {
    if (!text) return '';
    const stripped = text.replace(ATTRIBUTION_RE, () => { attributed = true; return ''; });
    return stripped.split(/\n\n+/).map((p) => p.trim()).filter(Boolean).join('\n\n');
  };
  // Technical evidence (endpoint/payload/curl) reads as code; prose
  // (description/impact/remediation) reads as a paragraph, not a code block.
  const codeBlock = (label, text) => text
    ? `<div class="field-group"><label class="field-label">${esc(label)}</label><pre class="poc-pre">${esc(text)}</pre></div>` : '';
  const proseBlock = (label, text) => text
    ? `<div class="field-group"><label class="field-label">${esc(label)}</label><div class="fm-prose">${esc(text)}</div></div>` : '';

  const impactText = clean(f.impact);
  const bizText = clean(f.business_impact);
  const impactCombined = bizText && bizText !== impactText
    ? [impactText, bizText].filter(Boolean).join('\n\n') : impactText;

  $('#fmSection-evidence').innerHTML =
    proseBlock('Description', clean(f.evidence)) +
    codeBlock('Technical evidence', [f.endpoint, f.payload].filter(Boolean).join('\n\n'));
  $('#fmSection-impact').innerHTML = proseBlock('Impact', impactCombined);
  $('#fmSection-remediation').innerHTML = proseBlock('Remediation', clean(f.remediation));
  $('#fmSection-chains').innerHTML =
    ((f.chains_from || []).length ? `<div class="field-help">Chains from: ${esc(f.chains_from.join(', '))}</div>` : '') +
    (attributed ? '<div class="field-help" style="margin-top:6px;">Identified and validated by NeuroSploit (multi-model adversarial validation) — full methodology in the generated report.</div>' : '');

  // Proof of concept — doctrine tells agents to cite the PoC's file name in
  // `evidence` (see pocs_line() in pipeline.rs), so match on that text first;
  // fall back to whatever the run wrote to pocs/ if nothing was cited.
  const citedIn = `${f.evidence || ''} ${f.payload || ''}`;
  const matches = (pocs || []).filter((p) => citedIn.includes(p));
  const list = matches.length ? matches : (pocs || []);
  const pocRoot = $('#fmPocList');
  if (!list.length) {
    pocRoot.textContent = 'No PoC script written for this finding yet — the exploiting agent only writes one when the finding warrants a runnable repro.';
  } else {
    pocRoot.innerHTML = list.map((name) => `
      <div class="poc-file">
        <span class="fn">pocs/${esc(name)}</span>
        <a class="btn btn-sm" href="/api/runs/${esc(runId)}/asset/pocs/${esc(name)}" target="_blank">Open raw</a>
      </div>
      <pre class="poc-pre" data-poc="${esc(name)}">loading…</pre>
    `).join('');
    for (const name of list) {
      fetch(`/api/runs/${runId}/asset/pocs/${name}`).then((r) => r.text()).then((txt) => {
        const pre = pocRoot.querySelector(`pre[data-poc="${CSS.escape(name)}"]`);
        if (pre) pre.textContent = txt.slice(0, 4000);
      }).catch(() => {});
    }
  }
  show($('#findingModal'), true);
}
$('#btnCloseFinding').addEventListener('click', () => show($('#findingModal'), false));
$('#findingModal').addEventListener('click', (e) => { if (e.target.id === 'findingModal') show($('#findingModal'), false); });

const KILL_CHAIN_STAGES = ['recon', 'initial-access', 'execution', 'privesc', 'lateral', 'exfil', 'impact'];

// Same severity tokens the rest of the console uses — the graph canvas
// follows the light/dark theme instead of a fixed dark palette.
function canvasColor(sev) { return `var(--sev-${['critical', 'high', 'medium', 'low', 'info'][sevRank(sev)]}-fg)`; }

function nodeIcon(f) {
  const t = `${f.title} ${f.evidence} ${f.cwe} ${f.stage}`.toLowerCase();
  if (/credential|password|secret|token|api[ _]?key|jwt/.test(t)) return '🔑';
  if (/admin|privile|domain admin|root/.test(t)) return '🛡';
  if (/account|user|identity/.test(t)) return '👤';
  if (/host|server|ip |port|service/.test(t)) return '🖥';
  if (/database|sql/.test(t)) return '🗄';
  if (t.includes('impact') || t.includes('exfil')) return '💥';
  return '⚠';
}

// Generative Attack Path Chaining — a real node graph (root = target, one
// node per confirmed finding, edges from chains_from when the harness set
// it, else fanned from root) instead of flat cards, so a single finding
// still reads as a graph and not an empty list.
function renderAttackPath(container, findings, target) {
  if (!findings.length) {
    container.innerHTML = '<div class="attackpath-empty">The attack path builds automatically as findings chain together — nothing confirmed yet.</div>';
    return;
  }
  const byId = new Map(findings.filter((f) => f.id).map((f) => [f.id, f]));
  const hasStages = findings.some((f) => f.stage);
  let groups;
  if (hasStages) {
    groups = KILL_CHAIN_STAGES
      .map((stage) => ({ label: stage.replace('-', ' '), items: findings.filter((f) => (f.stage || '') === stage) }))
      .filter((g) => g.items.length);
    const other = findings.filter((f) => !f.stage);
    if (other.length) groups.push({ label: 'unstaged', items: other });
  } else {
    groups = [{ label: 'confirmed findings', items: findings }];
  }

  // Layout: root at column 0; each kill-chain stage is its own column.
  const COL_W = 210, ROW_H = 78, NODE_W = 176, NODE_H = 54, PAD = 40;
  const rootX = PAD, rootY = PAD + (Math.max(...groups.map((g) => g.items.length)) * ROW_H) / 2;
  const nodes = [{ id: '__root', x: rootX, y: rootY, root: true, label: target || 'target' }];
  const nodeById = new Map(); // finding.id -> node (for chains_from edges)
  groups.forEach((g, ci) => {
    const colX = PAD + NODE_W / 2 + (ci + 1) * COL_W;
    const colH = g.items.length * ROW_H;
    const offsetY = rootY - colH / 2 + ROW_H / 2;
    g.items.forEach((f, ri) => {
      const node = { id: f.id || `${ci}-${ri}`, x: colX, y: offsetY + ri * ROW_H, finding: f, stageLabel: g.label };
      nodes.push(node);
      if (f.id) nodeById.set(f.id, node);
    });
  });

  const edges = [];
  for (const n of nodes) {
    if (n.root) continue;
    const parents = (n.finding.chains_from || []).map((cid) => nodeById.get(cid)).filter(Boolean);
    if (parents.length) parents.forEach((p) => edges.push([p, n]));
    else edges.push([nodes[0], n]);
  }

  const width = PAD * 2 + NODE_W + (groups.length) * COL_W;
  const height = Math.max(...nodes.map((n) => n.y)) + NODE_H + PAD;

  const edgePath = (a, b) => {
    const x1 = a.root ? a.x + 14 : a.x + NODE_W / 2, y1 = a.y;
    const x2 = b.x - NODE_W / 2, y2 = b.y;
    const midX = (x1 + x2) / 2;
    return `M ${x1},${y1} C ${midX},${y1} ${midX},${y2} ${x2},${y2}`;
  };

  const nodeSvg = (n) => {
    if (n.root) {
      return `<g>
        <circle cx="${n.x}" cy="${n.y}" r="15" style="fill:var(--accent);stroke:var(--accent-hover);" stroke-width="2"/>
        <text x="${n.x}" y="${n.y + 4}" text-anchor="middle" font-size="13" style="fill:var(--accent-contrast);">🎯</text>
        <text x="${n.x}" y="${n.y + 30}" text-anchor="middle" font-size="10.5" style="fill:var(--text-dim);" font-family="var(--mono)">${esc(trimMid(n.label, 26))}</text>
      </g>`;
    }
    const f = n.finding;
    const color = canvasColor(f.severity);
    const x = n.x - NODE_W / 2, y = n.y - NODE_H / 2;
    return `<g class="ap-node-g" data-idx="${esc(findings.indexOf(f))}" style="cursor:pointer;">
      <rect x="${x}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="8" style="fill:var(--surface);stroke:${color};" stroke-width="1.6"/>
      <text x="${x + 12}" y="${y + 20}" font-size="13">${nodeIcon(f)}</text>
      <text x="${x + 32}" y="${y + 19}" font-size="11.5" style="fill:var(--text);" font-weight="600">${esc(trimMid(f.title, 22))}</text>
      <text x="${x + 32}" y="${y + 36}" font-size="10" style="fill:var(--text-faint);" font-family="var(--mono)">${esc((f.mitre || f.owasp || f.cwe || n.stageLabel || '').slice(0, 26))}</text>
      <rect x="${x + NODE_W - 9}" y="${y + 6}" width="6" height="6" rx="1.5" style="fill:${color};"/>
    </g>`;
  };

  container.innerHTML = `
    ${!hasStages ? '<div class="field-help" style="margin-bottom:8px;">No kill-chain stage data yet — shown as a flat graph from the target.</div>' : ''}
    <div class="ap-canvas-wrap">
      <svg class="ap-canvas" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
        ${groups.map((g, ci) => `<line x1="${PAD + NODE_W / 2 + (ci + 1) * COL_W - COL_W / 2}" y1="0" x2="${PAD + NODE_W / 2 + (ci + 1) * COL_W - COL_W / 2}" y2="${height}" style="stroke:var(--border);" stroke-width="1"/>`).join('')}
        ${edges.map(([a, b]) => `<path d="${edgePath(a, b)}" fill="none" style="stroke:var(--border-strong);" stroke-width="1.5"/>`).join('')}
        ${nodes.map(nodeSvg).join('')}
      </svg>
    </div>
  `;
  container.querySelectorAll('.ap-node-g').forEach((g) => g.addEventListener('click', () => {
    const f = findings[Number(g.dataset.idx)];
    const isLive = container.id === 'liveAttackPath';
    const pocs = isLive ? (state.currentJob?.pocs || []) : (state.detailPocs || []);
    const runId = isLive ? state.currentJob?.runId : state.currentDetailId;
    if (f) openFindingModal(f, pocs, runId);
  }));
}

function trimMid(s, n) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
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
      // Every line here truncates: a long target URL used to run past the
      // sidebar's edge and collide with the main pane.
      const worst = SEV_ORDER.find((s) => Object.entries(r.severities || {}).some(([k, n]) => n && SEV_ORDER[sevRank(k)] === s));
      btn.innerHTML = `
        <span class="name">${worst ? `<span class="run-dot sev-dot-${worst}" title="worst severity: ${worst}"></span>` : ''}<span class="label">${esc(r.name || r.target)}</span></span>
        <span class="sub">${r.name ? esc(r.target) : esc(r.id)}</span>
        <span class="sub sub-facts"><span>${r.findings} finding${r.findings === 1 ? '' : 's'}</span><span>${esc(timeAgo(r.ts))}</span></span>`;
      btn.title = `${r.name ? r.name + '\n' : ''}${r.target}\n${r.id}${r.ts ? '\n' + new Date(r.ts * 1000).toLocaleString() : ''}`;
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
  if (state.detailLoadedId !== id) {
    // A filter left over from the previous run would silently hide findings
    // in the one just opened.
    state.tables.detail.sev = null;
    state.tables.detail.query = '';
    $('#detailFindingSearch').value = '';
    state.detailLoadedId = id;
  }
  const detail = await api(`/api/runs/${encodeURIComponent(id)}`);
  const target = detail.status?.target || detail.meta?.target || id;
  $('#detailTarget').textContent = detail.name || target;
  $('#detailTargetSub').textContent = detail.name ? target : '';
  $('#detailState').textContent = detail.status?.state || 'unknown';
  state.detailFindings = detail.findings;
  state.detailPocs = detail.pocs || [];
  renderFindings('detail');
  // A past run's identity: when it ran, how many agents, what asset the recon
  // decided it was. Previously the page showed only target + state, so two
  // runs of the same target were indistinguishable.
  const facts = [
    detail.status?.ts ? `${new Date(detail.status.ts * 1000).toLocaleString()} · ${timeAgo(detail.status.ts)}` : '',
    detail.status?.agents_ran ? `${detail.status.agents_ran} agents ran` : '',
    detail.meta?.asset || '',
    detail.pocs?.length ? `${detail.pocs.length} PoC script(s)` : '',
    id,
  ].filter(Boolean);
  $('#detailFacts').innerHTML = facts.map((f) => `<span>${esc(f)}</span>`).join('');
  renderAttackPath($('#detailAttackPath'), detail.findings, target);
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
// Terminal dock — the real CLI harness, rendered by xterm.js
//
// The old drawer was a <div> holding text: the harness's ANSI (colour, the
// box-drawn /status panel, its spinners) arrived stripped, long lines rewrapped
// mid-glyph, and it floated over the wizard's primary button. This is the same
// arrangement the Unistrike console uses — a terminal emulator fed the child
// process's raw stdout — docked so it takes vertical space instead of covering
// the page.
//
// One difference matters and shapes the code below: there is no PTY here (the
// server has no native deps), so the child sees a pipe and never echoes what
// is typed. The line editor — echo, cursor, history, Tab completion — is
// therefore local, and only completed lines cross the wire.
// ---------------------------------------------------------------------------

const SLASH_COMMANDS = [
  '/agents', '/attach', '/auth', '/burp', '/chain', '/clear', '/config', '/context', '/continue',
  '/creds', '/exclude', '/exit', '/expand', '/feed', '/finding', '/findings', '/focus', '/full',
  '/go', '/goal', '/help', '/history', '/idle', '/instructions', '/integrations', '/key', '/log',
  '/mcp', '/model', '/models', '/objective', '/offline', '/onboard', '/only', '/proxy', '/providers',
  '/quit', '/recon', '/repo', '/report', '/results', '/resume', '/retest', '/revalidate', '/run',
  '/runs', '/scope-out', '/show', '/status', '/stop', '/subscription', '/target', '/temp-email',
  '/theme', '/timeout', '/useragent', '/validate', '/votes',
];

const term = {
  xterm: null, fit: null, ro: null,
  mode: 'session',        // 'session' = standalone REPL · 'job' = the live engagement
  replId: null, es: null,
  line: '', cursor: 0,
  history: [], hIdx: null, stash: '',
  booted: false,
};

function termColors() {
  // Read the theme tokens rather than hardcoding: the console has a light mode,
  // and a terminal with its own fixed palette looks pasted in.
  const css = getComputedStyle(document.documentElement);
  const v = (n, fb) => (css.getPropertyValue(n) || '').trim() || fb;
  return {
    background: v('--term-bg', '#0f0e10'),
    foreground: v('--term-fg', '#d8d5cf'),
    cursor: v('--accent', '#e08a3e'),
    selectionBackground: v('--accent-soft', '#3a2a16'),
  };
}

function termStatus(stateName, text) {
  $('#termDot').dataset.state = stateName;
  $('#termStatus').textContent = text;
}
function termAlert(msg, kind = 'warn') {
  const el = $('#termAlert');
  el.textContent = msg || '';
  el.dataset.kind = kind;
  show(el, !!msg);
}

function termFit() {
  if (!term.fit || !term.xterm || $('#termDock').hidden) return;
  try { term.fit.fit(); } catch { /* container measured 0 — nothing to fit to */ }
}

function termEnsure() {
  if (term.xterm) return true;
  if (typeof Terminal === 'undefined') {
    termAlert("xterm.js didn't load — the terminal can't run. Check /vendor/xterm.js is being served.", 'error');
    termStatus('error', 'unavailable');
    return false;
  }
  term.xterm = new Terminal({
    fontFamily: getComputedStyle(document.documentElement).getPropertyValue('--mono').trim() || 'monospace',
    fontSize: 12,
    cursorBlink: true,
    convertEol: true,   // the harness writes bare \n; without this every line stair-steps
    scrollback: 8000,
    theme: termColors(),
  });
  if (window.FitAddon?.FitAddon) {
    term.fit = new window.FitAddon.FitAddon();
    term.xterm.loadAddon(term.fit);
  }
  term.xterm.open($('#termHost'));
  term.xterm.onData(termOnData);
  if (window.ResizeObserver) {
    // The dock is user-resizable and the sidebar collapses — both change the
    // terminal's box without firing a window resize.
    term.ro = new ResizeObserver(() => termFit());
    term.ro.observe($('#termHost'));
  }
  window.addEventListener('resize', termFit);
  return true;
}

function termWrite(s) { term.xterm?.write(s); }
function termNote(s) { termWrite(`\x1b[2m${s}\x1b[0m\r\n`); }

/* ---- local line editing ---- */

function termSetLine(s) {
  if (!term.xterm) return;
  if (term.cursor > 0) termWrite(`\x1b[${term.cursor}D`);
  termWrite('\x1b[K' + s);
  term.line = s;
  term.cursor = s.length;
}

function termInsert(s) {
  const rest = term.line.slice(term.cursor);
  term.line = term.line.slice(0, term.cursor) + s + rest;
  term.cursor += s.length;
  termWrite(s + rest);
  if (rest.length) termWrite(`\x1b[${rest.length}D`);
}

function termBackspace() {
  if (term.cursor === 0) return;
  term.line = term.line.slice(0, term.cursor - 1) + term.line.slice(term.cursor);
  term.cursor--;
  const rest = term.line.slice(term.cursor);
  termWrite('\b' + rest + ' ' + `\x1b[${rest.length + 1}D`);
}

function termComplete() {
  const word = term.line.slice(0, term.cursor);
  if (!word.startsWith('/') || word.includes(' ')) return;
  const hits = SLASH_COMMANDS.filter((c) => c.startsWith(word));
  if (!hits.length) return;
  if (hits.length === 1) { termInsert(hits[0].slice(word.length) + ' '); return; }
  // Complete as far as the candidates agree, then show what's left to choose.
  let common = hits[0];
  for (const h of hits) { while (!h.startsWith(common)) common = common.slice(0, -1); }
  const line = term.line;
  termWrite('\r\n' + hits.join('  ') + '\r\n');
  term.line = ''; term.cursor = 0;
  termInsert(common.length > word.length ? common + line.slice(word.length) : line);
}

async function termSubmit() {
  const line = term.line;
  termWrite('\r\n');
  term.line = ''; term.cursor = 0; term.hIdx = null;
  if (line.trim()) {
    term.history.push(line);
    if (term.history.length > 200) term.history.shift();
  }
  try {
    if (term.mode === 'job') {
      const job = state.currentJob;
      if (!job) { termNote('no live engagement attached — switch the target back to the standalone session.'); return; }
      await api(`/api/exploit/${job.id}/input`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ line }),
      });
    } else {
      if (!term.replId) await termConnect();
      await api(`/api/repl/${term.replId}/input`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data: line + '\n' }),
      });
    }
  } catch (e) {
    termWrite(`\x1b[31m[web] couldn't send: ${e.message}\x1b[0m\r\n`);
  }
}

async function termInterrupt() {
  termWrite('^C\r\n');
  term.line = ''; term.cursor = 0;
  try {
    if (term.mode === 'job' && state.currentJob) {
      // The engagement's own graceful stop — a raw SIGINT would kill the run
      // before it validates and reports what it already found.
      await api(`/api/exploit/${state.currentJob.id}/stop`, { method: 'POST' });
      termNote('sent /stop to the engagement (validate what is found so far, then report).');
    } else if (term.replId) {
      await api(`/api/repl/${term.replId}/input`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data: '\x03' }),
      });
    }
  } catch (e) { termNote(`interrupt failed: ${e.message}`); }
}

function termOnData(data) {
  // A paste arrives as one chunk and may carry newlines: split it so each line
  // is submitted, instead of shipping embedded \n the REPL would mis-read.
  if (data.length > 1 && !data.startsWith('\x1b') && /[\r\n]/.test(data)) {
    const parts = data.split(/\r?\n/);
    parts.forEach((part, i) => {
      if (part) termInsert(part);
      if (i < parts.length - 1) termSubmit();
    });
    return;
  }
  switch (data) {
    case '\r': case '\n': return void termSubmit();
    case '\x7f': case '\b': return termBackspace();
    case '\x03': return void termInterrupt();
    case '\x0c': return termClear();                       // Ctrl-L
    case '\x15': return termSetLine('');                   // Ctrl-U
    case '\x0b': {                                         // Ctrl-K — kill to end
      const keep = term.line.slice(0, term.cursor);
      const killed = term.line.length - keep.length;
      term.line = keep;
      if (killed) termWrite('\x1b[K');
      return;
    }
    case '\x01': case '\x1b[H':                            // Ctrl-A / Home
      if (term.cursor) { termWrite(`\x1b[${term.cursor}D`); term.cursor = 0; }
      return;
    case '\x05': case '\x1b[F': {                          // Ctrl-E / End
      const move = term.line.length - term.cursor;
      if (move) { termWrite(`\x1b[${move}C`); term.cursor = term.line.length; }
      return;
    }
    case '\t': return termComplete();
    case '\x1b[D': if (term.cursor > 0) { term.cursor--; termWrite('\x1b[D'); } return;
    case '\x1b[C': if (term.cursor < term.line.length) { term.cursor++; termWrite('\x1b[C'); } return;
    case '\x1b[A': {                                       // history back
      if (!term.history.length) return;
      if (term.hIdx === null) { term.stash = term.line; term.hIdx = term.history.length; }
      if (term.hIdx > 0) term.hIdx--;
      termSetLine(term.history[term.hIdx]);
      return;
    }
    case '\x1b[B': {                                       // history forward
      if (term.hIdx === null) return;
      term.hIdx++;
      if (term.hIdx >= term.history.length) { term.hIdx = null; termSetLine(term.stash); }
      else termSetLine(term.history[term.hIdx]);
      return;
    }
    case '\x1b[3~': {                                      // Delete
      if (term.cursor >= term.line.length) return;
      term.line = term.line.slice(0, term.cursor) + term.line.slice(term.cursor + 1);
      const rest = term.line.slice(term.cursor);
      termWrite(rest + ' ' + `\x1b[${rest.length + 1}D`);
      return;
    }
    default:
      if (data >= ' ' || data.length > 1) termInsert(data.replace(/[\x00-\x1f]/g, ''));
  }
}

function termClear() {
  term.xterm?.clear();
  // `clear` keeps the current row: redraw what was being typed so the cursor
  // and the buffer don't disagree.
  if (term.line) { const l = term.line, c = term.cursor; term.line = ''; term.cursor = 0; termInsert(l); term.cursor = c; }
}

/* ---- session wiring ---- */

async function termConnect() {
  termStatus('pending', 'starting…');
  termAlert('');
  try {
    const { id } = await api('/api/repl', { method: 'POST' });
    term.replId = id;
  } catch (e) {
    termStatus('error', 'failed');
    termAlert(`couldn't start the harness: ${e.message}`, 'error');
    return;
  }
  const es = new EventSource(`/api/repl/${term.replId}/events`);
  term.es = es;
  es.addEventListener('data', (e) => termWrite(JSON.parse(e.data).chunk));
  es.addEventListener('close', () => { es.close(); termStatus('off', 'session ended'); });
  es.onopen = () => termStatus('on', 'connected');
  es.onerror = () => { if (es.readyState === EventSource.CLOSED) termStatus('off', 'disconnected'); };
}

async function termRestart() {
  if (term.replId) await api(`/api/repl/${term.replId}/stop`, { method: 'POST' }).catch(() => {});
  term.es?.close();
  term.es = null; term.replId = null;
  term.xterm?.reset();
  term.line = ''; term.cursor = 0;
  await termConnect();
}

function termSetMode(mode) {
  term.mode = mode;
  if (mode === 'job') {
    const job = state.currentJob;
    termStatus(job && !job.done ? 'on' : 'off', job ? `engagement ${esc(job.name || job.target)}` : 'no live engagement');
    termNote(job
      ? `attached to the running engagement — what you type goes to the same harness process that is testing ${job.name || job.target}.`
      : 'no engagement is running; start one first.');
  } else {
    termStatus(term.replId ? 'on' : 'off', term.replId ? 'connected' : 'disconnected');
    if (!term.replId) termConnect();
  }
}

function termSyncTargets() {
  const sel = $('#termTarget');
  const job = state.currentJob;
  const want = ['session'].concat(job ? ['job'] : []);
  const have = $$('option', sel).map((o) => o.value);
  if (want.join() === have.join()) {
    if (job) sel.querySelector('option[value="job"]').textContent = `live: ${job.name || job.target}`;
    return;
  }
  sel.innerHTML = `<option value="session">standalone REPL session</option>` +
    (job ? `<option value="job">live: ${esc(job.name || job.target)}</option>` : '');
  sel.value = term.mode === 'job' && job ? 'job' : 'session';
  if (term.mode === 'job' && !job) termSetMode('session');
}

function termOpen(mode) {
  show($('#termDock'), true);
  if (!termEnsure()) return;
  termSyncTargets();
  // Only switch to a target the select actually offers — asking for 'job' with
  // no engagement running would leave the picker blank and the terminal
  // pointing at nothing.
  const wanted = mode && $(`#termTarget option[value="${mode}"]`) ? mode : null;
  if (wanted && wanted !== term.mode) { $('#termTarget').value = wanted; termSetMode(wanted); }
  else if (mode && !wanted) termNote('no engagement is running — this is the standalone REPL session.');
  if (!term.booted) {
    term.booted = true;
    termNote('NeuroSploit harness — type /help for commands, or describe what you want tested in plain language.');
    if (term.mode === 'session') termConnect();
  }
  termFit();
  term.xterm.focus();
}
function termClose() { show($('#termDock'), false); }
function termToggle() { $('#termDock').hidden ? termOpen() : termClose(); }

$('#btnOpenRepl').addEventListener('click', () => termOpen());
$('#btnOpenTerm2').addEventListener('click', () => termOpen());
$('#btnOpenTerm3').addEventListener('click', () => termOpen());
$('#btnSendPromptTerm').addEventListener('click', () => termOpen('job'));
$('#btnTermClose').addEventListener('click', termClose);
$('#btnTermClear').addEventListener('click', termClear);
$('#btnTermRestart').addEventListener('click', () => { if (term.mode === 'job') termNote('the engagement owns this session — restart applies to the standalone REPL.'); else termRestart(); });
$('#btnTermExpand').addEventListener('click', () => {
  const expanded = $('#termDock').classList.toggle('expanded');
  $('#btnTermExpand').textContent = expanded ? 'collapse' : 'expand';
  termFit();
});
$('#termTarget').addEventListener('change', (e) => termSetMode(e.target.value));

// Drag the dock's top edge. Height is remembered because the useful size
// depends on the screen, and re-dragging it every visit is the kind of small
// tax that makes a tool feel unfinished.
(function termResizer() {
  const dock = $('#termDock');
  const saved = Number(localStorage.getItem('ns-term-h'));
  if (saved) dock.style.height = `${saved}px`;
  let startY = 0, startH = 0, dragging = false;
  $('#termResize').addEventListener('pointerdown', (e) => {
    dragging = true; startY = e.clientY; startH = dock.getBoundingClientRect().height;
    $('#termResize').setPointerCapture(e.pointerId);
    document.body.classList.add('resizing-ns');
  });
  $('#termResize').addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const h = Math.max(140, Math.min(window.innerHeight - 120, startH + (startY - e.clientY)));
    dock.classList.remove('expanded');
    dock.style.height = `${h}px`;
    termFit();
  });
  const end = () => {
    if (!dragging) return;
    dragging = false;
    document.body.classList.remove('resizing-ns');
    localStorage.setItem('ns-term-h', String(Math.round(dock.getBoundingClientRect().height)));
  };
  $('#termResize').addEventListener('pointerup', end);
  $('#termResize').addEventListener('pointercancel', end);
})();

document.addEventListener('keydown', (e) => {
  if (e.key === '`' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); termToggle(); return; }
  if (e.key !== 'Escape') return;
  if (!$('#findingModal').hidden) return show($('#findingModal'), false);
  if (!$('#leadModal').hidden) return closeLeadModal();
  if (!$('#authModal').hidden) return show($('#authModal'), false);
  if (!$('#termDock').hidden) termClose();
});

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

// Below 768px the sidebar slides off-canvas. It previously had no way back:
// the CSS hid it and nothing could set .open.
$('#btnSidebarToggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
$('#sbGroups').addEventListener('click', () => {
  if (window.matchMedia('(max-width: 768px)').matches) $('#sidebar').classList.remove('open');
});

async function boot() {
  applyTheme();
  selectMode('run');
  goToStep(0);
  renderCustomLeads();
  renderFindings('live');
  renderFindings('detail');
  const meta = await api('/api/meta').catch(() => ({}));
  $('#sbVersion').textContent = `v${meta.version || '4.0.0'}`;
  await Promise.all([loadAgents(), loadProviders()]);
  await refreshRuns();
  await tryResumeActiveJob(); // survive an F5 while watching a live run
  setInterval(refreshRuns, 6000);
}
boot();
