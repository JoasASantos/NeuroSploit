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
  // The stepper scrolls horizontally on a phone; advancing to a step that is
  // off-screen would look like nothing happened.
  const active = $('.step-tab.active');
  if (active?.scrollIntoView) active.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' });
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
  show($('#dashView'), false);
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
$('#btnBackToBoard').addEventListener('click', () => { leaveLiveJob(); show($('#liveView'), false); show($('#dashView'), false); show($('#wizardView'), true); });
$('#btnDetailBack').addEventListener('click', () => { clearInterval(state.detailPoll); show($('#detailView'), false); show($('#dashView'), false); show($('#wizardView'), true); });
$('#btnNewEngagement').addEventListener('click', () => { leaveLiveJob(); clearInterval(state.detailPoll); show($('#detailView'), false); show($('#liveView'), false); show($('#dashView'), false); show($('#wizardView'), true); });

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

  // A reader works through a finding in a fixed order — where is it, what does
  // it mean, how do I fix it, how do I see it myself. The old layout led with
  // an evidence dump, which answers the last question first and the first three
  // not at all.
  $('#fmSection-evidence').innerHTML =
    proseBlock('Where the problem is', locationLine(f)) +
    proseBlock('What it means', impactCombined || clean(f.evidence)) +
    proseBlock('How to fix it', clean(f.remediation));
  $('#fmSection-impact').innerHTML = pocBlock(f, pocs, runId);
  $('#fmSection-remediation').innerHTML = codeBlock('Technical evidence', technicalEvidence(f));
  $('#fmSection-chains').innerHTML =
    ((f.chains_from || []).length ? `<div class="field-help">Chains from: ${esc(f.chains_from.join(', '))}</div>` : '') +
    (attributed ? '<div class="field-help" style="margin-top:6px;">Identified and validated by NeuroSploit (multi-model adversarial validation) — full methodology in the generated report.</div>' : '');

  // Proof of concept — doctrine tells agents to cite the PoC's file name in
  // `evidence` (see pocs_line() in pipeline.rs), so match on that text first;
  // fall back to whatever the run wrote to pocs/ if nothing was cited.
  // Scripts this finding cites are rendered inside the PoC block above; this
  // list is the run's remaining scripts, so nothing written is hidden.
  const citedIn = `${f.evidence || ''} ${f.payload || ''} ${(f.repro_steps || []).join(' ')}`;
  const list = (pocs || []).filter((p) => !citedIn.includes(p));
  const pocRoot = $('#fmPocList');
  if (!list.length) {
    pocRoot.textContent = 'No other scripts from this run.';
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

// ---------------------------------------------------------------------------
// Generative Attack Path Chaining
//
// The graph answers one question: how does an attacker get from the target to
// impact? Three things it must not do, each of which the first version did:
//
//  1. **Drop findings.** Stages were matched against a hardcoded list of seven,
//     so anything the harness emitted outside it (`credential-access`,
//     `discovery`, `persistence`, …) silently vanished — 5 of 27 findings on a
//     real run. The stage list now mirrors `knowledge_graph::STAGES`, and any
//     unknown stage still gets its own column rather than being discarded.
//  2. **Blur into unreadable boxes.** Titles were cut at 22 characters, so a
//     column read "SQL Injection Authent…" six times. Nodes now wrap onto two
//     lines and carry CWE / technique / exploitability.
//  3. **Present a guess as evidence.** Agents only sometimes fill `chains_from`.
//     Without it every node fanned off the root, which looks like a chain and
//     is not one. Inferred progression edges are drawn dashed, counted
//     separately in the toolbar, and can be hidden.
//
// When a run wrote `graph.json` (the harness's own knowledge graph), its edges
// are used verbatim — including which ones it inferred. Older runs fall back to
// deriving the same shape client-side, so the view degrades rather than empties.
// ---------------------------------------------------------------------------

// Mirrors knowledge_graph::STAGES on the Rust side. Order = attack progression.
const KILL_CHAIN_STAGES = [
  'recon', 'discovery', 'initial-access', 'execution', 'persistence',
  'privesc', 'credential-access', 'lateral', 'collection', 'exfil', 'impact',
];
const stageRank = (s) => {
  const i = KILL_CHAIN_STAGES.indexOf(s);
  return i === -1 ? KILL_CHAIN_STAGES.length : i;
};

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

/// Greedy wrap into at most `lines` lines of `max` chars, ellipsizing the tail.
function wrapLabel(s, max, lines) {
  const words = String(s || '').split(/\s+/).filter(Boolean);
  const out = [];
  let cur = '';
  for (const w of words) {
    const next = cur ? `${cur} ${w}` : w;
    if (next.length <= max) { cur = next; continue; }
    if (out.length === lines - 1) { cur = `${next.slice(0, max - 1)}…`; break; }
    out.push(cur || w.slice(0, max));
    cur = cur ? w : '';
  }
  if (cur) out.push(cur);
  return out.slice(0, lines);
}

/// Chain edges between findings, and where they came from.
/// Returns `{ edges: [{from, to, inferred}], source }` with indices into
/// `findings`, so the caller can tell the operator what it is looking at.
function chainEdges(findings, graph) {
  const byId = new Map(findings.map((f, i) => [f.id, i]));

  // 1. The harness's own graph, when the run wrote one.
  if (graph?.edges?.length) {
    const nodeToFinding = new Map();
    for (const [id, n] of Object.entries(graph.nodes || {})) {
      const fid = n.meta?.finding_id;
      if (n.kind === 'finding' && fid !== undefined && byId.has(fid)) nodeToFinding.set(id, byId.get(fid));
    }
    const edges = [];
    for (const e of graph.edges) {
      if (e.kind !== 'chains') continue;
      const a = nodeToFinding.get(e.from), b = nodeToFinding.get(e.to);
      if (a !== undefined && b !== undefined && a !== b) edges.push({ from: a, to: b, inferred: !!e.inferred });
    }
    if (edges.length) return { edges, source: edges.every((e) => e.inferred) ? 'graph-inferred' : 'graph' };
  }

  // 2. Edges the agents asserted on the findings themselves.
  const asserted = [];
  findings.forEach((f, i) => {
    for (const src of f.chains_from || []) {
      const a = byId.get(src);
      if (a !== undefined && a !== i) asserted.push({ from: a, to: i, inferred: false });
    }
  });
  if (asserted.length) return { edges: asserted, source: 'asserted' };

  // 3. Derive progression the same way the harness does: forward only, between
  // adjacent populated stages, from the strongest finding of the earlier one.
  // A full cross-product would look richer and mean nothing.
  const byStage = new Map();
  findings.forEach((f, i) => {
    const r = stageRank(f.stage || '');
    if (!byStage.has(r)) byStage.set(r, []);
    byStage.get(r).push(i);
  });
  const ranks = [...byStage.keys()].sort((a, b) => a - b);
  const weight = (i) => (4 - sevRank(findings[i].severity)) * (findings[i].confidence || 0.5);
  const edges = [];
  for (let k = 0; k + 1 < ranks.length; k++) {
    const from = byStage.get(ranks[k]).slice().sort((a, b) => weight(b) - weight(a))[0];
    for (const to of byStage.get(ranks[k + 1])) edges.push({ from, to, inferred: true });
  }
  return { edges, source: edges.length ? 'derived' : 'none' };
}

const AP_SEV_FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

function renderAttackPath(container, allFindings, target, graph) {
  const view = (container.__ap = container.__ap || { k: 1, tx: 0, ty: 0, sev: 'all', hideInferred: false, fitted: false });

  if (!allFindings.length) {
    container.innerHTML = '<div class="attackpath-empty">The attack path builds automatically as findings chain together — nothing confirmed yet.</div>';
    return;
  }

  const minRank = view.sev === 'all' ? 99 : sevRank(view.sev);
  const findings = view.sev === 'all' ? allFindings : allFindings.filter((f) => sevRank(f.severity) <= minRank);
  if (!findings.length) {
    container.innerHTML = `<div class="attackpath-empty">No ${esc(view.sev)}-or-higher finding to chain. <button class="btn btn-sm" data-ap-reset>Show all severities</button></div>`;
    container.querySelector('[data-ap-reset]')?.addEventListener('click', () => { view.sev = 'all'; renderAttackPath(container, allFindings, target, graph); });
    return;
  }

  const model = chainEdges(findings, graph);
  const edges = view.hideInferred ? model.edges.filter((e) => !e.inferred) : model.edges;

  // ---- columns: one per stage actually present, in progression order --------
  const groups = new Map();
  findings.forEach((f, i) => {
    const key = (f.stage || '').trim() || 'unstaged';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(i);
  });
  const cols = [...groups.entries()].sort((a, b) => {
    const ra = a[0] === 'unstaged' ? 999 : stageRank(a[0]);
    const rb = b[0] === 'unstaged' ? 999 : stageRank(b[0]);
    return ra - rb || a[0].localeCompare(b[0]);
  });
  for (const [, idxs] of cols) {
    idxs.sort((a, b) => sevRank(findings[a].severity) - sevRank(findings[b].severity) || (findings[b].confidence || 0) - (findings[a].confidence || 0));
  }

  const NODE_W = 236, NODE_H = 66, COL_GAP = 88, ROW_GAP = 14, PAD = 28, HEAD_H = 34, ROOT_W = 132;
  const rowH = NODE_H + ROW_GAP;
  const tallest = Math.max(...cols.map(([, v]) => v.length));
  const bodyH = tallest * rowH;
  const pos = new Map(); // finding index -> {x, y}
  cols.forEach(([, idxs], ci) => {
    const x = PAD + ROOT_W + ci * (NODE_W + COL_GAP);
    const colH = idxs.length * rowH;
    const top = PAD + HEAD_H + (bodyH - colH) / 2;
    idxs.forEach((fi, ri) => pos.set(fi, { x, y: top + ri * rowH }));
  });
  const width = PAD * 2 + ROOT_W + cols.length * NODE_W + Math.max(0, cols.length - 1) * COL_GAP;
  const height = PAD * 2 + HEAD_H + bodyH;
  const rootY = PAD + HEAD_H + bodyH / 2;

  const hasParent = new Set(edges.map((e) => e.to));
  const roots = findings.map((_, i) => i).filter((i) => !hasParent.has(i));

  const curve = (x1, y1, x2, y2) => {
    const mid = (x1 + x2) / 2;
    return `M ${x1},${y1} C ${mid},${y1} ${mid},${y2} ${x2},${y2}`;
  };

  const edgeSvg = edges.map((e, i) => {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b) return '';
    return `<path class="ap-edge${e.inferred ? ' inferred' : ''}" data-e="${i}" data-from="${e.from}" data-to="${e.to}"
      d="${curve(a.x + NODE_W, a.y + NODE_H / 2, b.x, b.y + NODE_H / 2)}" fill="none" marker-end="url(#apArrow)" />`;
  }).join('');

  const rootEdges = roots.map((i) => {
    const b = pos.get(i);
    return `<path class="ap-edge root-edge" data-root-to="${i}" d="${curve(PAD + ROOT_W - 18, rootY, b.x, b.y + NODE_H / 2)}" fill="none" />`;
  }).join('');

  const nodeSvg = findings.map((f, i) => {
    const p = pos.get(i);
    if (!p) return '';
    const color = canvasColor(f.severity);
    const title = wrapLabel(f.title, 30, 2);
    const meta = [f.cwe, f.mitre || f.owasp, f.exploitability].filter(Boolean).join(' · ');
    return `<g class="ap-node-g" data-idx="${i}" tabindex="0" role="button" aria-label="${esc(f.severity)}: ${esc(f.title)}">
      <rect class="ap-node" x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="9" style="stroke:${color};" />
      <rect class="ap-sevbar" x="${p.x}" y="${p.y}" width="4" height="${NODE_H}" rx="2" style="fill:${color};" />
      <text class="ap-icon" x="${p.x + 14}" y="${p.y + 22}">${nodeIcon(f)}</text>
      ${title.map((line, li) => `<text class="ap-title" x="${p.x + 34}" y="${p.y + 21 + li * 14}">${esc(line)}</text>`).join('')}
      <text class="ap-meta" x="${p.x + 34}" y="${p.y + NODE_H - 12}">${esc(meta || f.agent)}</text>
      <text class="ap-conf" x="${p.x + NODE_W - 10}" y="${p.y + NODE_H - 12}" text-anchor="end">${f.confidence ? f.confidence.toFixed(2) : ''}</text>
    </g>`;
  }).join('');

  // Column headers name the stage and count it — unlabelled separator lines
  // made the columns unreadable, which defeats a kill-chain layout entirely.
  const headSvg = cols.map(([stage, idxs], ci) => {
    const x = PAD + ROOT_W + ci * (NODE_W + COL_GAP);
    return `<g class="ap-col">
      <line class="ap-col-line" x1="${x - COL_GAP / 2}" y1="${PAD}" x2="${x - COL_GAP / 2}" y2="${height - PAD}" />
      <text class="ap-col-name" x="${x}" y="${PAD + 14}">${esc(stage.replace(/-/g, ' '))}</text>
      <text class="ap-col-count" x="${x + NODE_W}" y="${PAD + 14}" text-anchor="end">${idxs.length}</text>
    </g>`;
  }).join('');

  const inferredCount = model.edges.filter((e) => e.inferred).length;
  const provenance = {
    graph: 'chain edges from this run\'s knowledge graph',
    'graph-inferred': 'no chain was asserted — progression inferred by the harness',
    asserted: 'chain edges asserted by the agents',
    derived: 'no chain was asserted — progression inferred from kill-chain stages',
    none: 'no chain links',
  }[model.source];

  container.innerHTML = `
    <div class="ap-toolbar">
      <div class="ap-stats">
        <b>${findings.length}</b> finding(s) · <b>${cols.length}</b> stage(s) · <b>${edges.length}</b> link(s)${inferredCount ? ` <span class="ap-inferred-note">(${inferredCount} inferred)</span>` : ''} · <b>${roots.length}</b> entry point(s)
      </div>
      <div class="topbar-spacer"></div>
      <label class="ap-check"><input type="checkbox" id="apHideInferred" ${view.hideInferred ? 'checked' : ''} /> hide inferred</label>
      <select class="ap-sev" id="apSev" title="Minimum severity">
        ${AP_SEV_FILTERS.map((s) => `<option value="${s}"${view.sev === s ? ' selected' : ''}>${s === 'all' ? 'all severities' : `${s} and above`}</option>`).join('')}
      </select>
      <div class="ap-zoom">
        <button class="btn btn-sm" data-ap-zoom="-1" title="Zoom out">−</button>
        <button class="btn btn-sm" data-ap-fit title="Fit to window">fit</button>
        <button class="btn btn-sm" data-ap-zoom="1" title="Zoom in">+</button>
      </div>
    </div>
    <div class="ap-provenance">${esc(provenance)} — inferred links are hypotheses, drawn dashed.</div>
    <div class="ap-canvas-wrap" id="apWrap">
      <svg class="ap-canvas" id="apSvg" width="100%" height="100%">
        <defs>
          <marker id="apArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" />
          </marker>
        </defs>
        <g class="ap-pan" id="apPan">
          ${headSvg}
          ${rootEdges}
          ${edgeSvg}
          <g class="ap-root">
            <rect class="ap-node" x="${PAD}" y="${rootY - 22}" width="${ROOT_W - 18}" height="44" rx="9" />
            <text class="ap-icon" x="${PAD + 14}" y="${rootY + 4}">🎯</text>
            <text class="ap-title" x="${PAD + 34}" y="${rootY - 2}">target</text>
            <text class="ap-meta" x="${PAD + 34}" y="${rootY + 12}">${esc(trimMid(target || '', 14))}</text>
          </g>
          ${nodeSvg}
        </g>
      </svg>
      <div class="ap-hint">drag to pan · scroll to zoom · click a node for the finding</div>
    </div>
    <div class="ap-legend">
      ${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<span class="ap-key"><i style="background:var(--sev-${s}-fg)"></i>${s}</span>`).join('')}
      <span class="ap-key"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" class="ap-edge" /></svg>asserted chain</span>
      <span class="ap-key"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" class="ap-edge inferred" /></svg>inferred</span>
    </div>`;

  const svg = container.querySelector('#apSvg');
  const pan = container.querySelector('#apPan');
  const wrap = container.querySelector('#apWrap');

  const apply = () => pan.setAttribute('transform', `translate(${view.tx},${view.ty}) scale(${view.k})`);
  const fit = () => {
    const box = wrap.getBoundingClientRect();
    // The panel is rendered while its tab is still hidden, so the box measures
    // zero and a "fit" there would lock in a garbage scale. Report the failure
    // so the caller can try again once the tab is actually on screen.
    if (!box.width || !box.height) return false;
    view.k = Math.min(box.width / width, box.height / height, 1);
    view.tx = (box.width - width * view.k) / 2;
    view.ty = (box.height - height * view.k) / 2;
    apply();
    return true;
  };
  apply();
  // Auto-fit once, and only once it can actually measure: re-fitting on every
  // live finding would yank the canvas out from under someone mid-inspection.
  if (!view.fitted) {
    const tryFit = () => { if (fit()) view.fitted = true; };
    requestAnimationFrame(tryFit);
    if (window.ResizeObserver) {
      const ro = new ResizeObserver(() => { if (view.fitted) ro.disconnect(); else tryFit(); });
      ro.observe(wrap);
    }
  }

  container.querySelector('[data-ap-fit]').addEventListener('click', fit);
  container.querySelectorAll('[data-ap-zoom]').forEach((b) => b.addEventListener('click', () => {
    const box = wrap.getBoundingClientRect();
    const factor = Number(b.dataset.apZoom) > 0 ? 1.2 : 1 / 1.2;
    const cx = box.width / 2, cy = box.height / 2;
    view.tx = cx - (cx - view.tx) * factor;
    view.ty = cy - (cy - view.ty) * factor;
    view.k = Math.max(0.15, Math.min(3, view.k * factor));
    apply();
  }));
  container.querySelector('#apHideInferred').addEventListener('change', (e) => {
    view.hideInferred = e.target.checked;
    renderAttackPath(container, allFindings, target, graph);
  });
  container.querySelector('#apSev').addEventListener('change', (e) => {
    view.sev = e.target.value;
    renderAttackPath(container, allFindings, target, graph);
  });

  wrap.addEventListener('wheel', (e) => {
    e.preventDefault();
    const box = wrap.getBoundingClientRect();
    const mx = e.clientX - box.left, my = e.clientY - box.top;
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    view.tx = mx - (mx - view.tx) * factor;
    view.ty = my - (my - view.ty) * factor;
    view.k = Math.max(0.15, Math.min(3, view.k * factor));
    apply();
  }, { passive: false });

  let dragging = false, sx = 0, sy = 0, moved = 0;
  wrap.addEventListener('pointerdown', (e) => {
    dragging = true; moved = 0; sx = e.clientX - view.tx; sy = e.clientY - view.ty;
    wrap.setPointerCapture(e.pointerId);
    wrap.classList.add('dragging');
  });
  wrap.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    moved += Math.abs(e.movementX) + Math.abs(e.movementY);
    view.tx = e.clientX - sx; view.ty = e.clientY - sy;
    apply();
  });
  const endDrag = (e) => { dragging = false; wrap.classList.remove('dragging'); if (e?.pointerId !== undefined) { try { wrap.releasePointerCapture(e.pointerId); } catch { /* already released */ } } };
  wrap.addEventListener('pointerup', endDrag);
  wrap.addEventListener('pointercancel', endDrag);

  // Highlight the whole path through a node, both directions — the question a
  // reader has in front of a graph is "what led here, and where does it go".
  const up = new Map(), down = new Map();
  edges.forEach((e) => {
    if (!down.has(e.from)) down.set(e.from, []);
    down.get(e.from).push(e.to);
    if (!up.has(e.to)) up.set(e.to, []);
    up.get(e.to).push(e.from);
  });
  const reach = (start, map) => {
    const seen = new Set(), stack = [start];
    while (stack.length) {
      const n = stack.pop();
      for (const m of map.get(n) || []) if (!seen.has(m)) { seen.add(m); stack.push(m); }
    }
    return seen;
  };
  const focusOn = (idx) => {
    const set = new Set([idx, ...reach(idx, up), ...reach(idx, down)]);
    svg.classList.add('has-focus');
    container.querySelectorAll('.ap-node-g').forEach((g) => g.classList.toggle('focus', set.has(Number(g.dataset.idx))));
    container.querySelectorAll('.ap-edge').forEach((p) => {
      const f = Number(p.dataset.from), t = Number(p.dataset.to);
      const r = Number(p.dataset.rootTo);
      p.classList.toggle('focus', (set.has(f) && set.has(t)) || (!Number.isNaN(r) && r === idx));
    });
  };
  const clearFocus = () => {
    svg.classList.remove('has-focus');
    container.querySelectorAll('.focus').forEach((el) => el.classList.remove('focus'));
  };

  container.querySelectorAll('.ap-node-g').forEach((g) => {
    const idx = Number(g.dataset.idx);
    g.addEventListener('mouseenter', () => focusOn(idx));
    g.addEventListener('focus', () => focusOn(idx));
    g.addEventListener('mouseleave', clearFocus);
    g.addEventListener('blur', clearFocus);
    const open = () => {
      const isLive = container.id === 'liveAttackPath';
      const pocs = isLive ? (state.currentJob?.pocs || []) : (state.detailPocs || []);
      const runId = isLive ? state.currentJob?.runId : state.currentDetailId;
      openFindingModal(findings[idx], pocs, runId);
    };
    // A pan that ends on a node is not a click on it.
    g.addEventListener('click', () => { if (moved < 6) open(); });
    g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  });
}
/// Exactly where the problem is: parameter/field/flow, not just the URL.
function locationLine(f) {
  const loc = (f.location || '').trim();
  const ep = (f.endpoint || '').trim();
  if (!loc && !ep) return '(location not recorded)';
  if (!loc) return ep;
  if (!ep || loc.includes(ep)) return loc;
  return `${ep} — ${loc}`;
}

function isSecretHeader(k) {
  const n = k.toLowerCase();
  return n === 'authorization' || n === 'cookie' || n === 'x-api-key' || n.includes('token') || n.includes('secret');
}

/// A pasteable curl for the recorded request. Credentials are redacted: a
/// finding gets shared, and a live session cookie in a document is a new bug.
function curlCommand(f) {
  const a = f.evidence_data?.attack;
  if (a) {
    let cmd = 'curl -i -s';
    const m = (a.method || 'GET').toUpperCase();
    if (m !== 'GET') cmd += ` -X ${m}`;
    for (const [k, v] of Object.entries(a.request_headers || {})) {
      cmd += ` \\\n  -H '${k}: ${isSecretHeader(k) ? '<redacted — use your own>' : v}'`;
    }
    if (f.payload && m !== 'GET') cmd += ` \\\n  --data-raw '${String(f.payload).replace(/'/g, "'\\''")}'`;
    cmd += ` \\\n  '${a.url}'`;
    return cmd;
  }
  return f.endpoint ? `curl -i -s '${f.endpoint}'` : '';
}

/// Ordered steps: what the agent recorded, or a minimal derived sequence.
function reproSteps(f) {
  if (Array.isArray(f.repro_steps) && f.repro_steps.length) return f.repro_steps;
  const steps = [];
  const ev = f.evidence_data;
  if (ev?.identity_a && ev?.identity_b) {
    steps.push(`As ${ev.identity_a.identity || 'the owner'}:\ncurl -i -s '${ev.identity_a.url}'`);
    steps.push(`As ${ev.identity_b.identity || 'the other identity'}, request the SAME resource:\ncurl -i -s '${ev.identity_b.url}'`);
    steps.push('Compare the two bodies — the second returning the first\u2019s data is the finding.');
    return steps;
  }
  if (ev?.baseline) steps.push(`Baseline — the same resource without the payload:\ncurl -i -s '${ev.baseline.url}'`);
  const curl = curlCommand(f);
  if (curl) steps.push(`Send the request carrying the payload:\n${curl}`);
  if (f.payload) steps.push(`Payload used:\n${String(f.payload).trim()}`);
  return steps.length ? steps : ['No reproduction steps were recorded for this finding.'];
}

/// The measured difference plus the raw exchanges — what turns "it returned a
/// 500" into something a reviewer can check.
function technicalEvidence(f) {
  const ev = f.evidence_data;
  let out = '';
  const ex = (label, x) => {
    if (!x) return '';
    let s = `${label}\n  ${(x.method || 'GET')} ${x.url} → ${x.status}\n`;
    if (x.identity) s += `  identity: ${x.identity}\n`;
    for (const k of ['location', 'set-cookie', 'content-type', 'access-control-allow-origin', 'access-control-allow-credentials', 'x-frame-options', 'content-security-policy', 'retry-after']) {
      const v = (x.headers || {})[k];
      if (v) s += `  ${k}: ${String(v).slice(0, 200)}\n`;
    }
    if (x.body?.trim()) s += `  body (${x.body.length} bytes, excerpt):\n${x.body.trim().slice(0, 1200).split('\n').map((l) => '    ' + l).join('\n')}\n`;
    return s + '\n';
  };
  if (ev?.baseline && ev?.attack) {
    const b = ev.baseline, a = ev.attack;
    const ratio = b.body?.length ? (a.body.length / b.body.length) : 0;
    out += `MEASURED DIFFERENCE\n  baseline : ${b.status} · ${b.body?.length ?? 0} bytes · ${b.elapsed_ms ?? 0} ms\n`
        +  `  attack   : ${a.status} · ${a.body?.length ?? 0} bytes · ${a.elapsed_ms ?? 0} ms\n`
        +  `  delta    : status ${b.status} → ${a.status}, body ${((ratio - 1) * 100).toFixed(0)}%\n`;
    if (ev.repeats?.length) out += `  repeats  : ${ev.repeats.length} recorded\n`;
    out += '\n';
  }
  if (ev?.marker) {
    out += `CONTROLLED MARKER\n  ${ev.marker} — observed: ${ev.marker_observed ? 'yes' : 'no'}`
        +  `${ev.browser_executed ? ' · executed in a real browser' : ''}${ev.callback_received ? ' · out-of-band callback' : ''}\n\n`;
  }
  out += ex('BASELINE', ev?.baseline) + ex('ATTACK', ev?.attack) + ex('AS OWNER', ev?.identity_a) + ex('AS OTHER IDENTITY', ev?.identity_b);
  if (f.evidence?.trim()) out += `AGENT-RECORDED EVIDENCE\n${f.evidence.trim()}\n`;
  return out.trim();
}

/// The proof: numbered steps, then the payload, with any script offered as an
/// extra artifact rather than as the proof itself.
function pocBlock(f, pocs, runId) {
  const steps = reproSteps(f).map((s) => `<li><pre class="step">${esc(s)}</pre></li>`).join('');
  const payload = f.payload?.trim()
    ? `<div class="field-group"><label class="field-label">Payload</label><pre class="poc-pre">${esc(f.payload.trim())}</pre></div>` : '';
  const cited = `${f.evidence || ''} ${f.payload || ''} ${(f.repro_steps || []).join(' ')}`;
  const scripts = (pocs || []).filter((p) => cited.includes(p));
  const scriptBlock = scripts.length
    ? `<div class="field-group"><label class="field-label">Runnable script (extra)</label>
       <div class="field-help">The steps above are the proof; this script automates them.</div>
       ${scripts.map((n) => `<div class="poc-file"><span class="fn">pocs/${esc(n)}</span>
         <a class="btn btn-sm" href="/api/runs/${esc(runId)}/asset/pocs/${esc(n)}" target="_blank">Open raw</a></div>`).join('')}</div>`
    : '';
  return `<div class="field-group"><label class="field-label">Proof of concept — step by step</label>
            <ol class="poc-steps">${steps}</ol></div>${payload}${scriptBlock}`;
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

/// Group runs into target folders. Twelve runs of three hosts was a flat list
/// of twelve near-identical rows; the host is what an operator actually scans
/// for, so it becomes the folder and the runs live inside it.
function runFolders(runs) {
  const folders = new Map();
  for (const r of runs) {
    const key = engagementKey(r.target || r.id);
    if (!folders.has(key)) folders.set(key, { key, items: [], ts: 0, findings: 0, severities: {} });
    const f = folders.get(key);
    f.items.push(r);
    f.ts = Math.max(f.ts, r.ts || 0);
    f.findings += r.findings || 0;
    for (const [k, n] of Object.entries(r.severities || {})) f.severities[k] = (f.severities[k] || 0) + n;
  }
  for (const f of folders.values()) f.items.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return [...folders.values()].sort((a, b) => b.ts - a.ts);
}

/// Same normalization the harness uses for its engagement key, so a folder here
/// and an engagement in the harness's memory mean the same thing.
function engagementKey(target) {
  const t = String(target || '').trim().toLowerCase();
  const noScheme = t.includes('://') ? t.split('://')[1] : t;
  const host = noScheme.split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/^www\./, '');
  return host || t || 'unknown';
}

function worstSeverity(severities) {
  return SEV_ORDER.find((s) => Object.entries(severities || {}).some(([k, n]) => n && SEV_ORDER[sevRank(k)] === s));
}

const SB_OPEN_KEY = 'ns-sb-open';
function openFolders() {
  try { return new Set(JSON.parse(localStorage.getItem(SB_OPEN_KEY) || '[]')); } catch { return new Set(); }
}
function setFolderOpen(key, on) {
  const s = openFolders();
  if (on) s.add(key); else s.delete(key);
  localStorage.setItem(SB_OPEN_KEY, JSON.stringify([...s]));
}

function runButton(r) {
  const btn = document.createElement('button');
  btn.className = 'sb-run' + (state.currentDetailId === r.id ? ' active' : '');
  // Every line here truncates: a long target URL used to run past the
  // sidebar's edge and collide with the main pane.
  const worst = worstSeverity(r.severities);
  btn.innerHTML = `
    <span class="name">${worst ? `<span class="run-dot sev-dot-${worst}" title="worst severity: ${worst}"></span>` : ''}<span class="label">${esc(r.name || r.target)}</span></span>
    <span class="sub">${r.name ? esc(r.target) : esc(r.id)}</span>
    <span class="sub sub-facts"><span>${r.findings} finding${r.findings === 1 ? '' : 's'}</span><span>${esc(timeAgo(r.ts))}</span></span>`;
  btn.title = `${r.name ? r.name + '\n' : ''}${r.target}\n${r.id}${r.ts ? '\n' + new Date(r.ts * 1000).toLocaleString() : ''}`;
  btn.addEventListener('click', () => openRun(r));
  return btn;
}

function renderSidebar() {
  const root = $('#sbGroups');
  root.innerHTML = '';
  const q = (state.runFilter || '').trim().toLowerCase();
  const match = (r) => !q || `${r.name} ${r.target} ${r.id}`.toLowerCase().includes(q);
  const runs = state.runs.filter(match);
  const running = runs.filter((r) => r.state === 'running');
  const past = runs.filter((r) => r.state !== 'running');

  if (running.length) {
    const wrap = document.createElement('div');
    wrap.className = 'sb-group';
    wrap.innerHTML = `<div class="sb-group-head"><span class="caret">▾</span><span>Running</span><span class="count">${running.length}</span></div><div class="sb-items"></div>`;
    wrap.querySelector('.sb-group-head').addEventListener('click', () => wrap.classList.toggle('collapsed'));
    const items = wrap.querySelector('.sb-items');
    for (const r of running) {
      items.appendChild(runButton(r));
      if (state.currentJob && r.id === state.currentJob.runId) {
        const steps = document.createElement('div');
        steps.className = 'sb-steps';
        steps.innerHTML = ['recon', 'planning', 'exploiting', 'remediation'].map((s) =>
          `<div class="sb-step ${stepClassFor($('#livePhase').textContent, s)}">${s[0].toUpperCase() + s.slice(1)}</div>`).join('');
        items.appendChild(steps);
      }
    }
    root.appendChild(wrap);
  }

  const folders = runFolders(past);
  if (!folders.length) {
    const empty = document.createElement('div');
    empty.className = 'sb-empty';
    empty.textContent = q ? `No run matches “${q}”.` : 'No runs yet.';
    root.appendChild(empty);
    return;
  }

  const open = openFolders();
  for (const f of folders) {
    const holdsActive = f.items.some((r) => r.id === state.currentDetailId);
    // A search is a request to see what matched — collapsing the results would
    // hide the very thing that was searched for.
    const isOpen = !!q || holdsActive || open.has(f.key);
    const wrap = document.createElement('div');
    wrap.className = 'sb-folder' + (isOpen ? '' : ' collapsed');
    const worst = worstSeverity(f.severities);
    wrap.innerHTML = `
      <div class="sb-folder-head" title="${esc(f.key)} — ${f.items.length} run(s), ${f.findings} finding(s)">
        <span class="caret">▾</span>
        ${worst ? `<span class="run-dot sev-dot-${worst}"></span>` : '<span class="run-dot"></span>'}
        <span class="fname">${esc(f.key)}</span>
        <span class="fmeta">${f.items.length}</span>
      </div>
      <div class="sb-items"></div>`;
    wrap.querySelector('.sb-folder-head').addEventListener('click', () => {
      const nowCollapsed = wrap.classList.toggle('collapsed');
      setFolderOpen(f.key, !nowCollapsed);
    });
    const items = wrap.querySelector('.sb-items');
    for (const r of f.items) items.appendChild(runButton(r));
    root.appendChild(wrap);
  }
}

function openRun(run) {
  state.currentDetailId = run.id;
  if (run.state === 'running' && state.currentJob && run.id === state.currentJob.runId) {
    show($('#wizardView'), false); show($('#detailView'), false); show($('#dashView'), false); show($('#liveView'), true);
    renderSidebar();
    return;
  }
  show($('#wizardView'), false); show($('#liveView'), false); show($('#dashView'), false); show($('#detailView'), true);
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
  // The harness writes graph.json per run (knowledge_graph::ingest). When it
  // exists, its edges — including which ones it inferred — beat anything the
  // browser could re-derive; older runs simply fall back.
  const graph = await api(`/api/runs/${encodeURIComponent(id)}/asset/graph.json`).catch(() => null);
  renderAttackPath($('#detailAttackPath'), detail.findings, target, graph);
  const reportLink = $('#detailOpenReport');
  if (detail.assets.includes('report.html')) {
    reportLink.href = `/api/runs/${encodeURIComponent(id)}/asset/report.html`;
    show(reportLink, true);
  } else show(reportLink, false);
  // The PDF is produced by the harness (Typst) when that binary is present, so
  // it is offered only when it actually exists — a dead download button is
  // worse than none.
  const pdfLink = $('#detailOpenPdf');
  if (detail.assets.includes('report.pdf')) {
    pdfLink.href = `/api/runs/${encodeURIComponent(id)}/asset/report.pdf`;
    pdfLink.setAttribute('download', `${id}.pdf`);
    show(pdfLink, true);
  } else show(pdfLink, false);
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
  if ($('#sidebar').classList.contains('open')) return setSidebar(false);
  if (!$('#termDock').hidden) termClose();
});


// ---------------------------------------------------------------------------
// Dashboard — coverage, findings, and FAIR loss exposure
//
// The console could show one run at a time and nothing about the programme as a
// whole: how much has been tested, what keeps coming back, and what any of it
// is worth in money. The last question is the one a security owner is actually
// asked, and "14 highs" is not an answer to it.
//
// ## FAIR, and why the assumptions are on screen
//
// Risk here follows FAIR (Factor Analysis of Information Risk): annualized loss
// exposure = Loss Event Frequency × Loss Magnitude, where
//
//   LEF = Threat Event Frequency × Vulnerability
//
// Both factors are estimates, not measurements. TEF (how often someone tries)
// is derived from the harness's own `exploitability` rating — a trivially
// exploitable bug on an internet-facing app gets attempted constantly, a hard
// one rarely. Vulnerability (how often an attempt succeeds) uses the finding's
// validation confidence, which is exactly what the multi-model vote measured.
// Loss magnitude cannot be derived from a scan at all: it depends on the
// business. So the defaults below are stated openly, shown in the UI, and
// editable — and the result is a RANGE, never a single number, because a point
// estimate of a distribution is the classic way risk quantification lies.
// ---------------------------------------------------------------------------

const FAIR_DEFAULTS = {
  // Threat event frequency: attempts per year, by how easy the harness judged
  // the finding to exploit.
  tef: { trivial: 12, moderate: 4, hard: 1, unknown: 3 },
  // Loss magnitude in USD per event: [minimum, most likely, maximum].
  // Order-of-magnitude industry defaults — replace with your own loss data.
  lm: {
    critical: [250000, 1200000, 5000000],
    high: [75000, 400000, 1500000],
    medium: [15000, 80000, 300000],
    low: [2000, 15000, 60000],
    info: [0, 1000, 5000],
  },
};
const FAIR_KEY = 'ns-fair-params';

function fairParams() {
  try {
    const saved = JSON.parse(localStorage.getItem(FAIR_KEY) || 'null');
    if (saved?.tef && saved?.lm) return saved;
  } catch { /* fall through to defaults */ }
  return structuredClone(FAIR_DEFAULTS);
}
function saveFairParams(p) { localStorage.setItem(FAIR_KEY, JSON.stringify(p)); }

const money = (n) => {
  if (!isFinite(n)) return '—';
  if (n >= 1e9) return `$${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${Math.round(n / 1e3)}K`;
  return `$${Math.round(n)}`;
};

/// Annualized loss exposure for one finding, as [min, likely, max].
function fairForFinding(f, params) {
  const sev = SEV_ORDER[sevRank(f.severity)];
  const lm = params.lm[sev] || params.lm.info;
  const tef = params.tef[(f.exploitability || 'unknown').toLowerCase()] ?? params.tef.unknown;
  // A finding flagged for human review is a maybe, not a fact — halving its
  // frequency keeps it visible without letting unreviewed leads drive the total.
  const reviewFactor = f.reviewStatus === 'needs-review' ? 0.5 : 1;
  const vuln = Math.min(0.95, Math.max(0.2, f.confidence || 0.5));
  const lef = tef * vuln * reviewFactor;
  return lm.map((m) => lef * m);
}

/// Heuristic posture score, 0-100. Deliberately simple and fully stated in the
/// UI: an opaque score invites arguing with the number instead of the findings.
///
/// Subtracting a fixed penalty per finding hit zero after one critical and a
/// handful of highs, which makes the score useless exactly when there is
/// something to track — a programme that fixes half its criticals must be able
/// to see the number move. The saturating form has diminishing returns instead,
/// so it keeps discriminating at any volume and never quite reaches 0.
const SCORE_WEIGHT = { critical: 10, high: 5, medium: 2, low: 0.5, info: 0.1 };
const SCORE_SCALE = 25;
function riskLoad(findings) {
  return findings.reduce((acc, f) => {
    const sev = SEV_ORDER[sevRank(f.severity)];
    return acc + (SCORE_WEIGHT[sev] || 0) * Math.min(1, Math.max(0.3, f.confidence || 0.5));
  }, 0);
}
function exposureScore(findings) {
  return Math.round(100 / (1 + riskLoad(findings) / SCORE_SCALE));
}
function scoreBand(score) {
  if (score >= 85) return { label: 'low exposure', cls: 'low' };
  if (score >= 65) return { label: 'moderate exposure', cls: 'medium' };
  if (score >= 40) return { label: 'high exposure', cls: 'high' };
  return { label: 'critical exposure', cls: 'critical' };
}

/// One horizontal bar row: a label, a proportional fill, a direct value.
/// Values are labeled on every row, so the bar is a second encoding of a number
/// that is already readable — not the only way to read it.
function barRow(label, value, max, cls, title) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 0;
  return `<div class="bar-row" title="${esc(title || `${label}: ${value}`)}">
    <span class="bar-label">${esc(label)}</span>
    <span class="bar-track"><span class="bar-fill${cls ? ` bar-${cls}` : ''}" style="width:${pct}%"></span></span>
    <span class="bar-value">${esc(String(value))}</span>
  </div>`;
}

function dashRangeCutoff() {
  const days = Number($('#dashRange')?.value || 0);
  return days > 0 ? Date.now() / 1000 - days * 86400 : 0;
}

async function renderDashboard() {
  const body = $('#dashBody');
  let data;
  try {
    data = await api('/api/stats');
  } catch (e) {
    body.innerHTML = `<div class="empty-state">Couldn't load stats: ${esc(e.message)}</div>`;
    return;
  }
  const cutoff = dashRangeCutoff();
  const runs = data.runs.filter((r) => !cutoff || r.ts >= cutoff);
  const findings = data.findings.filter((f) => !cutoff || f.ts >= cutoff);
  const params = fairParams();

  if (!runs.length) {
    body.innerHTML = '<div class="empty-state">No runs in this range yet — start an engagement and the dashboard fills in.</div>';
    return;
  }

  const targets = new Set(runs.map((r) => engagementKey(r.target)));
  const sevCounts = {};
  for (const f of findings) {
    const s = SEV_ORDER[sevRank(f.severity)];
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  }
  const needsReview = findings.filter((f) => f.reviewStatus === 'needs-review').length;
  const score = exposureScore(findings);
  const band = scoreBand(score);

  const ale = findings.reduce((acc, f) => {
    const [lo, ml, hi] = fairForFinding(f, params);
    return [acc[0] + lo, acc[1] + ml, acc[2] + hi];
  }, [0, 0, 0]);

  // Which findings actually drive the exposure — the reason to quantify at all
  // is to rank remediation, and the ranking is what gets acted on.
  const contributors = findings
    .map((f) => ({ f, ml: fairForFinding(f, params)[1] }))
    .sort((a, b) => b.ml - a.ml)
    .slice(0, 6);

  const byCwe = {};
  for (const f of findings) {
    if (!f.cwe) continue;
    byCwe[f.cwe] = (byCwe[f.cwe] || 0) + 1;
  }
  const topCwe = Object.entries(byCwe).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const byTarget = {};
  for (const r of runs) {
    const k = engagementKey(r.target);
    byTarget[k] = byTarget[k] || { runs: 0, findings: 0, last: 0 };
    byTarget[k].runs++;
    byTarget[k].findings += r.findings;
    byTarget[k].last = Math.max(byTarget[k].last, r.ts);
  }
  const targetRows = Object.entries(byTarget).sort((a, b) => b[1].findings - a[1].findings);

  const maxSev = Math.max(1, ...Object.values(sevCounts));
  const maxCwe = Math.max(1, ...topCwe.map(([, n]) => n));

  body.innerHTML = `
    <div class="stat-row">
      <div class="stat-tile">
        <div class="stat-k">Engagements</div>
        <div class="stat-v">${runs.length}</div>
        <div class="stat-sub">${targets.size} distinct target(s)</div>
      </div>
      <div class="stat-tile">
        <div class="stat-k">Findings</div>
        <div class="stat-v">${findings.length}</div>
        <div class="stat-sub">${needsReview} awaiting human review</div>
      </div>
      <div class="stat-tile">
        <div class="stat-k">Agents run</div>
        <div class="stat-v">${runs.reduce((a, r) => a + (r.agentsRan || 0), 0).toLocaleString('en-US')}</div>
        <div class="stat-sub">across ${runs.length} run(s)</div>
      </div>
      <div class="stat-tile stat-score sev-${band.cls}">
        <div class="stat-k">Exposure score</div>
        <div class="stat-v">${score}<span class="stat-unit">/100</span></div>
        <div class="stat-sub">${esc(band.label)}</div>
      </div>
    </div>

    <div class="dash-grid">
      <section class="dash-card dash-fair">
        <div class="dash-card-head">
          <h3>Annualized loss exposure (FAIR)</h3>
          <button class="btn btn-sm" id="btnFairParams">Assumptions</button>
        </div>
        <div class="fair-hero">
          <div class="fair-range">
            <div class="fair-point"><span class="k">minimum</span><span class="v">${money(ale[0])}</span></div>
            <div class="fair-point fair-likely"><span class="k">most likely</span><span class="v">${money(ale[1])}</span></div>
            <div class="fair-point"><span class="k">maximum</span><span class="v">${money(ale[2])}</span></div>
          </div>
          <div class="fair-note">
            Loss Event Frequency × Loss Magnitude, summed over ${findings.length} finding(s).
            Frequency comes from each finding's exploitability and validation confidence;
            magnitude comes from the assumptions you set. A range, not a forecast.
            Findings are summed independently, so shared root causes count twice —
            read it as an upper bound on annual exposure, not a portfolio model.
          </div>
        </div>
        <div class="fair-contrib">
          <div class="dash-sub">Top contributors (most likely annual loss)</div>
          ${contributors.map(({ f, ml }) => `
            <div class="contrib-row" title="${esc(f.title)} — ${esc(f.target)}">
              <span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span>
              <span class="contrib-title">${esc(f.title || f.cwe || 'untitled')}</span>
              <span class="contrib-v">${money(ml)}</span>
            </div>`).join('') || '<div class="field-help">No findings in range.</div>'}
        </div>
      </section>

      <section class="dash-card">
        <h3>Findings by severity</h3>
        ${SEV_ORDER.filter((s) => sevCounts[s]).map((s) =>
          barRow(s, sevCounts[s], maxSev, s, `${sevCounts[s]} ${s} finding(s)`)).join('')
          || '<div class="field-help">No findings in range.</div>'}
      </section>

      <section class="dash-card">
        <h3>Most frequent weaknesses</h3>
        ${topCwe.map(([cwe, n]) => barRow(cwe, n, maxCwe, 'neutral', `${cwe}: ${n} finding(s)`)).join('')
          || '<div class="field-help">No CWE data in range.</div>'}
      </section>

      <section class="dash-card dash-wide">
        <h3>Targets</h3>
        <div class="table-wrap">
          <table class="data-table dash-table">
            <thead><tr><th>Target</th><th>Runs</th><th>Findings</th><th>Last tested</th></tr></thead>
            <tbody>
              ${targetRows.map(([k, v]) => `<tr data-target="${esc(k)}">
                <td class="mono">${esc(k)}</td>
                <td>${v.runs}</td>
                <td>${v.findings}</td>
                <td>${esc(timeAgo(v.last))}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <div class="dash-foot">Score = 100 / (1 + risk / ${SCORE_SCALE}) where risk = Σ(severity weight × confidence) = ${riskLoad(findings).toFixed(1)}. Weights: critical ${SCORE_WEIGHT.critical}, high ${SCORE_WEIGHT.high}, medium ${SCORE_WEIGHT.medium}, low ${SCORE_WEIGHT.low}, info ${SCORE_WEIGHT.info}. A heuristic for tracking direction over time, not a certification.</div>
  `;

  $('#btnFairParams').addEventListener('click', () => openFairParams(params));
  $$('#dashBody tbody tr[data-target]').forEach((tr) => tr.addEventListener('click', () => {
    state.runFilter = tr.dataset.target;
    $('#runFilter').value = tr.dataset.target;
    renderSidebar();
  }));
}

/// The assumptions panel. FAIR without visible inputs is a magic number; with
/// them it is a model the reader can disagree with concretely.
function openFairParams(params) {
  const p = structuredClone(params);
  const body = $('#dashBody');
  const host = document.createElement('div');
  host.className = 'modal-overlay';
  host.innerHTML = `
    <div class="modal modal-sm">
      <div class="modal-head"><div class="title">FAIR assumptions</div><button class="icon-btn" data-close>✕</button></div>
      <div class="modal-body">
        <div class="field-help">Threat event frequency — attempted events per year, by exploitability.</div>
        <div class="fair-params">
          ${Object.keys(p.tef).map((k) => `
            <label class="fair-param"><span>${esc(k)}</span>
              <input type="number" min="0" max="365" step="0.5" data-tef="${esc(k)}" value="${p.tef[k]}" /></label>`).join('')}
        </div>
        <div class="field-help" style="margin-top:var(--sp-4);">Loss magnitude per event (USD): minimum / most likely / maximum.</div>
        <div class="fair-params fair-lm">
          ${Object.keys(p.lm).map((k) => `
            <label class="fair-param"><span class="sev ${sevClass(k)}">${esc(k)}</span>
              <input type="number" min="0" step="1000" data-lm="${esc(k)}" data-i="0" value="${p.lm[k][0]}" />
              <input type="number" min="0" step="1000" data-lm="${esc(k)}" data-i="1" value="${p.lm[k][1]}" />
              <input type="number" min="0" step="1000" data-lm="${esc(k)}" data-i="2" value="${p.lm[k][2]}" />
            </label>`).join('')}
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn" data-reset>Reset to defaults</button>
        <button class="btn btn-primary" data-save>Apply</button>
      </div>
    </div>`;
  document.body.appendChild(host);
  const close = () => host.remove();
  host.addEventListener('click', (e) => { if (e.target === host) close(); });
  host.querySelector('[data-close]').addEventListener('click', close);
  host.querySelector('[data-reset]').addEventListener('click', () => {
    saveFairParams(structuredClone(FAIR_DEFAULTS));
    close();
    renderDashboard();
  });
  host.querySelector('[data-save]').addEventListener('click', () => {
    host.querySelectorAll('[data-tef]').forEach((i) => { p.tef[i.dataset.tef] = Number(i.value) || 0; });
    host.querySelectorAll('[data-lm]').forEach((i) => { p.lm[i.dataset.lm][Number(i.dataset.i)] = Number(i.value) || 0; });
    // A max below the minimum would silently invert the range.
    for (const k of Object.keys(p.lm)) p.lm[k].sort((a, b) => a - b);
    saveFairParams(p);
    close();
    renderDashboard();
  });
  body.scrollTop = body.scrollTop; // keep the page anchored while the modal opens
}

function showDashboard() {
  leaveLiveJob();
  clearInterval(state.detailPoll);
  show($('#wizardView'), false);
  show($('#liveView'), false);
  show($('#detailView'), false);
  show($('#dashView'), true);
  renderDashboard();
}
$('#btnDashboard').addEventListener('click', showDashboard);
$('#btnDashRefresh').addEventListener('click', renderDashboard);
$('#dashRange').addEventListener('change', renderDashboard);
$('#runFilter').addEventListener('input', (e) => { state.runFilter = e.target.value; renderSidebar(); });

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

// Below 900px the sidebar slides off-canvas. It previously had no way back:
// the CSS hid it and nothing could set .open.
const NARROW = '(max-width: 900px)';
function setSidebar(open) {
  $('#sidebar').classList.toggle('open', open);
  show($('#sidebarScrim'), open && window.matchMedia(NARROW).matches);
  $('#btnSidebarToggle').setAttribute('aria-expanded', String(open));
}
$('#btnSidebarToggle').addEventListener('click', () => setSidebar(!$('#sidebar').classList.contains('open')));
$('#sidebarScrim').addEventListener('click', () => setSidebar(false));
// Picking a run is the drawer's whole purpose — it should get out of the way
// once you have.
$('#sbGroups').addEventListener('click', (e) => {
  if (e.target.closest('.sb-run') && window.matchMedia(NARROW).matches) setSidebar(false);
});
$('#btnDashboard').addEventListener('click', () => { if (window.matchMedia(NARROW).matches) setSidebar(false); });
$('#btnNewEngagement').addEventListener('click', () => { if (window.matchMedia(NARROW).matches) setSidebar(false); });
// Growing the window past the breakpoint leaves a scrim over a sidebar that is
// no longer a drawer.
window.matchMedia(NARROW).addEventListener('change', (m) => { if (!m.matches) setSidebar(false); });

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
