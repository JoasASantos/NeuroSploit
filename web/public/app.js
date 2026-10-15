'use strict';
/* NeuroSploit v4.2.1 — web console frontend. Vanilla JS, no build step. */

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
  catFilter: '',
  search: '',
  expandedCats: new Set(),
  providers: [],
  auth: { header: '', roles: [] },
  credsPath: '',
  // Engagement authorization: the grant, plus settings that may only narrow it.
  authz: { capability: '', inScope: '', environment: 'production', policyProfile: 'web', transport: '', oobDomain: '', oobHttp: '', oobDns: '', sms: '' },
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
  populateCatFilter();
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
        ${String(a.id).startsWith('custom_') ? `<button class="agent-remove" data-remove="${esc(a.id)}" title="Remove this custom lead">✕</button>` : ''}
      `;
      rows.appendChild(row);
    }
    rows.querySelectorAll('.agent-remove').forEach((btn) => btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const a = group.agents.find((x) => x.id === btn.dataset.remove);
      removeCustomAgent(btn.dataset.remove, a?.title);
    }));
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
  const cat = state.catFilter || '';
  const narrowing = !!q || state.filter !== 'all' || !!cat;
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
    if (cat && card.dataset.category !== cat) { card.style.display = 'none'; return; }
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

// One place to pick a category: the select lists every category (with its
// selected/total count); choosing one shows just that card, "All" resets.
function populateCatFilter() {
  const sel = $('#catFilter');
  if (!sel) return;
  const cur = state.catFilter || '';
  sel.innerHTML = '<option value="">All categories</option>' + state.categories.map((g) => {
    const n = g.agents.filter((a) => state.selected.has(a.id)).length;
    return `<option value="${esc(g.category)}">${esc(g.category)} (${n}/${g.agents.length})</option>`;
  }).join('');
  sel.value = cur;
}
$('#catFilter')?.addEventListener('change', (e) => { state.catFilter = e.target.value; applyFilters(); });

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
function setLeadMode(mode) {
  state.leadMode = mode;
  $$('#leadModeTabs .seg-tab').forEach((t) => t.classList.toggle('active', t.dataset.leadmode === mode));
  $$('[data-leadpanel]').forEach((p) => show(p, p.dataset.leadpanel === mode));
  $('#btnLeadGenerate').textContent = mode === 'own' ? 'Add lead' : 'Generate lead';
}
function openLeadModal() {
  $('#leadDesc').value = '';
  $('#leadName') && ($('#leadName').value = '');
  $('#leadOwn') && ($('#leadOwn').value = '');
  fieldError('#errLead', '');
  setLeadMode('describe');
  show($('#leadModal'), true);
  $('#leadDesc').focus();
}
function closeLeadModal() { show($('#leadModal'), false); }
$('#btnCustomLead').addEventListener('click', openLeadModal);
$('#btnCloseLead').addEventListener('click', closeLeadModal);
$('#btnLeadCancel').addEventListener('click', closeLeadModal);
$('#leadModal').addEventListener('click', (e) => { if (e.target.id === 'leadModal') closeLeadModal(); });
$$('#leadModeTabs .seg-tab').forEach((t) => t.addEventListener('click', () => setLeadMode(t.dataset.leadmode)));
$('#leadDesc').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) $('#btnLeadGenerate').click();
});
$('#btnLeadGenerate').addEventListener('click', async () => {
  const mode = state.leadMode || 'describe';
  const btn = $('#btnLeadGenerate');
  const original = btn.textContent;
  // Mode B — the operator's own agent / system prompt, used verbatim.
  if (mode === 'own') {
    const md = $('#leadOwn').value.trim();
    const title = $('#leadName').value.trim();
    if (!md) { fieldError('#errLead', 'Paste your agent markdown or system prompt.'); return; }
    btn.disabled = true; btn.textContent = 'Adding…';
    try {
      const { agent } = await api('/api/leads/custom', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title, markdown: md }),
      });
      await loadAgents();
      if (agent) state.selected.add(agent.id);
      renderBoard();
      closeLeadModal();
      toast(`Added and pinned: ${agent?.title || title || 'custom lead'}`, 'ok');
    } catch (e) {
      fieldError('#errLead', e.message);
    } finally {
      btn.disabled = false; btn.textContent = original;
    }
    return;
  }
  // Mode A — Claude writes the agent from a description.
  const text = $('#leadDesc').value.trim();
  if (!text) { fieldError('#errLead', 'Describe what the lead should test.'); return; }
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

// Delete a custom lead (the operator's own custom_* agent file) from the board.
async function removeCustomAgent(id, title) {
  if (!confirm(`Remove custom lead “${title || id}”? This deletes its agent file.`)) return;
  try {
    await api(`/api/leads/${encodeURIComponent(id)}`, { method: 'DELETE' });
    state.selected.delete(id);
    await loadAgents();
    renderBoard();
    toast('Custom lead removed', 'ok');
  } catch (e) {
    toast(`Could not remove: ${e.message}`, 'error');
  }
}
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

/// What the budget controls add up to, in the operator's words. "unlimited"
/// is spelled out rather than left blank, because the absence of a cap is the
/// thing worth confirming before launching.
function budgetSummary() {
  const mode = $('#fieldBudget').value;
  const limit = Number($('#fieldTokenLimit').value) || 0;
  if (mode === 'unlimited' && !limit) return 'unlimited — full run, no cap';
  const parts = [mode, $('#fieldOrder').value];
  if (limit) parts.push(`${limit.toLocaleString()} tokens max`);
  parts.push(`${$('#fieldSampleRoute').value}/route`);
  return parts.join(' · ');
}

/// Gather the Scoping/Guardrails form into the object the server turns into a
/// scope YAML. A hard list is what makes it a boundary; without one the server
/// sends nothing and the run keeps its target+flags behaviour.
function collectScope() {
  const lines = (id) => ($(`#${id}`)?.value || '').split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
  const hard = lines('scopeHard');
  const scope = {
    hard,
    exclude: lines('scopeExclude'),
    observeOnly: lines('scopeObserve'),
    allowDestructive: $('#scopeDestructive')?.checked || false,
    allowAccountCreation: $('#scopeAccounts') ? $('#scopeAccounts').checked : true,
    maxAccounts: $('#scopeMaxAccounts')?.value ?? '',
    rateLimit: $('#scopeRate')?.value ?? '',
    forbidden: lines('scopeForbidden'),
    notes: lines('scopeNotes'),
  };
  // Only meaningful when a boundary was actually drawn.
  return hard.length ? scope : undefined;
}

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
    { k: 'Budget', v: budgetSummary() },
    { k: 'Egress', v: state.authz.transport || 'direct' },
    { k: 'Out-of-band', v: state.authz.oobDomain ? `*.${state.authz.oobDomain}` : 'none — blind classes stay leads' },
    { k: 'Hard scope', v: (() => { const sc = collectScope(); return sc ? `${sc.hard.length} rule(s), ${sc.exclude.length} excluded, ${sc.rateLimit || '∞'}rpm${sc.allowDestructive ? ', destructive ON' : ''}` : 'target + authorized hosts only'; })() },
    { k: 'Intercept', v: $('#fieldIntercept').value === 'off' ? 'direct' : $('#fieldIntercept').value },
    { k: 'Sandbox', v: $('#fieldSandbox').value ? 'Kali container' : 'host' },
    { k: 'PoC re-validation', v: $('#fieldRevalidatePoc').checked ? 'on' : 'off' },
    { k: 'TypeSafe', v: $('#fieldTypesafe') ? $('#fieldTypesafe').value : 'auto' },
    { k: 'Compliance', v: (['fieldCompPci', 'fieldCompHipaa', 'fieldCompSoc2', 'fieldCompGdpr'].map((id) => $(`#${id}`).checked && $(`#${id}`).value).filter(Boolean).join(', ')) || 'none' },
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
    quick: $('#fieldQuick') ? $('#fieldQuick').checked : false,
    research: $('#fieldResearch') ? $('#fieldResearch').checked : false,
    subscription: state.authMode === 'subscription',
    mcp: $('#fieldMcp').checked,
    agents: [...state.selected],
    focus: focusParts.join('; ') || undefined,
    objective: $('#fieldObjective').value.trim() || undefined,
    classes: $('#fieldClasses') ? ($('#fieldClasses').value.trim() || undefined) : undefined,
    outOfScope: $('#fieldOutOfScope').value.trim() || undefined,
    // Budget is opt-in: 'unlimited' sends nothing, so a run nobody budgeted is
    // the same full run it was before this control existed.
    budget: $('#fieldBudget').value,
    intercept: $('#fieldIntercept').value,
    sandbox: $('#fieldSandbox').value || undefined,
    revalidatePoc: $('#fieldRevalidatePoc').checked,
    typesafe: $('#fieldTypesafe') ? $('#fieldTypesafe').value : undefined,
    compliance: ['fieldCompPci', 'fieldCompHipaa', 'fieldCompSoc2', 'fieldCompGdpr'].map((id) => $(`#${id}`).checked && $(`#${id}`).value).filter(Boolean),
    tokenLimit: Number($('#fieldTokenLimit').value) || undefined,
    order: $('#fieldOrder').value,
    samplePerRoute: Number($('#fieldSampleRoute').value) || undefined,
    auth: state.auth.header || undefined,
    roles: state.auth.roles.length ? state.auth.roles : undefined,
    creds: state.credsPath || undefined,
    capability: state.authz.capability || undefined,
    inScope: state.authz.inScope.split(/[,;\s]+/).filter(Boolean),
    environment: state.authz.environment,
    policyProfile: state.authz.policyProfile,
    transport: state.authz.transport || undefined,
    oobDomain: state.authz.oobDomain || undefined,
    oobHttp: state.authz.oobHttp || undefined,
    oobDns: state.authz.oobDns || undefined,
    sms: state.authz.sms || undefined,
    scope: collectScope(),
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
    agentStatus: {},
  };
  localStorage.setItem(ACTIVE_JOB_KEY, id);
  if ($('#agentGrid')) $('#agentGrid').innerHTML = '';
  if ($('#agentPanel')) $('#agentPanel').hidden = true;

  show($('#wizardView'), false);
  show($('#detailView'), false);
  show($('#dashView'), false);
  show($('#liveView'), true);
  $('#liveTarget').textContent = name || target || '—';
  $('#liveTargetSub').textContent = name ? target : '';
  $('#livePhase').textContent = 'starting';
  $('#phaseDot').style.background = '';
  $('#phaseDot').classList.remove('static');
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
  es.addEventListener('agent', (e) => { const a = JSON.parse(e.data); if (state.currentJob) { (state.currentJob.agentStatus ||= {})[a.name] = { status: a.status, found: a.found || 0 }; renderAgentPanel(state.currentJob.agentStatus); } });
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

// What the wire said about a finding's evidence (see the harness's wire pass):
// the harness re-sent the agent's requests itself and/or matched them against
// recorded traffic. A contradiction means the finding cannot stand as proven.
function wireState(f) {
  const ev = f.evidence_data;
  if (!ev) return { key: 'none', rank: 3, label: 'no evidence', title: 'No structured evidence was recorded — nothing to check on the wire.' };
  const w = ev.wire;
  const fromWire = (x) => x && String(x.provenance || '').startsWith('wire:');
  if (w && (w.contradicted || []).length) {
    return { key: 'contradicted', rank: 0, label: 'contradicted', title: w.contradicted.join('\n') };
  }
  const backed = w ? (w.reproduced || 0) + (w.corroborated || 0) + (w.harness_observed || 0) : 0;
  if (backed > 0 || fromWire(ev.attack)) {
    const parts = w ? [`${w.reproduced || 0} re-observed by the harness`, `${w.corroborated || 0} matched recorded traffic`, `${w.harness_observed || 0} harness-made`] : ['harness-observed'];
    return { key: 'verified', rank: 1, label: 'wire-verified', title: parts.join(' · ') };
  }
  if (w) return { key: 'unverified', rank: 2, label: 'unverifiable', title: `${w.unverified || 0} exchange(s) could not be re-observed (mutating verb, scope, missing credentials or network).${(w.absent_from_capture || []).length ? `\nAbsent from the capture: ${w.absent_from_capture.join(', ')}` : ''}` };
  return { key: 'pending', rank: 2, label: 'pending', title: 'Not checked yet — the wire pass runs before final validation.' };
}

function reviewStatus(f) {
  return f.review_status || (f.validated ? 'confirmed' : 'candidate');
}

function findingRow(f, idx) {
  const w = wireState(f);
  const st = reviewStatus(f);
  const reg = state.detailRegression?.status?.[f.id];
  const regBadge = reg === 'recurring' ? '<span class="reg-badge reg-recurring" title="Also present in the previous run of this target">recurring</span>'
    : reg === 'new' ? '<span class="reg-badge reg-new" title="Not in the previous run of this target">new</span>' : '';
  return `<tr data-idx="${idx}">
    <td><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></td>
    <td>${esc(f.title)}${regBadge}</td>
    <td class="col-endpoint" title="${esc(f.endpoint)}">${esc(f.endpoint)}</td>
    <td class="col-cwe">${esc(f.cwe)}</td>
    <td><span class="status-badge st-${esc(st)}">${esc(st)}</span></td>
    <td><span class="wire-badge wire-${w.key}" title="${esc(w.title)}">${esc(w.label)}</span></td>
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
  detail: { tbody: '#detailFindingsTable tbody', table: '#detailFindingsTable', empty: '#detailFindingsEmpty', count: '#detailFindingsCount', summary: '#detailSevSummary', search: '#detailFindingSearch', kpis: '#detailKpis' },
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
    else if (key === 'wire') cmp = wireState(a.f).rank - wireState(b.f).rank;
    else if (key === 'review_status') cmp = reviewStatus(a.f).localeCompare(reviewStatus(b.f));
    else cmp = String(a.f[key] || '').localeCompare(String(b.f[key] || ''));
    return cmp * t.dir;
  });

  t.visible = rows.map(({ f }) => f);
  $(cfg.tbody).innerHTML = rows.map(({ f, idx }) => findingRow(f, idx)).join('');
  if (cfg.kpis) renderKpis(cfg.kpis, all);
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
}

// Live "what's being tested" grid: one chip per agent, coloured by status.
function renderAgentPanel(statusMap) {
  const grid = $('#agentGrid');
  const panel = $('#agentPanel');
  if (!grid || !panel) return;
  const entries = Object.entries(statusMap || {});
  if (!entries.length) { panel.hidden = true; return; }
  panel.hidden = false;
  // Order: running first, then found, then pending, then done, then failed.
  const rank = (s, found) => s === 'running' ? 0 : (s === 'done' && found > 0) ? 1 : s === 'pending' ? 2 : s === 'done' ? 3 : 4;
  entries.sort((a, b) => rank(a[1].status, a[1].found) - rank(b[1].status, b[1].found) || a[0].localeCompare(b[0]));
  const cls = (s, found) => s === 'running' ? 'running' : s === 'failed' ? 'failed' : (s === 'done' && found > 0) ? 'found' : s === 'done' ? 'done' : 'pending';
  grid.innerHTML = entries.map(([name, st]) =>
    `<span class="agent-chip ap-${cls(st.status, st.found)}" title="${esc(name)} — ${esc(st.status)}${st.found ? ` · ${st.found} finding(s)` : ''}">${st.status === 'running' ? '<i class="spin"></i>' : ''}${esc(name)}${st.found ? `<b>${st.found}</b>` : ''}</span>`).join('');
  const done = entries.filter(([, s]) => s.status === 'done' || s.status === 'failed').length;
  const run = entries.filter(([, s]) => s.status === 'running').length;
  $('#agentPanel .agent-panel-head > span').textContent = `What's being tested — ${run} running · ${done}/${entries.length} done`;
}

function applySnapshot(snap) {
  if (snap.agentStatus) {
    if (state.currentJob) state.currentJob.agentStatus = snap.agentStatus;
    renderAgentPanel(snap.agentStatus);
  }
  $('#livePhase').textContent = snap.phase;
  state.currentJob.runId = snap.runId;
  state.currentJob.interactive = !!snap.interactive;
  show($('#sendPromptRow'), snap.interactive && !snap.done);
  show($('#sendPromptHelp'), snap.interactive && !snap.done);
  if (snap.pinnedAgents?.length && !state.currentJob.pinnedAgents.length) {
    state.currentJob.pinnedAgents = snap.pinnedAgents;
    updatePinnedLine();
  }
  if (state.currentJob) state.currentJob.phase = snap.phase;
  $('#progressLabel').textContent = `${snap.agentsDone} / ${snap.agents || '?'} agents`;
  $('#progressBar').classList.toggle('indeterminate', !snap.agents);
  if (snap.agents) $('#progressFill').style.width = `${Math.min(100, (snap.agentsDone / snap.agents) * 100)}%`;
  if (snap.reportUrl && snap.runId) {
    $('#btnOpenReport').href = `/api/runs/${snap.runId}/asset/report.html`;
    show($('#btnOpenReport'), true);
  }
  const paused = (snap.phase || '').startsWith('paused');
  $('#btnPauseRun').textContent = paused ? '▶ Continue' : '⏸ Pause';
  $('#btnPauseRun').classList.toggle('btn-warn', paused);
  $('#btnPauseRun').disabled = !!snap.done || !snap.interactive;
  $('#btnReportNow').disabled = !snap.interactive;
  $('#btnDownloadLog').href = `/api/exploit/${snap.id}/log`;
  if (snap.done) $('#phaseDot').classList.add('static');
}

$('#btnStopRun').addEventListener('click', async () => {
  if (!state.currentJob) return;
  await api(`/api/exploit/${state.currentJob.id}/stop`, { method: 'POST' });
});

// Pause is a toggle against the run's own phase, so the button always says
// what pressing it will do rather than what the run currently is.
$('#btnPauseRun').addEventListener('click', async () => {
  if (!state.currentJob) return;
  const paused = (state.currentJob.phase || '').startsWith('paused');
  const verb = paused ? 'continue' : 'pause';
  try {
    await api(`/api/exploit/${state.currentJob.id}/${verb}`, { method: 'POST' });
    toast(paused ? 'Resuming the run.' : 'Pausing — in-flight agents finish first, findings are kept.', 'ok');
  } catch (e) {
    toast(e.message, 'error', 8000);
  }
});

// Report from where it stopped: the REPL's /report writes from the evidence on
// disk, so a run that is paused, stalled or simply long can be read now.
$('#btnReportNow').addEventListener('click', async () => {
  if (!state.currentJob) return;
  try {
    await api(`/api/exploit/${state.currentJob.id}/report`, { method: 'POST' });
    toast('Building a report from what has been found so far — it appears above when written.', 'ok', 7000);
  } catch (e) {
    toast(e.message, 'error', 8000);
  }
});
function leaveLiveJob() {
  localStorage.removeItem(ACTIVE_JOB_KEY);
  clearInterval(state.currentJob?.pocPoll);
  state.currentJob?.es?.close();
  state.currentJob = null;
  termSyncTargets();
}
$('#btnBackToBoard').addEventListener('click', () => { leaveLiveJob(); show($('#liveView'), false); show($('#dashView'), false); show($('#wizardView'), true); });
// Regenerating from the evidence already on disk, rather than re-running the
// engagement: a run whose PDF was never produced (no `typst` at the time, or a
// since-improved template) would otherwise be unreportable.
$('#btnBuildReport').addEventListener('click', async () => {
  const id = state.currentDetailId;
  if (!id) return;
  const btn = $('#btnBuildReport');
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Generating…';
  try {
    const r = await api(`/api/runs/${encodeURIComponent(id)}/report`, { method: 'POST' });
    toast(r.pdf ? 'Report rebuilt — PDF ready.' : (r.note || 'Report rebuilt.'), r.pdf ? 'ok' : 'warn', 7000);
    await loadDetail(id);
  } catch (e) {
    toast(`Couldn't generate the report: ${e.message}`, 'error', 9000);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

$('#btnDeleteRun').addEventListener('click', async () => {
  const id = state.currentDetailId;
  if (!id) return;
  const label = $('#detailTarget').textContent || id;
  if (!confirm(`Delete this session permanently?\n\n${label}\n${id}\n\nThis removes the findings, evidence, PoCs and every report artifact for this run. It cannot be undone.`)) return;
  const btn = $('#btnDeleteRun');
  btn.disabled = true;
  try {
    await api(`/api/runs/${encodeURIComponent(id)}`, { method: 'DELETE' });
    toast('Session deleted.', 'ok', 5000);
    clearInterval(state.detailPoll);
    state.currentDetailId = null;
    state.detailLoadedId = null;
    show($('#detailView'), false); show($('#dashView'), false); show($('#wizardView'), true);
    await refreshRuns();
  } catch (e) {
    toast(`Couldn't delete the session: ${e.message}`, 'error', 9000);
  } finally {
    btn.disabled = false;
  }
});

$('#btnDetailBack').addEventListener('click', () => { clearInterval(state.detailPoll); show($('#detailView'), false); show($('#dashView'), false); show($('#wizardView'), true); });
$('#btnNewEngagement').addEventListener('click', () => { leaveLiveJob(); clearInterval(state.detailPoll); show($('#detailView'), false); show($('#liveView'), false); show($('#dashView'), false); show($('#wizardView'), true); });

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
  // Wire evidence — the real request/response pairs behind the finding, plus
  // its re-test history. Loaded on demand; the section hides itself when the
  // finding carries no replayable exchange and has never been re-tested.
  state.fmFinding = { f, runId };
  loadWireEvidence(f, runId);

  show($('#findingModal'), true);
}
$('#btnCloseFinding').addEventListener('click', () => show($('#findingModal'), false));
$('#findingModal').addEventListener('click', (e) => { if (e.target.id === 'findingModal') show($('#findingModal'), false); });

// ---- wire evidence + per-finding re-test -----------------------------------

const PROV_LABEL = {
  'wire:replay': 'wire · harness replay', 'wire:recorded': 'wire · interceptor',
  'wire:harness': 'wire · harness', '': 'agent-reported',
};
const REPRO_CLASS = { reproduced: 'ok', changed: 'warn', gone: 'bad', unverifiable: 'muted' };

async function loadWireEvidence(f, runId) {
  const summary = $('#fmWireSummary');
  const exRoot = $('#fmWireExchanges');
  summary.innerHTML = '';
  exRoot.innerHTML = '<div class="field-help">loading…</div>';
  let data = {};
  try { data = await api(`/api/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}/traffic`); } catch { data = {}; }
  // A later modal may have opened while this was in flight.
  if (state.fmFinding?.f?.id !== f.id) return;

  const w = data.wire;
  if (w) {
    const chips = [];
    if (w.reproduced) chips.push(`<span class="wire-chip ok">${w.reproduced} reproduced by replay</span>`);
    if (w.corroborated) chips.push(`<span class="wire-chip ok">${w.corroborated} corroborated on wire</span>`);
    if (w.harness_observed) chips.push(`<span class="wire-chip ok">${w.harness_observed} harness-observed</span>`);
    if (w.unverified) chips.push(`<span class="wire-chip muted">${w.unverified} unverifiable</span>`);
    (w.contradicted || []).forEach((c) => chips.push(`<span class="wire-chip bad" title="${esc(c)}">contradicted</span>`));
    (w.absent_from_capture || []).length && chips.push(`<span class="wire-chip warn">${w.absent_from_capture.length} not seen by interceptor</span>`);
    summary.innerHTML = `<div class="wire-chips">${chips.join('')}</div>` +
      ((w.contradicted || []).length ? `<ul class="wire-contra">${w.contradicted.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>` : '');
  }

  const ex = data.exchanges || [];
  const flows = data.flows || [];
  exRoot.innerHTML =
    (ex.length ? ex.map(exchangeCard).join('') : '') +
    (flows.length ? `<div class="wire-sub">Recorded flows on this endpoint (${flows.length})</div>` + flows.map(flowRow).join('') : '') +
    (!ex.length && !flows.length ? '<div class="field-help">No replayable exchange recorded for this finding. Re-test sends its proof again if one exists.</div>' : '');

  loadRetestHistory(f.id, runId);
}

function exchangeCard(ex) {
  const prov = PROV_LABEL[ex.provenance] ?? ex.provenance ?? 'agent-reported';
  const wireCls = String(ex.provenance || '').startsWith('wire:') ? 'ok' : 'muted';
  const st = ex.status >= 500 ? 'tf-5' : ex.status >= 400 ? 'tf-4' : ex.status >= 300 ? 'tf-3' : ex.status >= 200 ? 'tf-2' : 'tf-0';
  const reqH = Object.entries(ex.request_headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  const resH = Object.entries(ex.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  const body = (ex.body || '').slice(0, 4000);
  return `<details class="wire-ex">
    <summary>
      <span class="wire-role">${esc(ex.role || '')}</span>
      <span class="method">${esc(ex.method || 'GET')}</span>
      <span class="wire-url" title="${esc(ex.url)}">${esc(ex.url || '')}</span>
      <span class="tf ${st}">${ex.status || '—'}</span>
      ${ex.identity ? `<span class="wire-id">as ${esc(ex.identity)}</span>` : ''}
      <span class="wire-prov ${wireCls}">${esc(prov)}</span>
    </summary>
    <div class="wire-ex-body">
      ${reqH ? `<div class="wire-h"><b>Request headers</b><pre class="poc-pre">${esc(reqH)}</pre></div>` : ''}
      ${resH ? `<div class="wire-h"><b>Response headers</b><pre class="poc-pre">${esc(resH)}</pre></div>` : ''}
      ${body ? `<div class="wire-h"><b>Response body${ex.body.length > 4000 ? ' (first 4 KB)' : ''}</b><pre class="poc-pre">${esc(body)}</pre></div>` : ''}
    </div>
  </details>`;
}

function flowRow(r) {
  const st = r.status >= 500 ? 'tf-5' : r.status >= 400 ? 'tf-4' : r.status >= 300 ? 'tf-3' : r.status >= 200 ? 'tf-2' : 'tf-0';
  return `<div class="wire-flow"><span class="method">${esc(r.method || '')}</span>
    <span class="wire-url" title="${esc(r.url)}">${esc(r.url || '')}</span>
    <span class="tf ${st}">${r.tunnelled ? 'TLS' : r.status || '—'}</span></div>`;
}

async function loadRetestHistory(fid, runId) {
  const root = $('#fmRetestHistory');
  let h = [];
  try { h = (await api(`/api/runs/${encodeURIComponent(runId)}/retests/${encodeURIComponent(fid)}`)).history || []; } catch { h = []; }
  if (state.fmFinding?.f?.id !== fid) return;
  renderRetestHistory(h);
}

function renderRetestHistory(h) {
  const root = $('#fmRetestHistory');
  if (!h.length) { root.innerHTML = ''; return; }
  root.innerHTML = `<div class="retest-hist"><div class="wire-sub">Re-test history</div>${h.slice().reverse().map((e) => {
    const cls = REPRO_CLASS[e.reproduction] || 'muted';
    return `<div class="retest-row"><span class="wire-chip ${cls}">${esc(e.reproduction || 'error')}</span>
      <span class="retest-when">${e.at ? new Date(e.at * 1000).toLocaleString() : ''}</span>
      <span class="retest-detail" title="${esc(e.detail || e.raw || '')}">${esc(e.detail || e.raw || '')}</span></div>`;
  }).join('')}</div>`;
}

$('#btnFindingRetest').addEventListener('click', async (e) => {
  const cur = state.fmFinding;
  if (!cur?.f || !cur.runId) return;
  const btn = e.currentTarget;
  btn.disabled = true; const label = btn.textContent; btn.textContent = '⟳ re-testing…';
  try {
    const r = await api(`/api/runs/${encodeURIComponent(cur.runId)}/retest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ finding: cur.f.id }) });
    if (state.fmFinding?.f?.id === cur.f.id) renderRetestHistory(r.history || []);
    toast(`Re-test: ${r.result?.reproduction || 'done'}`, (REPRO_CLASS[r.result?.reproduction] === 'bad' ? 'error' : 'ok'));
  } catch (err) {
    toast(`Re-test failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
});

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
  // A hover ✕ so the operator can clear test runs without opening each one.
  const row = document.createElement('div');
  row.className = 'sb-run-row';
  const del = document.createElement('button');
  del.className = 'sb-run-del';
  del.textContent = '✕';
  del.title = 'Delete this session';
  del.setAttribute('aria-label', 'Delete this session');
  del.addEventListener('click', async (e) => {
    e.stopPropagation();
    if (!confirm(`Delete this session permanently?\n\n${r.name || r.target}\n${r.id}\n\nRemoves findings, evidence, PoCs and reports. Cannot be undone.`)) return;
    try {
      await api(`/api/runs/${encodeURIComponent(r.id)}`, { method: 'DELETE' });
      if (state.currentDetailId === r.id) {
        clearInterval(state.detailPoll);
        state.currentDetailId = null; state.detailLoadedId = null;
        show($('#detailView'), false); show($('#wizardView'), true);
      }
      toast('Session deleted.', 'ok', 4000);
      await refreshRuns();
    } catch (err) {
      toast(`Couldn't delete: ${err.message}`, 'error', 8000);
    }
  });
  row.appendChild(btn);
  row.appendChild(del);
  return row;
}

function renderSidebar() {
  const root = $('#sbGroups');
  root.innerHTML = '';
  const q = (state.runFilter || '').trim().toLowerCase();
  const match = (r) => !q || `${r.name} ${r.target} ${r.id}`.toLowerCase().includes(q);
  const runs = state.runs.filter(match);
  const running = runs.filter((r) => r.state === 'running');
  const interrupted = runs.filter((r) => r.state === 'interrupted');
  const past = runs.filter((r) => r.state !== 'running' && r.state !== 'interrupted');

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

  if (interrupted.length) {
    const wrap = document.createElement('div');
    wrap.className = 'sb-group';
    wrap.innerHTML = `<div class="sb-group-head"><span class="caret">▾</span><span>Interrupted</span><span class="count">${interrupted.length}</span></div><div class="sb-items"></div>`;
    wrap.querySelector('.sb-group-head').addEventListener('click', () => wrap.classList.toggle('collapsed'));
    const items = wrap.querySelector('.sb-items');
    for (const r of interrupted) items.appendChild(runButton(r));
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

// Resume an interrupted run from the sidebar: if a persisted job exists for it,
// relaunch it live; otherwise just open its detail (partial findings on disk).
async function resumeFromSidebar(run) {
  let jobs = [];
  try { jobs = await api('/api/exploit'); } catch { /* fall through to detail */ }
  const job = jobs.find((j) => (j.interrupted && j.resumable) && (j.runId === run.id || j.id === run.id || j.id === run.jobId));
  if (job) {
    try {
      await api(`/api/exploit/${job.id}/resume`, { method: 'POST' });
      localStorage.setItem(ACTIVE_JOB_KEY, job.id);
      attachLiveJob(job.id, run.target, run.name, job.pinnedAgents || []);
      await refreshRuns();
      return;
    } catch (e) {
      toast(`Couldn't resume: ${e.message}`, 'error', 8000);
    }
  }
  // No resumable job — show what's on disk.
  show($('#wizardView'), false); show($('#liveView'), false); show($('#dashView'), false); show($('#detailView'), true);
  loadDetail(run.id);
  renderSidebar();
}

// Map a sidebar run (keyed by run-id) to the live harness job that owns it.
// The server keys jobs by UUID and records each job's runId once the CLI prints
// it, so match on that. Returns the job UUID, or null when no live job exists.
async function resolveJobId(run) {
  if (run.jobId) return run.jobId;
  try {
    const jobs = await api('/api/exploit');
    const live = jobs.find((j) => !j.done && (j.runId === run.id || j.id === run.id));
    if (live) return live.id;
    const any = jobs.find((j) => j.runId === run.id || j.id === run.id);
    return any ? any.id : null;
  } catch { return null; }
}

function openRun(run) {
  state.currentDetailId = run.id;
  if (run.state === 'running' && state.currentJob && run.id === state.currentJob.runId) {
    show($('#wizardView'), false); show($('#detailView'), false); show($('#dashView'), false); show($('#liveView'), true);
    renderSidebar();
    return;
  }
  // A running job we're not already attached to (e.g. opened in another tab, or
  // just started): reconnect its live stream instead of showing a static detail.
  // The sidebar run is keyed by its run-id (ns-…), but the live job is keyed by
  // its own UUID — so resolve the run-id to the owning job before attaching,
  // otherwise /api/exploit/<run-id> 404s and the activity log stays empty.
  if (run.state === 'running') {
    resolveJobId(run).then((jid) => {
      if (!jid) { // no live job (server restarted): fall back to static detail
        show($('#wizardView'), false); show($('#liveView'), false); show($('#dashView'), false); show($('#detailView'), true);
        loadDetail(run.id); renderSidebar(); return;
      }
      localStorage.setItem(ACTIVE_JOB_KEY, jid);
      attachLiveJob(jid, run.target, run.name, []);
      renderSidebar();
    });
    return;
  }
  if (run.state === 'interrupted') {
    // Offer to resume where it left off; falls back to the static detail view.
    resumeFromSidebar(run);
    return;
  }
  show($('#wizardView'), false); show($('#liveView'), false); show($('#dashView'), false); show($('#detailView'), true);
  loadDetail(run.id);
  renderSidebar();
}

async function loadRegression(id, token) {
  const box = $('#detailRegression');
  let r = null;
  try { r = await api(`/api/runs/${encodeURIComponent(id)}/regression`); } catch { r = null; }
  if (token !== state.detailToken) return;
  if (!r || !r.prev) { state.detailRegression = null; show(box, false); return; }
  state.detailRegression = r;
  renderFindings('detail'); // repaint so the new/recurring badges show
  // Count over the findings actually shown, so the banner matches the table
  // even when a run's findings.json reuses an id.
  const cur = state.detailFindings || [];
  const recurring = cur.filter((f) => r.status?.[f.id] === 'recurring').length;
  const fresh = cur.filter((f) => r.status?.[f.id] === 'new').length;
  const fixed = r.fixed || [];
  const when = r.prev.when ? timeAgo(Math.floor(new Date(r.prev.when).getTime() / 1000)) : '';
  box.innerHTML = `<div class="reg-banner">
    <span class="reg-h">vs previous run</span>
    <span class="muted">${esc(when)}</span>
    <span class="reg-chip reg-new">${fresh} new</span>
    <span class="reg-chip reg-recurring">${recurring} recurring</span>
    <span class="reg-chip reg-fixed">${fixed.length} fixed</span>
    ${fixed.length ? `<details class="reg-fixed-list"><summary>fixed since</summary><ul>${fixed.map((x) => `<li><span class="sev ${sevClass(x.severity)}">${esc(x.severity)}</span> ${esc(x.title)}</li>`).join('')}</ul></details>` : ''}
  </div>`;
  show(box, true);
}

async function loadDetail(id) {
  clearInterval(state.detailPoll);
  // A poll for the previously opened run may still be in flight; when it
  // lands it must not repaint that run over the one the operator opened.
  const token = (state.detailToken = (state.detailToken || 0) + 1);
  if (state.detailLoadedId !== id) {
    // A filter left over from the previous run would silently hide findings
    // in the one just opened.
    state.tables.detail.sev = null;
    state.tables.detail.query = '';
    $('#detailFindingSearch').value = '';
    state.detailLoadedId = id;
  }
  const detail = await api(`/api/runs/${encodeURIComponent(id)}`);
  if (token !== state.detailToken) return;
  const target = detail.status?.target || detail.meta?.target || id;
  $('#detailTarget').textContent = detail.name || target;
  $('#detailTargetSub').textContent = detail.name ? target : '';
  $('#detailState').textContent = detail.status?.state || 'unknown';
  state.detailFindings = detail.findings;
  state.detailPocs = detail.pocs || [];
  // Regression vs the previous run of this target — new / recurring badges and a
  // "fixed since" banner. Best-effort: it never blocks the findings table.
  state.detailRegression = null;
  renderFindings('detail');
  loadRegression(id, token);
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
  const reportLink = $('#detailOpenReport');
  if (detail.assets.includes('report.html')) {
    reportLink.href = `/api/runs/${encodeURIComponent(id)}/asset/report.html`;
    show(reportLink, true);
  } else show(reportLink, false);
  // The PDF is produced by the harness (Typst) when that binary is present, so
  // it is offered only when it actually exists — a dead download button is
  // worse than none.
  // The audit trail travels with the run's evidence; offering it here is what
  // makes "show me what the tool did" a link rather than a support request.
  const auditLink = $('#detailOpenAudit');
  if (detail.assets.includes('audit.jsonl')) {
    auditLink.href = `/api/runs/${encodeURIComponent(id)}/asset/audit.jsonl`;
    show(auditLink, true);
  } else show(auditLink, false);
  const pdfLink = $('#detailOpenPdf');
  if (detail.assets.includes('report.pdf')) {
    pdfLink.href = `/api/runs/${encodeURIComponent(id)}/asset/report.pdf`;
    pdfLink.setAttribute('download', `${id}.pdf`);
    show(pdfLink, true);
  } else show(pdfLink, false);
  afterDetailLoaded(id, detail);
  if (token !== state.detailToken) return;
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

$('#capToken').addEventListener('input', (e) => {
  state.authz.capability = e.target.value.trim();
  // Decode the claims for display only. This is NOT verification — the
  // signature is checked by the harness, which holds the key; showing a
  // "valid" badge here would be the browser vouching for something it cannot
  // check.
  const el = $('#capStatus');
  const t = state.authz.capability;
  if (!t) { el.textContent = ''; el.className = 'field-status'; return; }
  try {
    const body = t.replace(/^ns-cap\.v1\./, '').split('.')[0];
    const claims = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    const left = claims.expires_at ? Math.round((claims.expires_at - Date.now() / 1000) / 3600) : null;
    el.className = 'field-status ' + (left !== null && left <= 0 ? 'bad' : 'ok');
    el.textContent = `claims (unverified here — the harness checks the signature): ${claims.issuer} → ${claims.subject} · ${(claims.scope || []).join(', ')} · ${claims.environment} · max ${claims.max_action}` +
      (left === null ? '' : left <= 0 ? ' · EXPIRED' : ` · ${left}h left`);
  } catch {
    el.className = 'field-status bad';
    el.textContent = 'not a readable ns-cap.v1 token';
  }
});
$('#inScope').addEventListener('input', (e) => { state.authz.inScope = e.target.value; });
$('#envSelect').addEventListener('change', (e) => { state.authz.environment = e.target.value; });
$('#policySelect').addEventListener('change', (e) => { state.authz.policyProfile = e.target.value; });
// Egress and OOB live with authorization, not with run settings: they decide
// WHICH network is being tested, which is an authorization question.
for (const [id, key] of [['transportSpec', 'transport'], ['oobDomain', 'oobDomain'], ['oobHttp', 'oobHttp'], ['oobDns', 'oobDns'], ['smsSpec', 'sms']]) {
  $(`#${id}`).addEventListener('input', (e) => { state.authz[key] = e.target.value.trim(); });
}

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
        <span class="key-verify" data-verify="${esc(p.key)}"></span>
      </div>
    `;
  }).join('');
  const doSave = async (btn) => {
    const provider = btn.dataset.save;
    const input = root.querySelector(`input[data-provider="${provider}"]`);
    const vtag = root.querySelector(`[data-verify="${provider}"]`);
    const key = input.value.trim();
    if (!key) return;
    btn.disabled = true; const label = btn.textContent; btn.textContent = 'Saving…';
    if (vtag) { vtag.className = 'key-verify checking'; vtag.textContent = '· verifying…'; }
    try {
      // Save verifies the key server-side with a cheap authenticated call.
      const r = await api('/api/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider, key }) });
      input.value = '';
      const v = r.verify || { ok: null, message: 'saved' };
      if (vtag) {
        vtag.className = `key-verify ${v.ok === true ? 'ok' : v.ok === false ? 'bad' : 'unknown'}`;
        vtag.textContent = v.ok === true ? '✓ valid' : v.ok === false ? '✗ ' + v.message : '• ' + v.message;
      }
      toast(v.ok === true ? `${provider}: key valid` : v.ok === false ? `${provider}: ${v.message}` : `${provider}: ${v.message}`, v.ok === false ? 'error' : 'ok');
      // Refresh the set-dots but keep the verify tag we just set.
      state.keys = await api('/api/keys').catch(() => state.keys);
      const dot = root.querySelector(`[data-save="${provider}"]`)?.closest('.provider-row')?.querySelector('.dot');
      if (dot) dot.classList.add('set');
    } catch (e) {
      if (vtag) { vtag.className = 'key-verify bad'; vtag.textContent = '✗ ' + e.message; }
    } finally {
      btn.disabled = false; btn.textContent = label;
    }
  };
  $$('[data-save]', root).forEach((btn) => btn.addEventListener('click', () => doSave(btn)));
  $$('input[data-provider]', root).forEach((inp) => inp.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') root.querySelector(`[data-save="${inp.dataset.provider}"]`)?.click();
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
            <button class="contrib-row contrib-click" data-run="${esc(f.runId || '')}" data-title="${esc(f.title || '')}" data-cwe="${esc(f.cwe || '')}" title="Open this finding — ${esc(f.title)} (${esc(f.target)})">
              <span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span>
              <span class="contrib-title">${esc(f.title || f.cwe || 'untitled')}</span>
              <span class="contrib-v">${money(ml)}</span>
            </button>`).join('') || '<div class="field-help">No findings in range.</div>'}
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
  // A top contributor is a specific finding in a specific run — clicking it
  // opens that run and pops the finding's full detail (evidence/impact/PoC),
  // so "what is this loss" is one click, not a hunt through run history.
  $$('#dashBody .contrib-click').forEach((row) => row.addEventListener('click', () =>
    openContributorFinding(row.dataset.run, row.dataset.title, row.dataset.cwe)));
}

/// Open the run a dashboard contributor belongs to and surface that exact
/// finding. The dashboard row carries only (runId, title, cwe) — the full
/// finding lives in the run detail — so we load the run, then match by title
/// (falling back to CWE) and open its modal.
async function openContributorFinding(runId, title, cwe) {
  if (!runId) return;
  const run = (state.runs || []).find((r) => r.id === runId) || { id: runId, state: 'complete' };
  // Switch to the run's detail view (this also refreshes the tables), and in
  // parallel fetch the detail directly so we match the finding without racing
  // loadDetail's own async fill of state.detailFindings.
  openRun(run);
  let detail;
  try { detail = await api(`/api/runs/${encodeURIComponent(runId)}`); }
  catch { return; }
  const fs = detail.findings || [];
  const norm = (s) => String(s || '').trim().toLowerCase();
  let f = fs.find((x) => norm(x.title) === norm(title));
  if (!f && cwe) f = fs.find((x) => norm(x.cwe) === norm(cwe));
  if (f) {
    openFindingModal(f, detail.pocs || [], runId);
  } else {
    toast('Opened the run — this finding was recalibrated or merged, so its row may differ.', 'warn', 6000);
  }
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
  await offerInterruptedJobs(); // a run the server lost on restart/crash
  setInterval(refreshRuns, 6000);
}
boot();

// A job that was live when the server stopped is reloaded from disk as
// `interrupted`. When it is resumable (a REPL-backed run/whitebox/greybox, the
// ones the harness checkpoints), offer a one-click resume: the server relaunches
// the REPL, which auto-recovers the on-disk checkpoint and /continue's it.
async function offerInterruptedJobs() {
  let jobs;
  try { jobs = await api('/api/exploit'); } catch { return; }
  const resumable = (jobs || []).filter((j) => j.interrupted && j.resumable);
  if (!resumable.length) return;
  const bar = document.createElement('div');
  bar.className = 'resume-bar';
  bar.innerHTML = `
    <span class="resume-ico">↻</span>
    <span class="resume-text">${resumable.length} interrupted run(s) — the server restarted mid-engagement. Findings are saved; resume to continue where it left off.</span>
    <span class="resume-actions"></span>
    <button class="resume-x" title="Dismiss">✕</button>`;
  const actions = bar.querySelector('.resume-actions');
  for (const j of resumable) {
    const b = document.createElement('button');
    b.className = 'btn btn-sm btn-primary';
    b.textContent = `Resume ${j.name || j.target || j.id.slice(0, 8)}`;
    b.addEventListener('click', async () => {
      b.disabled = true; b.textContent = 'Resuming…';
      try {
        await api(`/api/exploit/${j.id}/resume`, { method: 'POST' });
        localStorage.setItem(ACTIVE_JOB_KEY, j.id);
        attachLiveJob(j.id, j.target, j.name, j.pinnedAgents || []);
        bar.remove();
      } catch (e) {
        b.disabled = false; b.textContent = 'Retry';
        toast(`Couldn't resume: ${e.message}`, 'error', 9000);
      }
    });
    actions.appendChild(b);
  }
  bar.querySelector('.resume-x').addEventListener('click', () => bar.remove());
  document.body.insertBefore(bar, document.body.firstChild);
}

// ---------------------------------------------------------------------------
// Run detail — attack graph, dependencies, traffic, traces, deliverables.
//
// Every tab reads files the CLI wrote into the run directory, and every action
// (recompute the graph, push to Neo4j, re-test the PoCs) shells out to the CLI
// through the server — the console never re-implements harness logic.
// ---------------------------------------------------------------------------

function renderKpis(sel, all) {
  const el = $(sel);
  if (!el) return;
  const by = (fn) => all.filter(fn).length;
  const sev = (s) => by((f) => SEV_ORDER[sevRank(f.severity)] === s);
  const cards = [
    { k: 'Findings', v: all.length, sub: `${sev('critical')} critical · ${sev('high')} high · ${sev('medium')} medium · ${sev('low')} low` },
    { k: 'Confirmed', v: by((f) => reviewStatus(f) === 'confirmed'), sub: `${by((f) => reviewStatus(f) === 'needs-review')} need review`, cls: 'kpi-ok' },
    { k: 'Wire-verified', v: by((f) => wireState(f).key === 'verified'), sub: 'evidence re-observed on the wire', cls: 'kpi-ok' },
    { k: 'Contradicted', v: by((f) => wireState(f).key === 'contradicted'), sub: 'the wire disagreed with the agent', cls: 'kpi-bad' },
  ];
  el.innerHTML = cards.map((c) => `<div class="kpi ${c.cls || ''}"><div class="kpi-k">${esc(c.k)}</div><div class="kpi-v">${c.v}</div><div class="kpi-sub">${esc(c.sub)}</div></div>`).join('');
}

function exportCsv() {
  const rows = state.tables.detail.visible || state.detailFindings || [];
  const cols = ['severity', 'title', 'endpoint', 'cwe', 'status', 'wire', 'agent', 'confidence', 'cvss'];
  const cell = (v) => `"${String(v ?? '').replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`;
  const lines = [cols.join(',')].concat(rows.map((f) => [f.severity, f.title, f.endpoint, f.cwe, reviewStatus(f), wireState(f).label, f.agent, f.confidence, f.cvss].map(cell).join(',')));
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${state.detailLoadedId || 'findings'}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
$('#btnExportCsv')?.addEventListener('click', exportCsv);

function showOutput(title, text) {
  const host = document.createElement('div');
  host.className = 'modal-overlay';
  host.innerHTML = `<div class="modal modal-lg out-modal" role="dialog" aria-label="${esc(title)}">
    <header class="modal-head"><span class="title">${esc(title)}</span><button class="btn btn-sm" data-close>Close</button></header>
    <pre class="out-pre">${esc(text || '(no output)')}</pre></div>`;
  document.body.appendChild(host);
  const close = () => host.remove();
  host.addEventListener('click', (e) => { if (e.target === host || e.target.hasAttribute('data-close')) close(); });
}

// ---- the extras component ---------------------------------------------------
//
// Attack graph · Chains · Dependencies · Traffic · Traces · Deliverables, mounted into
// both the past-run detail view and the live view. Each mount owns its state
// and queries only inside its own root, so the two never collide.

const EXTRAS_TABS = [
  ['graph', 'Attack graph'], ['chains', 'Chains'], ['todo', 'Dependencies'],
  ['traffic', 'Traffic'], ['traces', 'Traces'], ['deliverables', 'Deliverables'],
];
const STATUS_LABEL = { confirmed: 'confirmed', needs_validation: 'needs validation', hypothesis: 'hypothesis', needs_review: 'needs review' };

function extrasPanelsHtml(uid) {
  return `
  <div class="run-tab-panel" data-tabpanel="chains" hidden>
    <div class="panel-toolbar"><div class="chip-row" data-x="chain-filters"></div><div class="topbar-spacer"></div>
      <span class="muted">Chain severity rises above the findings only when every step is evidenced.</span></div>
    <div data-x="moves"></div><div class="chain-list" data-x="chains"></div>
    <div class="empty-state" data-x="chains-empty" hidden>No multi-step path to an impact yet. Findings keep their local severity.</div>
  </div>
  <div class="run-tab-panel" data-tabpanel="todo" hidden>
    <p class="panel-help">Each open chain, step by step in dependency order. <b>ready</b> steps are what the chaining rounds dispatch next; <b>blocked</b> steps wait for the fact an earlier step yields; steps turn <b>done</b> when the graph holds evidence for them.</p>
    <div data-x="todo"></div><div class="empty-state" data-x="todo-empty" hidden>Nothing pending — every chain is confirmed, or there is no multi-step path yet.</div>
  </div>
  <div class="run-tab-panel" data-tabpanel="graph" hidden>
    <div class="panel-toolbar"><div class="chip-row" data-x="legend"></div><div class="topbar-spacer"></div>
      <label class="toggle"><input type="checkbox" data-x="full" /> full graph</label></div>
    <div class="gm-wrap" data-x="wrap"><div class="gm-stage" data-x="stage"></div>
      <div class="gm-zoom"><button class="btn btn-sm" data-z="in">+</button><button class="btn btn-sm" data-z="out">−</button><button class="btn btn-sm" data-z="fit">⤢</button></div></div>
    <div class="gm-detail" data-x="node" hidden></div>
    <div class="empty-state" data-x="graph-empty" hidden>No attack graph yet — it is written at every graph checkpoint of a run, or press ↻ Graph on a finished run.</div>
  </div>
  <div class="run-tab-panel" data-tabpanel="traffic" hidden>
    <div class="panel-toolbar">
      <input type="text" placeholder="host…" class="input-sm" data-x="t-host" list="${uid}-hosts" /><datalist id="${uid}-hosts" data-x="t-hosts"></datalist>
      <div class="search-wrap"><span class="search-icon" aria-hidden="true">⌕</span><input type="text" placeholder="Search URL / method / status / type" data-x="t-q" /></div>
      <select class="input-sm" data-x="t-method"><option value="">all methods</option><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>CONNECT</option></select>
      <div class="topbar-spacer"></div><span class="muted" data-x="t-count"></span></div>
    <div class="table-wrap"><table class="data-table"><thead><tr><th>Time</th><th>Host</th><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th class="col-conf">Size</th></tr></thead><tbody data-x="t-body"></tbody></table></div>
    <div class="empty-state" data-x="t-empty" hidden>No recorded traffic. The recording interceptor runs with <code>--intercept own</code>; findings are still wire-checked by the harness's own replay.</div>
  </div>
  <div class="run-tab-panel" data-tabpanel="traces" hidden>
    <div class="panel-toolbar"><div class="search-wrap"><span class="search-icon" aria-hidden="true">⌕</span><input type="text" placeholder="Search every agent's trace (error, parameter, version…)" data-x="tr-q" /></div>
      <div class="topbar-spacer"></div><span class="muted" data-x="tr-note"></span></div>
    <div class="trace-layout"><ul class="trace-files" data-x="tr-files"></ul><div class="trace-hits" data-x="tr-hits"></div></div>
    <div class="empty-state" data-x="tr-empty" hidden>No agent traces yet.</div>
  </div>
  <div class="run-tab-panel" data-tabpanel="deliverables" hidden>
    <div class="deliv-grid" data-x="deliv"></div><div class="empty-state" data-x="deliv-empty" hidden>No deliverables yet — they are written with the report.</div>
  </div>`;
}

function makeExtras(viewSel, uid, getRunId) {
  const root = $(viewSel);
  const nav = $('.run-tabs', root);
  const body = $('.run-body', root);
  if (!root || !nav || !body) return null;
  for (const [tab, label] of EXTRAS_TABS) {
    const b = document.createElement('button');
    b.className = 'run-tab';
    b.dataset.tab = tab;
    // Only tabs with a meaningful number carry a counter.
    b.innerHTML = ['chains', 'todo', 'traces', 'deliverables'].includes(tab) ? `${esc(label)} <span data-count="${tab}">0</span>` : esc(label);
    nav.appendChild(b);
  }
  body.insertAdjacentHTML('beforeend', extrasPanelsHtml(uid));
  const x = {
    root, getRunId, graphData: null, extras: {}, chainFilter: 'all',
    view: { k: 1, tx: 20, ty: 20, sel: null }, timers: {},
    q: (k) => $(`[data-x="${k}"]`, root),
    count: (tab, n) => { const el = $(`[data-count="${tab}"]`, root); if (el) el.textContent = n; },
    active: () => $('.run-tab.active', root)?.dataset.tab || 'findings',
  };
  // Our tabs switch panels like the built-in ones (whose handlers already
  // hide every .run-tab-panel in this view, ours included).
  $$('.run-tab', nav).forEach((t) => {
    if (!EXTRAS_TABS.some(([k]) => k === t.dataset.tab)) return;
    t.addEventListener('click', () => {
      $$('.run-tab', root).forEach((o) => o.classList.remove('active'));
      t.classList.add('active');
      $$('.run-tab-panel', root).forEach((p) => show(p, p.dataset.tabpanel === t.dataset.tab));
      extrasLoad(x, t.dataset.tab);
    });
  });
  // Inputs.
  const debounce = (k, fn) => () => { clearTimeout(x.timers[k]); x.timers[k] = setTimeout(fn, 250); };
  x.q('t-host').addEventListener('input', debounce('t', () => extrasTraffic(x)));
  x.q('t-q').addEventListener('input', debounce('t', () => extrasTraffic(x)));
  x.q('t-method').addEventListener('change', () => extrasTraffic(x));
  x.q('tr-q').addEventListener('input', debounce('tr', () => extrasTraces(x)));
  x.q('full').addEventListener('change', () => renderGraphMemory(x));
  bindGraphInteractions(x);
  return x;
}

async function extrasGraph(x, force) {
  const id = x.getRunId();
  if (!id) return {};
  if (!force && x.graphData && x.graphData.id === id) return x.graphData;
  const g = await api(`/api/runs/${encodeURIComponent(id)}/graph`);
  if (id !== x.getRunId()) return x.graphData || {};
  x.graphData = { id, ...g };
  return x.graphData;
}

function extrasCounts(x) {
  const g = x.graphData || {};
  x.count('chains', (g.chains?.chains || []).length);
  x.count('todo', (g.todo || []).filter((t) => t.state === 'ready').length);
  x.count('traces', x.extras.traces || 0);
  x.count('deliverables', (x.extras.deliverables || []).length);
}

// Refresh after the run's metadata changed (detail load, or a live tick).
async function extrasRefresh(x, extras, force) {
  if (!x) return;
  const id = x.getRunId();
  if (x.lastId !== id) { x.lastId = id; x.graphData = null; x.view = { k: 1, tx: 20, ty: 20, sel: null }; }
  x.extras = extras || {};
  try { await extrasGraph(x, force); } catch { /* no graph yet */ }
  extrasCounts(x);
  const tab = x.active();
  if (EXTRAS_TABS.some(([k]) => k === tab)) extrasLoad(x, tab, true);
}

async function extrasLoad(x, tab, quiet) {
  try {
    if (tab === 'chains') renderChains(x, await extrasGraph(x));
    else if (tab === 'todo') renderTodo(x, await extrasGraph(x));
    else if (tab === 'graph') {
      const g = (await extrasGraph(x))?.graph;
      const sig = g ? `${(g.nodes || []).length}:${(g.edges || []).length}` : '';
      // Redraw only when the graph changed, so a live refresh keeps the
      // operator's zoom, pan and selection.
      if (!quiet || sig !== x.drawnSig) { x.drawnSig = sig; renderGraphMemory(x); }
    }
    else if (tab === 'traffic') await extrasTraffic(x);
    else if (tab === 'traces') await extrasTraces(x);
    else if (tab === 'deliverables') renderDeliverables(x);
  } catch (e) {
    if (!quiet) toast(`Could not load ${tab}: ${e.message}`, 'error');
  }
}

// ---- chains ----------------------------------------------------------------

function renderChains(x, g) {
  const all = g?.chains?.chains || [];
  const moves = g?.chains?.next_moves || [];
  const counts = { all: all.length };
  for (const c of all) counts[c.status] = (counts[c.status] || 0) + 1;
  x.q('chain-filters').innerHTML = ['all', 'confirmed', 'needs_validation', 'hypothesis']
    .map((k) => `<button class="chip${x.chainFilter === k ? ' chip-active' : ''}" data-cf="${k}">${esc(k === 'all' ? 'all' : STATUS_LABEL[k])} <span>${counts[k] || 0}</span></button>`).join('');
  $$('[data-cf]', x.q('chain-filters')).forEach((b) => b.addEventListener('click', () => { x.chainFilter = b.dataset.cf; renderChains(x, g); }));
  const mv = (m) => `<li title="${esc(m)}">${esc(m)}</li>`;
  x.q('moves').innerHTML = moves.length ? `<div class="moves"><div class="moves-h">Next moves · ${moves.length}</div>
    <ul>${moves.slice(0, 3).map(mv).join('')}</ul>
    ${moves.length > 3 ? `<details><summary>show all ${moves.length}</summary><ul>${moves.slice(3).map(mv).join('')}</ul></details>` : ''}</div>` : '';
  const list = all.filter((c) => x.chainFilter === 'all' || c.status === x.chainFilter);
  show(x.q('chains-empty'), all.length === 0);
  x.q('chains').innerHTML = list.map((c, i) => `
    <details class="chain-card st-${esc(c.status)}"${i < 3 ? ' open' : ''}>
      <summary>
        <span class="chain-status st-${esc(c.status)}">${esc(STATUS_LABEL[c.status] || c.status)}</span>
        <span class="sev ${sevClass(c.chain_severity)}">${esc(c.chain_severity)}</span>
        ${c.potential_severity ? `<span class="chain-pot" title="Severity once every step is validated">→ ${esc(c.potential_severity)} once validated</span>` : ''}
        <span class="chain-title">${esc(c.title)}</span>
        <span class="chain-meta">conf ${Number(c.confidence || 0).toFixed(2)} · blast ${c.blast_radius} · ${esc(c.exploitability)}</span>
      </summary>
      <div class="chain-body">
        <div class="chain-impact"><b>Impact:</b> ${chainText(c.impact)}</div>
        <ol class="chain-steps">${(c.step_text || []).map((s, j) => `<li class="step st-${esc(c.steps?.[j]?.status || '')}">${chainText(s)}</li>`).join('')}</ol>
        ${block('Findings involved', (c.findings || []).map((f) => `${chainText(f.title)} <span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span> <span class="chain-note">${esc(f.status)}</span>`), null, true)}
        ${block('Evidence references', (c.evidence || []).map(chainText), 'none recorded — this chain is unproven', true)}
        ${block('Required assumptions', (c.assumptions || []).map(chainText), 'none — every step is evidenced', true)}
        ${block('Recommended validation', (c.validation || []).map(chainText), 'none needed — confirmed end to end', true)}
        ${block('Recommended remediation', (c.remediation || []).map(chainText), null, true)}
      </div>
    </details>`).join('');
}

// Turn the graph's prose into readable markup: node names (backtick-quoted) become
// trimmed code references, relation tokens (—[ESCALATES_TO]→) become labelled
// chips, and the "(needs_validation, conf 0.80)" tail becomes a muted note.
function chainText(s) {
  let e = esc(String(s || ''));
  // Node references: `…` → <code>, with mid-word ellipsis trimmed to a word edge.
  e = e.replace(/`([^`]*)`/g, (_m, inner) => {
    let t = inner;
    if (t.endsWith('…')) t = t.replace(/\s*\S*…$/, '…');
    return `<code class="chain-ref" title="${inner}">${t}</code>`;
  });
  // Generic node-type words before a reference are noise once it is a code chip.
  e = e.replace(/\b(?:Finding|BusinessImpact|Host|Service|Endpoint|Credential|Identity|AttackStep|Vulnerability)\s+(?=<code)/g, '');
  // Relation tokens, em-dash or ASCII arrow form.
  e = e.replace(/\s*(?:—|-)\[([A-Z_]+)\](?:→|-&gt;|->)\s*/g, ' <span class="chain-rel">$1</span> ');
  // Trailing status/confidence note.
  e = e.replace(/\(([a-z_]+,\s*conf\s*[0-9.]+)\)/g, '<span class="chain-note">$1</span>');
  return e;
}

function block(title, items, emptyText, html) {
  const arr = items || [];
  if (!arr.length && !emptyText) return '';
  const cell = (v) => html ? v : esc(v);
  return `<div class="chain-block"><div class="chain-block-h">${esc(title)}</div><ul>${arr.length ? arr.map((v) => `<li>${cell(v)}</li>`).join('') : `<li class="muted">${esc(emptyText)}</li>`}</ul></div>`;
}

// ---- dependency todolist ---------------------------------------------------

function renderTodo(x, g) {
  const todo = g?.todo || [];
  show(x.q('todo-empty'), todo.length === 0);
  const groups = new Map();
  for (const t of todo) { if (!groups.has(t.chain)) groups.set(t.chain, []); groups.get(t.chain).push(t); }
  x.q('todo').innerHTML = [...groups.entries()].map(([chain, steps]) => {
    const head = steps[0];
    const done = steps.filter((s) => s.state === 'done').length;
    return `<section class="todo-chain">
      <header><span class="todo-title">${esc(chain)}</span>
        <span class="sev ${sevClass(head.chain_severity)}">${esc(head.chain_severity)}</span>
        ${head.potential ? `<span class="chain-pot">→ ${esc(head.potential)} once validated</span>` : ''}
        <span class="todo-progress"><span style="width:${Math.round((done / steps.length) * 100)}%"></span></span>
        <span class="muted">${done}/${steps.length}</span></header>
      <ol class="todo-steps">${steps.map((s) => `
        <li class="todo-step ts-${esc(s.state)}">
          <span class="ts-badge">${s.state === 'done' ? '✓ done' : s.state === 'ready' ? '▶ ready' : `⏸ after step ${s.blocked_by}`}</span>
          <div><div class="ts-step">${esc(s.step)}</div>${s.state !== 'done' ? `<div class="ts-action">${esc(s.action)}</div>` : ''}</div>
        </li>`).join('')}</ol>
    </section>`;
  }).join('');
}

// ---- graph (web + internal network) ----------------------------------------

const GM_COL = {
  Target: 0, Domain: 0, IPAddress: 0, Host: 0,
  Service: 1, Technology: 1, Endpoint: 1,
  Vulnerability: 2, Finding: 2, Evidence: 2, ValidationResult: 2,
  AttackStep: 3, ExploitAttempt: 3, Credential: 3, Secret: 3, Identity: 3,
  Role: 4, Permission: 4, Asset: 4, Control: 4,
  BusinessImpact: 5, Mitigation: 5, AttackPath: 5,
};
const GM_KIND = {
  Target: 'asset', Domain: 'asset', IPAddress: 'asset', Host: 'asset', Asset: 'asset',
  Service: 'surface', Technology: 'surface', Endpoint: 'surface',
  Vulnerability: 'weak', Finding: 'weak',
  AttackStep: 'step', ExploitAttempt: 'step',
  Credential: 'cred', Secret: 'cred', Identity: 'cred', Role: 'cred', Permission: 'cred',
  BusinessImpact: 'impact',
  Evidence: 'meta', ValidationResult: 'meta', Mitigation: 'meta', AttackPath: 'meta', Control: 'meta',
};
// Attack progression (mirrors knowledge_graph::STAGES): within a column,
// findings and attack steps read in the order an attacker meets them.
const KILL_CHAIN_STAGES = [
  'recon', 'discovery', 'initial-access', 'execution', 'persistence',
  'privesc', 'credential-access', 'lateral', 'collection', 'exfil', 'impact',
];
const stageRank = (s) => {
  const i = KILL_CHAIN_STAGES.indexOf(s);
  return i === -1 ? KILL_CHAIN_STAGES.length : i;
};
const GM_HIDDEN = new Set(['Evidence', 'ValidationResult', 'Mitigation', 'AttackPath', 'Domain', 'IPAddress']);
const GM_TRAVERSAL = new Set(['ENABLES', 'YIELDS', 'CAN_ACCESS', 'HAS_PERMISSION', 'ESCALATES_TO', 'PIVOTS_TO', 'IMPACTS']);

function gmName(n) {
  const p = n.props || {};
  return p.title || p.name || p.category || p.path || p.type || p.address || n.key;
}

function renderGraphMemory(x) {
  const data = x.graphData?.graph;
  const stage = x.q('stage');
  const has = !!(data && (data.nodes || []).length);
  show(x.q('graph-empty'), !has);
  show(x.q('wrap'), has);
  x.q('legend').innerHTML = [['asset', 'asset / host'], ['surface', 'service / endpoint'], ['weak', 'vulnerability / finding'], ['step', 'attack step'], ['cred', 'credential / identity'], ['impact', 'impact']]
    .map(([k, l]) => `<span class="gm-leg gk-${k}">${esc(l)}</span>`).join('') +
    '<span class="gm-leg-sep"></span><span class="gm-edge-leg es-confirmed">confirmed</span><span class="gm-edge-leg es-needs_validation">needs validation</span><span class="gm-edge-leg es-hypothesis">hypothesis</span>';
  if (!has) { stage.innerHTML = ''; return; }

  const full = x.q('full').checked;
  const id = (n) => `${n.label}|${n.key}`;
  const eid = (e) => `${e.label}|${e.key}`;
  let nodes = data.nodes.filter((n) => full || !GM_HIDDEN.has(n.label));
  let keep = new Set(nodes.map(id));
  let edges = (data.edges || []).filter((e) => keep.has(eid(e.from)) && keep.has(eid(e.to)));
  if (!full) {
    // Attack view: what an attacker moves through, plus the host each finding
    // was proven on (the vulnerability / service / endpoint hops stay in the
    // full graph).
    const trav = (data.edges || []).filter((e) => GM_TRAVERSAL.has(e.type));
    const outTrav = new Set(trav.map((e) => eid(e.from)));
    const onPath = new Set();
    for (const e of trav) for (const end of [e.from, e.to]) {
      if (end.label === 'AttackStep' && !outTrav.has(eid(end))) continue;
      onPath.add(eid(end));
    }
    const parent = {};
    for (const e of data.edges || []) {
      if (['HAS_FINDING', 'HAS_VULNERABILITY', 'HAS_ENDPOINT', 'EXPOSES'].includes(e.type)) (parent[e.type] = parent[e.type] || new Map()).set(eid(e.to), eid(e.from));
    }
    const hostOf = (fid) => {
      const v = parent.HAS_FINDING?.get(fid); const ep = v && parent.HAS_VULNERABILITY?.get(v);
      const sv = ep && parent.HAS_ENDPOINT?.get(ep); return sv && parent.EXPOSES?.get(sv);
    };
    const virtual = [];
    for (const nid of [...onPath]) {
      if (!nid.startsWith('Finding|')) continue;
      const h = hostOf(nid);
      if (h) { onPath.add(h); virtual.push({ type: 'PROVEN_ON', from: { label: 'Host', key: h.slice(5) }, to: { label: 'Finding', key: nid.slice(8) }, status: 'confirmed', confidence: 1 }); }
    }
    if (onPath.size) {
      nodes = data.nodes.filter((n) => onPath.has(id(n)));
      keep = new Set(nodes.map(id));
      edges = trav.filter((e) => keep.has(eid(e.from)) && keep.has(eid(e.to))).concat(virtual);
    }
  }

  // Columns by entity kind; a long column wraps into sub-columns.
  const W = 220, H = 54, GX = 90, GY = 12, PER = 12;
  const cols = new Map();
  for (const n of nodes) {
    const c = GM_COL[n.label] ?? 3;
    if (!cols.has(c)) cols.set(c, []);
    cols.get(c).push(n);
  }
  const pos = new Map();
  let maxH = 0;
  let col = 0;
  [...cols.keys()].sort((a, b) => a - b).forEach((c) => {
    const list = cols.get(c).sort((a, b) =>
      stageRank(a.props?.stage) - stageRank(b.props?.stage)
      || sevRank(a.props?.local_severity) - sevRank(b.props?.local_severity)
      || (a.label + gmName(a)).localeCompare(b.label + gmName(b)));
    const sub = Math.ceil(list.length / PER);
    list.forEach((n, i) => pos.set(id(n), { x: (col + Math.floor(i / PER)) * (W + GX) - Math.floor(i / PER) * (GX - 24), y: (i % PER) * (H + GY) }));
    maxH = Math.max(maxH, Math.min(list.length, PER) * (H + GY));
    col += sub;
  });
  const width = col * (W + GX);
  const path = (a, b) => {
    const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2;
    if (x2 > x1) { const m = (x1 + x2) / 2; return `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`; }
    const r = Math.max(a.x, b.x) + W + 40;
    return `M${x1},${y1} C${r},${y1} ${r},${y2} ${b.x + W},${y2}`;
  };
  const svg = edges.map((e) => {
    const a = pos.get(eid(e.from)), b = pos.get(eid(e.to));
    if (!a || !b) return '';
    const st = e.status || 'needs_validation';
    return `<path class="gm-e es-${esc(st)}${GM_TRAVERSAL.has(e.type) ? ' gm-trav' : ''}" data-from="${esc(eid(e.from))}" data-to="${esc(eid(e.to))}" d="${path(a, b)}"><title>${esc(e.type)} · ${esc(st)} · conf ${Number(e.confidence || 0).toFixed(2)}</title></path>`;
  }).join('');
  const cards = nodes.map((n) => {
    const p = pos.get(id(n));
    const props = n.props || {};
    const badge = props.status ? `<span class="gm-st st-${esc(props.status)}">${esc(STATUS_LABEL[props.status] || props.status)}</span>` : '';
    const sev = props.local_severity ? `<span class="sev ${sevClass(props.local_severity)}">${esc(props.local_severity)}</span>` : '';
    const crit = props.critical === true || props.privileged === true ? '<span class="gm-crit" title="crown jewel / privileged">★</span>' : '';
    return `<div class="gm-node gk-${GM_KIND[n.label] || 'meta'}" style="left:${p.x}px;top:${p.y}px;width:${W}px;height:${H}px" data-id="${esc(id(n))}">
      <div class="gm-node-h"><span class="gm-lbl">${esc(n.label)}${props.stage ? ` · ${esc(props.stage)}` : ''}</span>${crit}${sev}${badge}</div>
      <div class="gm-node-t" title="${esc(gmName(n))}">${esc(gmName(n))}</div></div>`;
  }).join('');
  stage.innerHTML = `<svg class="gm-svg" width="${width + 80}" height="${maxH + 40}">${svg}</svg>${cards}`;
  stage.style.width = `${width + 80}px`;
  stage.style.height = `${maxH + 40}px`;
  gmApply(x);

  const byId = new Map(nodes.map((n) => [id(n), n]));
  $$('.gm-node', stage).forEach((el) => el.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const nid = el.dataset.id;
    x.view.sel = x.view.sel === nid ? null : nid;
    $$('.gm-node', stage).forEach((o) => o.classList.toggle('sel', o.dataset.id === x.view.sel));
    $$('.gm-e', stage).forEach((p) => p.classList.toggle('hl', !!x.view.sel && (p.dataset.from === x.view.sel || p.dataset.to === x.view.sel)));
    stage.classList.toggle('focusing', !!x.view.sel);
    const n = byId.get(nid);
    const box = x.q('node');
    if (!x.view.sel || !n) { show(box, false); return; }
    const rel = (dir) => edges.filter((e) => eid(dir === 'out' ? e.from : e.to) === nid)
      .map((e) => { const o = dir === 'out' ? e.to : e.from; const on = byId.get(eid(o)); return `${dir === 'out' ? '→' : '←'} ${e.type} ${o.label} “${on ? gmName(on) : o.key}” (${e.status})`; });
    const finding = n.label === 'Finding' ? gmFinding(x, n.props?.finding_id) : null;
    box.innerHTML = `<header><b>${esc(n.label)}</b> ${esc(gmName(n))}${finding ? '<button class="btn btn-sm" data-open>Open finding</button>' : ''}<button class="btn btn-sm" data-close>×</button></header>
      <table class="kv">${Object.entries(n.props || {}).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(Array.isArray(v) ? v.join(', ') : v)}</td></tr>`).join('')}</table>
      ${block('Relationships', rel('out').concat(rel('in')), 'none')}`;
    show(box, true);
    $('[data-close]', box).addEventListener('click', () => show(box, false));
    $('[data-open]', box)?.addEventListener('click', () => openFindingModal(finding.f, finding.pocs, finding.runId));
  }));
}

/// The finding behind a graph node, with what the finding modal needs.
function gmFinding(x, fid) {
  if (fid === undefined || fid === null || fid === '') return null;
  const live = x.root.id === 'liveView';
  const list = live ? (state.currentJob?.findings || []) : (state.detailFindings || []);
  const f = list.find((o) => o.id === fid);
  if (!f) return null;
  return { f, pocs: live ? (state.currentJob?.pocs || []) : (state.detailPocs || []), runId: live ? state.currentJob?.runId : state.currentDetailId };
}

function gmApply(x) {
  const st = x.q('stage');
  if (st) st.style.transform = `translate(${x.view.tx}px,${x.view.ty}px) scale(${x.view.k})`;
}

function bindGraphInteractions(x) {
  const wrap = x.q('wrap');
  let drag = null;
  wrap.addEventListener('wheel', (e) => {
    e.preventDefault();
    const r = wrap.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const k2 = Math.min(2.5, Math.max(0.2, x.view.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
    x.view.tx = mx - ((mx - x.view.tx) * k2) / x.view.k;
    x.view.ty = my - ((my - x.view.ty) * k2) / x.view.k;
    x.view.k = k2;
    gmApply(x);
  }, { passive: false });
  wrap.addEventListener('pointerdown', (e) => { if (e.target.closest('.gm-node, .gm-zoom')) return; drag = { x: e.clientX - x.view.tx, y: e.clientY - x.view.ty }; wrap.classList.add('dragging'); });
  window.addEventListener('pointermove', (e) => { if (!drag) return; x.view.tx = e.clientX - drag.x; x.view.ty = e.clientY - drag.y; gmApply(x); });
  window.addEventListener('pointerup', () => { drag = null; wrap.classList.remove('dragging'); });
  $$('.gm-zoom [data-z]', wrap).forEach((b) => b.addEventListener('click', () => {
    const z = b.dataset.z;
    if (z === 'fit') {
      const st = x.q('stage');
      const sw = parseFloat(st.style.width) || 1, sh = parseFloat(st.style.height) || 1;
      x.view.k = Math.min(1.2, Math.max(0.2, Math.min(wrap.clientWidth / sw, wrap.clientHeight / sh) * 0.95));
      x.view.tx = 10; x.view.ty = 10;
    } else x.view.k = Math.min(2.5, Math.max(0.2, x.view.k * (z === 'in' ? 1.2 : 1 / 1.2)));
    gmApply(x);
  }));
}

// ---- traffic ---------------------------------------------------------------

async function extrasTraffic(x) {
  const id = x.getRunId();
  if (!id) return;
  const q = new URLSearchParams({ host: x.q('t-host').value, method: x.q('t-method').value, q: x.q('t-q').value, limit: '200' });
  const t = await api(`/api/runs/${encodeURIComponent(id)}/traffic?${q}`);
  x.q('t-hosts').innerHTML = (t.hosts || []).map((h) => `<option value="${esc(h)}">`).join('');
  x.q('t-count').textContent = t.total ? `${Math.min(t.total, t.limit)} of ${t.total} flow(s)` : '';
  show(x.q('t-empty'), !t.total && !x.q('t-q').value && !x.q('t-host').value && !x.q('t-method').value);
  const stCls = (s) => (s >= 500 ? 'tf-5' : s >= 400 ? 'tf-4' : s >= 300 ? 'tf-3' : s >= 200 ? 'tf-2' : 'tf-0');
  const size = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n || 0} B`);
  x.q('t-body').innerHTML = (t.rows || []).map((r) => {
    let host = ''; try { host = new URL(r.url).host; } catch { host = String(r.url || '').split('/')[0]; }
    return `<tr><td class="col-cwe">${r.at ? new Date(r.at * 1000).toLocaleTimeString() : '—'}</td><td>${esc(host)}</td>
      <td><span class="method">${esc(r.method)}</span></td><td class="col-endpoint" title="${esc(r.url)}">${esc(r.url)}</td>
      <td><span class="tf ${stCls(r.status)}">${r.tunnelled ? 'TLS' : r.status || '—'}</span></td><td class="col-cwe">${esc(r.content_type || '')}</td><td class="col-conf">${size(r.resp_bytes)}</td></tr>`;
  }).join('');
}

// ---- traces ----------------------------------------------------------------

async function extrasTraces(x) {
  const id = x.getRunId();
  if (!id) return;
  const qv = x.q('tr-q').value.trim();
  const r = await api(`/api/runs/${encodeURIComponent(id)}/traces?q=${encodeURIComponent(qv)}`);
  x.count('traces', (r.traces || []).length);
  show(x.q('tr-empty'), !(r.traces || []).length);
  const base = `/api/runs/${encodeURIComponent(id)}/asset/`;
  x.q('tr-files').innerHTML = (r.traces || []).map((t) =>
    `<li><button class="trace-file-btn${x.trAgent === t.agent ? ' active' : ''}" data-agent="${esc(t.agent)}" data-file="${esc(t.file)}">${esc(t.agent)}</button><span class="muted">${(t.bytes / 1024).toFixed(1)} KB</span></li>`).join('');
  $$('.trace-file-btn', x.q('tr-files')).forEach((b) => b.addEventListener('click', () => showTranscript(x, b.dataset.agent, b.dataset.file)));
  x.q('tr-note').textContent = qv ? `${r.hits.length}${r.hits.length >= 200 ? '+' : ''} hit(s) for “${qv}”` : `${(r.traces || []).length} agent trace(s) — click one to read it, or search across all`;
  const re = qv ? new RegExp(qv.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'ig') : null;
  if (qv) {
    x.trAgent = null;
    x.q('tr-hits').innerHTML = r.hits.length
      ? r.hits.map((h) => `<div class="trace-hit"><button class="trace-file-btn" data-agent="${esc(h.agent)}" data-file="${esc(h.file)}" data-line="${h.line}">${esc(h.agent)}</button><span class="muted">:${h.line}</span><code>${esc(h.snippet).replace(re, (m) => `<mark>${m}</mark>`)}</code></div>`).join('')
      : '<div class="muted">No agent saw that.</div>';
    $$('.trace-file-btn', x.q('tr-hits')).forEach((b) => b.addEventListener('click', () => showTranscript(x, b.dataset.agent, b.dataset.file, qv)));
  } else if (x.trAgent) {
    const cur = (r.traces || []).find((t) => t.agent === x.trAgent);
    if (cur) showTranscript(x, cur.agent, cur.file);
    else x.q('tr-hits').innerHTML = '<div class="muted">Click an agent on the left to read its transcript.</div>';
  } else {
    x.q('tr-hits').innerHTML = '<div class="muted">Click an agent on the left to read its transcript, or type a keyword to search across all of them.</div>';
  }
}

// A transcript is mostly target output and tool noise. Render it readable:
// group by the tool-call / HTTP-request boundaries the harness writes, and let
// each block collapse, so a long run is navigable rather than one wall of text.
const TR_STEP_RE = /^(?:#{1,4}\s|\$\s|>\s|(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+\S|(?:TOOL|STEP|AGENT|ROUND|PHASE)\b|={3,}|-{3,}\s*$)/i;

async function showTranscript(x, agent, file, highlight) {
  x.trAgent = agent;
  $$('.trace-file-btn', x.q('tr-files')).forEach((b) => b.classList.toggle('active', b.dataset.agent === agent));
  const hits = x.q('tr-hits');
  hits.innerHTML = '<div class="field-help">loading…</div>';
  const id = x.getRunId();
  let text = '';
  try { text = await (await fetch(`/api/runs/${encodeURIComponent(id)}/asset/${encodeURI(file)}`)).text(); } catch { hits.innerHTML = '<div class="muted">Could not load trace.</div>'; return; }
  if (x.trAgent !== agent) return;
  text = stripAnsiJs(text);
  const lines = text.split('\n');
  // Split into blocks at each step/request boundary.
  const blocks = [];
  let cur = null;
  for (const line of lines) {
    if (TR_STEP_RE.test(line) || !cur) { cur = { head: line, body: [] }; blocks.push(cur); }
    else cur.body.push(line);
  }
  const re = highlight ? new RegExp(highlight.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'ig') : null;
  const mark = (s) => { const e = esc(s); return re ? e.replace(re, (m) => `<mark>${m}</mark>`) : e; };
  hits.innerHTML = `<div class="transcript">
    <div class="transcript-head"><b>${esc(agent)}</b><span class="muted">${blocks.length} block(s) · ${lines.length} line(s)</span>
      <a class="btn btn-sm" href="/api/runs/${encodeURIComponent(id)}/asset/${encodeURI(file)}" target="_blank">Open raw</a></div>
    ${blocks.map((b) => {
      const body = b.body.join('\n').replace(/\s+$/, '');
      const open = re && (re.test(b.head) || re.test(body));
      re && (re.lastIndex = 0);
      return `<details class="transcript-block"${open ? ' open' : ''}>
        <summary>${mark(b.head.slice(0, 200)) || '<span class="muted">(blank)</span>'}</summary>
        ${body ? `<pre class="poc-pre">${mark(body)}</pre>` : ''}
      </details>`;
    }).join('')}
  </div>`;
}

/// Strip ANSI escapes client-side (traces are served raw).
function stripAnsiJs(s) { return String(s || '').replace(/\u001b\[[0-9;]*m/g, ''); }

// ---- deliverables ----------------------------------------------------------

const DELIV_INFO = {
  'differential-proof.md': ['Differential proof', 'Is it real? Attack vs negative control, computed diff, repeat distribution.'],
  'evidence-custody.md': ['Chain of custody', 'Observed vs derived vs inferred, hash-chained.'],
  'evidence-custody.json': ['Chain of custody (JSON)', 'Machine-readable custody chain.'],
  'Makefile': ['Regression tests', '`make verify-<id>` — fails while open, passes once fixed.'],
  'README.md': ['Deliverables index', 'What each artifact answers.'],
  'persona-dev.md': ['For developers', 'One ticket per finding: where, how to prove it, the fix.'],
  'persona-appsec.md': ['For AppSec', 'Verdicts, CVSS, differential proof, chains.'],
  'persona-executive.md': ['Executive summary', 'Impact in business terms.'],
  'detection/modsecurity.conf': ['ModSecurity rules', 'WAF rules derived from the exploits.'],
  'detection/siem-queries.md': ['SIEM queries', 'Splunk / Elastic queries to check the SOC saw it.'],
};

function renderDeliverables(x) {
  const id = x.getRunId();
  const files = x.extras.deliverables || [];
  show(x.q('deliv-empty'), files.length === 0);
  const base = `/api/runs/${encodeURIComponent(id)}/asset/`;
  const rel = (f) => f.replace(/^deliverables\//, '');
  const groups = [['tests/', 'Exploit-as-test (pytest)'], ['nuclei/', 'Nuclei templates'], ['detection/', 'Sigma rules']];
  x.q('deliv').innerHTML = files.filter((f) => DELIV_INFO[rel(f)]).map((f) => {
    const [t, d] = DELIV_INFO[rel(f)];
    return `<a class="deliv-card" href="${base}${encodeURI(f)}" target="_blank"><b>${esc(t)}</b><span>${esc(d)}</span><code>${esc(f)}</code></a>`;
  }).join('') + groups.map(([dir, title]) => {
    const list = files.filter((f) => f.startsWith(`deliverables/${dir}`) && !DELIV_INFO[rel(f)]);
    return list.length ? `<div class="deliv-card deliv-group"><b>${esc(title)}</b><span>${list.length} file(s)</span><ul>${list.slice(0, 40).map((f) => `<li><a href="${base}${encodeURI(f)}" target="_blank">${esc(f.split('/').pop())}</a></li>`).join('')}</ul></div>` : '';
  }).join('');
}

// ---- mounts ----------------------------------------------------------------

const detailExtras = makeExtras('#detailView', 'dx', () => state.detailLoadedId);
const liveExtras = makeExtras('#liveView', 'lx', () => state.currentJob?.runId);

// Detail view: called by loadDetail after every (re)load.
function afterDetailLoaded(id, detail) {
  extrasRefresh(detailExtras, detail.extras || {});
}

// Live view: the run directory fills in as the harness works (graph
// checkpoints, traces, recorded traffic). Re-read it every few seconds while a
// job is open, from the same files the CLI writes.
setInterval(async () => {
  const id = state.currentJob?.runId;
  if (!id || !liveExtras || $('#liveView').hidden) return;
  try {
    const d = await api(`/api/runs/${encodeURIComponent(id)}`);
    await extrasRefresh(liveExtras, d.extras || {}, true);
  } catch { /* run dir not there yet */ }
}, 5000);

// ---- actions through the CLI -----------------------------------------------

async function cliAction(btn, label, url, body, after) {
  const id = state.detailLoadedId;
  if (!id) return;
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = `${label}…`;
  try {
    const r = await api(`/api/runs/${encodeURIComponent(id)}${url}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    if (after) await after(r);
    if (r.output) showOutput(label, r.output);
    else toast(`${label}: done`, 'ok');
  } catch (e) {
    showOutput(`${label} failed`, e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
}

const adoptGraph = (r) => {
  detailExtras.graphData = { id: state.detailLoadedId, chains: r.chains, todo: r.todo, graph: r.graph };
  detailExtras.drawnSig = null;
  extrasCounts(detailExtras);
  const tab = detailExtras.active();
  if (EXTRAS_TABS.some(([k]) => k === tab)) extrasLoad(detailExtras, tab);
};
$('#btnGraphRecompute')?.addEventListener('click', (e) => cliAction(e.currentTarget, 'Recompute graph', '/graph', {}, adoptGraph));
$('#btnGraphPush')?.addEventListener('click', (e) => cliAction(e.currentTarget, 'Push to Neo4j', '/graph', { push: true }, adoptGraph));
$('#btnRetest')?.addEventListener('click', (e) => cliAction(e.currentTarget, 'Re-test PoCs', '/retest', {}));
