'use strict';
/* NeuroSploit v4.0.0 — web console frontend. Vanilla JS, no build step. */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  categories: [],        // from /api/agents
  selected: new Set(),   // agent ids toggled on
  customLeads: [],       // free-text custom leads (folded into --focus)
  filter: 'all',         // all | selected | excluded
  search: '',
  runs: [],               // from /api/runs
  currentJob: null,       // {id, es} for the live view
  currentDetailId: null,  // run id shown in detail view
  detailPoll: null,
  askFocus: '', askObjective: '', askOutOfScope: '',
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
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return res.headers.get('content-type')?.includes('json') ? res.json() : res.text();
}
function sevClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s.includes('crit')) return 'sev-critical';
  if (s.includes('high')) return 'sev-high';
  if (s.includes('med')) return 'sev-medium';
  if (s.includes('low')) return 'sev-low';
  return 'sev-info';
}
function show(el, on) { el.hidden = !on; }

// ---------------------------------------------------------------------------
// agents / lead board
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
    card.dataset.category = group.category;
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
      for (const a of group.agents) {
        if (on) state.selected.add(a.id); else state.selected.delete(a.id);
      }
      renderBoard();
      updateChips();
    });
    rows.querySelectorAll('.agent-toggle').forEach((input) => {
      input.addEventListener('change', (e) => {
        const id = e.target.dataset.id;
        if (e.target.checked) state.selected.add(id); else state.selected.delete(id);
        renderBoard();
        updateChips();
        applyFilters();
      });
    });
    root.appendChild(card);
  }
  updateChips();
  applyFilters();
}

function allAgents() {
  return state.categories.flatMap((g) => g.agents);
}

function updateChips() {
  const total = allAgents().length;
  $('#chipAll').textContent = total;
  $('#chipSelected').textContent = state.selected.size;
  $('#chipExcluded').textContent = total - state.selected.size;
}

function applyFilters() {
  const q = state.search.trim().toLowerCase();
  $$('.agent-row').forEach((row) => {
    const id = row.dataset.id;
    const isSel = state.selected.has(id);
    let visible = true;
    if (state.filter === 'selected') visible = isSel;
    if (state.filter === 'excluded') visible = !isSel;
    if (visible && q) visible = row.dataset.title.includes(q);
    row.classList.toggle('hidden-by-search', !visible);
  });
  $$('.cat-card').forEach((card) => {
    const anyVisible = [...card.querySelectorAll('.agent-row')].some((r) => !r.classList.contains('hidden-by-search'));
    card.style.display = anyVisible ? '' : 'none';
  });
}

// ---------------------------------------------------------------------------
// engagement bar / ask panel
// ---------------------------------------------------------------------------

function currentMode() { return $('#fieldMode').value; }

$('#fieldMode').addEventListener('change', () => {
  show($('.eb-repo'), currentMode() === 'greybox');
  $('.eb-target label').textContent = currentMode() === 'whitebox' ? 'Repo / path' : 'Target';
});

$('#btnAskSend').addEventListener('click', () => {
  const kind = $('#askKind').value;
  const text = $('#askInput').value.trim();
  if (!text) return;
  if (kind === 'focus') state.askFocus = text;
  if (kind === 'objective') state.askObjective = text;
  if (kind === 'scope-out') state.askOutOfScope = text;
  $('#askHint').textContent = `✓ ${kind} definido — aplicado no próximo "Start Exploitation"`;
  $('#askInput').value = '';
});

$('#btnCustomLead').addEventListener('click', () => {
  const text = prompt('Descreva a lead customizada (linguagem livre — vira contexto de foco para os agentes):');
  if (text && text.trim()) {
    state.customLeads.push(text.trim());
    $('#askHint').textContent = `✓ custom lead adicionada (${state.customLeads.length} total)`;
  }
});

$$('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    $$('.chip').forEach((c) => c.classList.remove('chip-active'));
    chip.classList.add('chip-active');
    state.filter = chip.dataset.filter;
    applyFilters();
  });
});

$('#leadSearch').addEventListener('input', (e) => { state.search = e.target.value; applyFilters(); });

// ---------------------------------------------------------------------------
// start exploitation → live run view
// ---------------------------------------------------------------------------

$('#btnStartExploitation').addEventListener('click', startExploitation);

async function startExploitation() {
  const mode = currentMode();
  const target = $('#fieldTarget').value.trim();
  const repo = $('#fieldRepo').value.trim();
  if (mode !== 'whitebox' && !target) { alert('Defina o target.'); return; }
  if (mode === 'whitebox' && !target && !repo) { alert('Defina o repo/path.'); return; }
  if (mode === 'greybox' && !repo) { alert('Grey-box precisa de repo + target.'); return; }

  const modelField = $('#fieldModel').value.trim();
  const focusParts = [state.askFocus, ...state.customLeads].filter(Boolean);

  const body = {
    mode,
    target: mode === 'whitebox' ? undefined : target,
    repo: mode === 'whitebox' ? (target || repo) : (repo || undefined),
    models: modelField ? [modelField] : [],
    votes: Number($('#fieldVotes').value) || 3,
    chainDepth: Number($('#fieldChain').value),
    recon: Number($('#fieldRecon').value),
    subscription: $('#fieldSubscription').checked,
    mcp: $('#fieldMcp').checked,
    agents: [...state.selected],
    focus: focusParts.join('; ') || undefined,
    objective: state.askObjective || undefined,
    outOfScope: state.askOutOfScope || undefined,
  };

  $('#btnStartExploitation').disabled = true;
  try {
    const { id } = await api('/api/exploit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    attachLiveJob(id, body.target || body.repo);
  } catch (e) {
    alert('Falha ao iniciar: ' + e.message);
  } finally {
    $('#btnStartExploitation').disabled = false;
  }
}

function attachLiveJob(id, target) {
  if (state.currentJob) state.currentJob.es.close();
  state.currentJob = { id, es: null, findings: [], target, phase: 'starting', agents: 0, agentsDone: 0, reportUrl: null };

  show($('#boardView'), false);
  show($('#detailView'), false);
  show($('#liveView'), true);
  $('#liveTarget').textContent = target || '—';
  $('#livePhase').textContent = 'starting';
  $('#findingsList').innerHTML = '';
  $('#logList').innerHTML = '';
  $('#findingsCount').textContent = '0';
  $('#progressFill').style.width = '0%';
  $('#progressLabel').textContent = '0 / 0 agents';
  show($('#btnOpenReport'), false);

  const es = new EventSource(`/api/exploit/${id}/events`);
  state.currentJob.es = es;
  es.addEventListener('log', (e) => appendLog(JSON.parse(e.data).line));
  es.addEventListener('finding', (e) => addFinding(JSON.parse(e.data).finding));
  es.addEventListener('snapshot', (e) => applySnapshot(JSON.parse(e.data)));
  es.addEventListener('done', (e) => { applySnapshot(JSON.parse(e.data)); refreshRuns(); });
  es.onerror = () => { /* browser auto-retries; fine for a long-running engagement */ };
}

function appendLog(line) {
  const div = document.createElement('div');
  div.className = 'log-line';
  div.textContent = line;
  const list = $('#logList');
  list.appendChild(div);
  list.scrollTop = list.scrollHeight;
}

function addFinding(f) {
  state.currentJob.findings.push(f);
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="f-top"><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span><span class="f-title">${esc(f.title)}</span></div>
    <div class="f-meta">${esc(f.cwe || '')} ${f.endpoint ? '· ' + esc(f.endpoint) : ''} ${f.agent ? '· ' + esc(f.agent) : ''}</div>
  `;
  $('#findingsList').appendChild(card);
  $('#findingsCount').textContent = state.currentJob.findings.length;
}

function applySnapshot(snap) {
  $('#livePhase').textContent = snap.phase;
  $('#progressLabel').textContent = `${snap.agentsDone} / ${snap.agents || '?'} agents`;
  if (snap.agents) $('#progressFill').style.width = `${Math.min(100, (snap.agentsDone / snap.agents) * 100)}%`;
  if (snap.reportUrl) {
    const link = $('#btnOpenReport');
    link.href = `/api/runs/${snap.runId}/asset/report.html`;
    show(link, !!snap.runId);
  }
  if (snap.done) $('#phaseDot').style.background = 'var(--green)';
}

$('#btnStopRun').addEventListener('click', async () => {
  if (!state.currentJob) return;
  await api(`/api/exploit/${state.currentJob.id}/stop`, { method: 'POST' });
});
$('#btnBackToBoard').addEventListener('click', () => { show($('#liveView'), false); show($('#boardView'), true); });

// ---------------------------------------------------------------------------
// sidebar — runs history
// ---------------------------------------------------------------------------

async function refreshRuns() {
  try {
    state.runs = await api('/api/runs');
  } catch { state.runs = []; }
  renderSidebar();
}

function stepClassFor(phase, step) {
  const order = ['recon', 'planning', 'exploiting', 'remediation'];
  const idx = { recon: 0, starting: 0, planning: 1, exploiting: 2, validating: 2, chaining: 2, complete: 3 }[phase] ?? 0;
  const stepIdx = order.indexOf(step);
  if (step === 'remediation') return 'pending'; // not automated yet — shown for roadmap parity only
  if (stepIdx < idx) return 'done';
  if (stepIdx === idx) return 'active';
  return 'pending';
}

function renderSidebar() {
  const root = $('#sbGroups');
  root.innerHTML = '';

  const running = state.runs.filter((r) => r.state === 'running');
  const completed = state.runs.filter((r) => r.state !== 'running');

  const groups = [
    { label: 'Running', items: running, open: true },
    { label: 'Completed', items: completed, open: true },
  ];

  for (const g of groups) {
    const wrap = document.createElement('div');
    wrap.className = 'sb-group';
    wrap.innerHTML = `<div class="sb-group-head"><span class="caret">▾</span><span>${g.label}</span><span class="count">${g.items.length}</span></div><div class="sb-items"></div>`;
    wrap.querySelector('.sb-group-head').addEventListener('click', () => wrap.classList.toggle('collapsed'));
    const items = wrap.querySelector('.sb-items');
    for (const r of g.items) {
      const btn = document.createElement('button');
      btn.className = 'sb-run' + (state.currentDetailId === r.id ? ' active' : '');
      btn.innerHTML = `${esc(r.target)}<span class="sub">${esc(r.id)} · ${r.findings} finding(s)</span>`;
      btn.addEventListener('click', () => openRun(r));
      items.appendChild(btn);
      if (r.state === 'running' && state.currentJob) {
        const phase = state.currentJob.target === r.target ? $('#livePhase').textContent : null;
        const steps = document.createElement('div');
        steps.className = 'sb-steps';
        steps.innerHTML = ['recon', 'planning', 'exploiting', 'remediation'].map((s) =>
          `<div class="sb-step ${stepClassFor(phase || 'recon', s)}">${s[0].toUpperCase() + s.slice(1)}</div>`).join('');
        items.appendChild(steps);
      }
    }
    root.appendChild(wrap);
  }
}

function openRun(run) {
  state.currentDetailId = run.id;
  if (run.state === 'running' && state.currentJob) {
    show($('#boardView'), false); show($('#detailView'), false); show($('#liveView'), true);
    return;
  }
  show($('#boardView'), false); show($('#liveView'), false); show($('#detailView'), true);
  loadDetail(run.id);
  renderSidebar();
}

async function loadDetail(id) {
  clearInterval(state.detailPoll);
  const detail = await api(`/api/runs/${encodeURIComponent(id)}`);
  $('#detailTarget').textContent = detail.status?.target || detail.meta?.target || id;
  $('#detailState').textContent = detail.status?.state || 'unknown';
  const list = $('#detailFindings');
  list.innerHTML = detail.findings.length
    ? detail.findings.map((f) => `
        <div class="finding-card">
          <div class="f-top"><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span><span class="f-title">${esc(f.title)}</span></div>
          <div class="f-meta">${esc(f.cwe || '')} ${f.endpoint ? '· ' + esc(f.endpoint) : ''} ${f.agent ? '· ' + esc(f.agent) : ''}</div>
        </div>`).join('')
    : '<div class="f-meta">nenhum finding validado.</div>';
  const reportLink = $('#detailOpenReport');
  if (detail.assets.includes('report.html')) {
    reportLink.href = `/api/runs/${encodeURIComponent(id)}/asset/report.html`;
    show(reportLink, true);
  } else show(reportLink, false);

  if (detail.status?.state === 'running') {
    state.detailPoll = setInterval(() => loadDetail(id), 4000);
  }
}

$('#btnDetailBack').addEventListener('click', () => { clearInterval(state.detailPoll); show($('#detailView'), false); show($('#boardView'), true); });
$('#btnNewEngagement').addEventListener('click', () => { show($('#detailView'), false); show($('#liveView'), false); show($('#boardView'), true); });

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
    out.textContent += chunk;
    out.scrollTop = out.scrollHeight;
  });
  es.addEventListener('close', () => { es.close(); });
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
  out.textContent += `❭ ${line}\n`;
  out.scrollTop = out.scrollHeight;
  if (!state.replId) await startRepl();
  await api(`/api/repl/${state.replId}/input`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ line }) });
});

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

async function boot() {
  const meta = await api('/api/meta').catch(() => ({}));
  $('#sbMeta').textContent = `v${meta.version || '4.0.0'}`;
  await loadAgents();
  await refreshRuns();
  setInterval(refreshRuns, 6000);
}
boot();
