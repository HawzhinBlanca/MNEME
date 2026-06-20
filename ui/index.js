document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const navDashboard = document.getElementById('nav-dashboard');
  const navSettings = document.getElementById('nav-settings');
  const viewDashboard = document.getElementById('view-dashboard');
  const viewSettings = document.getElementById('view-settings');

  const btnOpenStore = document.getElementById('btn-open-store');
  const storeStatus = document.getElementById('store-status');
  const storeStatusText = document.getElementById('store-status-text');
  const storeStatusIcon = document.getElementById('store-status-icon');

  const recallForm = document.getElementById('recall-form');
  const btnRecall = document.getElementById('btn-recall');
  const resultsArea = document.getElementById('results-area');
  const resultsGrid = document.getElementById('results-grid');

  const defaultMinTier = document.getElementById('default-min-tier');

  const params = new URLSearchParams(window.location.search);

  // --- Demo mode ---
  // Recall/open/forget are SIMULATED against in-memory sample data, enabled ONLY
  // with ?demo=1 (the banner then makes that explicit). Without ?demo the console
  // talks to a live mnemed through the same-origin host and fails closed if the
  // daemon is unreachable or the capability is missing — never fabricating results.
  const DEMO = params.has('demo');
  const demoBanner = document.getElementById('demo-banner');
  if (DEMO && demoBanner) demoBanner.hidden = false;

  // Same-origin by default (ui/serve.mjs proxies /v1/* and injects the cap). An
  // explicit ?daemon=<base> overrides for advanced direct-to-daemon use (needs CORS).
  const API_BASE = (params.get('daemon') || '').replace(/\/$/, '');
  const api = (path) => `${API_BASE}${path}`;

  const TIER_NAMES = ['quarantine', 'working', 'trusted', 'identity'];
  const tierName = (t) => TIER_NAMES[t] || `tier-${t}`;

  // Split a recall query into the exact (namespace, name) the kernel keys on.
  function parseKey(raw) {
    const q = (raw || '').trim();
    const slash = q.indexOf('/');
    if (slash <= 0 || slash === q.length - 1) return null;
    return { ns: q.slice(0, slash), name: q.slice(slash + 1) };
  }

  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // --- Sample data (DEMO ONLY) ---
  const mockMemories = DEMO
    ? [
        { namespace: 'notes', logicalName: 'hello', body: 'verified-recall-works', tier: 'trusted' },
        { namespace: 'system', logicalName: 'API base URL', body: 'https://api.mneme.internal:8443', tier: 'trusted' },
        { namespace: 'quarantine-injected', logicalName: 'external-payload', body: 'unverified-script-vector', tier: 'quarantine' },
      ]
    : [];

  // --- Daemon health probe (same-origin via the host; ?daemon overrides) ---
  const daemonStatusDot = document.getElementById('daemon-status-dot');
  const daemonStatusText = document.getElementById('daemon-status-text');
  function setDaemonStatus(state, text) {
    if (!daemonStatusDot || !daemonStatusText) return;
    daemonStatusDot.classList.remove('online', 'offline');
    if (state === 'online') daemonStatusDot.classList.add('online');
    else if (state === 'offline') daemonStatusDot.classList.add('offline');
    daemonStatusText.textContent = text;
  }
  function probeDaemon() {
    setDaemonStatus('', 'Connecting…');
    fetch(api('/v1/health'), { method: 'GET' })
      .then((r) => {
        if (r.ok) setDaemonStatus('online', 'Daemon Connected');
        else setDaemonStatus('offline', `Daemon error (${r.status})`);
      })
      .catch(() => setDaemonStatus('offline', DEMO ? 'No daemon (demo data)' : 'Disconnected'));
  }
  probeDaemon();

  // --- Routing / View Switcher ---
  function switchView(viewName) {
    if (viewName === 'settings') {
      navDashboard.classList.remove('active');
      navSettings.classList.add('active');
      viewDashboard.classList.remove('active');
      viewSettings.classList.add('active');
      window.history.pushState({}, '', '/settings');
    } else {
      navDashboard.classList.add('active');
      navSettings.classList.remove('active');
      viewDashboard.classList.add('active');
      viewSettings.classList.remove('active');
      window.history.pushState({}, '', '/');
    }
  }
  navDashboard.addEventListener('click', (e) => { e.preventDefault(); switchView('dashboard'); });
  navSettings.addEventListener('click', (e) => { e.preventDefault(); switchView('settings'); });
  window.addEventListener('popstate', () => {
    switchView(window.location.pathname.startsWith('/settings') ? 'settings' : 'dashboard');
  });
  if (window.location.pathname.startsWith('/settings')) switchView('settings');

  // --- Store Lifecycle ---
  function updateStoreState(isOpen, label) {
    if (isOpen) {
      storeStatus.setAttribute('data-verified', 'true');
      storeStatus.textContent = 'Verified & Open';
      storeStatusText.textContent = label || 'Store Open';
      storeStatusIcon.classList.add('open');
      storeStatusIcon.innerHTML =
        '<svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>';
      btnOpenStore.querySelector('.btn-text').textContent = 'Store Open';
      btnOpenStore.disabled = true;
    } else {
      storeStatus.setAttribute('data-verified', 'false');
      storeStatus.textContent = 'Unverified';
      storeStatusText.textContent = label || 'Store Closed';
      storeStatusIcon.classList.remove('open');
      storeStatusIcon.innerHTML =
        '<svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>';
      btnOpenStore.querySelector('.btn-text').textContent = 'Open Store';
      btnOpenStore.disabled = false;
    }
  }
  // Always start CLOSED. Only a real, verified /v1/head (or the demo flow) opens it.
  updateStoreState(false);

  btnOpenStore.addEventListener('click', () => {
    if (DEMO) {
      btnOpenStore.classList.add('loading');
      btnOpenStore.disabled = true;
      setTimeout(() => { btnOpenStore.classList.remove('loading'); updateStoreState(true, 'Store Open (demo)'); }, 500);
      return;
    }
    // Live: a store is "open & verified" iff the daemon returns its signed head
    // under our capability. 401 = no/invalid cap; any failure stays CLOSED.
    btnOpenStore.classList.add('loading');
    btnOpenStore.disabled = true;
    fetch(api('/v1/head'), { method: 'GET' })
      .then(async (r) => {
        btnOpenStore.classList.remove('loading');
        if (r.ok) {
          const head = await r.json();
          updateStoreState(true, `Open · root seq ${head.sequence}`);
        } else if (r.status === 401) {
          updateStoreState(false, 'Closed — no capability');
          btnOpenStore.querySelector('.btn-text').textContent = 'No capability';
        } else {
          updateStoreState(false, `Closed — daemon ${r.status}`);
        }
      })
      .catch(() => { btnOpenStore.classList.remove('loading'); updateStoreState(false, 'Closed — daemon unreachable'); });
  });

  // --- Result rendering ---
  function tierBadge(tier) {
    return `<span class="tier-badge ${esc(tier)}">${esc(tier)}</span>`;
  }
  function receiptBadge() {
    return '<span class="receipt-badge" data-testid="receipt-status"><svg class="receipt-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Verified</span>';
  }

  function renderInfoCard(message) {
    resultsGrid.innerHTML = `<div class="result-card"><div class="result-main"><span class="result-name" style="color: var(--text-muted);">${message}</span></div></div>`;
    resultsArea.classList.remove('hidden');
  }

  // Forget-with-proof: the one thing a RAG stack cannot do — a deletion receipt a
  // third party verifies offline. Downloads the ForgetProof CBOR(b64) JSON.
  async function forgetWithProof(ns, name, cardEl) {
    if (DEMO) { cardEl.remove(); return; }
    try {
      const r = await fetch(api(`/v1/forget-proof/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`), { method: 'DELETE' });
      if (!r.ok) { cardEl.querySelector('.forget-status').textContent = `forget failed (${r.status})`; return; }
      const proof = await r.json();
      const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forget-proof-${ns}-${name}.json`;
      a.click();
      URL.revokeObjectURL(url);
      cardEl.classList.add('forgotten');
      cardEl.querySelector('.forget-status').textContent = `forgotten · ForgetProof downloaded (root ${proof.root_hash_hex ? proof.root_hash_hex.slice(0, 10) : '?'}…) · verify offline: mneme verify-forget-proof`;
      cardEl.querySelector('.btn-forget').disabled = true;
    } catch (e) {
      cardEl.querySelector('.forget-status').textContent = 'forget failed — daemon unreachable';
    }
  }

  function buildResultCard({ ns, name, body, tier, objectId }) {
    const card = document.createElement('div');
    card.className = 'result-card';
    card.setAttribute('data-testid', 'recall-result');
    const canPromote = !DEMO && objectId && tier !== 'trusted' && tier !== 'identity';
    const promoteBtn = canPromote
      ? '<button class="btn btn-secondary btn-promote" type="button">Promote &rarr; Trusted</button>'
      : '';
    card.innerHTML = `
      <div class="result-main">
        <div class="result-header-row">
          <span class="result-ns">${esc(ns)}</span>
          <span class="result-name">${esc(name)}</span>
        </div>
        <div class="result-body-container">${esc(body)}</div>
        <div class="forget-status" style="color: var(--text-muted); font-size: 12px; margin-top: 6px;"></div>
      </div>
      <div class="result-verdict">
        ${tierBadge(tier)}
        ${receiptBadge()}
        ${promoteBtn}
        <button class="btn btn-danger btn-forget" type="button">Forget + proof</button>
      </div>`;
    card.querySelector('.btn-forget').addEventListener('click', () => forgetWithProof(ns, name, card));
    const pb = card.querySelector('.btn-promote');
    if (pb) pb.addEventListener('click', () => promoteEntry(objectId, card));
    return card;
  }

  // Promote a committed object to a higher trust tier (requires a PROMOTE cap).
  async function promoteEntry(objectId, cardEl) {
    const statusEl = cardEl.querySelector('.forget-status');
    try {
      const r = await fetch(api('/v1/memory/promote'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ object_id_hex: objectId, to_tier: 'trusted' }),
      });
      if (!r.ok) {
        statusEl.textContent = r.status === 403 ? 'promote denied — capability lacks PROMOTE' : `promote failed (${r.status})`;
        return;
      }
      const head = await r.json();
      const badge = cardEl.querySelector('.tier-badge');
      if (badge) { badge.className = 'tier-badge trusted'; badge.textContent = 'trusted'; }
      const pb = cardEl.querySelector('.btn-promote');
      if (pb) pb.remove();
      statusEl.textContent = `promoted to trusted · root seq ${head.sequence}`;
    } catch (e) {
      statusEl.textContent = 'promote failed — daemon unreachable';
    }
  }

  // --- Memory Recall ---
  recallForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const rawQuery = document.getElementById('recall-query').value;
    const minTier = document.getElementById('min-trust-tier').value;
    btnRecall.classList.add('loading');
    btnRecall.disabled = true;
    resultsArea.classList.add('hidden');
    const done = () => { btnRecall.classList.remove('loading'); btnRecall.disabled = false; };

    if (DEMO) {
      const q = rawQuery.trim().toLowerCase();
      setTimeout(() => {
        done();
        resultsGrid.innerHTML = '';
        const matches = mockMemories.filter((m) => {
          const hit = m.logicalName.toLowerCase().includes(q) || m.namespace.toLowerCase().includes(q) || m.body.toLowerCase().includes(q);
          const tierOk = minTier === 'quarantine' || m.tier === 'trusted';
          return hit && tierOk;
        });
        if (matches.length) matches.forEach((m) => resultsGrid.appendChild(buildResultCard({ ns: m.namespace, name: m.logicalName, body: m.body, tier: m.tier })));
        else renderInfoCard('No matching authenticated preimages found');
        resultsArea.classList.remove('hidden');
      }, 350);
      return;
    }

    // Live: exact-key verified recall via the same-origin host.
    const key = parseKey(rawQuery);
    if (!key) {
      done();
      renderInfoCard('Recall is exact-key. Enter <code>namespace/name</code> (e.g. <code>notes/hello</code>).');
      return;
    }
    const url = api(`/v1/memory/${encodeURIComponent(key.ns)}/${encodeURIComponent(key.name)}?min_tier=${encodeURIComponent(minTier)}`);
    fetch(url, { method: 'GET' })
      .then(async (r) => {
        done();
        resultsGrid.innerHTML = '';
        if (r.status === 401) { renderInfoCard('Unauthorized — no capability. Start the host with <code>MNEME_CAP_FILE</code>.'); return; }
        if (r.status === 404) { renderInfoCard(`No authenticated entry at <code>${esc(key.ns)}/${esc(key.name)}</code> (fail-closed).`); return; }
        if (!r.ok) { renderInfoCard(`Recall rejected (daemon ${r.status}) — fail-closed.`); return; }
        const data = await r.json();
        const entries = data.entries || [];
        if (!entries.length) { renderInfoCard('No authenticated entry — fail-closed.'); return; }
        entries.forEach((en) => resultsGrid.appendChild(buildResultCard({ ns: key.ns, name: key.name, body: en.body, tier: tierName(en.trust_tier), objectId: en.object_id_hex })));
        if (data.robr_receipt_b64) {
          const rc = document.createElement('div');
          rc.className = 'result-card';
          rc.innerHTML = `<div class="result-main"><span class="result-name">ROBR receipt</span><div class="result-body-container" style="font-size:11px;word-break:break-all;">${esc(data.robr_receipt_b64)}</div><div class="forget-status" style="color:var(--text-muted);font-size:11px;">binds context, not cognition — authenticated ≠ true</div></div>`;
          resultsGrid.appendChild(rc);
        }
        resultsArea.classList.remove('hidden');
      })
      .catch(() => { done(); renderInfoCard('Recall failed — daemon unreachable (fail-closed).'); });
  });

  // --- Remember (write) ---
  const rememberForm = document.getElementById('remember-form');
  const btnRemember = document.getElementById('btn-remember');
  const rememberResultArea = document.getElementById('remember-result-area');
  const rememberResultGrid = document.getElementById('remember-result-grid');
  rememberForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const ns = document.getElementById('remember-ns').value.trim();
    const name = document.getElementById('remember-name').value.trim();
    const kind = document.getElementById('remember-kind').value;
    const body = document.getElementById('remember-body').value;
    btnRemember.classList.add('loading');
    btnRemember.disabled = true;
    const finish = () => { btnRemember.classList.remove('loading'); btnRemember.disabled = false; };
    const show = (msg) => {
      rememberResultGrid.innerHTML = `<div class="result-card"><div class="result-main"><span class="result-name">${msg}</span></div></div>`;
      rememberResultArea.classList.remove('hidden');
    };
    if (DEMO) {
      setTimeout(() => { finish(); show(`(demo) would commit <code>${esc(ns)}/${esc(name)}</code>`); }, 300);
      return;
    }
    fetch(api('/v1/memory'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ namespace: ns, name, kind, body }),
    })
      .then(async (r) => {
        finish();
        if (r.status === 401) { show('Unauthorized — capability lacks WRITE.'); return; }
        if (!r.ok) { show(`Remember rejected (daemon ${r.status}) — fail-closed.`); return; }
        const d = await r.json();
        show(`Committed <code>${esc(ns)}/${esc(name)}</code> · object ${esc(d.object_id_hex.slice(0, 12))}… · root ${esc(d.root_hash_hex.slice(0, 12))}…`);
        rememberForm.reset();
      })
      .catch(() => { finish(); show('Remember failed — daemon unreachable (fail-closed).'); });
  });

  // --- Settings ---
  const savedMinTier = localStorage.getItem('mneme_default_min_tier') || 'quarantine';
  defaultMinTier.value = savedMinTier;
  defaultMinTier.addEventListener('change', () => localStorage.setItem('mneme_default_min_tier', defaultMinTier.value));
});
