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

  // --- Demo mode ---
  // This console ships with NO daemon wiring. The recall/open flows below are
  // SIMULATED against in-memory sample data. To avoid presenting fiction as a
  // live system, they are enabled ONLY when the page is opened with ?demo=1; the
  // banner then makes the demo nature explicit. Without ?demo=1 the form reports
  // that no daemon is connected instead of returning fabricated results.
  const DEMO = new URLSearchParams(window.location.search).has('demo');
  const demoBanner = document.getElementById('demo-banner');
  if (DEMO && demoBanner) demoBanner.hidden = false;

  // --- Sample data (DEMO ONLY) ---
  const mockMemories = DEMO
    ? [
        {
          namespace: 'system',
          logicalName: 'API base URL',
          body: 'https://api.mneme.substrate.internal:8443',
          tier: 'trusted'
        },
        {
          namespace: 'agent-session',
          logicalName: 'operator-seed-hash',
          body: 'sha256:d8a5c4e0b2a3f65d0bfea1ce9fe101b59dd54e0d',
          tier: 'trusted'
        },
        {
          namespace: 'quarantine-injected',
          logicalName: 'external-payload',
          body: 'unverified-script-execution-vector',
          tier: 'quarantine'
        }
      ]
    : [];

  // --- Real daemon health probe ---
  // Default to the mnemed HTTP port; overridable with ?daemon=<base-url>. The pill
  // stays neutral until this resolves, then shows online ONLY on a successful
  // /v1/health response. A cross-origin/CORS/connection failure is reported as
  // offline (we cannot confirm a daemon), never as connected.
  const daemonStatusDot = document.getElementById('daemon-status-dot');
  const daemonStatusText = document.getElementById('daemon-status-text');
  function setDaemonStatus(state, text) {
    if (!daemonStatusDot || !daemonStatusText) return;
    daemonStatusDot.classList.remove('online', 'offline');
    if (state === 'online') daemonStatusDot.classList.add('online');
    else if (state === 'offline') daemonStatusDot.classList.add('offline');
    daemonStatusText.textContent = text;
  }
  (function probeDaemon() {
    const base = (new URLSearchParams(window.location.search).get('daemon')
      || 'http://localhost:7845').replace(/\/$/, '');
    setDaemonStatus('', 'Connecting…');
    fetch(`${base}/v1/health`, { method: 'GET', mode: 'cors' })
      .then((r) => {
        if (r.ok) setDaemonStatus('online', 'Daemon Connected');
        else setDaemonStatus('offline', `Daemon error (${r.status})`);
      })
      .catch(() => {
        setDaemonStatus('offline', DEMO ? 'No daemon (demo data)' : 'Disconnected');
      });
  })();

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

  navDashboard.addEventListener('click', (e) => {
    e.preventDefault();
    switchView('dashboard');
  });

  navSettings.addEventListener('click', (e) => {
    e.preventDefault();
    switchView('settings');
  });

  // Handle browser back/forward navigation
  window.addEventListener('popstate', () => {
    if (window.location.pathname.startsWith('/settings')) {
      switchView('settings');
    } else {
      switchView('dashboard');
    }
  });

  // Handle initial load based on path
  if (window.location.pathname.startsWith('/settings')) {
    switchView('settings');
  }

  // --- Store Lifecycle (Open/Close) ---
  function updateStoreState(isOpen) {
    if (isOpen) {
      storeStatus.setAttribute('data-verified', 'true');
      storeStatus.textContent = 'Verified & Open';
      storeStatusText.textContent = 'Store Open';
      storeStatusIcon.classList.add('open');
      storeStatusIcon.innerHTML = `
        <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
      `;
      btnOpenStore.querySelector('.btn-text').textContent = 'Store Open';
      btnOpenStore.disabled = true;
    } else {
      storeStatus.setAttribute('data-verified', 'false');
      storeStatus.textContent = 'Unverified';
      storeStatusText.textContent = 'Store Closed';
      storeStatusIcon.classList.remove('open');
      storeStatusIcon.innerHTML = `
        <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 9.9-1"></path>
        </svg>
      `;
      btnOpenStore.querySelector('.btn-text').textContent = 'Open Store';
      btnOpenStore.disabled = false;
    }
  }

  // Always start CLOSED. The previous build spoofed "open" from a localStorage
  // flag, which let the UI claim a verified, open store with no daemon behind it.
  // Store state must reflect a real open, so default closed and only the demo
  // flow simulates an open (clearly labelled by the demo banner).
  updateStoreState(false);

  btnOpenStore.addEventListener('click', () => {
    if (!DEMO) {
      // No daemon wiring in this console; do not fake a verified open.
      btnOpenStore.querySelector('.btn-text').textContent =
        'No daemon — open with ?demo=1';
      return;
    }
    btnOpenStore.classList.add('loading');
    btnOpenStore.disabled = true;

    // DEMO ONLY: simulate the cryptographic/SMT verification flow.
    setTimeout(() => {
      btnOpenStore.classList.remove('loading');
      updateStoreState(true);
    }, 600);
  });

  // --- Memory Recall Form Submission ---
  recallForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const query = document.getElementById('recall-query').value.trim().toLowerCase();
    const minTier = document.getElementById('min-trust-tier').value;

    btnRecall.classList.add('loading');
    btnRecall.disabled = true;
    resultsArea.classList.add('hidden');

    if (!DEMO) {
      // No daemon wiring: do not fabricate a recall result or a fake "no results".
      btnRecall.classList.remove('loading');
      btnRecall.disabled = false;
      resultsGrid.innerHTML = '';
      const card = document.createElement('div');
      card.className = 'result-card';
      card.innerHTML = `
        <div class="result-main">
          <span class="result-name" style="color: var(--text-muted);">No daemon connected — append <code>?demo=1</code> to explore with sample data.</span>
        </div>
      `;
      resultsGrid.appendChild(card);
      resultsArea.classList.remove('hidden');
      return;
    }

    // DEMO ONLY: simulate search & verify lookup latency (500ms)
    setTimeout(() => {
      btnRecall.classList.remove('loading');
      btnRecall.disabled = false;

      // Filter based on query and trust tier
      const matches = mockMemories.filter(m => {
        const matchesQuery = m.logicalName.toLowerCase().includes(query) || 
                             m.namespace.toLowerCase().includes(query) ||
                             m.body.toLowerCase().includes(query);
        
        // If query is matched, check if it fits the trust tier policy.
        // If minTier is "trusted", we only show "trusted".
        // If minTier is "quarantine", we can show both "trusted" and "quarantine".
        const matchesTier = minTier === 'quarantine' || m.tier === 'trusted';

        return matchesQuery && matchesTier;
      });

      // Clear previous results
      resultsGrid.innerHTML = '';

      if (matches.length > 0) {
        matches.forEach(item => {
          const card = document.createElement('div');
          card.className = 'result-card';
          card.setAttribute('data-testid', 'recall-result');
          
          card.innerHTML = `
            <div class="result-main">
              <div class="result-header-row">
                <span class="result-ns">${item.namespace}</span>
                <span class="result-name">${item.logicalName}</span>
              </div>
              <div class="result-body-container">
                ${item.body}
              </div>
            </div>
            <div class="result-verdict">
              <span class="tier-badge ${item.tier}">${item.tier}</span>
              <span class="receipt-badge" data-testid="receipt-status">
                <svg class="receipt-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                Verified
              </span>
            </div>
          `;
          resultsGrid.appendChild(card);
        });
      } else {
        const emptyCard = document.createElement('div');
        emptyCard.className = 'result-card';
        emptyCard.innerHTML = `
          <div class="result-main">
            <span class="result-name" style="color: var(--text-muted);">No matching authenticated preimages found</span>
          </div>
        `;
        resultsGrid.appendChild(emptyCard);
      }

      resultsArea.classList.remove('hidden');
    }, 500);
  });

  // --- Settings Policy State Management ---
  const savedMinTier = localStorage.getItem('mneme_default_min_tier') || 'quarantine';
  defaultMinTier.value = savedMinTier;

  defaultMinTier.addEventListener('change', () => {
    localStorage.setItem('mneme_default_min_tier', defaultMinTier.value);
  });
});
