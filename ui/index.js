document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const navDashboard = document.getElementById('nav-dashboard');
  const navSettings = document.getElementById('nav-settings');
  const navForget = document.getElementById('nav-forget');
  const viewDashboard = document.getElementById('view-dashboard');
  const viewSettings = document.getElementById('view-settings');
  const viewForget = document.getElementById('view-forget');

  const btnOpenStore = document.getElementById('btn-open-store');
  const storeStatus = document.getElementById('store-status');
  const storeStatusText = document.getElementById('store-status-text');
  const storeStatusIcon = document.getElementById('store-status-icon');

  const recallForm = document.getElementById('recall-form');
  const btnRecall = document.getElementById('btn-recall');
  const resultsArea = document.getElementById('results-area');
  const resultsGrid = document.getElementById('results-grid');

  const forgetForm = document.getElementById('forget-form');
  const btnForget = document.getElementById('btn-forget');
  const forgetResultsArea = document.getElementById('forget-results-area');
  const forgetResultsGrid = document.getElementById('forget-results-grid');

  const defaultMinTier = document.getElementById('default-min-tier');

  // --- Mock Database ---
  let mockMemories = [
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
  ];

  // --- Routing / View Switcher ---
  function switchView(viewName) {
    navDashboard.classList.remove('active');
    navSettings.classList.remove('active');
    navForget.classList.remove('active');
    viewDashboard.classList.remove('active');
    viewSettings.classList.remove('active');
    viewForget.classList.remove('active');

    if (viewName === 'settings') {
      navSettings.classList.add('active');
      viewSettings.classList.add('active');
      window.history.pushState({}, '', '/settings');
    } else if (viewName === 'forget') {
      navForget.classList.add('active');
      viewForget.classList.add('active');
      window.history.pushState({}, '', '/forget');
    } else {
      navDashboard.classList.add('active');
      viewDashboard.classList.add('active');
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

  navForget.addEventListener('click', (e) => {
    e.preventDefault();
    switchView('forget');
  });

  // Handle browser back/forward navigation
  window.addEventListener('popstate', () => {
    if (window.location.pathname.startsWith('/settings')) {
      switchView('settings');
    } else if (window.location.pathname.startsWith('/forget')) {
      switchView('forget');
    } else {
      switchView('dashboard');
    }
  });

  // Handle initial load based on path
  if (window.location.pathname.startsWith('/settings')) {
    switchView('settings');
  } else if (window.location.pathname.startsWith('/forget')) {
    switchView('forget');
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

  // Load initial store state
  const isStoreOpen = localStorage.getItem('mneme_store_open') === 'true';
  updateStoreState(isStoreOpen);

  btnOpenStore.addEventListener('click', () => {
    btnOpenStore.classList.add('loading');
    btnOpenStore.disabled = true;

    // Simulate cryptographic/SMT verification flow
    setTimeout(() => {
      btnOpenStore.classList.remove('loading');
      localStorage.setItem('mneme_store_open', 'true');
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

    // Simulate search & verify lookup latency (500ms)
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

  // --- Forget Form Submission ---
  forgetForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const key = document.getElementById('forget-key').value.trim();
    const namespace = document.getElementById('forget-namespace').value;

    btnForget.classList.add('loading');
    btnForget.disabled = true;
    forgetResultsArea.classList.add('hidden');

    setTimeout(() => {
      btnForget.classList.remove('loading');
      btnForget.disabled = false;

      // Find the memory to mock-shred
      const targetIndex = mockMemories.findIndex(
        m => m.logicalName.toLowerCase() === key.toLowerCase() && m.namespace === namespace
      );

      let foundMemory = null;
      if (targetIndex !== -1) {
        foundMemory = mockMemories[targetIndex];
        // Shred/remove from mock database
        mockMemories.splice(targetIndex, 1);
      }

      const displayedKey = foundMemory ? foundMemory.logicalName : key;
      const preimageHash = foundMemory 
        ? `blake3:${Array.from({length: 40}, (_, i) => (i % 16).toString(16)).join('')}`
        : 'absent';

      // Generate a mock ForgetProof CBOR hex
      const mockCborHex = `a70103024c666f726765745f70726f6f66035820${Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('')}045840${Array.from({length: 128}, () => Math.floor(Math.random()*16).toString(16)).join('')}`;

      forgetResultsGrid.innerHTML = '';
      const card = document.createElement('div');
      card.className = 'result-card';
      card.setAttribute('data-testid', 'forget-proof-result');

      card.innerHTML = `
        <div class="result-main">
          <div class="result-header-row">
            <span class="result-ns" style="background-color: var(--accent-orange-glow); color: var(--accent-orange); border: 1px solid hsla(24, 90%, 50%, 0.3);">${namespace}</span>
            <span class="result-name">${displayedKey} (Shredded)</span>
          </div>
          <div class="settings-control-desc" style="margin-top: 8px;">
            <strong>Preimage Hash:</strong> <code style="color: var(--text-secondary);">${preimageHash}</code>
          </div>
          <div class="result-body-container" style="font-size: 0.8rem; margin-top: 8px; max-width: 100%;">
            <div style="color: var(--accent-orange); font-weight: 600; margin-bottom: 4px;">ForgetProof CBOR Envelope:</div>
            ${mockCborHex}
          </div>
        </div>
        <div class="result-verdict">
          <span class="tier-badge shredded" style="background-color: hsla(24, 90%, 50%, 0.15); color: var(--accent-orange); border-color: hsla(24, 90%, 50%, 0.25);">SHREDDED</span>
          <span class="receipt-badge" data-testid="forget-proof-status" style="background-color: hsla(142, 70%, 45%, 0.15); color: var(--accent-green); border-color: hsla(142, 70%, 45%, 0.25);">
            <svg class="receipt-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            Verified Proof
          </span>
        </div>
      `;
      forgetResultsGrid.appendChild(card);
      forgetResultsArea.classList.remove('hidden');
    }, 500);
  });

  // --- Settings Policy State Management ---
  const savedMinTier = localStorage.getItem('mneme_default_min_tier') || 'quarantine';
  defaultMinTier.value = savedMinTier;

  defaultMinTier.addEventListener('change', () => {
    localStorage.setItem('mneme_default_min_tier', defaultMinTier.value);
  });
});
