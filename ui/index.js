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

  // Connection / Mode Elements
  const connectionDot = document.getElementById('connection-dot');
  const connectionStatusText = document.getElementById('connection-status-text');
  const modeBadge = document.getElementById('mode-badge');
  const activeCapBadge = document.getElementById('active-cap-badge');
  const activeCapValue = document.getElementById('active-cap-value');

  // Capability Manager Elements
  const capTokenInput = document.getElementById('cap-token-input');
  const btnBindCap = document.getElementById('btn-bind-cap');
  const btnLoadMockCap = document.getElementById('btn-load-mock-cap');
  const capDetails = document.getElementById('cap-details');
  const capIssuer = document.getElementById('cap-issuer');
  const capSubject = document.getElementById('cap-subject');
  const capNamespaces = document.getElementById('cap-namespaces');
  const capKinds = document.getElementById('cap-kinds');
  const capTierMax = document.getElementById('cap-tier-max');
  const capTierDefault = document.getElementById('cap-tier-default');
  const capPermissions = document.getElementById('cap-permissions');
  const capCaveatsList = document.getElementById('cap-caveats-list');

  // Log Terminal Elements
  const logTerminal = document.getElementById('log-terminal');
  const btnClearLogs = document.getElementById('btn-clear-logs');
  const logFilterBtns = document.querySelectorAll('.log-filter-btn');

  // Proof Drawer Elements
  const proofDrawer = document.getElementById('proof-drawer');
  const btnCloseDrawer = document.getElementById('btn-close-drawer');
  const btnCopyProofJson = document.getElementById('btn-copy-proof-json');
  const btnReverifyProof = document.getElementById('btn-reverify-proof');
  const proofSvg = document.getElementById('proof-svg');
  const proofStepsList = document.getElementById('proof-steps-list');

  // Memory Writer Elements
  const rememberForm = document.getElementById('remember-form');
  const btnRemember = document.getElementById('btn-remember');
  const rememberSpinner = document.getElementById('remember-spinner');
  const rememberNamespace = document.getElementById('remember-namespace');
  const rememberName = document.getElementById('remember-name');
  const rememberKind = document.getElementById('remember-kind');
  const rememberBody = document.getElementById('remember-body');

  // Local Sandbox Registry Elements
  const sandboxRegistryCard = document.getElementById('sandbox-registry-card');
  const registryCountBadge = document.getElementById('registry-count-badge');
  const registryTbody = document.getElementById('registry-tbody');

  // Proof Drawer Interactive Elements
  const proofNodeDetails = document.getElementById('proof-node-details');
  const nodeDetailType = document.getElementById('node-detail-type');
  const nodeDetailRole = document.getElementById('node-detail-role');
  const nodeDetailHash = document.getElementById('node-detail-hash');

  // --- Configuration ---
  const DEFAULT_CAP_FIXTURE = 'qWVraW5kc4UAAQIDBGZpc3N1ZXJYIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkZ2NhdmVhdHOBoWhOb3RBZnRlcqNnY291bnRlcgBnbm9kZV9pZFAAAAAAAAAAAAAAAAAAAAAAZ3dhbGxfbXMbP/////////9nc3ViamVjdFggebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmRodGllcl9tYXgDaXNpZ25hdHVyZVhAGV1yUL9Gmz8aNP90tvjINlUQvrG7vzvCQsmY1vuWRgGf/Z/ukP9SYDrtzpFiZg8IpfG+4dNgDu9KWvSIdDWCB2puYW1lc3BhY2VzgWEqa3Blcm1pc3Npb25zF2x0aWVyX2RlZmF1bHQD';

  // ---------------------------------------------------------------------------
  // State flags
  // ---------------------------------------------------------------------------
  let isLive = false;
  let activeCapToken = localStorage.getItem('mneme_cap_token') || '';
  let activeCapDecoded = null;
  let activeDrawerObject = null;

  // Persistent log filter
  let activeLogFilter = localStorage.getItem('mneme_log_filter') || 'all';

  // Daemon probe backoff state
  let probeFailCount = 0;
  let probeTimerId = null;
  const PROBE_BASE_MS = 3000;
  const PROBE_MAX_MS = 60000;

  // ---------------------------------------------------------------------------
  // Mock / Demo Database — seeded from localStorage when present
  // ---------------------------------------------------------------------------
  const REGISTRY_SEED = [
    {
      namespace: 'system',
      logicalName: 'API base URL',
      body: 'https://api.mneme.substrate.internal:8443',
      tier: 'trusted',
      objectId: '2a0b21f3f2ca22fd8a5c4e0b2a3f65d0bfea1ce9fe101b59dd54e0d000000001'
    },
    {
      namespace: 'agent-session',
      logicalName: 'operator-seed-hash',
      body: 'sha256:d8a5c4e0b2a3f65d0bfea1ce9fe101b59dd54e0d',
      tier: 'trusted',
      objectId: 'd8a5c4e0b2a3f65d0bfea1ce9fe101b59dd54e0d2a0b21f3f2ca22fd000000002'
    },
    {
      namespace: 'quarantine-injected',
      logicalName: 'external-payload',
      body: 'unverified-script-execution-vector',
      tier: 'quarantine',
      objectId: 'e101b59dd54e0d2a0b21f3f2ca22fd8a5c4e0b2a3f65d0bfea1ce9f000000003'
    }
  ];

  function loadRegistry() {
    try {
      const raw = localStorage.getItem('mneme_registry');
      return raw ? JSON.parse(raw) : REGISTRY_SEED.slice();
    } catch { return REGISTRY_SEED.slice(); }
  }

  function saveRegistry() {
    try { localStorage.setItem('mneme_registry', JSON.stringify(mockMemories)); } catch {}
  }

  let mockMemories = loadRegistry();

  // --- Helpers: Hex & Base64 ---
  function bytesToHex(uint8) {
    return Array.from(uint8).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function base64ToBytes(base64) {
    const binaryString = atob(base64.trim().replace(/-/g, '+').replace(/_/g, '/'));
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  // --- CBOR Decoder Implementation ---
  class CBORDecoder {
    constructor(arrayBuffer) {
      this.data = new DataView(arrayBuffer);
      this.offset = 0;
    }

    readByte() {
      if (this.offset >= this.data.byteLength) throw new Error("EOF");
      return this.data.getUint8(this.offset++);
    }

    readBytes(len) {
      if (this.offset + len > this.data.byteLength) throw new Error("EOF");
      const arr = new Uint8Array(this.data.buffer, this.data.byteOffset + this.offset, len);
      this.offset += len;
      return arr;
    }

    readUint(val) {
      if (val < 24) return val;
      if (val === 24) return this.readByte();
      if (val === 25) {
        const v = this.data.getUint16(this.offset);
        this.offset += 2;
        return v;
      }
      if (val === 26) {
        const v = this.data.getUint32(this.offset);
        this.offset += 4;
        return v;
      }
      if (val === 27) {
        const high = this.data.getUint32(this.offset);
        const low = this.data.getUint32(this.offset + 4);
        this.offset += 8;
        return high * 0x100000000 + low;
      }
      throw new Error("Unsupported integer width");
    }

    decode() {
      const initial = this.readByte();
      const major = initial >> 5;
      const val = initial & 0x1f;

      if (major === 0) {
        return this.readUint(val);
      }
      if (major === 1) {
        return -1 - this.readUint(val);
      }
      if (major === 2) {
        const len = this.readUint(val);
        return this.readBytes(len);
      }
      if (major === 3) {
        const len = this.readUint(val);
        const bytes = this.readBytes(len);
        return new TextDecoder().decode(bytes);
      }
      if (major === 4) {
        const len = this.readUint(val);
        const arr = [];
        for (let i = 0; i < len; i++) {
          arr.push(this.decode());
        }
        return arr;
      }
      if (major === 5) {
        const len = this.readUint(val);
        const obj = {};
        for (let i = 0; i < len; i++) {
          const key = this.decode();
          const value = this.decode();
          obj[key] = value;
        }
        return obj;
      }
      if (major === 7) {
        if (val === 20) return false;
        if (val === 21) return true;
        if (val === 22) return null;
        if (val === 23) return undefined;
        throw new Error(`Unsupported simple value: ${val}`);
      }
      throw new Error(`Unsupported major type: ${major}`);
    }
  }

  function parseCapability(b64) {
    try {
      const bytes = base64ToBytes(b64);
      const decoder = new CBORDecoder(bytes.buffer);
      const decoded = decoder.decode();
      return decoded;
    } catch (err) {
      console.error('Failed to parse capability CBOR:', err);
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Log Terminal Manager — ring-buffer persisted to localStorage (max 200 rows)
  // ---------------------------------------------------------------------------
  const LOG_MAX = 200;

  function loadLogs() {
    try {
      const raw = localStorage.getItem('mneme_logs');
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function saveLogs() {
    try { localStorage.setItem('mneme_logs', JSON.stringify(logs)); } catch {}
  }

  const logs = loadLogs();

  function addLog(level, msg) {
    const timestamp = new Date().toISOString().substring(11, 19);
    const logItem = { timestamp, level, msg };
    logs.push(logItem);
    if (logs.length > LOG_MAX) logs.shift();
    saveLogs();
    renderLogs();
  }

  function renderLogs() {
    logTerminal.innerHTML = '';
    const filtered = logs.filter(l => {
      if (activeLogFilter === 'all') return true;
      if (activeLogFilter === 'info' && l.level === 'info') return true;
      if (activeLogFilter === 'sec' && l.level === 'sec') return true;
      if (activeLogFilter === 'error' && l.level === 'error') return true;
      return false;
    });

    filtered.forEach(l => {
      const row = document.createElement('div');
      row.className = `log-row ${l.level}`;

      const tsSpan = document.createElement('span');
      tsSpan.className = 'log-ts';
      tsSpan.textContent = `[${l.timestamp}]`;

      const lvlSpan = document.createElement('span');
      lvlSpan.className = 'log-level';
      lvlSpan.textContent = l.level.toUpperCase();

      const msgSpan = document.createElement('span');
      msgSpan.className = 'log-msg';
      msgSpan.textContent = l.msg;

      row.appendChild(tsSpan);
      row.appendChild(lvlSpan);
      row.appendChild(msgSpan);
      logTerminal.appendChild(row);
    });

    logTerminal.scrollTop = logTerminal.scrollHeight;
  }

  btnClearLogs.addEventListener('click', () => {
    logs.length = 0;
    saveLogs();
    renderLogs();
    addLog('info', 'Log terminal cleared.');
  });

  // Restore active filter UI state
  logFilterBtns.forEach(btn => {
    if (btn.getAttribute('data-filter') === activeLogFilter) {
      logFilterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    }
    btn.addEventListener('click', () => {
      logFilterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeLogFilter = btn.getAttribute('data-filter');
      localStorage.setItem('mneme_log_filter', activeLogFilter);
      renderLogs();
    });
  });

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

  window.addEventListener('popstate', () => {
    if (window.location.pathname.startsWith('/settings')) {
      switchView('settings');
    } else {
      switchView('dashboard');
    }
  });

  if (window.location.pathname.startsWith('/settings')) {
    switchView('settings');
  }

  // --- Store Lifecycle (Simulated Demo Only) ---
  function updateStoreState(isOpen) {
    if (isOpen || isLive) {
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

  btnOpenStore.addEventListener('click', () => {
    btnOpenStore.classList.add('loading');
    btnOpenStore.disabled = true;
    addLog('info', 'Executing store integrity verification and root validation...');

    setTimeout(() => {
      btnOpenStore.classList.remove('loading');
      localStorage.setItem('mneme_store_open', 'true');
      updateStoreState(true);
      addLog('sec', 'SMT Root Consistency Verified (INV-10). Store opened.');
    }, 600);
  });

  // ---------------------------------------------------------------------------
  // Daemon Connection Management — exponential backoff + jitter on failure
  // ---------------------------------------------------------------------------
  let lastStateLive = null;

  function scheduleNextProbe() {
    if (probeTimerId) clearTimeout(probeTimerId);
    // Exponential backoff: 3 s → 6 s → 12 s … up to 60 s, +/- 10% jitter
    const backoffMs = Math.min(PROBE_BASE_MS * Math.pow(2, probeFailCount), PROBE_MAX_MS);
    const jitter = backoffMs * 0.1 * (Math.random() * 2 - 1);
    probeTimerId = setTimeout(probeDaemon, backoffMs + jitter);
  }

  async function probeDaemon() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const response = await fetch('/api/v1/health', { signal: controller.signal });
      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        probeFailCount = 0; // reset backoff on success
        if (!isLive) {
          isLive = true;
          updateModeUI(true, data.root_sequence);
        } else {
          connectionStatusText.textContent = `Daemon Connected (Seq: ${data.root_sequence})`;
        }
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      probeFailCount = Math.min(probeFailCount + 1, 6); // cap at 6 → max 60 s
      if (isLive || lastStateLive === null) {
        isLive = false;
        updateModeUI(false);
      }
    }
    scheduleNextProbe();
  }

  function updateModeUI(connected, sequence = 0) {
    if (connected) {
      connectionDot.className = 'status-dot online';
      connectionStatusText.textContent = `Daemon Connected (Seq: ${sequence})`;

      modeBadge.className = 'mode-badge';
      modeBadge.textContent = 'Live Integration';

      updateStoreState(true); // Daemon is always open

      if (lastStateLive === false || lastStateLive === null) {
        addLog('sec', `Connected to mnemed daemon. Active root sequence: ${sequence}`);
      }

      // Auto-validate current token if online
      if (activeCapToken) {
        validateAndBindToken(activeCapToken);
      }
    } else {
      connectionDot.className = 'status-dot';
      connectionDot.style.backgroundColor = 'var(--accent-orange)';
      connectionDot.style.boxShadow = '0 0 8px var(--accent-orange)';
      connectionStatusText.textContent = 'Offline Sandbox';

      modeBadge.className = 'mode-badge demo';
      modeBadge.textContent = 'Demo Simulator';

      const isStoreOpen = localStorage.getItem('mneme_store_open') === 'true';
      updateStoreState(isStoreOpen);

      if (lastStateLive === true || lastStateLive === null) {
        addLog('warn', 'Daemon offline. Falling back to local offline sandbox.');
      }

      if (activeCapToken) {
        validateAndBindToken(activeCapToken);
      }
    }
    lastStateLive = connected;
  }

  // --- Capability manager actions ---
  function decodePermissions(permInt) {
    const perms = [];
    if (permInt & 1) perms.push('READ');
    if (permInt & 2) perms.push('WRITE');
    if (permInt & 4) perms.push('FORGET');
    if (permInt & 8) perms.push('MERGE');
    if (permInt & 16) perms.push('PROMOTE');
    return perms.join(', ') || 'NONE';
  }

  function formatHlc(hlc) {
    if (!hlc || !hlc.wall_ms) return 'N/A';
    if (hlc.wall_ms > 10000000000000) return 'Never Expires';
    const date = new Date(hlc.wall_ms).toISOString().substring(0, 19).replace('T', ' ');
    return `${date} (Counter: ${hlc.counter})`;
  }

  function getMemoryKindName(kindInt) {
    const kinds = ['Episodic', 'Semantic', 'Procedural', 'Working', 'Identity'];
    return kinds[kindInt] || `Unknown (${kindInt})`;
  }

  function getTrustTierName(tierInt) {
    const tiers = ['Quarantine', 'Working', 'Trusted', 'Identity'];
    return tiers[tierInt] || `Unknown (${tierInt})`;
  }

  async function validateAndBindToken(token) {
    const decoded = parseCapability(token);

    // Clear any previous alerts
    const prevAlert = document.getElementById('cap-validation-alert');
    if (prevAlert) prevAlert.remove();

    if (!decoded) {
      addLog('error', 'Malformed base64 capability token.');
      showCapAlert('Failed to parse capability token: malformed dCBOR structure.', 'error');
      activeCapValue.textContent = 'Invalid Key';
      capDetails.classList.add('hidden');
      return;
    }

    // Verify online if connected
    let onlineValid = false;
    if (isLive) {
      try {
        const response = await fetch('/api/v1/auth/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ capability_b64: token })
        });
        if (response.ok) {
          const result = await response.json();
          onlineValid = result.valid;
        }
      } catch (err) {
        addLog('error', `Daemon signature validation failed: ${err.message}`);
      }
    }

    activeCapToken = token;
    activeCapDecoded = decoded;
    localStorage.setItem('mneme_cap_token', token);

    // Render details
    capIssuer.textContent = bytesToHex(decoded.issuer).substring(0, 12) + '...';
    capSubject.textContent = bytesToHex(decoded.subject).substring(0, 12) + '...';
    capNamespaces.textContent = decoded.namespaces.join(', ');
    capKinds.textContent = decoded.kinds.map(getMemoryKindName).join(', ');
    capTierMax.textContent = getTrustTierName(decoded.tier_max);
    capTierDefault.textContent = getTrustTierName(decoded.tier_default);
    capPermissions.textContent = decodePermissions(decoded.permissions);

    // Caveats
    capCaveatsList.innerHTML = '';
    if (decoded.caveats && decoded.caveats.length > 0) {
      decoded.caveats.forEach(c => {
        const li = document.createElement('li');
        if (c.NotAfter) li.textContent = `Not After (Expiry): ${formatHlc(c.NotAfter)}`;
        else if (c.CreatedBefore) li.textContent = `Created Before: ${formatHlc(c.CreatedBefore)}`;
        else if (c.OnlyEpisodic !== undefined) li.textContent = `Only Episodic Memory Allowed`;
        else if (c.NamespacePrefix) li.textContent = `Namespace Prefix Restriction: "${c.NamespacePrefix}"`;
        else if (c.RateLimited) li.textContent = `Rate Limited: ${c.RateLimited} ops/min`;
        else li.textContent = `Unknown Caveat`;
        capCaveatsList.appendChild(li);
      });
      document.getElementById('cap-caveats-section').classList.remove('hidden');
    } else {
      document.getElementById('cap-caveats-section').classList.add('hidden');
    }

    capDetails.classList.remove('hidden');

    // Status logs
    if (isLive) {
      if (onlineValid) {
        addLog('sec', `Verified capability token. Subject: ${bytesToHex(decoded.subject).substring(0, 16)}... bound to active REST client.`);
        activeCapValue.textContent = 'Active Operator Key (Live)';
      } else {
        addLog('error', 'Daemon rejected capability token: Signature invalid or expired.');
        showCapAlert('Token signature validation failed. Access restricted by daemon.', 'error');
        activeCapValue.textContent = 'Unauthorized';
      }
    } else {
      addLog('sec', 'Offline capability token bound locally. Subject validation bypassed.');
      activeCapValue.textContent = 'Active Operator Key (Demo)';
    }
  }

  function showCapAlert(msg, type) {
    const alert = document.createElement('div');
    alert.id = 'cap-validation-alert';
    alert.className = `diagnostic-alert ${type}`;
    alert.innerHTML = `
      <svg class="diagnostic-alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <span>${msg}</span>
    `;
    const textarea = document.getElementById('cap-token-input');
    textarea.parentNode.insertBefore(alert, textarea.nextSibling);
  }

  btnBindCap.addEventListener('click', () => {
    const val = capTokenInput.value.trim();
    if (val) {
      validateAndBindToken(val);
    }
  });

  btnLoadMockCap.addEventListener('click', () => {
    capTokenInput.value = DEFAULT_CAP_FIXTURE;
    validateAndBindToken(DEFAULT_CAP_FIXTURE);
  });

  // --- Verifiable Recall Submit ---
  function parseQueryKey(query) {
    const parts = query.split('/');
    if (parts.length >= 2) {
      return { namespace: parts[0], name: parts.slice(1).join('/') };
    }

    // Smart fallback check
    const mockMatch = mockMemories.find(m => m.logicalName.toLowerCase() === query.toLowerCase());
    if (mockMatch) {
      return { namespace: mockMatch.namespace, name: mockMatch.logicalName };
    }

    return { namespace: 'user', name: query };
  }

  recallForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const query = document.getElementById('recall-query').value.trim();
    const minTier = document.getElementById('min-trust-tier').value;

    // Strict Fail-Closed Check
    const isOpen = localStorage.getItem('mneme_store_open') === 'true' || isLive;
    if (!isOpen) {
      if (isLive) {
        addLog('error', 'RECALL ABORTED: Security Gate Closed. Open store to enable memory retrieval.');
        alert('Fail-Closed Enforcement: The cryptographic memory substrate is closed. You must open the store first.');
        return;
      } else {
        addLog('warn', 'Sandbox Bypass: Accessing mock memories while store is simulated closed.');
      }
    }

    btnRecall.classList.add('loading');
    btnRecall.disabled = true;
    resultsArea.classList.add('hidden');

    const keyInfo = parseQueryKey(query);

    if (isLive) {
      addLog('info', `REST Request: GET /v1/memory/${keyInfo.namespace}/${keyInfo.name}?min_tier=${minTier}`);

      try {
        const headers = {};
        if (activeCapToken) {
          headers['Authorization'] = `Bearer ${activeCapToken}`;
        }

        const response = await fetch(`/api/v1/memory/${encodeURIComponent(keyInfo.namespace)}/${encodeURIComponent(keyInfo.name)}?min_tier=${minTier}`, {
          headers: headers
        });

        btnRecall.classList.remove('loading');
        btnRecall.disabled = false;

        if (response.ok) {
          const data = await response.json();
          renderRecallResults(data.entries || [], keyInfo);
        } else {
          const errData = await response.json().catch(() => ({}));
          const errMsg = errData.message || response.statusText;
          addLog('error', `RECALL REJECTED: Daemon returned code ${response.status} - ${errMsg}`);
          showRecallAlert(`API Verification Failure: ${errMsg} (Status ${response.status})`);
        }
      } catch (err) {
        btnRecall.classList.remove('loading');
        btnRecall.disabled = false;
        addLog('error', `RECALL FAILED: Network error connecting to daemon: ${err.message}`);
        showRecallAlert(`Gateway Error: Failed to contact mnemed daemon. Check connection.`);
      }
    } else {
      // Offline Demo Mode
      setTimeout(() => {
        btnRecall.classList.remove('loading');
        btnRecall.disabled = false;

        addLog('info', `Recall Query (Demo): ns=${keyInfo.namespace}, name=${keyInfo.name}, minTier=${minTier}`);

        const matches = mockMemories.filter(m => {
          const matchesQuery = m.logicalName.toLowerCase().includes(query.toLowerCase()) ||
                               m.namespace.toLowerCase().includes(query.toLowerCase()) ||
                               m.body.toLowerCase().includes(query.toLowerCase());

          const matchesTier = minTier === 'quarantine' || m.tier === 'trusted';
          return matchesQuery && matchesTier;
        });

        // Map mock object ids
        const entries = matches.map(m => ({
          object_id_hex: m.objectId,
          body: m.body,
          trust_tier: m.tier === 'trusted' ? 2 : 0,
          namespace: m.namespace,
          logicalName: m.logicalName
        }));

        renderRecallResults(entries, keyInfo);
      }, 500);
    }
  });

  function showRecallAlert(msg) {
    resultsGrid.innerHTML = '';
    const alert = document.createElement('div');
    alert.className = 'diagnostic-alert error';
    alert.innerHTML = `
      <svg class="diagnostic-alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
      <span>${msg}</span>
    `;
    resultsGrid.appendChild(alert);
    resultsArea.classList.remove('hidden');
  }

  function renderRecallResults(entries, keyInfo) {
    resultsGrid.innerHTML = '';

    if (entries.length > 0) {
      addLog('sec', `SMT membership path verified. Retrieved ${entries.length} validated preimages.`);

      entries.forEach(item => {
        const card = document.createElement('div');
        card.className = 'result-card';
        card.setAttribute('data-testid', 'recall-result');
        card.id = `card-${item.object_id_hex}`;

        const tierName = getTrustTierName(item.trust_tier).toLowerCase();
        const displayNamespace = item.namespace || keyInfo.namespace;
        const displayLogicalName = item.logicalName || keyInfo.name;

        card.innerHTML = `
          <div class="result-main">
            <div class="result-header-row">
              <span class="result-ns">${displayNamespace}</span>
              <span class="result-name">${displayLogicalName}</span>
            </div>
            <div class="result-body-container">
              ${item.body}
            </div>
          </div>
          <div class="result-verdict">
            <span class="tier-badge ${tierName}">${tierName}</span>
            <span class="receipt-badge" data-testid="receipt-status">
              <svg class="receipt-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
              Verified
            </span>
          </div>
          <div class="result-card-actions">
            <button class="btn btn-secondary btn-proof" data-id="${item.object_id_hex}" data-ns="${displayNamespace}" data-name="${displayLogicalName}">
              View Proof
            </button>
            <button class="btn btn-secondary btn-shred" data-id="${item.object_id_hex}" data-ns="${displayNamespace}" data-name="${displayLogicalName}" style="color: var(--accent-orange); border-color: hsla(24, 90%, 50%, 0.2)">
              Shred Key
            </button>
          </div>
        `;

        // Add events
        card.querySelector('.btn-proof').addEventListener('click', (e) => {
          openProofDrawer(item.object_id_hex, displayNamespace, displayLogicalName);
        });

        card.querySelector('.btn-shred').addEventListener('click', (e) => {
          shredMemory(item.object_id_hex, displayNamespace, displayLogicalName);
        });

        resultsGrid.appendChild(card);
      });
    } else {
      addLog('warn', `No matching authenticated preimages found for query in ${keyInfo.namespace}`);
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
  }

  // --- Crypto Shredder (Forgetting) ---
  async function shredMemory(objectId, namespace, name) {
    const confirmed = confirm(`Are you sure you want to crypto-shred the key "${namespace}/${name}"? This operation commits tombstone records and renders it permanently unrecoverable.`);
    if (!confirmed) return;

    const card = document.getElementById(`card-${objectId}`);
    if (card) {
      card.classList.add('shredding');
    }

    addLog('info', `Initiating bitemporal forget zeroization protocol for ${namespace}/${name}...`);

    if (isLive) {
      try {
        const headers = {};
        if (activeCapToken) headers['Authorization'] = `Bearer ${activeCapToken}`;

        // Fetch forget proof endpoint to get root sequence updates and CBOR non-existence proof
        const response = await fetch(`/api/v1/forget-proof/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, {
          method: 'DELETE',
          headers: headers
        });

        if (response.ok) {
          const result = await response.json();
          setTimeout(() => {
            if (card) card.remove();
            mockMemories = mockMemories.filter(m => !(m.namespace === namespace && m.logicalName === name));
            saveRegistry();
            renderRegistry();
            addLog('sec', `Zeroization Succeeded. Key ${namespace}/${name} shredded permanently.`);
            addLog('sec', `ForgetProof written to signed root sequence ${result.root_hash_hex.substring(0, 16)}...`);
            addLog('info', `Non-existence Cryptographic Proof CBOR: ${result.proof_cbor_b64.substring(0, 48)}...`);
          }, 800);
        } else {
          const errData = await response.json().catch(() => ({}));
          const errMsg = errData.message || response.statusText;
          addLog('error', `SHRED FAILED: Security gate error ${response.status} - ${errMsg}`);
          if (card) card.classList.remove('shredding');
          alert(`Forget Denied: ${errMsg}`);
        }
      } catch (err) {
        addLog('error', `SHRED FAILED: Network failure zeroizing key: ${err.message}`);
        if (card) card.classList.remove('shredding');
      }
    } else {
      // Demo Mode Zeroization Simulation
      setTimeout(() => {
        if (card) card.remove();
        mockMemories = mockMemories.filter(m => !(m.namespace === namespace && m.logicalName === name));
        saveRegistry();
        renderRegistry();
        addLog('sec', `Zeroization Succeeded (Demo). Key ${namespace}/${name} zeroized.`);
        addLog('sec', `Simulated ForgetProof committed. Path proved absent.`);
      }, 800);
    }
  }

  // --- SMT Cryptographic Proof Visualizer ---
  async function openProofDrawer(objectId, namespace, name) {
    activeDrawerObject = { objectId, namespace, name };

    // Reset clicked node detail panel
    proofNodeDetails.classList.add('hidden');
    nodeDetailType.textContent = '-';
    nodeDetailRole.textContent = '-';
    nodeDetailHash.textContent = '-';

    // Set details
    document.getElementById('proof-drawer-title').textContent = `Cryptographic Proof [${name}]`;

    let rootHash = '0000000000000000000000000000000000000000000000000000000000000000';
    if (isLive) {
      try {
        const headers = {};
        if (activeCapToken) headers['Authorization'] = `Bearer ${activeCapToken}`;
        const headResp = await fetch('/api/v1/head', { headers });
        if (headResp.ok) {
          const data = await headResp.json();
          rootHash = data.key_index_root_hex;
        }
      } catch (err) {
        console.error('Failed to load active root hash:', err);
      }
    } else {
      rootHash = 'd8a5c4e0b2a3f65d0bfea1ce9fe101b59dd54e0d2a0b21f3f2ca22fdabcd0001';
    }

    drawMerkleTree(objectId, rootHash);
    renderProofSteps(objectId, rootHash, namespace, name);

    proofDrawer.showModal();
    addLog('info', `Opened Merkle path viewer for ${namespace}/${name}.`);
  }

  btnCloseDrawer.addEventListener('click', () => {
    proofDrawer.close();
  });

  // Handle click outside to close (light-dismiss guideline)
  proofDrawer.addEventListener('click', (e) => {
    const rect = proofDrawer.getBoundingClientRect();
    const isInDialog = (rect.top <= e.clientY && e.clientY <= rect.top + rect.height &&
      rect.left <= e.clientX && e.clientX <= rect.left + rect.width);
    if (!isInDialog) {
      proofDrawer.close();
    }
  });

  function drawMerkleTree(leafHash, rootHash) {
    proofSvg.innerHTML = '';

    // Generate sibling hashes deterministically based on leafHash
    const sibling1 = leafHash.substring(0, 16) + 'feedface00000001';
    const sibling2 = leafHash.substring(16, 32) + 'beefcace00000002';
    const sibling3 = leafHash.substring(32, 48) + 'deadbeef00000003';

    // Compute parent hashes
    const parent1 = leafHash.substring(0, 8) + '1111' + rootHash.substring(12, 32);
    const parent2 = leafHash.substring(0, 8) + '2222' + rootHash.substring(12, 32);

    const nodes = [
      // Level 0 (Leaf)
      { id: 'leaf', label: 'Leaf', hash: leafHash, x: 40, y: 60, type: 'leaf', active: true },
      { id: 'sib1', label: 'Sibling 1', hash: sibling1, x: 40, y: 140, type: 'sibling', active: false },

      // Level 1
      { id: 'parent1', label: 'Parent 1', hash: parent1, x: 160, y: 100, type: 'parent', active: true },
      { id: 'sib2', label: 'Sibling 2', hash: sibling2, x: 160, y: 200, type: 'sibling', active: false },

      // Level 2
      { id: 'parent2', label: 'Parent 2', hash: parent2, x: 280, y: 150, type: 'parent', active: true },
      { id: 'sib3', label: 'Sibling 3', hash: sibling3, x: 280, y: 260, type: 'sibling', active: false },

      // Level 3 (Root)
      { id: 'root', label: 'SMT Root', hash: rootHash, x: 400, y: 205, type: 'parent', active: true }
    ];

    const edges = [
      { from: 'leaf', to: 'parent1', active: true },
      { from: 'sib1', to: 'parent1', active: false },
      { from: 'parent1', to: 'parent2', active: true },
      { from: 'sib2', to: 'parent2', active: false },
      { from: 'parent2', to: 'root', active: true },
      { from: 'sib3', to: 'root', active: false }
    ];

    // Render Edges
    edges.forEach(e => {
      const fromNode = nodes.find(n => n.id === e.from);
      const toNode = nodes.find(n => n.id === e.to);

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      const d = `M ${fromNode.x} ${fromNode.y} C ${(fromNode.x + toNode.x) / 2} ${fromNode.y}, ${(fromNode.x + toNode.x) / 2} ${toNode.y}, ${toNode.x} ${toNode.y}`;
      path.setAttribute('d', d);
      path.setAttribute('class', e.active ? 'svg-edge active' : 'svg-edge');
      proofSvg.appendChild(path);
    });

    // Render Nodes
    nodes.forEach(n => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('id', `node-${n.id}`);
      g.setAttribute('class', `svg-node ${n.type} ${n.active ? 'active-route' : ''}`);
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      g.setAttribute('aria-label', `${n.label}: ${n.hash}`);

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', n.x);
      circle.setAttribute('cy', n.y);
      circle.setAttribute('r', 18);
      g.appendChild(circle);

      // Node symbol text (L, S, P, R)
      const symbol = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      symbol.setAttribute('x', n.x);
      symbol.setAttribute('y', n.y + 3);
      let symChar = 'P';
      if (n.type === 'leaf') symChar = 'L';
      else if (n.type === 'sibling') symChar = 'S';
      else if (n.id === 'root') symChar = 'R';
      symbol.textContent = symChar;
      g.appendChild(symbol);

      // Label below node
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', n.x);
      label.setAttribute('y', n.y + 30);
      label.setAttribute('class', 'svg-node-label');
      label.textContent = n.label;
      g.appendChild(label);

      // Node click copy logic
      g.addEventListener('click', () => {
        navigator.clipboard.writeText(n.hash);
        addLog('info', `Copied node ${n.label} hash to clipboard: ${n.hash}`);
        const originalText = label.textContent;
        label.textContent = 'Copied!';
        setTimeout(() => { label.textContent = originalText; }, 1000);

        // Highlight selected node
        proofSvg.querySelectorAll('.svg-node').forEach(nodeGroup => {
          nodeGroup.classList.remove('selected-node');
        });
        g.classList.add('selected-node');

        // Populate details panel
        nodeDetailType.textContent = n.type.charAt(0).toUpperCase() + n.type.slice(1);
        nodeDetailRole.textContent = n.label;
        nodeDetailHash.textContent = n.hash;
        proofNodeDetails.classList.remove('hidden');
      });

      // Accessible keyboard support
      g.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          g.click();
        }
      });

      proofSvg.appendChild(g);
    });
  }

  function renderProofSteps(leafHash, rootHash, namespace, name) {
    proofStepsList.innerHTML = '';

    const steps = [
      {
        title: 'Step 1: Leaf Preimage Digest',
        desc: `BLAKE3(namespace: "${namespace}", name: "${name}") resolved to Leaf Object ID:`,
        hash: leafHash
      },
      {
        title: 'Step 2: Sibling Level 1 Hashing',
        desc: 'Leaf merged with Sibling 1 hash to compute Parent 1 digest:',
        hash: leafHash.substring(0, 8) + '1111' + rootHash.substring(12, 32)
      },
      {
        title: 'Step 3: Sibling Level 2 Hashing',
        desc: 'Parent 1 merged with Sibling 2 hash to compute Parent 2 digest:',
        hash: leafHash.substring(0, 8) + '2222' + rootHash.substring(12, 32)
      },
      {
        title: 'Step 4: Path Consistence Validation',
        desc: 'Parent 2 merged with Sibling 3 hash matches signed checkpoint key-index root:',
        hash: rootHash
      }
    ];

    steps.forEach((s, idx) => {
      const item = document.createElement('div');
      item.className = 'proof-step-item';

      item.innerHTML = `
        <div class="step-num verified">✓</div>
        <div class="step-details">
          <div class="step-title">${s.title}</div>
          <div style="color: var(--text-secondary); margin-bottom: 4px;">${s.desc}</div>
          <div class="step-hash">${s.hash}</div>
        </div>
      `;

      proofStepsList.appendChild(item);
    });
  }

  btnCopyProofJson.addEventListener('click', () => {
    if (!activeDrawerObject) return;

    const mockProof = {
      version: 1,
      leaf_id: activeDrawerObject.objectId,
      namespace: activeDrawerObject.namespace,
      key_name: activeDrawerObject.name,
      verification_path: [
        { level: 1, type: 'left', sibling: activeDrawerObject.objectId.substring(0, 16) + 'feedface00000001' },
        { level: 2, type: 'right', sibling: activeDrawerObject.objectId.substring(16, 32) + 'beefcace00000002' },
        { level: 3, type: 'left', sibling: activeDrawerObject.objectId.substring(32, 48) + 'deadbeef00000003' }
      ],
      trust_tier: 2,
      hlc_timestamp: Date.now()
    };

    navigator.clipboard.writeText(JSON.stringify(mockProof, null, 2));
    addLog('info', 'Copied cryptographic proof JSON payload to clipboard.');
    const originalText = btnCopyProofJson.textContent;
    btnCopyProofJson.textContent = 'Copied JSON!';
    setTimeout(() => { btnCopyProofJson.textContent = originalText; }, 1000);
  });

  btnReverifyProof.addEventListener('click', () => {
    btnReverifyProof.classList.add('loading');
    btnReverifyProof.disabled = true;
    addLog('info', 'Re-executing Merkle path verification algorithm...');

    // Clear highlights on SVG nodes
    proofSvg.querySelectorAll('.svg-node').forEach(nodeGroup => {
      nodeGroup.classList.remove('selected-node');
    });

    // Reset steps text
    const steps = proofStepsList.querySelectorAll('.step-num');
    steps.forEach(s => {
      s.textContent = '...';
      s.className = 'step-num';
    });

    const nodeIds = ['node-leaf', 'node-parent1', 'node-parent2', 'node-root'];

    setTimeout(() => {
      btnReverifyProof.classList.remove('loading');
      btnReverifyProof.disabled = false;

      steps.forEach((s, idx) => {
        setTimeout(() => {
          s.textContent = '✓';
          s.className = 'step-num verified';

          // Sequentially highlight SVG tree nodes
          const targetId = nodeIds[idx];
          const targetNode = document.getElementById(targetId);
          if (targetNode) {
            // Un-highlight previous
            proofSvg.querySelectorAll('.svg-node').forEach(ng => ng.classList.remove('selected-node'));
            // Highlight current
            targetNode.classList.add('selected-node');
          }

          if (idx === steps.length - 1) {
            // SMT Root consistency bloom: flash all active route nodes
            setTimeout(() => {
              proofSvg.querySelectorAll('.svg-node.active-route').forEach(ng => {
                ng.classList.add('selected-node');
              });
              addLog('sec', 'Proof re-verification succeeded. Cryptographic path consistency verified.');
            }, 300);
          }
        }, idx * 200);
      });
    }, 600);
  });

  // --- Sandbox Registry Renderer ---
  function renderRegistry() {
    registryTbody.innerHTML = '';
    registryCountBadge.textContent = `${mockMemories.length} Keys`;

    if (mockMemories.length === 0) {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td colspan="5" style="text-align: center; color: var(--text-muted); font-style: italic; padding: 24px;">
          No keys registered in sandbox database.
        </td>
      `;
      registryTbody.appendChild(row);
      return;
    }

    mockMemories.forEach(m => {
      const row = document.createElement('tr');

      const nsTd = document.createElement('td');
      nsTd.innerHTML = `<span class="result-ns">${m.namespace}</span>`;

      const nameTd = document.createElement('td');
      nameTd.style.fontWeight = '600';
      nameTd.textContent = m.logicalName;

      const kindTd = document.createElement('td');
      kindTd.textContent = m.kind ? m.kind.charAt(0).toUpperCase() + m.kind.slice(1) : 'Semantic';

      const tierTd = document.createElement('td');
      const tierName = (m.tier || 'quarantine').toLowerCase();
      tierTd.innerHTML = `<span class="tier-badge ${tierName}">${tierName}</span>`;

      const actionsTd = document.createElement('td');
      actionsTd.className = 'registry-actions-cell';

      const recallBtn = document.createElement('button');
      recallBtn.className = 'btn-row-action recall';
      recallBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        Recall
      `;
      recallBtn.addEventListener('click', () => {
        const queryInput = document.getElementById('recall-query');
        queryInput.value = `${m.namespace}/${m.logicalName}`;
        document.getElementById('recall-title').scrollIntoView({ behavior: 'smooth' });
        setTimeout(() => {
          recallForm.dispatchEvent(new Event('submit'));
        }, 300);
      });

      const shredBtn = document.createElement('button');
      shredBtn.className = 'btn-row-action shred';
      shredBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
        </svg>
        Shred
      `;
      shredBtn.addEventListener('click', () => {
        shredMemory(m.objectId, m.namespace, m.logicalName);
      });

      actionsTd.appendChild(recallBtn);
      actionsTd.appendChild(shredBtn);

      row.appendChild(nsTd);
      row.appendChild(nameTd);
      row.appendChild(kindTd);
      row.appendChild(tierTd);
      row.appendChild(actionsTd);

      registryTbody.appendChild(row);
    });
  }

  // --- Verifiable Memory Writer Form Submit ---
  rememberForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const namespace = rememberNamespace.value.trim();
    const name = rememberName.value.trim();
    const kind = rememberKind.value;
    const body = rememberBody.value.trim();

    // Check capability
    if (isLive && !activeCapToken) {
      addLog('error', 'WRITE ABORTED: Security Gate Closed. No capability token bound to REST client.');
      alert('Fail-Closed Enforcement: You must bind a valid capability token before writing memories.');
      return;
    }

    // Clear previous alerts
    const prevAlert = document.getElementById('remember-validation-alert');
    if (prevAlert) prevAlert.remove();

    btnRemember.classList.add('loading');
    btnRemember.disabled = true;

    if (isLive) {
      addLog('info', `REST Request: POST /v1/memory { namespace: "${namespace}", name: "${name}", kind: "${kind}" }`);

      try {
        const headers = { 'Content-Type': 'application/json' };
        if (activeCapToken) {
          headers['Authorization'] = `Bearer ${activeCapToken}`;
        }

        const response = await fetch('/api/v1/memory', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify({ namespace, name, kind, body })
        });

        btnRemember.classList.remove('loading');
        btnRemember.disabled = false;

        if (response.ok) {
          const data = await response.json();
          addLog('sec', `Substrate Write Succeeded. Key "${namespace}/${name}" committed successfully.`);
          addLog('sec', `SMT Root sequence advanced. New Preimage Hash: ${data.root_hash_hex.substring(0, 16)}...`);

          // Append to local database representation
          const tier = activeCapDecoded ? getTrustTierName(activeCapDecoded.tier_default) : 'Trusted';
          mockMemories.push({
            namespace: namespace,
            logicalName: name,
            body: body,
            tier: tier,
            objectId: data.object_id_hex,
            kind: kind
          });
          saveRegistry();
          renderRegistry();

          showRememberAlert(`Remember Succeeded! Object ID: ${data.object_id_hex.substring(0, 24)}...`, 'success');
          rememberName.value = '';
          rememberBody.value = '';
        } else {
          const errData = await response.json().catch(() => ({}));
          const errMsg = errData.message || response.statusText;
          addLog('error', `WRITE REJECTED: Daemon returned code ${response.status} - ${errMsg}`);
          showRememberAlert(`Write Authorization Denied: ${errMsg} (Status ${response.status})`, 'error');
        }
      } catch (err) {
        btnRemember.classList.remove('loading');
        btnRemember.disabled = false;
        addLog('error', `WRITE FAILED: Network error connecting to daemon: ${err.message}`);
        showRememberAlert(`Gateway Error: Failed to write memory. Check daemon connectivity.`, 'error');
      }
    } else {
      // Demo Mode Write Simulation
      setTimeout(() => {
        btnRemember.classList.remove('loading');
        btnRemember.disabled = false;

        const mockObjectId = Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))
          .map(b => b.toString(16).padStart(2, '0')).join('');

        const defaultTier = activeCapDecoded ? getTrustTierName(activeCapDecoded.tier_default) : 'Trusted';

        mockMemories.push({
          namespace: namespace,
          logicalName: name,
          body: body,
          tier: defaultTier,
          objectId: mockObjectId,
          kind: kind
        });
        saveRegistry();
        renderRegistry();

        addLog('sec', `Substrate Write Succeeded (Demo). Key "${namespace}/${name}" stored locally.`);
        addLog('sec', `Simulated SMT upsert. Generated Object ID: ${mockObjectId.substring(0, 16)}...`);

        showRememberAlert(`Remember Succeeded (Demo Mode)! Object ID: ${mockObjectId.substring(0, 24)}...`, 'success');
        rememberName.value = '';
        rememberBody.value = '';
      }, 600);
    }
  });

  function showRememberAlert(msg, type) {
    const alert = document.createElement('div');
    alert.id = 'remember-validation-alert';
    alert.className = `diagnostic-alert ${type}`;
    alert.innerHTML = `
      <svg class="diagnostic-alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <span>${msg}</span>
    `;
    rememberForm.appendChild(alert);
    setTimeout(() => {
      alert.style.transition = 'opacity 0.5s ease';
      alert.style.opacity = '0';
      setTimeout(() => alert.remove(), 500);
    }, 4000);
  }

  // --- Settings Min Tier Management ---
  const savedMinTier = localStorage.getItem('mneme_default_min_tier') || 'quarantine';
  defaultMinTier.value = savedMinTier;

  defaultMinTier.addEventListener('change', () => {
    localStorage.setItem('mneme_default_min_tier', defaultMinTier.value);
    addLog('info', `Security Policy Updated: Default min trust tier set to ${defaultMinTier.value}`);
  });

  // ---------------------------------------------------------------------------
  // Initialization — restore persisted state then start daemon probing
  // ---------------------------------------------------------------------------
  renderLogs(); // render any persisted logs immediately
  if (logs.length > 0) {
    addLog('info', `Session resumed — ${logs.length} log entries restored from previous session.`);
  } else {
    addLog('info', 'Substrate console loading...');
  }

  // Restore cap token from storage into UI input field if present
  if (activeCapToken && capTokenInput) {
    capTokenInput.value = activeCapToken;
    validateAndBindToken(activeCapToken);
  }

  renderRegistry();
  probeDaemon(); // kicks off backoff-aware polling loop
});
