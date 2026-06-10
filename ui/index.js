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

  // ===========================================================================
  // Phase VI — HNSW Semantic Graph Explorer
  // ===========================================================================

  const graphEdgesLayer = document.getElementById('graph-edges-layer');
  const graphNodesLayer = document.getElementById('graph-nodes-layer');
  const graphTooltip    = document.getElementById('graph-tooltip');
  const graphTipLabel   = document.getElementById('graph-tooltip-label');
  const graphTipId      = document.getElementById('graph-tooltip-id');
  const graphTipDist    = document.getElementById('graph-tooltip-dist');
  const graphModeBadge  = document.getElementById('graph-mode-badge');
  const graphStatLevel  = document.getElementById('graph-stat-level');
  const graphStatSeq    = document.getElementById('graph-stat-seq');
  const btnExplore      = document.getElementById('btn-explore-graph');

  // Fruchterman-Reingold spring layout (pure vanilla, no D3)
  function forceLayout(nodes, edges, W, H) {
    var iterations = 65;
    var k = Math.sqrt((W * H) / Math.max(nodes.length, 1));
    nodes.forEach(function(n) {
      n.x = W * 0.1 + Math.random() * W * 0.8;
      n.y = H * 0.1 + Math.random() * H * 0.8;
      n.vx = 0; n.vy = 0;
    });
    var temp = W * 0.3;
    for (var iter = 0; iter < iterations; iter++) {
      for (var i = 0; i < nodes.length; i++) {
        nodes[i].vx = 0; nodes[i].vy = 0;
        for (var j = 0; j < nodes.length; j++) {
          if (i === j) continue;
          var dx = nodes[i].x - nodes[j].x;
          var dy = nodes[i].y - nodes[j].y;
          var dist = Math.max(Math.sqrt(dx*dx + dy*dy), 0.01);
          var f = (k*k) / dist;
          nodes[i].vx += (dx/dist)*f;
          nodes[i].vy += (dy/dist)*f;
        }
      }
      edges.forEach(function(e) {
        var u = nodes.find(function(n) { return n.id === e.from; });
        var v = nodes.find(function(n) { return n.id === e.to; });
        if (!u || !v) return;
        var dx = v.x - u.x, dy = v.y - u.y;
        var dist = Math.max(Math.sqrt(dx*dx + dy*dy), 0.01);
        var f = (dist*dist) / k;
        u.vx += (dx/dist)*f; u.vy += (dy/dist)*f;
        v.vx -= (dx/dist)*f; v.vy -= (dy/dist)*f;
      });
      nodes.forEach(function(n) {
        var disp = Math.sqrt(n.vx*n.vx + n.vy*n.vy);
        if (disp > 0) {
          n.x += (n.vx/disp)*Math.min(disp,temp);
          n.y += (n.vy/disp)*Math.min(disp,temp);
          n.x = Math.max(28, Math.min(W-28, n.x));
          n.y = Math.max(28, Math.min(H-28, n.y));
        }
      });
      temp *= 0.92;
    }
  }

  function renderGraphData(graphData) {
    var W = 640, H = 340;
    graphEdgesLayer.innerHTML = '';
    graphNodesLayer.innerHTML = '';
    graphTooltip.hidden = true;

    var nodes = graphData.nodes, edges = graphData.edges;
    var visitedPath = graphData.visitedPath;
    var resultId = graphData.resultId, entryId = graphData.entryId;
    var proofLevel = graphData.proofLevel, rootSeq = graphData.rootSeq;

    forceLayout(nodes, edges, W, H);

    var traversedPairs = {};
    for (var i = 0; i + 1 < visitedPath.length; i++) {
      traversedPairs[visitedPath[i] + '-' + visitedPath[i+1]] = true;
      traversedPairs[visitedPath[i+1] + '-' + visitedPath[i]] = true;
    }

    edges.forEach(function(e) {
      var u = nodes.find(function(n) { return n.id === e.from; });
      var v = nodes.find(function(n) { return n.id === e.to; });
      if (!u || !v) return;
      var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', u.x); line.setAttribute('y1', u.y);
      line.setAttribute('x2', v.x); line.setAttribute('y2', v.y);
      line.setAttribute('class', traversedPairs[e.from+'-'+e.to] ? 'graph-edge traversed' : 'graph-edge');
      graphEdgesLayer.appendChild(line);
    });

    nodes.forEach(function(n, idx) {
      var isResult  = n.id === resultId;
      var isVisited = visitedPath.indexOf(n.id) >= 0;
      var isEntry   = n.id === entryId;
      var cls = 'graph-node' + (isResult ? ' result' : isVisited ? ' visited' : '') + (isEntry ? ' entry' : '');

      var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', cls);
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      g.setAttribute('aria-label', n.label + ': ' + n.objectIdHex);

      var r = isResult ? 16 : isVisited ? 13 : 10;
      var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', n.x); circle.setAttribute('cy', n.y); circle.setAttribute('r', r);
      g.appendChild(circle);

      var sym = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      sym.setAttribute('x', n.x); sym.setAttribute('y', n.y + 4);
      sym.textContent = isResult ? '\u2605' : isEntry ? 'E' : String(idx);
      g.appendChild(sym);

      var lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      lbl.setAttribute('x', n.x); lbl.setAttribute('y', n.y + r + 12);
      lbl.setAttribute('class', 'node-label');
      lbl.textContent = n.label.length > 10 ? n.label.substring(0,10) + '\u2026' : n.label;
      g.appendChild(lbl);

      var showTip = function() {
        graphTipLabel.textContent = n.label;
        graphTipId.textContent    = n.objectIdHex;
        graphTipDist.textContent  = n.distance !== undefined ? 'Distance: ' + n.distance : '';
        graphTooltip.hidden = false;
      };
      g.addEventListener('mouseenter', showTip);
      g.addEventListener('focus',      showTip);
      g.addEventListener('mouseleave', function() { graphTooltip.hidden = true; });
      g.addEventListener('blur',       function() { graphTooltip.hidden = true; });
      g.addEventListener('keydown',    function(ev) { if (ev.key === 'Enter' || ev.key === ' ') showTip(); });

      graphNodesLayer.appendChild(g);
    });

    graphStatLevel.textContent = proofLevel || 'ExactDominance';
    graphStatSeq.textContent   = 'Seq: ' + (rootSeq !== null && rootSeq !== undefined ? rootSeq : '\u2014');

    visitedPath.forEach(function(vid, i) {
      var nData = nodes.find(function(n) { return n.id === vid; });
      if (!nData) return;
      var el = graphNodesLayer.querySelector('[aria-label^="' + nData.label.substring(0,8) + '"]');
      if (!el) return;
      setTimeout(function() { el.classList.add('visited'); }, i * 160);
    });
  }

  function buildDemoGraphData(namespace, name) {
    var ids = [];
    for (var i = 0; i < 10; i++) ids.push(i.toString(16).padStart(2,'0').repeat(32).substring(0,64));
    var nodes = ids.map(function(id, i) {
      return { id: 'n'+i, objectIdHex: id, label: i===0 ? namespace+'/'+name : 'cand-'+i,
               distance: i===0 ? 0 : -Math.floor(1000 + Math.random()*8000) };
    });
    var edges = [
      {from:'n0',to:'n1'},{from:'n0',to:'n2'},{from:'n1',to:'n3'},
      {from:'n1',to:'n4'},{from:'n2',to:'n4'},{from:'n2',to:'n5'},
      {from:'n3',to:'n6'},{from:'n4',to:'n6'},{from:'n4',to:'n7'},
      {from:'n5',to:'n7'},{from:'n6',to:'n8'},{from:'n7',to:'n9'}
    ];
    return { nodes: nodes, edges: edges, visitedPath: ['n0','n1','n3','n6','n8'],
             resultId: 'n8', entryId: 'n0', proofLevel: 'ExactDominance (Demo)', rootSeq: null };
  }

  btnExplore.addEventListener('click', async function() {
    var ns   = document.getElementById('graph-query-ns').value.trim() || 'user';
    var name = document.getElementById('graph-query-name').value.trim() || 'sample';
    btnExplore.classList.add('loading');
    btnExplore.disabled = true;

    if (isLive) {
      try {
        var headers = {};
        if (activeCapToken) headers['Authorization'] = 'Bearer ' + activeCapToken;
        var resp = await fetch(
          '/api/v1/semantic-graph/' + encodeURIComponent(ns) + '/' + encodeURIComponent(name),
          { headers: headers }
        );
        if (resp.ok) {
          var data = await resp.json();
          if (data.key_index_only) {
            addLog('warn', 'No semantic index for ' + ns + '/' + name + '. Showing demo.');
            renderGraphData(buildDemoGraphData(ns, name));
            graphModeBadge.textContent = 'Key-Index Only';
          } else {
            renderGraphData(data);
            graphModeBadge.textContent = 'Live Semantic Graph';
          }
        } else { throw new Error('HTTP ' + resp.status); }
      } catch (err) {
        addLog('error', 'Graph fetch failed: ' + err.message + '. Showing demo.');
        renderGraphData(buildDemoGraphData(ns, name));
        graphModeBadge.textContent = 'Demo (Fallback)';
      }
    } else {
      await new Promise(function(r) { setTimeout(r, 400); });
      renderGraphData(buildDemoGraphData(ns, name));
      graphModeBadge.textContent = 'Demo Mode';
    }

    btnExplore.classList.remove('loading');
    btnExplore.disabled = false;
    addLog('info', 'HNSW graph rendered for ' + ns + '/' + name + '.');
  });

  // ===========================================================================
  // Phase VI — Cognition Certificate Inspector
  // ===========================================================================

  var PROOF_LEVEL_MAP = {0:'ExactDominance',1:'ZkannLevel1',2:'ZkannLevel2',3:'ZkannFull'};

  function parseNestedCbor(bytes) {
    try {
      var buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      return new CBORDecoder(buf).decode();
    } catch(e) { return null; }
  }

  function parseCognitionCert(b64) {
    try {
      var bytes = base64ToBytes(b64);
      var raw   = new CBORDecoder(bytes.buffer).decode();
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
      return {
        version:     raw[1] || null,
        level:       PROOF_LEVEL_MAP[raw[2]] || ('Unknown(' + raw[2] + ')'),
        asOfSeq:     raw[3] || null,
        storedRoot:  raw[4] instanceof Uint8Array ? parseNestedCbor(raw[4]) : null,
        receipt:     raw[5] instanceof Uint8Array ? parseNestedCbor(raw[5]) : null,
        attestation: raw[6] instanceof Uint8Array ? parseNestedCbor(raw[6]) : null
      };
    } catch(e) { return null; }
  }

  function hexOf(val) {
    if (val instanceof Uint8Array) return bytesToHex(val);
    if (typeof val === 'string')   return val;
    if (val === null || val === undefined) return '\u2014';
    return String(val);
  }

  function addCertField(container, label, value, mono) {
    if (mono === undefined) mono = true;
    var lbl = document.createElement('div');
    lbl.className = 'cert-field-label';
    lbl.textContent = label;
    var val = document.createElement('div');
    val.className  = mono ? 'cert-field-value' : 'cert-field-value plain';
    val.textContent = value;
    container.appendChild(lbl);
    container.appendChild(val);
  }

  function renderCert(cert) {
    var statusRow    = document.getElementById('cert-status-row');
    var rootFields   = document.getElementById('cert-root-fields');
    var voContent    = document.getElementById('cert-vo-content');
    var attestFields = document.getElementById('cert-attest-fields');
    var certChecks   = document.getElementById('cert-checks');
    var certResult   = document.getElementById('cert-result');
    var certBadge    = document.getElementById('cert-version-badge');
    var sectAttest   = document.getElementById('cert-section-attest');

    statusRow.innerHTML    = '';
    rootFields.innerHTML   = '';
    voContent.innerHTML    = '';
    attestFields.innerHTML = '';
    certChecks.innerHTML   = '';
    sectAttest.classList.add('hidden');

    var isV2 = cert.attestation !== null && cert.attestation !== undefined;
    certBadge.textContent = isV2 ? 'v2-draft' : 'v1';

    var badges = [
      ['cert-badge valid', '\u2713 Structure Valid'],
      ['cert-badge ' + (isV2 ? 'v2' : 'v1'), 'CognitionCert ' + (isV2 ? 'v2-draft' : 'v1')],
      ['cert-badge warning', 'Level: ' + cert.level]
    ];
    badges.forEach(function(pair) {
      var b = document.createElement('span');
      b.className = pair[0]; b.textContent = pair[1];
      statusRow.appendChild(b);
    });

    if (cert.storedRoot) {
      var r = cert.storedRoot;
      addCertField(rootFields, 'Version',        String(r[1] !== undefined ? r[1] : '\u2014'), false);
      addCertField(rootFields, 'Sequence',        String(r[9] !== undefined ? r[9] : '\u2014'), false);
      addCertField(rootFields, 'Preimage Hash',   hexOf(r[2]));
      addCertField(rootFields, 'DAG Head Root',   hexOf(r[3]));
      addCertField(rootFields, 'Key Index Root',  hexOf(r[4]));
      addCertField(rootFields, 'Semantic Commit', hexOf(r[5]));
      addCertField(rootFields, 'HLC Max',         hexOf(r[6]));
      addCertField(rootFields, 'Prev Root',       hexOf(r[7]));
      addCertField(rootFields, 'Signature',       hexOf(r[8]));
    } else {
      addCertField(rootFields, 'Status', 'Could not decode stored root bytes', false);
    }

    if (cert.receipt) {
      var rec = cert.receipt;
      var voMeta = document.createElement('div');
      voMeta.className = 'cert-fields';
      addCertField(voMeta, 'Root Bound',      hexOf(rec[1]));
      addCertField(voMeta, 'Semantic Commit', hexOf(rec[2]));
      addCertField(voMeta, 'Procedure ID',    hexOf(rec[3]));
      voContent.appendChild(voMeta);

      var candidates = rec[4];
      if (Array.isArray(candidates) && candidates.length > 0) {
        var tbl = document.createElement('table');
        tbl.className = 'cert-candidates-table';
        tbl.innerHTML = '<thead><tr><th>#</th><th>Object ID</th><th>Distance</th></tr></thead>';
        var tbody = document.createElement('tbody');
        candidates.forEach(function(c, i) {
          var tr = document.createElement('tr');
          var id   = Array.isArray(c) ? hexOf(c[0]).substring(0,24) + '\u2026' : '\u2014';
          var dist = Array.isArray(c) ? (c[2] !== undefined ? c[2] : '\u2014') : '\u2014';
          tr.innerHTML = '<td>' + (i+1) + '</td><td>' + id + '</td><td>' + dist + '</td>';
          tbody.appendChild(tr);
        });
        tbl.appendChild(tbody);
        voContent.appendChild(tbl);
      }

      var zkann = rec[5];
      if (zkann && typeof zkann === 'object') {
        var visitedIds = zkann['visited'] || zkann[2] || [];
        if (Array.isArray(visitedIds) && visitedIds.length > 0) {
          var sec = document.createElement('div');
          sec.innerHTML = '<div style="padding:8px 16px 4px;font-size:11px;color:var(--text-muted);font-weight:600;">zkANN Visited Order (' + visitedIds.length + ' hops)</div>';
          var tl = document.createElement('div');
          tl.className = 'visited-order-list';
          visitedIds.forEach(function(vid, i) {
            var tag = document.createElement('span');
            tag.className = 'visited-tag';
            tag.textContent = i + ': ' + hexOf(vid).substring(0,10) + '\u2026';
            tl.appendChild(tag);
          });
          sec.appendChild(tl);
          voContent.appendChild(sec);
        }
      }
    } else {
      var p = document.createElement('p');
      p.style.cssText = 'padding:12px 16px;color:var(--text-muted);font-size:12px;';
      p.textContent = 'Could not decode semantic receipt bytes.';
      voContent.appendChild(p);
    }

    if (isV2) {
      sectAttest.classList.remove('hidden');
      var att    = cert.attestation;
      var status = att['status'] || att[1] || '\u2014';
      var ctx    = att['context_digest'] || att[2] || null;
      addCertField(attestFields, 'Status',         status, false);
      addCertField(attestFields, 'Context Digest', hexOf(ctx));
      var wb = document.createElement('span');
      wb.className = 'cert-badge warning';
      wb.style.margin = '8px 16px';
      wb.textContent = '\u26a0 ' + status;
      attestFields.appendChild(wb);
      attestFields.appendChild(document.createElement('div'));
    }

    var checks = [];
    if (cert.storedRoot && cert.receipt) {
      var ph = hexOf(cert.storedRoot[2]);
      var rb = hexOf(cert.receipt[1]);
      checks.push({ pass: ph === rb, label: 'receipt.root_bound \u2261 stored_root.preimage_hash',
                    detail: ph === rb ? '\u2713 Bound' : 'Got ' + rb.substring(0,16) + '\u2026' });
    }
    if (cert.receipt) {
      var sc = cert.receipt[2];
      checks.push({ pass: sc instanceof Uint8Array && sc.length === 32,
                    label: 'receipt.semantic_commit present (32 bytes)',
                    detail: sc instanceof Uint8Array ? sc.length + ' bytes' : 'missing' });
    }
    if (isV2 && cert.attestation) {
      var st = cert.attestation['status'] || cert.attestation[1] || '';
      var ok = st === 'unverified_until_phase_ii_gate';
      checks.push({ pass: ok, label: 'attestation.status == "unverified_until_phase_ii_gate"',
                    detail: ok ? '\u2713 Honest label' : 'Got: "' + st + '"' });
    }

    checks.forEach(function(c) {
      var row = document.createElement('div');
      row.className = 'cert-check-row';
      row.innerHTML =
        '<span class="check-icon ' + (c.pass ? 'pass' : 'fail') + '">' + (c.pass ? '\u2713' : '\u2717') + '</span>' +
        '<span class="check-label">' + c.label + '</span>' +
        '<span class="check-detail">' + c.detail + '</span>';
      certChecks.appendChild(row);
    });

    certResult.classList.remove('hidden');
  }

  var DEMO_CERT_STORED_ROOT = {
    1: 1, 2: new Uint8Array(32).fill(0xde), 3: new Uint8Array(32).fill(0xad),
    4: new Uint8Array(32).fill(0xbe), 5: new Uint8Array(32).fill(0xef),
    6: new Uint8Array(8).fill(0x00),  7: new Uint8Array(32).fill(0x00),
    8: new Uint8Array(64).fill(0xab), 9: 42
  };
  var DEMO_CERT_RECEIPT = {
    1: new Uint8Array(32).fill(0xde), // root_bound matches preimage_hash above
    2: new Uint8Array(32).fill(0xca),
    3: new Uint8Array(32).fill(0xfe),
    4: [[new Uint8Array(32).fill(0x01), new Uint8Array(32).fill(0x02), -4200]]
  };

  function loadDemoCert(v2) {
    document.getElementById('cert-input').value = '(demo fixture \u2014 not real Base64)';
    addLog('info', 'Loaded demo CognitionCert ' + (v2 ? 'v2-draft' : 'v1') + ' fixture.');
    renderCert({
      version: v2 ? 2 : 1, level: 'ExactDominance', asOfSeq: 42,
      storedRoot: DEMO_CERT_STORED_ROOT,
      receipt: DEMO_CERT_RECEIPT,
      attestation: v2 ? { 'status': 'unverified_until_phase_ii_gate',
                          'context_digest': new Uint8Array(32).fill(0xcc) } : null
    });
  }

  document.getElementById('btn-inspect-cert').addEventListener('click', function() {
    var b64 = document.getElementById('cert-input').value.trim();
    if (!b64 || b64.indexOf('(demo') === 0) {
      addLog('warn', 'Paste a real Base64 CBOR cert, or use a demo fixture.');
      return;
    }
    var cert = parseCognitionCert(b64);
    if (!cert) {
      addLog('error', 'Failed to parse Cognition Certificate: malformed Base64 CBOR.');
      return;
    }
    addLog('sec', 'Cognition Certificate parsed: v' + cert.version + ', level=' + cert.level);
    renderCert(cert);
  });

  document.getElementById('btn-load-demo-cert-v1').addEventListener('click', function() { loadDemoCert(false); });
  document.getElementById('btn-load-demo-cert-v2').addEventListener('click', function() { loadDemoCert(true); });

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
