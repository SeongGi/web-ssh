// Global Fetch Interceptor to redirect 401 Unauthorized to login page
const originalFetch = window.fetch;
window.fetch = async function(...args) {
  const res = await originalFetch(...args);
  if (res.status === 401 && !window.location.pathname.endsWith('/login.html')) {
    window.location.href = '/login.html';
  }
  return res;
};

// Application State
let servers = [];
let activeTerminal = null;
let activeSocket = null;
let resizeHandler = null;
let currentConnectingServerId = null;

// DOM Elements
const serverGrid = document.getElementById('server-grid');
const addServerBtn = document.getElementById('add-server-btn');
const refreshAllBtn = document.getElementById('refresh-all-status');
const serverModal = document.getElementById('server-modal');
const modalCloseBtn = document.getElementById('modal-close-btn');
const modalCancelBtn = document.getElementById('modal-cancel-btn');
const serverForm = document.getElementById('server-form');
const modalTitle = document.getElementById('modal-title');
const authTypeSelect = document.getElementById('server-authType');
const authPasswordSection = document.getElementById('auth-password-section');
const authKeySection = document.getElementById('auth-key-section');
const keyStatusHint = document.getElementById('key-status-hint');

// Terminal DOM Elements
const terminalModal = document.getElementById('terminal-modal');
const terminalCloseBtn = document.getElementById('terminal-close-btn');
const terminalServerTitle = document.getElementById('terminal-server-title');
const terminalClearBtn = document.getElementById('terminal-clear');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  fetchConfig();
  fetchServers();
  setupEventListeners();
  // Initialize Lucide Icons
  lucide.createIcons();
});

// Fetch portal brand configurations
async function fetchConfig() {
  try {
    const res = await fetch('/api/config');
    if (res.ok) {
      const data = await res.json();
      const name = data.portalName || 'Web-SSH Portal';
      document.title = name;
      const brandTitle = document.getElementById('brand-title');
      if (brandTitle) brandTitle.innerText = name;
    }
  } catch (e) {
    console.warn('Failed to load portal config:', e);
  }
}

// Event Listeners Configuration
function setupEventListeners() {
  // Modal toggle
  addServerBtn.addEventListener('click', () => openModal());
  modalCloseBtn.addEventListener('click', closeModal);
  modalCancelBtn.addEventListener('click', closeModal);
  
  // Dynamic Authentication Fields
  authTypeSelect.addEventListener('change', (e) => {
    toggleAuthFields(e.target.value);
  });

  // Form Submit
  serverForm.addEventListener('submit', handleFormSubmit);

  // Status refresh
  refreshAllBtn.addEventListener('click', checkAllServersStatus);

  // Terminal Close
  terminalCloseBtn.addEventListener('click', closeTerminal);
  
  // Terminal Screen Clear
  terminalClearBtn.addEventListener('click', () => {
    if (activeTerminal) activeTerminal.clear();
  });

  // Terminal Exit Overlay Actions
  document.getElementById('btn-reconnect').addEventListener('click', () => {
    document.getElementById('terminal-exit-overlay').classList.add('hidden');
    if (currentConnectingServerId) {
      connectToSSH(currentConnectingServerId);
    }
  });

  document.getElementById('btn-to-dashboard').addEventListener('click', () => {
    document.getElementById('terminal-exit-overlay').classList.add('hidden');
    closeTerminal();
  });

  // Password Modal toggle
  document.getElementById('change-pwd-btn').addEventListener('click', openPwdModal);
  document.getElementById('pwd-close-btn').addEventListener('click', closePwdModal);
  document.getElementById('pwd-cancel-btn').addEventListener('click', closePwdModal);
  document.getElementById('password-form').addEventListener('submit', handlePasswordChange);

  // Logout button
  document.getElementById('logout-btn').addEventListener('click', handleLogout);

  // Scanner Event Listeners
  document.getElementById('btn-ip-scan').addEventListener('click', handleIPScan);
  document.getElementById('btn-system-scan').addEventListener('click', handleSystemScan);

  // Security Audit
  document.getElementById('audit-all-btn').addEventListener('click', auditAllServers);
  document.getElementById('audit-close-btn').addEventListener('click', closeAuditModal);
  document.getElementById('audit-done-btn').addEventListener('click', closeAuditModal);
  document.getElementById('audit-copy-btn').addEventListener('click', copyAuditReport);

  // Escape and backdrop close. Without these, a modal taller than the viewport (a phone
  // in landscape, where no mobile media query applies) put its close button off-screen
  // with no way to scroll to it — a dead end needing a page reload.
  const overlays = [
    { id: 'audit-modal', close: closeAuditModal },
    { id: 'server-modal', close: closeModal },
    { id: 'password-modal', close: closePwdModal }
  ];
  overlays.forEach(({ id, close }) => {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) close();
    });
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    const open = overlays.find(({ id }) => document.getElementById(id)?.classList.contains('active'));
    if (open) open.close();
  });
}

// Fetch Server Profiles
async function fetchServers() {
  try {
    const res = await fetch('/api/servers');
    if (!res.ok) {
      // On 401 the fetch interceptor navigates away, but execution continues here —
      // without this guard `servers` became {error:...} and renderServerCards threw.
      console.warn('Failed to fetch servers: HTTP', res.status);
      return;
    }
    const data = await res.json();
    servers = Array.isArray(data) ? data : [];

    // Update Stats
    document.getElementById('total-servers-count').innerText = servers.length;

    renderServerCards();
    checkAllServersStatus();
  } catch (err) {
    console.error('Failed to fetch servers:', err);
  }
}

// Render Server Cards to UI with Grouping and Collapse toggles
function renderServerCards() {
  serverGrid.innerHTML = '';

  if (servers.length === 0) {
    const addCard = document.createElement('div');
    addCard.className = 'server-card add-card';
    addCard.innerHTML = `
      <div class="add-card-icon">
        <i data-lucide="plus"></i>
      </div>
      <span class="add-card-text">새 서버 등록하기</span>
    `;
    addCard.addEventListener('click', () => openModal());
    serverGrid.appendChild(addCard);
    lucide.createIcons();
    return;
  }

  // Load persistent collapsed group states from localStorage
  const collapsedGroups = JSON.parse(localStorage.getItem('collapsedGroups') || '[]');

  // Group servers by their group name (defaulting to "General")
  const groups = {};
  servers.forEach(server => {
    const groupName = server.group || 'General';
    if (!groups[groupName]) {
      groups[groupName] = [];
    }
    groups[groupName].push(server);
  });

  const groupNames = Object.keys(groups).sort();
  groupNames.forEach((groupName, groupIdx) => {
    const safeGroupId = groupName.replace(/[^a-zA-Z0-9-_]/g, '_');
    const isCollapsed = collapsedGroups.includes(groupName);

    const groupSection = document.createElement('div');
    groupSection.className = 'group-section';

    const groupHeader = document.createElement('h2');
    groupHeader.className = 'group-header';
    // A closure instead of an inline onclick string. setAttribute does no entity
    // decoding, so the handler received the *escaped* name — a group called "A&B"
    // stored "A&amp;B" in localStorage and its collapsed state never restored, and a
    // trailing backslash produced a one-argument call that silently did nothing.
    groupHeader.addEventListener('click', (event) => toggleGroup(groupName, safeGroupId, event));
    groupHeader.innerHTML = `
      <i data-lucide="chevron-down" class="group-chevron ${isCollapsed ? 'collapsed' : ''}" id="chevron-${safeGroupId}"></i>
      <span>${escapeHtml(groupName)}</span>
      <span class="group-header-count">${groups[groupName].length}</span>
    `;

    const grid = document.createElement('div');
    grid.className = 'server-grid' + (isCollapsed ? ' collapsed' : '');
    grid.id = `grid-${safeGroupId}`;

    groups[groupName].forEach(server => {
      const card = document.createElement('div');
      card.className = 'server-card';
      card.id = `server-card-${server.id}`;

      let badgesHtml = '';
      // os/spec are read off the remote host (/etc/os-release, nproc, df), so they are
      // attacker-controlled if any managed server is compromised. Must be escaped.
      if (server.os) badgesHtml += `<span class="badge badge-os">${escapeHtml(server.os)}</span>`;
      if (server.spec) badgesHtml += `<span class="badge badge-spec">${escapeHtml(server.spec)}</span>`;
      badgesHtml += `<span class="badge badge-auth">${server.authType === 'key' ? 'Key File' : 'Password'}</span>`;

      card.innerHTML = `
        <div class="card-header">
          <div class="server-title">
            <h3>${escapeHtml(server.name)}</h3>
            <span class="server-host-info">
              <i data-lucide="server" style="width:12px;height:12px"></i>
              <span>${escapeHtml(server.username)}@${escapeHtml(server.host)}:${server.port}</span>
            </span>
          </div>
          <div class="status-wrapper status-checking" id="status-${server.id}">
            <div class="status-dot"></div>
            <span class="status-text">Checking</span>
          </div>
        </div>

        <div class="card-badges">
          ${badgesHtml}
        </div>

        <div class="card-body">
          <p>${escapeHtml(server.description || '설명이 없습니다.')}</p>
          <div class="specs-toggle-link" onclick="toggleSpecs('${server.id}', event)">
            <i data-lucide="cpu" style="width:12px;height:12px"></i>
            <span>시스템 사양 정보</span>
            <i data-lucide="chevron-right" class="specs-chevron" id="specs-chevron-${server.id}" style="width:12px;height:12px"></i>
          </div>
        </div>

        <div class="card-specs-drawer" id="specs-drawer-${server.id}">
          ${systemInfoHtml(server)}
        </div>

        <div class="card-footer">
          <button class="btn btn-primary btn-connect" onclick="connectToSSH('${server.id}')">
            <i data-lucide="terminal"></i>
            <span>연결하기</span>
          </button>
          <div class="card-actions">
            <button class="btn btn-secondary btn-audit" onclick="auditServer('${server.id}')" title="보안 점검">
              <i data-lucide="shield-check" style="width:14px;height:14px"></i>
              <span>점검</span>
            </button>
            <button class="btn btn-secondary btn-edit" onclick="editServer('${server.id}')">
              <i data-lucide="edit-3" style="width:14px;height:14px"></i>
              <span>수정</span>
            </button>
            <button class="btn btn-secondary btn-delete" onclick="deleteServer('${server.id}')">
              <i data-lucide="trash-2" style="width:14px;height:14px"></i>
              <span>삭제</span>
            </button>
          </div>
        </div>
      `;
      grid.appendChild(card);
    });

    // Append the "+ Add Server" card to the grid of the very last group
    if (groupIdx === groupNames.length - 1) {
      const addCard = document.createElement('div');
      addCard.className = 'server-card add-card';
      addCard.innerHTML = `
        <div class="add-card-icon">
          <i data-lucide="plus"></i>
        </div>
        <span class="add-card-text">새 서버 등록하기</span>
      `;
      addCard.addEventListener('click', () => openModal());
      grid.appendChild(addCard);
    }

    groupSection.appendChild(groupHeader);
    groupSection.appendChild(grid);
    serverGrid.appendChild(groupSection);
  });

  lucide.createIcons();
}

// Asynchronously check online status of all servers
function checkAllServersStatus() {
  servers.forEach(server => {
    const statusContainer = document.getElementById(`status-${server.id}`);
    if (!statusContainer) return;
    
    // Set checking status
    statusContainer.className = 'status-wrapper status-checking';
    statusContainer.querySelector('.status-text').innerText = 'Checking';

    fetch(`/api/servers/${server.id}/ping`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'online') {
          statusContainer.className = 'status-wrapper status-online';
          statusContainer.querySelector('.status-text').innerText = 'Online';
        } else {
          statusContainer.className = 'status-wrapper status-offline';
          statusContainer.querySelector('.status-text').innerText = 'Offline';
        }
        updateOnlineCount();
      })
      .catch(() => {
        statusContainer.className = 'status-wrapper status-offline';
        statusContainer.querySelector('.status-text').innerText = 'Offline';
        updateOnlineCount();
      });
  });
}

function updateOnlineCount() {
  const onlineCount = document.querySelectorAll('.status-online').length;
  document.getElementById('online-servers-count').innerText = onlineCount;
}

// Open Form Modal
function openModal(serverData = null) {
  serverForm.reset();
  
  if (serverData) {
    // Edit Mode
    modalTitle.innerText = 'SSH 서버 설정 수정';
    document.getElementById('server-id').value = serverData.id;
    document.getElementById('server-name').value = serverData.name;
    document.getElementById('server-group').value = serverData.group || '';
    document.getElementById('server-host').value = serverData.host;
    document.getElementById('server-port').value = serverData.port;
    document.getElementById('server-username').value = serverData.username;
    document.getElementById('server-authType').value = serverData.authType;
    document.getElementById('server-os').value = serverData.os || '';
    document.getElementById('server-spec').value = serverData.spec || '';
    document.getElementById('server-description').value = serverData.description || '';
    
    toggleAuthFields(serverData.authType);

    if (serverData.authType === 'key') {
      keyStatusHint.innerText = '기존 등록된 키가 있습니다. 변경하려면 새 PEM 내용을 붙여넣으세요. 비워두면 기존 키를 유지합니다.';
    } else {
      document.getElementById('server-password').value = '';
    }
  } else {
    // Create Mode
    modalTitle.innerText = '새 SSH 서버 등록';
    document.getElementById('server-id').value = '';
    document.getElementById('server-group').value = 'OCI Cloud'; // Default group
    toggleAuthFields('key');
    keyStatusHint.innerText = '서버 접속을 위한 .pem Private Key 파일의 전체 텍스트 내용을 붙여넣으세요.';
  }

  serverModal.classList.add('active');
}

function closeModal() {
  serverModal.classList.remove('active');
}

function toggleAuthFields(type) {
  if (type === 'key') {
    authKeySection.classList.remove('hidden');
    authPasswordSection.classList.add('hidden');
    document.getElementById('server-privateKey').required = !document.getElementById('server-id').value; // required only on creation
  } else {
    authKeySection.classList.add('hidden');
    authPasswordSection.classList.remove('hidden');
    document.getElementById('server-privateKey').required = false;
  }
}

// Handle Form Submit (Add / Edit)
async function handleFormSubmit(e) {
  e.preventDefault();
  
  const id = document.getElementById('server-id').value;
  const formData = new FormData(serverForm);
  const data = Object.fromEntries(formData.entries());
  
  const isEdit = !!id;
  const url = isEdit ? `/api/servers/${id}` : '/api/servers';
  const method = isEdit ? 'PUT' : 'POST';

  try {
    const res = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });
    
    if (res.ok) {
      closeModal();
      fetchServers();
    } else {
      const err = await res.json();
      alert(`저장 실패: ${err.error || '알 수 없는 오류'}`);
    }
  } catch (err) {
    console.error('Submit failed:', err);
    alert('서버 전송 중 오류가 발생했습니다.');
  }
}

// Edit Server Trigger
function editServer(id) {
  const server = servers.find(s => s.id === id);
  if (!server) return;
  openModal(server);
}

// Delete Server Profile
async function deleteServer(id) {
  const server = servers.find(s => s.id === id);
  if (!server) return;

  if (!confirm(`정말로 '${server.name}' 서버 설정을 삭제하시겠습니까?`)) {
    return;
  }

  try {
    const res = await fetch(`/api/servers/${id}`, {
      method: 'DELETE'
    });
    if (res.ok) {
      fetchServers();
    } else {
      alert('삭제에 실패했습니다.');
    }
  } catch (e) {
    console.error('Delete failed:', e);
  }
}

// SSH Connection Logic using xterm.js & WS
function connectToSSH(id) {
  const server = servers.find(s => s.id === id);
  if (!server) return;

  // Always tear down any previous session first — reconnect comes through here too.
  disposeSession();

  currentConnectingServerId = id;

  // Hide exit overlay on fresh connection
  document.getElementById('terminal-exit-overlay').classList.add('hidden');
  document.getElementById('terminal-status-dot').className = 'status-indicator-green pulse';
  document.getElementById('terminal-status-dot').style.backgroundColor = '';

  terminalServerTitle.innerText = `${server.username}@${server.host}:${server.port}`;
  terminalModal.classList.add('active');

  const terminalBody = document.getElementById('terminal-body');
  terminalBody.innerHTML = ''; // Clear container

  // Create terminal
  const term = new Terminal({
    cursorBlink: true,
    // Fira Code has no Hangul glyphs, so Korean fell through to an arbitrary system
    // font. Name real CJK monospace faces so the fallback is predictable.
    fontFamily: '"Fira Code", "D2Coding", "Noto Sans Mono CJK KR", "Apple SD Gothic Neo", "Malgun Gothic", "Courier New", monospace',
    // 14px only yields ~42 columns on a 390px phone.
    fontSize: window.innerWidth < 480 ? 11 : 14,
    theme: {
      background: '#181b2d',
      foreground: '#f8fafc',
      cursor: '#8b5cf6',
      selectionBackground: 'rgba(139, 92, 246, 0.3)',
      black: '#000000',
      red: '#ef4444',
      green: '#10b981',
      yellow: '#f59e0b',
      blue: '#3b82f6',
      magenta: '#8b5cf6',
      cyan: '#06b6d4',
      white: '#f8fafc'
    }
  });

  term.open(terminalBody);
  
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  
  // Wait minor frame to let DOM settle and calculate dimensions accurately
  setTimeout(() => {
    fitAddon.fit();
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ssh?id=${id}&cols=${term.cols}&rows=${term.rows}`;
    const socket = new WebSocket(wsUrl);

    activeTerminal = term;
    activeSocket = socket;

    socket.onopen = () => {
      // Re-fit and re-send geometry here rather than racing it with a timer. The old
      // code fired one corrective resize 50ms after the socket was created, which was
      // usually still CONNECTING, so the readyState guard silently dropped it and the
      // PTY stayed at whatever the initial (often wrong) size was for the whole session.
      fitAddon.fit();
      socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));

      // Connect term handler
      term.onData(data => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'data', data }));
        }
      });
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'data') {
          term.write(msg.data);
        } else if (msg.type === 'status') {
          term.write(`\r\n\x1b[36m[Dashboard] ${msg.message}\x1b[0m\r\n`);
        } else if (msg.type === 'error') {
          term.write(`\r\n\x1b[31m[Connection Error] ${msg.message}\x1b[0m\r\n`);
        }
      } catch (e) {
        // Fallback for non-JSON content
        term.write(event.data);
      }
    };

    socket.onclose = () => {
      term.write('\r\n\x1b[33m[Dashboard] SSH Session Closed.\x1b[0m\r\n');
      
      // Update terminal status header indicator to red (offline)
      const statusDot = document.getElementById('terminal-status-dot');
      if (statusDot) {
        statusDot.className = 'status-indicator-green'; // remove pulse
        statusDot.style.backgroundColor = 'var(--color-offline)';
      }
      
      // Show exit actions overlay
      const exitOverlay = document.getElementById('terminal-exit-overlay');
      if (exitOverlay) {
        exitOverlay.classList.remove('hidden');
        lucide.createIcons();
      }
    };

    socket.onerror = (err) => {
      term.write(`\r\n\x1b[31m[WebSocket Error] Connection failed.\x1b[0m\r\n`);
    };

    // Keep handle of resize event
    const applyViewport = () => {
      // Handle mobile keyboard visual viewport sizing
      if (window.visualViewport) {
        const modal = document.getElementById('terminal-modal');
        modal.style.height = `${window.visualViewport.height}px`;
        modal.style.top = `${window.visualViewport.offsetTop}px`;
      }

      fitAddon.fit();
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
          type: 'resize',
          cols: term.cols,
          rows: term.rows
        }));
      }
    };

    // visualViewport 'scroll' fires continuously while scrolling on mobile, and each
    // firing sent a window-change and forced a full reflow. Debounce it.
    let resizeTimer = null;
    resizeHandler = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(applyViewport, 100);
    };

    window.addEventListener('resize', resizeHandler);
    window.addEventListener('orientationchange', resizeHandler);
    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', resizeHandler);
      window.visualViewport.addEventListener('scroll', resizeHandler);
    }
    applyViewport();
  }, 100);
}

// Tear down the current SSH session without leaving the terminal view.
// Reconnect used to call connectToSSH() directly, which only blanked the container: the
// old Terminal was never disposed and its resize handlers stayed registered on window
// and visualViewport, so every reconnect leaked a terminal and stacked three more live
// listeners firing fit() on a detached instance.
function disposeSession() {
  if (resizeHandler) {
    window.removeEventListener('resize', resizeHandler);
    window.removeEventListener('orientationchange', resizeHandler);
    if (window.visualViewport) {
      window.visualViewport.removeEventListener('resize', resizeHandler);
      window.visualViewport.removeEventListener('scroll', resizeHandler);
    }
    resizeHandler = null;
  }

  // Reset mobile viewport styles
  const modal = document.getElementById('terminal-modal');
  if (modal) {
    modal.style.height = '';
    modal.style.top = '';
  }

  if (activeSocket) {
    activeSocket.onclose = null; // don't let teardown trigger the exit overlay
    activeSocket.close();
    activeSocket = null;
  }

  if (activeTerminal) {
    activeTerminal.dispose();
    activeTerminal = null;
  }
}

// Close SSH Terminal
function closeTerminal() {
  disposeSession();
  terminalModal.classList.remove('active');
  // Refresh server status when returning to dashboard
  checkAllServersStatus();
}

// Helper to escape HTML tags.
// Coerces instead of assuming a string: a number/object reaching the old version threw
// "str.replace is not a function", and because renderServerCards had already cleared
// the grid, one bad stored record left the dashboard permanently blank with no UI to
// delete it. escapeHtml(0) also used to return '' and drop a legitimate value.
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Toggle Collapsible Group
function toggleGroup(groupName, safeGroupId) {
  const grid = document.getElementById(`grid-${safeGroupId}`);
  const chevron = document.getElementById(`chevron-${safeGroupId}`);
  if (!grid || !chevron) return;

  const isCollapsed = grid.classList.toggle('collapsed');
  chevron.classList.toggle('collapsed', isCollapsed);

  let collapsedGroups = JSON.parse(localStorage.getItem('collapsedGroups') || '[]');
  if (isCollapsed) {
    if (!collapsedGroups.includes(groupName)) {
      collapsedGroups.push(groupName);
    }
  } else {
    collapsedGroups = collapsedGroups.filter(g => g !== groupName);
  }
  localStorage.setItem('collapsedGroups', JSON.stringify(collapsedGroups));
}

// IP & SSH Port Scanner
async function handleIPScan() {
  const host = document.getElementById('server-host').value.trim();
  const port = document.getElementById('server-port').value.trim() || '22';
  const ipScanBtn = document.getElementById('btn-ip-scan');

  if (!host) {
    alert('호스트 IP 주소 또는 도메인을 먼저 입력하세요.');
    return;
  }

  const originalText = ipScanBtn.innerText;
  ipScanBtn.innerText = '스캔 중...';
  ipScanBtn.disabled = true;

  try {
    const res = await fetch(`/api/scan-ip?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`);
    const data = await res.json();
    
    if (data.success) {
      document.getElementById('server-os').value = data.guessedOS;
      
      // Visual feedback highlight
      const osInput = document.getElementById('server-os');
      osInput.style.boxShadow = '0 0 15px rgba(6, 182, 212, 0.6)';
      osInput.style.borderColor = 'var(--accent-color)';
      setTimeout(() => {
        osInput.style.boxShadow = '';
        osInput.style.borderColor = '';
      }, 2000);

      alert(`IP 스캔 성공!\n감지된 SSH 배너: ${data.banner}\n운영체제(OS) 입력창에 [${data.guessedOS}]를 설정했습니다.`);
    } else {
      alert(`스캔 실패: ${data.error || 'SSH 포트가 닫혀있거나 연결할 수 없습니다.'}`);
    }
  } catch (err) {
    console.error('IP Scan error:', err);
    alert('스캔 중 통신 오류가 발생했습니다.');
  } finally {
    ipScanBtn.innerText = originalText;
    ipScanBtn.disabled = false;
  }
}

// Deep Credentials Diagnostics & System Specs Scan
async function handleSystemScan() {
  const host = document.getElementById('server-host').value.trim();
  const port = document.getElementById('server-port').value.trim() || '22';
  const username = document.getElementById('server-username').value.trim();
  const authType = document.getElementById('server-authType').value;
  const password = document.getElementById('server-password').value;
  const privateKey = document.getElementById('server-privateKey').value;
  
  const scanBtn = document.getElementById('btn-system-scan');
  const scanStatus = document.getElementById('system-scan-status');

  if (!host || !username) {
    scanStatus.innerHTML = '<span style="color:var(--color-offline)">※ 호스트 IP 및 계정명을 먼저 입력해주세요.</span>';
    return;
  }
  
  if (authType === 'password' && !password) {
    scanStatus.innerHTML = '<span style="color:var(--color-offline)">※ 비밀번호 인증 방식을 위해 패스워드를 입력해주세요.</span>';
    return;
  }
  
  if (authType === 'key' && !privateKey) {
    scanStatus.innerHTML = '<span style="color:var(--color-offline)">※ 키 파일 인증 방식을 위해 Private Key 내용을 입력해주세요.</span>';
    return;
  }

  // Set loading state
  const originalText = document.getElementById('system-scan-text').innerText;
  document.getElementById('system-scan-text').innerText = '진단 및 감지 중...';
  scanBtn.disabled = true;
  scanStatus.innerHTML = '<span style="color:var(--color-warning)">⏳ 서버 연결을 시도하고 시스템 자원을 분석하는 중입니다 (최대 10초)...</span>';

  try {
    const res = await fetch('/api/servers/diagnose', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ host, port, username, authType, password, privateKey })
    });
    
    const data = await res.json();
    
    if (data.success) {
      // Set values
      document.getElementById('server-os').value = data.os || '';
      document.getElementById('server-spec').value = data.spec || '';
      
      // Highlight inputs with a green glow
      const osInput = document.getElementById('server-os');
      const specInput = document.getElementById('server-spec');
      const glow = '0 0 15px rgba(16, 185, 129, 0.6)';
      osInput.style.boxShadow = glow;
      osInput.style.borderColor = 'var(--color-online)';
      specInput.style.boxShadow = glow;
      specInput.style.borderColor = 'var(--color-online)';
      
      setTimeout(() => {
        osInput.style.boxShadow = '';
        osInput.style.borderColor = '';
        specInput.style.boxShadow = '';
        specInput.style.borderColor = '';
      }, 2000);

      scanStatus.innerHTML = '<span style="color:var(--color-online)">✓ 접속 진단 성공! OS 및 하드웨어 스펙 정보를 자동 완성했습니다.</span>';
    } else {
      scanStatus.innerHTML = `<span style="color:var(--color-offline)">❌ 진단 실패: ${escapeHtml(data.error)}</span>`;
    }
  } catch (err) {
    console.error('System diagnose error:', err);
    scanStatus.innerHTML = '<span style="color:var(--color-offline)">❌ 진단 시도 중 통신 에러가 발생했습니다.</span>';
  } finally {
    document.getElementById('system-scan-text').innerText = originalText;
    scanBtn.disabled = false;
  }
}

// Account Profile Change Modal Variables
const passwordModal = document.getElementById('password-modal');
const passwordForm = document.getElementById('password-form');
const pwdErrorContainer = document.getElementById('pwd-error-container');
const pwdErrorText = document.getElementById('pwd-error-text');

async function openPwdModal() {
  passwordForm.reset();
  pwdErrorContainer.classList.add('hidden');
  
  // Pre-populate username (ID) and portal name from server
  try {
    const resProfile = await fetch('/api/profile');
    if (resProfile.ok) {
      const data = await resProfile.json();
      document.getElementById('new-username').value = data.username || 'admin';
    }
    const resConfig = await fetch('/api/config');
    if (resConfig.ok) {
      const data = await resConfig.json();
      document.getElementById('new-portal-name').value = data.portalName || 'Web-SSH Portal';
    }
  } catch (err) {
    console.warn('Failed to load profile details:', err);
    document.getElementById('new-username').value = 'admin';
    document.getElementById('new-portal-name').value = 'Web-SSH Portal';
  }

  passwordModal.classList.add('active');
}

function closePwdModal() {
  passwordModal.classList.remove('active');
}

async function handlePasswordChange(e) {
  e.preventDefault();
  pwdErrorContainer.classList.add('hidden');

  const currentPassword = document.getElementById('current-pwd').value;
  const newUsername = document.getElementById('new-username').value.trim();
  const portalName = document.getElementById('new-portal-name').value.trim();
  const newPassword = document.getElementById('new-pwd').value;
  const confirmPassword = document.getElementById('confirm-pwd').value;

  if (newPassword && newPassword !== confirmPassword) {
    pwdErrorText.innerText = '새 비밀번호와 확인 비밀번호가 일치하지 않습니다.';
    pwdErrorContainer.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch('/api/update-profile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ currentPassword, newUsername, newPassword, portalName })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      alert('계정 및 포털 정보가 성공적으로 변경되었습니다. 다시 로그인해주세요.');
      handleLogout();
    } else {
      pwdErrorText.innerText = data.error || '계정 정보 변경에 실패했습니다.';
      pwdErrorContainer.classList.remove('hidden');
    }
  } catch (err) {
    console.error('Profile update error:', err);
    pwdErrorText.innerText = '계정 정보 변경 처리 중 오류가 발생했습니다.';
    pwdErrorContainer.classList.remove('hidden');
  }
}

async function handleLogout() {
  try {
    await fetch('/api/logout', { method: 'POST' });
  } catch (e) {
    console.warn('Logout request failed:', e);
  } finally {
    window.location.href = '/login.html';
  }
}

// Toggle specifications drawer inside cards
function toggleSpecs(serverId, event) {
  if (event) event.stopPropagation();
  const drawer = document.getElementById(`specs-drawer-${serverId}`);
  const chevron = document.getElementById(`specs-chevron-${serverId}`);
  if (drawer && chevron) {
    const isActive = drawer.classList.toggle('active');
    chevron.classList.toggle('rotated', isActive);
  }
}

// Render HTML for server specifications detail drawer
function systemInfoHtml(server) {
  const info = server.systemInfo;
  if (!info) {
    return `
      <div class="specs-empty">
        <p>수집된 서버 사양 상세 정보가 없습니다.</p>
        <button class="btn btn-secondary btn-xs btn-diagnose-card" onclick="diagnoseServer('${server.id}', event)">
          <i data-lucide="refresh-cw" style="width:12px;height:12px"></i>
          <span>지금 정보 가져오기</span>
        </button>
      </div>
    `;
  }

  return `
    <div class="specs-grid">
      <div class="specs-item">
        <span class="specs-label">CPU 모델</span>
        <span class="specs-value" title="${escapeHtml(info.cpuModel)}">${escapeHtml(info.cpuModel || 'N/A')}</span>
      </div>
      <div class="specs-item">
        <span class="specs-label">코어 수</span>
        <span class="specs-value">${escapeHtml(info.cpuCores || 'N/A')}</span>
      </div>
      <div class="specs-item">
        <span class="specs-label">메모리 (RAM)</span>
        <span class="specs-value">${escapeHtml(info.ramUsed || 'N/A')} / ${escapeHtml(info.ramTotal || 'N/A')}</span>
      </div>
      <div class="specs-item">
        <span class="specs-label">디스크 (SSD/HDD)</span>
        <span class="specs-value">${escapeHtml(info.diskUsed || 'N/A')} / ${escapeHtml(info.diskTotal || 'N/A')} (${escapeHtml(info.diskPercent || 'N/A')})</span>
      </div>
      <div class="specs-item">
        <span class="specs-label">업타임 (Uptime)</span>
        <span class="specs-value">${escapeHtml(info.uptime || 'N/A')}</span>
      </div>
      <div class="specs-item">
        <span class="specs-label">평균 로드율 (1,5,15m)</span>
        <span class="specs-value">${escapeHtml(info.loadAvg || 'N/A')}</span>
      </div>
      <div class="specs-item full-width" style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.05); padding-top:0.5rem; margin-top:0.25rem;">
        <span class="specs-label" style="font-size:0.7rem;">마지막 업데이트: ${escapeHtml(info.lastChecked || 'N/A')}</span>
        <button class="btn btn-secondary btn-xs btn-diagnose-card" onclick="diagnoseServer('${server.id}', event)">
          <i data-lucide="refresh-cw" style="width:10px;height:10px"></i>
          <span>정보 갱신</span>
        </button>
      </div>
    </div>
  `;
}

// Trigger diagnostic scan for an existing server
async function diagnoseServer(serverId, event) {
  if (event) event.stopPropagation();
  
  const card = document.getElementById(`server-card-${serverId}`);
  const drawer = document.getElementById(`specs-drawer-${serverId}`);
  const btn = event ? event.currentTarget : null;
  
  let originalBtnHtml = '';
  if (btn) {
    originalBtnHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="refresh-cw" class="spin" style="width:12px;height:12px"></i> <span>진단 중...</span>';
    lucide.createIcons();
  }

  try {
    const res = await fetch(`/api/servers/${serverId}/diagnose`, {
      method: 'POST'
    });
    
    const data = await res.json();
    
    if (res.ok && data.success) {
      // Find server in local array and update it
      const serverIdx = servers.findIndex(s => s.id === serverId);
      if (serverIdx !== -1) {
        servers[serverIdx].os = data.os;
        servers[serverIdx].spec = data.spec;
        servers[serverIdx].systemInfo = data.systemInfo;
      }
      
      // Re-render only the drawer contents
      if (drawer) {
        drawer.innerHTML = systemInfoHtml(servers[serverIdx]);
      }
      
      // Update badges in the card
      if (card) {
        const badgesContainer = card.querySelector('.card-badges');
        if (badgesContainer) {
          let badgesHtml = '';
          if (data.os) badgesHtml += `<span class="badge badge-os">${escapeHtml(data.os)}</span>`;
          if (data.spec) badgesHtml += `<span class="badge badge-spec">${escapeHtml(data.spec)}</span>`;
          badgesHtml += `<span class="badge badge-auth">${servers[serverIdx].authType === 'key' ? 'Key File' : 'Password'}</span>`;
          badgesContainer.innerHTML = badgesHtml;
        }
        
        // Highlight card with a green success glow
        const glow = '0 0 20px rgba(16, 185, 129, 0.5)';
        card.style.boxShadow = glow;
        card.style.borderColor = 'var(--color-online)';
        setTimeout(() => {
          card.style.boxShadow = '';
          card.style.borderColor = '';
        }, 2000);
      }
      
      lucide.createIcons();
    } else {
      alert(`진단 실패: ${data.error || '알 수 없는 오류가 발생했습니다.'}`);
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalBtnHtml;
        lucide.createIcons();
      }
    }
  } catch (err) {
    console.error('Server diagnose error:', err);
    alert('진단 요청 처리 중 네트워크 오류가 발생했습니다.');
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalBtnHtml;
      lucide.createIcons();
    }
  }
}

/* ==========================================================================
   Security Audit
   ========================================================================== */

const SEVERITY_META = {
  critical: { label: '치명적', className: 'sev-critical', icon: 'octagon-alert' },
  high: { label: '높음', className: 'sev-high', icon: 'alert-triangle' },
  medium: { label: '중간', className: 'sev-medium', icon: 'alert-circle' },
  low: { label: '낮음', className: 'sev-low', icon: 'info' },
  unknown: { label: '확인불가', className: 'sev-unknown', icon: 'help-circle' }
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];

let lastAuditReports = [];
// Guards against overlapping sweeps: a second click used to launch another full set of
// SSH connections, and a single-server audit started mid-sweep would be overwritten by
// the sweep's results under whatever title was on screen.
let auditRunId = 0;
let auditInFlight = false;

// The portal is HTTP/1.1, so the browser caps ~6 requests per origin. Auditing every
// server at once starved /ping, icons and every other request behind 60s SSH probes.
const AUDIT_CONCURRENCY = 3;

function setAuditButtonsDisabled(disabled) {
  const all = document.getElementById('audit-all-btn');
  if (all) all.disabled = disabled;
  document.querySelectorAll('.btn-audit').forEach(b => { b.disabled = disabled; });
}

function openAuditModal(title) {
  document.getElementById('audit-modal-title').innerText = title;
  document.getElementById('audit-modal').classList.add('active');
  // Stale results must not be copyable while a new run is pending.
  lastAuditReports = [];
  document.body.style.overflow = 'hidden';
}

function closeAuditModal() {
  document.getElementById('audit-modal').classList.remove('active');
  document.body.style.overflow = '';
}

function renderAuditPending(names) {
  const rows = names.map(n => `
    <div class="audit-pending-row" id="audit-pending-${escapeHtml(n.id)}">
      <div class="spinner-sm"></div>
      <span>${escapeHtml(n.name)} 점검 중...</span>
    </div>`).join('');
  document.getElementById('audit-body').innerHTML = `<div class="audit-pending">${rows}</div>`;
}

function severityCountsHtml(counts) {
  return SEVERITY_ORDER
    .filter(s => counts[s])
    .map(s => `<span class="sev-pill ${SEVERITY_META[s].className}">${SEVERITY_META[s].label} ${counts[s]}</span>`)
    .join('');
}

function renderAuditReports(reports) {
  const body = document.getElementById('audit-body');

  if (!reports.length) {
    body.innerHTML = '<p class="audit-empty">점검할 서버가 없습니다.</p>';
    return;
  }

  const totals = {};
  reports.filter(r => r.success).forEach(r => {
    SEVERITY_ORDER.forEach(s => { if (r.counts[s]) totals[s] = (totals[s] || 0) + r.counts[s]; });
  });
  const failedCount = reports.filter(r => !r.success).length;

  const summary = `
    <div class="audit-summary">
      <div class="audit-summary-main">
        <span class="audit-summary-count">${reports.length - failedCount}</span>
        <span class="audit-summary-label">대 점검 완료${failedCount ? ` · ${failedCount}대 실패` : ''}</span>
      </div>
      <div class="sev-pills">${severityCountsHtml(totals) || '<span class="sev-pill sev-ok">문제 없음</span>'}</div>
    </div>`;

  const sections = reports.map(report => {
    const name = escapeHtml(report.serverName);
    if (!report.success) {
      return `
        <section class="audit-server">
          <header class="audit-server-header">
            <h3>${name}</h3>
            <span class="sev-pill sev-unknown">점검 실패</span>
          </header>
          <p class="audit-error">${escapeHtml(report.error || '알 수 없는 오류')}</p>
        </section>`;
    }

    const findings = report.findings.length
      ? report.findings.map(f => {
          const meta = SEVERITY_META[f.severity] || SEVERITY_META.unknown;
          return `
            <li class="audit-finding ${meta.className}">
              <div class="audit-finding-head">
                <i data-lucide="${meta.icon}" style="width:15px;height:15px"></i>
                <span class="audit-finding-title">${escapeHtml(f.title)}</span>
                <span class="audit-finding-cat">${escapeHtml(f.category)}</span>
              </div>
              <p class="audit-finding-detail">${escapeHtml(f.detail)}</p>
              ${f.evidence ? `<code class="audit-evidence">${escapeHtml(f.evidence)}</code>` : ''}
            </li>`;
        }).join('')
      : '<li class="audit-finding sev-ok"><div class="audit-finding-head"><i data-lucide="check-circle" style="width:15px;height:15px"></i><span class="audit-finding-title">발견된 문제 없음</span></div></li>';

    return `
      <section class="audit-server">
        <header class="audit-server-header">
          <h3>${name}</h3>
          <div class="sev-pills">${severityCountsHtml(report.counts) || '<span class="sev-pill sev-ok">문제 없음</span>'}</div>
        </header>
        <p class="audit-server-meta">
          ${escapeHtml(report.host || '')} · ${escapeHtml(report.kernel || '')}
          ${report.privileged ? '' : ' · <strong>sudo 권한 없음 — 일부 항목은 설정 파일 기준</strong>'}
        </p>
        <ul class="audit-findings">${findings}</ul>
      </section>`;
  }).join('');

  body.innerHTML = summary + sections;
  lucide.createIcons();
}

async function runAudit(server) {
  try {
    const res = await fetch(`/api/servers/${server.id}/audit`, { method: 'POST' });
    let data = {};
    try {
      data = await res.json();
    } catch {
      return { success: false, serverName: server.name, error: `응답을 해석할 수 없습니다 (HTTP ${res.status})` };
    }
    if (!res.ok) return { success: false, serverName: server.name, error: data.error || `HTTP ${res.status}` };
    return { ...data, serverName: server.name };
  } catch (err) {
    console.error('Audit error:', err);
    return { success: false, serverName: server.name, error: '네트워크 오류가 발생했습니다.' };
  }
}

// Replace one spinner row in place as its audit lands, so a slow host does not hold
// every other row spinning.
function settlePendingRow(server, report) {
  const row = document.getElementById(`audit-pending-${server.id}`);
  if (!row) return;
  const ok = report.success;
  const counts = ok ? (report.counts || {}) : null;
  const summary = ok
    ? (Object.keys(counts).length ? SEVERITY_ORDER.filter(s => counts[s]).map(s => `${SEVERITY_META[s].label} ${counts[s]}`).join(' · ') : '문제 없음')
    : `실패 — ${report.error || '알 수 없는 오류'}`;
  row.innerHTML = `<i data-lucide="${ok ? 'check' : 'x'}" style="width:14px;height:14px;color:${ok ? 'var(--color-online)' : 'var(--color-offline)'}"></i>
    <span>${escapeHtml(server.name)} — ${escapeHtml(summary)}</span>`;
  lucide.createIcons();
}

// Run tasks with a bounded number in flight at once.
async function runWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

async function auditServer(id) {
  const server = servers.find(s => s.id === id);
  if (!server || auditInFlight) return;

  const runId = ++auditRunId;
  auditInFlight = true;
  setAuditButtonsDisabled(true);
  openAuditModal(`보안 점검 — ${server.name}`);
  renderAuditPending([{ id: server.id, name: server.name }]);

  try {
    const report = await runAudit(server);
    if (runId !== auditRunId) return; // a newer run superseded this one
    lastAuditReports = [report];
    renderAuditReports(lastAuditReports);
  } finally {
    if (runId === auditRunId) {
      auditInFlight = false;
      setAuditButtonsDisabled(false);
    }
  }
}

async function auditAllServers() {
  if (auditInFlight) return;

  if (!servers.length) {
    openAuditModal('보안 점검');
    renderAuditReports([]);
    return;
  }

  const runId = ++auditRunId;
  auditInFlight = true;
  setAuditButtonsDisabled(true);
  openAuditModal(`보안 점검 — 전체 ${servers.length}대`);
  renderAuditPending(servers.map(s => ({ id: s.id, name: s.name })));

  try {
    const targets = servers.slice();
    const reports = await runWithConcurrency(targets, AUDIT_CONCURRENCY, async (server) => {
      const report = await runAudit(server);
      if (runId === auditRunId) settlePendingRow(server, report);
      return report;
    });
    if (runId !== auditRunId) return;
    lastAuditReports = reports;
    renderAuditReports(reports);
  } finally {
    if (runId === auditRunId) {
      auditInFlight = false;
      setAuditButtonsDisabled(false);
    }
  }
}

function buildAuditText() {
  if (!lastAuditReports.length) return '점검 결과가 없습니다.';
  return lastAuditReports.map(r => {
    if (!r || !r.success) return `## ${r ? r.serverName : '알 수 없음'}\n점검 실패: ${r ? r.error : '결과 없음'}\n`;
    const lines = (r.findings || []).length
      ? r.findings.map(f => {
          const meta = SEVERITY_META[f.severity] || SEVERITY_META.unknown;
          return `- [${meta.label}] (${f.category}) ${f.title}\n  ${f.detail}${f.evidence ? `\n  근거: ${f.evidence}` : ''}`;
        }).join('\n')
      : '- 발견된 문제 없음';
    return `## ${r.serverName} (${r.host})\n점검 시각: ${r.checkedAt}\n${lines}\n`;
  }).join('\n');
}

// Remembering the label across clicks would capture "복사됨" on a fast second click and
// never restore, so keep the original text as a constant.
const AUDIT_COPY_LABEL = '보고서 복사';
let auditCopyTimer = null;

async function copyAuditReport() {
  const label = document.getElementById('audit-copy-btn').querySelector('span');
  try {
    await navigator.clipboard.writeText(buildAuditText());
    label.innerText = '복사됨';
  } catch (err) {
    console.error('Clipboard error:', err);
    label.innerText = '복사 실패';
  }
  clearTimeout(auditCopyTimer);
  auditCopyTimer = setTimeout(() => { label.innerText = AUDIT_COPY_LABEL; }, 1500);
}
