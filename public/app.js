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
}

// Fetch Server Profiles
async function fetchServers() {
  try {
    const res = await fetch('/api/servers');
    servers = await res.json();
    
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
    groupHeader.setAttribute('onclick', `toggleGroup('${escapeHtml(groupName).replace(/'/g, "\\'")}', '${safeGroupId}')`);
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
      if (server.os) badgesHtml += `<span class="badge badge-os">${server.os}</span>`;
      if (server.spec) badgesHtml += `<span class="badge badge-spec">${server.spec}</span>`;
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
        </div>

        <div class="card-footer">
          <button class="btn btn-primary btn-connect" onclick="connectToSSH('${server.id}')">
            <i data-lucide="terminal"></i>
            <span>연결하기</span>
          </button>
          <div class="card-actions">
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
async function editServer(id) {
  const server = servers.find(s => s.id === id);
  if (!server) return;

  // If auth is key, fetch the key content first
  if (server.authType === 'key') {
    try {
      const res = await fetch(`/api/servers/${id}/key`);
      const keyData = await res.json();
      server.privateKey = keyData.privateKey;
    } catch (e) {
      console.warn('Failed to load existing private key string:', e);
    }
  }
  
  openModal(server);
  if (server.privateKey) {
    document.getElementById('server-privateKey').value = server.privateKey;
  }
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
    fontFamily: '"Fira Code", monospace, Courier-New',
    fontSize: 14,
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
    resizeHandler = () => {
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
    window.addEventListener('resize', resizeHandler);
    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', resizeHandler);
      window.visualViewport.addEventListener('scroll', resizeHandler);
      // Trigger resize for proper initial size calculations
      setTimeout(resizeHandler, 50);
    }
  }, 100);
}

// Close SSH Terminal
function closeTerminal() {
  if (resizeHandler) {
    window.removeEventListener('resize', resizeHandler);
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
    activeSocket.close();
    activeSocket = null;
  }

  if (activeTerminal) {
    activeTerminal.dispose();
    activeTerminal = null;
  }

  terminalModal.classList.remove('active');
  // Refresh server status when returning to dashboard
  checkAllServersStatus();
}

// Helper to escape HTML tags
function escapeHtml(str) {
  if (!str) return '';
  return str
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
