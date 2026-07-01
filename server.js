const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const net = require('net');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const { Client } = require('ssh2');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const KEYS_DIR = path.join(DATA_DIR, 'keys');
const CONNECTIONS_FILE = path.join(DATA_DIR, 'connections.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

let authConfig = { username: 'admin', salt: '', hash: '' };
let appConfig = { portalName: 'Web-SSH Portal' };

// Initialize portal config
if (!fs.existsSync(CONFIG_FILE)) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(appConfig, null, 2), 'utf-8');
} else {
  try {
    appConfig = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
  } catch (e) {
    console.error('Error reading config file, using default:', e);
  }
}

// Initialize auth configuration (admin / adminpassword)
if (!fs.existsSync(AUTH_FILE)) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync('adminpassword', salt, 10000, 64, 'sha512').toString('hex');
  authConfig = { username: 'admin', salt, hash };
  fs.writeFileSync(AUTH_FILE, JSON.stringify(authConfig, null, 2), 'utf-8');
  console.log('Default credentials initialized: admin / adminpassword');
} else {
  try {
    authConfig = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8'));
  } catch (e) {
    console.error('Error reading auth file, regenerating defaults:', e);
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync('adminpassword', salt, 10000, 64, 'sha512').toString('hex');
    authConfig = { username: 'admin', salt, hash };
    fs.writeFileSync(AUTH_FILE, JSON.stringify(authConfig, null, 2), 'utf-8');
  }
}

// In-memory active session tokens
const activeSessions = new Set();

// Native Cookie Parser Helper
function getCookie(req, name) {
  const cookies = req.headers.cookie;
  if (!cookies) return null;
  const parts = cookies.split(';');
  for (let part of parts) {
    const [k, v] = part.trim().split('=');
    if (k === name) return v;
  }
  return null;
}

// Authentication Middleware
function requireAuth(req, res, next) {
  const path = req.path;
  
  // Publicly accessible paths
  const publicRoutes = ['/login.html', '/style.css', '/icon.jpg', '/manifest.json', '/sw.js', '/api/config'];
  if (publicRoutes.includes(path) || path.startsWith('/api/login')) {
    return next();
  }

  // Extract and verify session token
  const token = getCookie(req, 'session_token');
  if (token && activeSessions.has(token)) {
    return next();
  }

  // Handle unauthorized requests
  if (path === '/' || path === '/index.html') {
    return res.redirect('/login.html');
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Ensure data and keys directory exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR);
}
if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR);
}

// Auto-run import if config doesn't exist but import files exist
if (!fs.existsSync(CONNECTIONS_FILE)) {
  const importScriptPath = path.join(__dirname, 'import-existing.js');
  if (fs.existsSync(importScriptPath)) {
    console.log('connections.json not found. Running automatic import...');
    try {
      require('./import-existing.js');
    } catch (err) {
      console.error('Failed to run automatic import:', err);
    }
  }
}

// Helper to read/write connections
function readConnections() {
  if (!fs.existsSync(CONNECTIONS_FILE)) {
    return [];
  }
  try {
    return JSON.parse(fs.readFileSync(CONNECTIONS_FILE, 'utf-8'));
  } catch (e) {
    console.error('Error reading connections file:', e);
    return [];
  }
}

function writeConnections(connections) {
  try {
    fs.writeFileSync(CONNECTIONS_FILE, JSON.stringify(connections, null, 2), 'utf-8');
  } catch (e) {
    console.error('Error writing connections file:', e);
  }
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(requireAuth); // Protect static files and API routes
app.use(express.static(path.join(__dirname, 'public')));

// API Routes

// List all servers (without sensitive passwords)
app.get('/api/servers', (req, res) => {
  const connections = readConnections();
  const sanitized = connections.map(conn => ({
    id: conn.id,
    name: conn.name,
    host: conn.host,
    port: conn.port,
    username: conn.username,
    authType: conn.authType,
    os: conn.os || '',
    spec: conn.spec || '',
    description: conn.description || '',
    group: conn.group || 'General',
    hasKey: !!conn.privateKeyFile,
    hasPassword: !!conn.password
  }));
  res.json(sanitized);
});

// Add server
app.post('/api/servers', (req, res) => {
  const { name, host, port, username, authType, password, privateKey, os, spec, description, group } = req.body;
  if (!name || !host || !username) {
    return res.status(400).json({ error: 'Name, Host, and Username are required' });
  }

  const connections = readConnections();
  const id = uuidv4();
  const newConn = {
    id,
    name,
    host,
    port: parseInt(port, 10) || 22,
    username,
    authType,
    os: os || '',
    spec: spec || '',
    description: description || '',
    group: group || 'General',
    privateKeyFile: ''
  };

  if (authType === 'key' && privateKey) {
    const keyFileName = `${id}.pem`;
    const keyPath = path.join(KEYS_DIR, keyFileName);
    fs.writeFileSync(keyPath, privateKey, 'utf-8');
    fs.chmodSync(keyPath, 0o600);
    newConn.privateKeyFile = keyFileName;
  } else if (authType === 'password') {
    newConn.password = password || '';
  }

  connections.push(newConn);
  writeConnections(connections);

  res.status(201).json({ success: true, server: { id, name, host, port: newConn.port, username, authType } });
});

// Edit server
app.put('/api/servers/:id', (req, res) => {
  const { id } = req.params;
  const { name, host, port, username, authType, password, privateKey, os, spec, description, group } = req.body;

  const connections = readConnections();
  const connIndex = connections.findIndex(c => c.id === id);

  if (connIndex === -1) {
    return res.status(404).json({ error: 'Server not found' });
  }

  const existing = connections[connIndex];
  
  existing.name = name || existing.name;
  existing.host = host || existing.host;
  existing.port = parseInt(port, 10) || existing.port;
  existing.username = username || existing.username;
  existing.authType = authType || existing.authType;
  existing.os = os !== undefined ? os : existing.os;
  existing.spec = spec !== undefined ? spec : existing.spec;
  existing.description = description !== undefined ? description : existing.description;
  existing.group = group !== undefined ? group : existing.group;

  if (authType === 'key') {
    // If a new private key string is provided, overwrite or create the file
    if (privateKey) {
      const keyFileName = existing.privateKeyFile || `${id}.pem`;
      const keyPath = path.join(KEYS_DIR, keyFileName);
      fs.writeFileSync(keyPath, privateKey, 'utf-8');
      fs.chmodSync(keyPath, 0o600);
      existing.privateKeyFile = keyFileName;
    }
    // Delete password if switching to key
    delete existing.password;
  } else if (authType === 'password') {
    if (password !== undefined) {
      existing.password = password;
    }
    // Delete key file if switching to password
    if (existing.privateKeyFile) {
      const keyPath = path.join(KEYS_DIR, existing.privateKeyFile);
      if (fs.existsSync(keyPath)) {
        fs.unlinkSync(keyPath);
      }
      existing.privateKeyFile = '';
    }
  }

  connections[connIndex] = existing;
  writeConnections(connections);

  res.json({ success: true, server: { id, name: existing.name, host: existing.host } });
});

// Delete server
app.delete('/api/servers/:id', (req, res) => {
  const { id } = req.params;
  const connections = readConnections();
  const connIndex = connections.findIndex(c => c.id === id);

  if (connIndex === -1) {
    return res.status(404).json({ error: 'Server not found' });
  }

  const conn = connections[connIndex];
  
  // Clean up private key file if exists
  if (conn.privateKeyFile) {
    const keyPath = path.join(KEYS_DIR, conn.privateKeyFile);
    if (fs.existsSync(keyPath)) {
      try {
        fs.unlinkSync(keyPath);
      } catch (err) {
        console.error(`Error deleting key file ${conn.privateKeyFile}:`, err);
      }
    }
  }

  connections.splice(connIndex, 1);
  writeConnections(connections);

  res.json({ success: true });
});

// Port check/ping route
app.get('/api/servers/:id/ping', (req, res) => {
  const { id } = req.params;
  const connections = readConnections();
  const conn = connections.find(c => c.id === id);

  if (!conn) {
    return res.status(404).json({ error: 'Server not found' });
  }

  const socket = new net.Socket();
  let status = 'offline';

  socket.setTimeout(1500);

  socket.on('connect', () => {
    status = 'online';
    socket.destroy();
  });

  socket.on('timeout', () => {
    socket.destroy();
  });

  socket.on('error', () => {
    socket.destroy();
  });

  socket.on('close', () => {
    res.json({ id, status });
  });

  socket.connect(conn.port, conn.host);
});

// Get raw private key for editing
app.get('/api/servers/:id/key', (req, res) => {
  const { id } = req.params;
  const connections = readConnections();
  const conn = connections.find(c => c.id === id);

  if (!conn) {
    return res.status(404).json({ error: 'Server not found' });
  }

  if (conn.authType !== 'key' || !conn.privateKeyFile) {
    return res.json({ privateKey: '' });
  }

  const keyPath = path.join(KEYS_DIR, conn.privateKeyFile);
  if (fs.existsSync(keyPath)) {
    const keyContent = fs.readFileSync(keyPath, 'utf-8');
    res.json({ privateKey: keyContent });
  } else {
    res.status(404).json({ error: 'Key file not found' });
  }
});

// Basic Port & SSH Banner Scan
app.get('/api/scan-ip', (req, res) => {
  const { host, port } = req.query;
  const targetPort = parseInt(port, 10) || 22;
  
  if (!host) {
    return res.status(400).json({ error: 'Host is required' });
  }

  const socket = new net.Socket();
  let banner = '';
  let answered = false;

  socket.setTimeout(2500);

  socket.on('data', (data) => {
    banner += data.toString('utf-8');
    if (banner.includes('SSH-')) {
      answered = true;
      socket.destroy();
    }
  });

  socket.on('timeout', () => {
    socket.destroy();
  });

  socket.on('error', () => {
    socket.destroy();
  });

  socket.on('close', () => {
    if (answered && banner) {
      let guessedOS = 'Linux';
      const cleanBanner = banner.trim().split('\n')[0];
      const lowerBanner = cleanBanner.toLowerCase();
      
      if (lowerBanner.includes('ubuntu')) {
        guessedOS = 'Ubuntu';
      } else if (lowerBanner.includes('debian')) {
        guessedOS = 'Debian';
      } else if (lowerBanner.includes('redhat') || lowerBanner.includes('rhel')) {
        guessedOS = 'Red Hat Enterprise Linux';
      } else if (lowerBanner.includes('centos')) {
        guessedOS = 'CentOS';
      } else if (lowerBanner.includes('oracle') || lowerBanner.includes('ol')) {
        guessedOS = 'Oracle Linux';
      } else if (lowerBanner.includes('freebsd')) {
        guessedOS = 'FreeBSD';
      }
      res.json({ success: true, banner: cleanBanner, guessedOS });
    } else {
      res.json({ success: false, error: 'SSH banner not received. Port might be open but not SSH.' });
    }
  });

  socket.connect(targetPort, host);
});

// Deep Credentials Diagnostics & System Specs Scan
app.post('/api/servers/diagnose', (req, res) => {
  const { host, port, username, authType, password, privateKey } = req.body;
  const targetPort = parseInt(port, 10) || 22;

  if (!host || !username) {
    return res.status(400).json({ error: 'Host and Username are required' });
  }

  const sshConfig = {
    host,
    port: targetPort,
    username,
    readyTimeout: 10000
  };

  if (authType === 'key') {
    if (!privateKey) {
      return res.status(400).json({ error: 'Private Key content is required for key diagnostics.' });
    }
    sshConfig.privateKey = privateKey;
  } else if (authType === 'password') {
    sshConfig.password = password;
  } else {
    return res.status(400).json({ error: 'Invalid authentication type' });
  }

  const sshClient = new Client();

  sshClient.on('ready', () => {
    const command = 'cat /etc/os-release; echo "---CPU---"; nproc; echo "---MEM---"; cat /proc/meminfo; echo "---DISK---"; df -h /';
    
    sshClient.exec(command, (err, stream) => {
      if (err) {
        sshClient.end();
        return res.json({ success: false, error: `Command execution failed: ${err.message}` });
      }

      let stdout = '';
      stream.on('data', (data) => {
        stdout += data.toString();
      });

      stream.on('close', () => {
        sshClient.end();
        
        try {
          const sections = stdout.split('---');
          const osRelease = sections[0] || '';
          
          let os = 'Linux';
          const prettyNameMatch = osRelease.match(/PRETTY_NAME="([^"]+)"/);
          if (prettyNameMatch) {
            os = prettyNameMatch[1];
          } else {
            const nameMatch = osRelease.match(/NAME="([^"]+)"/);
            if (nameMatch) os = nameMatch[1];
          }

          let cpu = '1';
          let mem = '';
          let disk = '';

          const cpuSection = sections.find(s => s.startsWith('CPU---'));
          if (cpuSection) {
            const lines = cpuSection.split('\n');
            cpu = lines[1] ? lines[1].trim() : '1';
          }

          const memSection = sections.find(s => s.startsWith('MEM---'));
          if (memSection) {
            const memTotalMatch = memSection.match(/MemTotal:\s+(\d+)/);
            if (memTotalMatch) {
              const memKb = parseInt(memTotalMatch[1], 10);
              const memGb = Math.round(memKb / 1024 / 1024);
              mem = memGb >= 1 ? `${memGb}GB RAM` : `${Math.round(memKb / 1024)}MB RAM`;
            }
          }

          const diskSection = sections.find(s => s.startsWith('DISK---'));
          if (diskSection) {
            const lines = diskSection.trim().split('\n');
            const rootDiskLine = lines.find(l => l.endsWith(' /') || l.includes(' % /'));
            if (rootDiskLine) {
              const cols = rootDiskLine.trim().split(/\s+/);
              if (cols[1]) {
                disk = `${cols[1]}B`;
              }
            }
          }

          const specParts = [];
          if (cpu) specParts.push(`${cpu} CPU`);
          if (mem) specParts.push(mem);
          if (disk) specParts.push(disk);
          const spec = specParts.join(' / ');

          res.json({ success: true, os, spec });
        } catch (e) {
          res.json({ success: true, os: 'Linux', spec: 'Detected successfully (parsed basic details)' });
        }
      });
    });
  });

  sshClient.on('error', (err) => {
    res.json({ success: false, error: err.message });
  });

  sshClient.connect(sshConfig);
});

// Auth API Endpoints

// Login Route
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  if (username !== authConfig.username) {
    return res.status(400).json({ error: 'Invalid username or password.' });
  }

  const hash = crypto.pbkdf2Sync(password, authConfig.salt, 10000, 64, 'sha512').toString('hex');
  if (hash !== authConfig.hash) {
    return res.status(400).json({ error: 'Invalid username or password.' });
  }

  // Generate secure random session token
  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.add(token);

  // Set HTTP-Only Cookie
  res.setHeader('Set-Cookie', `session_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`);
  res.json({ success: true });
});

// Logout Route
app.post('/api/logout', (req, res) => {
  const token = getCookie(req, 'session_token');
  if (token) {
    activeSessions.delete(token);
  }
  // Clear Cookie
  res.setHeader('Set-Cookie', 'session_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  res.json({ success: true });
});

// Get Profile Details
app.get('/api/profile', (req, res) => {
  res.json({ username: authConfig.username });
});

// Get Portal Configuration
app.get('/api/config', (req, res) => {
  res.json({ portalName: appConfig.portalName });
});

// Update Profile & Portal Configuration (Username, Password, Portal Name)
app.post('/api/update-profile', (req, res) => {
  const { currentPassword, newUsername, newPassword, portalName } = req.body;
  if (!currentPassword || !newUsername) {
    return res.status(400).json({ error: 'Current password and username are required.' });
  }

  const currentHash = crypto.pbkdf2Sync(currentPassword, authConfig.salt, 10000, 64, 'sha512').toString('hex');
  if (currentHash !== authConfig.hash) {
    return res.status(400).json({ error: 'Current password does not match.' });
  }

  authConfig.username = newUsername;

  if (newPassword) {
    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = crypto.pbkdf2Sync(newPassword, newSalt, 10000, 64, 'sha512').toString('hex');
    authConfig.salt = newSalt;
    authConfig.hash = newHash;
  }

  // Update Portal Name if provided
  if (portalName) {
    appConfig.portalName = portalName;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(appConfig, null, 2), 'utf-8');
  }

  fs.writeFileSync(AUTH_FILE, JSON.stringify(authConfig, null, 2), 'utf-8');

  res.json({ success: true });
});

// Setup server and WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ssh' });

wss.on('connection', (ws, req) => {
  const urlParams = new URL(req.url, `http://${req.headers.host}`);
  const id = urlParams.searchParams.get('id');
  const termCols = parseInt(urlParams.searchParams.get('cols'), 10) || 80;
  const termRows = parseInt(urlParams.searchParams.get('rows'), 10) || 24;

  // Authenticate WebSocket Session
  const cookies = req.headers.cookie || '';
  const tokenMatch = cookies.match(/session_token=([^;]+)/);
  const token = tokenMatch ? tokenMatch[1] : null;

  if (!token || !activeSessions.has(token)) {
    ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized WebSocket session.' }));
    ws.close();
    return;
  }

  const connections = readConnections();
  const connInfo = connections.find(c => c.id === id);

  if (!connInfo) {
    ws.send(JSON.stringify({ type: 'error', message: 'Connection profile not found.' }));
    ws.close();
    return;
  }

  ws.send(JSON.stringify({ type: 'status', message: `Connecting to ${connInfo.name} (${connInfo.host})...` }));

  const sshConfig = {
    host: connInfo.host,
    port: connInfo.port || 22,
    username: connInfo.username,
    keepaliveInterval: 10000,
    readyTimeout: 20000
  };

  if (connInfo.authType === 'key' && connInfo.privateKeyFile) {
    const keyPath = path.join(KEYS_DIR, connInfo.privateKeyFile);
    if (fs.existsSync(keyPath)) {
      sshConfig.privateKey = fs.readFileSync(keyPath);
    } else {
      ws.send(JSON.stringify({ type: 'error', message: `SSH Private key file not found on server.` }));
      ws.close();
      return;
    }
  } else if (connInfo.authType === 'password') {
    sshConfig.password = connInfo.password;
  } else {
    ws.send(JSON.stringify({ type: 'error', message: `No credentials configured for this connection.` }));
    ws.close();
    return;
  }

  const sshClient = new Client();

  sshClient.on('ready', () => {
    ws.send(JSON.stringify({ type: 'status', message: 'SSH Connection Established. Spawning shell...' }));

    sshClient.shell({ term: 'xterm-256color', cols: termCols, rows: termRows }, (err, stream) => {
      if (err) {
        ws.send(JSON.stringify({ type: 'error', message: `Shell spawn error: ${err.message}` }));
        ws.close();
        return;
      }

      ws.send(JSON.stringify({ type: 'status', message: 'Shell connected.' }));

      // Data from SSH to WebSocket
      stream.on('data', (data) => {
        ws.send(JSON.stringify({ type: 'data', data: data.toString('utf-8') }));
      });

      stream.on('close', () => {
        ws.send(JSON.stringify({ type: 'status', message: '\r\nConnection closed by remote host.' }));
        ws.close();
      });

      // Data from WebSocket to SSH
      ws.on('message', (message) => {
        try {
          const parsed = JSON.parse(message);
          if (parsed.type === 'data') {
            stream.write(parsed.data);
          } else if (parsed.type === 'resize') {
            stream.setWindow(parsed.rows, parsed.cols, 0, 0);
          }
        } catch (e) {
          // If not valid JSON, write as raw data
          stream.write(message);
        }
      });

      ws.on('close', () => {
        stream.end();
        sshClient.end();
      });
    });
  });

  sshClient.on('error', (err) => {
    ws.send(JSON.stringify({ type: 'error', message: `SSH error: ${err.message}` }));
    ws.close();
  });

  sshClient.on('close', () => {
    ws.close();
  });

  sshClient.connect(sshConfig);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
