const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const { Client } = require('ssh2');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(os.homedir(), '.local', 'share', 'web-ssh'));
const KEYS_DIR = path.join(DATA_DIR, 'keys');
const CONNECTIONS_FILE = path.join(DATA_DIR, 'connections.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const PASSWORD_ITERATIONS = 210000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

// Google OAuth 2.0 / OpenID Connect single sign-on (optional)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || '';
const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_ENDPOINT = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const OAUTH_COOKIE_PATH = '/api/auth/google';

function parseAllowList(value) {
  return (value || '')
    .split(',')
    .map(entry => entry.trim().toLowerCase())
    .filter(Boolean);
}

const GOOGLE_ALLOWED_EMAILS = new Set(parseAllowList(process.env.GOOGLE_ALLOWED_EMAILS));
const GOOGLE_ALLOWED_DOMAINS = new Set(parseAllowList(process.env.GOOGLE_ALLOWED_DOMAINS).map(d => d.replace(/^@/, '')));

// Google sign-in stays off unless an explicit allow list exists. Without one, every
// Google account on the internet would get a shell on every managed server.
const googleClientConfigured = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
const googleAllowListConfigured = GOOGLE_ALLOWED_EMAILS.size > 0 || GOOGLE_ALLOWED_DOMAINS.size > 0;
const GOOGLE_LOGIN_ENABLED = googleClientConfigured && googleAllowListConfigured;

if (!googleClientConfigured && (GOOGLE_CLIENT_ID || GOOGLE_CLIENT_SECRET)) {
  console.warn('Google login disabled: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must both be set.');
} else if (googleClientConfigured && !googleAllowListConfigured) {
  console.warn('Google login disabled: set GOOGLE_ALLOWED_EMAILS or GOOGLE_ALLOWED_DOMAINS to name the accounts that may sign in.');
} else if (GOOGLE_LOGIN_ENABLED) {
  console.log('Google login enabled.');
}

let authConfig = { username: 'admin', salt: '', hash: '' };
let appConfig = { portalName: 'Web-SSH Portal' };

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
fs.chmodSync(DATA_DIR, 0o700);
fs.chmodSync(KEYS_DIR, 0o700);

function writeJsonSecure(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), { encoding: 'utf-8', mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

// Initialize portal config
if (!fs.existsSync(CONFIG_FILE)) {
  writeJsonSecure(CONFIG_FILE, appConfig);
} else {
  try {
    appConfig = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
  } catch (e) {
    console.error('Error reading config file, using default:', e);
  }
}

function hashPassword(password, salt, iterations = PASSWORD_ITERATIONS) {
  return crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
}

function safeEqualHex(left, right) {
  try {
    const leftBuffer = Buffer.from(left, 'hex');
    const rightBuffer = Buffer.from(right, 'hex');
    return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

// Initialize auth configuration from an operator-supplied secret.
if (!fs.existsSync(AUTH_FILE)) {
  const initialPassword = process.env.ADMIN_PASSWORD;
  if (!initialPassword || initialPassword.length < 12) {
    throw new Error('First start requires ADMIN_PASSWORD with at least 12 characters.');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(initialPassword, salt);
  authConfig = { username: process.env.ADMIN_USERNAME || 'admin', salt, hash, iterations: PASSWORD_ITERATIONS };
  writeJsonSecure(AUTH_FILE, authConfig);
  console.log('Administrator credentials initialized from environment.');
} else {
  try {
    authConfig = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8'));
  } catch (e) {
    throw new Error(`Cannot read authentication configuration: ${e.message}`);
  }
  if (!authConfig.username || !authConfig.salt || !authConfig.hash) {
    throw new Error('Authentication configuration is incomplete; restore it or remove it and set ADMIN_PASSWORD.');
  }
  const storedIterations = authConfig.iterations || 10000;
  const isLegacyDefault = safeEqualHex(
    hashPassword('adminpassword', authConfig.salt, storedIterations),
    authConfig.hash
  );
  if (isLegacyDefault) {
    const replacement = process.env.ADMIN_PASSWORD;
    if (!replacement || replacement.length < 12 || replacement === 'adminpassword') {
      throw new Error('Insecure legacy default password detected. Set a new ADMIN_PASSWORD (12+ characters) to rotate it.');
    }
    const salt = crypto.randomBytes(16).toString('hex');
    authConfig = {
      username: process.env.ADMIN_USERNAME || authConfig.username,
      salt,
      hash: hashPassword(replacement, salt),
      iterations: PASSWORD_ITERATIONS
    };
    writeJsonSecure(AUTH_FILE, authConfig);
    console.log('Insecure legacy administrator password was rotated.');
  }
}

// In-memory active session tokens: token -> { expiresAt, user }
const activeSessions = new Map();
const loginAttempts = new Map();

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

// Return the live session for a token, dropping it once it has expired.
function getSession(token) {
  if (!token) return null;
  const session = activeSessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    activeSessions.delete(token);
    return null;
  }
  return session;
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.set(token, { expiresAt: Date.now() + SESSION_TTL_MS, user });
  return token;
}

function sessionCookie(token) {
  const secure = COOKIE_SECURE ? '; Secure' : '';
  return `session_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secure}`;
}

// Authentication Middleware
function requireAuth(req, res, next) {
  const path = req.path;

  // Publicly accessible paths
  const publicRoutes = ['/login.html', '/style.css', '/icon.jpg', '/manifest.json', '/sw.js', '/api/config'];
  if (publicRoutes.includes(path) || path.startsWith('/api/login') || path.startsWith('/api/auth/google')) {
    return next();
  }

  // Extract and verify session token
  if (getSession(getCookie(req, 'session_token'))) {
    return next();
  }

  // Handle unauthorized requests
  if (path === '/' || path === '/index.html') {
    return res.redirect('/login.html');
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Google OAuth helpers

// Pending authorization requests: state -> { nonce, codeVerifier, redirectUri, expiresAt }
const pendingOAuthStates = new Map();
let googleJwksCache = { keys: [], expiresAt: 0 };

function base64UrlEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value) {
  return Buffer.from(String(value).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function prunePendingOAuthStates() {
  const now = Date.now();
  for (const [state, entry] of pendingOAuthStates) {
    if (entry.expiresAt <= now) pendingOAuthStates.delete(state);
  }
}

function oauthStateCookie(state) {
  const secure = COOKIE_SECURE ? '; Secure' : '';
  const maxAge = state ? OAUTH_STATE_TTL_MS / 1000 : 0;
  // SameSite=Lax so the cookie survives the top-level redirect back from Google.
  return `oauth_state=${state || ''}; Path=${OAUTH_COOKIE_PATH}; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

// The redirect URI must match the one registered in the Google Cloud console.
function resolveGoogleRedirectUri(req) {
  if (GOOGLE_REDIRECT_URI) return GOOGLE_REDIRECT_URI;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const proto = forwardedProto || (COOKIE_SECURE ? 'https' : 'http');
  const host = forwardedHost || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}${OAUTH_COOKIE_PATH}/callback`;
}

async function fetchGoogleJwks(forceRefresh = false) {
  if (!forceRefresh && googleJwksCache.expiresAt > Date.now()) return googleJwksCache.keys;
  const response = await fetch(GOOGLE_JWKS_ENDPOINT);
  if (!response.ok) throw new Error(`Google JWKS request failed with HTTP ${response.status}.`);
  const body = await response.json();
  const maxAge = /max-age=(\d+)/i.exec(response.headers.get('cache-control') || '');
  const ttlSeconds = maxAge ? Number(maxAge[1]) : 3600;
  googleJwksCache = {
    keys: Array.isArray(body.keys) ? body.keys : [],
    expiresAt: Date.now() + ttlSeconds * 1000
  };
  return googleJwksCache.keys;
}

async function findGoogleSigningKey(kid) {
  const cached = (await fetchGoogleJwks()).find(key => key.kid === kid && key.kty === 'RSA');
  if (cached) return cached;
  // Google rotates signing keys, so refresh once before giving up.
  return (await fetchGoogleJwks(true)).find(key => key.kid === kid && key.kty === 'RSA') || null;
}

async function verifyGoogleIdToken(idToken, expectedNonce) {
  const segments = String(idToken || '').split('.');
  if (segments.length !== 3) throw new Error('Malformed ID token.');

  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf-8'));
  if (header.alg !== 'RS256') throw new Error(`Unsupported ID token algorithm: ${header.alg}`);

  const jwk = await findGoogleSigningKey(header.kid);
  if (!jwk) throw new Error('No matching Google signing key for this ID token.');

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signedInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  if (!crypto.verify('RSA-SHA256', signedInput, publicKey, base64UrlDecode(encodedSignature))) {
    throw new Error('ID token signature verification failed.');
  }

  const payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf-8'));
  const nowSeconds = Math.floor(Date.now() / 1000);
  const clockSkewSeconds = 60;
  if (!GOOGLE_ISSUERS.has(payload.iss)) throw new Error('Unexpected ID token issuer.');
  if (payload.aud !== GOOGLE_CLIENT_ID) throw new Error('ID token was issued for a different client.');
  if (typeof payload.exp !== 'number' || payload.exp + clockSkewSeconds < nowSeconds) {
    throw new Error('ID token has expired.');
  }
  if (typeof payload.iat === 'number' && payload.iat - clockSkewSeconds > nowSeconds) {
    throw new Error('ID token is not valid yet.');
  }
  if (payload.nonce !== expectedNonce) throw new Error('ID token nonce mismatch.');
  return payload;
}

function isGoogleAccountAllowed(payload) {
  if (payload.email_verified !== true && payload.email_verified !== 'true') return false;
  const email = String(payload.email || '').toLowerCase();
  if (!email.includes('@')) return false;
  if (GOOGLE_ALLOWED_EMAILS.has(email)) return true;
  return GOOGLE_ALLOWED_DOMAINS.has(email.slice(email.lastIndexOf('@') + 1));
}

// Auto-run import only when an external import directory was explicitly configured.
const SSH_IMPORT_DIR = process.env.SSH_IMPORT_DIR;
if (!fs.existsSync(CONNECTIONS_FILE) && SSH_IMPORT_DIR && fs.existsSync(path.join(SSH_IMPORT_DIR, 'config'))) {
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
    writeJsonSecure(CONNECTIONS_FILE, connections);
  } catch (e) {
    console.error('Error writing connections file:', e);
  }
}

// Helper to parse detailed system specs from raw SSH output
function parseDiagnosticOutput(stdout) {
  try {
    const sections = stdout.split('---');
    const osRelease = sections[0] || '';
    
    let osName = 'Linux';
    const prettyNameMatch = osRelease.match(/PRETTY_NAME="([^"]+)"/);
    if (prettyNameMatch) {
      osName = prettyNameMatch[1];
    } else {
      const nameMatch = osRelease.match(/NAME="([^"]+)"/);
      if (nameMatch) osName = nameMatch[1];
    }

    let cpuCores = '1';
    let cpuModel = 'Virtual CPU';
    const cpuIdx = sections.findIndex(s => s.trim() === 'CPU');
    const cpuSection = cpuIdx !== -1 ? sections[cpuIdx + 1] : '';
    if (cpuSection) {
      const lines = cpuSection.split('\n');
      cpuCores = lines[1] ? lines[1].trim() : '1';
      if (lines[2]) {
        cpuModel = lines[2].replace('model name\t:', '').replace('model name :', '').trim();
      }
    }

    let ramTotal = 'N/A';
    let ramUsed = 'N/A';
    let ramFree = 'N/A';
    let ramGbVal = 0;
    const memIdx = sections.findIndex(s => s.trim() === 'MEM');
    const memSection = memIdx !== -1 ? sections[memIdx + 1] : '';
    if (memSection) {
      const memTotalMatch = memSection.match(/MemTotal:\s+(\d+)/);
      const memFreeMatch = memSection.match(/MemFree:\s+(\d+)/);
      const memAvailableMatch = memSection.match(/MemAvailable:\s+(\d+)/);

      if (memTotalMatch) {
        const totalKb = parseInt(memTotalMatch[1], 10);
        const freeKb = memAvailableMatch ? parseInt(memAvailableMatch[1], 10) : (memFreeMatch ? parseInt(memFreeMatch[1], 10) : 0);
        const usedKb = totalKb - freeKb;
        
        ramGbVal = Math.round(totalKb / 1024 / 1024);
        ramTotal = ramGbVal >= 1 ? `${ramGbVal}GB` : `${Math.round(totalKb / 1024)}MB`;
        
        const usedGbVal = usedKb / 1024 / 1024;
        ramUsed = usedGbVal >= 1 ? `${usedGbVal.toFixed(1)}GB` : `${Math.round(usedKb / 1024)}MB`;
        
        const freeGbVal = freeKb / 1024 / 1024;
        ramFree = freeGbVal >= 1 ? `${freeGbVal.toFixed(1)}GB` : `${Math.round(freeKb / 1024)}MB`;
      }
    }

    let diskTotal = 'N/A';
    let diskUsed = 'N/A';
    let diskFree = 'N/A';
    let diskPercent = 'N/A';
    const diskIdx = sections.findIndex(s => s.trim() === 'DISK');
    const diskSection = diskIdx !== -1 ? sections[diskIdx + 1] : '';
    if (diskSection) {
      const lines = diskSection.trim().split('\n');
      const rootDiskLine = lines.find(l => l.endsWith(' /') || l.includes(' % /') || l.includes(' / '));
      if (rootDiskLine) {
        const cols = rootDiskLine.trim().split(/\s+/);
        if (cols.length >= 5) {
          diskTotal = cols[1];
          diskUsed = cols[2];
          diskFree = cols[3];
          diskPercent = cols[4];
        }
      }
    }

    let uptime = 'N/A';
    let loadAvg = 'N/A';
    const uptimeIdx = sections.findIndex(s => s.trim() === 'UPTIME');
    const uptimeSection = uptimeIdx !== -1 ? sections[uptimeIdx + 1] : '';
    if (uptimeSection) {
      const line = uptimeSection.trim();
      const uptimeMatch = line.match(/up\s+([^,]+(?:,\s+[^,]+)?),/);
      if (uptimeMatch) {
        uptime = uptimeMatch[1].trim();
      } else {
        const uptimeAltMatch = line.match(/up\s+([^,]+),/);
        if (uptimeAltMatch) uptime = uptimeAltMatch[1].trim();
      }
      
      const loadMatch = line.match(/load average:\s+([^$]+)/);
      if (loadMatch) {
        loadAvg = loadMatch[1].trim();
      }
    }

    const specParts = [];
    specParts.push(`${cpuCores} Core CPU`);
    specParts.push(`${ramTotal} RAM`);
    specParts.push(`${diskTotal} Disk`);
    const spec = specParts.join(' / ');

    return {
      success: true,
      os: osName,
      spec,
      systemInfo: {
        osName,
        cpuModel,
        cpuCores: `${cpuCores} Cores`,
        ramTotal,
        ramUsed,
        ramFree,
        diskTotal,
        diskUsed,
        diskFree,
        diskPercent,
        uptime,
        loadAvg,
        lastChecked: new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' })
      }
    };
  } catch (e) {
    console.error('Error parsing diagnostic output:', e);
    return {
      success: true,
      os: 'Linux',
      spec: 'Detected (parsing error)',
      systemInfo: null
    };
  }
}

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; connect-src 'self' ws: wss:; img-src 'self' data:");
  next();
});
app.use(express.json({ limit: '64kb' }));
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
    hasPassword: !!conn.password,
    systemInfo: conn.systemInfo || null
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
  const id = crypto.randomUUID();
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
    privateKeyFile: '',
    systemInfo: req.body.systemInfo || null
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
  if (req.body.systemInfo !== undefined) {
    existing.systemInfo = req.body.systemInfo;
  }

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
    const command = 'cat /etc/os-release; echo "---CPU---"; nproc; grep "model name" /proc/cpuinfo | head -1; echo "---MEM---"; cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"; echo "---DISK---"; df -h /; echo "---UPTIME---"; uptime;';
    
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
        const result = parseDiagnosticOutput(stdout);
        res.json(result);
      });
    });
  });

  sshClient.on('error', (err) => {
    res.json({ success: false, error: err.message });
  });

  sshClient.connect(sshConfig);
});

// Trigger deep credentials diagnostics & system specs scan for an existing server
app.post('/api/servers/:id/diagnose', (req, res) => {
  const { id } = req.params;
  const connections = readConnections();
  const conn = connections.find(c => c.id === id);

  if (!conn) {
    return res.status(404).json({ error: 'Server not found' });
  }

  const sshConfig = {
    host: conn.host,
    port: conn.port,
    username: conn.username,
    readyTimeout: 10000
  };

  if (conn.authType === 'key') {
    if (!conn.privateKeyFile) {
      return res.status(400).json({ error: 'Private Key file not found on server' });
    }
    const keyPath = path.join(KEYS_DIR, conn.privateKeyFile);
    if (!fs.existsSync(keyPath)) {
      return res.status(400).json({ error: 'Private Key file does not exist on disk' });
    }
    sshConfig.privateKey = fs.readFileSync(keyPath, 'utf-8');
  } else if (conn.authType === 'password') {
    sshConfig.password = conn.password;
  } else {
    return res.status(400).json({ error: 'Invalid authentication type' });
  }

  const sshClient = new Client();

  sshClient.on('ready', () => {
    const command = 'cat /etc/os-release; echo "---CPU---"; nproc; grep "model name" /proc/cpuinfo | head -1; echo "---MEM---"; cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"; echo "---DISK---"; df -h /; echo "---UPTIME---"; uptime;';
    
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
        
        const result = parseDiagnosticOutput(stdout);
        if (result.success) {
          // Update database
          conn.os = result.os;
          conn.spec = result.spec;
          conn.systemInfo = result.systemInfo;
          writeConnections(connections);
          
          res.json({ success: true, os: result.os, spec: result.spec, systemInfo: result.systemInfo });
        } else {
          res.json({ success: false, error: 'Failed to parse diagnostic output' });
        }
      });
    });
  });

  sshClient.on('error', (err) => {
    res.json({ success: false, error: err.message });
  });

  sshClient.connect(sshConfig);
});

// Security Audit

// Read-only posture checks. Nothing here writes, installs, or restarts anything;
// privileged probes go through `sudo -n` so they fail closed instead of prompting.
const SECURITY_AUDIT_COMMAND = [
  'export LC_ALL=C 2>/dev/null;',
  // Every probe that can block on a lock, a repo refresh, or a big filesystem walk
  // gets a hard cap so one slow check cannot stall the whole audit.
  // TL is the longer budget for the package-manager probe, which routinely needs
  // more than 10s (apt-check alone takes ~13s on a mid-size Ubuntu host).
  'T=""; TL=""; command -v timeout >/dev/null 2>&1 && { T="timeout 10"; TL="timeout 30"; };',
  'echo "===HOST===";',
  'uname -sr 2>/dev/null;',
  '. /etc/os-release 2>/dev/null && echo "OS=$PRETTY_NAME";',
  'echo "===SSHD===";',
  'if $T sudo -n /usr/sbin/sshd -T >/tmp/.sshdT.$$ 2>/dev/null || $T /usr/sbin/sshd -T >/tmp/.sshdT.$$ 2>/dev/null; then',
  '  echo "SOURCE=effective"; cat /tmp/.sshdT.$$;',
  'else',
  '  echo "SOURCE=configfile";',
  '  cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sed -e "s/#.*//" -e "/^[[:space:]]*$/d" | tr -s " \\t" " " | sed -e "s/^ //" | tr "A-Z" "a-z";',
  'fi;',
  'rm -f /tmp/.sshdT.$$;',
  'echo "===LISTEN===";',
  'ss -tulnH 2>/dev/null | head -80 || netstat -tuln 2>/dev/null | head -80;',
  'echo "===FIREWALL===";',
  'for s in ufw firewalld nftables; do st=$(systemctl is-active $s 2>/dev/null); echo "svc:$s=${st:-unknown}"; done;',
  'echo "ufw:$(ufw status 2>/dev/null | head -1)";',
  'nf=$($T sudo -n nft list ruleset 2>/dev/null | grep -cE \'^[[:space:]]*(tcp|udp|ct|meta) \'); echo "nftrules:${nf:-NA}";',
  // Count only INPUT rules, and drop docker/libvirt chains so container plumbing
  // is not mistaken for an actual host firewall policy.
  'ipt=$($T sudo -n iptables -S INPUT 2>/dev/null | grep \'^-A INPUT\' | grep -cvE \'DOCKER|LIBVIRT|br-|docker0|virbr\'); echo "iptinput:${ipt:-NA}";',
  'echo "iptpolicy:$($T sudo -n iptables -S INPUT 2>/dev/null | grep \'^-P INPUT\' | awk \'{print $3}\')";',
  'echo "===FAIL2BAN===";',
  'echo "active=$(systemctl is-active fail2ban 2>/dev/null || echo unknown)";',
  '$T sudo -n fail2ban-client status 2>/dev/null | head -3;',
  'echo "===UPDATES===";',
  'if [ -x /usr/lib/update-notifier/apt-check ]; then echo "aptcheck=$($TL /usr/lib/update-notifier/apt-check 2>&1)";',
  'elif command -v apt-get >/dev/null 2>&1; then echo "aptinst=$($TL apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -c \'^Inst\')";',
  'elif command -v dnf >/dev/null 2>&1; then echo "dnfcount=$($TL dnf -C -q check-update 2>/dev/null | grep -cE \'^[a-zA-Z0-9][^ ]*\\.\')";',
  'else echo "pkgmgr=unknown"; fi;',
  'echo "reboot_required=$([ -f /var/run/reboot-required ] && echo yes || echo no)";',
  'if command -v needs-restarting >/dev/null 2>&1; then $T needs-restarting -r >/dev/null 2>&1; echo "needs_restarting_rc=$?"; fi;',
  'echo "===SUDO===";',
  'np=$($T sudo -n -l 2>/dev/null | grep -c NOPASSWD); echo "nopasswd=${np:-NA}";',
  'echo "===KEYS===";',
  'for f in "$HOME/.ssh/authorized_keys" /root/.ssh/authorized_keys; do',
  '  [ -r "$f" ] && echo "ak:$f:$(stat -c %a "$f" 2>/dev/null):$(grep -cvE \'^[[:space:]]*(#|$)\' "$f" 2>/dev/null)";',
  'done;',
  '[ -d "$HOME/.ssh" ] && echo "dir:$HOME/.ssh:$(stat -c %a "$HOME/.ssh" 2>/dev/null)";',
  '$T find "$HOME" -maxdepth 3 \\( -name "id_*" ! -name "*.pub" -o -name "*.pem" -o -name "*.key" \\) -type f 2>/dev/null | head -20 | while read -r k; do echo "privkey:$k:$(stat -c %a "$k" 2>/dev/null)"; done;',
  'echo "===LOGINS===";',
  'fl=$($T sudo -n journalctl -u ssh -u sshd --since \'24 hours ago\' --no-pager 2>/dev/null | grep -ciE \'failed password|invalid user\'); echo "failed24h=${fl:-NA}";',
  'echo "===DOCKER===";',
  '{ $T docker ps --format "{{.Names}}|{{.Ports}}" 2>/dev/null || $T sudo -n docker ps --format "{{.Names}}|{{.Ports}}" 2>/dev/null; } | head -20;',
  'echo "===UNITS===";',
  'for u in /etc/systemd/system/*.service; do',
  '  [ -r "$u" ] || continue;',
  '  p=$(stat -c %a "$u" 2>/dev/null);',
  // Last octal digit >= 4 means every user on the box can read the file.
  '  case "$p" in *[4567]) grep -qiE "^Environment=.*(KEY|TOKEN|SECRET|PASSWORD|WEBHOOK)" "$u" 2>/dev/null && echo "unit:$u:$p";; esac;',
  'done 2>/dev/null;',
  'echo "===END==="'
].join(' ');

function auditSection(stdout, name) {
  const match = new RegExp(`===${name}===\\n([\\s\\S]*?)(?:\\n===|$)`).exec(stdout);
  return match ? match[1].trim() : '';
}

function sshdSetting(sshdSection, key) {
  const line = sshdSection
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.toLowerCase().startsWith(`${key} `))
    .pop();
  return line ? line.slice(key.length).trim().toLowerCase() : null;
}

// Turn the raw section output into severity-ranked findings.
function parseSecurityAudit(stdout) {
  const findings = [];
  const add = (severity, category, title, detail, evidence) =>
    findings.push({ severity, category, title, detail, evidence: evidence || null });

  // SSH daemon configuration
  const sshd = auditSection(stdout, 'SSHD');
  const effective = sshd.includes('SOURCE=effective');
  const configNote = effective ? '' : ' (설정 파일 기준 — sudo 권한이 없어 실효 설정을 읽지 못했습니다)';

  const rootLogin = sshdSetting(sshd, 'permitrootlogin');
  if (rootLogin === 'yes') {
    add('critical', 'SSH', 'root 직접 로그인 허용', `PermitRootLogin=yes 입니다. root 계정에 대한 무차별 대입이 가능합니다.${configNote}`, `PermitRootLogin ${rootLogin}`);
  } else if (rootLogin === 'without-password' || rootLogin === 'prohibit-password') {
    add('low', 'SSH', 'root 키 로그인 허용', `PermitRootLogin=${rootLogin} — 키가 있으면 root로 직접 들어올 수 있습니다. 심층 방어 차원에서 no 권장.${configNote}`, `PermitRootLogin ${rootLogin}`);
  }

  const passwordAuth = sshdSetting(sshd, 'passwordauthentication');
  if (passwordAuth === 'yes') {
    add('high', 'SSH', '비밀번호 인증 허용', `PasswordAuthentication=yes 입니다. 키 인증만 사용한다면 꺼두는 편이 안전합니다.${configNote}`, `PasswordAuthentication ${passwordAuth}`);
  }

  const emptyPasswords = sshdSetting(sshd, 'permitemptypasswords');
  if (emptyPasswords === 'yes') {
    add('critical', 'SSH', '빈 비밀번호 로그인 허용', `PermitEmptyPasswords=yes 입니다.${configNote}`, `PermitEmptyPasswords ${emptyPasswords}`);
  }

  const maxAuthTries = parseInt(sshdSetting(sshd, 'maxauthtries') || '', 10);
  if (Number.isFinite(maxAuthTries) && maxAuthTries > 6) {
    add('low', 'SSH', '인증 시도 허용 횟수 과다', `MaxAuthTries=${maxAuthTries} 입니다.${configNote}`, `MaxAuthTries ${maxAuthTries}`);
  }
  if (!sshd) {
    add('unknown', 'SSH', 'SSH 설정을 읽지 못함', 'sshd 설정을 확인할 수 없었습니다.', null);
  }

  // Listening sockets reachable from outside the host
  const listen = auditSection(stdout, 'LISTEN');
  const sockets = [];
  for (const line of listen.split('\n')) {
    const tokens = line.trim().split(/\s+/);
    const proto = /^(tcp|udp)$/i.test(tokens[0]) ? tokens[0].toLowerCase() : '';
    // ss prints "<local> <peer>"; the peer column always ends in ":*".
    const local = tokens.find(t => /:(\d+)$/.test(t) && /[.:]/.test(t.slice(0, t.lastIndexOf(':'))));
    if (!local) continue;
    const port = local.slice(local.lastIndexOf(':') + 1);
    const rawAddr = local.slice(0, local.lastIndexOf(':'));
    // "0.0.0.0%virbr0" is scoped to one interface, so it is not a true wildcard bind.
    const scoped = rawAddr.includes('%');
    const addr = rawAddr.split('%')[0].replace(/[[\]]/g, '');
    if (addr.startsWith('127.') || addr === '::1') continue;
    const wildcard = !scoped && (addr === '0.0.0.0' || addr === '::' || addr === '*' || addr === '');
    sockets.push({ proto, addr: addr || '*', port, wildcard, label: scoped ? rawAddr : addr });
  }
  const unique = [...new Map(sockets.map(s => [`${s.proto}:${s.addr}:${s.port}:${s.wildcard}`, s])).values()];

  // A wildcard bind is reachable on every interface the host has, including public ones.
  // IPv4 and IPv6 listeners for one service collapse into a single entry.
  const wildcardPorts = [...new Set(unique.filter(s => s.wildcard && s.port !== '22').map(s => `${s.proto}/${s.port}`))];
  if (wildcardPorts.length) {
    add(
      wildcardPorts.length > 4 ? 'high' : 'medium',
      '네트워크',
      `전체 인터페이스(0.0.0.0/::)에 열린 포트 ${wildcardPorts.length}개`,
      '모든 인터페이스에 바인딩된 SSH 외 서비스입니다. 클라우드 보안 그룹으로만 막고 있다면 규칙이 풀리는 순간 그대로 인터넷에 노출됩니다. 내부 전용이라면 127.0.0.1로 바인딩하세요.',
      wildcardPorts.join(', ')
    );
  }
  const otherBinds = [...new Set(unique.filter(s => !s.wildcard && s.port !== '22').map(s => `${s.label}:${s.port}`))];
  if (otherBinds.length) {
    add('low', '네트워크', `특정 인터페이스에 열린 포트 ${otherBinds.length}개`, '루프백이 아닌 개별 주소나 인터페이스에 바인딩된 서비스입니다. 해당 주소가 외부에서 닿는지 확인하세요.', otherBinds.join(', '));
  }
  if (unique.some(s => s.port === '111')) {
    add('medium', '네트워크', 'rpcbind(111) 노출', 'NFS를 쓰지 않는다면 rpcbind는 불필요합니다. 증폭 DDoS 반사체로 악용될 수 있으니 서비스를 중지하세요.', 'port 111');
  }

  // Host firewall
  const firewall = auditSection(stdout, 'FIREWALL');
  const activeFw = ['ufw', 'firewalld', 'nftables'].filter(s => new RegExp(`svc:${s}=active`).test(firewall));
  const nftRules = parseInt((/nftrules:(\d+)/.exec(firewall) || [])[1] || '', 10);
  const iptInput = parseInt((/iptinput:(\d+)/.exec(firewall) || [])[1] || '', 10);
  const iptPolicy = (/iptpolicy:(\w+)/.exec(firewall) || [])[1] || '';
  const probeBlocked = !/nftrules:\d/.test(firewall) && !/iptinput:\d/.test(firewall);
  const hasHostRules = (Number.isFinite(nftRules) && nftRules > 0) || (Number.isFinite(iptInput) && iptInput > 0);
  // A handful of INPUT rules with a default-ACCEPT policy is not a firewall — that is
  // what fail2ban alone looks like. Default-deny is what actually gates traffic.
  const defaultDeny = /^(DROP|REJECT)$/i.test(iptPolicy);

  if (probeBlocked && !activeFw.length) {
    add('unknown', '방화벽', '방화벽 상태 확인 불가', 'sudo 권한이 없어 규칙을 읽지 못했고, 활성화된 방화벽 서비스도 찾지 못했습니다.', null);
  } else if (!activeFw.length && !defaultDeny) {
    add('medium', '방화벽', '호스트 방화벽 없음 (기본 정책 ACCEPT)',
      `동작 중인 방화벽 서비스가 없고 INPUT 기본 정책이 ${iptPolicy || 'ACCEPT'}입니다. docker/libvirt를 제외한 INPUT 규칙 ${Number.isFinite(iptInput) ? iptInput : 0}건은 fail2ban 등이 넣은 것으로 기본 차단 역할을 하지 못합니다. 클라우드 보안 그룹에만 의존하면 규칙 오설정 시 전면 노출됩니다.`,
      `${firewall.split('\n').filter(l => l.startsWith('svc:')).join(' ')} INPUT정책=${iptPolicy || '?'} 규칙=${iptInput}`);
  } else if (activeFw.length && !hasHostRules) {
    add('high', '방화벽', '방화벽은 켜져 있으나 규칙이 비어 있음', `${activeFw.join(', ')} 서비스는 active인데 실제 필터 규칙이 0건입니다. 차단이 동작하지 않습니다.`, `nft=${nftRules} INPUT=${iptInput}`);
  }

  // fail2ban
  const fail2ban = auditSection(stdout, 'FAIL2BAN');
  if (/active=(inactive|failed|unknown)/.test(fail2ban)) {
    add('medium', '침입차단', 'fail2ban 비활성', 'SSH 무차별 대입 차단이 동작하지 않습니다.', (/active=(\S+)/.exec(fail2ban) || [])[0]);
  }

  // Pending updates
  const updates = auditSection(stdout, 'UPDATES');
  const aptCheck = /aptcheck=(\d+);(\d+)/.exec(updates);
  const aptInst = /aptinst=(\d+)/.exec(updates);
  const dnfCount = /dnfcount=(\d+)/.exec(updates);
  if (aptCheck) {
    const [, total, security] = aptCheck;
    if (Number(security) > 0) add('high', '패치', `보안 업데이트 ${security}건 미적용`, `전체 미적용 업데이트 ${total}건 중 보안 관련이 ${security}건입니다.`, `apt-check ${total};${security}`);
    else if (Number(total) > 50) add('low', '패치', `미적용 업데이트 ${total}건`, '보안 업데이트는 없지만 누적된 패키지 업데이트가 많습니다.', `apt-check ${total};0`);
  } else if (aptInst && Number(aptInst[1]) > 0) {
    const count = Number(aptInst[1]);
    add(count > 100 ? 'high' : 'medium', '패치', `미적용 업데이트 ${count}건`, '보안/일반 구분 없이 집계된 값입니다.', `apt ${count}`);
  } else if (dnfCount && Number(dnfCount[1]) > 0) {
    const count = Number(dnfCount[1]);
    add(count > 100 ? 'high' : 'medium', '패치', `미적용 업데이트 ${count}건`, 'dnf 캐시 기준 집계입니다. 커널 패치가 포함되면 재부팅이 필요합니다.', `dnf ${count}`);
  } else if (!aptCheck && !aptInst && !dnfCount) {
    // A probe that times out must not read as "no pending updates".
    add('unknown', '패치', '업데이트 상태 확인 불가',
      /pkgmgr=unknown/.test(updates)
        ? '지원하는 패키지 관리자를 찾지 못했습니다.'
        : '패키지 관리자 조회가 제한 시간을 넘겨 미적용 업데이트 수를 세지 못했습니다. 서버에서 직접 확인하세요.',
      updates.split('\n').filter(Boolean).join(' ') || null);
  }
  if (/reboot_required=yes/.test(updates) || /needs_restarting_rc=1/.test(updates)) {
    add('medium', '패치', '재부팅 필요', '적용된 업데이트를 반영하려면 재부팅이 필요합니다. 커널 취약점이 아직 살아 있을 수 있습니다.', null);
  }

  // Passwordless sudo
  const sudo = auditSection(stdout, 'SUDO');
  const nopasswd = parseInt((/nopasswd:(\d+)/.exec(sudo) || [])[1] || '', 10);
  if (Number.isFinite(nopasswd) && nopasswd > 0) {
    add('medium', '권한', `NOPASSWD sudo 규칙 ${nopasswd}건`, '이 계정은 비밀번호 없이 sudo를 실행할 수 있습니다. SSH 키가 유출되면 즉시 root 권한으로 이어집니다.', `NOPASSWD x${nopasswd}`);
  }

  // Key and permission hygiene
  const keys = auditSection(stdout, 'KEYS');
  for (const line of keys.split('\n')) {
    const ak = /^ak:(.+):(\d+):(\d+)$/.exec(line.trim());
    if (ak) {
      const [, file, mode, count] = ak;
      const groupOther = mode.slice(-2);
      // Group/other write lets another local user add their own key — sshd refuses it too.
      if (/[2367]/.test(groupOther)) {
        add('critical', '권한', 'authorized_keys 쓰기 권한 개방', `${file} 권한이 ${mode} 입니다. 다른 로컬 사용자가 자기 공개키를 추가할 수 있습니다. 즉시 600으로 낮추세요.`, `${file} ${mode}`);
      } else if (/[4567]/.test(groupOther)) {
        add('low', '권한', 'authorized_keys 읽기 권한 개방', `${file} 권한이 ${mode} 입니다. 노출 위험은 낮지만(공개키) 관례상 600으로 두세요.`, `${file} ${mode}`);
      }
      if (Number(count) > 5) add('low', '권한', `authorized_keys 항목 ${count}개`, `${file}에 등록된 공개키가 많습니다. 사용하지 않는 키가 남아 있는지 확인하세요.`, `${file} keys=${count}`);
    }
    const dir = /^dir:(.+):(\d+)$/.exec(line.trim());
    if (dir && !/^700$/.test(dir[2])) {
      add('medium', '권한', '.ssh 디렉터리 권한 과다', `${dir[1]} 권한이 ${dir[2]} 입니다. 700이어야 합니다.`, `${dir[1]} ${dir[2]}`);
    }
    const pk = /^privkey:(.+):(\d+)$/.exec(line.trim());
    if (pk) {
      const tooOpen = !/^[0-6]00$/.test(pk[2]);
      add(tooOpen ? 'high' : 'low', '권한', tooOpen ? '개인키 권한 과다' : '서버에 개인키 파일 존재',
        tooOpen
          ? `${pk[1]} 권한이 ${pk[2]} 입니다. 600으로 낮추세요.`
          : `${pk[1]} — 서버에 저장된 개인키입니다. 이 서버가 뚫리면 다른 서버로 번집니다. 꼭 필요한 게 아니면 제거하세요.`,
        `${pk[1]} ${pk[2]}`);
    }
  }

  // Brute-force pressure
  const logins = auditSection(stdout, 'LOGINS');
  const failed = parseInt((/failed24h=(\d+)/.exec(logins) || [])[1] || '', 10);
  if (Number.isFinite(failed) && failed > 100) {
    add(failed > 1000 ? 'medium' : 'low', '침입차단', `24시간 SSH 인증 실패 ${failed}건`, '지속적인 무차별 대입 시도가 있습니다. fail2ban과 키 전용 인증이 적용돼 있는지 확인하세요.', `failed=${failed}`);
  }

  // Containers publishing to all interfaces
  const dockerSection = auditSection(stdout, 'DOCKER');
  const openContainers = dockerSection
    .split('\n')
    .filter(l => l.includes('|') && /0\.0\.0\.0:|\[::\]:/.test(l))
    .map(l => l.split('|')[0]);
  if (openContainers.length) {
    add('medium', '컨테이너', `전체 인터페이스에 게시된 컨테이너 ${openContainers.length}개`, '컨테이너 포트가 0.0.0.0으로 게시돼 호스트 방화벽을 우회합니다(도커는 iptables에 자체 규칙을 넣습니다). 내부 전용이라면 127.0.0.1로 게시하세요.', openContainers.join(', '));
  }

  // World-readable unit files carrying secrets
  const units = auditSection(stdout, 'UNITS');
  const leakyUnits = units.split('\n').filter(l => l.startsWith('unit:'));
  if (leakyUnits.length) {
    add('high', '시크릿', `시크릿이 담긴 world-readable 유닛 파일 ${leakyUnits.length}건`, 'systemd 유닛 파일에 API 키/토큰/비밀번호가 Environment=로 들어 있고 다른 사용자도 읽을 수 있습니다. 권한을 640으로 낮추고 해당 시크릿을 재발급하세요.', leakyUnits.map(l => l.replace('unit:', '')).join(', '));
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  const counts = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});
  const hostLine = auditSection(stdout, 'HOST').split('\n');

  return {
    host: (hostLine.find(l => l.startsWith('OS=')) || '').replace('OS=', '') || hostLine[0] || 'unknown',
    kernel: hostLine[0] || '',
    privileged: effective,
    findings,
    counts,
    checkedAt: new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' })
  };
}

// Build an ssh2 config from a stored connection profile.
function buildSshConfig(conn) {
  const sshConfig = { host: conn.host, port: conn.port || 22, username: conn.username, readyTimeout: 15000 };
  if (conn.authType === 'key') {
    if (!conn.privateKeyFile) throw new Error('이 서버에 등록된 개인키가 없습니다.');
    const keyPath = path.join(KEYS_DIR, conn.privateKeyFile);
    if (!fs.existsSync(keyPath)) throw new Error('개인키 파일을 서버에서 찾을 수 없습니다.');
    sshConfig.privateKey = fs.readFileSync(keyPath);
  } else if (conn.authType === 'password') {
    sshConfig.password = conn.password;
  } else {
    throw new Error('인증 방식이 올바르지 않습니다.');
  }
  return sshConfig;
}

// Run the read-only security audit against a stored server
app.post('/api/servers/:id/audit', (req, res) => {
  const conn = readConnections().find(c => c.id === req.params.id);
  if (!conn) return res.status(404).json({ error: 'Server not found' });

  let sshConfig;
  try {
    sshConfig = buildSshConfig(conn);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const sshClient = new Client();
  let settled = false;
  const finish = (payload) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    try { sshClient.end(); } catch { /* already closed */ }
    res.json(payload);
  };
  const timer = setTimeout(() => finish({ success: false, error: '점검이 60초 안에 끝나지 않아 중단했습니다.' }), 60000);

  sshClient.on('ready', () => {
    sshClient.exec(SECURITY_AUDIT_COMMAND, (err, stream) => {
      if (err) return finish({ success: false, error: `명령 실행 실패: ${err.message}` });

      let stdout = '';
      stream.on('data', (data) => {
        if (stdout.length < 512 * 1024) stdout += data.toString();
      });
      stream.stderr.on('data', () => { /* probes are expected to fail without sudo */ });
      stream.on('close', () => {
        try {
          finish({ success: true, server: { id: conn.id, name: conn.name, host: conn.host }, ...parseSecurityAudit(stdout) });
        } catch (e) {
          console.error('Audit parse error:', e);
          finish({ success: false, error: `점검 결과를 해석하지 못했습니다: ${e.message}` });
        }
      });
    });
  });

  sshClient.on('error', (err) => finish({ success: false, error: err.message }));
  sshClient.connect(sshConfig);
});

// Auth API Endpoints

// Login Route
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const attemptKey = req.socket.remoteAddress || 'unknown';
  const attempt = loginAttempts.get(attemptKey) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
  if (attempt.resetAt <= Date.now()) {
    attempt.count = 0;
    attempt.resetAt = Date.now() + 15 * 60 * 1000;
  }
  if (attempt.count >= 10) {
    res.setHeader('Retry-After', Math.ceil((attempt.resetAt - Date.now()) / 1000));
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const iterations = authConfig.iterations || 10000;
  const hash = hashPassword(password, authConfig.salt, iterations);
  if (username !== authConfig.username || !safeEqualHex(hash, authConfig.hash)) {
    attempt.count += 1;
    loginAttempts.set(attemptKey, attempt);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  loginAttempts.delete(attemptKey);

  // Upgrade hashes created by older releases after a successful login.
  if (iterations < PASSWORD_ITERATIONS) {
    const salt = crypto.randomBytes(16).toString('hex');
    authConfig = { ...authConfig, salt, hash: hashPassword(password, salt), iterations: PASSWORD_ITERATIONS };
    writeJsonSecure(AUTH_FILE, authConfig);
  }

  // Generate secure random session token and set the HTTP-Only cookie
  const token = createSession({ provider: 'local', name: authConfig.username });
  res.setHeader('Set-Cookie', sessionCookie(token));
  res.json({ success: true });
});

// Google Login: start the authorization code flow
app.get('/api/auth/google', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!GOOGLE_LOGIN_ENABLED) {
    return res.redirect('/login.html?error=google_disabled');
  }

  prunePendingOAuthStates();
  const state = base64UrlEncode(crypto.randomBytes(32));
  const nonce = base64UrlEncode(crypto.randomBytes(32));
  const codeVerifier = base64UrlEncode(crypto.randomBytes(32));
  const codeChallenge = base64UrlEncode(crypto.createHash('sha256').update(codeVerifier).digest());
  const redirectUri = resolveGoogleRedirectUri(req);

  pendingOAuthStates.set(state, { nonce, codeVerifier, redirectUri, expiresAt: Date.now() + OAUTH_STATE_TTL_MS });
  res.setHeader('Set-Cookie', oauthStateCookie(state));

  const authorizeUrl = new URL(GOOGLE_AUTH_ENDPOINT);
  authorizeUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', 'openid email profile');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('nonce', nonce);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  authorizeUrl.searchParams.set('prompt', 'select_account');
  res.redirect(authorizeUrl.toString());
});

// Google Login: exchange the authorization code and open a portal session
app.get('/api/auth/google/callback', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  const fail = (code) => {
    res.setHeader('Set-Cookie', oauthStateCookie(''));
    res.redirect(`/login.html?error=${code}`);
  };

  if (!GOOGLE_LOGIN_ENABLED) return fail('google_disabled');
  if (req.query.error) return fail('google_denied');

  prunePendingOAuthStates();
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const cookieState = getCookie(req, 'oauth_state');
  if (!code || !state || !cookieState || state !== cookieState) return fail('google_state');

  const pending = pendingOAuthStates.get(state);
  pendingOAuthStates.delete(state);
  if (!pending) return fail('google_state');

  try {
    const tokenResponse = await fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: pending.redirectUri,
        grant_type: 'authorization_code',
        code_verifier: pending.codeVerifier
      })
    });
    if (!tokenResponse.ok) {
      console.error(`Google token exchange failed with HTTP ${tokenResponse.status}.`);
      return fail('google_token');
    }

    const tokens = await tokenResponse.json();
    const payload = await verifyGoogleIdToken(tokens.id_token, pending.nonce);
    if (!isGoogleAccountAllowed(payload)) {
      console.warn(`Google login rejected for ${payload.email || 'unknown account'}: not on the allow list.`);
      return fail('google_forbidden');
    }

    const email = String(payload.email).toLowerCase();
    const token = createSession({ provider: 'google', email, name: payload.name || email });
    res.setHeader('Set-Cookie', [oauthStateCookie(''), sessionCookie(token)]);
    console.log(`Google login succeeded for ${email}.`);

    // The SameSite=Strict session cookie would be withheld on a 302 that is still part
    // of the cross-site redirect chain from Google, so bounce through our own document.
    res.type('html').send(`<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="0;url=/">
  <title>Signing in...</title>
</head>
<body>
  <p>로그인 처리 중입니다. <a href="/">자동으로 이동하지 않으면 여기를 클릭하세요.</a></p>
</body>
</html>`);
  } catch (err) {
    console.error('Google login error:', err.message);
    return fail('google_failed');
  }
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
  const session = getSession(getCookie(req, 'session_token'));
  const user = (session && session.user) || { provider: 'local' };
  res.json({
    username: authConfig.username,
    provider: user.provider || 'local',
    email: user.email || null,
    displayName: user.name || authConfig.username
  });
});

// Get Portal Configuration
app.get('/api/config', (req, res) => {
  res.json({ portalName: appConfig.portalName, googleLoginEnabled: GOOGLE_LOGIN_ENABLED });
});

// Update Profile & Portal Configuration (Username, Password, Portal Name)
app.post('/api/update-profile', (req, res) => {
  const { currentPassword, newUsername, newPassword, portalName } = req.body;
  if (!currentPassword || !newUsername) {
    return res.status(400).json({ error: 'Current password and username are required.' });
  }

  const currentHash = hashPassword(currentPassword, authConfig.salt, authConfig.iterations || 10000);
  if (!safeEqualHex(currentHash, authConfig.hash)) {
    return res.status(400).json({ error: 'Current password does not match.' });
  }

  authConfig.username = newUsername;

  if (newPassword) {
    if (newPassword.length < 12) {
      return res.status(400).json({ error: 'New password must be at least 12 characters.' });
    }
    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = hashPassword(newPassword, newSalt);
    authConfig.salt = newSalt;
    authConfig.hash = newHash;
    authConfig.iterations = PASSWORD_ITERATIONS;
  }

  // Update Portal Name if provided
  if (portalName) {
    appConfig.portalName = portalName;
    writeJsonSecure(CONFIG_FILE, appConfig);
  }

  writeJsonSecure(AUTH_FILE, authConfig);
  activeSessions.clear();

  res.json({ success: true });
});

// Setup server and WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ssh' });

wss.on('connection', (ws, req) => {
  const requestOrigin = req.headers.origin;
  if (!requestOrigin) {
    ws.close(1008, 'Origin header required');
    return;
  }
  try {
    if (new URL(requestOrigin).host !== req.headers.host) {
      ws.close(1008, 'Cross-origin WebSocket rejected');
      return;
    }
  } catch {
    ws.close(1008, 'Invalid Origin header');
    return;
  }
  const urlParams = new URL(req.url, `http://${req.headers.host}`);
  const id = urlParams.searchParams.get('id');
  const termCols = parseInt(urlParams.searchParams.get('cols'), 10) || 80;
  const termRows = parseInt(urlParams.searchParams.get('rows'), 10) || 24;

  // Authenticate WebSocket Session
  const cookies = req.headers.cookie || '';
  const tokenMatch = cookies.match(/session_token=([^;]+)/);
  const token = tokenMatch ? tokenMatch[1] : null;

  if (!getSession(token)) {
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
