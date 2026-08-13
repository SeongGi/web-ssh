const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const KEYS_DIR = path.join(DATA_DIR, 'keys');
const SSH_EXPORT_DIR = process.env.SSH_IMPORT_DIR && path.resolve(process.env.SSH_IMPORT_DIR);
if (!SSH_EXPORT_DIR) {
  console.error('Error: SSH_IMPORT_DIR must point to an external SSH export directory.');
  process.exit(1);
}
const CONFIG_FILE = path.join(SSH_EXPORT_DIR, 'config');
const README_FILE = path.join(SSH_EXPORT_DIR, 'README.md');

// Ensure directories exist
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
fs.chmodSync(DATA_DIR, 0o700);
fs.chmodSync(KEYS_DIR, 0o700);

function parseSSHConfig(configContent) {
  const servers = [];
  const lines = configContent.split('\n');
  let currentServer = null;

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;

    const parts = line.split(/\s+/);
    const key = parts[0].toLowerCase();
    const value = parts.slice(1).join(' ');

    if (key === 'host') {
      if (currentServer) {
        servers.push(currentServer);
      }
      currentServer = {
        id: crypto.randomUUID(),
        name: value,
        host: '',
        port: 22,
        username: '',
        authType: 'key',
        privateKeyFile: '',
        description: '',
        spec: '',
        os: '',
        group: 'OCI Cloud'
      };
    } else if (currentServer) {
      if (key === 'hostname') {
        currentServer.host = value;
      } else if (key === 'user') {
        currentServer.username = value;
      } else if (key === 'port') {
        currentServer.port = parseInt(value, 10) || 22;
      } else if (key === 'identityfile') {
        // Resolve IdentityFile name
        const pemName = path.basename(value);
        currentServer.identityFileSrc = pemName;
      }
    }
  }

  if (currentServer) {
    servers.push(currentServer);
  }

  return servers;
}

function parseReadme(readmeContent) {
  const hostInfo = {};
  const lines = readmeContent.split('\n');
  
  for (let line of lines) {
    if (line.trim().startsWith('|') && !line.includes('Host') && !line.includes('---')) {
      const cols = line.split('|').map(c => c.trim());
      if (cols.length >= 7) {
        const host = cols[1];
        const os = cols[4];
        const spec = cols[5];
        const desc = cols[6];
        hostInfo[host] = { os, spec, desc };
      }
    }
  }
  return hostInfo;
}

function run() {
  console.log('Starting SSH servers configuration import...');

  if (!fs.existsSync(CONFIG_FILE)) {
    console.error(`Error: Config file not found at ${CONFIG_FILE}`);
    process.exit(1);
  }

  const configContent = fs.readFileSync(CONFIG_FILE, 'utf-8');
  const servers = parseSSHConfig(configContent);

  let hostInfo = {};
  if (fs.existsSync(README_FILE)) {
    const readmeContent = fs.readFileSync(README_FILE, 'utf-8');
    hostInfo = parseReadme(readmeContent);
    console.log('Parsed readme information for description styling.');
  }

  // Process each parsed server
  const importedServers = servers.map(server => {
    // Merge README details if available
    if (hostInfo[server.name]) {
      server.os = hostInfo[server.name].os;
      server.spec = hostInfo[server.name].spec;
      server.description = hostInfo[server.name].desc;
    }

    // Handle private key copying
    if (server.identityFileSrc) {
      const srcKeyPath = path.join(SSH_EXPORT_DIR, server.identityFileSrc);
      if (fs.existsSync(srcKeyPath)) {
        const keyUuidName = `${server.id}.pem`;
        const destKeyPath = path.join(KEYS_DIR, keyUuidName);
        
        fs.copyFileSync(srcKeyPath, destKeyPath);
        // Set permissions (chmod 600)
        fs.chmodSync(destKeyPath, 0o600);
        
        server.privateKeyFile = keyUuidName;
        console.log(`Imported key for ${server.name} -> ${keyUuidName}`);
      } else {
        console.warn(`Warning: Key file ${server.identityFileSrc} not found in ${SSH_EXPORT_DIR}`);
      }
      delete server.identityFileSrc; // Clean up temp property
    }

    return server;
  });

  const connectionsJsonPath = path.join(DATA_DIR, 'connections.json');
  fs.writeFileSync(connectionsJsonPath, JSON.stringify(importedServers, null, 2), { encoding: 'utf-8', mode: 0o600 });
  fs.chmodSync(connectionsJsonPath, 0o600);
  console.log(`Successfully imported ${importedServers.length} servers to ${connectionsJsonPath}`);
}

run();
