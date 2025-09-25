#!/usr/bin/env node
const os = require('os');
const { execFile } = require('child_process');
const net = require('net');

// ---------- IP utilities ----------
function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + (parseInt(oct, 10) & 0xff), 0) >>> 0;
}

function intToIp(int) {
  return [24, 16, 8, 0].map(shift => (int >>> shift) & 0xff).join('.');
}

function maskToPrefix(mask) {
  const n = ipToInt(mask);
  let count = 0;
  for (let i = 31; i >= 0; i--) {
    if ((n >>> i) & 1) count++; else break;
  }
  return count;
}

function cidrToRange(cidr) {
  const [base, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error('Invalid CIDR prefix');
  const baseInt = ipToInt(base);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const first = prefix >= 31 ? network : (network + 1) >>> 0;
  const last = prefix >= 31 ? broadcast : (broadcast - 1) >>> 0;
  return { first, last, network, broadcast };
}

function* iterHosts(first, last) {
  for (let n = first; n <= last; n++) {
    yield intToIp(n >>> 0);
  }
}

function defaultCidrFromInterfaces() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const info of ifaces[name]) {
      if (info.family === 'IPv4' && !info.internal) {
        const prefix = maskToPrefix(info.netmask);
        const baseInt = ipToInt(info.address) & (prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0);
        return `${intToIp(baseInt >>> 0)}/${prefix}`;
      }
    }
  }
  // fallback to typical local net
  return '192.168.1.0/24';
}

// ---------- Ping and Port Check ----------
function pingHost(ip, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const platform = os.platform();
    let cmd = 'ping';
    let args;
    if (platform === 'win32') {
      args = ['-n', '1', '-w', String(timeoutMs), ip];
    } else if (platform === 'darwin') {
      // -c 1 one packet, -W timeout in milliseconds on macOS
      args = ['-c', '1', '-W', String(timeoutMs), ip];
    } else {
      // Linux: -c 1 one packet, -W timeout in seconds
      const seconds = Math.max(1, Math.ceil(timeoutMs / 1000));
      args = ['-c', '1', '-W', String(seconds), ip];
    }
    const child = execFile(cmd, args, { timeout: timeoutMs + 1000 }, (err) => {
      resolve(!err); // success exit -> reachable
    });
    child.on('error', () => resolve(false));
  });
}

function checkPort(ip, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, ip);
  });
}

function getMacAddress(ip) {
  return new Promise((resolve) => {
    const platform = os.platform();
    const normalize = (mac) => mac ? mac.toLowerCase().replace(/-/g, ':') : null;
    const anyMac = (text) => {
      const m = /([0-9a-fA-F]{2}([-:])){5}[0-9a-fA-F]{2}/.exec(String(text || ''));
      return normalize(m && m[0]);
    };
    const macOnIpLine = (text) => {
      const lines = String(text || '').split(/\r?\n/);
      for (const line of lines) {
        if (line.includes(ip)) {
          const m = /([0-9a-fA-F]{2}([-:])){5}[0-9a-fA-F]{2}/.exec(line);
          if (m) return normalize(m[0]);
        }
      }
      return null;
    };

    const tryCmds = [];
    if (platform === 'win32') {
      tryCmds.push(['arp', ['-a', ip]]);
      tryCmds.push(['arp', ['-a']]); // search whole ARP table
      tryCmds.push(['nbtstat', ['-A', ip]]); // sometimes reveals MAC
    } else if (platform === 'darwin') {
      tryCmds.push(['arp', ['-n', ip]]);
      tryCmds.push(['arp', ['-a', ip]]);
      tryCmds.push(['arp', ['-an']]); // parse table
    } else {
      // Linux and others
      tryCmds.push(['arp', ['-n', ip]]);
      tryCmds.push(['arp', ['-a', ip]]);
      tryCmds.push(['ip', ['neigh', 'show', ip]]);
      tryCmds.push(['arp', ['-an']]);
    }

    const next = (idx) => {
      if (idx >= tryCmds.length) return resolve(null);
      const [cmd, args] = tryCmds[idx];
      execFile(cmd, args, { timeout: 1500 }, (err, stdout) => {
        if (!err && stdout) {
          const mac = macOnIpLine(stdout) || anyMac(stdout);
          if (mac) return resolve(mac);
        }
        return next(idx + 1);
      }).on('error', () => next(idx + 1));
    };

    next(0);
  });
}

// ---------- Concurrency helper ----------
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  let active = 0;
  return new Promise((resolve, reject) => {
    const next = () => {
      if (i >= items.length && active === 0) return resolve(results);
      while (active < limit && i < items.length) {
        const idx = i++;
        active++;
        Promise.resolve(fn(items[idx], idx))
          .then((res) => { results[idx] = res; active--; next(); })
          .catch((err) => { reject(err); });
      }
    };
    next();
  });
}

// ---------- Main scanner ----------
async function scanNetwork({ cidr, ports, timeoutMs, concurrency, includeNon9100 = false }) {
  const { first, last } = cidrToRange(cidr);
  const ips = Array.from(iterHosts(first, last));

  const results = await mapLimit(ips, concurrency, async (ip) => {
    const reachable = await pingHost(ip, timeoutMs);
    // Probe ports concurrently per host for speed
    const checks = (ports || [9100]).map((p) =>
      checkPort(ip, p, timeoutMs).then((open) => (open ? p : null))
    );
    const checkResults = await Promise.all(checks);
    const openPorts = checkResults.filter((p) => p != null);
    // Only collect MAC if likely interesting (reachable or any port open)
    let mac = null;
    if (reachable || openPorts.length > 0) {
      mac = await getMacAddress(ip);
    }
    return { ip, mac, openPorts };
  });

  // Filter to likely printers: port 9100 open, unless includeNon9100 is true
  const filtered = includeNon9100 ? results : results.filter(r => r.openPorts.includes(9100));
  return filtered.filter(Boolean);
}

// ---------- CLI ----------
function parseArgs(argv) {
  const args = { ports: [9100, 515, 631, 80, 443], timeoutMs: 800, concurrency: 128, includeNon9100: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cidr' && argv[i + 1]) { args.cidr = argv[++i]; continue; }
    if (a === '--ports' && argv[i + 1]) { args.ports = argv[++i].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !Number.isNaN(n)); continue; }
    if (a === '--timeout' && argv[i + 1]) { args.timeoutMs = parseInt(argv[++i], 10) || args.timeoutMs; continue; }
    if (a === '--concurrency' && argv[i + 1]) { args.concurrency = parseInt(argv[++i], 10) || args.concurrency; continue; }
    if (a === '--all') { args.includeNon9100 = true; continue; }
    if (a === '--help' || a === '-h') { args.help = true; }
  }
  if (!args.cidr) args.cidr = process.env.SUBNET || defaultCidrFromInterfaces();
  return args;
}

function printHelp() {
  console.log(`Usage: node discoverPrinters.js [--cidr 192.168.1.0/24] [--ports 9100,515,631] [--timeout 800] [--concurrency 128] [--all]\n\n` +
    `Options:\n` +
    `  --cidr         CIDR to scan (default: infer from interfaces or 192.168.1.0/24)\n` +
    `  --ports        Comma-separated ports to probe (default: 9100,515,631,80,443)\n` +
    `  --timeout      Per-ping/port timeout in ms (default: 800)\n` +
    `  --concurrency  Parallel probes (default: 128)\n` +
    `  --all          Include hosts without port 9100 open\n` +
    `  --help         Show this help`);
}

if (require.main === module) {
  (async () => {
    const args = parseArgs(process.argv);
    if (args.help) { printHelp(); process.exit(0); }
    try {
      const printers = await scanNetwork(args);
      console.log(JSON.stringify({ cidr: args.cidr, count: printers.length, printers }, null, 2));
    } catch (err) {
      console.error('Scan failed:', err.message || err);
      process.exit(1);
    }
  })();
}

module.exports = { scanNetwork, defaultCidrFromInterfaces };
