require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const net = require('net');
const https = require('https');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const logger = require('./logger');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8443;
const PRINTER_PORT = 9100;
const { getPrinterIp, setPrinterIp } = require('./printerMap');
const { scanNetwork, defaultCidrFromInterfaces } = require('./discoverPrinters');
const DISCOVERY_INTERVAL_MS = parseInt(process.env.DISCOVERY_INTERVAL_MS || '300000', 10); // 5 minutes
const DISCOVERY_PORTS = [9100, 515, 631, 80, 443];
const JWT_SECRET = process.env.JWT_SECRET || '';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Routes
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.post('/echo', (req, res) => {
    res.json({ received: req.body });
});

// Demonstrate using the built-in `net` module
app.get('/is-ip/:value', (req, res) => {
    const { value } = req.params;
    res.json({ value, isIP: net.isIP(value), isIPv4: net.isIPv4(value), isIPv6: net.isIPv6(value) });
});

// Optional example using axios (won't run unless endpoint is called)
// Example external call route removed to avoid external dependencies

// Basic UI to view printers and assign mapping
app.get('/ui', (req, res) => {
    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Print Bridge UI</title>
  <style>
    body { font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; color: #222; }
    h1 { font-size: 20px; margin: 0 0 12px; }
    .controls { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
    button, input, select { font-size: 14px; padding: 6px 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align: left; border-bottom: 1px solid #ddd; padding: 8px; }
    th { background: #f6f6f6; position: sticky; top: 0; }
    .status { font-size: 12px; color: #666; margin-top: 8px; }
    .badge { display: inline-block; background: #eef; color: #224; padding: 2px 6px; border-radius: 10px; font-size: 12px; margin-right: 4px; }
    .ok { color: #0a0; }
    .err { color: #a00; }
    .muted { color: #666; }
  </style>
 </head>
<body>
  <h1>Print Bridge</h1>
  <div class="controls">
    <button id="refresh">Refresh</button>
    <button id="rescan">Re-scan LAN</button>
    <span id="summary" class="muted"></span>
  </div>
  <table id="tbl">
    <thead>
      <tr>
        <th>IP</th>
        <th>Ports</th>
        <th>MAC</th>
        <th>Hostname</th>
        <th>Assign</th>
      </tr>
    </thead>
    <tbody>
      <tr><td colspan="5" class="muted">Loading…</td></tr>
    </tbody>
  </table>
  <p class="status" id="status"></p>

  <script>
    const $ = (sel) => document.querySelector(sel);
    const tblBody = $('#tbl tbody');
    const statusEl = $('#status');
    const summaryEl = $('#summary');

    function fmtPorts(ports) { return (ports || []).map(p => '<span class="badge">' + p + '</span>').join(''); }

    async function loadPrinters(opts={}) {
      statusEl.textContent = 'Fetching printers…';
      try {
        const q = opts.refresh ? '?refresh=true' : '';
        const res = await fetch('/printers' + q, { headers: { 'Accept': 'application/json' } });
        const data = await res.json();
        const printers = data.printers || [];
        const rows = printers.map(p => {
          const ip = p.ip || '';
          const mac = p.mac || '';
          const host = p.hostname || '';
          const ports = p.ports || [];
          return '<tr>' +
            '<td><code>' + ip + '</code></td>' +
            '<td>' + fmtPorts(ports) + '</td>' +
            '<td>' + (mac ? '<code>' + mac + '</code>' : '') + '</td>' +
            '<td>' + host + '</td>' +
            '<td><button data-ip="' + ip + '" class="assign">Assign…</button></td>' +
          '</tr>';
        }).join('');
        tblBody.innerHTML = rows || '<tr><td colspan="5" class="muted">No printers found.</td></tr>';
        summaryEl.textContent = 'CIDR: ' + (data.cidr || 'n/a') +
          ' • ' + printers.length + ' printer(s) • Updated: ' +
          (data.lastUpdated ? new Date(data.lastUpdated).toLocaleString() : 'n/a');
        statusEl.textContent = '';
      } catch (e) {
        statusEl.textContent = 'Failed to fetch printers: ' + e.message;
      }
    }

    async function assign(ip) {
      const terminalId = prompt('Enter terminalId to assign to ' + ip + ':');
      if (!terminalId) return;
      statusEl.textContent = 'Assigning…';
      try {
        const res = await fetch('/assign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ terminalId, ip }) });
        const data = await res.json();
        if (res.ok && data && data.ok) {
          statusEl.innerHTML = '<span class="ok">Assigned</span> ' + terminalId + ' → ' + ip;
        } else {
          statusEl.innerHTML = '<span class="err">Assign failed:</span> ' + (data && (data.error || JSON.stringify(data)));
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="err">Assign error:</span> ' + e.message;
      }
    }

    document.addEventListener('click', (ev) => {
      const btn = ev.target.closest('button.assign');
      if (btn) assign(btn.getAttribute('data-ip'));
    });

    document.getElementById('refresh').addEventListener('click', () => loadPrinters({}));
    document.getElementById('rescan').addEventListener('click', () => loadPrinters({ refresh: true }));

    loadPrinters({});
  </script>
</body>
</html>`;
    res.set('Content-Type', 'text/html');
    res.send(html);
});

// POST /assign { terminalId, ip }
// Stores/updates the mapping in printerMap.json
app.post('/assign', authenticateToken, async (req, res) => {
    const { terminalId, ip } = req.body || {};
    if (!terminalId || !ip) {
        return res.status(400).json({ error: 'terminalId and ip are required' });
    }
    if (net.isIP(String(ip)) === 0) {
        return res.status(400).json({ error: 'ip must be a valid IPv4/IPv6 address' });
    }
    try {
        const map = setPrinterIp(String(terminalId), String(ip));
        logger.info('Printer mapping assigned', { terminalId: String(terminalId), ip: String(ip) });
        return res.json({ ok: true, terminalId: String(terminalId), ip: String(ip), mappings: map });
    } catch (err) {
        logger.error('Failed to assign printer mapping', { error: err.message || String(err), terminalId });
        return res.status(500).json({ ok: false, error: err.message || String(err) });
    }
});

// GET /printers - discover printers on the network
// Query params:
//   cidr: optional, e.g., 192.168.1.0/24 (defaults to interface-derived)
//   ports: optional, comma-separated (default: 9100,515,631,80,443)
//   timeout: optional, per host/port timeout in ms (default: 800)
//   concurrency: optional, parallel probes (default: 128)
//   all: optional, include hosts without 9100 open
// Cached discovery state
let discoveryCache = { cidr: null, lastUpdated: 0, printers: [] };

function truthy(v) {
    return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

async function runDiscovery(cidr) {
    const selectedCidr = cidr || process.env.SUBNET || defaultCidrFromInterfaces();
    logger.info('Printer discovery started', { cidr: selectedCidr, ports: DISCOVERY_PORTS });
    try {
        const discovered = await scanNetwork({ cidr: selectedCidr, ports: DISCOVERY_PORTS, timeoutMs: 800, concurrency: 128, includeNon9100: false });
        const printers = await Promise.all(
            discovered.map(async (d) => {
                let hostname = null;
                try {
                    const names = await dns.reverse(d.ip);
                    hostname = names && names.length ? names[0] : null;
                } catch (_) {
                    hostname = null;
                }
                return { ip: d.ip, ports: d.openPorts, mac: d.mac || null, hostname };
            })
        );
        discoveryCache = { cidr: selectedCidr, lastUpdated: Date.now(), printers };
        logger.info('Printer discovery complete', { cidr: selectedCidr, count: printers.length });
        return printers;
    } catch (err) {
        logger.error('Printer discovery failed', { error: err.message });
        throw err;
    }
}

app.get('/printers', async (req, res) => {
    try {
        if (truthy(req.query.refresh)) {
            const cidr = req.query.cidr || discoveryCache.cidr || process.env.SUBNET || defaultCidrFromInterfaces();
            await runDiscovery(cidr);
        }
        const { cidr, lastUpdated, printers } = discoveryCache;
        if (!lastUpdated) {
            // No discovery has run yet; kick one off but don’t block
            runDiscovery(process.env.SUBNET || defaultCidrFromInterfaces()).catch(() => {});
        }
        res.json({ cidr, lastUpdated, count: (printers || []).length, printers: printers || [] });
    } catch (err) {
        logger.error('GET /printers failed', { error: err.message });
        res.status(500).json({ error: err.message });
    }
});

function sendToPrinter(ip, buffer, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: ip, port: PRINTER_PORT });
        let settled = false;

        socket.setTimeout(timeoutMs);

        socket.on('connect', () => {
            socket.write(buffer, (err) => {
                if (err) {
                    if (!settled) {
                        settled = true;
                        socket.destroy();
                        reject(err);
                    }
                    return;
                }
                socket.end();
            });
        });

        socket.on('timeout', () => {
            if (!settled) {
                settled = true;
                socket.destroy(new Error('Socket timeout'));
                reject(new Error('Printer connection timed out'));
            }
        });

        socket.on('error', (err) => {
            if (!settled) {
                settled = true;
                reject(err);
            }
        });

        socket.on('close', (hadError) => {
            if (!settled && !hadError) {
                settled = true;
                resolve({ bytesWritten: socket.bytesWritten });
            }
        });
    });
}

// POST /print { terminalId, data } where data is base64-encoded ESC/POS bytes
app.post('/print', authenticateToken, async (req, res) => {
    const { terminalId, data } = req.body || {};

    if (!terminalId || typeof data !== 'string') {
        return res.status(400).json({
            error: 'terminalId and data (base64) are required',
        });
    }

    const ip = getPrinterIp(terminalId);
    if (!ip) {
        try {
            const cidr = process.env.SUBNET || defaultCidrFromInterfaces();
            logger.warn('No printer mapping found; starting discovery', { terminalId, cidr });
            const discovered = await scanNetwork({ cidr, ports: [9100, 515, 631], timeoutMs: 800, concurrency: 128, includeNon9100: false });
            logger.info('Discovery result for missing mapping', { terminalId, count: discovered.length, printers: discovered });
            return res.status(404).json({
                error: 'No printer mapping found for terminalId',
                terminalId,
                hint: 'Set mapping in printerMap.json or via utility',
                discoveredPrinters: discovered,
            });
        } catch (e) {
            logger.error('Discovery failed for missing mapping', { terminalId, error: e.message });
            return res.status(404).json({
                error: 'No printer mapping found for terminalId',
                terminalId,
                discoveredPrinters: [],
                discoveryError: e.message,
            });
        }
    }

    let payload;
    try {
        payload = Buffer.from(data, 'base64');
    } catch (e) {
        return res.status(400).json({ error: 'Invalid base64 data' });
    }
    if (!payload || payload.length === 0) {
        return res.status(400).json({ error: 'Decoded payload is empty' });
    }

    try {
        logger.info('Dispatching direct print request', { terminalId, ip, bytes: payload.length });
        const result = await sendToPrinter(ip, payload);
        logger.info('Direct print success', { terminalId, ip, bytesSent: result.bytesWritten });
        return res.json({ ok: true, terminalId, ip, bytesSent: result.bytesWritten });
    } catch (err) {
        logger.error('Direct print failed', { terminalId, ip, error: err.message });
        return res.status(502).json({ ok: false, error: err.message, terminalId, ip });
    }
});

// HTTPS server setup with self-signed certificates
const keyPath = path.join(__dirname, 'key.pem');
const certPath = path.join(__dirname, 'cert.pem');

function boot() {
    const credentials = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
    };
    https.createServer(credentials, app).listen(PORT, () => {
        logger.info(`HTTPS server listening on https://localhost:${PORT}`);
    });

    // ----------------------
    // Scheduled printer discovery
    // ----------------------
    logger.info('Configuring periodic printer discovery', { DISCOVERY_INTERVAL_MS, SUBNET: process.env.SUBNET || null });
    // Run once at startup
    runDiscovery(process.env.SUBNET || defaultCidrFromInterfaces()).catch(() => {});
    // Re-scan every interval
    setInterval(() => {
        runDiscovery(discoveryCache.cidr || process.env.SUBNET || defaultCidrFromInterfaces()).catch(() => {});
    }, DISCOVERY_INTERVAL_MS);

    // ----------------------
    // Background print poller
    // ----------------------
    if (PRINT_POLL_ENABLED) {
        logger.info('Print poller configured', { PRINT_JOBS_URL, STORE_ID, POLL_INTERVAL_MS, POLL_INSECURE_TLS, POLL_CA_FILE: POLL_CA_FILE || null });
        setInterval(pollOnce, POLL_INTERVAL_MS);
        // Kick off immediately
        setImmediate(pollOnce);
    } else {
        logger.info('Print poller disabled; PRINT_JOBS_URL not set');
    }
}

// ----------------------
// Background print poller config
// ----------------------
const PRINT_JOBS_URL = (process.env.PRINT_JOBS_URL || '').trim();
const PRINT_POLL_ENABLED = PRINT_JOBS_URL.length > 0;
const STORE_ID = process.env.STORE_ID || '0';
const POLL_INTERVAL_MS = parseInt(process.env.PRINT_POLL_INTERVAL_MS || '5000', 10);
// Outbound auth preference: JWT (JWT_TOKEN or POLL_JWT), fallback to API_TOKEN
const OUTBOUND_JWT = process.env.JWT_TOKEN || process.env.POLL_JWT || '';
const API_TOKEN = process.env.API_TOKEN || process.env.PRINT_API_TOKEN || '';
const POLL_INSECURE_TLS = ['1','true','yes','on'].includes(String(process.env.PRINT_POLL_INSECURE_TLS).toLowerCase());
const POLL_CA_FILE = process.env.PRINT_POLL_CA_FILE || '';

async function fetchPendingPrintJobs() {
    if (!PRINT_POLL_ENABLED) {
        return [];
    }
    try {
        const headers = {};
        if (OUTBOUND_JWT) headers['Authorization'] = `Bearer ${OUTBOUND_JWT}`;
        else if (API_TOKEN) headers['Authorization'] = `Bearer ${API_TOKEN}`;
        let httpsAgent;
        try {
            const agentOpts = {};
            if (POLL_INSECURE_TLS) agentOpts.rejectUnauthorized = false;
            if (POLL_CA_FILE && fs.existsSync(POLL_CA_FILE)) agentOpts.ca = fs.readFileSync(POLL_CA_FILE);
            if (Object.keys(agentOpts).length) httpsAgent = new https.Agent(agentOpts);
        } catch (e) {
            logger.warn('Poller HTTPS agent setup failed', { error: e.message });
        }
        const resp = await axios.get(PRINT_JOBS_URL, {
            params: { storeId: STORE_ID },
            headers,
            httpsAgent,
            timeout: 8000,
        });
        const data = resp && resp.data;
        if (!data) return [];
        // Accept either { jobs: [...] } or [...] directly
        const jobs = Array.isArray(data) ? data : Array.isArray(data.jobs) ? data.jobs : [];
        return jobs;
    } catch (err) {
        logger.error('Print poll: fetch failed', { error: err.message || err });
        return [];
    }
}

async function processPrintJob(job) {
    const { terminalId, data } = job || {};
    if (!terminalId || typeof data !== 'string') {
        logger.warn('Print job skipped: invalid payload', { job });
        return { ok: false, error: 'invalid job' };
    }

    const ip = getPrinterIp(terminalId);
    if (!ip) {
        logger.warn('No mapping for terminal; skipping job', { terminalId });
        return { ok: false, error: 'no mapping', terminalId };
    }

    let payload;
    try {
        payload = Buffer.from(data, 'base64');
    } catch (e) {
        logger.warn('Job base64 decode failed', { terminalId, error: e.message });
        return { ok: false, error: 'invalid base64', terminalId };
    }
    if (!payload || payload.length === 0) {
        return { ok: false, error: 'empty payload', terminalId };
    }

    try {
        logger.info('Dispatching polled job', { terminalId, ip, bytes: payload.length });
        const result = await sendToPrinter(ip, payload);
        logger.info('Polled job success', { terminalId, ip, bytesSent: result.bytesWritten });
        return { ok: true, terminalId, ip, bytesSent: result.bytesWritten };
    } catch (err) {
        logger.error('Polled job send failed', { terminalId, ip, error: err.message || String(err) });
        return { ok: false, error: err.message || String(err), terminalId, ip };
    }
}

let pollInFlight = false;
async function pollOnce() {
    if (!PRINT_POLL_ENABLED) return;
    if (pollInFlight) return;
    pollInFlight = true;
    try {
        const jobs = await fetchPendingPrintJobs();
        if (jobs.length) logger.info('Processing print jobs', { count: jobs.length });
        for (const job of jobs) {
            const res = await processPrintJob(job);
            if (!res.ok) {
                // already logged; continue
            }
        }
    } finally {
        pollInFlight = false;
    }
}

if (require.main === module && process.env.NODE_ENV !== 'test') {
    boot();
}
// Authentication middleware (JWT)
// Requires Authorization: Bearer <token> header. Verifies with JWT_SECRET.
function authenticateToken(req, res, next) {
    try {
        const header = req.headers['authorization'] || req.headers['Authorization'];
        if (!header || !/^Bearer\s+/i.test(header)) {
            return res.status(401).json({ error: 'Unauthorized: missing Bearer token' });
        }
        if (!JWT_SECRET) {
            logger.error('JWT_SECRET not set; rejecting auth request');
            return res.status(401).json({ error: 'Unauthorized: server not configured' });
        }
        const token = header.split(/\s+/)[1];
        jwt.verify(token, JWT_SECRET, (err, payload) => {
            if (err) {
                return res.status(401).json({ error: 'Unauthorized: invalid token' });
            }
            req.user = payload;
            next();
        });
    } catch (e) {
        logger.error('Auth middleware error', { error: e.message });
        return res.status(401).json({ error: 'Unauthorized' });
    }
}

module.exports = {
    app,
    boot,
    sendToPrinter,
    runDiscovery,
    fetchPendingPrintJobs,
    processPrintJob,
    pollOnce,
    authenticateToken,
};
