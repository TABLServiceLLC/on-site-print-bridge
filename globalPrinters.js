const fs = require('fs');
const path = require('path');
const net = require('net');

const GLOBAL_PRINTERS_PATH = process.env.GLOBAL_PRINTERS_FILE || path.join(__dirname, 'globalPrinters.json');

let cached = null;
let cachedMtime = 0;

function ensureFile() {
  try {
    if (!fs.existsSync(GLOBAL_PRINTERS_PATH)) {
      const dir = path.dirname(GLOBAL_PRINTERS_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(GLOBAL_PRINTERS_PATH, '{}\n', 'utf8');
    }
  } catch (err) {
    // ignore; subsequent reads will handle errors
  }
}

function readStore() {
  ensureFile();
  try {
    const stat = fs.statSync(GLOBAL_PRINTERS_PATH);
    const mtime = stat.mtimeMs || 0;
    if (cached && cachedMtime === mtime) return cached;
    const raw = fs.readFileSync(GLOBAL_PRINTERS_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    if (!parsed || typeof parsed !== 'object') {
      cached = {};
    } else {
      cached = parsed;
    }
    cachedMtime = mtime;
    return cached;
  } catch (err) {
    cached = {};
    cachedMtime = 0;
    return cached;
  }
}

function writeStore(map) {
  const data = JSON.stringify(map || {}, null, 2) + '\n';
  const tmp = GLOBAL_PRINTERS_PATH + '.tmp';
  fs.writeFileSync(tmp, data, 'utf8');
  fs.renameSync(tmp, GLOBAL_PRINTERS_PATH);
  try {
    const stat = fs.statSync(GLOBAL_PRINTERS_PATH);
    cached = map;
    cachedMtime = stat.mtimeMs || Date.now();
  } catch (_) {
    cached = map;
    cachedMtime = Date.now();
  }
}

function getAllGlobalPrinters() {
  const store = readStore();
  return { ...store };
}

function getGlobalPrinter(printerId) {
  if (!printerId) return null;
  const store = readStore();
  return store[printerId] || null;
}

function setGlobalPrinter(printerId, ip, label = '') {
  if (!printerId || typeof printerId !== 'string') {
    throw new Error('printerId is required');
  }
  const trimmedId = printerId.trim();
  if (!trimmedId) throw new Error('printerId cannot be blank');
  if (!ip || net.isIP(String(ip).trim()) === 0) {
    throw new Error('A valid IPv4/IPv6 address is required');
  }
  const trimmedIp = String(ip).trim();
  const trimmedLabel = typeof label === 'string' ? label.trim() : '';
  const store = readStore();
  store[trimmedId] = { ip: trimmedIp, label: trimmedLabel };
  writeStore(store);
  return store;
}

function removeGlobalPrinter(printerId) {
  if (!printerId || typeof printerId !== 'string') {
    throw new Error('printerId is required');
  }
  const trimmedId = printerId.trim();
  if (!trimmedId) throw new Error('printerId cannot be blank');
  const store = readStore();
  const existing = store[trimmedId] || null;
  if (existing) {
    delete store[trimmedId];
    writeStore(store);
  }
  return { map: store, removed: existing };
}

module.exports = {
  GLOBAL_PRINTERS_PATH,
  getAllGlobalPrinters,
  getGlobalPrinter,
  setGlobalPrinter,
  removeGlobalPrinter,
};
