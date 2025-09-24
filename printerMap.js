const fs = require('fs');
const path = require('path');
const net = require('net');

const MAP_PATH = path.join(__dirname, 'printerMap.json');

function ensureMapFile() {
  try {
    if (!fs.existsSync(MAP_PATH)) {
      fs.writeFileSync(MAP_PATH, '{}\n', 'utf8');
    }
  } catch (e) {
    // swallow; subsequent reads will handle errors
  }
}

function readMap() {
  ensureMapFile();
  try {
    const txt = fs.readFileSync(MAP_PATH, 'utf8');
    const obj = JSON.parse(txt || '{}');
    if (obj && typeof obj === 'object') return obj;
  } catch (_) {
    // if the file is corrupt, back it up and start fresh
    try {
      const bad = fs.readFileSync(MAP_PATH, 'utf8');
      fs.writeFileSync(MAP_PATH + '.bak', bad, 'utf8');
    } catch {}
    try { fs.writeFileSync(MAP_PATH, '{}\n', 'utf8'); } catch {}
  }
  return {};
}

function writeMap(obj) {
  const tmp = MAP_PATH + '.tmp';
  const data = JSON.stringify(obj || {}, null, 2) + '\n';
  fs.writeFileSync(tmp, data, 'utf8');
  fs.renameSync(tmp, MAP_PATH);
}

function getAllMappings() {
  return readMap();
}

function getPrinterIp(terminalId) {
  if (terminalId == null) return undefined;
  const map = readMap();
  return map[String(terminalId)];
}

function setPrinterIp(terminalId, ip) {
  if (!terminalId) throw new Error('terminalId is required');
  if (!ip || net.isIP(ip) === 0) throw new Error('A valid IPv4/IPv6 address is required');
  const map = readMap();
  map[String(terminalId)] = ip;
  writeMap(map);
  return map;
}

module.exports = {
  MAP_PATH,
  getAllMappings,
  getPrinterIp,
  setPrinterIp,
};

