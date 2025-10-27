const fs = require('fs');
const path = require('path');

const LABELS_PATH = process.env.PRINTER_LABELS_FILE || path.join(__dirname, 'printerLabels.json');

let cached = null;
let cachedMtime = 0;

const DEFAULT_DATA = { printers: {}, terminals: {} };

function ensureFile() {
  if (!fs.existsSync(LABELS_PATH)) {
    const dir = path.dirname(LABELS_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(LABELS_PATH, JSON.stringify(DEFAULT_DATA, null, 2) + '\n', 'utf8');
  }
}

function normalizeData(data) {
  if (!data || typeof data !== 'object') return { ...DEFAULT_DATA };
  const printers = data.printers && typeof data.printers === 'object' ? data.printers : {};
  const terminals = data.terminals && typeof data.terminals === 'object' ? data.terminals : {};
  return { printers, terminals };
}

function readLabels() {
  ensureFile();
  try {
    const stat = fs.statSync(LABELS_PATH);
    const mtime = stat.mtimeMs || 0;
    if (cached && cachedMtime === mtime) return cached;
    const raw = fs.readFileSync(LABELS_PATH, 'utf8');
    const parsed = normalizeData(JSON.parse(raw || '{}'));
    cached = parsed;
    cachedMtime = mtime;
    return parsed;
  } catch (err) {
    cached = { ...DEFAULT_DATA };
    cachedMtime = 0;
    return cached;
  }
}

function writeLabels(data) {
  const normal = normalizeData(data);
  const tmp = LABELS_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(normal, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, LABELS_PATH);
  try {
    const stat = fs.statSync(LABELS_PATH);
    cached = normal;
    cachedMtime = stat.mtimeMs || Date.now();
  } catch (_) {
    cached = normal;
    cachedMtime = Date.now();
  }
  return cached;
}

function getAllLabels() {
  return readLabels();
}

function getAllPrinterLabels() {
  return { ...readLabels().printers };
}

function getAllTerminalLabels() {
  return { ...readLabels().terminals };
}

function setPrinterLabel(ip, label) {
  const labels = readLabels();
  labels.printers[ip] = { label };
  return writeLabels(labels);
}

function removePrinterLabel(ip) {
  const labels = readLabels();
  if (labels.printers[ip]) {
    delete labels.printers[ip];
    writeLabels(labels);
  }
  return labels;
}

function setTerminalLabel(terminalId, label) {
  const labels = readLabels();
  labels.terminals[terminalId] = { label };
  return writeLabels(labels);
}

function removeTerminalLabel(terminalId) {
  const labels = readLabels();
  if (labels.terminals[terminalId]) {
    delete labels.terminals[terminalId];
    writeLabels(labels);
  }
  return labels;
}

module.exports = {
  LABELS_PATH,
  getAllLabels,
  getAllPrinterLabels,
  getAllTerminalLabels,
  setPrinterLabel,
  removePrinterLabel,
  setTerminalLabel,
  removeTerminalLabel,
};
