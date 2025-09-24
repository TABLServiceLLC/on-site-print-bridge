const fs = require('fs');
const path = require('path');

const LOG_PATH = process.env.LOG_FILE || path.join(__dirname, 'bridge.log');

let stream;
function getStream() {
  if (!stream) {
    try {
      stream = fs.createWriteStream(LOG_PATH, { flags: 'a' });
    } catch (_) {
      // If file cannot be opened, fallback to no-op stream-like object
      stream = { write: () => {} };
    }
  }
  return stream;
}

function ts() {
  return new Date().toISOString();
}

function serializeMeta(meta) {
  if (!meta) return '';
  try {
    return ' ' + JSON.stringify(meta, (key, value) => {
      if (value instanceof Error) {
        return { message: value.message, stack: value.stack };
      }
      return value;
    });
  } catch (_) {
    return ' ' + String(meta);
  }
}

function write(level, message, meta) {
  const line = `${ts()} ${level.toUpperCase()} ${message}${serializeMeta(meta)}\n`;
  try { getStream().write(line); } catch {}
  // Console output
  if (level === 'error') console.error(message, meta || '');
  else if (level === 'warn') console.warn(message, meta || '');
  else console.log(message, meta || '');
}

module.exports = {
  info: (msg, meta) => write('info', msg, meta),
  warn: (msg, meta) => write('warn', msg, meta),
  error: (msg, meta) => write('error', msg, meta),
  debug: (msg, meta) => write('debug', msg, meta),
  LOG_PATH,
};

