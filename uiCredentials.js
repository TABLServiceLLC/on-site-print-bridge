const fs = require('fs');
const path = require('path');

const CREDENTIALS_PATH = process.env.UI_CREDENTIALS_FILE || path.join(__dirname, 'uiCredentials.json');

let cachedCreds = null;
let cachedMtime = 0;

function ensureFile() {
  if (!fs.existsSync(CREDENTIALS_PATH)) {
    const dir = path.dirname(CREDENTIALS_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(
      CREDENTIALS_PATH,
      JSON.stringify({ username: 'admin', password: 'admin' }, null, 2) + '\n',
      'utf8'
    );
  }
}

function readCredentials() {
  ensureFile();
  try {
    const stat = fs.statSync(CREDENTIALS_PATH);
    const mtime = stat.mtimeMs || 0;
    if (cachedCreds && cachedMtime === mtime) return cachedCreds;
    const raw = fs.readFileSync(CREDENTIALS_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const username = typeof parsed.username === 'string' ? parsed.username : '';
    const password = typeof parsed.password === 'string' ? parsed.password : '';
    cachedCreds = { username, password };
    cachedMtime = mtime;
    return cachedCreds;
  } catch (err) {
    cachedCreds = { username: '', password: '' };
    cachedMtime = 0;
    return cachedCreds;
  }
}

function writeCredentials({ username, password }) {
  if (typeof username !== 'string' || !username.trim()) {
    throw new Error('Username is required');
  }
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Password is required');
  }
  ensureFile();
  const payload = { username: username.trim(), password };
  const tmp = `${CREDENTIALS_PATH}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, CREDENTIALS_PATH);
  try {
    const stat = fs.statSync(CREDENTIALS_PATH);
    cachedCreds = payload;
    cachedMtime = stat.mtimeMs || Date.now();
  } catch (_) {
    cachedCreds = payload;
    cachedMtime = Date.now();
  }
  return cachedCreds;
}

module.exports = {
  CREDENTIALS_PATH,
  readCredentials,
  writeCredentials,
};
