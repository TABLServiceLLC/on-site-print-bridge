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
const crypto = require('crypto');
const logger = require('./logger');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8443;
const PRINTER_PORT = 9100;
const { getPrinterIp, setPrinterIp, getAllMappings, removePrinterIp } = require('./printerMap');
const { scanNetwork, defaultCidrFromInterfaces } = require('./discoverPrinters');
const { readCredentials, writeCredentials, CREDENTIALS_PATH } = require('./uiCredentials');
const { getAllLabels, getAllPrinterLabels, getAllTerminalLabels, setPrinterLabel, removePrinterLabel, setTerminalLabel, removeTerminalLabel } = require('./printerLabels');
const { getAllGlobalPrinters, getGlobalPrinter, setGlobalPrinter, removeGlobalPrinter } = require('./globalPrinters');
const DISCOVERY_INTERVAL_MS = parseInt(process.env.DISCOVERY_INTERVAL_MS || '300000', 10); // 5 minutes
const DISCOVERY_PORTS = [9100, 515, 631, 80, 443];
const JWT_SECRET = process.env.JWT_SECRET || '';
const SESSION_COOKIE_NAME = 'tabl_ui_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const sessions = new Map();
const KEY_FILE_PATH = path.join(__dirname, 'server.key');
const CERT_FILE_PATH = path.join(__dirname, 'server.crt');
const CA_FILE_PATH = path.join(__dirname, 'ca.crt');

const DEFAULT_ALLOWED_ORIGINS = ['https://pos.tabl.page', 'http://localhost:8080', 'https://raspberrypi.local', 'https://raspberrypi.local:8443'];

function normalizeOrigin(value) {
    if (!value || typeof value !== 'string') return '';
    try {
        const parsed = new URL(value);
        return `${parsed.protocol}//${parsed.host}`.toLowerCase();
    } catch (_) {
        return value.replace(/\/+$/, '').toLowerCase();
    }
}

function loadAllowedOrigins() {
    const envList = (process.env.CORS_ALLOWED_ORIGINS || '')
        .split(/[\s,]+/)
        .map((item) => item.trim())
        .filter(Boolean);
    const merged = [...DEFAULT_ALLOWED_ORIGINS, ...envList];
    const unique = Array.from(new Set(merged.map(normalizeOrigin))).filter(Boolean);
    return unique;
}

const ALLOWED_ORIGINS = loadAllowedOrigins();
logger.info('CORS origins configured', { allowedOrigins: ALLOWED_ORIGINS });

const corsOptions = {
    origin(origin, callback) {
        if (!origin) return callback(null, true);
        const normalized = normalizeOrigin(origin);
        if (ALLOWED_ORIGINS.includes(normalized)) {
            return callback(null, true);
        }
        logger.warn('Blocked CORS origin', { origin, normalized });
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Authorization', 'Accept'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 204,
};

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use((req, res, next) => {
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    return next();
});

// Routes

function parseCookies(req) {
    const header = req.headers.cookie;
    if (!header) return {};
    return header.split(';').reduce((acc, chunk) => {
        const index = chunk.indexOf('=');
        if (index === -1) return acc;
        const key = chunk.slice(0, index).trim();
        const value = chunk.slice(index + 1).trim();
        if (key) {
            try {
                acc[key] = decodeURIComponent(value);
            } catch (_) {
                acc[key] = value;
            }
        }
        return acc;
    }, {});
}

function getSession(req) {
    const cookies = parseCookies(req);
    const sessionId = cookies[SESSION_COOKIE_NAME];
    if (!sessionId) return null;
    const entry = sessions.get(sessionId);
    if (!entry || entry.expiresAt <= Date.now()) {
        sessions.delete(sessionId);
        return null;
    }
    // sliding expiration
    entry.expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(sessionId, entry);
    return { id: sessionId, username: entry.username };
}

function createSession(username) {
    const id = crypto.randomBytes(32).toString('hex');
    sessions.set(id, { username, expiresAt: Date.now() + SESSION_TTL_MS });
    return id;
}

function destroySession(sessionId) {
    if (!sessionId) return;
    sessions.delete(sessionId);
}

function pushCookie(res, cookieValue) {
    const existing = res.getHeader('Set-Cookie');
    if (!existing) {
        res.setHeader('Set-Cookie', cookieValue);
    } else if (Array.isArray(existing)) {
        res.setHeader('Set-Cookie', existing.concat(cookieValue));
    } else {
        res.setHeader('Set-Cookie', [existing, cookieValue]);
    }
}

function setSessionCookie(res, sessionId) {
    const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
    pushCookie(res, `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionId)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}`);
}

function clearSessionCookie(res) {
    pushCookie(res, `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
}

function constantTimeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length === 0 || b.length === 0) return false;
    try {
        const bufA = Buffer.from(a, 'utf8');
        const bufB = Buffer.from(b, 'utf8');
        if (bufA.length !== bufB.length) return false;
        return crypto.timingSafeEqual(bufA, bufB);
    } catch (err) {
        return false;
    }
}

function getUiAuthState() {
    const raw = readCredentials();
    const username = typeof raw.username === 'string' ? raw.username.trim() : '';
    const password = typeof raw.password === 'string' ? raw.password : '';
    return {
        username,
        password,
        enabled: username.length > 0 && password.length > 0,
    };
}

function escapeHtmlLite(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getUserInitials(displayName) {
    if (typeof displayName !== 'string' || !displayName.trim()) return 'U';
    const tokens = displayName.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return 'U';
    const first = tokens[0][0];
    const second = tokens.length > 1 ? tokens[1][0] : tokens[0][1] || '';
    return (first + second).toUpperCase();
}

function buildUserMenu(authState, signedInUserRaw) {
    if (!authState || !authState.enabled) return '';
    if (typeof signedInUserRaw !== 'string' || !signedInUserRaw.trim()) return '';
    const sanitizedUserName = escapeHtmlLite(signedInUserRaw);
    const sanitizedInitials = escapeHtmlLite(getUserInitials(signedInUserRaw));
    return `<div class="user-menu" data-open="false">
      <button class="user-menu__trigger" type="button" aria-haspopup="true" aria-expanded="false">
        <span class="user-menu__initials">${sanitizedInitials}</span>
        <span class="user-menu__name">${sanitizedUserName}</span>
        <span class="user-menu__caret">&#9662;</span>
      </button>
      <div class="user-menu__dropdown" role="menu">
        <a class="user-menu__link" href="/profile" role="menuitem">Edit profile</a>
        <form method="POST" action="/logout" role="none">
          <input type="hidden" name="redirect" value="/login" />
          <button type="submit" class="user-menu__link user-menu__logout" role="menuitem">Log out</button>
        </form>
      </div>
    </div>`;
}

function sanitizeRedirectTarget(target) {
    if (typeof target !== 'string' || target.length === 0) return '/ui';
    try {
        const decoded = decodeURIComponent(target);
        if (!decoded.startsWith('/')) return '/ui';
        if (decoded.startsWith('//')) return '/ui';
        return decoded;
    } catch (_) {
        return '/ui';
    }
}

function renderLoginPage({ redirectTo = '/ui', error = '' } = {}) {
    const errorBlock = error ? `<div class="alert"><strong>Login failed.</strong> ${error}</div>` : '';
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TABL Print Bridge Login</title>
  <meta name="theme-color" content="#3B7FBE" />
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico" />
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.webp" />
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.webp" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.webp" />
  <link rel="manifest" href="/assets/site.webmanifest" />
  <style>
    :root { color-scheme: light; font-size: 16px; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(120% 120% at 20% -10%, rgba(59, 127, 190, 0.2), transparent 55%),
                  radial-gradient(110% 110% at 90% 0%, rgba(15, 27, 51, 0.16), transparent 60%),
                  linear-gradient(180deg, #0f172a 0%, #1e3a5f 45%, #ffffff 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #0f172a;
      padding: 24px;
    }
    .login-layout {
      width: 100%;
      max-width: 520px;
    }
    .card {
      background: rgba(248, 251, 255, 0.96);
      border-radius: 20px;
      box-shadow: 0 22px 60px rgba(13, 51, 102, 0.30);
      max-width: 420px;
      width: 100%;
      padding: 42px 36px 36px;
    }
    .logo {
      display: flex;
      justify-content: center;
      margin-bottom: 28px;
    }
    .logo img {
      width: 180px;
      height: auto;
    }
    h1 {
      text-align: center;
      margin: 0 0 12px;
      font-size: 26px;
      font-weight: 700;
      color: #0f172a;
      letter-spacing: -0.01em;
    }
    p.subtitle {
      text-align: center;
      color: #4b5563;
      margin: 0 0 28px;
      font-size: 15px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 8px;
    }
    input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid rgba(30, 58, 95, 0.2);
      font-size: 15px;
      transition: border-color 120ms ease, box-shadow 120ms ease;
      background: #fff;
    }
    input:focus {
      outline: none;
      border-color: rgba(59, 127, 190, 0.8);
      box-shadow: 0 0 0 4px rgba(59, 127, 190, 0.25);
    }
    button {
      width: 100%;
      margin-top: 28px;
      padding: 12px 16px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      letter-spacing: 0.01em;
      cursor: pointer;
      box-shadow: 0 14px 28px rgba(59, 127, 190, 0.45);
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 16px 32px rgba(59, 127, 190, 0.5);
    }
    button:focus-visible {
      outline: 3px solid rgba(59, 127, 190, 0.55);
      outline-offset: 2px;
    }
    .field {
      margin-bottom: 18px;
    }
    .alert {
      background: rgba(217, 48, 37, 0.12);
      color: #b3261e;
      border-radius: 12px;
      padding: 12px 14px;
      font-size: 13px;
      margin-bottom: 20px;
      border: 1px solid rgba(217, 48, 37, 0.2);
    }
    .meta {
      margin-top: 24px;
      font-size: 12px;
      text-align: center;
      color: #64748b;
    }
  </style>
</head>
<body>
  <main class="login-layout">
    <div class="card" role="main">
      <div class="logo">
        <img src="/assets/TABL_Logo.svg" alt="TABL" />
      </div>
      <h1>Sign in</h1>
      <p class="subtitle">Enter the bridge credentials to continue.</p>
      ${errorBlock}
      <form method="POST" action="/login" novalidate>
        <input type="hidden" name="redirect" value="${encodeURIComponent(redirectTo)}" />
        <div class="field">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" autocomplete="username" required />
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" autocomplete="current-password" required />
        </div>
        <button type="submit">Access Bridge</button>
      </form>
      <p class="meta">Need access? Contact your device administrator.</p>
    </div>
  </main>
</body>
</html>`;
}

function renderProfilePage({ username = '', error = '', success = '', navHtml = '', userMenuHtml = '' } = {}) {
    const safeUsername = escapeHtmlLite(username);
    const messageBlock = error ? `<div class="notice notice--error"><strong>Update failed.</strong> ${escapeHtmlLite(error)}</div>` : success ? `<div class="notice notice--success">${escapeHtmlLite(success)}</div>` : '';
    const topbarSection = userMenuHtml ? `<div class="topbar">${userMenuHtml}</div>` : '';
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TABL Profile</title>
  <meta name="theme-color" content="#3B7FBE" />
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico" />
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.webp" />
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.webp" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.webp" />
  <link rel="manifest" href="/assets/site.webmanifest" />
  <style>
    :root { color-scheme: light; font-size: 16px; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(120% 120% at 12% -18%, rgba(59, 127, 190, 0.14), transparent 55%),
                  radial-gradient(120% 120% at 88% -10%, rgba(15, 27, 51, 0.12), transparent 60%),
                  linear-gradient(180deg, #0f172a 0%, #1b2f4f 45%, #ffffff 100%);
      min-height: 100vh;
      padding: 24px;
      color: #0f172a;
    }
    .container {
      max-width: 480px;
      margin: 0 auto;
      background: rgba(248, 251, 255, 0.96);
      border-radius: 20px;
      padding: 32px 34px;
      box-shadow: 0 22px 52px rgba(15, 31, 55, 0.32);
    }
    .topbar {
      max-width: 480px;
      margin: 0 auto 18px;
      display: flex;
      justify-content: flex-end;
      align-items: center;
    }
    .user-menu {
      position: relative;
    }
    .user-menu__trigger {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      border: 1px solid rgba(15, 27, 51, 0.12);
      border-radius: 14px;
      background: rgba(248, 251, 255, 0.9);
      padding: 8px 14px;
      font-size: 14px;
      font-weight: 600;
      color: #0f172a;
      cursor: pointer;
      box-shadow: 0 10px 26px rgba(15, 31, 55, 0.18);
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    .user-menu__trigger:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 32px rgba(15, 31, 55, 0.22);
    }
    .user-menu__initials {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      font-size: 13px;
      font-weight: 700;
    }
    .user-menu__caret {
      font-size: 11px;
      color: #64748b;
    }
    .user-menu__dropdown {
      position: absolute;
      top: calc(100% + 10px);
      right: 0;
      min-width: 180px;
      background: #fff;
      border-radius: 14px;
      box-shadow: 0 24px 60px rgba(15, 31, 55, 0.26);
      padding: 8px 0;
      opacity: 0;
      pointer-events: none;
      transform: translateY(-6px);
      transition: opacity 140ms ease, transform 140ms ease;
      z-index: 10;
    }
    .user-menu.is-open .user-menu__dropdown {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }
    .user-menu__dropdown form {
      margin: 0;
    }
    .user-menu__link {
      display: block;
      width: 100%;
      text-align: left;
      background: transparent;
      border: none;
      padding: 10px 20px;
      font-size: 14px;
      font-weight: 600;
      color: #1e293b;
      text-decoration: none;
      cursor: pointer;
    }
    .user-menu__link:hover {
      background: rgba(59, 127, 190, 0.12);
    }
    .user-menu__logout {
      color: #b3261e;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
    }
    .title {
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .back-link {
      font-size: 13px;
      color: #3B7FBE;
      text-decoration: none;
      font-weight: 600;
    }
    .back-link:hover {
      text-decoration: underline;
    }
    .header-subtitle {
      margin: 0 0 18px;
      font-size: 13px;
      color: rgba(15, 27, 51, 0.7);
    }
    .notice {
      border-radius: 12px;
      padding: 11px 14px;
      font-size: 13px;
      margin-bottom: 18px;
      border: 1px solid transparent;
    }
    .notice--error {
      background: rgba(217, 48, 37, 0.12);
      color: #b3261e;
      border-color: rgba(217, 48, 37, 0.2);
    }
    .notice--success {
      background: rgba(52, 168, 83, 0.12);
      color: #137333;
      border-color: rgba(52, 168, 83, 0.2);
    }
    .section {
      border: 1px solid rgba(15, 31, 55, 0.08);
      border-radius: 16px;
      padding: 18px 20px;
      background: rgba(255, 255, 255, 0.98);
      margin-bottom: 16px;
    }
    .section:last-of-type {
      margin-bottom: 0;
    }
    .section__header {
      margin-bottom: 12px;
    }
    .section__title {
      margin: 0;
      font-size: 17px;
      font-weight: 700;
      color: #102542;
    }
    .section__subtitle {
      margin: 6px 0 0;
      font-size: 12px;
      color: #64748b;
    }
    form {
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 11px 14px;
      border-radius: 12px;
      border: 1px solid rgba(30, 58, 95, 0.16);
      font-size: 14px;
      transition: border-color 120ms ease, box-shadow 120ms ease;
      background: #fff;
    }
    input:focus {
      outline: none;
      border-color: rgba(59, 127, 190, 0.85);
      box-shadow: 0 0 0 3px rgba(59, 127, 190, 0.25);
    }
    .helper {
      font-size: 11px;
      color: #94a3b8;
      margin-top: 4px;
    }
    .actions {
      display: flex;
      justify-content: flex-end;
    }
    button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 18px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      letter-spacing: 0.01em;
      cursor: pointer;
      box-shadow: 0 10px 26px rgba(59, 127, 190, 0.38);
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 30px rgba(59, 127, 190, 0.42);
    }
    .label-cell {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .label-cell__value {
      font-weight: 600;
      color: #102542;
    }
    .label-cell__actions {
      display: flex;
      gap: 6px;
    }
    .label-cell__icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 26px;
      height: 26px;
      border-radius: 50%;
      border: none;
      background: rgba(59, 127, 190, 0.12);
      color: #1e3a5f;
      font-size: 13px;
      cursor: pointer;
      transition: background 120ms ease, color 120ms ease;
    }
    .label-cell__icon:hover {
      background: rgba(59, 127, 190, 0.18);
      color: #12375d;
    }
    .label-cell__icon:focus-visible {
      outline: 2px solid rgba(59, 127, 190, 0.35);
      outline-offset: 2px;
    }
    .modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 40;
    }
    .modal.is-open {
      display: flex;
    }
    .modal__overlay {
      position: absolute;
      inset: 0;
      background: rgba(15, 23, 42, 0.45);
      backdrop-filter: blur(2px);
    }
    .modal__content {
      position: relative;
      background: #fff;
      border-radius: 16px;
      padding: 22px 26px 24px;
      max-width: 360px;
      width: calc(100% - 48px);
      box-shadow: 0 26px 60px rgba(15, 31, 55, 0.35);
      z-index: 1;
    }
    .modal__title {
      margin: 0 0 10px;
      font-size: 18px;
      font-weight: 700;
    }
    .modal__body {
      font-size: 14px;
      color: #475569;
      margin-bottom: 18px;
    }
    .modal__actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .modal__actions button {
      padding: 10px 16px;
      border-radius: 10px;
    }
    .btn-secondary {
      background: rgba(15, 27, 51, 0.08);
      color: #102542;
      box-shadow: none;
    }
    .btn-secondary:hover {
      transform: none;
      box-shadow: none;
      background: rgba(15, 27, 51, 0.12);
    }
    @media (max-width: 520px) {
      .container {
        padding: 28px 22px;
      }
      .section {
        padding: 16px;
      }
    }
  </style>
</head>
<body>
  ${navHtml}
  ${topbarSection}
  <div class="container">
    <div class="header">
      <h1 class="title">Edit profile</h1>
      <a class="back-link" href="/ui">← Back</a>
    </div>
    <p class="header-subtitle">Manage the credentials for this bridge device.</p>
    ${messageBlock}
    <section class="section">
      <header class="section__header">
        <h2 class="section__title">Username</h2>
        <p class="section__subtitle">Update the name used to sign in and shown in the dashboard.</p>
      </header>
      <form id="username-form" method="POST" action="/profile" autocomplete="off" novalidate>
        <input type="hidden" name="intent" value="update-username" />
        <div>
          <label for="profile-username">Username</label>
          <input type="text" id="profile-username" name="username" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" inputmode="text" required value="${safeUsername}" />
        </div>
        <div class="actions">
          <button type="button" id="username-save-btn">Save username</button>
        </div>
      </form>
    </section>
    <section class="section">
      <header class="section__header">
        <h2 class="section__title">Password</h2>
        <p class="section__subtitle">Choose a strong password to guard printer access.</p>
      </header>
      <form method="POST" action="/profile" autocomplete="off" novalidate>
        <input type="hidden" name="intent" value="update-password" />
        <div>
          <label for="profile-current-password-password">Current password</label>
          <input type="password" id="profile-current-password-password" name="currentPassword" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" required />
        </div>
        <div>
          <label for="profile-password">New password</label>
          <input type="password" id="profile-password" name="password" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" required />
        </div>
        <div>
          <label for="profile-password-confirm">Confirm new password</label>
          <input type="password" id="profile-password-confirm" name="passwordConfirm" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" required />
          <p class="helper">Both entries must match exactly.</p>
        </div>
        <div class="actions">
          <button type="submit">Update password</button>
        </div>
      </form>
    </section>
  </div>
  <div class="modal" id="username-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="username-modal-title">
    <div class="modal__overlay" data-close="true"></div>
    <div class="modal__content">
      <h3 class="modal__title" id="username-modal-title">Confirm username change</h3>
      <div class="modal__body">
        The next time you sign in, you'll need to use the new username. Continue?
      </div>
      <div class="modal__actions">
        <button type="button" class="btn-secondary" data-close="true">Cancel</button>
        <button type="button" id="username-confirm-btn">Yes, update</button>
      </div>
    </div>
  </div>
  <script>
    (function () {
      const form = document.getElementById('username-form');
      const saveBtn = document.getElementById('username-save-btn');
      const modal = document.getElementById('username-confirm-modal');
      const confirmBtn = document.getElementById('username-confirm-btn');
      const closeTargets = modal ? modal.querySelectorAll('[data-close="true"]') : [];

      function openModal() {
        if (modal) modal.classList.add('is-open');
      }

      function closeModal() {
        if (modal) modal.classList.remove('is-open');
      }

      if (saveBtn) {
        saveBtn.addEventListener('click', (event) => {
          event.preventDefault();
          if (!form || !form.reportValidity()) return;
          openModal();
        });
      }

      if (confirmBtn && form) {
        confirmBtn.addEventListener('click', () => {
          closeModal();
          form.submit();
        });
      }

      closeTargets.forEach((el) => {
        el.addEventListener('click', () => closeModal());
      });

      document.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') closeModal();
      });
    })();
  </script>
</body>
</html>`;
}

function getAuthHeader(req) {
    if (!req || !req.headers) return '';
    return req.headers['authorization'] || req.headers['Authorization'] || req.headers['x-authorization'] || req.headers['X-Authorization'] || '';
}

function extractBearerToken(headerValue) {
    if (!headerValue || typeof headerValue !== 'string') return '';
    const trimmed = headerValue.trim();
    if (/^Bearer\s+/i.test(trimmed)) {
        return trimmed.replace(/^Bearer\s+/i, '').trim();
    }
    return trimmed;
}

function collectTerminals() {
    const labels = getAllTerminalLabels() || {};
    const mappings = getAllMappings() || {};
    const ids = new Set([...Object.keys(labels), ...Object.keys(mappings)]);
    const sorted = Array.from(ids).sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    return sorted.map((terminalId) => ({
        terminalId,
        label: typeof labels[terminalId]?.label === 'string' ? labels[terminalId].label : '',
        assignedIp: mappings[terminalId] || null,
    }));
}

function collectPrinters() {
    const labels = getAllPrinterLabels() || {};
    const terminalLabels = getAllTerminalLabels() || {};
    const mappings = getAllMappings() || {};
    const terminalsByIp = {};
    Object.entries(mappings).forEach(([terminalId, ip]) => {
        if (!ip) return;
        const key = String(ip);
        if (!terminalsByIp[key]) terminalsByIp[key] = [];
        terminalsByIp[key].push(String(terminalId));
    });
    Object.values(terminalsByIp).forEach((list) => list.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })));
    const ips = new Set([...Object.keys(labels), ...Object.keys(terminalsByIp)]);
    const sortedIps = Array.from(ips).sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    return sortedIps.map((ip) => {
        const assignedTerminals = terminalsByIp[ip] || [];
        const assignedTerminalDetails = assignedTerminals.map((terminalId) => ({
            terminalId,
            label: typeof terminalLabels[terminalId]?.label === 'string' ? terminalLabels[terminalId].label : '',
        }));
        return {
            ip,
            label: typeof labels[ip]?.label === 'string' ? labels[ip].label : '',
            assignedTerminals,
            assignedTerminalDetails,
        };
    });
}

function collectGlobalPrinters() {
    const map = getAllGlobalPrinters() || {};
    const entries = Object.entries(map);
    entries.sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true, sensitivity: 'base' }));
    return entries.map(([printerId, value]) => {
        const ip = value && typeof value.ip === 'string' ? value.ip : '';
        const label = value && typeof value.label === 'string' ? value.label : '';
        return {
            printerId,
            ip,
            label,
        };
    });
}

const NAV_LINKS = [
    { href: '/ui', label: 'Dashboard' },
    { href: '/ui/printers', label: 'Printers' },
    { href: '/ui/terminals', label: 'Terminals' },
    { href: '/cert', label: 'Certificate' },
];

const GLOBAL_NAV_STYLES = `
    .global-nav {
      position: sticky;
      top: 0;
      z-index: 120;
      backdrop-filter: blur(12px);
      background: rgba(248, 251, 255, 0.86);
      border-bottom: 1px solid rgba(15, 31, 55, 0.08);
    }
    .global-nav__inner {
      max-width: 1200px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 14px 24px;
    }
    .global-nav__brand {
      font-weight: 700;
      font-size: 16px;
      letter-spacing: 0.04em;
      color: #1e3a5f;
    }
    .global-nav__links {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
      justify-content: flex-end;
    }
    .global-nav__actions {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .global-nav__link {
      text-decoration: none;
      font-size: 14px;
      font-weight: 600;
      color: #475569;
      padding: 6px 12px;
      border-radius: 999px;
      transition: background 120ms ease, color 120ms ease, transform 120ms ease;
    }
    .global-nav__link:hover {
      color: #1d4ed8;
      background: rgba(29, 78, 216, 0.12);
      transform: translateY(-1px);
    }
    .global-nav__link--active {
      color: #0f172a;
      background: rgba(15, 23, 42, 0.14);
    }
    .user-menu {
      position: relative;
    }
    .user-menu__trigger {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      border: 1px solid rgba(15, 27, 51, 0.12);
      border-radius: 14px;
      background: rgba(248, 251, 255, 0.85);
      padding: 8px 14px;
      font-size: 14px;
      font-weight: 600;
      color: #0f172a;
      cursor: pointer;
      box-shadow: 0 10px 26px rgba(15, 31, 55, 0.18);
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    .user-menu__trigger:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 32px rgba(15, 31, 55, 0.22);
    }
    .user-menu__initials {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      font-size: 13px;
      font-weight: 700;
    }
    .user-menu__caret {
      font-size: 11px;
      color: #64748b;
    }
    .user-menu__name {
      font-weight: 600;
      color: #0f172a;
    }
    .user-menu__dropdown {
      position: absolute;
      top: calc(100% + 10px);
      right: 0;
      min-width: 180px;
      background: #fff;
      border-radius: 14px;
      box-shadow: 0 24px 60px rgba(15, 31, 55, 0.26);
      padding: 8px 0;
      opacity: 0;
      pointer-events: none;
      transform: translateY(-6px);
      transition: opacity 140ms ease, transform 140ms ease;
      z-index: 10;
    }
    .user-menu.is-open .user-menu__dropdown {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }
    .user-menu__dropdown form {
      margin: 0;
    }
    .user-menu__link {
      display: block;
      width: 100%;
      text-align: left;
      background: transparent;
      border: none;
      padding: 10px 20px;
      font-size: 14px;
      font-weight: 600;
      color: #1e293b;
      text-decoration: none;
      cursor: pointer;
    }
    .user-menu__link:hover {
      background: rgba(59, 127, 190, 0.12);
    }
    .user-menu__logout {
      color: #b3261e;
    }
`;

const CERT_PAGE_STYLES = `
    :root { color-scheme: light; font-size: 16px; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background-color: #f5f7fb;
      background-image:
        radial-gradient(120% 120% at 12% -10%, rgba(59, 127, 190, 0.14), transparent 55%),
        radial-gradient(120% 120% at 88% 0%, rgba(15, 27, 51, 0.1), transparent 60%),
        linear-gradient(180deg, #f6f9ff 0%, #ffffff 100%);
      background-attachment: fixed;
      background-repeat: no-repeat;
      color: #0f172a;
    }
    .cert-page {
      max-width: 720px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }
    .cert-card {
      background: #fff;
      border-radius: 20px;
      padding: 36px;
      box-shadow: 0 20px 45px rgba(15, 23, 42, 0.1);
    }
    .cert-card h1 {
      margin: 0 0 8px;
      font-size: 30px;
      letter-spacing: -0.01em;
    }
    .cert-card p {
      margin: 0 0 18px;
      font-size: 16px;
      color: #475569;
    }
    .cert-meta {
      font-size: 14px;
      color: #64748b;
      margin-bottom: 24px;
    }
    .cert-meta--warning {
      color: #b3261e;
    }
    .cert-actions {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }
    .cert-button {
      border: none;
      border-radius: 999px;
      padding: 12px 24px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      color: #fff;
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      box-shadow: 0 14px 30px rgba(59, 127, 190, 0.35);
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    .cert-button:hover {
      transform: translateY(-1px);
      box-shadow: 0 18px 38px rgba(59, 127, 190, 0.4);
    }
    .cert-button:focus-visible {
      outline: 3px solid rgba(59, 127, 190, 0.4);
      outline-offset: 2px;
    }
    .cert-note {
      font-size: 14px;
      color: #334155;
      background: #f1f5f9;
      border-radius: 12px;
      padding: 14px 16px;
      margin-top: 18px;
    }
    .cert-error {
      color: #b3261e;
      font-weight: 600;
      margin: 18px 0 0;
    }
`;

function normalizePathForNav(value) {
    if (typeof value !== 'string' || value.length === 0) return '/';
    if (value.startsWith('/')) return value;
    return `/${value.replace(/^\/+/, '')}`;
}

function buildNavBar({ currentPath = '/', signedIn = false, userMenuHtml = '' } = {}) {
    const normalized = normalizePathForNav(currentPath);
    const links = NAV_LINKS.map((link) => {
        const isActive = normalized === link.href || (link.href !== '/' && normalized.startsWith(`${link.href}/`));
        const cls = isActive ? 'global-nav__link global-nav__link--active' : 'global-nav__link';
        return `<a class="${cls}" href="${link.href}">${link.label}</a>`;
    }).join('');
    const actions = userMenuHtml || (signedIn ? '' : `<a class="global-nav__link" href="/login">Login</a>`);
    return `<nav class="global-nav"><div class="global-nav__inner"><span class="global-nav__brand">TABL Print Bridge</span><div class="global-nav__links">${links}</div><div class="global-nav__actions">${actions}</div></div></nav>`;
}

function requireUiAuth(req, res, next) {
    const { enabled } = getUiAuthState();
    if (!enabled) return next();
    const session = getSession(req);
    if (session) {
        res.locals.uiUser = session.username;
        return next();
    }
    const redirectTarget = encodeURIComponent(req.originalUrl || '/ui');
    return res.redirect(`/login?redirect=${redirectTarget}`);
}

function authorizeApi(req, res, next) {
    const header = getAuthHeader(req);
    const token = extractBearerToken(header);
    if (token) {
        if (!JWT_SECRET) {
            logger.error('JWT_SECRET not set; rejecting API auth request');
            return res.status(401).json({ error: 'Unauthorized: server not configured' });
        }
        return jwt.verify(token, JWT_SECRET, (err, payload) => {
            if (err) {
                return res.status(401).json({ error: 'Unauthorized: invalid token' });
            }
            req.user = payload;
            return next();
        });
    }
    const session = getSession(req);
    if (session) {
        res.locals.uiUser = session.username;
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized' });
}

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.post('/echo', (req, res) => {
    res.json({ received: req.body });
});

app.get('/', (req, res) => {
    res.redirect('/ui');
});

app.get('/login', (req, res) => {
    const state = getUiAuthState();
    if (!state.enabled) {
        return res.redirect('/ui');
    }
    const session = getSession(req);
    const redirectTarget = sanitizeRedirectTarget(req.query.redirect);
    if (session) {
        return res.redirect(redirectTarget);
    }
    res.set('Content-Type', 'text/html');
    res.send(renderLoginPage({ redirectTo: redirectTarget }));
});

app.post('/login', (req, res) => {
    const state = getUiAuthState();
    if (!state.enabled) {
        return res.redirect('/ui');
    }
    const session = getSession(req);
    if (session) {
        return res.redirect(sanitizeRedirectTarget(req.body && req.body.redirect));
    }
    const submittedUser = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const submittedPass = typeof req.body?.password === 'string' ? req.body.password : '';
    const redirectTarget = sanitizeRedirectTarget(req.body?.redirect);

    const userOk = constantTimeCompare(submittedUser, state.username);
    const passOk = constantTimeCompare(submittedPass, state.password);

    if (userOk && passOk) {
        const sessionId = createSession(state.username);
        setSessionCookie(res, sessionId);
        return res.redirect(redirectTarget);
    }

    clearSessionCookie(res);
    res.status(401);
    res.set('Content-Type', 'text/html');
    res.send(renderLoginPage({ redirectTo: redirectTarget, error: 'Check your username and password and try again.' }));
});

app.post('/logout', (req, res) => {
    const session = getSession(req);
    if (session) {
        destroySession(session.id);
    }
    clearSessionCookie(res);
    const redirectTarget = sanitizeRedirectTarget(req.body?.redirect || '/login');
    res.redirect(redirectTarget);
});

app.get('/profile', requireUiAuth, (req, res) => {
    const state = getUiAuthState();
    if (!state.enabled) {
        return res.redirect('/ui');
    }
    res.set('Content-Type', 'text/html');
    res.send(renderProfilePage({ username: state.username }));
});

app.post('/profile', requireUiAuth, (req, res) => {
    const state = getUiAuthState();
    if (!state.enabled) {
        return res.redirect('/ui');
    }
    const session = getSession(req);
    const intent = typeof req.body?.intent === 'string' ? req.body.intent : '';
    const submittedUser = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
    const newPassword = typeof req.body?.password === 'string' ? req.body.password : '';
    const confirmPassword = typeof req.body?.passwordConfirm === 'string' ? req.body.passwordConfirm : '';

    const respond = ({ status = 200, username = state.username, error, success }) => {
        res.status(status).set('Content-Type', 'text/html');
        res.send(renderProfilePage({ username, error, success }));
    };

    if (intent === 'update-username') {
        const targetUsername = submittedUser;
        if (!targetUsername) {
            return respond({ status: 400, username: '', error: 'Username is required.' });
        }
        if (!state.password) {
            return respond({ status: 500, username: state.username, error: 'Password missing from credentials store.' });
        }
        try {
            writeCredentials({ username: targetUsername, password: state.password });
            logger.info('UI username updated', { username: targetUsername });
        } catch (err) {
            logger.error('Failed to update UI username', { error: err.message || String(err) });
            return respond({ status: 500, username: targetUsername || state.username, error: 'Unable to save username. Try again.' });
        }
        if (session) {
            destroySession(session.id);
        }
        const newSessionId = createSession(targetUsername);
        setSessionCookie(res, newSessionId);
        res.locals.uiUser = targetUsername;
        return respond({ username: targetUsername, success: 'Username updated. Use this on your next login.' });
    }

    if (intent === 'update-password') {
        if (!currentPassword) {
            return respond({ status: 400, username: state.username, error: 'Current password is required.' });
        }
        if (!constantTimeCompare(currentPassword, state.password)) {
            return respond({ status: 401, username: state.username, error: 'Current password is incorrect.' });
        }
        if (!newPassword || !confirmPassword) {
            return respond({ status: 400, username: state.username, error: 'Enter and confirm the new password.' });
        }
        if (newPassword !== confirmPassword) {
            return respond({ status: 400, username: state.username, error: 'New passwords do not match.' });
        }
        try {
            writeCredentials({ username: state.username, password: newPassword });
            logger.info('UI password updated', { username: state.username });
        } catch (err) {
            logger.error('Failed to update UI password', { error: err.message || String(err) });
            return respond({ status: 500, username: state.username, error: 'Unable to save password. Try again.' });
        }
        if (session) {
            destroySession(session.id);
        }
        const newSessionId = createSession(state.username);
        setSessionCookie(res, newSessionId);
        res.locals.uiUser = state.username;
        return respond({ username: state.username, success: 'Password updated.' });
    }

    return respond({ status: 400, username: state.username, error: 'Unsupported action.' });
});

app.get('/printer-labels', authorizeApi, (req, res) => {
    const { printers } = getAllLabels();
    res.json({ printers });
});

app.post('/printer-labels', authorizeApi, (req, res) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    const rawLabel = typeof req.body?.label === 'string' ? req.body.label : '';
    if (!ip || net.isIP(ip) === 0) {
        return res.status(400).json({ error: 'A valid printer IP is required.' });
    }
    const label = rawLabel.trim();
    if (!label) {
        removePrinterLabel(ip);
        logger.info('Printer label removed', { ip });
        return res.json({ ok: true, ip, label: null, printers: getAllPrinterLabels() });
    }
    setPrinterLabel(ip, label);
    logger.info('Printer label updated', { ip, label });
    return res.json({ ok: true, ip, label, printers: getAllPrinterLabels() });
});

app.delete('/printer-labels/:ip', authorizeApi, (req, res) => {
    const ip = typeof req.params?.ip === 'string' ? req.params.ip.trim() : '';
    if (!ip || net.isIP(ip) === 0) {
        return res.status(400).json({ error: 'A valid printer IP is required.' });
    }
    removePrinterLabel(ip);
    logger.info('Printer label removed', { ip });
    res.json({ ok: true, ip, label: null, printers: getAllPrinterLabels() });
});

app.get('/terminal-labels', authorizeApi, (req, res) => {
    const { terminals } = getAllLabels();
    res.json({ terminals });
});

app.post('/terminal-labels', authorizeApi, (req, res) => {
    const terminalId = typeof req.body?.terminalId === 'string' ? req.body.terminalId.trim() : '';
    const rawLabel = typeof req.body?.label === 'string' ? req.body.label : '';
    if (!terminalId) {
        return res.status(400).json({ error: 'terminalId is required.' });
    }
    const label = rawLabel.trim();
    if (!label) {
        removeTerminalLabel(terminalId);
        logger.info('Terminal label removed', { terminalId });
        return res.json({ ok: true, terminalId, label: null, terminals: getAllTerminalLabels() });
    }
    setTerminalLabel(terminalId, label);
    logger.info('Terminal label updated', { terminalId, label });
    res.json({ ok: true, terminalId, label, terminals: getAllTerminalLabels() });
});

app.delete('/terminal-labels/:terminalId', authorizeApi, (req, res) => {
    const terminalId = typeof req.params?.terminalId === 'string' ? req.params.terminalId.trim() : '';
    if (!terminalId) {
        return res.status(400).json({ error: 'terminalId is required.' });
    }
    removeTerminalLabel(terminalId);
    logger.info('Terminal label removed', { terminalId });
    res.json({ ok: true, terminalId, label: null, terminals: getAllTerminalLabels() });
});

// Demonstrate using the built-in `net` module
app.get('/is-ip/:value', (req, res) => {
    const { value } = req.params;
    res.json({ value, isIP: net.isIP(value), isIPv4: net.isIPv4(value), isIPv6: net.isIPv6(value) });
});

// Optional example using axios (won't run unless endpoint is called)
// Example external call route removed to avoid external dependencies

// Self-service page to distribute the HTTPS certificate
app.get('/cert', requireUiAuth, (req, res) => {
    const formatBytes = (bytes) => {
        if (!Number.isFinite(bytes) || bytes <= 0) return 'Unknown size';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    };
    const authState = getUiAuthState();
    const signedInUserRaw = typeof res.locals.uiUser === 'string' ? res.locals.uiUser : authState.enabled ? authState.username : '';
    const userMenuHtml = buildUserMenu(authState, signedInUserRaw);
    const navHtml = buildNavBar({ currentPath: req.path, signedIn: Boolean(signedInUserRaw), userMenuHtml });

    let certExists = false;
    let certSizeLabel = 'Unknown size';
    let certUpdatedLabel = 'Unknown';
    try {
        const stats = fs.statSync(CA_FILE_PATH);
        if (stats && stats.isFile()) {
            certExists = true;
            certSizeLabel = formatBytes(stats.size);
            certUpdatedLabel = stats.mtime ? stats.mtime.toLocaleString() : 'Unknown';
        }
    } catch (_) {
        certExists = false;
    }

    const metaMarkup = certExists ? `<p class="cert-meta">Last updated: ${escapeHtmlLite(certUpdatedLabel)} • Size: ${escapeHtmlLite(certSizeLabel)}</p>` : '<p class="cert-meta cert-meta--warning">CA certificate file not found on this bridge.</p>';
    const actionMarkup = certExists
        ? `<form class="cert-actions" method="GET" action="/cert/download">
            <button class="cert-button" type="submit">Download ca.crt</button>
          </form>`
        : '<p class="cert-error">Place ca.crt in the application root and reload this page.</p>';

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Download Certificate · TABL Print Bridge</title>
  <meta name="theme-color" content="#3B7FBE" />
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico" />
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.webp" />
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.webp" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.webp" />
  <link rel="manifest" href="/assets/site.webmanifest" />
  <style>
    ${GLOBAL_NAV_STYLES}
    ${CERT_PAGE_STYLES}
  </style>
</head>
<body>
  ${navHtml}
  <main class="cert-page">
    <section class="cert-card">
      <h1>Download Certificate</h1>
      <p>Install this CA certificate on clients that should trust the TABL Print Bridge HTTPS endpoint.</p>
      ${metaMarkup}
      ${actionMarkup}
      <p class="cert-note">After downloading <code>ca.crt</code>, add it to your operating system or browser trust store, then restart any apps that connect to the bridge.</p>
    </section>
  </main>
  <script>
    (function() {
      const userMenuEl = document.querySelector('.user-menu');
      const trigger = userMenuEl ? userMenuEl.querySelector('.user-menu__trigger') : null;
      const logoutRedirectInput = userMenuEl ? userMenuEl.querySelector('form[action="/logout"] input[name="redirect"]') : null;
      if (logoutRedirectInput) {
        const currentPath = (window.location.pathname || '/cert') + (window.location.search || '');
        logoutRedirectInput.value = encodeURIComponent(currentPath || '/login');
      }
      const closeMenu = () => {
        if (!userMenuEl || !trigger) return;
        userMenuEl.classList.remove('is-open');
        trigger.setAttribute('aria-expanded', 'false');
      };
      const toggleMenu = () => {
        if (!userMenuEl || !trigger) return;
        const willOpen = !userMenuEl.classList.contains('is-open');
        if (willOpen) {
          userMenuEl.classList.add('is-open');
          trigger.setAttribute('aria-expanded', 'true');
        } else {
          closeMenu();
        }
      };
      document.addEventListener('click', (event) => {
        if (!userMenuEl || !trigger) return;
        if (event.target.closest('.user-menu__trigger')) {
          event.preventDefault();
          toggleMenu();
          return;
        }
        if (event.target.closest('.user-menu__link')) {
          closeMenu();
        } else if (userMenuEl.classList.contains('is-open') && !event.target.closest('.user-menu')) {
          closeMenu();
        }
      });
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeMenu();
      });
    })();
  </script>
</body>
</html>`;
    res.set('Content-Type', 'text/html');
    res.send(html);
});

app.get('/cert/download', requireUiAuth, (req, res) => {
    if (!fs.existsSync(CA_FILE_PATH)) {
        logger.warn('CA certificate download requested but file not found');
        return res.status(404).json({ error: 'Certificate not found.' });
    }
    return res.download(CA_FILE_PATH, 'ca.crt', (err) => {
        if (err) {
            logger.error('Certificate download failed', { error: err.message });
            if (!res.headersSent) {
                res.status(err.statusCode || 500).json({ error: 'Unable to download certificate.' });
            }
        } else {
            logger.info('CA certificate downloaded', { username: res.locals.uiUser || 'unknown' });
        }
    });
});

// Basic UI to view printers and assign mapping
app.get('/ui', requireUiAuth, (req, res) => {
    const authState = getUiAuthState();
    const signedInUserRaw = typeof res.locals.uiUser === 'string' ? res.locals.uiUser : authState.enabled ? authState.username : '';
    const userMenuHtml = buildUserMenu(authState, signedInUserRaw);
    const navHtml = buildNavBar({ currentPath: req.path, signedIn: Boolean(signedInUserRaw), userMenuHtml });
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TABL Print Bridge</title>
  <meta name="theme-color" content="#3B7FBE" />
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico" />
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.webp" />
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.webp" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.webp" />
  <link rel="manifest" href="/assets/site.webmanifest" />
  <style>
    ${GLOBAL_NAV_STYLES}
    :root { color-scheme: light; font-size: 16px; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background-color: #f5f7fb;
      background-image:
        radial-gradient(120% 120% at 12% -10%, rgba(59, 127, 190, 0.14), transparent 55%),
        radial-gradient(120% 120% at 88% 0%, rgba(15, 27, 51, 0.1), transparent 60%),
        linear-gradient(180deg, #f6f9ff 0%, #ffffff 100%);
      background-attachment: fixed;
      background-repeat: no-repeat;
      color: #0f172a;
    }
    .page {
      max-width: 1200px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }
    .user-menu {
      position: relative;
    }
    .user-menu__trigger {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      border: 1px solid rgba(15, 27, 51, 0.12);
      border-radius: 14px;
      background: rgba(248, 251, 255, 0.85);
      padding: 8px 14px;
      font-size: 14px;
      font-weight: 600;
      color: #0f172a;
      cursor: pointer;
      box-shadow: 0 10px 26px rgba(15, 31, 55, 0.18);
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    .user-menu__trigger:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 32px rgba(15, 31, 55, 0.22);
    }
    .user-menu__initials {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      font-size: 13px;
      font-weight: 700;
    }
    .user-menu__caret {
      font-size: 11px;
      color: #64748b;
    }
    .user-menu__dropdown {
      position: absolute;
      top: calc(100% + 10px);
      right: 0;
      min-width: 180px;
      background: #fff;
      border-radius: 14px;
      box-shadow: 0 24px 60px rgba(15, 31, 55, 0.26);
      padding: 8px 0;
      opacity: 0;
      pointer-events: none;
      transform: translateY(-6px);
      transition: opacity 140ms ease, transform 140ms ease;
      z-index: 10;
    }
    .user-menu.is-open .user-menu__dropdown {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }
    .user-menu__dropdown form {
      margin: 0;
    }
    .user-menu__link {
      display: block;
      width: 100%;
      text-align: left;
      background: transparent;
      border: none;
      padding: 10px 20px;
      font-size: 14px;
      font-weight: 600;
      color: #1e293b;
      text-decoration: none;
      cursor: pointer;
    }
    .user-menu__link:hover {
      background: rgba(59, 127, 190, 0.12);
    }
    .user-menu__logout {
      color: #b3261e;
    }
    .hero {
      display: flex;
      align-items: center;
      gap: 24px;
      margin-bottom: 32px;
      padding: 32px;
      border-radius: 20px;
      background: linear-gradient(135deg, #0f1b33 0%, #3B7FBE 100%);
      color: #f8fbff;
      box-shadow: 0 20px 45px rgba(13, 51, 102, 0.25);
    }
    .hero__logo {
      width: 160px;
      flex-shrink: 0;
    }
    .hero__title {
      margin: 0;
      font-size: 32px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .hero__subtitle {
      margin: 8px 0 0;
      font-size: 16px;
      color: rgba(248, 251, 255, 0.85);
    }
    .card {
      background: #fff;
      border-radius: 18px;
      box-shadow: 0 14px 40px rgba(15, 23, 42, 0.08);
      padding: 24px 28px;
    }
    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 12px;
    }
    .controls__summary {
      margin-left: auto;
      font-size: 14px;
      color: #475569;
    }
    button {
      border: none;
      border-radius: 10px;
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 600;
      letter-spacing: 0.01em;
      cursor: pointer;
      transition: transform 120ms ease, box-shadow 120ms ease, background 120ms ease;
    }
    button:focus-visible {
      outline: 3px solid rgba(59, 127, 190, 0.55);
      outline-offset: 2px;
    }
    .btn-primary {
      background: #3B7FBE;
      color: #fff;
      box-shadow: 0 10px 20px rgba(59, 127, 190, 0.35);
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 26px rgba(59, 127, 190, 0.4);
    }
    .btn-outline {
      background: #e7f1fc;
      color: #265785;
    }
    .btn-outline:hover {
      background: #d9e8f9;
      transform: translateY(-1px);
    }
    .table-wrapper {
      overflow-x: auto;
      border-radius: 14px;
      border: 1px solid #e2e8f0;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 640px;
      background: #fff;
    }
    th, td {
      text-align: left;
      padding: 14px 16px;
      border-bottom: 1px solid #e2e8f0;
      font-size: 14px;
    }
    th {
      background: #f8fbff;
      font-weight: 600;
      color: #1e293b;
      position: sticky;
      top: 0;
      z-index: 1;
    }
    code {
      font-family: SFMono-Regular, SFMono, ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      color: #0f172a;
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 6px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      background: rgba(59, 127, 190, 0.12);
      color: #265785;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      margin-right: 6px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: rgba(15, 23, 42, 0.08);
      color: #0f172a;
      padding: 4px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      margin: 0 6px 6px 0;
    }
    .chip--assigned {
      background: rgba(59, 127, 190, 0.18);
      color: #1e3a5f;
    }
    .chip__remove {
      border: none;
      background: transparent;
      color: inherit;
      margin-left: 8px;
      padding: 0;
      font-size: 16px;
      line-height: 1;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      transition: color 120ms ease;
    }
    .chip__remove:hover {
      color: #d93025;
    }
    .chip__remove:focus-visible {
      outline: 2px solid rgba(217, 48, 37, 0.4);
      outline-offset: 2px;
    }
    .chip__edit {
      border: none;
      background: transparent;
      color: inherit;
      margin-left: 6px;
      padding: 0;
      font-size: 14px;
      line-height: 1;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      transition: color 120ms ease;
    }
    .chip__edit:hover {
      color: #1d4ed8;
    }
    .chip__edit:focus-visible {
      outline: 2px solid rgba(29, 78, 216, 0.35);
      outline-offset: 2px;
    }
    .chip__label {
      font-weight: 600;
      margin-right: 6px;
      color: #0f172a;
    }
    .chip__id {
      font-size: 11px;
      letter-spacing: 0.01em;
      color: #475569;
      background: rgba(15, 23, 42, 0.04);
      border-radius: 999px;
      padding: 2px 6px;
    }
    .chip__id--hidden {
      display: none;
    }
    .chip--assigned:hover .chip__id--hidden,
    .chip--assigned:focus-within .chip__id--hidden {
      display: inline-flex;
    }
    .label-chip {
      background: rgba(59, 127, 190, 0.18);
      color: #1e3a5f;
    }
    .status {
      font-size: 13px;
      color: #475569;
      margin: 16px 4px 0;
    }
    .status strong {
      font-weight: 600;
    }
    .ok { color: #0f9d58; font-weight: 600; }
    .err { color: #d93025; font-weight: 600; }
    .muted { color: #94a3b8; }
    .assign {
      background: transparent;
      border: 1px solid rgba(59, 127, 190, 0.6);
      color: #1e3a5f;
      padding: 8px 14px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: background 120ms ease, color 120ms ease, transform 120ms ease;
    }
    .assign:hover {
      background: rgba(59, 127, 190, 0.12);
      transform: translateY(-1px);
    }
    .assigned-cell {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 4px;
    }
    @media (max-width: 720px) {
      .hero {
        flex-direction: column;
        align-items: flex-start;
        text-align: left;
      }
      .hero__logo {
        width: 140px;
      }
      .controls {
        flex-direction: column;
        align-items: stretch;
      }
      .controls__summary {
        margin-left: 0;
      }
      table {
        min-width: 520px;
      }
    }
  </style>
</head>
<body>
  ${navHtml}
  <div class="page">
    <header class="hero">
      <img class="hero__logo" src="/assets/TABL_Logo.svg" alt="TABL" />
      <div>
        <p class="hero__title">TABL Print Bridge</p>
        <p class="hero__subtitle">Discover printers on your network and assign them to TABL terminals with confidence.</p>
      </div>
    </header>
    <section class="card">
      <div class="controls">
        <button id="refresh" class="btn-primary">Refresh</button>
        <button id="rescan" class="btn-outline">Re-scan LAN</button>
        <span id="summary" class="controls__summary muted"></span>
      </div>
      <div class="table-wrapper">
        <table id="tbl">
          <thead>
            <tr>
              <th>IP</th>
              <th>Label</th>
              <th>Ports</th>
              <th>MAC</th>
              <th>Hostname</th>
              <th>Assigned To</th>
              <th>Assign</th>
            </tr>
          </thead>
          <tbody>
            <tr><td colspan="7" class="muted">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <p class="status" id="status"></p>
    </section>
  </div>
  <script>
    const $ = (sel) => document.querySelector(sel);
    const tblBody = $('#tbl tbody');
    const statusEl = $('#status');
    const summaryEl = $('#summary');
    const userMenuEl = document.querySelector('.user-menu');
    const userMenuTrigger = userMenuEl ? userMenuEl.querySelector('.user-menu__trigger') : null;
    const logoutRedirectInput = userMenuEl ? userMenuEl.querySelector('form[action="/logout"] input[name="redirect"]') : null;
    if (logoutRedirectInput) {
      const currentPath = (window.location.pathname || '/ui') + (window.location.search || '');
      logoutRedirectInput.value = encodeURIComponent(currentPath || '/login');
    }
    const closeUserMenu = () => {
      if (!userMenuEl || !userMenuTrigger) return;
      userMenuEl.classList.remove('is-open');
      userMenuTrigger.setAttribute('aria-expanded', 'false');
    };
    const toggleUserMenu = () => {
      if (!userMenuEl || !userMenuTrigger) return;
      const willOpen = !userMenuEl.classList.contains('is-open');
      if (willOpen) {
        userMenuEl.classList.add('is-open');
        userMenuTrigger.setAttribute('aria-expanded', 'true');
      } else {
        closeUserMenu();
      }
    };
    if (userMenuEl && userMenuTrigger) {
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeUserMenu();
      });
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
    function fmtPorts(ports) { return (ports || []).map(p => '<span class="badge">' + escapeHtml(p) + '</span>').join(''); }
    function fmtPrinterLabel(printer) {
      const ip = printer.ip || '';
      const label = printer.label ? printer.label : '';
      const safeIp = escapeHtml(ip);
      const safeLabelAttr = escapeHtml(label);
      const hasLabel = Boolean(label);
      const labelContent = hasLabel
        ? '<span class="chip__label">' + escapeHtml(label) + '</span>'
        : '<span class="chip__id">No label</span>';
      return '<span class="chip label-chip">' +
        labelContent +
        '<button type="button" class="chip__edit" data-ip="' + safeIp + '" data-label="' + safeLabelAttr + '">✎</button>' +
        (hasLabel ? '<button type="button" class="chip__remove" data-ip="' + safeIp + '" aria-label="Remove label">×</button>' : '') +
      '</span>';
    }
    function fmtAssignments(printer) {
      const safeIp = escapeHtml(printer.ip || '');
      const details = Array.isArray(printer.assignedTerminalDetails) && printer.assignedTerminalDetails.length
        ? printer.assignedTerminalDetails
        : (printer.assignedTerminals || []).map((terminalId) => ({ terminalId, label: null }));
      if (!details.length) return '<span class="muted">Unassigned</span>';
      return details.map((det) => {
        const safeTerm = escapeHtml(det.terminalId || '');
        const safeLabelAttr = det.label ? escapeHtml(det.label) : '';
        const labelMarkup = det.label ? '<span class="chip__label">' + escapeHtml(det.label) + '</span>' : '';
        const idMarkup = '<span class="chip__id' + (det.label ? ' chip__id--hidden' : '') + '" data-terminal-id="' + safeTerm + '">' + safeTerm + '</span>';
        const chipTitle = safeTerm ? ' title="' + safeTerm + '"' : '';
        return '<span class="chip chip--assigned"' + chipTitle + '>' +
          labelMarkup + idMarkup +
          '<button type="button" class="chip__edit" data-terminal="' + safeTerm + '" data-label="' + safeLabelAttr + '">✎</button>' +
          '<button type="button" class="chip__remove" data-terminal="' + safeTerm + '" data-ip="' + safeIp + '" aria-label="Remove assignment for ' + safeTerm + '">×</button>' +
        '</span>';
      }).join('');
    }

    async function loadPrinters(opts={}) {
      statusEl.textContent = 'Fetching printers…';
      try {
        const q = opts.refresh ? '?refresh=true' : '';
        const res = await fetch('/printers' + q, { headers: { 'Accept': 'application/json' } });
        const data = await res.json();
        const printers = data.printers || [];
        const totalAssignments = data && data.mappings ? Object.keys(data.mappings).length : 0;
        const rows = printers.map(p => {
          const ip = p.ip || '';
          const mac = p.mac || '';
          const host = p.hostname || '';
          const ports = p.ports || [];
          const assignedMarkup = fmtAssignments(p);
          const safeIp = escapeHtml(ip);
          const safeMac = escapeHtml(mac);
          const safeHost = escapeHtml(host);
          return '<tr>' +
            '<td><code>' + safeIp + '</code></td>' +
            '<td>' + fmtPrinterLabel(p) + '</td>' +
            '<td>' + fmtPorts(ports) + '</td>' +
            '<td>' + (mac ? '<code>' + safeMac + '</code>' : '') + '</td>' +
            '<td>' + safeHost + '</td>' +
            '<td><div class="assigned-cell">' + assignedMarkup + '</div></td>' +
            '<td><button data-ip="' + safeIp + '" class="assign">Assign…</button></td>' +
          '</tr>';
        }).join('');
        tblBody.innerHTML = rows || '<tr><td colspan="7" class="muted">No printers found.</td></tr>';
        summaryEl.textContent = 'CIDR: ' + (data.cidr || 'n/a') +
          ' • ' + printers.length + ' printer(s)' +
          ' • ' + totalAssignments + ' assignment' + (totalAssignments === 1 ? '' : 's') +
          ' • Updated: ' +
          (data.lastUpdated ? new Date(data.lastUpdated).toLocaleString() : 'n/a');
        statusEl.textContent = '';
      } catch (e) {
        statusEl.textContent = 'Failed to fetch printers: ' + e.message;
      }
    }

    async function assign(ip) {
      const ipStr = String(ip || '').trim();
      const terminalIdInput = prompt('Enter terminalId to assign to ' + ipStr + ':');
      if (!terminalIdInput) return;
      const terminalId = terminalIdInput.trim();
      if (!terminalId) return;
      statusEl.textContent = 'Assigning…';
      try {
        const res = await fetch('/assign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ terminalId, ip: ipStr }) });
        const data = await res.json();
        if (res.ok && data && data.ok) {
          await loadPrinters({});
          statusEl.innerHTML = '<span class="ok">Assigned</span> ' + escapeHtml(terminalId) + ' → ' + escapeHtml(ipStr);
        } else {
          const message = data && (data.error || JSON.stringify(data));
          statusEl.innerHTML = '<span class="err">Assign failed:</span> ' + escapeHtml(message || 'Unknown error');
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="err">Assign error:</span> ' + escapeHtml(e.message || String(e));
      }
    }

    async function unassign(terminalId) {
      if (!terminalId) return;
      const id = String(terminalId).trim();
      if (!id) return;
      statusEl.textContent = 'Removing assignment…';
      try {
        const res = await fetch('/assign/' + encodeURIComponent(id), { method: 'DELETE', headers: { 'Accept': 'application/json' } });
        const data = await res.json();
        if (res.ok && data && data.ok) {
          await loadPrinters({});
          statusEl.innerHTML = '<span class="ok">Unassigned</span> ' + escapeHtml(id);
        } else {
          const message = data && (data.error || JSON.stringify(data));
          statusEl.innerHTML = '<span class="err">Unassign failed:</span> ' + escapeHtml(message || 'Unknown error');
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="err">Unassign error:</span> ' + escapeHtml(e.message || String(e));
      }
    }

    async function setPrinterLabelValue(ip, label) {
      const trimmedIp = String(ip || '').trim();
      if (!trimmedIp) return;
      const trimmedLabel = String(label || '').trim();
      const removing = trimmedLabel.length === 0;
      statusEl.textContent = removing ? 'Removing printer label…' : 'Saving printer label…';
      try {
        let res;
        if (removing) {
          res = await fetch('/printer-labels/' + encodeURIComponent(trimmedIp), {
            method: 'DELETE',
            headers: { 'Accept': 'application/json' },
          });
        } else {
          res = await fetch('/printer-labels', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: trimmedIp, label: trimmedLabel }),
          });
        }
        const data = await res.json();
        if (res.ok && data) {
          await loadPrinters({});
          statusEl.innerHTML = '<span class="ok">' + (removing ? 'Label cleared' : 'Label saved') + '</span> ' + escapeHtml(trimmedIp);
        } else {
          const message = data && (data.error || JSON.stringify(data));
          statusEl.innerHTML = '<span class="err">Label update failed:</span> ' + escapeHtml(message || 'Unknown error');
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="err">Label update error:</span> ' + escapeHtml(e.message || String(e));
      }
    }

    async function editPrinterLabel(ip, currentLabel = '') {
      const ipStr = String(ip || '').trim();
      if (!ipStr) return;
      const value = prompt('Enter label for ' + ipStr + ':', currentLabel || '');
      if (value === null) return;
      await setPrinterLabelValue(ipStr, value);
    }

    async function clearPrinterLabel(ip) {
      const ipStr = String(ip || '').trim();
      if (!ipStr) return;
      if (!window.confirm('Remove label for ' + ipStr + '?')) return;
      await setPrinterLabelValue(ipStr, '');
    }

    async function setTerminalLabelValue(terminalId, label) {
      const id = String(terminalId || '').trim();
      if (!id) return;
      const trimmedLabel = String(label || '').trim();
      const removing = trimmedLabel.length === 0;
      statusEl.textContent = removing ? 'Removing terminal label…' : 'Saving terminal label…';
      try {
        let res;
        if (removing) {
          res = await fetch('/terminal-labels/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: { 'Accept': 'application/json' },
          });
        } else {
          res = await fetch('/terminal-labels', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ terminalId: id, label: trimmedLabel }),
          });
        }
        const data = await res.json();
        if (res.ok && data) {
          await loadPrinters({});
          statusEl.innerHTML = '<span class="ok">' + (removing ? 'Terminal label cleared' : 'Terminal label saved') + '</span> ' + escapeHtml(id);
        } else {
          const message = data && (data.error || JSON.stringify(data));
          statusEl.innerHTML = '<span class="err">Terminal label failed:</span> ' + escapeHtml(message || 'Unknown error');
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="err">Terminal label error:</span> ' + escapeHtml(e.message || String(e));
      }
    }

    async function editTerminalLabel(terminalId, currentLabel = '') {
      const id = String(terminalId || '').trim();
      if (!id) return;
      const value = prompt('Enter label for ' + id + ':', currentLabel || '');
      if (value === null) return;
      await setTerminalLabelValue(id, value);
    }

    document.addEventListener('click', (ev) => {
      if (userMenuEl && userMenuTrigger) {
        const triggerMatch = ev.target.closest('.user-menu__trigger');
        if (triggerMatch) {
          ev.preventDefault();
          toggleUserMenu();
          return;
        }
        const menuItem = ev.target.closest('.user-menu__link');
        if (menuItem) {
          closeUserMenu();
        } else if (userMenuEl.classList.contains('is-open') && !ev.target.closest('.user-menu')) {
          closeUserMenu();
        }
      }
      const terminalIdSpan = ev.target.closest('.chip__id');
      if (terminalIdSpan) {
        const copyValue = terminalIdSpan.getAttribute('data-terminal-id') || terminalIdSpan.textContent || '';
        const trimmed = copyValue.trim();
        if (trimmed) {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(trimmed).catch(() => {});
          } else {
            try {
              const range = document.createRange();
              range.selectNodeContents(terminalIdSpan);
              const selection = window.getSelection();
              selection.removeAllRanges();
              selection.addRange(range);
            } catch (err) {
              console.error('Copy fallback failed', err);
            }
          }
        }
        return;
      }
      const editBtn = ev.target.closest('button.chip__edit');
      if (editBtn) {
        const ipTarget = editBtn.getAttribute('data-ip') || '';
        if (ipTarget) {
          const current = editBtn.getAttribute('data-label') || '';
          editPrinterLabel(ipTarget, current);
          return;
        }
        const terminalId = editBtn.getAttribute('data-terminal') || '';
        if (terminalId) {
          const current = editBtn.getAttribute('data-label') || '';
          editTerminalLabel(terminalId, current);
          return;
        }
      }
      const removeBtn = ev.target.closest('button.chip__remove');
      if (removeBtn) {
        const ipTarget = removeBtn.getAttribute('data-ip') || '';
        if (ipTarget && !removeBtn.getAttribute('data-terminal')) {
          clearPrinterLabel(ipTarget);
          return;
        }
        const terminalIdAttr = removeBtn.getAttribute('data-terminal');
        if (terminalIdAttr) {
          const trimmedId = terminalIdAttr.trim();
          if (trimmedId && window.confirm('Remove assignment for ' + trimmedId + '?')) {
            unassign(trimmedId);
          }
        }
        return;
      }
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

app.delete('/assign/:terminalId', authenticateToken, async (req, res) => {
    const { terminalId } = req.params || {};
    if (!terminalId) {
        return res.status(400).json({ error: 'terminalId is required' });
    }
    try {
        const { map, removedIp } = removePrinterIp(String(terminalId));
        if (removedIp === undefined) {
            return res.status(404).json({ error: 'No assignment found for terminalId', terminalId });
        }
        logger.info('Printer mapping removed', { terminalId: String(terminalId), ip: removedIp });
        return res.json({ ok: true, terminalId: String(terminalId), removedIp, mappings: map });
    } catch (err) {
        logger.error('Failed to remove printer mapping', { error: err.message || String(err), terminalId });
        return res.status(500).json({ ok: false, error: err.message || String(err) });
    }
});

app.get('/api/printers', authorizeApi, (req, res) => {
    const printers = collectPrinters();
    res.json({ printers });
});

app.post('/printers', authorizeApi, (req, res) => {
    const ipRaw = typeof req.body?.ip === 'string' ? req.body.ip : '';
    const ip = ipRaw.trim();
    if (!ip || net.isIP(ip) === 0) {
        return res.status(400).json({ error: 'ip must be a valid IPv4/IPv6 address' });
    }
    const labelRaw = typeof req.body?.label === 'string' ? req.body.label : '';
    const label = labelRaw.trim();
    setPrinterLabel(ip, label);
    logger.info('Printer label saved', { ip, label });
    const printers = collectPrinters();
    const printer = printers.find((entry) => entry.ip === ip) || null;
    res.json({ ok: true, printer, printers });
});

app.patch('/printers/:ip', authorizeApi, (req, res) => {
    const ipParam = typeof req.params?.ip === 'string' ? req.params.ip : '';
    const ip = ipParam.trim();
    if (!ip || net.isIP(ip) === 0) {
        return res.status(400).json({ error: 'ip must be a valid IPv4/IPv6 address' });
    }
    const labelRaw = typeof req.body?.label === 'string' ? req.body.label : '';
    const label = labelRaw.trim();
    if (!label) {
        removePrinterLabel(ip);
        logger.info('Printer label removed', { ip });
    } else {
        setPrinterLabel(ip, label);
        logger.info('Printer label saved', { ip, label });
    }
    const printers = collectPrinters();
    const printer = printers.find((entry) => entry.ip === ip) || null;
    res.json({ ok: true, printer, printers });
});

app.delete('/printers/:ip', authorizeApi, (req, res) => {
    const ipParam = typeof req.params?.ip === 'string' ? req.params.ip : '';
    const ip = ipParam.trim();
    if (!ip || net.isIP(ip) === 0) {
        return res.status(400).json({ error: 'ip must be a valid IPv4/IPv6 address' });
    }
    removePrinterLabel(ip);
    const mappings = getAllMappings();
    const affectedTerminals = Object.entries(mappings || {})
        .filter(([, mappedIp]) => String(mappedIp).trim() === ip)
        .map(([terminalId]) => terminalId);
    const removedTerminals = [];
    affectedTerminals.forEach((terminalId) => {
        try {
            const result = removePrinterIp(terminalId);
            if (result && Object.prototype.hasOwnProperty.call(result, 'removedIp')) {
                removedTerminals.push(String(terminalId));
            }
        } catch (err) {
            logger.warn('Failed to remove mapping during printer delete', { terminalId, ip, error: err.message });
        }
    });
    logger.info('Printer entry removed', { ip, removedTerminals });
    const printers = collectPrinters();
    res.json({ ok: true, ip, removedTerminals, printers });
});

app.get('/api/global-printers', authorizeApi, (req, res) => {
    const printers = collectGlobalPrinters();
    res.json({ printers });
});

app.post('/global-printers', authorizeApi, (req, res) => {
    const printerIdRaw = typeof req.body?.printerId === 'string' ? req.body.printerId : '';
    const printerId = printerIdRaw.trim();
    if (!printerId) {
        return res.status(400).json({ error: 'printerId is required' });
    }
    const ipRaw = typeof req.body?.ip === 'string' ? req.body.ip : '';
    const ip = ipRaw.trim();
    if (!ip || net.isIP(ip) === 0) {
        return res.status(400).json({ error: 'ip must be a valid IPv4/IPv6 address' });
    }
    const labelRaw = typeof req.body?.label === 'string' ? req.body.label : '';
    const label = labelRaw.trim();
    if (getGlobalPrinter(printerId)) {
        return res.status(409).json({ error: 'Global printer already exists', printerId });
    }
    setGlobalPrinter(printerId, ip, label);
    logger.info('Global printer saved', { printerId, ip, label });
    const printers = collectGlobalPrinters();
    const printer = printers.find((entry) => entry.printerId === printerId) || null;
    res.json({ ok: true, printer, printers });
});

app.patch('/global-printers/:printerId', authorizeApi, (req, res) => {
    const printerIdParam = typeof req.params?.printerId === 'string' ? req.params.printerId : '';
    const printerId = printerIdParam.trim();
    if (!printerId) {
        return res.status(400).json({ error: 'printerId is required' });
    }
    const existing = getGlobalPrinter(printerId);
    if (!existing) {
        return res.status(404).json({ error: 'Global printer not found', printerId });
    }
    const ipProvided = typeof req.body?.ip === 'string';
    const labelProvided = typeof req.body?.label === 'string';
    if (!ipProvided && !labelProvided) {
        return res.status(400).json({ error: 'Nothing to update' });
    }
    let nextIp = existing.ip;
    if (ipProvided) {
        const ipCandidate = req.body.ip.trim();
        if (!ipCandidate || net.isIP(ipCandidate) === 0) {
            return res.status(400).json({ error: 'ip must be a valid IPv4/IPv6 address' });
        }
        nextIp = ipCandidate;
    }
    const nextLabel = labelProvided ? req.body.label.trim() : existing.label || '';
    setGlobalPrinter(printerId, nextIp, nextLabel);
    logger.info('Global printer updated', { printerId, ip: nextIp, label: nextLabel });
    const printers = collectGlobalPrinters();
    const printer = printers.find((entry) => entry.printerId === printerId) || null;
    res.json({ ok: true, printer, printers });
});

app.delete('/global-printers/:printerId', authorizeApi, (req, res) => {
    const printerIdParam = typeof req.params?.printerId === 'string' ? req.params.printerId : '';
    const printerId = printerIdParam.trim();
    if (!printerId) {
        return res.status(400).json({ error: 'printerId is required' });
    }
    const removal = removeGlobalPrinter(printerId);
    if (!removal.removed) {
        return res.status(404).json({ error: 'Global printer not found', printerId });
    }
    logger.info('Global printer removed', { printerId, ip: removal.removed.ip || null });
    const printers = collectGlobalPrinters();
    res.json({ ok: true, printerId, printers });
});

app.get('/ui/printers', requireUiAuth, (req, res) => {
    const authState = getUiAuthState();
    const signedInUserRaw = typeof res.locals.uiUser === 'string' ? res.locals.uiUser : authState.enabled ? authState.username : '';
    const userMenuHtml = buildUserMenu(authState, signedInUserRaw);
    const navHtml = buildNavBar({ currentPath: req.path, signedIn: Boolean(signedInUserRaw), userMenuHtml });
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TABL Printers</title>
  <meta name="theme-color" content="#3B7FBE" />
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico" />
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.webp" />
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.webp" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.webp" />
  <link rel="manifest" href="/assets/site.webmanifest" />
  <style>
    ${GLOBAL_NAV_STYLES}
    :root { color-scheme: light; font-size: 16px; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background-color: #f5f7fb;
      background-image:
        radial-gradient(120% 120% at 12% -10%, rgba(59, 127, 190, 0.14), transparent 55%),
        radial-gradient(120% 120% at 88% 0%, rgba(15, 27, 51, 0.1), transparent 60%),
        linear-gradient(180deg, #f6f9ff 0%, #ffffff 100%);
      background-attachment: fixed;
      background-repeat: no-repeat;
      color: #0f172a;
    }
    .page {
      max-width: 960px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }
    .hero {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
      margin-bottom: 24px;
    }
    .hero__text {
      flex: 1 1 420px;
    }
    .hero__title {
      margin: 0;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .hero__subtitle {
      margin: 6px 0 0;
      font-size: 15px;
      color: #475569;
      max-width: 520px;
    }
    .hero__actions {
      display: flex;
      align-items: center;
    }
    .hero__link {
      font-size: 13px;
      color: #3B7FBE;
      font-weight: 600;
      text-decoration: none;
    }
    .hero__link:hover {
      text-decoration: underline;
    }
    .card {
      background: rgba(248, 251, 255, 0.96);
      border-radius: 18px;
      box-shadow: 0 22px 56px rgba(15, 31, 55, 0.22);
      padding: 28px 24px;
    }
    .controls {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }
    .controls__group {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .controls__summary {
      font-size: 13px;
      color: #64748b;
    }
    .btn-primary, .btn-outline {
      border-radius: 12px;
      padding: 10px 18px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 120ms ease, box-shadow 120ms ease, background 120ms ease, color 120ms ease;
      border: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      box-shadow: 0 14px 28px rgba(59, 127, 190, 0.45);
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 16px 32px rgba(59, 127, 190, 0.5);
    }
    .btn-outline {
      background: transparent;
      color: #1e3a5f;
      border: 1px solid rgba(59, 127, 190, 0.6);
    }
    .btn-outline:hover {
      background: rgba(59, 127, 190, 0.12);
      transform: translateY(-1px);
    }
    .table-wrapper {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border-radius: 12px;
      overflow: hidden;
    }
    th, td {
      padding: 12px 16px;
      text-align: left;
      font-size: 14px;
      border-bottom: 1px solid rgba(15, 31, 55, 0.08);
    }
    th {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #64748b;
      background: rgba(15, 23, 42, 0.04);
    }
    tbody tr:last-child td {
      border-bottom: none;
    }
    tbody tr:hover {
      background: rgba(59, 127, 190, 0.08);
    }
    code {
      background: rgba(15, 23, 42, 0.08);
      color: #1f2937;
      border-radius: 6px;
      padding: 2px 6px;
      font-size: 12px;
    }
    .label-pill {
      display: inline-flex;
      align-items: center;
      background: rgba(59, 127, 190, 0.18);
      color: #1e3a5f;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
    }
    .assigned-pill {
      display: inline-flex;
      align-items: center;
      background: rgba(15, 23, 42, 0.08);
      color: #0f172a;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11px;
      margin: 0 6px 6px 0;
    }
    .assigned-pill__label {
      font-weight: 600;
      margin-right: 6px;
      color: #0f172a;
    }
    .assigned-pill__id {
      color: #475569;
      background: rgba(15, 23, 42, 0.04);
      border-radius: 999px;
      padding: 2px 6px;
    }
    .actions {
      display: flex;
      gap: 12px;
    }
    .btn-link {
      border: none;
      background: transparent;
      font-size: 13px;
      font-weight: 600;
      color: #1d4ed8;
      cursor: pointer;
      padding: 0;
    }
    .btn-link:hover {
      text-decoration: underline;
    }
    .btn-link.delete {
      color: #b3261e;
    }
    .muted {
      color: #94a3b8;
    }
    .status {
      margin: 18px 4px 0;
      font-size: 13px;
      color: #475569;
    }
    @media (max-width: 720px) {
      .controls {
        flex-direction: column;
        align-items: stretch;
      }
      .controls__group {
        justify-content: flex-start;
      }
      table {
        min-width: 520px;
      }
    }
  </style>
</head>
<body>
  ${navHtml}
  <div class="page">
    <header class="hero">
      <div class="hero__text">
        <h1 class="hero__title">Printer Directory</h1>
        <p class="hero__subtitle">Review discovered printers, manage labels, and monitor terminal usage.</p>
      </div>
      <div class="hero__actions">
        <a class="hero__link" href="/ui">← Back to Printers Table</a>
      </div>
    </header>
    <section class="card">
      <div class="controls">
        <div class="controls__group">
          <button id="refresh" class="btn-outline" type="button">Refresh</button>
          <button id="add-printer" class="btn-primary" type="button">Add Printer</button>
        </div>
        <span id="summary" class="controls__summary muted"></span>
      </div>
      <div class="table-wrapper">
        <table id="printer-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Label</th>
              <th>Assigned Terminals</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr><td colspan="4" class="muted">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <p class="status" id="status"></p>
    </section>
  </div>
  <script>
    const userMenuEl = document.querySelector('.user-menu');
    const userMenuTrigger = userMenuEl ? userMenuEl.querySelector('.user-menu__trigger') : null;
    const logoutRedirectInput = userMenuEl ? userMenuEl.querySelector('form[action="/logout"] input[name="redirect"]') : null;
    if (logoutRedirectInput) {
      const currentPath = (window.location.pathname || '/ui/printers') + (window.location.search || '');
      logoutRedirectInput.value = encodeURIComponent(currentPath || '/ui/printers');
    }
    const closeUserMenu = () => {
      if (!userMenuEl || !userMenuTrigger) return;
      userMenuEl.classList.remove('is-open');
      userMenuTrigger.setAttribute('aria-expanded', 'false');
    };
    const toggleUserMenu = () => {
      if (!userMenuEl || !userMenuTrigger) return;
      const willOpen = !userMenuEl.classList.contains('is-open');
      if (willOpen) {
        userMenuEl.classList.add('is-open');
        userMenuTrigger.setAttribute('aria-expanded', 'true');
      } else {
        closeUserMenu();
      }
    };
    if (userMenuEl && userMenuTrigger) {
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeUserMenu();
      });
    }

    const tblBody = document.querySelector('#printer-table tbody');
    const statusEl = document.getElementById('status');
    const summaryEl = document.getElementById('summary');
    const refreshBtn = document.getElementById('refresh');
    const addBtn = document.getElementById('add-printer');
    let printers = [];

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function renderAssigned(details) {
      if (!Array.isArray(details) || details.length === 0) return '<span class="muted">Unassigned</span>';
      return details.map((item) => {
        const labelMarkup = item.label ? '<span class="assigned-pill__label">' + escapeHtml(item.label) + '</span>' : '';
        const idMarkup = '<span class="assigned-pill__id">' + escapeHtml(item.terminalId || '') + '</span>';
        return '<span class="assigned-pill">' + labelMarkup + idMarkup + '</span>';
      }).join('');
    }

    function renderPrinters(list) {
      if (!Array.isArray(list) || list.length === 0) {
        tblBody.innerHTML = '<tr><td colspan="4" class="muted">No printers found.</td></tr>';
        summaryEl.textContent = '0 printers';
        return;
      }
      const rows = list.map((item) => {
        const safeIp = escapeHtml(item.ip || '');
        const label = typeof item.label === 'string' && item.label.length > 0 ? escapeHtml(item.label) : '';
        const labelCell = label ? '<span class="label-pill">' + label + '</span>' : '<span class="muted">No label</span>';
        const assigned = renderAssigned(Array.isArray(item.assignedTerminalDetails) ? item.assignedTerminalDetails : []);
        return '<tr data-ip="' + safeIp + '">' +
          '<td><code>' + safeIp + '</code></td>' +
          '<td>' + labelCell + '</td>' +
          '<td>' + assigned + '</td>' +
          '<td class="actions">' +
            '<button type="button" class="btn-link edit" data-action="edit" data-ip="' + safeIp + '">Edit</button>' +
            '<button type="button" class="btn-link delete" data-action="delete" data-ip="' + safeIp + '">Delete</button>' +
          '</td>' +
        '</tr>';
      }).join('');
      tblBody.innerHTML = rows;
      const count = list.length;
      summaryEl.textContent = count + ' printer' + (count === 1 ? '' : 's');
    }

    async function loadPrinters() {
      statusEl.textContent = 'Loading printers…';
      try {
        const res = await fetch('/api/printers', { headers: { 'Accept': 'application/json' } });
        if (!res.ok) throw new Error('Request failed (' + res.status + ')');
        const data = await res.json();
        printers = Array.isArray(data.printers) ? data.printers : [];
        renderPrinters(printers);
        statusEl.textContent = 'Loaded ' + printers.length + ' printer' + (printers.length === 1 ? '' : 's') + '.';
      } catch (err) {
        statusEl.textContent = 'Load failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    async function createPrinter() {
      const ipValue = window.prompt('Enter printer IP address:');
      if (ipValue === null) return;
      const ip = String(ipValue).trim();
      if (!ip) {
        window.alert('Printer IP is required.');
        return;
      }
      const labelValue = window.prompt('Enter label for ' + ip + ' (optional):', '');
      if (labelValue === null) return;
      const label = String(labelValue).trim();
      statusEl.textContent = 'Creating printer entry…';
      try {
        const res = await fetch('/printers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, label })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          throw new Error((data && data.error) || 'Request failed (' + res.status + ')');
        }
        printers = Array.isArray(data.printers) ? data.printers : printers;
        renderPrinters(printers);
        statusEl.textContent = 'Printer ' + ip + ' saved.';
      } catch (err) {
        statusEl.textContent = 'Create failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    async function savePrinterLabel(ip, label) {
      if (!ip) return;
      statusEl.textContent = 'Saving label…';
      try {
        const res = await fetch('/printers/' + encodeURIComponent(ip), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          throw new Error((data && data.error) || 'Request failed (' + res.status + ')');
        }
        printers = Array.isArray(data.printers) ? data.printers : printers;
        renderPrinters(printers);
        statusEl.textContent = 'Label updated for ' + ip + '.';
      } catch (err) {
        statusEl.textContent = 'Update failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    async function deletePrinter(ip) {
      if (!ip) return;
      const confirmed = window.confirm('Delete printer ' + ip + '? Any assignments to this IP will be removed.');
      if (!confirmed) return;
      statusEl.textContent = 'Deleting printer…';
      try {
        const res = await fetch('/printers/' + encodeURIComponent(ip), {
          method: 'DELETE',
          headers: { 'Accept': 'application/json' }
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          throw new Error((data && data.error) || 'Request failed (' + res.status + ')');
        }
        printers = Array.isArray(data.printers) ? data.printers : printers;
        renderPrinters(printers);
        const removed = Array.isArray(data.removedTerminals) && data.removedTerminals.length
          ? ' Removed assignments for ' + data.removedTerminals.join(', ') + '.'
          : '';
        statusEl.textContent = 'Printer ' + ip + ' deleted.' + removed;
      } catch (err) {
        statusEl.textContent = 'Delete failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    document.addEventListener('click', (event) => {
      if (userMenuEl && userMenuTrigger) {
        const triggerMatch = event.target.closest('.user-menu__trigger');
        if (triggerMatch) {
          event.preventDefault();
          toggleUserMenu();
          return;
        }
        const menuItem = event.target.closest('.user-menu__link');
        if (menuItem) {
          closeUserMenu();
        } else if (userMenuEl.classList.contains('is-open') && !event.target.closest('.user-menu')) {
          closeUserMenu();
        }
      }
      const actionBtn = event.target.closest('button[data-action]');
      if (actionBtn) {
        const ip = actionBtn.getAttribute('data-ip') || '';
        const action = actionBtn.getAttribute('data-action');
        if (!ip || !action) return;
        if (action === 'edit') {
          const entry = printers.find((item) => item.ip === ip);
          const currentLabel = entry ? entry.label || '' : '';
          const next = window.prompt('Update label for ' + ip + ':', currentLabel);
          if (next === null) return;
          savePrinterLabel(ip, String(next).trim());
        } else if (action === 'delete') {
          deletePrinter(ip);
        }
      }
    });

    refreshBtn.addEventListener('click', () => loadPrinters());
    addBtn.addEventListener('click', () => createPrinter());

    loadPrinters();
  </script>
</body>
</html>`;
    res.set('Content-Type', 'text/html');
    res.send(html);
});

app.get('/ui/terminals', requireUiAuth, (req, res) => {
    const authState = getUiAuthState();
    const signedInUserRaw = typeof res.locals.uiUser === 'string' ? res.locals.uiUser : authState.enabled ? authState.username : '';
    const userMenuHtml = buildUserMenu(authState, signedInUserRaw);
    const navHtml = buildNavBar({ currentPath: req.path, signedIn: Boolean(signedInUserRaw), userMenuHtml });
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TABL Terminals</title>
  <meta name="theme-color" content="#3B7FBE" />
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico" />
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.webp" />
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.webp" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.webp" />
  <link rel="manifest" href="/assets/site.webmanifest" />
  <style>
    ${GLOBAL_NAV_STYLES}
    :root { color-scheme: light; font-size: 16px; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background-color: #f5f7fb;
      background-image:
        radial-gradient(120% 120% at 12% -10%, rgba(59, 127, 190, 0.14), transparent 55%),
        radial-gradient(120% 120% at 88% 0%, rgba(15, 27, 51, 0.1), transparent 60%),
        linear-gradient(180deg, #f6f9ff 0%, #ffffff 100%);
      background-attachment: fixed;
      background-repeat: no-repeat;
      color: #0f172a;
    }
    .page {
      max-width: 960px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }
    .hero {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
      margin-bottom: 24px;
    }
    .hero__text {
      flex: 1 1 420px;
    }
    .hero__title {
      margin: 0;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .hero__subtitle {
      margin: 6px 0 0;
      font-size: 15px;
      color: #475569;
      max-width: 520px;
    }
    .hero__actions {
      display: flex;
      align-items: center;
    }
    .hero__link {
      font-size: 13px;
      color: #3B7FBE;
      font-weight: 600;
      text-decoration: none;
    }
    .hero__link:hover {
      text-decoration: underline;
    }
    .card {
      background: rgba(248, 251, 255, 0.96);
      border-radius: 18px;
      box-shadow: 0 22px 56px rgba(15, 31, 55, 0.22);
      padding: 28px 24px;
    }
    .controls {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }
    .controls__group {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .controls__summary {
      font-size: 13px;
      color: #64748b;
    }
    .btn-primary, .btn-outline {
      border-radius: 12px;
      padding: 10px 18px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 120ms ease, box-shadow 120ms ease, background 120ms ease, color 120ms ease;
      border: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, #3B7FBE 0%, #265785 100%);
      color: #fff;
      box-shadow: 0 14px 28px rgba(59, 127, 190, 0.45);
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 16px 32px rgba(59, 127, 190, 0.5);
    }
    .btn-outline {
      background: transparent;
      color: #1e3a5f;
      border: 1px solid rgba(59, 127, 190, 0.6);
    }
    .btn-outline:hover {
      background: rgba(59, 127, 190, 0.12);
      transform: translateY(-1px);
    }
    .table-wrapper {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border-radius: 12px;
      overflow: hidden;
    }
    th, td {
      padding: 12px 16px;
      text-align: left;
      font-size: 14px;
      border-bottom: 1px solid rgba(15, 31, 55, 0.08);
    }
    th {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #64748b;
      background: rgba(15, 23, 42, 0.04);
    }
    tbody tr:last-child td {
      border-bottom: none;
    }
    tbody tr:hover {
      background: rgba(59, 127, 190, 0.08);
    }
    code {
      background: rgba(15, 23, 42, 0.08);
      color: #1f2937;
      border-radius: 6px;
      padding: 2px 6px;
      font-size: 12px;
    }
    .label-pill {
      display: inline-flex;
      align-items: center;
      background: rgba(59, 127, 190, 0.18);
      color: #1e3a5f;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
    }
    .actions {
      display: flex;
      gap: 12px;
    }
    .btn-link {
      border: none;
      background: transparent;
      font-size: 13px;
      font-weight: 600;
      color: #1d4ed8;
      cursor: pointer;
      padding: 0;
    }
    .btn-link:hover {
      text-decoration: underline;
    }
    .btn-link.delete {
      color: #b3261e;
    }
    .muted {
      color: #94a3b8;
    }
    .status {
      margin: 18px 4px 0;
      font-size: 13px;
      color: #475569;
    }
    @media (max-width: 720px) {
      .controls {
        flex-direction: column;
        align-items: stretch;
      }
      .controls__group {
        justify-content: flex-start;
      }
      table {
        min-width: 520px;
      }
    }
  </style>
</head>
<body>
  ${navHtml}
  <div class="page">
    <header class="hero">
      <div class="hero__text">
        <h1 class="hero__title">Terminal Directory</h1>
        <p class="hero__subtitle">Manage terminal IDs and labels used by the Print Bridge.</p>
      </div>
      <div class="hero__actions">
        <a class="hero__link" href="/ui">← Back to Printers</a>
      </div>
    </header>
    <section class="card">
      <div class="controls">
        <div class="controls__group">
          <button id="refresh" class="btn-outline" type="button">Refresh</button>
          <button id="add-terminal" class="btn-primary" type="button">Add Terminal</button>
        </div>
        <span id="summary" class="controls__summary muted"></span>
      </div>
      <div class="table-wrapper">
        <table id="terminal-table">
          <thead>
            <tr>
              <th>Terminal ID</th>
              <th>Label</th>
              <th>Assigned Printer</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr><td colspan="4" class="muted">Loading…</td></tr>
          </tbody>
        </table>
      </div>
      <p class="status" id="status"></p>
    </section>
  </div>
  <script>
    const userMenuEl = document.querySelector('.user-menu');
    const userMenuTrigger = userMenuEl ? userMenuEl.querySelector('.user-menu__trigger') : null;
    const logoutRedirectInput = userMenuEl ? userMenuEl.querySelector('form[action="/logout"] input[name="redirect"]') : null;
    if (logoutRedirectInput) {
      const currentPath = (window.location.pathname || '/ui/terminals') + (window.location.search || '');
      logoutRedirectInput.value = encodeURIComponent(currentPath || '/ui/terminals');
    }
    const closeUserMenu = () => {
      if (!userMenuEl || !userMenuTrigger) return;
      userMenuEl.classList.remove('is-open');
      userMenuTrigger.setAttribute('aria-expanded', 'false');
    };
    const toggleUserMenu = () => {
      if (!userMenuEl || !userMenuTrigger) return;
      const willOpen = !userMenuEl.classList.contains('is-open');
      if (willOpen) {
        userMenuEl.classList.add('is-open');
        userMenuTrigger.setAttribute('aria-expanded', 'true');
      } else {
        closeUserMenu();
      }
    };
    if (userMenuEl && userMenuTrigger) {
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeUserMenu();
      });
    }

    const tblBody = document.querySelector('#terminal-table tbody');
    const statusEl = document.getElementById('status');
    const summaryEl = document.getElementById('summary');
    const refreshBtn = document.getElementById('refresh');
    const addBtn = document.getElementById('add-terminal');
    let terminals = [];

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function renderTerminals(list) {
      if (!Array.isArray(list) || list.length === 0) {
        tblBody.innerHTML = '<tr><td colspan="4" class="muted">No terminals found.</td></tr>';
        summaryEl.textContent = '0 terminals';
        return;
      }
      const rows = list.map((item) => {
        const safeId = escapeHtml(item.terminalId || '');
        const label = typeof item.label === 'string' && item.label.length > 0 ? escapeHtml(item.label) : '';
        const assigned = item.assignedIp ? '<code>' + escapeHtml(item.assignedIp) + '</code>' : '<span class="muted">—</span>';
        const labelCell = label ? '<span class="label-pill">' + label + '</span>' : '<span class="muted">No label</span>';
        return '<tr data-id="' + safeId + '">' +
          '<td><code>' + safeId + '</code></td>' +
          '<td>' + labelCell + '</td>' +
          '<td>' + assigned + '</td>' +
          '<td class="actions">' +
            '<button type="button" class="btn-link edit" data-action="edit" data-id="' + safeId + '">Edit</button>' +
            '<button type="button" class="btn-link delete" data-action="delete" data-id="' + safeId + '">Delete</button>' +
          '</td>' +
        '</tr>';
      }).join('');
      tblBody.innerHTML = rows;
      const count = list.length;
      summaryEl.textContent = count + ' terminal' + (count === 1 ? '' : 's');
    }

    async function loadTerminals() {
      statusEl.textContent = 'Loading terminals…';
      try {
        const res = await fetch('/api/terminals', { headers: { 'Accept': 'application/json' } });
        if (!res.ok) {
          throw new Error('Request failed (' + res.status + ')');
        }
        const data = await res.json();
        terminals = Array.isArray(data.terminals) ? data.terminals : [];
        renderTerminals(terminals);
        statusEl.textContent = 'Loaded ' + terminals.length + ' terminal' + (terminals.length === 1 ? '' : 's') + '.';
      } catch (err) {
        statusEl.textContent = 'Load failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    async function createTerminal() {
      const idValue = window.prompt('Enter new terminal ID:');
      if (idValue === null) return;
      const terminalId = String(idValue).trim();
      if (!terminalId) {
        window.alert('Terminal ID is required.');
        return;
      }
      const labelValue = window.prompt('Enter label for ' + terminalId + ' (optional):', '');
      if (labelValue === null) return;
      const label = String(labelValue).trim();
      statusEl.textContent = 'Creating terminal…';
      try {
        const res = await fetch('/terminals', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ terminalId, label })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          throw new Error((data && data.error) || 'Request failed (' + res.status + ')');
        }
        terminals = Array.isArray(data.terminals) ? data.terminals : terminals;
        renderTerminals(terminals);
        statusEl.textContent = 'Terminal ' + terminalId + ' created.';
      } catch (err) {
        statusEl.textContent = 'Create failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    async function saveTerminalLabel(id, label) {
      if (!id) return;
      statusEl.textContent = 'Saving label…';
      try {
        const res = await fetch('/terminals/' + encodeURIComponent(id), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          throw new Error((data && data.error) || 'Request failed (' + res.status + ')');
        }
        terminals = Array.isArray(data.terminals) ? data.terminals : terminals;
        renderTerminals(terminals);
        statusEl.textContent = 'Label updated for ' + id + '.';
      } catch (err) {
        statusEl.textContent = 'Update failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    async function deleteTerminal(id) {
      if (!id) return;
      const confirmed = window.confirm('Delete terminal ' + id + '? This will also remove existing assignments.');
      if (!confirmed) return;
      statusEl.textContent = 'Deleting terminal…';
      try {
        const res = await fetch('/terminals/' + encodeURIComponent(id), {
          method: 'DELETE',
          headers: { 'Accept': 'application/json' }
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          throw new Error((data && data.error) || 'Request failed (' + res.status + ')');
        }
        terminals = Array.isArray(data.terminals) ? data.terminals : terminals;
        renderTerminals(terminals);
        statusEl.textContent = 'Terminal ' + id + ' deleted.';
      } catch (err) {
        statusEl.textContent = 'Delete failed: ' + (err && err.message ? err.message : String(err));
      }
    }

    document.addEventListener('click', (event) => {
      if (userMenuEl && userMenuTrigger) {
        const triggerMatch = event.target.closest('.user-menu__trigger');
        if (triggerMatch) {
          event.preventDefault();
          toggleUserMenu();
          return;
        }
        const menuItem = event.target.closest('.user-menu__link');
        if (menuItem) {
          closeUserMenu();
        } else if (userMenuEl.classList.contains('is-open') && !event.target.closest('.user-menu')) {
          closeUserMenu();
        }
      }
      const actionBtn = event.target.closest('button[data-action]');
      if (actionBtn) {
        const id = actionBtn.getAttribute('data-id') || '';
        const action = actionBtn.getAttribute('data-action');
        if (!id || !action) return;
        if (action === 'edit') {
          const entry = terminals.find((item) => item.terminalId === id);
          const currentLabel = entry ? entry.label || '' : '';
          const next = window.prompt('Update label for ' + id + ':', currentLabel);
          if (next === null) return;
          saveTerminalLabel(id, String(next).trim());
        } else if (action === 'delete') {
          deleteTerminal(id);
        }
      }
    });

    refreshBtn.addEventListener('click', () => loadTerminals());
    addBtn.addEventListener('click', () => createTerminal());

    loadTerminals();
  </script>
</body>
</html>`;
    res.set('Content-Type', 'text/html');
    res.send(html);
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
        const mappings = getAllMappings();
        const { printers: printerLabelMap, terminals: terminalLabelMap } = getAllLabels();
        const terminalsByIp = {};
        Object.entries(mappings || {}).forEach(([terminalId, ip]) => {
            if (!ip) return;
            const key = String(ip);
            if (!terminalsByIp[key]) terminalsByIp[key] = [];
            terminalsByIp[key].push(String(terminalId));
        });
        Object.values(terminalsByIp).forEach((arr) => arr.sort());
        const printersWithAssignments = (printers || []).map((printer) => {
            const ip = printer.ip;
            const assignedIds = terminalsByIp[ip] || [];
            const assignedTerminalDetails = assignedIds.map((terminalId) => ({
                terminalId,
                label: terminalLabelMap[terminalId]?.label || null,
            }));
            return {
                ...printer,
                label: printerLabelMap[ip]?.label || null,
                assignedTerminals: assignedIds,
                assignedTerminalDetails,
            };
        });
        if (!lastUpdated) {
            // No discovery has run yet; kick one off but don’t block
            runDiscovery(process.env.SUBNET || defaultCidrFromInterfaces()).catch(() => {});
        }
        res.json({
            cidr,
            lastUpdated,
            count: (printers || []).length,
            printers: printersWithAssignments,
            mappings,
            labels: {
                printers: printerLabelMap,
                terminals: terminalLabelMap,
            },
        });
    } catch (err) {
        logger.error('GET /printers failed', { error: err.message });
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/terminals', authorizeApi, (req, res) => {
    const terminals = collectTerminals();
    res.json({ terminals });
});

app.post('/terminals', authorizeApi, (req, res) => {
    const terminalIdRaw = typeof req.body?.terminalId === 'string' ? req.body.terminalId : '';
    const terminalId = terminalIdRaw.trim();
    if (!terminalId) {
        return res.status(400).json({ error: 'terminalId is required' });
    }
    const labelRaw = typeof req.body?.label === 'string' ? req.body.label : '';
    const label = labelRaw.trim();
    const existingLabels = getAllTerminalLabels();
    if (Object.prototype.hasOwnProperty.call(existingLabels, terminalId)) {
        return res.status(409).json({ error: 'Terminal already exists', terminalId });
    }
    setTerminalLabel(terminalId, label);
    logger.info('Terminal created', { terminalId, label });
    const terminals = collectTerminals();
    const terminal = terminals.find((entry) => entry.terminalId === terminalId) || null;
    res.json({ ok: true, terminal, terminals });
});

app.patch('/terminals/:terminalId', authorizeApi, (req, res) => {
    const terminalParam = typeof req.params?.terminalId === 'string' ? req.params.terminalId : '';
    const terminalId = terminalParam.trim();
    if (!terminalId) {
        return res.status(400).json({ error: 'terminalId is required' });
    }
    const labelRaw = typeof req.body?.label === 'string' ? req.body.label : '';
    const label = labelRaw.trim();
    setTerminalLabel(terminalId, label);
    logger.info('Terminal label saved', { terminalId, label });
    const terminals = collectTerminals();
    const terminal = terminals.find((entry) => entry.terminalId === terminalId) || null;
    res.json({ ok: true, terminal, terminals });
});

app.delete('/terminals/:terminalId', authorizeApi, (req, res) => {
    const terminalParam = typeof req.params?.terminalId === 'string' ? req.params.terminalId : '';
    const terminalId = terminalParam.trim();
    if (!terminalId) {
        return res.status(400).json({ error: 'terminalId is required' });
    }
    const before = collectTerminals();
    const exists = before.some((entry) => entry.terminalId === terminalId);
    if (!exists) {
        return res.status(404).json({ error: 'Terminal not found', terminalId });
    }
    removeTerminalLabel(terminalId);
    let removedIp = null;
    try {
        const removal = removePrinterIp(terminalId);
        removedIp = Object.prototype.hasOwnProperty.call(removal, 'removedIp') ? removal.removedIp ?? null : null;
    } catch (err) {
        logger.warn('Failed to remove printer mapping during terminal delete', { terminalId, error: err.message });
    }
    logger.info('Terminal removed', { terminalId, removedIp });
    const terminals = collectTerminals();
    res.json({ ok: true, terminalId, removedIp, terminals });
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

// POST /print/global { printerId, data } where data is base64-encoded ESC/POS bytes
app.post('/print/global', authenticateToken, async (req, res) => {
    const printerIdRaw = typeof req.body?.printerId === 'string' ? req.body.printerId : '';
    const printerId = printerIdRaw.trim();
    const data = req.body?.data;
    if (!printerId || typeof data !== 'string') {
        return res.status(400).json({ error: 'printerId and data (base64) are required' });
    }
    const printer = getGlobalPrinter(printerId);
    if (!printer || !printer.ip || net.isIP(printer.ip) === 0) {
        return res.status(404).json({ error: 'Global printer not found', printerId });
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
        logger.info('Dispatching global print request', { printerId, ip: printer.ip, bytes: payload.length });
        const result = await sendToPrinter(printer.ip, payload);
        logger.info('Global print success', { printerId, ip: printer.ip, bytesSent: result.bytesWritten });
        return res.json({ ok: true, printerId, ip: printer.ip, bytesSent: result.bytesWritten });
    } catch (err) {
        logger.error('Global print failed', { printerId, ip: printer.ip, error: err.message });
        return res.status(502).json({ ok: false, error: err.message, printerId, ip: printer.ip });
    }
});

// HTTPS server setup with self-signed certificates
function boot() {
    const credentials = {
        key: fs.readFileSync(KEY_FILE_PATH),
        cert: fs.readFileSync(CERT_FILE_PATH),
        minVersion: 'TLSv1.2',
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
const POLL_INSECURE_TLS = ['1', 'true', 'yes', 'on'].includes(String(process.env.PRINT_POLL_INSECURE_TLS).toLowerCase());
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
// Requires Authorization or X-Authorization: Bearer <token> header. Verifies with JWT_SECRET.
function authenticateToken(req, res, next) {
    try {
        const header = getAuthHeader(req);
        const token = extractBearerToken(header);
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized: missing token' });
        }
        if (!JWT_SECRET) {
            logger.error('JWT_SECRET not set; rejecting auth request');
            return res.status(401).json({ error: 'Unauthorized: server not configured' });
        }
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
