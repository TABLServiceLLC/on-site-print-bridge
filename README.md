# 🖨️ Print Bridge Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green?logo=node.js)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/express-5.x-blue?logo=express&logoColor=white)](#)
[![Tests](https://img.shields.io/badge/tests-jest-%23C21325?logo=jest&logoColor=white)](#)
[![PM2](https://img.shields.io/badge/process%20manager-pm2-2B037A?logo=pm2&logoColor=white)](https://pm2.keymetrics.io/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey?logo=linux&logoColor=white)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#)

HTTPS print bridge for ESC/POS printers. Discovers printers on the LAN and forwards print jobs directly over TCP:9100. Optionally polls a cloud endpoint for queued jobs. Runs over HTTPS with JWT-authenticated APIs.

---

## ✨ Features

- LAN discovery of printers (9100/515/631/80/443)
- Direct print to TCP:9100 using base64 payloads
- Per-terminal printer mapping persisted to `printerMap.json`
- Optional background poller for cloud-hosted jobs
- HTTPS with self-signed certs; JWT-authenticated endpoints

---

## 🚀 Quick Start

- Prerequisites
  - Node.js >= 18, npm, OpenSSL
  - Network access to printers (usually TCP:9100)
- Setup
  - Install deps: `npm install`
  - Copy env: `cp .env.example .env`
  - Edit `.env` and set at minimum:
    - `JWT_SECRET=<your-secret>` (required to authenticate API calls)
    - Optionally set `SUBNET` (CIDR) if not detected automatically
  - Generate HTTPS certs (self-signed) in repo root:
    - `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"`
- Run
  - Start (dev): `npm start` (serves at `https://localhost:8443`)
  - Recommended PM2 (auto-start on boot):
    - Install: `npm i -g pm2`
    - Start: `pm2 start server.js --name print-bridge`
    - Enable boot: `pm2 startup` (follow printed command; may need `sudo`)
    - Save list: `pm2 save`
    - Logs/Restart: `pm2 logs print-bridge` / `pm2 restart print-bridge`
- Get a test token (JWT)
  - `TOKEN=$(node -e "console.log(require('jsonwebtoken').sign({ sub: 'local-test' }, process.env.JWT_SECRET || 'replace-with-your-secret'))")`
  - Or replace `process.env.JWT_SECRET` above with your actual secret
- Verify it’s running
  - Health: `curl -k https://localhost:8443/health`
  - Discover printers: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/printers?refresh=true"`
- Map a terminal to a printer
  - `curl -k -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"terminalId":"t1","ip":"192.168.1.50"}' https://localhost:8443/assign`
- Send a test print
  - `DATA=$(node -e "process.stdout.write(Buffer.from('Hello\\n','utf8').toString('base64'))")`
  - `curl -k -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"terminalId":"t1","data":"'"$DATA"'"}' https://localhost:8443/print`
- Logs
  - Default file: `bridge.log` (configurable via `LOG_FILE`)
  - Tail: `tail -f bridge.log`

---

## 🛠️ Configuration

Set in `.env` (defaults shown where applicable):

- `PORT` — HTTPS port (default `8443`)
- `JWT_SECRET` — secret used to verify inbound JWTs (required)
- Discovery
  - `SUBNET` — CIDR to scan (defaults to inferred interface or `192.168.1.0/24`)
  - `DISCOVERY_INTERVAL_MS` — periodic re-scan interval (default `300000`)
- Polling (optional)
  - `PRINT_JOBS_URL` — cloud endpoint for pending jobs (leave unset to disable polling)
  - `STORE_ID` — store/site identifier (default `0`)
  - `PRINT_POLL_INTERVAL_MS` — poll interval in ms (default `5000`)
  - Outbound auth header preference:
    - `JWT_TOKEN` or `POLL_JWT` — bearer token used if set
    - Fallback: `API_TOKEN` or `PRINT_API_TOKEN`
  - TLS to cloud API:
    - `PRINT_POLL_CA_FILE` — path to CA bundle PEM to trust
    - `PRINT_POLL_INSECURE_TLS` — `true` to skip TLS verification (not recommended)
- Logging
  - `LOG_FILE` — path to log file (default `bridge.log`)

Certificates: server reads `key.pem` and `cert.pem` from the repo root.

---

## 🔐 Authentication

The following endpoints require `Authorization: Bearer <jwt>` verifiable with `JWT_SECRET`:

- `POST /print`
- `POST /assign`
- `GET /printers`

Note: The UI at `/ui` is unauthenticated, but the API it calls (`/printers`) requires a JWT. For local debugging, call the API with a token (see Examples) or temporarily relax auth in code.

---

## 🌐 Endpoints

- `GET /health` — Health check
- `GET /ui` — Minimal web UI for discovery and mapping
- `GET /printers` — Returns discovered printers (JWT)
- `POST /assign` — Body `{ terminalId, ip }` (JWT)
- `POST /print` — Body `{ terminalId, data }` with `data` base64 (JWT)

Examples:

- List printers (replace `<JWT>`):
  - `curl -k -H "Authorization: Bearer <JWT>" https://localhost:8443/printers`
- Assign mapping:
  - `curl -k -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"terminalId":"t1","ip":"192.168.1.50"}' https://localhost:8443/assign`
- Print job:
  - `curl -k -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"terminalId":"t1","data":"<base64-escpos>"}' https://localhost:8443/print`

---

## ⚙️ Behavior

- Discovery runs on startup and every `DISCOVERY_INTERVAL_MS`. Force refresh with `/printers?refresh=true` (JWT).
- When `PRINT_JOBS_URL` is set, the poller fetches from `PRINT_JOBS_URL?storeId=<STORE_ID>` on an interval and prints using saved mappings.
- Raw print is sent to the mapped printer on port `9100`.
- Logs append to `LOG_FILE` (default `bridge.log`).

---

## 🚢 Deployment Notes

- Works on any Node.js host (Raspberry Pi recommended for on-prem installs).
- For services, consider PM2 or systemd. PM2 quickstart:
  - `npm i -g pm2 && pm2 start server.js --name print-bridge && pm2 save && pm2 startup`

---

## 🧰 Troubleshooting

- UI loads but no printers: ensure requests include a valid JWT for `/printers`.
- Cert warnings in browser: self-signed cert. Use `-k` in curl or trust the cert.
- Cloud polling TLS: set `PRINT_POLL_CA_FILE` for private CAs; avoid `PRINT_POLL_INSECURE_TLS=true` unless necessary.

---

## 📄 License

MIT License — see [LICENSE.md](LICENSE.md)
