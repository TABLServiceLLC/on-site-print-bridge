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
  - Generate HTTPS certs (self-signed CA + signed server cert) in the repo root:
    - Create a certificate authority once (outputs `ca.key`, `ca.crt`, `ca.srl`):
      ```bash
      openssl genrsa -out ca.key 4096
      openssl req -x509 -new -key ca.key -sha256 -days 3650 \
        -out ca.crt -subj "/CN=TABL Print Bridge CA"
      openssl rand -hex 16 > ca.srl
      ```
    - Issue a server certificate signed by that CA (outputs `server.key`, `server.csr`, `server.crt`):
      ```bash
      openssl genrsa -out server.key 4096
      openssl req -new -key server.key -out server.csr \
        -subj "/CN=raspberrypi.local"
      ```
    - Create `server-ext.cnf` (kept alongside the CSR) so you can reuse the TLS extensions:
      ```bash
      cat > server-ext.cnf <<'EOF'
      [ server_ext ]
      basicConstraints=CA:FALSE
      keyUsage=digitalSignature,keyEncipherment
      extendedKeyUsage=serverAuth
      subjectAltName=DNS:raspberrypi.local
      EOF
      ```
      Update `subjectAltName` with every hostname/IP clients use (comma-separate multiple entries).
    - Sign the CSR with that CA, referencing the extensions file:
      ```bash
      openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl \
        -out server.crt -days 825 -sha256 -extfile server-ext.cnf -extensions server_ext
      ```
    - Replace `raspberrypi.local` with the hostname clients use; keep the subject/alt name list in sync.
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
- Discover printers: `curl -k "https://localhost:8443/printers?refresh=true"`
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
  - `SUBNET` — CIDR to scan (defaults to host interface constrained to `/24`, e.g. `192.168.5.x` → `192.168.5.0/24`; fallback `192.168.1.0/24`)
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

Certificates: place `server.key` + `server.crt` (signed by your CA) and `ca.crt` in the repo root; `/cert` serves the CA for clients to trust.

---

## 🔐 Authentication

The following endpoints require a JWT verifiable with `JWT_SECRET`. Supply it using either the standard `Authorization: Bearer <jwt>` header or the custom `X-Authorization: Bearer <jwt>` header:

- `POST /print`
- `POST /print/global`
- `POST /assign`
- `GET /api/printers`
- `POST /printers`
- `PATCH /printers/:ip`
- `DELETE /printers/:ip`
- `GET /api/global-printers`
- `POST /global-printers`
- `PATCH /global-printers/:printerId`
- `DELETE /global-printers/:printerId`
- `GET /api/terminals`
- `POST /terminals`
- `PATCH /terminals/:terminalId`
- `DELETE /terminals/:terminalId`

Note: `/ui` and `/printers` are unauthenticated so the UI can load discovery results without extra configuration.

---

## 🌐 Endpoints

- `GET /health` — Health check
- `GET /ui` — Minimal web UI for discovery and mapping
- `GET /ui/printers` — UI directory focused on printer labels and usage
- `GET /ui/terminals` — UI to manage terminal IDs and labels
- `GET /printers` — Returns discovered printers
- `POST /assign` — Body `{ terminalId, ip }` (JWT)
- `POST /print` — Body `{ terminalId, data }` with `data` base64 (JWT)
- `POST /print/global` — Body `{ printerId, data }` for global printers (JWT)
- `GET /api/printers` — JSON list of printers with label + assignment data (JWT or UI session)
- `POST /printers` — Body `{ ip, label }` to create/label printer (JWT or UI session)
- `PATCH /printers/:ip` — Body `{ label }` to edit printer label (JWT or UI session)
- `DELETE /printers/:ip` — Remove printer label and clear assignments (JWT or UI session)
- `GET /api/global-printers` — JSON list of global printers (JWT or UI session)
- `POST /global-printers` — Body `{ printerId, ip, label }` to create/update global printers (JWT or UI session)
- `PATCH /global-printers/:printerId` — Update global printer ip/label (JWT or UI session)
- `DELETE /global-printers/:printerId` — Remove global printer entry (JWT or UI session)
- `GET /api/terminals` — JSON list of terminals (JWT or UI session)
- `POST /terminals` — Body `{ terminalId, label }` to create/update (JWT or UI session)
- `PATCH /terminals/:terminalId` — Body `{ label }` to edit terminal label (JWT or UI session)
- `DELETE /terminals/:terminalId` — Remove terminal + mapping (JWT or UI session)

Examples:

- List printers:
  - `curl -k https://localhost:8443/printers`
- Manage printers:
  - `curl -k -H "X-Authorization: Bearer <JWT>" https://localhost:8443/api/printers`
  - `curl -k -H "X-Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"ip":"192.168.1.60","label":"Kitchen"}' https://localhost:8443/printers`
- Manage global printers:
  - `curl -k -H "X-Authorization: Bearer <JWT>" https://localhost:8443/api/global-printers`
  - `curl -k -H "X-Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"printerId":"kitchen","ip":"192.168.1.210","label":"Kitchen"}' https://localhost:8443/global-printers`
- List terminals:
  - `curl -k -H "X-Authorization: Bearer <JWT>" https://localhost:8443/api/terminals`
- Assign mapping:
  - `curl -k -H "X-Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"terminalId":"t1","ip":"192.168.1.50"}' https://localhost:8443/assign`
- Print job:
  - `curl -k -H "X-Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"terminalId":"t1","data":"<base64-escpos>"}' https://localhost:8443/print`
- Global print job:
  - `curl -k -H "X-Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"printerId":"kitchen","data":"<base64-escpos>"}' https://localhost:8443/print/global`
- Create terminal:
  - `curl -k -H "X-Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"terminalId":"t1","label":"Front Counter"}' https://localhost:8443/terminals`

---

## ⚙️ Behavior

- Discovery runs on startup and every `DISCOVERY_INTERVAL_MS`. Force refresh with `/printers?refresh=true`.
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

- UI loads but no printers: wait for discovery to finish or click Refresh; inspect `bridge.log` for recent scan results.
- Cert warnings in browser: self-signed CA. Use `-k` in curl or import `ca.crt` into the client trust store.
- Cloud polling TLS: set `PRINT_POLL_CA_FILE` for private CAs; avoid `PRINT_POLL_INSECURE_TLS=true` unless necessary.

---

## 📄 License

MIT License — see [LICENSE.md](LICENSE.md)
