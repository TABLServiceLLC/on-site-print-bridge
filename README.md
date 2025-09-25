# Print Bridge Agent

HTTPS print bridge for ESC/POS printers. Discovers printers on the LAN and forwards print jobs directly over TCP:9100. Optionally polls a cloud endpoint for queued jobs. Runs over HTTPS with JWT-authenticated APIs.

---

## Features

- LAN discovery of printers (9100/515/631/80/443)
- Direct print to TCP:9100 using base64 payloads
- Per-terminal printer mapping persisted to `printerMap.json`
- Optional background poller for cloud-hosted jobs
- HTTPS with self-signed certs; JWT-authenticated endpoints

---

## Quick Start

- Install dependencies: `npm install`
- Copy config: `cp .env.example .env` and set values (see Configuration)
- Generate HTTPS certs in repo root:
  - `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365`
- Start: `npm start` (defaults to `https://localhost:8443`)

---

## Configuration

Set in `.env` (defaults shown where applicable):

- `PORT` — HTTPS port (default `8443`)
- `JWT_SECRET` — secret used to verify inbound JWTs (required)
- Discovery
  - `SUBNET` — CIDR to scan (defaults to inferred interface or `192.168.1.0/24`)
  - `DISCOVERY_INTERVAL_MS` — periodic re-scan interval (default `300000`)
- Polling (optional)
  - `PRINT_JOBS_URL` — cloud endpoint for pending jobs (default `https://api.myapp.com/print-jobs`)
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

## Authentication

The following endpoints require `Authorization: Bearer <jwt>` verifiable with `JWT_SECRET`:

- `POST /print`
- `POST /assign`
- `GET /printers`

Note: The UI at `/ui` is unauthenticated, but the API it calls (`/printers`) requires a JWT. For local debugging, call the API with a token (see Examples) or temporarily relax auth in code.

---

## Endpoints

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

## Behavior

- Discovery runs on startup and every `DISCOVERY_INTERVAL_MS`. Force refresh with `/printers?refresh=true` (JWT).
- Poller fetches from `PRINT_JOBS_URL?storeId=<STORE_ID>` on an interval and prints using saved mappings.
- Raw print is sent to the mapped printer on port `9100`.
- Logs append to `LOG_FILE` (default `bridge.log`).

---

## Deployment Notes

- Works on any Node.js host (Raspberry Pi recommended for on-prem installs).
- For services, consider PM2 or systemd. PM2 quickstart:
  - `npm i -g pm2 && pm2 start server.js --name print-bridge && pm2 save && pm2 startup`

---

## Troubleshooting

- UI loads but no printers: ensure requests include a valid JWT for `/printers`.
- Cert warnings in browser: self-signed cert. Use `-k` in curl or trust the cert.
- Cloud polling TLS: set `PRINT_POLL_CA_FILE` for private CAs; avoid `PRINT_POLL_INSECURE_TLS=true` unless necessary.

---

## 📄 License

MIT License
