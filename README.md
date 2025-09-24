# Print Bridge Agent

HTTPS Express bridge that discovers ESC/POS printers on the LAN and forwards print jobs directly over TCP:9100. Includes optional polling of a cloud endpoint for queued jobs.

## Setup

1. Install dependencies

   - `npm install`

2. Configure environment

   - Copy `.env.example` to `.env` and set values:
     - `JWT_SECRET` — secret to verify inbound JWTs (required)
- `JWT_TOKEN` — JWT to send when polling the cloud API (optional but recommended)
- `PRINT_JOBS_URL`, `STORE_ID`, `PRINT_POLL_INTERVAL_MS` — polling config
- `SUBNET`, `DISCOVERY_INTERVAL_MS` — discovery config
- TLS for polling:
  - `PRINT_POLL_INSECURE_TLS` — set to `true` to skip TLS verification for cloud polling (not recommended)
  - `PRINT_POLL_CA_FILE` — path to CA bundle PEM to trust for cloud polling

3. Start the bridge

   - `npm start`
   - Accept the self-signed certificate in your browser.

## Authentication

- The following endpoints require `Authorization: Bearer <jwt>` with a token verifiable using `JWT_SECRET`:
  - `POST /print`
  - `POST /assign`
  - `GET /printers`

- The UI at `/ui` does not require authentication.

- When polling the cloud for jobs, the bridge sends an `Authorization: Bearer <JWT_TOKEN>` header if `JWT_TOKEN` is set (falls back to `API_TOKEN`/`PRINT_API_TOKEN`).
  - If your cloud uses a private CA, either run Node with `--use-system-ca` or set `PRINT_POLL_CA_FILE` to your CA bundle; as a last resort set `PRINT_POLL_INSECURE_TLS=true`.

## Endpoints

- `GET /ui` — Minimal web UI for discovery and assigning mappings
- `GET /printers` — Returns discovered printers (requires JWT)
- `POST /assign` — Assign `{ terminalId, ip }` (requires JWT)
- `POST /print` — Print `{ terminalId, data: base64 }` (requires JWT)
- `GET /health` — Health check

## Notes

- Self-signed TLS certs `cert.pem` and `key.pem` are used for HTTPS on port 8443.
- Discovery runs on startup and every 5 minutes. Use `/printers?refresh=true` to force a scan.
- Logs are written to `bridge.log` (override with `LOG_FILE`).
# 🖨️ Print Bridge Agent for ESC/POS Printers (Raspberry Pi)

This project is a secure print bridge that runs on a Raspberry Pi, auto-discovers ESC/POS printers on the LAN, and listens for secure print jobs from your cloud backend via HTTPS using JWT authentication.

---

## 🚀 Features

- Auto-discovers printers over the LAN (even with random IPs)
- Accepts raw ESC/POS print jobs via HTTPS
- Associates terminals with specific printers
- Polls cloud backend for jobs, or accepts direct POSTs
- Runs headless on Raspberry Pi (auto-starts on boot)
- Secured with JWT authentication
- Self-signed HTTPS support

---

## 🧰 Requirements

- Raspberry Pi (Pi 3, 4, or Zero 2 W recommended)
- Raspbian OS (Lite or Full)
- Node.js (LTS)
- Internet access for install
- Local network access to printers

---

## 📦 Installation

### 1. Flash Raspberry Pi OS

- Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/) to install Raspberry Pi OS Lite.
- Enable SSH during setup.

### 2. SSH into the Pi

```bash
ssh pi@raspberrypi.local
# Or use IP address: ssh pi@<your-pi-ip>
```

### 3. Update System & Install Node.js

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential curl git

# Install Node LTS using 'n'
curl -fsSL https://raw.githubusercontent.com/tj/n/master/bin/n | bash -s lts
export PATH=$PATH:/usr/local/bin
```

---

## 🔧 Setup the Print Bridge

### 4. Clone or Transfer the Project

```bash
git clone https://github.com/YOUR_USERNAME/print-bridge-agent.git
cd print-bridge-agent
```

Or use `scp` from your dev machine:

```bash
scp -r ./print-bridge-agent pi@raspberrypi.local:~/print-bridge-agent
cd ~/print-bridge-agent
```

---

### 5. Install Dependencies

```bash
npm install
```

---

### 6. Create `.env` File

```bash
nano .env
```

Paste:

```env
JWT_SECRET=supersecuresecret123
```

---

### 7. Generate HTTPS Certificates

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
```

Use `localhost` or `raspberrypi.local` as the Common Name (CN).

---

### 8. Start the Server

#### Temporary:

```bash
node server.js
```

#### Persistent (Background):

```bash
nohup node server.js > bridge.log 2>&1 &
```

#### Or use PM2:

```bash
sudo npm install -g pm2
pm2 start server.js --name print-bridge
pm2 save
pm2 startup
```

---

## 🌐 Access & Test

- Access printer list:  
  `https://raspberrypi.local:8443/printers`

- Send print job via POST:  
  `https://raspberrypi.local:8443/print`  
  With `Authorization: Bearer <your-jwt>` and JSON payload:

```json
{
  "terminalId": "terminal1",
  "data": "base64-encoded-escpos"
}
```

---

## 🔁 Auto Discovery

- Printer discovery runs at startup and every 5 minutes.
- Identifies printers on port `9100`, `631`, or `80`.

---

## 🛠 Helpful Commands

### Check Node/NPM:

```bash
node -v
npm -v
```

### Check Bridge Logs:

```bash
tail -f bridge.log
```

### Restart PM2 App:

```bash
pm2 restart print-bridge
```

---

## 🔐 Security Notes

- JWT authentication is required for all API calls (`/print`, `/assign`, `/printers`).
- Secret is stored in `.env`.
- Use static JWTs or issue them from your backend per site.

---

## 🧠 Tips

- Use DHCP reservations for the Pi so its IP doesn't change.
- Label each terminal (e.g., terminal1, terminal2) and store the mappings.
- Backup your `printerMap.json` file periodically.

---

## ✅ To Do

- [ ] Add a web UI at `/ui` to select terminal printer mapping
- [ ] Integrate WebSocket or MQTT for push jobs
- [ ] Build a lightweight dashboard for job monitoring

---

## 📄 License

MIT License
