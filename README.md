# 🔍 Network Scanner & Topology Mapper

**Dockerized web application** that scans your local network, discovers live hosts, and generates an interactive HTML topology map — all through a browser-based GUI.

![Python](https://img.shields.io/badge/python-3.11+-blue)
![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Web GUI** | Select interfaces and subnets from your browser — no CLI needed |
| **ARP Scanning** | Fast Layer-2 host discovery via `scapy` |
| **ICMP Fallback** | Automatic ping-sweep fallback when ARP fails |
| **Port Scanning** | TCP connect scan on 20 common ports (customisable) |
| **Hostname Resolution** | Reverse DNS lookup for every live host |
| **MAC Vendor Lookup** | Bundled OUI database — no API calls needed |
| **Gateway Detection** | Auto-identifies the default gateway |
| **Device Classification** | Heuristic device-type inference (server, VM, IoT, mobile…) |
| **Interactive Topology Map** | `pyvis` / `vis.js` force-directed graph, self-contained in a single HTML file |
| **Docker Ready** | One-command deploy with `docker compose up` |

---

## 🚀 Quick Start (Docker)

```bash
# 1. Clone the repo
git clone https://github.com/your-org/network-scanner.git
cd network-scanner

# 2. Start the container
docker compose up -d

# 3. Open the web GUI
open http://localhost:5000
```

> **Note:** The container uses `network_mode: host` and requires `NET_ADMIN` + `NET_RAW` capabilities for raw-socket scanning. This is set automatically in `docker-compose.yml`.

---

## 🖥️ Running Without Docker

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the web server
python app.py

# 3. Open http://localhost:5000
```

### CLI Mode (Original)

```bash
python scan.py
```

---

## 📸 Screenshot

```
┌─────────────────────────────────────────────────────────┐
│  🔍 Network Scanner & Topology Mapper                  │
│  ─────────────────────────────────────────────────────  │
│  ⚙️ Scan Configuration                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Network Interface: [eth0 — 192.168.1.42/24    ▾ ] │  │
│  │ Subnet:            [192.168.1.0/24              ] │  │
│  │ Custom Ports:      [80,443,8080                 ] │  │
│  │                                                    │  │
│  │ [🚀 Start Scan]  [🔄 Refresh Interfaces]           │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  📊 Scan Results                                        │
│  Hosts: 12  |  Gateway: 192.168.1.1                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │ IP              Hostname   MAC             Type   │  │
│  │ 192.168.1.1     router     aa:bb:cc:...    Router │  │
│  │ 192.168.1.10    desktop    11:22:33:...    WS     │  │
│  │ ...                                               │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  🗺️ Topology Map                                       │
│  ┌───────────────────────────────────────────────────┐  │
│  │          (interactive vis.js graph)                │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
network-scanner/
├── app.py                 # Flask web server (REST API + GUI)
├── scan.py                # Core scanning engine
├── requirements.txt       # Python dependencies
├── Dockerfile             # Docker image definition
├── docker-compose.yml     # Docker Compose config
├── .dockerignore          # Docker build exclusions
├── templates/
│   └── index.html         # Web GUI (single-page app)
├── static/                # Static assets (CSS, JS — if needed)
└── README.md              # This file
```

---

## 🔧 Configuration

| Port | Description |
|------|-------------|
| `5000` | Flask web server (GUI + API) |

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `PYTHONUNBUFFERED` | `1` | Ensures real-time log output |

Customise the default ports list by editing the `COMMON_PORTS` array in `scan.py`, or enter comma-separated ports in the web GUI.

---

## 🛠️ API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web GUI |
| `GET` | `/api/interfaces` | List detected network interfaces |
| `POST` | `/api/scan` | Start a scan job → returns `job_id` |
| `GET` | `/api/scan/<job_id>` | Poll scan status and results |
| `GET` | `/map/<job_id>` | Serve the generated topology HTML |

---

## 📦 Dependencies

- **scapy** ≥ 2.5 — ARP / ICMP packet crafting
- **pyvis** ≥ 0.3 — Interactive network graph (vis.js)
- **flask** ≥ 3.0 — Web server and REST API

---

## ⚠️ Requirements & Limitations

- **Root / Administrator** privileges are required for raw ARP/ICMP sockets.
- Docker needs `--cap-add=NET_ADMIN --cap-add=NET_RAW` (set in compose).
- The container uses `network_mode: host` for accurate interface detection.
- Only **IPv4** networks are supported.
- Default subnet scan is `/24` (254 hosts) — larger subnets will take longer.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

Made with ❤️ by AgnesCode