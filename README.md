<![CDATA[<div align="center">

# 🛡️ Antigravity SOC — AI-Powered Cyber Threat Intelligence Engine

**Real-time threat detection, MITRE ATT&CK classification, and automated remediation — powered by Google Gemini AI.**

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Gemini](https://img.shields.io/badge/Google_Gemini-AI_Agent-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-2ECC71?style=for-the-badge&logo=shield&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-FF6F00?style=for-the-badge)

---

*A production-grade Security Operations Center (SOC) dashboard that uses an autonomous AI agent to analyse system logs, classify cyber threats against the MITRE ATT&CK framework, and generate one-click firewall remediation — all running locally.*

</div>

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [Live Demo Preview](#-live-demo-preview)
- [System Architecture](#-system-architecture)
- [AI / ML Pipeline](#-ai--ml-pipeline)
- [Tech Stack](#-tech-stack)
- [Setup & Installation](#-setup--installation)
- [Running the System](#-running-the-system)
- [API Reference](#-api-reference)
- [Security Hardening](#-security-hardening)
- [Project Structure](#-project-structure)
- [How It Works — End to End](#-how-it-works--end-to-end)
- [Future Roadmap](#-future-roadmap)
- [License](#-license)

---

## ✨ Key Features

| Category | Feature |
|----------|---------|
| 🤖 **AI Agent** | Autonomous Gemini 3.5 Flash agent analyses raw syslog events and returns structured threat intelligence via constrained decoding |
| 🧠 **Threat Classification** | Real-time classification of SSH brute force, SQL injection, XSS, directory traversal, privilege escalation, and web authentication attacks |
| 🎯 **MITRE ATT&CK Mapping** | Every detected threat is mapped to its MITRE ATT&CK technique ID (T1110, T1190, T1078, T1548) with full technique names |
| 🔥 **One-Click Remediation** | Dashboard generates and executes `iptables` firewall block rules with a single button press |
| 📊 **Real-Time Dashboard** | Polished dark-mode SOC dashboard with live threat feed, agent reasoning trace, and incident artifact cards |
| 🛡️ **Security Hardened** | XSS-safe DOM rendering, CORS lockdown, rate limiting, directory traversal protection, payload size caps, atomic file writes |
| 🔄 **Graceful Degradation** | AI agent → rule-based fallback classifier pipeline; system works with or without an API key |
| 📈 **Live Statistics API** | RESTful endpoints for threat distribution, top attacker IPs with GeoIP, login success rates, and blocked IP tracking |

---

## 🖥️ Live Demo Preview

```
┌─────────────────────────────────────────────────────────────────────┐
│  ANTIGRAVITY // THREAT INTELLIGENCE ENGINE        ● Agent Active   │
├─────────────────────┬──────────────────────┬────────────────────────┤
│ // SYSTEM FEED      │ // AGENT REASONING   │ // INCIDENT ARTIFACT   │
│                     │                      │                        │
│ [CRITICAL]          │ ● Step 01: Trace     │ Attack: SQL Injection  │
│ 195.133.40.12       │   Isolated           │ Source: 195.133.40.12  │
│ SQL Injection on    │   Evaluating input   │ MITRE: T1190           │
│ backend API         │   against signature  │                        │
│                     │   indices...         │ $ iptables -A INPUT    │
│ [INFO] 127.0.0.1    │                      │   -s 195.133.40.12     │
│ Health check 200 OK │ ● Step 02: Strategy  │   -j DROP              │
│                     │   Staged             │                        │
│                     │   Writing recovery   │ [APPROVE CONTAINMENT]  │
│                     │   blocks to JSON...  │                        │
└─────────────────────┴──────────────────────┴────────────────────────┘
```

---

## 🏗️ System Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │            PRODUCER LAYER                    │
                    │                                              │
   mock_auth.log ──►│  agent_platform.py                          │
   (syslog events)  │  ┌─────────────┐    ┌───────────────────┐   │
                    │  │ Log Watcher  │───►│ Gemini 3.5 Flash  │   │
                    │  │ (async tail) │    │ AI Agent          │   │
                    │  └─────────────┘    │ (structured out)  │   │
                    │        │            └────────┬──────────┘   │
                    │        │  fallback           │              │
                    │        ▼                     │              │
                    │  ┌─────────────┐             │              │
                    │  │ Rule-Based  │             │              │
                    │  │ Classifier  │             │              │
                    │  └──────┬──────┘             │              │
                    │         └──────────┬─────────┘              │
                    │                    ▼                        │
                    │         mitigation_report.json              │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │            CONSUMER LAYER                    │
                    │                                              │
                    │  app.py  (HTTP Server)                       │
                    │  ┌────────────────┐  ┌───────────────────┐   │
                    │  │ Log Parser     │  │ Rate Limiter      │   │
                    │  │ (7 regex       │  │ IP Validator      │   │
                    │  │  patterns)     │  │ Path Sanitiser    │   │
                    │  ├────────────────┤  ├───────────────────┤   │
                    │  │ GET  /         │  │ POST /api/block   │   │
                    │  │ GET  /api/logs │  │ (block / unblock) │   │
                    │  │ GET  /api/stats│  │                   │   │
                    │  └────────────────┘  └───────────────────┘   │
                    │         │                                    │
                    │         ▼                                    │
                    │  ┌─────────────────────────────────────┐     │
                    │  │ Threat Simulator (background thread)│     │
                    │  │ Generates realistic attack traffic  │     │
                    │  │ every 3-6 seconds                   │     │
                    │  └─────────────────────────────────────┘     │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │            PRESENTATION LAYER                │
                    │                                              │
                    │  index.html (Tailwind CSS Dashboard)         │
                    │  • Polls /mitigation_report.json every 3s    │
                    │  • XSS-safe DOM rendering (no innerHTML)     │
                    │  • Pauses polling when tab is hidden         │
                    │  • One-click firewall block via POST         │
                    └──────────────────────────────────────────────┘
```

---

## 🤖 AI / ML Pipeline

This project implements a **two-tier AI inference pipeline** for real-time cyber threat analysis:

### Tier 1 — Large Language Model (Gemini 3.5 Flash)

```python
# An autonomous AI agent receives raw syslog text and returns structured threat intel
config = LocalAgentConfig(
    model="gemini-3.5-flash",
    response_schema=MitigationReport,   # constrained decoding → valid JSON
)
security_analyst = Agent(config)

# For each suspicious log event:
response = await security_analyst.chat(
    "Analyze this log event: 'Failed password for root from 195.133.40.12 port 22 ssh2'. "
    "Map to MITRE ATT&CK. Generate mitigation command."
)
data = await response.structured_output()
# → {"status": "Active Threat", "ip": "195.133.40.12",
#    "vector": "SSH Brute Force", "mitre_id": "T1110 - Brute Force",
#    "patch_command": "iptables -A INPUT -s 195.133.40.12 -j DROP"}
```

**What the LLM does:**
- **Natural Language Understanding** — Parses unstructured syslog text with no fixed schema
- **Multi-label Threat Classification** — Identifies attack type from dozens of possible vectors
- **Knowledge Retrieval** — Maps attacks to the MITRE ATT&CK taxonomy (learned during pretraining)
- **Constrained Decoding** — `response_schema` forces the transformer to output valid JSON matching the Pydantic model

### Tier 2 — Rule-Based Fallback Classifier

When the API is unavailable, a **keyword-based classifier** with a curated MITRE knowledge base provides deterministic results:

```python
MITRE_ATTACK_DB = {
    "sshd_fail":            {"vector": "SSH Brute Force",          "mitre_id": "T1110"},
    "web_sql":              {"vector": "SQL Injection",            "mitre_id": "T1190"},
    "web_traversal":        {"vector": "Directory Traversal",      "mitre_id": "T1190"},
    "sudo_abuse":           {"vector": "Privilege Escalation",     "mitre_id": "T1548.003"},
    "sshd_accept_external": {"vector": "Suspicious External Login","mitre_id": "T1078"},
}
```

### ML Techniques Used

| Technique | Where | Purpose |
|-----------|-------|---------|
| **LLM Inference** | `agent_platform.py` | Threat classification via Gemini transformer |
| **Constrained Decoding** | `response_schema=MitigationReport` | Forces structured JSON output from the model |
| **Feature Extraction** | `constants.py` (7 regex patterns) | Extract IP, user, port, attack type from raw text |
| **Pattern Classification** | `local_fallback_parse()` | Keyword-based classifier with lookup table |
| **Deterministic GeoIP** | `get_geoip_details()` | Last-octet modulo mapping for reproducible demos |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **AI Engine** | Google Antigravity SDK + Gemini 3.5 Flash | Autonomous threat analysis agent |
| **Backend** | Python 3.9+ / `http.server` (stdlib) | Zero-dependency HTTP server |
| **Data Models** | Pydantic v2 | Type-safe schemas with validation |
| **Frontend** | Tailwind CSS + Vanilla JS | Responsive dark-mode SOC dashboard |
| **Config** | python-dotenv | Secure environment variable management |
| **Concurrency** | `asyncio` (agent) + `threading` (server) | Non-blocking log tailing + background simulation |

---

## 🚀 Setup & Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- A Gemini API key *(optional — system works without it in fallback mode)*

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cyber-threat-dashboard.git
cd cyber-threat-dashboard

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install google-antigravity python-dotenv pydantic

# 4. Configure environment (optional — enables AI agent)
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### Verify Installation

```bash
python3 -c "import google.antigravity; from pydantic import BaseModel; print('✅ All dependencies OK')"
```

---

## ▶️ Running the System

### Option A — Dashboard Only (Quick Start)

```bash
python3 app.py
```

Open **http://localhost:8080** in your browser. The built-in threat simulator will generate realistic attack traffic automatically.

### Option B — Dashboard + AI Agent (Full Pipeline)

```bash
# Terminal 1: Start the dashboard server
python3 app.py

# Terminal 2: Start the AI agent watcher
python3 agent_platform.py
```

The AI agent will tail `mock_auth.log`, analyse each threat event, and update `mitigation_report.json` in real-time.

---

## 📡 API Reference

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `GET` | `/` | Serves the SOC dashboard UI | `text/html` |
| `GET` | `/api/logs` | Returns all parsed log events (newest first) | `[{timestamp, ip, status, threat_level, ...}]` |
| `GET` | `/api/stats` | Aggregated threat statistics | `{total_alerts, failed_logins, threat_level_distribution, top_ips, ...}` |
| `GET` | `/mitigation_report.json` | Latest AI-generated mitigation report | `{status, ip, vector, mitre_id, patch_command}` |
| `POST` | `/api/block` | Block or unblock an IP address | `{status: "success", action, ip}` |

### Example — Block an Attacker IP

```bash
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "195.133.40.12", "action": "block"}'

# Response: {"status": "success", "action": "block", "ip": "195.133.40.12"}
```

---

## 🔒 Security Hardening

This project implements **defence-in-depth** with multiple security layers:

| Vulnerability | Mitigation | File |
|--------------|------------|------|
| **XSS (Cross-Site Scripting)** | All dynamic content uses `textContent` / `createElement` — zero `innerHTML` | `index.html` |
| **Directory Traversal** | Paths resolved via `os.path.realpath()` and verified against `BASE_DIR` | `app.py` |
| **CORS Abuse** | Origin locked to `http://localhost:8080` (not wildcard `*`) | `app.py` |
| **Rate Limiting** | Sliding-window rate limiter: 120 requests / 60s per client IP | `app.py` |
| **Header Spoofing** | Rate limiter uses `client_address[0]` directly — never trusts `X-Forwarded-For` | `app.py` |
| **Memory Exhaustion** | POST body capped at 4096 bytes; oversized payloads rejected with `413` | `app.py` |
| **IP Validation** | All IPs validated through `ipaddress.ip_address()` before processing | `app.py` |
| **API Key Leakage** | `.env` git-ignored; `.env.example` provided with placeholders | `.gitignore` |
| **Atomic Writes** | Mitigation reports written to `.tmp` then `os.replace()` for crash safety | `agent_platform.py` |
| **Loopback Protection** | Blocking `127.0.0.1` and `192.168.1.100` is explicitly prohibited | `app.py` |
| **Graceful Shutdown** | SIGTERM handler for clean server termination | `app.py` |
| **Tab Visibility** | Polling pauses when browser tab is hidden to reduce resource waste | `index.html` |

---

## 📂 Project Structure

```
cyber-threat-dashboard/
│
├── app.py                  # HTTP server: routing, log parsing, threat simulator
├── agent_platform.py       # AI agent: Gemini-powered log watcher & threat classifier
├── constants.py            # Centralised config: paths, regex, MITRE DB, GeoIP, tunables
├── models.py               # Pydantic v2 schemas: LogEntry, MitigationReport
├── index.html              # Real-time SOC dashboard (Tailwind CSS)
│
├── .env.example            # Template for environment variables
├── .env                    # Your API key (git-ignored)
├── .gitignore              # Excludes secrets, logs, caches, build artifacts
├── .flake8                 # Linter configuration
├── mypy.ini                # Type checker configuration
├── README.md               # This document
│
├── mock_auth.log           # Runtime: simulated syslog events (git-ignored)
├── mitigation_report.json  # Runtime: latest AI threat assessment (git-ignored)
│
└── .agents/
    └── rules/
        └── security-guardrails.md   # Agent execution constraints & policies
```

---

## 🔄 How It Works — End to End

```
1. SIMULATE                     2. DETECT                      3. CLASSIFY
┌──────────────┐               ┌──────────────┐               ┌──────────────┐
│ Threat       │  writes log   │ Log Watcher  │  trigger       │ Gemini Agent │
│ Simulator    │──────────────►│ (async tail) │──keyword──────►│ (LLM)        │
│ (3-6s loop)  │               │              │  detected      │              │
└──────────────┘               └──────────────┘               └──────┬───────┘
                                                                     │
                                      ┌──────────────────────────────┘
                                      │ structured output
                                      ▼
4. REPORT                      5. SERVE                       6. REMEDIATE
┌──────────────┐               ┌──────────────┐               ┌──────────────┐
│ Atomic JSON  │  read by      │ HTTP Server  │  renders       │ Dashboard    │
│ File Write   │──────────────►│ /api/stats   │──────────────►│ UI           │
│              │               │ /api/logs    │               │ [BLOCK IP]   │
└──────────────┘               └──────────────┘               └──────────────┘
```

**Step-by-step:**

1. **Threat Simulation** — A background thread in `app.py` generates realistic syslog events (SSH brute force, SQL injection, XSS, privilege escalation) every 3–6 seconds, writing them to `mock_auth.log`.

2. **Log Detection** — `agent_platform.py` continuously tails the log file using async I/O. When a trigger keyword is detected (`Failed password`, `WARNING:`, `FAIL LOGIN`, `Accepted password`), the line is forwarded for analysis.

3. **AI Classification** — The Gemini 3.5 Flash agent receives the raw log line, identifies the attack vector, maps it to a MITRE ATT&CK technique, and generates a remediation command. If the AI is unavailable, a rule-based classifier handles it.

4. **Report Persistence** — The structured assessment is written atomically to `mitigation_report.json` (write to `.tmp`, then `os.replace()`).

5. **API Serving** — `app.py` serves the dashboard UI and RESTful endpoints. The log parser uses 7 compiled regex patterns to extract structured fields from raw syslog lines. Statistics are aggregated on-the-fly.

6. **Remediation** — The dashboard displays the threat assessment and offers a one-click **"Approve Active Containment Patch"** button. Clicking it sends a `POST /api/block` request, which adds the attacker IP to the blocked set and logs a firewall rule event.

---

## 🗺️ Future Roadmap

- [ ] **WebSocket / SSE** — Replace polling with real-time push updates
- [ ] **Persistent Storage** — Store threat history in SQLite or Firestore
- [ ] **Multi-Agent Architecture** — Specialised agents for network, endpoint, and application threats
- [ ] **Real Log Integration** — Point to live `/var/log/auth.log` for production deployment
- [ ] **Threat Heatmap** — Geographic visualisation of attacker origins using GeoIP coordinates
- [ ] **SIEM Integration** — Export threat events to Splunk, Elastic, or Google Chronicle
- [ ] **Authentication** — Add login flow for multi-user SOC environments
- [ ] **CI/CD Pipeline** — Automated testing, linting, and deployment

---

## 📄 License

MIT License — feel free to fork, modify, and deploy.

---

<div align="center">

**Built with 🛡️ by Sahil**

*Autonomous AI × Cybersecurity × Real-Time Intelligence*

</div>
]]>
