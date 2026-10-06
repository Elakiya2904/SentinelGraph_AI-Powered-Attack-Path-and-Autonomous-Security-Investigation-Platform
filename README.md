# SentinelGraph: AI-Powered Attack-Path and Autonomous Security Investigation Platform 🛡️

**Explainable Attack-Path Intelligence & Autonomous Threat Response**

SentinelGraph is an end-to-end security operations platform that bridges the gap between raw intrusion telemetry and graph-theoretic risk analysis. It models enterprise cloud networks as a live directed property graph (via NetworkX), ingests real-time security alerts from edge detectors, executes deterministic autonomous investigations, and simulates remediation impact before changes touch production.

---

## 🌟 Key Capabilities & The 4 SOC Screens

The web operations console runs at **`http://localhost:3000`** in a clean, high-contrast **Enterprise Security Operations theme** (Safety Orange / Warm Linen) featuring four synchronized screens:

### 01. Attack Graph (`/`)
* **Real-Time Graph Visualization:** Renders network topology with Cytoscape.js, classifying nodes as External Ingress (diamonds), Internal Assets/Roles/Services (circles/hexagons), and Crown Jewels (stars).
* **Compromised Attack Route Highlighting:** When an intrusion occurs, the compromised node (`vpn-bastion`) and the entire downstream attack chain to the database (`prod-db`) are illuminated in **bold crimson red (5.5px)** with directional target arrows, while non-attack assets are dimmed for instant visual clarity.
* **Live Route Ribbon:** Displays an active breadcrumb stepper:
  `internet ➔ edge-gateway ➔ 🚨 vpn-bastion (Breached) ➔ web-portal ➔ admin-role ➔ app-server ➔ ⭐ prod-db (Target)`

### 02. Top Risks (`/risks`)
* **Choke Point Prioritization:** Identifies structural network bottlenecks where the highest percentage of attack paths converge.
* **Matching Broken Paths Display:** Under each choke point (e.g., `VPN Bastion` and `Edge Gateway`), explicitly lists the exact broken attack routes that correspond to the Attack Graph, demonstrating how single-point remediations break multiple lateral movement chains.

### 03. Autonomous Investigation (`/investigation`)
* **"WHAT HAPPENED" Executive SOC Briefing:** 4 high-impact briefing cards:
  - 👤 **WHO:** Threat Actor from external IP `172.18.0.5`
  - 🎯 **WHAT:** SSH Brute Force (3 Failed Credentials ➔ 1 Valid Session Opened)
  - 📍 **WHERE:** Perimeter Host `vpn-bastion` (`victim:2222` · Vulnerable to `CVE-2024-3400`)
  - 🛡️ **IMPACT:** 11 Lateral Attack Paths Exposed Toward `prod-db`
* **Zero Hallucination ReAct Engine:** Deterministic reasoning agent cross-correlates authentication logs, graph reachability, and CVE fixtures into an **89% Confidence Confirmed Attack Verdict**.
* **Human-in-the-Loop Gated Containment:** Operators review the evidence findings and approve the host isolation rule with a single click.

### 04. What-If Workbench (`/what-if`)
* **Crystal-Clear Remediation Answers:** Answers the central question without confusing jargon:
  - *"What happens if we patch CVE-2024-3400 on VPN Bastion right now?"*
  - 🛑 **Active Breach Status:** **100% NEUTRALIZED** (Lateral access to database completely blocked)
  - 📉 **Attack Paths Eliminated:** **−11 Paths (−50% drop: 22 ➔ 11 Paths)**
  - 🛡️ **Enclave Risk Drop:** **−43 Points (Risk drops from 96 ➔ 53/100)**
  - 🏆 **Crown Jewels Secured:** Production Database (`prod-db`) & Enterprise Vault (`secrets-vault`)
* **Side-by-Side Impact Comparison:** Previews exact eliminated paths (matching the live graph route) and allows the operator to approve and commit the mitigation directly into the live enclave baseline.

---

## 🚀 Quick Start (Docker-First)

### Prerequisites
* Docker Desktop active and running.

### 1. Launch the Lab Stack
```bash
docker compose up -d
```
This automatically boots 4 containers on an isolated Docker network:
* `platform`: FastAPI backend engine listening on port `8000`.
* `frontend`: Nginx serving the production Vite React console on port `3000`.
* `victim`: Isolated service exposing SSH (`:2222`) and web (`:8080`) surfaces with shared log volume.
* `detector`: Continuous log-tailing agent that captures anomalies and posts alerts to `platform:8000/alerts`.

Open your browser to: **[http://localhost:3000](http://localhost:3000)**

---

---

## 🎬 Live Presentation Walkthrough & Terminal Screenshots

Demonstrating the live incident flow side-by-side (Terminal on left, Browser on right):

```
┌────────────────────────────────────────┬────────────────────────────────────────┐
│            TERMINAL (LEFT)             │         BROWSER (RIGHT: :3000)         │
│                                        │                                        │
│  > .\demo.ps1 web                      │   [01 Attack Graph]                    │
│    Target: victim:8080 (web-portal)    │   🚨 ACTIVE INGRESS (web-portal)       │
│    Payload: /login?user=admin' OR 1=1  │   [03 Autonomous Investigation]        │
│    Payload: /view?page=../../etc/passwd│   Executive Briefing: SQLi/Traversal   │
│    Verdict: CONFIRMED ATTACK (89%)     │   [04 What-If Workbench]               │
│    Action: WAF Rule & CVE-2021-44228   │   Patching Log4Shell Cuts Route        │
└────────────────────────────────────────┴────────────────────────────────────────┘
```

### 🖥️ Real Output: Live Terminal Execution

#### Attack Scenario 1: Web Application Exploit (`web-portal`)
```text
=================================================================
  SENTINELGRAPH DOCKER-BASED DEMO TRIGGER (WEB)
=================================================================
[1/5] Checking Docker daemon status...
      Docker daemon is active.
[2/5] Ensuring required lab services are running...
[3/5] Checking SentinelGraph platform webhook (http://127.0.0.1:8000/health)...
      Platform is online and listening for detector webhooks.

[4/5] Executing simulated attack scenario 'web' against victim...
=================================================================
SCENARIO 2: Web Application Exploit against Web Portal
Target: victim:8080 (web-portal / Customer Web Portal)
-----------------------------------------------------------------
[*] Sending Health probe payload to http://victim:8080/health...
    [Response HTTP 200]: victim-ok
[*] Sending SQL Injection (' OR 1=1) payload to http://victim:8080/login?user=admin'%20OR%201=1--...
    [Response HTTP 500]: HTTP 500 Internal Server Error: SQL syntax error near 'OR 1=1'
[*] Sending Directory Traversal (../) payload to http://victim:8080/view?page=../../../../etc/passwd...
    [Response HTTP 200]: root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[+] Web exploit sequence finished.

SAFE DEMO COMPLETE: no external target was contacted
[5/5] Waiting for detector to post normalized alerts to SentinelGraph...

=================================================================
  GENERATED ALERTS & PIPELINE VERIFICATION
=================================================================
Total Alerts in Queue: 74
-----------------------------------------------------------------
[Alert 1]
  Alert ID:          alert-6e75e7ed39
  Source Host:       web-portal
  Rule Triggered:    web_path_traversal_attempt
  Severity:          8/10
  Timestamp:         2026-10-06T04:51:50.768366+00:00
  Detector:          sentinelgraph-edr-agent
  Status:            queued
  Raw Log Reference: victim.log:2026-10-06T04:51:50.550299+00:00 WEB_REQUEST client=172.18.0.5 method=GET path=/view?page=../../../../etc/passwd raw_path=/view?page=../../../../etc/passwd
-----------------------------------------------------------------
[Alert 2]
  Alert ID:          alert-ac173728e3
  Source Host:       web-portal
  Rule Triggered:    web_sqli_injection_attempt
  Severity:          8/10
  Timestamp:         2026-10-06T04:51:50.264581+00:00
  Detector:          sentinelgraph-edr-agent
  Status:            queued
  Raw Log Reference: victim.log:2026-10-06T04:51:50.245931+00:00 WEB_REQUEST client=172.18.0.5 method=GET path=/login?user=admin' OR 1=1-- raw_path=/login?user=admin'%20OR%201=1--
-----------------------------------------------------------------
INVESTIGATION TRIGGERED AUTOMATICALLY:
  Run ID:            investigation-eeb634dd52
  Status:            complete
  Verdict:           confirmed attack (89% confidence)
  Evidence Coverage: 100%
  Action (Gated):    Apply perimeter WAF filtering rule, isolate web-portal container ingress, and patch CVE-2021-44228; human operator authorization required.
-----------------------------------------------------------------

Demo flow completed successfully:
  .\demo.ps1 -> simulated attack -> victim log -> detector -> SentinelGraph /alerts
```

#### Attack Scenario 2: SSH Brute Force (`vpn-bastion`)
```text
=================================================================
  SENTINELGRAPH DOCKER-BASED DEMO TRIGGER (SSH)
=================================================================
[4/5] Executing simulated attack scenario 'ssh' against victim:2222...
SAFE DEMO: target=victim:2222 (Compose network only)
AUTH FAILED
AUTH FAILED
AUTH FAILED
AUTH OK lab session opened
SAFE DEMO COMPLETE: no external target was contacted
[5/5] Waiting for detector to post normalized alerts to SentinelGraph...

=================================================================
  GENERATED ALERTS & PIPELINE VERIFICATION
=================================================================
[Alert 1]
  Alert ID:          alert-bd8ffd2528
  Source Host:       victim
  Rule Triggered:    ssh_success_after_failures
  Severity:          9/10
  Detector:          sentinelgraph-edr-agent
  Raw Log Reference: victim.log: AUTH_SUCCESS src=172.18.0.5 user=demo service=ssh action=login
-----------------------------------------------------------------
INVESTIGATION TRIGGERED AUTOMATICALLY:
  Verdict:           confirmed attack (89% confidence)
  Action (Gated):    Isolate compromised asset at perimeter firewall, block ingress threat IP, and rotate credentials; human operator authorization required.
```

---

## 🖥️ SOC UI Dashboard Screens (Visual Architecture)

### 01. Attack Graph (`http://localhost:3000/`)
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🚨 ACTIVE BREACH DETECTED: Ingress via Customer Web Portal (web-portal)                │
│    Correlated live alert: web_sqli_injection_attempt · Lateral path to Crown Jewels    │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ [ATTACK PATHS: 24]     [OVERALL RISK: 96/100]     [CROWN JEWELS: 02]    [CHOKE: 100%] │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ROUTE STEPPER:                                                                         │
│   internet ➔ edge-gateway ➔ 🚨 web-portal (Breached) ➔ admin-role ➔ app-server ➔ ⭐ prod-db│
├────────────────────────────────────────────────────────────────────────────────────────┤
│ GRAPH CANVAS (Cytoscape.js):                                                           │
│           (internet) ──[443]──> (edge-gateway)                                         │
│                                       │                                                │
│                                  [8080/HTTP]                                           │
│                                       ▼                                                │
│                          🚨 [ web-portal ] (BREACHED FOOTHOLD)                        │
│                                       │                                                │
│                               [CVE-2021-44228]                                         │
│                                       ▼                                                │
│                                [ admin-role ]                                          │
│                                       │                                                │
│                                       ▼                                                │
│                                [ app-server ]                                          │
│                                  /         \                                           │
│                            [5432]           [8200]                                     │
│                              ▼                 ▼                                       │
│                       ⭐ [prod-db]       ⭐ [secrets-vault]                            │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 02. Autonomous Investigation (`http://localhost:3000/investigation`)
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ WHAT HAPPENED: 4 Executive SOC Briefing Cards                                          │
├────────────────────┬────────────────────┬────────────────────┬─────────────────────────┤
│ 👤 WHO ATTACKED    │ 🎯 WHAT HAPPENED   │ 📍 WHERE (FOOTHOLD)│ 🛡️ IMPACT ON CROWN JEWELS│
│ External IP        │ Web App Exploit    │ web-portal         │ Critical Lateral Pivot  │
│ 172.18.0.5         │ SQLi (' OR 1=1) &  │ victim:8080        │ Exposed path to Database│
│ Lab Attacker       │ Traversal (../)    │ CVE-2021-44228     │ and HashiCorp Vault     │
├────────────────────┴────────────────────┴────────────────────┴─────────────────────────┤
│ INCIDENT PROGRESSION TIMELINE:                       DETERMINISTIC VERDICT:            │
│ 01. Suspicious HTTP Ingress (port 8080)              ● CONFIRMED ATTACK                │
│ 02. Exploit Signature Verified (SQLi / Traversal)    Confidence: 89% Evidence-Backed   │
│ 03. Attack Graph Lateral Correlation (NetworkX)      --------------------------------- │
│ 04. Perimeter CVE Matched (CVE-2021-44228 Log4j2)    GATED CONTAINMENT ACTION:         │
│                                                      Deploy perimeter WAF rule, isolate│
│                                                      web-portal, patch CVE-2021-44228. │
│                                                      [ Approve & Execute Containment ] │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🕹️ How to Test and Verify Both Live Triggers

### 1. Web Application Exploit (Web Portal)
To simulate the web application exploit with `' OR 1=1` and `../`:
```bash
# In PowerShell:
powershell -ExecutionPolicy Bypass -File .\demo.ps1 web

# In Bash / macOS / Linux / WSL:
./demo.sh web

# Or via direct Docker Compose:
docker compose --profile demo run --rm -e ATTACK_SCENARIO=web attacker
```

### 2. SSH Brute Force (VPN Bastion)
To simulate the perimeter SSH brute-force attack:
```bash
# In PowerShell:
powershell -ExecutionPolicy Bypass -File .\demo.ps1 ssh

# In Bash / Linux:
./demo.sh ssh

# Or via direct Docker Compose:
docker compose --profile demo run --rm -e ATTACK_SCENARIO=ssh attacker
```

### 3. Both Scenarios Sequentially
```bash
powershell -ExecutionPolicy Bypass -File .\demo.ps1 all
```

### 4. Direct In-Browser Triggering
You can also trigger either attack directly inside the web UI at **`http://localhost:3000`**:
* Click **`🌐 Web Portal`** in the top navigation bar to launch the Web exploit.
* Click **`⚡ SSH Bastion`** in the top navigation bar to launch the SSH brute force.
* Click **`↺ Reset Lab`** at any time to clear the alerts and restore the baseline.

---

## 🔍 What is Real vs. Simulated

| Component | Architecture & Status |
|---|---|
| **Graph Construction & Path Enumeration** | **Real Computation:** Live NetworkX directed graph, cycle-free path search, and betweenness centrality ranking. |
| **Attack Simulation** | **Real Socket Traffic:** Attacker container establishes TCP connection to `victim:2222`, sending invalid passwords followed by successful login. |
| **Victim Log Generation** | **Real Service:** `victim.py` processes socket logins and writes standard auth records to `/logs/victim.log`. |
| **Detector Telemetry** | **Real-Time Agent:** `detector.py` tails the shared log file, correlates 3 failures + 1 success, and issues HTTP POST webhooks. |
| **Event Streaming (SSE)** | **Real Streaming:** FastAPI publishes events via `EventSource` (`/api/alerts/stream` and `/api/investigation/stream`). |
| **Investigation Reasoning** | **Real Deterministic Engine:** ReAct orchestration cross-correlating tool evidence without AI hallucination. |
| **Vulnerability Fixtures** | **Simulated Threat Feed:** Real-world CVE identifiers (`CVE-2024-3400`, `CVE-2021-44228`) and MITRE ATT&CK techniques (`T1110`). |
| **Remediation Execution** | **Human-Gated:** Mitigations require explicit operator authorization before being committed to the live enclave graph. |

---

## 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status and queue depth |
| `POST` | `/alerts` | Ingests EDR/detector alerts, normalizes data, and triggers ReAct agent |
| `GET` | `/api/alerts` | Returns recent ingested alerts and queue depth |
| `GET` | `/api/alerts/stream` | Server-Sent Events stream for real-time alert ingestion |
| `GET` | `/api/investigation/current` | Returns the current investigation transcript and verdict |
| `GET` | `/api/investigation/stream` | Server-Sent Events stream for live ReAct reasoning steps |
| `GET` | `/api/graph` | Serialized NetworkX graph nodes, edges, and risk metrics |
| `GET` | `/api/paths` | Enumerated attack paths from ingress to crown jewels |
| `GET` | `/api/risks` | Prioritized choke points and path coverage rankings |
| `POST` | `/api/what-if/simulate` | Clones graph in-memory and simulates mitigation impact |
| `POST` | `/api/what-if/approve` | Commits approved mitigation into live enclave baseline |
| `GET` | `/api/prediction` | Predicts attacker's next lateral pivots based on exploitability |
| `POST` | `/api/demo/trigger` | Injects simulated threat event directly via API |
| `POST` | `/api/demo/reset` | Resets lab to safe baseline (0 alerts, clean graph) |

---

## 🧪 Validation & Testing

Run the automated backend test suite:
```bash
python -m pytest backend/tests -q
```

Validate frontend production build:
```bash
cd frontend && npm run build
```

To stop and clean up all lab containers and volumes:
```bash
docker compose down -v
```
