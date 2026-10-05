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

## 🎬 Live Presentation Walkthrough (For Judges)

Demonstrating the live incident flow side-by-side (Terminal on left, Browser on right):

```
┌─────────────────────────────────┬─────────────────────────────────┐
│        TERMINAL (LEFT)          │       BROWSER (RIGHT: 3000)     │
│                                 │                                 │
│  > docker compose ... run       │   [01 Attack Graph]             │
│    attacker                     │   🚨 ACTIVE INCIDENT (vpn-bastion)│
│                                 │   [03 Investigation]            │
│    AUTH FAILED x3               │   Executive Briefing + Verdict  │
│    AUTH OK (lab session opened) │   [04 What-If]                  │
│                                 │   -50% Paths Severed (Clear Fix)│
└─────────────────────────────────┴─────────────────────────────────┘
```

### Step 1: Ensure Clean Baseline
In the web console, click **`↺ Reset Lab`** in the top right.
The status shows **`Enclave Protected`** (green beacon) with **`No Active Threats`**.

### Step 2: Trigger the Live Docker Attack in Terminal
Run this command in your terminal:
```bash
# Using raw Docker Compose:
docker compose --profile demo run --rm attacker

# Or using the PowerShell automation script:
powershell -ExecutionPolicy Bypass -File .\demo.ps1

# Or in Linux/macOS/WSL:
./demo.sh
```

### Step 3: Watch the Automated Screen-to-Screen Flow
The browser detects the real-time Server-Sent Event (SSE) and **automatically advances across screens**:
1. **01 Attack Graph (6s):** Flashes `🚨 ACTIVE BREACH DETECTED`. Lights up the compromised route in bold crimson red directly to `prod-db`.
2. **02 Top Risks (6s):** Displays the choke points and shows the matching broken attack paths.
3. **03 Investigation (6s):** Displays the executive **WHO / WHAT / WHERE / IMPACT** cards, 4-step progression, and 89% confirmed attack verdict.
4. **04 What-If Workbench (Settles here):** Shows the crystal-clear answer: patching `CVE-2024-3400` destroys 11 attack paths (-50%). Click **`Approve & Apply Mitigation`** to seal the perimeter!

### Step 4: Repeat on Demand
Click **`↺ Reset Lab`** in the browser anytime to clear all alerts and reset the graph baseline for another live demonstration.

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
