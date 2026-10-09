# CYBERSCOPE

### Explainable Cyber-Fraud Intelligence & Investigation Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Vite](https://img.shields.io/badge/Vite-5.1+-646CFF.svg?style=flat&logo=vite&logoColor=white)](https://vitejs.dev)
[![UI: Cyber-Neon Design](https://img.shields.io/badge/UI-Cyber--Neon%20Design-36CFFF.svg?style=flat)](https://github.com)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA%20NIM-Llama%203.2%20Vision-76B900.svg?style=flat&logo=nvidia&logoColor=white)](https://build.nvidia.com)
[![Leaflet](https://img.shields.io/badge/Geospatial-Leaflet.js-199900.svg?style=flat&logo=leaflet&logoColor=white)](https://leafletjs.com)
[![NetworkX](https://img.shields.io/badge/Graph-NetworkX-blue.svg?style=flat)](https://networkx.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> *"Fraud does not happen as one isolated event. It appears as a chain of connected evidence. CYBERSCOPE reconstructs that chain."*

---

## 1. Project Overview

**CYBERSCOPE** is an enterprise-grade defensive cyber-fraud intelligence and investigation console designed for security operations centers (SOCs), financial fraud analysts, and incident response teams.

Traditional anti-fraud systems evaluate suspicious events in isolation (such as an individual phishing complaint or a single anomalous transfer). CYBERSCOPE reconstructs the complete evidence chain:
- **Evidence Ingestion & Case Intake:** Ingests raw unstructured scam narrative evidence, victim reports, and evidence file attachments (`new-case.html`).
- **Entity Extraction & Normalization:** Extracts and normalizes digital identifiers (phones, domains, UPI IDs, bank accounts) with strict regex and E.164 standardization.
- **Interactive Multi-Hop Fraud Graph:** Connects fragmented indicators into a dynamic 2D/3D visual network powered by NetworkX (`fraud-graph.html`).
- **Live Attacker Threat Map:** Visualizes real-time geospatial attacker infrastructure, botnet nodes, and regional threat metrics using Leaflet.js (`threat-map.html`).
- **CYBER-ASSIST AI Chatbot Workspace:** Features a dedicated conversational AI investigation assistant powered by NVIDIA NIM (`meta/llama-3.2-11b-vision-instruct`) with multi-modal vision instruction support and offline local fallback (`chatbot.html`).
- **Explainable Investigation Risk Score (0–100):** Itemizes transparent, additive contributing signals without black-box opacity.
- **Coordinated Campaign Discovery:** Detects cybercrime syndicates sharing underlying attack infrastructure (`campaign-explorer.html`).
- **Money-Flow Traversal Engine:** Traces simulated fund movement through complex mule networks, identifying layering, fan-out, circular loops, and exit cash-out nodes (`transaction-explorer.html`).
- **Structured Investigation Workspace:** Consolidates evidence, dynamic timelines, investigator notes, IOC tables, and one-click markdown report export (`investigation-workspace.html`).
- **Enterprise Authenticated Portal:** Complete JWT/Session authentication portal with investigator registration and a client-side real-time 10-point password strength evaluator (`signin.html`, `register.html`, `password-strength.js`).

---

## 2. Safety & Scope Disclaimer

> **IMPORTANT DEFENSIVE RESEARCH NOTICE:**  
> **CYBERSCOPE is a defensive research and hackathon prototype using synthetic, fictional data only.**  
> It does not connect to real bank accounts, real payment gateways, or live telecommunication carriers. Risk scores are investigative signals intended for analyst prioritization, not legal proof of criminal activity.

---

## 3. High-Level System Architecture

```
                       SYNTHETIC DATA & EVIDENCE INGESTION
                    (Narrative Intake, Raw Text, File Attachments)
                                       │
                                       ▼
       ┌────────────────────────────────────────────────────────┐
       │         Entity Extraction & Normalization Engine       │
       │  (Regex + E.164 Phone, Domain, UPI, IFSC Normalization)│
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │             In-Memory Fraud Graph (NetworkX)           │
       │   (Hops, Shortest Paths, Cycles, Shared Infrastructure)│
       └───────┬───────────────────┬───────────────────┬────────┘
               │                   │                   │
               ▼                   ▼                   ▼
       ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
       │ Explainable  │    │  Campaign    │    │  Money-Flow  │
       │ Risk Engine  │    │  Detector    │    │ Trace Engine │
       │  (Max 100)   │    │ (Clustering) │    │  (BFS Hops)  │
       └───────┬──────┘    └──────┬───────┘    └──────┬───────┘
               │                  │                   │
               └──────────────────┼───────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │      NVIDIA NIM AI Assistant & CYBER-ASSIST Engine     │
       │  (/api/chat Proxy + Llama 3.2 Vision + Local Fallback) │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │            Live Geospatial Threat Intelligence         │
       │   (/api/threat-map Attacker Nodes & Regional Density)   │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │         CyberScope Cyber-Neon Investigation Suite      │
       │ (Showcase, Dashboard, Cases, Graph, Threat Map, Chat)  │
       └────────────────────────────────────────────────────────┘
```

---

## 4. Complete Project File Structure

```text
CYBERSCOPE/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth.py               # Enterprise JWT authentication, login, register & password verification
│   │   │   ├── campaigns.py          # Coordinated fraud campaign clustering endpoints
│   │   │   ├── cases.py              # Case ingestion, file evidence, filtering & risk computation
│   │   │   ├── chat.py               # NVIDIA NIM API Proxy, vision instruction & fallback chat engine
│   │   │   ├── entities.py           # 360-degree entity lookup and neighbor exploration
│   │   │   ├── graph.py              # Interactive fraud graph & circular flow endpoints
│   │   │   ├── health.py             # Health check & defensive scope disclaimer
│   │   │   ├── investigations.py     # CYBER-ASSIST AI investigator & summary brief
│   │   │   ├── search.py             # Safe controlled natural-language search
│   │   │   ├── stats.py              # Platform KPI aggregations for SOC dashboard
│   │   │   ├── threat_map.py         # Live attacker infrastructure feed & regional threat telemetry
│   │   │   └── transactions.py       # Financial ledger exploration & recursive fund tracing
│   │   ├── analyzers/
│   │   │   ├── __init__.py           # Package exports for analyzers
│   │   │   ├── behavioral_analyzer.py# Burst velocity, fan-out/in, dormancy-to-burst
│   │   │   ├── communication_analyzer.py # Impersonation, urgency, credential harvesting
│   │   │   ├── graph_analyzer.py     # NetworkX topology, cycles, shortest paths
│   │   │   └── transaction_analyzer.py # High-value, structuring, and counterparty risk
│   │   ├── models/
│   │   │   ├── __init__.py           # Package exports for ORM models
│   │   │   ├── base.py               # Base class & timestamp mixin
│   │   │   ├── campaign.py           # Campaign ORM model
│   │   │   ├── case.py               # Case ORM model with metadata
│   │   │   ├── entity.py             # Entity ORM model (phones, accounts, domains)
│   │   │   ├── indicator.py          # Indicator ORM model
│   │   │   ├── investigation.py      # Investigation log ORM model
│   │   │   ├── message.py            # Communication records (SMS/email)
│   │   │   ├── relationship.py       # Graph edges & multi-hop connections
│   │   │   ├── transaction.py        # Financial ledger transactions
│   │   │   └── user.py               # Authenticated investigator user & verification ORM models
│   │   ├── schemas/
│   │   │   ├── __init__.py           # Package exports for Pydantic schemas
│   │   │   ├── auth.py               # Login, register & verification schemas
│   │   │   ├── campaign.py           # Campaign serialization schemas
│   │   │   ├── case.py               # Case detail, list, update & risk signal schemas
│   │   │   ├── entity.py             # Entity detail & neighbor response schemas
│   │   │   ├── graph.py              # GraphNode, GraphEdge & filter schemas
│   │   │   ├── investigation.py      # AI query, citations & timeline event schemas
│   │   │   ├── threat_map.py         # Attacker nodes, telemetry & live event schemas
│   │   │   └── transaction.py        # Transaction & money-flow trace schemas
│   │   ├── services/
│   │   │   ├── ai_service.py         # AIProvider abstraction (Deterministic + OpenAI/NVIDIA)
│   │   │   ├── auth_service.py       # JWT creation, password hashing & verification service
│   │   │   ├── campaign_service.py   # Multi-incident syndicate clustering service
│   │   │   ├── entity_service.py     # Deduplication, resolution, and relational indexing
│   │   │   ├── graph_service.py      # In-memory NetworkX synchronized graph engine
│   │   │   ├── ingestion_service.py  # Regex extraction & automatic graph link creation
│   │   │   ├── notification_service.py# Alert & email dispatch service
│   │   │   ├── risk_service.py       # Transparent explainable scoring engine (Max 100)
│   │   │   ├── threat_map_service.py # Attacker telemetry & geospatial mapping service
│   │   │   ├── timeline_service.py   # Chronological evidence sequencing service
│   │   │   └── transaction_service.py# Recursive BFS money-flow trace engine
│   │   ├── utils/
│   │   │   ├── normalization.py      # E.164 phone, domain, URL, and UPI normalizers
│   │   │   └── password_strength.py  # 10-point password strength rating algorithm
│   │   ├── config.py                 # Pydantic BaseSettings with environment overrides
│   │   ├── database.py               # Session lifecycle (SQLite default / PostgreSQL)
│   │   └── main.py                   # FastAPI lifespan, CORS, and centralized routing
│   ├── scripts/
│   │   ├── generate_dataset.py       # Deterministic generator (Seed 42, 9 patterns)
│   │   ├── seed_demo.py              # Populates database with "Operation Phantom KYC"
│   │   ├── reset_demo.py             # One-command demo reset utility
│   │   └── evaluate_patterns.py      # Benchmark evaluation (Regression + Held-Out Noisy)
│   ├── tests/
│   │   ├── test_analyzers.py         # Unit tests for heuristics, normalization & ReDoS
│   │   └── test_api.py               # REST API integration tests & security checks (20/20)
│   ├── Dockerfile                    # Python 3.11 container build definition
│   └── requirements.txt              # Backend dependencies
├── frontend/
│   ├── index.html                    # Root entry point & Flagship CyberScope landing showcase
│   ├── CyberScope.html               # Dedicated landing showcase & live AI intelligence overview
│   ├── dashboard.html                # SOC Command dashboard & real-time telemetry
│   ├── cases.html                    # Case registry with severity badges & quick filters
│   ├── new-case.html                 # Case ingestion & evidence file upload portal
│   ├── threat-map.html               # Live Attacker Threat Map & geospatial intelligence portal
│   ├── fraud-graph.html              # Multi-hop fraud network relationship visualizer
│   ├── entity-explorer.html          # Entity registry & 360-degree identifier search
│   ├── transaction-explorer.html     # Financial transaction ledger & money-flow metrics
│   ├── campaign-explorer.html        # Coordinated campaign clusters & shared infrastructure
│   ├── investigation-workspace.html  # Case deep-dive, dynamic timeline, notes & report export
│   ├── chatbot.html                  # Dedicated CYBER-ASSIST AI Chatbot workspace
│   ├── signin.html                   # Authenticated access portal with demo fallback
│   ├── register.html                 # Investigator registration portal & live password meter
│   ├── assets/
│   │   ├── cyberscope.css            # Cyber-Neon dark glassmorphism design system
│   │   ├── cyberscope.js             # Core UI helper scripts & API integrations
│   │   ├── password-strength.js      # Client-side 10-point password strength evaluator
│   │   ├── supabase-client.js        # Supabase authentication integration client
│   │   ├── logo.png                  # CyberScope high-resolution logo asset
│   │   └── cyberscope-logo.png       # Alternative logo brand asset
│   ├── server.py                     # Optional standalone Python server & NIM proxy
│   ├── vite.config.ts                # Multi-page Rollup builder & API reverse proxy (13 pages)
│   ├── package.json                  # Clean Vite dev configuration
│   ├── nginx.conf                    # Production Nginx container routing
│   └── Dockerfile                    # Multi-stage production build
├── data/
│   └── synthetic/
│       └── benchmark_dataset.json    # Exported benchmark dataset
├── docs/
│   ├── api.md                        # Full REST API specification
│   ├── architecture.md               # Technical subsystem design
│   ├── demo-script.md                # 3-minute hackathon walkthrough script
│   └── detection-methodology.md      # Mathematical & heuristic fraud formulas
├── .env                              # Active environment configuration
├── .env.example                      # Environment variables template
├── .gitignore                        # Git exclusion rules
├── docker-compose.yml                # Multi-container orchestration (Postgres, Backend, Frontend)
├── LICENSE                           # MIT License
├── Makefile                          # Unified build and automation commands
└── README.md                         # Platform documentation and guide
```

---

## 5. Website Modules & Key Features

CYBERSCOPE features 13 custom-engineered web application modules built with the **Cyber-Neon Dark Glassmorphism Design System** (`#050a12`, `#0a1220`, `#0d1727`), glowing cyan accents (`#36cfff`), micro-animations, and responsive layouts:

### 1. Flagship CyberScope Landing Portal (`index.html` / `CyberScope.html`)
- **Interactive Platform Gateway:** Presents an overview of defensive capabilities, fraud graph visualization, campaign discovery, and explainable risk scores.
- **Live AI Intelligence Showcase:** Integrated live assistant feature previews demonstrating automated incident synthesis.

### 2. Live Attacker Threat Map (`threat-map.html`)
- **Geospatial Attacker Intelligence:** Powered by Leaflet.js (`/api/threat-map`), rendering verified cyber attacker infrastructure, phishing gateways, DDoS botnet nodes, and SIM box relays.
- **Regional Threat Breakdown:** Displays regional threat density, pincode geographic clustering, active botnet overlays, and live attack vector tickers with strict privacy filters (attacker nodes only; zero victim data exposed).

### 3. Dedicated CYBER-ASSIST AI Chatbot Workspace (`chatbot.html`)
- **Conversational Intelligence Copilot:** Powered by NVIDIA NIM (`meta/llama-3.2-11b-vision-instruct`) via the `/api/chat` proxy.
- **Multi-Turn Workspace:** Supports dynamic queries, graph evidence cross-examination, screenshot/vision analysis, prompt suggestions, and local deterministic fallback.

### 4. New Case Ingestion & Evidence File Portal (`new-case.html`)
- **Streamlined Incident Intake:** Dedicated ingestion portal for lodging new cyber-fraud complaints (`/api/cases`).
- **Automated Identifier Extraction:** Extracts phone numbers, domains, UPI IDs, and bank account numbers from unstructured text.
- **Evidence File Uploader:** Allows uploading supporting document attachments and automatically computes instant risk scores upon creation.

### 5. Interactive Multi-Hop Fraud Graph (`fraud-graph.html`)
- **Visual Network Topology:** Renders interconnected indicators, victim accounts, apex domains, and mule accounts using interactive force-directed graph controls (`/api/graph`).
- **Multi-Hop Traversal:** Highlights shortest path connections, multi-hop linkages, circular financial transfers, and neighborhood expansion.

### 6. SOC Command Dashboard (`dashboard.html`)
- **Situational Awareness Suite:** Aggregates real-time SOC metrics, active case counts, risk score distribution, high-priority incident tickers, and quick investigation shortcuts (`/api/stats`).

### 7. Case Registry & Filter Management (`cases.html`)
- **Central Incident Ledger:** Categorized case registry with severity badges (CRITICAL, HIGH, MEDIUM, LOW), status filtering (New, Under Review, Escalated, Closed), and instant report ingestion triggers.

### 8. 360-Degree Entity Explorer (`entity-explorer.html`)
- **Digital Identifier Lookup:** Searches E.164 formatted phone numbers, normalized domains, UPI IDs, and bank accounts (`/api/entities`).
- **Complete Relational Context:** Displays connected entity counts, associated case histories, risk indicators, and neighbor relationship maps.

### 9. Transaction Explorer & Money-Flow Engine (`transaction-explorer.html`)
- **Financial Ledger Analysis:** Traces funds through complex mule networks (`/api/transactions`).
- **BFS Money Traversal:** Identifies fan-out patterns, rapid fund dispersion, circular money laundering loops, and exit cash-out points.

### 10. Coordinated Campaign Syndicate Explorer (`campaign-explorer.html`)
- **Syndicate Clustering:** Groups isolated incidents into named campaign clusters (`/api/campaigns`) based on shared malicious apex domains, central collection UPI IDs, or VoIP sender numbers.

### 11. Structured Investigation Workspace (`investigation-workspace.html`)
- **Analyst Deep-Dive Console:** Consolidates incident timelines, evidence artifacts, persistent investigator notes, and IOC tables.
- **One-Click Report Export:** Generates structured, defensible markdown investigation reports for executive briefing.

### 12. Enterprise Authenticated Portal & Password Evaluator (`signin.html` & `register.html`)
- **Secure Authentication:** Features session/JWT token authentication (`/api/auth`) and user registration.
- **Real-Time Password Strength Evaluator (`password-strength.js`):** Client-side 10-point scoring algorithm measuring entropy, character diversity, dictionary leaks, and pattern runs with color-coded UI feedback (A+ to F grades).

---

## 6. Backend REST API Reference

| Endpoint Group | Route Prefix | Key Functionality |
| :--- | :--- | :--- |
| **Authentication** | `/api/auth` | User login, registration, JWT session verification & password validation |
| **Threat Map** | `/api/threat-map` | Attacker infrastructure geospatial nodes, stats & live attack vector feed |
| **Case Management** | `/api/cases` | Incident listing, detailed view, file ingestion & automatic risk calculation |
| **Fraud Graph** | `/api/graph` | Multi-hop nodes, edges, shortest paths & circular money flow queries |
| **Entity Lookup** | `/api/entities` | 360-degree identifier search, neighbor exploration & risk profiling |
| **Transactions** | `/api/transactions` | Financial ledger exploration, counterparty risk & recursive BFS fund tracing |
| **Campaigns** | `/api/campaigns` | Multi-incident syndicate clustering & shared infrastructure analysis |
| **AI Intelligence** | `/api/chat`, `/api/investigations` | NVIDIA NIM AI proxy, multi-modal prompt routing & investigation summaries |
| **SOC Statistics** | `/api/stats` | Platform aggregated KPIs, threat spectrum & campaign distribution |
| **Natural Search** | `/api/search` | Safe, controlled natural language query endpoint |
| **Health Check** | `/api/health` | System health check and defensive scope statement |

---

## 7. Technology Stack

### Backend
- **Framework:** FastAPI (Python 3.11+)
- **Data Validation:** Pydantic v2
- **Relational Store:** SQLAlchemy ORM (SQLite default for zero-friction local execution; PostgreSQL for containerized deployments)
- **Graph Analytics:** NetworkX (in-memory synchronized engine with abstract `IGraphService` interface)
- **AI & LLM Services:** NVIDIA NIM API (`meta/llama-3.2-11b-vision-instruct`) with automated local proxy and deterministic rule-based fallback
- **Data Science:** pandas, NumPy, scikit-learn
- **Testing:** pytest (20/20 passing unit/integration tests including security checks)

### Frontend
- **Architecture:** Multi-Page Application (MPA) powered by Vite 5.1+ (13 configured input entry points)
- **Geospatial Mapping:** Leaflet.js 1.9.4
- **Styling:** Custom CyberScope Cyber-Neon Design System (Vanilla CSS with CSS variables, radial glows, glassmorphism, responsive grids)
- **Typography:** Inter, Space Grotesk & JetBrains Mono via Google Fonts
- **Deployment:** Nginx reverse proxy with HTML multi-page resolution

---

## 8. Getting Started & Local Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm 9+ (optional if using Docker or standalone Python server)

---

### A. Quick Start: Local Development (Windows PowerShell)

```powershell
# 1. Clone repository & navigate to backend
cd "d:\CyberScope-Cursive\Backend"

# 2. Setup Virtual Environment & Install Dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 3. Seed Demo Scenario ("Operation Phantom KYC")
python scripts/seed_demo.py

# 4. Start FastAPI Backend Server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

In a second PowerShell terminal:
```powershell
# 5. Start Frontend Console (Vite)
cd "d:\CyberScope-Cursive\Frontend"
npm install
npm run dev
```

* **Frontend Console:** `http://localhost:5173`
* **FastAPI Interactive API Docs:** `http://localhost:8000/docs` (Development mode)

---

### B. Quick Start: macOS / Linux

```bash
# Backend Setup
cd Backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/seed_demo.py
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &

# Frontend Setup
cd ../Frontend
npm install
npm run dev
```

---

### C. Standalone Zero-Dependency Python Runner

If Node.js is not installed, the frontend can be served directly using the built-in Python server:

```bash
cd Frontend
python server.py 8000
```
Open **`http://localhost:8000/index.html`** or **`http://localhost:8000/dashboard.html`**.

---

### D. Docker Compose (Full Stack)

CYBERSCOPE includes production-ready Docker Compose orchestration:

```bash
docker compose up --build
```
- **Frontend Console:** `http://localhost:5173`
- **Backend API:** `http://localhost:8000`
- **PostgreSQL:** Internal Docker bridge network

*Note: On container startup, the backend automatically seeds the database with the "Operation Phantom KYC" demo dataset if the database is empty.*

---

## 9. Demo Scenario: "Operation Phantom KYC"

CYBERSCOPE includes a pre-seeded, deterministic investigative scenario called **"Operation Phantom KYC"**:
- **5 Victims** receiving urgent bank account deactivation / KYC suspension SMS lures.
- **Shared Phishing Domain:** `secure-kyc-update.com`
- **Shared Central Collection UPI ID:** `centralmule99@okaxis`
- **Mule Bank Account:** `AC-MULE-4482`
- **Coordinated Campaign Code:** `CAMP-KYC-01`

### Running the Evaluation Benchmark & Automated Tests

To verify detection heuristics against synthetic noise:
```bash
cd Backend
python scripts/evaluate_patterns.py
```

To run the automated test suite (verifying analyzers, ReDoS prevention, and REST contracts):
```bash
cd Backend
pytest tests/ -v
```

---

## 10. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
