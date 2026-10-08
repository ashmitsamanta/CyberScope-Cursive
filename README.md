# CYBERSCOPE

### Explainable Cyber-Fraud Intelligence & Investigation Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Vite](https://img.shields.io/badge/Vite-5.1+-646CFF.svg?style=flat&logo=vite&logoColor=white)](https://vitejs.dev)
[![HTML5/Vanilla CSS](https://img.shields.io/badge/UI-Cyber--Neon%20Design-36CFFF.svg?style=flat)](https://github.com)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA%20NIM-Llama%203.2%20Vision-76B900.svg?style=flat&logo=nvidia&logoColor=white)](https://build.nvidia.com)
[![NetworkX](https://img.shields.io/badge/Graph-NetworkX-blue.svg?style=flat)](https://networkx.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> *"Fraud does not happen as one isolated event. It appears as a chain of connected evidence. CYBERSCOPE reconstructs that chain."*

---

## 1. Project Overview

**CYBERSCOPE** is an enterprise-grade defensive cyber-fraud intelligence and investigation console designed for security operations centers (SOCs), financial fraud analysts, and incident response teams.

Traditional anti-fraud systems evaluate suspicious events in isolation (such as an individual phishing complaint or a single anomalous transfer). CYBERSCOPE reconstructs the complete evidence chain:
- **Evidence Ingestion:** Ingests raw unstructured scam evidence (SMS lures, victim complaints, web forms).
- **Entity Extraction & Normalization:** Extracts and normalizes digital identifiers (phones, domains, UPI IDs, bank accounts).
- **Fraud Graph Analytics:** Connects fragmented entities into an interactive, multi-hop **Fraud Graph** powered by NetworkX.
- **Explainable Investigation Risk Score (0–100):** Itemizes transparent, additive contributing signals without black-box opacity.
- **Campaign Clustering:** Detects coordinated cybercrime syndicates sharing underlying attack infrastructure.
- **Money-Flow Traversal:** Traces simulated money movement through complex mule networks (layering, fan-out, circular loops).
- **AI Intelligence & NVIDIA NIM Assistant:** Features a real-time conversational intelligence assistant powered by NVIDIA NIM (`meta/llama-3.2-11b-vision-instruct`) with built-in zero-CORS proxying and fallback local expertise.
- **Structured Investigation Workspace:** Consolidates incident evidence, chronological timelines, persistent investigator notes, and one-click markdown report export.

---

## 2. Safety & Scope Disclaimer

> **IMPORTANT DEFENSIVE RESEARCH NOTICE:**  
> **CYBERSCOPE is a defensive research and hackathon prototype using synthetic, fictional data only.**  
> It does not connect to real bank accounts, real payment gateways, or live telecommunication carriers. Risk scores are investigative signals intended for analyst prioritization, not legal proof of criminal activity.

---

## 3. High-Level Architecture

```
                       SYNTHETIC DATA INGESTION
                                  ↓
      ┌────────────────────────────────────────────────────────┐
      │         Entity Extraction & Normalization Engine       │
      │  (Regex + Normalization for Phone, Domain, UPI, IFSC)  │
      └───────────────────────────┬────────────────────────────┘
                                  ↓
      ┌────────────────────────────────────────────────────────┐
      │             In-Memory Fraud Graph (NetworkX)           │
      │   (Hops, Shortest Paths, Cycles, Shared Infrastructure)│
      └───────┬───────────────────┬───────────────────┬────────┘
              │                   │                   │
              ↓                   ↓                   ↓
      ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
      │ Explainable  │    │  Campaign    │    │  Money-Flow  │
      │ Risk Engine  │    │  Detector    │    │ Trace Engine │
      │  (Max 100)   │    │ (Clustering) │    │  (BFS Hops)  │
      └───────┬──────┘    └──────┬───────┘    └──────┬───────┘
              │                  │                   │
              └──────────────────┼───────────────────┘
                                 ↓
      ┌────────────────────────────────────────────────────────┐
      │      NVIDIA NIM AI Assistant & CYBER-ASSIST Engine     │
      │  (/api/chat Proxy + Llama 3.2 Vision + Local Fallback) │
      └──────────────────────────┬─────────────────────────────┘
                                 ↓
      ┌────────────────────────────────────────────────────────┐
      │         CyberScope Cyber-Neon Investigation Suite      │
      │ (Showcase, Dashboard, Cases, Graph, Entities, Ledgers) │
      └────────────────────────────────────────────────────────┘
```

---

## 4. Complete Project File Structure

```text
CYBERSCOPE/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── campaigns.py          # Coordinated fraud campaign clustering endpoints
│   │   │   ├── cases.py              # Case management, filtering, and report ingestion
│   │   │   ├── chat.py               # NVIDIA NIM API Proxy & fallback chat engine
│   │   │   ├── entities.py           # 360-degree entity lookup and neighbor exploration
│   │   │   ├── graph.py              # Interactive fraud graph & circular flow endpoints
│   │   │   ├── health.py             # Health check & defensive scope disclaimer
│   │   │   ├── investigations.py     # CYBER-ASSIST AI investigator & summary brief
│   │   │   ├── search.py             # Safe controlled natural-language search
│   │   │   ├── stats.py              # Platform KPI aggregations for SOC dashboard
│   │   │   └── transactions.py       # Ledger exploration and recursive fund tracing
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
│   │   │   └── transaction.py        # Financial ledger transactions
│   │   ├── schemas/
│   │   │   ├── __init__.py           # Package exports for Pydantic schemas
│   │   │   ├── campaign.py           # Campaign serialization schemas
│   │   │   ├── case.py               # Case detail, list, update & risk signal schemas
│   │   │   ├── entity.py             # Entity detail & neighbor response schemas
│   │   │   ├── graph.py              # GraphNode, GraphEdge & filter schemas
│   │   │   ├── investigation.py      # AI query, citations & timeline event schemas
│   │   │   └── transaction.py        # Transaction & money-flow trace schemas
│   │   ├── services/
│   │   │   ├── ai_service.py         # AIProvider abstraction (Deterministic + OpenAI)
│   │   │   ├── campaign_service.py   # Multi-incident syndicate clustering service
│   │   │   ├── entity_service.py     # Deduplication, resolution, and relational indexing
│   │   │   ├── graph_service.py      # In-memory NetworkX synchronized graph engine
│   │   │   ├── ingestion_service.py  # Regex extraction & automatic graph link creation
│   │   │   ├── risk_service.py       # Transparent explainable scoring engine (Max 100)
│   │   │   ├── timeline_service.py   # Chronological evidence sequencing service
│   │   │   └── transaction_service.py# Recursive BFS money-flow trace engine
│   │   ├── utils/
│   │   │   └── normalization.py      # E.164 phone, domain, URL, and UPI normalizers
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
│   ├── CyberScope.html               # Platform landing page & live AI intelligence showcase
│   ├── index.html                    # Root entry point (Flagship CyberScope interface)
│   ├── dashboard.html                # SOC Overview dashboard & real-time telemetry
│   ├── cases.html                    # Case registry with severity badges & report ingest modal
│   ├── fraud-graph.html              # Multi-hop fraud network relationship visualizer
│   ├── entity-explorer.html          # Entity registry & 360-degree identifier search
│   ├── transaction-explorer.html     # Financial transaction ledger & flow metrics
│   ├── campaign-explorer.html        # Coordinated campaign clusters & shared infrastructure
│   ├── investigation-workspace.html  # Case deep-dive, dynamic timeline, notes & report export
│   ├── signin.html                   # Authenticated access portal with demo fallback
│   ├── register.html                 # Investigator identity onboarding
│   ├── server.py                     # Optional standalone Python server & NIM proxy
│   ├── vite.config.ts                # Multi-page Rollup builder & API reverse proxy
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

## 5. Key Features

- **Cyber-Neon Dark Glassmorphism Design System:** Tailored dark aesthetics (`#050a12`, `#0a1220`, `#0d1727`) with glowing cyan/blue accents, micro-animations, noise overlays, and responsive mobile layouts.
- **Explainable Risk Scoring:** Replaces opaque black-box probabilities with itemized signal cards (e.g. `KNOWN_SUSPICIOUS_IDENTIFIER` +20, `SHARED_INFRASTRUCTURE` +15, `RAPID_FUND_DISPERSION` +15) where signal points sum exactly to the final score.
- **Interactive Multi-Hop Fraud Graph:** Visualizes cross-case links between phone numbers, domains, UPI IDs, and bank accounts with clickable nodes and neighborhood inspection.
- **Money-Flow Traversal:** Traces simulated fund dispersal from victim origin accounts across intermediary mules to final exit cash-out points. Flags fan-out and rapid layering automatically.
- **Coordinated Campaign Discovery:** Clusters incidents sharing malicious apex domains, collection UPI IDs, or VoIP sender numbers.
- **NVIDIA NIM Integration & CYBER-ASSIST:** Real-time chat assistant powered by `meta/llama-3.2-11b-vision-instruct` via backend proxy (`/api/chat`), with live API key testing and fallback expert intelligence.
- **One-Click Incident Report Export:** Generates structured, defensible markdown investigation reports with executive summaries, indicators of compromise (IOCs), timelines, and investigator notes.
- **Zero-Friction Authentication:** Includes session management and pre-configured demo access (`investigator@cyberscope.io` / `password123`) alongside custom investigator registration.

---

## 6. Technology Stack

### Backend
- **Framework:** FastAPI (Python 3.11+)
- **Data Validation:** Pydantic v2
- **Relational Store:** SQLAlchemy ORM (SQLite default for zero-friction local execution; PostgreSQL for containerized deployments)
- **Graph Analytics:** NetworkX (in-memory synchronized engine with abstract `IGraphService` interface)
- **AI & LLM Services:** NVIDIA NIM API (`meta/llama-3.2-11b-vision-instruct`) with automated local proxy and deterministic rule-based fallback
- **Data Science:** pandas, NumPy, scikit-learn
- **Testing:** pytest (20/20 passing tests including security checks)

### Frontend
- **Architecture:** Multi-Page Application (MPA) powered by Vite 5.1+
- **Styling:** Custom CyberScope Cyber-Neon Design System (Vanilla CSS with CSS variables, radial glows, glassmorphism, responsive grids)
- **Typography:** Inter & Space Grotesk via Google Fonts
- **Deployment:** Nginx reverse proxy with HTML multi-page resolution

---

## 7. Getting Started & Local Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm 9+ (optional if using Docker or standalone Python server)

---

### A. Quick Start: Local Development (Windows PowerShell)

```powershell
# 1. Clone repository & navigate to project
cd "d:\CYBERSCOPE 2"

# 2. Setup Backend Virtual Environment
cd backend
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
cd "d:\CYBERSCOPE 2\frontend"
npm install
npm run dev
```

* **Frontend Console:** `http://localhost:5173`
* **FastAPI Interactive API Docs:** `http://localhost:8000/docs`
* **Demo Sign In Credentials:** `investigator@cyberscope.io` / `password123`

---

### B. Quick Start: macOS / Linux

```bash
# Backend Setup
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/seed_demo.py
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &

# Frontend Setup
cd ../frontend
npm install
npm run dev
```

---

### C. Standalone Zero-Dependency Python Runner

If Node.js is not installed, the frontend can be served directly using the built-in Python server:

```bash
cd frontend
python server.py 8000
```
Open **`http://localhost:8000/CyberScope.html`** or **`http://localhost:8000/dashboard.html`**.

---

### D. Docker Compose (Full Stack)

CYBERSCOPE includes production-ready Docker Compose orchestration. Database port 5432 remains internal to the container network:

```bash
docker compose up --build
```
- **Frontend Console:** `http://localhost:5173`
- **Backend API:** `http://localhost:8000`
- **PostgreSQL:** Internal Docker bridge network

*Note: On container startup, the backend automatically seeds the database with the "Operation Phantom KYC" demo dataset if the table is empty.*

---

## 8. Demo Scenario: "Operation Phantom KYC"

CYBERSCOPE includes a pre-seeded, deterministic investigative scenario called **"Operation Phantom KYC"**:
- **5 Victims** receiving urgent bank account deactivation / KYC suspension SMS lures.
- **Shared Phishing Domain:** `secure-kyc-update.com`
- **Shared Central Collection UPI ID:** `centralmule99@okaxis`
- **Mule Bank Account:** `AC-MULE-4482`
- **Coordinated Campaign Code:** `CAMP-KYC-01`

### Running the Evaluation Benchmark

To verify detection heuristics against synthetic noise:
```bash
cd backend
python scripts/evaluate_patterns.py
```

To run the automated test suite (20 tests verifying analyzers, ReDoS prevention, and REST contracts):
```bash
cd backend
pytest tests/ -v
```

---

## 9. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
