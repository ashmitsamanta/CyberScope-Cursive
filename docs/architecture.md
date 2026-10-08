# CYBERSCOPE — Architecture & Technical Design

## 1. System Overview
CYBERSCOPE is an explainable cyber-fraud intelligence and investigation platform engineered for defensive security analysts, fraud investigators, and incident response teams. Its primary goal is not to prove criminal guilt, but to connect fragmented evidence, score risk transparently, trace simulated money movements, detect coordinated campaigns, and assist human investigators via evidence-grounded AI.

```
Synthetic Telemetry
       ↓
Data Ingestion (Regex & Pattern Parsers)
       ↓
Entity Extraction & Normalization
       ↓
Relationship Construction
       ↓
In-Memory Fraud Graph (NetworkX)
       ↓
Behavioral & Anomaly Engine
       ↓
Campaign Detection & Clustering
       ↓
Money-Flow Traversal Engine (BFS)
       ↓
Case Chronological Timeline
       ↓
Explainable Grounded AI (CYBER-ASSIST)
       ↓
CyberScope Investigation Suite (Cyber-Neon MPA + Vite)
```

---

## 2. Core Subsystems

### 2.1 Entity Extraction & Normalization
- **Extractors:** Deterministic regex extractors identify phone numbers (+91 synthetic numbers), domains, URLs, UPI handles (`id@bank`), bank account tokens, and currency amounts.
- **Normalizers:** Ensures strings like `+91 90000 00001`, `9000000001`, and `+919000000001` resolve to the exact same synthetic entity `+919000000001`. Domain normalizers strip schemes, `www.`, ports, and trailing paths.

### 2.2 Relational & Graph Storage
- **Relational Layer:** SQLAlchemy ORM managing SQLite for local frictionless execution and PostgreSQL for containerized deployments.
- **Graph Service Interface (`IGraphService`):**
  - Active Implementation: `NetworkXGraphService` builds an in-memory directed graph synchronized with the relational store for fast, deterministic topology exploration and cycle detection.
  - Interface Pattern: Designed with an abstract interface (`IGraphService`) should external graph database adapters be integrated in future work.
- **Algorithms:** $k$-hop neighborhood expansion, shortest path discovery, directed cycle detection (circular fund movements), weakly connected components, and degree centrality anomaly detection.

### 2.3 Explainable Risk Engine
- Capped at 100 points, avoiding misleading "probabilities".
- Transparent point breakdown with itemized signal codes:
  - `KNOWN_SUSPICIOUS_IDENTIFIER` (+20 pts)
  - `SHARED_INFRASTRUCTURE` (+15 pts)
  - `MULTI_CASE_ASSOCIATION` (+15 pts)
  - `SUSPICIOUS_COMMUNICATION_PATTERN` (+15 pts)
  - `RAPID_FUND_DISPERSION` (+15 pts)
  - `RAPID_TRANSACTION_BURST` (+15 pts)
  - `UNUSUAL_AMOUNT` (+4 to +10 pts)
- Severity classifications: LOW (0–39), MEDIUM (40–69), HIGH (70–89), CRITICAL (90–100).

### 2.4 Money-Flow Trace Engine
- BFS graph traversal from starting victim or fraudulent transaction.
- Classifies nodes into roles: `SOURCE`, `MULE`, `INTERMEDIARY`, `DESTINATION`.
- Flags behavioral patterns: `FAN_OUT` (one account distributing to $\ge 3$ recipients), `RAPID_LAYERING` ($\ge 3$ sequential hops), and `CIRCULAR_MOVEMENT` ($A \to B \to C \to A$).

### 2.5 CYBER-ASSIST (Grounded AI Investigator)
- Implements `AIProvider` abstraction.
- Default: `DeterministicExpertProvider` produces verifiable, citation-backed analyses (`[CS-1024]`, `[DOMAIN-1]`, `[TX-9000]`) grounded directly in observed database records.
- Optional: `OpenAIProvider` passes structured context JSON to OpenAI-compatible LLMs under strict grounding system prompts.
- Explicitly separates: **Observed Evidence**, **Calculated Signals**, **Inferences**, and **Uncertainties**.

### 2.6 CyberScope Cyber-Neon Multi-Page Suite
- Modern glassmorphism dark aesthetic with custom typography (`Inter`, `Space Grotesk`) and micro-animations.
- Multi-page application structure powered by Vite with Rollup multi-page inputs:
  - `CyberScope.html` / `index.html`: Showcase landing, live AI engine, interactive modules.
  - `dashboard.html`: Live telemetry and recent investigations.
  - `cases.html`: Incident registry and ingestion modal.
  - `fraud-graph.html`: Node-and-link topological network exploration.
  - `entity-explorer.html`: 360-degree identifier dossiers.
  - `transaction-explorer.html`: Financial ledger and flow metrics.
  - `campaign-explorer.html`: Syndicate correlation clusters.
  - `investigation-workspace.html`: Case evidence, timeline, notes, and report export.
  - `signin.html` & `register.html`: Identity authentication with pre-seeded demo fallback.

### 2.7 NVIDIA NIM API Proxy Architecture
- Resolves browser CORS restrictions by proxying `/api/chat` through the FastAPI backend to NVIDIA NIM (`meta/llama-3.2-11b-vision-instruct`).
- Handles upstream connection errors with automatic fallback to built-in deterministic cyber-intelligence responses.

### 2.8 Supabase Authentication & Identity Architecture
- **Supabase Auth Client (`frontend/assets/supabase-client.js`):** Unified identity and session management wrapping `@supabase/supabase-js`.
  - Email & password registration with investigator metadata (name, phone, role, organization).
  - Persistent JWT sessions (`localStorage` + auto-refresh tokens).
  - In-browser configuration drawer allowing instant connection to any Supabase project or dynamic server config via `GET /api/auth/config`.
  - Built-in zero-friction demo mode (`investigator@cyberscope.io` / `password123`) for offline evaluation and instant hackathon judging.
- **Backend Token Verification (`backend/app/services/auth_service.py` & `backend/app/api/auth.py`):**
  - Supabase JWT validation supporting `SUPABASE_JWT_SECRET` (HS256) and direct verification via Supabase Auth REST API.
  - Dependency injection `get_current_user` for securing backend routes.
  - Graceful development fallback when `REQUIRE_AUTH=False`, with strict enforcement toggleable in `.env`.

