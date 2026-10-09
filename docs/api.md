# CYBERSCOPE — REST API Documentation

Base URL: `http://localhost:8000/api`

Interactive Swagger Docs: `http://localhost:8000/docs`

---

## 1. System & Statistics

### `GET /health`
Returns service status, environment, active graph engine, and mandatory synthetic data disclaimer.

### `GET /stats/dashboard`
Returns high-level platform KPIs:
- Total cases, high risk cases, critical cases, linked entities, campaigns, transactions
- Risk distribution breakdown (Low, Medium, High, Critical)
- Top active campaigns and recent high-risk cases queue.

---

## 2. Cases

### `GET /cases`
Query parameters:
- `status` (NEW, INVESTIGATING, ESCALATED, RESOLVED)
- `severity` (LOW, MEDIUM, HIGH, CRITICAL)
- `min_risk` (float)
- `search` (case number or keyword)
- `limit`, `offset`

### `GET /cases/{case_id}`
Returns comprehensive case details including itemized `risk_breakdown`, counts of transactions/messages/indicators, and parent campaign reference.

### `GET /cases/{case_id}/timeline`
Returns unified chronological evidence stream (communications, threat signals, transfers).

### `POST /cases/ingest`
Ingests raw unformatted complaint text or SMS, runs deterministic entity extraction, classifies scam markers, and links extracted items to the fraud graph.

---

## 3. Fraud Graph

### `GET /graph`
Returns global network nodes and edges (up to specified `limit`).

### `GET /graph/case/{case_id}?hops=2`
Returns localized subgraph anchored on a specific case.

### `GET /graph/entity/{entity_id}?hops=2`
Expands graph around an arbitrary entity up to $k$-hops.

### `GET /graph/shortest-path?source_id={id}&target_id={id}`
Finds shortest investigative path between two entities.

### `GET /graph/shared-infrastructure`
Finds common nexus nodes (domains, phones, UPIs) connected to $\ge 2$ distinct cases.

### `GET /graph/circular-flows`
Detects directed cycles in money transfers ($A \to B \to C \to A$).

---

## 4. Financial Transactions & Fund Tracing

### `GET /transactions`
List financial transactions with counterparty values, amounts, channels, and flagged statuses.

### `POST /transactions/trace-funds`
Body:
```json
{
  "start_transaction_id": 1,
  "max_hops": 4,
  "time_window_hours": 72
}
```
Returns multi-hop reachable fund tree, node roles (`SOURCE`, `MULE`, `INTERMEDIARY`, `DESTINATION`), and detected flow anomalies (`FAN_OUT`, `RAPID_LAYERING`, `CIRCULAR_MOVEMENT`).

---

## 5. Coordinated Campaigns

### `GET /campaigns`
List active coordinated campaigns and cluster statistics.

### `GET /campaigns/{campaign_id_or_code}`
Returns campaign deep-dive, shared infrastructure fingerprints, and linked incident files.

---

## 6. CYBER-ASSIST AI Investigator

### `POST /investigations/query`
Body:
```json
{
  "case_id": 1,
  "query": "Why was this case flagged?"
}
```
Returns evidence-grounded answer, itemized observed evidence, calculated signals, citations (`[CS-1024]`, `[DOMAIN-1]`, `[TX-9000]`), and recommended next defensive actions.

### `POST /investigations/summary`
Generates structured executive investigation brief for a case.

---

## 7. Natural-Language Search

### `GET /search?q={query}`
Controlled intent parser translating search prompts into safe parameterized queries.

---

## 8. CyberScope AI & NVIDIA NIM API Proxy

### `POST /chat`
Proxies chat completions requests to NVIDIA NIM (`meta/llama-3.2-11b-vision-instruct`) with zero browser CORS restrictions, falling back to local CyberScope intelligence if upstream is unreachable.

Headers:
- `Authorization: Bearer <NVIDIA_API_KEY>` (optional, defaults to configured key)
- `Content-Type: application/json`

Body:
```json
{
  "model": "meta/llama-3.2-11b-vision-instruct",
  "messages": [
    { "role": "user", "content": "Explain the indicators of compromise in KYC phishing." }
  ],
  "temperature": 0.3,
  "max_tokens": 450
}
```

Response:
Standard OpenAI / NVIDIA NIM chat completion format (`choices[0].message.content`).

---

## 9. Authentication & Supabase

### `GET /auth/config`
Returns public Supabase client initialization configuration:
```json
{
  "supabase_url": "https://your-project.supabase.co",
  "supabase_anon_key": "eyJhbGciOiJIUzI1NiIsInR5...",
  "configured": true,
  "auth_required": true
}
```

### `GET /auth/me`
Returns current authenticated investigator profile claims extracted from the Supabase JWT.
Headers:
- `Authorization: Bearer <SUPABASE_JWT_ACCESS_TOKEN>`

Response:
```json
{
  "status": "authenticated",
  "user": {
    "id": "uuid-here",
    "email": "investigator@cyberscope.io",
    "name": "Special Agent Ray",
    "role": "Lead Investigator",
    "phone": "+919876543210",
    "organization": "National Cyber Crime Cell",
    "is_demo": false
  }
}
```

### `POST /auth/verify`
Verifies a Supabase access token payload.
Body:
```json
{
  "access_token": "<SUPABASE_JWT_ACCESS_TOKEN>"
}
```
Response:
```json
{
  "valid": true,
  "user": { ... }
}
```

