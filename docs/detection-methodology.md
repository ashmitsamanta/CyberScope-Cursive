# CYBERSCOPE — Fraud Detection & Behavioral Analytics Methodology

## 1. Core Philosophy: The Evidence Chain
Cyber-enabled financial fraud rarely occurs as an isolated occurrence. Criminal operations rely on reused infrastructure to achieve economic scale:
1. Reused phishing domains and URL landing pages.
2. Reused SMS gateway phone senders.
3. Reused mule bank accounts and UPI payment handles.
4. Layered fund transfers to fragment balances below reporting limits.

CYBERSCOPE systematically correlates evidence across independent incident reports to reveal the underlying operational syndicate.

---

## 2. Behavioral & Anomaly Detection Heuristics

### 2.1 Velocity & Burst Analysis
- **Definition:** Quantifies the frequency of transactions occurring within tight temporal intervals (1 minute, 5 minutes, 15 minutes).
- **Rule:** If an account triggers $\ge 4$ transactions within a 15-minute window, the engine flags `RAPID_TRANSACTION_BURST` (+15 points).

### 2.2 Fan-Out & Fan-In Ratios
- **Fan-Out (One-to-Many):** A single aggregator account disperses funds across $\ge 3$ distinct beneficiaries within a 1-hour window. Flags `HIGH_FAN_OUT` (+15 points).
- **Fan-In (Many-to-One):** An account receives deposits from $\ge 3$ distinct originators within a 1-hour window. Flags `HIGH_FAN_IN` (+15 points).

### 2.3 Rapid Fund Dispersion (Mule Behavior)
- **Heuristic:** An inflow of $\ge ₹10,000$ is followed by outward transfers of $\ge 75\%$ of the received volume within 30 minutes across $\ge 2$ recipients.
- **Signal:** `RAPID_FUND_DISPERSION` (+15 points).

### 2.4 Dormancy-to-Burst Detection
- **Heuristic:** An account with zero transaction activity for $> 30$ days suddenly initiates high-velocity or high-value transfers.
- **Signal:** `DORMANCY_TO_BURST` (+15 points).

### 2.5 Circular Fund Flow Detection
- **Heuristic:** Traverses directed transfer edges to identify cycles of length $2 \le k \le 5$ ($A \to B \to C \to A$) intended to wash funds or simulate artificial transaction volume.
- **Signal:** `CIRCULAR_MOVEMENT` (+20 points).

---

## 3. Communication Content Analysis
Deterministic token & regex rules detect deceptive social engineering:
- **Authority Impersonation:** Regulators (RBI), law enforcement (Cyber Crime Cell, Police), utility boards, and financial institutions.
- **Coercive Urgency:** Deadlines under 2 hours, immediate deactivation threats.
- **Threat Markers:** Account blocking, SIM suspension, arrest warrants.
- **Credential Harvesting:** OTP, PIN, CVV, or remote screen sharing applications (AnyDesk, TeamViewer).

---

## 4. Graph Analytics & Shared Infrastructure
- **Shared Hubs:** Any infrastructure node (domain, phone, UPI, device) that intersects $\ge 2$ distinct cases is elevated to `SHARED_INFRASTRUCTURE` (+15 points).
- **Multi-Case Clustering:** Intersections across $\ge 3$ cases indicate an active coordinated campaign (`MULTI_CASE_ASSOCIATION`, +15 points).

---

## 5. Risk Score Formulation & Threshold Spectrum

CYBERSCOPE implements an **additive, transparent heuristic risk model capped at 100 points**. It deliberately rejects opaque black-box statistical percentages to ensure complete auditability for fraud analysts.

### Defined Severity Thresholds
| Band | Range | Description |
| :--- | :--- | :--- |
| **LOW** | 0 – 39 | Routine ambient noise or low-priority unlinked complaint |
| **MEDIUM** | 40 – 69 | Elevated indicators requiring analyst triage and review |
| **HIGH** | 70 – 89 | High-confidence multi-vector fraud; active case investigation |
| **CRITICAL** | 90 – 100 | Severe confirmed multi-case cybercrime syndicate requiring immediate emergency freeze |

### Case CS-1024 Exact Arithmetic Breakdown (Score: 84 / 100 — HIGH)
| Signal Code | Points | Evidentiary Rationale |
| :--- | :--- | :--- |
| `KNOWN_SUSPICIOUS_IDENTIFIER` | +20.0 PTS | Direct link to known malicious entity (`+919686579303`, Risk: 85/100) |
| `SHARED_INFRASTRUCTURE` | +15.0 PTS | Identifier recurs across 5 separate investigation files |
| `MULTI_CASE_ASSOCIATION` | +15.0 PTS | Clustered connection in Campaign *Operation Phantom KYC* ($\ge 3$ incidents) |
| `SUSPICIOUS_COMMUNICATION_PATTERN` | +15.0 PTS | Coercive phishing SMS exhibiting urgency and regulatory impersonation |
| `RAPID_FUND_DISPERSION` | +15.0 PTS | Incoming victim funds immediately routed to secondary mule hops |
| `UNUSUAL_AMOUNT` | +4.0 PTS | Stolen transfer volume of ₹48,500 exceeds elevated exposure baseline |
| **Total Calculated Score** | **84.0 PTS** | **Exact match: 20 + 15 + 15 + 15 + 15 + 4 = 84 (HIGH Severity)** |

---

## 6. Evaluation Methodology: Regression Check vs. Held-Out Noisy Testing

To provide transparent and honest performance metrics, CYBERSCOPE separates internal deterministic test fixtures from noisy, held-out evaluation:

### A. Deterministic Regression Check (Planted Fixtures)
- Evaluated on the 42 planted synthetic database cases.
- Validates that established heuristic rules and data models execute without accidental regressions.
- **Precision:** 100.00% | **Recall:** 100.00% | **F1 Score:** 1.0000

### B. Held-Out Adversarial & Noisy Evaluation
- Evaluated against 30 held-out edge cases (15 evasive fraud cases with obfuscated URLs, low-amount structuring, and indirect conversational lures; 15 noisy benign cases with flash-sale transaction velocity, hospital emergency transfers, and public awareness notices).
- **True Positives:** 8 / 15
- **False Positives:** 3 / 15
- **True Negatives:** 12 / 15
- **False Negatives:** 7 / 15
- **Precision:** 72.73%
- **Recall:** 53.33%
- **F1 Score:** 0.6154
- **False Positive Rate (FPR):** 20.00%

*Honest takeaway:* Rule-based heuristics achieve good precision (~73%) on known indicators, but recall drops (~53%) when fraudsters use conversational evasion or off-platform communication.

---

## 7. Known Methodological Limitations

1. **Uncalibrated Heuristic Weights:** Signal weights (+20, +15, +4) are expert hand-tuned priors rather than mathematically calibrated weights learned via logistic regression on live production banking feeds.
2. **Synthetic Telemetry Only:** All accounts, phone numbers, and victim complaints are procedurally generated synthetic models; real-world data contains carrier noise, OCR extraction errors, and dialect variations.
3. **No Authentication or RBAC:** The platform is built as a defensive research console and assumes deployment inside a secure, authenticated network enclave.
4. **Offline Cash Disconnect:** Fund traversal terminates at OTC physical withdrawals or cash-out points absent in digital telemetry.
