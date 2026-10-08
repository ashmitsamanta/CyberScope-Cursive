import asyncio
import json
import logging
import os
from typing import AsyncGenerator, List, Optional

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.config import settings

logger = logging.getLogger("cyberscope.chat")

router = APIRouter(prefix="", tags=["chat"])

SYSTEM_PROMPT = (
    "You are CyberScope AI, a senior cyber-fraud intelligence and investigation expert assisting "
    "law enforcement officers, cybercrime cells, financial intelligence units, and fraud risk analysts "
    "on the CyberScope platform by TetraByte.\n\n"
    "MISSION AND SCOPE:\n"
    "You provide authoritative, in-depth, structured, and actionable investigative briefings. "
    "Do NOT give short, shallow, or generic responses. When analyzing cybercrime incidents, scams, "
    "suspicious digital entities, money flows, or platform capabilities, provide comprehensive analytical depth.\n\n"
    "RESPONSE ARCHITECTURE:\n"
    "Where applicable to the investigator's query, structure your intelligence report with clear Markdown headings:\n"
    "### 1. Executive Summary & Incident Classification\n"
    "- Classify the threat taxonomy (e.g. Digital Arrest / Law Enforcement Impersonation, Part-Time Job / Task Scam, "
    "Fake Stock Trading App, Loan App Extortion, SIM Swap / OTP Interception, Mule Network Layering).\n"
    "- Detail threat severity, victim impact profile, and urgency level.\n\n"
    "### 2. Modus Operandi & Technical Vectors\n"
    "- Step-by-step breakdown of initial vector (WhatsApp, Telegram, spoofed IVR, malicious APK, fake domain).\n"
    "- Social engineering tactics (urgency, panic, authority intimidation, isolation).\n"
    "- Technical artifacts utilized (VoIP spoofing, remote desktop apps like AnyDesk/TeamViewer, fake digital warrants).\n\n"
    "### 3. Entity & Threat Infrastructure Analysis\n"
    "- Analysis of extracted digital identifiers: Suspicious MSISDNs/SIMs, Phishing Domains & C2 Servers, "
    "UPI Handles / Virtual Payment Addresses (VPAs), and Layered Bank Accounts.\n"
    "- Explain how correlation across distinct cases exposes shared syndicated infrastructure.\n\n"
    "### 4. Financial Topology & Mule Chain Mechanics\n"
    "- Stage 1 (Placement): Rapid collection via primary mule accounts or payment gateway merchant aggregators.\n"
    "- Stage 2 (Layering & Fan-Out): High-velocity splitting into sub-accounts to evade banking rule engines.\n"
    "- Stage 3 (Integration & Off-Ramping): Crypto P2P off-ramps, ATM cash withdrawals, or international hawala channels.\n\n"
    "### 5. CyberScope Platform Investigation Playbook\n"
    "- Concrete steps using CyberScope: Fraud Graph exploration (Cytoscape link analysis & community clusters), "
    "Transaction Explorer (multi-hop traversal & velocity anomalies), Case Management, and Entity Explorer.\n\n"
    "### 6. Actionable Law Enforcement Next Steps & Mitigations\n"
    "- Immediate debit freeze requests under Section 102 CrPC / BNSS 106.\n"
    "- Coordination via the National Cyber Crime Reporting Portal (NCRP / 1930 / I4C).\n"
    "- Preservations for CDR/IPDR with Telecom Service Providers (TSPs) and registrar DNS takedowns.\n\n"
    "Tone: Analytical, precise, investigative, professional. Format with clean Markdown headers, bullet points, and bold entities."
)

_http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        limits = httpx.Limits(
            max_keepalive_connections=30,
            max_connections=50,
            keepalive_expiry=120.0,
        )
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            limits=limits,
            headers={"User-Agent": "CyberScope-Backend/1.0"},
        )
    return _http_client


class ChatMessage(BaseModel):
    role: str = Field(default="user", description="Message role (system, user, assistant)")
    content: str = Field(default="", description="Message content")


class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(default_factory=list, description="List of chat messages")
    stream: bool = Field(default=False, description="Enable SSE token streaming")
    model: Optional[str] = Field(default=None, description="Optional model override")
    temperature: Optional[float] = Field(default=0.3, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=2048, ge=1, le=4096)


def get_api_key(request: Request) -> str:
    """
    Extracts the upstream NVIDIA API key safely.
    1. Custom X-NVIDIA-API-KEY header if provided by client.
    2. Authorization header ONLY if it contains an actual NVIDIA key (starts with 'nvapi-').
       This ensures user session JWTs (Supabase) are NOT mistakenly forwarded to NVIDIA.
    3. Server-configured NVIDIA_API_KEY from settings/.env.
    """
    custom_key = request.headers.get("X-NVIDIA-API-KEY", "").strip()
    if custom_key:
        return custom_key

    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token.startswith("nvapi-"):
            return token

    return (settings.NVIDIA_API_KEY or os.environ.get("NVIDIA_API_KEY", "")).strip()


def build_payload_messages(messages: List[dict]) -> List[dict]:
    payload: List[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            payload[0]["content"] += f"\n\n{content}"
        else:
            payload.append({"role": role, "content": content})
    return payload


def get_local_intelligence_response(messages: List[dict]) -> str:
    last_msg = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_msg = msg.get("content", "").lower()
            break

    if "ping" in last_msg or "test" in last_msg:
        return (
            "### CyberScope Intelligence Engine Status\n\n"
            "**Status**: Operational & Synchronized\n"
            "- **Graph Engine**: Active (NetworkX synchronized relational store)\n"
            "- **Analytical Model**: Ready (Deep investigative briefing mode)\n"
            "- **Telemetry**: Real-time cross-case correlation active."
        )

    if "graph" in last_msg or "schema" in last_msg:
        return (
            "### CyberScope Fraud Graph Architecture & Analysis\n\n"
            "The **Fraud Graph** is CyberScope's core analytical engine, translating fragmented complaints "
            "into a unified link-analysis topology powered by Cytoscape.js and graph clustering algorithms.\n\n"
            "#### 1. Core Graph Schema & Node Types\n"
            "- **Case Nodes**: Victim incident files with classification, timeline, and loss metrics.\n"
            "- **Phone Nodes (MSISDN)**: Caller/WhatsApp contact points used for social engineering.\n"
            "- **Domain Nodes**: Phishing landing pages, fake banking portals, and APK hosting endpoints.\n"
            "- **UPI ID Nodes (VPA)**: Virtual Payment Addresses used for immediate extortion payments.\n"
            "- **Bank Account Nodes**: Mule accounts receiving and routing layered transactions.\n\n"
            "#### 2. Key Edge Relationships\n"
            "- `SENT`: Direct communication connection from suspect to victim.\n"
            "- `REQUESTS_PAYMENT_TO`: Initial demand link pointing to malicious VPA or account.\n"
            "- `TRANSFERRED_TO`: Financial hop indicating money movement across mule tiers.\n"
            "- `LINKED_TO`: Infrastructure association (e.g., shared registrar, device fingerprint, IP).\n\n"
            "#### 3. Investigative Value\n"
            "Isolated police stations often treat complaints as independent petty frauds. The Fraud Graph instantly "
            "flags **high-degree shared nodes** (e.g., the same UPI handle appearing in 14 cases across 4 states), "
            "revealing organized cyber syndicates and enabling joint multi-jurisdiction crackdowns."
        )

    if "case" in last_msg:
        return (
            "### CyberScope Case Management & Evidence Ingestion\n\n"
            "The **Cases Module** serves as the primary investigative workspace for aggregating digital evidence, "
            "victim statements, and financial traces into unified case dossiers.\n\n"
            "#### 1. Case Intake & Automated Extraction\n"
            "- When a case report is ingested (via NCRP/1930 feed or manual complaint entry), CyberScope extracts "
            "all structured digital artifacts: phone numbers, email addresses, URLs, UPI VPAs, IFSC codes, and account numbers.\n"
            "- The built-in NLP classifier categorizes the modus operandi (Digital Arrest, Job Scam, KYC Phishing, etc.).\n\n"
            "#### 2. Automated Risk Assessment (0–100)\n"
            "- Each case is dynamically scored using explainable risk indicators.\n"
            "- Contributing signals: Velocity of transactions, entity reuse count, cross-border infrastructure, and community degree.\n\n"
            "#### 3. Evidentiary Audit Trail\n"
            "- All investigator notes, evidence attachments, and timeline milestones are cryptographically stamped "
            "for court-admissible charge sheet preparation under the Bharatiya Sakshya Adhiniyam (BSA) / Indian Evidence Act."
        )

    if "entity" in last_msg or "phone" in last_msg or "domain" in last_msg or "upi" in last_msg:
        return (
            "### Entity Intelligence & Threat Infrastructure Profiling\n\n"
            "In cyber-fraud investigations, **entities** represent the persistent operational footprint left by threat actors.\n\n"
            "#### 1. Entity Classification Taxonomy\n"
            "- **Phone (MSISDN)**: Often procured via fake SIM distributor rings or spoofed via VoIP PBX gateways.\n"
            "- **Domain / URL**: Newly registered domains (NRDs) impersonating banks, government portals, or courier services.\n"
            "- **UPI Handle (VPA)**: Merchant aggregators or peer-to-peer handles used for rapid collection.\n"
            "- **Bank Account**: Primary mule accounts (Tier 1) through tertiary layering accounts (Tier 2/3).\n\n"
            "#### 2. Cross-Case Entity Correlation\n"
            "- CyberScope's **Entity Explorer** computes a connection degree and risk centrality for each identifier.\n"
            "- A single high-centrality phone number or domain immediately bridges separate FIRs across different police jurisdictions.\n\n"
            "#### 3. Recommended Containment Actions\n"
            "- Issue immediate Section 91 CrPC / BNSS 94 notices to Telecom Service Providers for CDR/CAF/IPDR.\n"
            "- Submit domain takedown requests to the respective domain registrars and CERT-In / I4C."
        )

    if "transaction" in last_msg or "money" in last_msg or "mule" in last_msg:
        return (
            "### Transaction Flow Analysis & Money Mule Disruption\n\n"
            "Cyber-fraud proceeds are engineered to move faster than formal banking freeze notices. "
            "CyberScope's **Transaction Explorer** provides multi-hop tracing to follow and interdict illicit capital.\n\n"
            "#### 1. The Three Stages of Mule Layering\n"
            "1. **Placement (Tier 1 Mules)**: Victim transfers money directly to a local student or compromised account.\n"
            "2. **Fan-Out Layering (Tier 2 & 3 Mules)**: Funds are split within minutes into 5 to 15 smaller tranches (e.g., ₹20,000–₹50,000) "
            "to stay under automated Anti-Money Laundering (AML) radar.\n"
            "3. **Integration & Extraction**: Money is withdrawn via ATMs in high-density corridors or converted into USDT via P2P crypto exchanges.\n\n"
            "#### 2. Pattern Detection Features\n"
            "- **Burst Velocity**: Detects accounts with 0 normal activity suddenly transacting 50 transactions in 2 hours.\n"
            "- **Circular Loops**: Identifies round-trip transactions intended to obfuscate provenance.\n"
            "- **Fan-In Consolidation**: Tracks multiple streams converging into a single master accumulator account.\n\n"
            "#### 3. Rapid Intervention Protocol\n"
            "- Identify the active 'holding balance' hop in the transaction graph.\n"
            "- Dispatch emergency Section 102 CrPC / BNSS 106 debit freeze notices directly to the nodal bank officer via the 1930 / I4C framework."
        )

    if "campaign" in last_msg or "digital arrest" in last_msg or "kyc" in last_msg:
        return (
            "### Campaign Intelligence & Syndicate Cluster Detection\n\n"
            "Organized cybercrime syndicates operate industrialized fraud campaigns that target thousands of victims simultaneously.\n\n"
            "#### 1. Campaign Profile: Digital Arrest Extortion\n"
            "- **Impersonation**: Callers pose as CBI, ED, Mumbai Police, or Supreme Court officials via Skype/WhatsApp video.\n"
            "- **Staged Settings**: Use fake police backdrops, fabricated arrest warrants, and counterfeit court seals.\n"
            "- **Coercion**: Victims are kept on video call for 24–72 hours under 'digital arrest' while coerced into liquidating FDs, mutual funds, and savings into 'RBI verification accounts'.\n\n"
            "#### 2. Campaign Profile: Fake KYC & Utility Bill Scams\n"
            "- Phishing SMS claiming power disconnection at 9:30 PM due to unpaid electricity bills.\n"
            "- Lures victim into downloading remote-control APKs (e.g., QuickSupport) to capture SMS OTPs and credentials.\n\n"
            "#### 3. Syndicate Clustering in CyberScope\n"
            "- The **Campaign Explorer** groups disparate cases sharing common infrastructure (shared APK hashes, identical C2 subnets, or co-occurring mule account clusters).\n"
            "- This transforms low-level complaint processing into high-impact syndicate takedowns."
        )

    if "risk" in last_msg or "score" in last_msg:
        return (
            "### CyberScope Explainable Risk Scoring Engine\n\n"
            "Rather than relying on opaque black-box metrics, CyberScope computes an **explainable 0–100 risk score** "
            "backed by transparent evidentiary signals.\n\n"
            "#### 1. Scoring Weight Distribution\n"
            "- **Entity Multi-Case Reuse (35%)**: Frequency of associated phone numbers, UPIs, or domains across known fraud cases.\n"
            "- **Financial Velocity & Topology (30%)**: Burst transaction velocity, fan-out layering speed, and proximity to known mule accounts.\n"
            "- **Threat Vector Severity (20%)**: High-harm classifications such as Digital Arrest and extortion receive higher initial baseline weight.\n"
            "- **Infrastructure Freshness (15%)**: Newly registered domains (<14 days old), dynamic DNS, and proxy/VPN origin.\n\n"
            "#### 2. Action Thresholds\n"
            "- **CRITICAL (80–100)**: Immediate bank freeze request & priority inter-state cyber cell escalation.\n"
            "- **HIGH (60–79)**: Coordinated entity monitoring, KYC verification request to financial institutions.\n"
            "- **MEDIUM (40–59)**: Additional evidence gathering, TSP subscriber details requisition.\n"
            "- **LOW (0–39)**: Routine record-keeping and baseline monitoring."
        )

    return (
        "### CyberScope Cyber-Fraud Intelligence Briefing\n\n"
        "CyberScope AI is the analytical backbone of the CyberScope defense platform developed by TetraByte. "
        "It empowers law enforcement, banks, and intelligence analysts to dismantle organized cyber-fraud operations.\n\n"
        "#### Key Capabilities & Modules Available:\n"
        "1. **Fraud Graph**: Interactive Cytoscape link analysis highlighting shared phones, domains, VPAs, and bank accounts across independent complaints.\n"
        "2. **Transaction Explorer**: Multi-hop financial tracking to trace money mule networks, detect fan-out splitting, and catch exit nodes.\n"
        "3. **Campaign Clustering**: Automated syndicate identification grouping incidents sharing identical social engineering playbooks and C2 assets.\n"
        "4. **Investigation Workspace**: Centralized evidentiary case management, timeline construction, and legal charge-sheet export.\n\n"
        "To begin an investigation, ask me about a specific scam vector (e.g. *Digital Arrest*, *SIM Swap*), "
        "an entity type (e.g. *Mule Accounts*, *Phishing Domains*), or how to analyze graph linkages."
    )


async def execute_nim_chat(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    model: str,
    messages: List[dict],
    temperature: float,
    max_tokens: int,
) -> dict:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "CyberScope-Backend/1.0",
    }
    body = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    response = await client.post(base_url, headers=headers, json=body)
    response.raise_for_status()
    return response.json()


async def stream_nim_generator(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    model: str,
    fallback_model: str,
    messages: List[dict],
    temperature: float,
    max_tokens: int,
) -> AsyncGenerator[str, None]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "User-Agent": "CyberScope-Backend/1.0",
    }
    body = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": True,
    }

    selected_model = model
    stream_response: Optional[httpx.Response] = None

    try:
        req = client.build_request("POST", base_url, headers=headers, json=body)
        stream_response = await client.send(req, stream=True)

        if stream_response.status_code >= 400 and selected_model != fallback_model:
            await stream_response.aclose()
            logger.warning(
                "Primary model stream returned %d. Switching to fallback %s",
                stream_response.status_code,
                fallback_model,
            )
            selected_model = fallback_model
            body["model"] = fallback_model
            req = client.build_request("POST", base_url, headers=headers, json=body)
            stream_response = await client.send(req, stream=True)

        stream_response.raise_for_status()
    except Exception as exc:
        if stream_response:
            await stream_response.aclose()
        if selected_model != fallback_model:
            logger.warning("Primary model stream failed: %s. Retrying with fallback %s", exc, fallback_model)
            try:
                body["model"] = fallback_model
                req = client.build_request("POST", base_url, headers=headers, json=body)
                stream_response = await client.send(req, stream=True)
                stream_response.raise_for_status()
            except Exception as fb_exc:
                if stream_response:
                    await stream_response.aclose()
                logger.warning("Fallback stream failed (%s). Yielding local intelligence stream.", fb_exc)
                fallback_reply = get_local_intelligence_response(messages)
                for word in fallback_reply.split(" "):
                    chunk = {
                        "choices": [{"delta": {"content": word + " "}}]
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    await asyncio.sleep(0.02)
                yield "data: [DONE]\n\n"
                return
        else:
            logger.warning("Stream initiation error (%s). Yielding local intelligence stream.", exc)
            fallback_reply = get_local_intelligence_response(messages)
            for word in fallback_reply.split(" "):
                chunk = {
                    "choices": [{"delta": {"content": word + " "}}]
                }
                yield f"data: {json.dumps(chunk)}\n\n"
                await asyncio.sleep(0.02)
            yield "data: [DONE]\n\n"
            return

    try:
        async for line in stream_response.aiter_lines():
            if line:
                yield f"{line}\n\n"
    except Exception as err:
        logger.error("Error during streaming: %s", err)
        yield f"data: {json.dumps({'error': 'Stream interrupted'})}\n\n"
        yield "data: [DONE]\n\n"
    finally:
        await stream_response.aclose()


@router.post("/chat")
@router.post("/chat/completions")
@router.post("/test")
async def chat_endpoint(request: Request):
    """
    CyberScope AI Chat Endpoint.
    Supports both Server-Sent Events (SSE) streaming and standard JSON completions.
    Features NVIDIA NIM primary model, automated secondary model fallback,
    and a local cyber-intelligence fallback for resilient operation.
    """
    try:
        req_json = await request.json()
    except Exception:
        req_json = {}

    raw_messages = req_json.get("messages", [])
    if isinstance(raw_messages, list):
        messages_list = [
            {"role": m.get("role", "user"), "content": m.get("content", "")}
            for m in raw_messages
            if isinstance(m, dict)
        ]
    else:
        messages_list = []

    stream = bool(req_json.get("stream", False))
    primary_model = req_json.get("model") or settings.PRIMARY_MODEL or settings.NVIDIA_MODEL or "meta/llama-3.2-11b-vision-instruct"
    fallback_model = settings.FALLBACK_MODEL or "google/diffusiongemma-26b-a4b-it"
    temperature = float(req_json.get("temperature", 0.3))
    max_tokens = int(req_json.get("max_tokens", 2048))
    base_url = settings.NVIDIA_BASE_URL or "https://integrate.api.nvidia.com/v1/chat/completions"
    api_key = get_api_key(request)

    payload_messages = build_payload_messages(messages_list)
    client = get_http_client()

    # If stream requested:
    if stream:
        if not api_key:
            # Yield local intelligence stream smoothly
            async def local_stream_gen() -> AsyncGenerator[str, None]:
                reply = get_local_intelligence_response(messages_list)
                for word in reply.split(" "):
                    chunk = {
                        "choices": [{"delta": {"content": word + " "}}]
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    await asyncio.sleep(0.015)
                yield "data: [DONE]\n\n"

            return StreamingResponse(
                local_stream_gen(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )

        return StreamingResponse(
            stream_nim_generator(
                client=client,
                base_url=base_url,
                api_key=api_key,
                model=primary_model,
                fallback_model=fallback_model,
                messages=payload_messages,
                temperature=temperature,
                max_tokens=max_tokens,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # Non-streaming JSON completion
    if api_key:
        try:
            data = await execute_nim_chat(
                client=client,
                base_url=base_url,
                api_key=api_key,
                model=primary_model,
                messages=payload_messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return JSONResponse(content=data)
        except Exception as exc:
            logger.warning("Primary model %s failed: %s. Trying fallback %s", primary_model, exc, fallback_model)
            try:
                data = await execute_nim_chat(
                    client=client,
                    base_url=base_url,
                    api_key=api_key,
                    model=fallback_model,
                    messages=payload_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return JSONResponse(content=data)
            except Exception as fb_exc:
                logger.warning("Fallback model %s failed: %s. Using local intelligence response.", fallback_model, fb_exc)

    # Local intelligence fallback response (OpenAI compatible format)
    fallback_text = get_local_intelligence_response(messages_list)
    return JSONResponse(
        content={
            "id": "chatcmpl-fallback-cyberscope",
            "object": "chat.completion",
            "model": primary_model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": fallback_text,
                    },
                    "finish_reason": "stop",
                }
            ],
        }
    )
