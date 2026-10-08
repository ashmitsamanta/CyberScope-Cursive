from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, text
import random
import logging

from app.models.threat_node import ThreatNode
from app.models.entity import Entity
from app.models.case import Case
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.models.message import Message

logger = logging.getLogger("cyberscope.threat_map")

DEFAULT_CASE_MAP: Dict[str, int] = {
    "CS-1024": 1,
    "CS-1025": 2,
    "CS-1026": 3,
    "CS-1027": 4,
    "CS-1028": 5,
    "CS-1029": 6,
    "CS-1030": 7,
    "CS-1031": 8,
    "CS-1032": 9,
    "CS-1033": 10,
    "CS-1034": 11,
    "CS-1035": 12,
}

# Canonical Curated Attacker & Scammer Infrastructure Dataset
# Strictly attacker/scammer infrastructure located across Indian cybercrime hotspots.
# Zero victim IPs, zero victim bank accounts, zero victim personal identity.
INITIAL_THREAT_NODES: List[Dict[str, Any]] = [
    {
        "id": 1,
        "ip": "198.51.100.10",
        "hostname": "phantom-kyc-c2.jamtara.net",
        "asn": "AS133982 Bharti Airtel",
        "isp": "Bharti Airtel Broadband",
        "city": "Jamtara",
        "state": "Jharkhand",
        "pincode": "815351",
        "latitude": 23.9637,
        "longitude": 86.8029,
        "attack_type": "PHISHING_HOST",
        "severity": "CRITICAL",
        "risk_score": 98.5,
        "attack_count": 4820,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /api/v1/sbi/verify-pan-aadhaar HTTP/1.1 (Payload: stolen_creds, otp_bypass_hook)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1024", "CS-1025", "CS-1026", "CS-1027", "CS-1028"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:48:22Z",
        "metadata": {"open_ports": [80, 443, 8080], "os": "Linux Ubuntu 22.04", "ssl_issuer": "Let's Encrypt Simulated", "role": "Primary C2 Phishing Host"}
    },
    {
        "id": 2,
        "ip": "103.15.28.45",
        "hostname": "node-karmatanr-sim.net",
        "asn": "AS45609 Vodafone Idea",
        "isp": "Vodafone Idea Telecom",
        "city": "Karmatanr",
        "state": "Jharkhand",
        "pincode": "815352",
        "latitude": 24.0833,
        "longitude": 86.8333,
        "attack_type": "SIM_BOX_RELAY",
        "severity": "CRITICAL",
        "risk_score": 95.0,
        "attack_count": 2150,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /sim/pool/karmatanr-relay HTTP/1.1 (Payload: 32-channel OTP intercept hook)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1024", "CS-1026"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:50:10Z",
        "metadata": {"open_ports": [5060, 8080], "sim_slots": 32, "gsm_channels": 16}
    },
    {
        "id": 3,
        "ip": "49.36.128.91",
        "hostname": "relay-09.nuh-mewat-telecom.org",
        "asn": "AS55836 Reliance Jio",
        "isp": "Reliance Jio Infocomm",
        "city": "Nuh / Mewat",
        "state": "Haryana",
        "pincode": "122107",
        "latitude": 28.1090,
        "longitude": 77.0033,
        "attack_type": "SIM_BOX_RELAY",
        "severity": "CRITICAL",
        "risk_score": 94.0,
        "attack_count": 2830,
        "target_sector": "Telecommunications",
        "malicious_request_sample": "POST /simbox/routing/push HTTP/1.1 (SIP VoIP GSM Gateway redirecting 40 concurrent lures)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1024", "CS-1028"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:51:10Z",
        "metadata": {"open_ports": [5060, 8000], "sim_slots": 64, "concurrent_calls": 38}
    },
    {
        "id": 4,
        "ip": "103.242.116.14",
        "hostname": "upi-skimmer-03.bharatpur.in",
        "asn": "AS45609 Vodafone Idea",
        "isp": "Vodafone Idea Telecom",
        "city": "Bharatpur",
        "state": "Rajasthan",
        "pincode": "321001",
        "latitude": 27.2152,
        "longitude": 77.4930,
        "attack_type": "UPI_MULE_VECTOR",
        "severity": "CRITICAL",
        "risk_score": 91.5,
        "attack_count": 980,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /api/v3/gateway/upi/spoof-vpa HTTP/1.1 (Payload: {\"vpa\": \"centralmule99@okaxis\", \"amount\": 48500})",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1024", "CS-1027"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:42:05Z",
        "metadata": {"mule_vpasingle": "centralmule99@okaxis", "layering_hops": 3}
    },
    {
        "id": 5,
        "ip": "122.161.49.202",
        "hostname": "c2-botnet.gurugram-cyber.tech",
        "asn": "AS133982 Bharti Airtel",
        "isp": "Airtel Fiber Gurugram",
        "city": "Gurugram",
        "state": "Haryana",
        "pincode": "122001",
        "latitude": 28.4595,
        "longitude": 77.0266,
        "attack_type": "MALWARE_C2",
        "severity": "CRITICAL",
        "risk_score": 95.0,
        "attack_count": 3410,
        "target_sector": "Govt Services",
        "malicious_request_sample": "POST /android/c2/beacon HTTP/1.1 (SMS Forwarder Trojan ping: dev_imei_intercept)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1025", "CS-1029"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:53:01Z",
        "metadata": {"active_zombies": 312, "trojan_family": "SpyNote.v12"}
    },
    {
        "id": 6,
        "ip": "182.74.88.115",
        "hostname": "callcenter-voip-relay.kolkata.in",
        "asn": "AS9498 Bharti Airtel",
        "isp": "Airtel Business Kolkata",
        "city": "Salt Lake Sector V, Kolkata",
        "state": "West Bengal",
        "pincode": "700091",
        "latitude": 22.5804,
        "longitude": 88.4177,
        "attack_type": "FAKE_KYC_GATEWAY",
        "severity": "HIGH",
        "risk_score": 87.0,
        "attack_count": 1120,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "GET /auth/kyc-v4/session?token=phish_session_91823 HTTP/1.1",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1025", "CS-1026"],
        "status": "HONEYPOT_TRAPPED",
        "last_seen": "2026-10-02T13:30:19Z",
        "metadata": {"honeypot_trap": "T-POT Cowrie & Dionaea", "sessions_captured": 84}
    },
    {
        "id": 7,
        "ip": "115.110.201.78",
        "hostname": "crypto-mule-fastpay.surat.biz",
        "asn": "AS17488 Hathway Cable and Datacom",
        "isp": "Hathway Broadband",
        "city": "Surat",
        "state": "Gujarat",
        "pincode": "395003",
        "latitude": 21.1702,
        "longitude": 72.8311,
        "attack_type": "UPI_MULE_VECTOR",
        "severity": "HIGH",
        "risk_score": 84.5,
        "attack_count": 760,
        "target_sector": "E-Commerce / Logistics",
        "malicious_request_sample": "POST /p2p/crypto/layering HTTP/1.1 (Payload: INR to USDT mule wash 35,000)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1024"],
        "status": "BLOCKED_BY_FIREWALL",
        "last_seen": "2026-10-02T12:15:00Z",
        "metadata": {"block_rule": "FW-ACL-SURAT-01", "crypto_bridge": "P2P Telegram Escrow"}
    },
    {
        "id": 8,
        "ip": "106.51.72.33",
        "hostname": "brute-force-worker01.blr.net",
        "asn": "AS24309 Atria Convergence Technologies (ACT)",
        "isp": "ACT Fibernet Bengaluru",
        "city": "Bengaluru",
        "state": "Karnataka",
        "pincode": "560001",
        "latitude": 12.9716,
        "longitude": 77.5946,
        "attack_type": "BRUTE_FORCE_STUFFER",
        "severity": "HIGH",
        "risk_score": 86.0,
        "attack_count": 4190,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /netbanking/api/v2/login HTTP/1.1 (Credential Stuffing: 1,420 hits/min)",
        "active_campaign": "State Electricity Billing Lure",
        "linked_case_numbers": ["CS-1030"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:52:40Z",
        "metadata": {"wordlist_size": "1.2M hashes", "concurrency": 60}
    },
    {
        "id": 9,
        "ip": "103.21.58.12",
        "hostname": "ddos-flood-master.mum.tech",
        "asn": "AS4755 Tata Communications",
        "isp": "Tata Communications Mumbai",
        "city": "Mumbai",
        "state": "Maharashtra",
        "pincode": "400051",
        "latitude": 19.0657,
        "longitude": 72.8687,
        "attack_type": "DDOS_BOTNET",
        "severity": "CRITICAL",
        "risk_score": 97.8,
        "attack_count": 9840,
        "target_sector": "Public Utilities",
        "malicious_request_sample": "TCP SYN Flood: 48,000 pkts/sec targeting 103.24.12.80:443 (Govt Service Portal)",
        "active_campaign": "State Electricity Billing Lure",
        "linked_case_numbers": ["CS-1030", "CS-1031"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:54:02Z",
        "metadata": {"bot_amplification": "NTP/DNS Monlist", "peak_bandwidth": "14.2 Gbps"}
    },
    {
        "id": 10,
        "ip": "183.82.112.55",
        "hostname": "phish-portal.hyd-node.co",
        "asn": "AS24309 Atria Convergence Technologies (ACT)",
        "isp": "ACT Fibernet Hyderabad",
        "city": "Hyderabad",
        "state": "Telangana",
        "pincode": "500081",
        "latitude": 17.4435,
        "longitude": 78.3772,
        "attack_type": "PHISHING_HOST",
        "severity": "HIGH",
        "risk_score": 83.0,
        "attack_count": 890,
        "target_sector": "Public Utilities",
        "malicious_request_sample": "GET /pay/bill?acc=9021&threat=disconnect_midnight HTTP/1.1 (Simulated phishing lure)",
        "active_campaign": "State Electricity Billing Lure",
        "linked_case_numbers": ["CS-1031"],
        "status": "BLOCKED_BY_FIREWALL",
        "last_seen": "2026-10-02T11:45:10Z",
        "metadata": {"cert_fingerprint": "SHA256:4a8b...19e", "redirect_domain": "urgent-ebill-pay.co"}
    },
    {
        "id": 11,
        "ip": "117.250.64.19",
        "hostname": "sim-gateway.patna-cluster.net",
        "asn": "AS9829 BSNL",
        "isp": "BSNL Bihar Circle",
        "city": "Patna",
        "state": "Bihar",
        "pincode": "800001",
        "latitude": 25.5941,
        "longitude": 85.1376,
        "attack_type": "SIM_BOX_RELAY",
        "severity": "HIGH",
        "risk_score": 81.0,
        "attack_count": 1340,
        "target_sector": "Telecommunications",
        "malicious_request_sample": "POST /sms/dispatch/bulk HTTP/1.1 (Fake Electricity Notice Dispatcher)",
        "active_campaign": "State Electricity Billing Lure",
        "linked_case_numbers": ["CS-1030"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:49:15Z",
        "metadata": {"bulk_rate": "240 sms/min", "channel": "GSM 900/1800"}
    },
    {
        "id": 12,
        "ip": "103.112.214.88",
        "hostname": "customs-scam-proxy.indore.org",
        "asn": "AS132203 Excitel Broadband",
        "isp": "Excitel Broadband",
        "city": "Indore",
        "state": "Madhya Pradesh",
        "pincode": "452001",
        "latitude": 22.7196,
        "longitude": 75.8577,
        "attack_type": "FAKE_KYC_GATEWAY",
        "severity": "MEDIUM",
        "risk_score": 74.5,
        "attack_count": 520,
        "target_sector": "E-Commerce / Logistics",
        "malicious_request_sample": "POST /customs/clearance/inbound?awb=IN984128 HTTP/1.1 (Fake fee collector gateway)",
        "active_campaign": "International Parcel Customs Fee Trap",
        "linked_case_numbers": ["CS-1032"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:38:00Z",
        "metadata": {"proxy_protocol": "SOCKS5 / Shadowsocks", "forward_ip": "103.242.116.14"}
    },
    {
        "id": 13,
        "ip": "122.173.80.41",
        "hostname": "parcel-trafficker.chd.net",
        "asn": "AS133982 Bharti Airtel",
        "isp": "Bharti Airtel Punjab",
        "city": "Chandigarh",
        "state": "Punjab",
        "pincode": "160017",
        "latitude": 30.7333,
        "longitude": 76.7794,
        "attack_type": "PHISHING_HOST",
        "severity": "MEDIUM",
        "risk_score": 72.0,
        "attack_count": 410,
        "target_sector": "E-Commerce / Logistics",
        "malicious_request_sample": "GET /parcel/track?consignment=DL90412 HTTP/1.1 (Malicious APK download payload)",
        "active_campaign": "International Parcel Customs Fee Trap",
        "linked_case_numbers": ["CS-1032"],
        "status": "HONEYPOT_TRAPPED",
        "last_seen": "2026-10-02T13:12:44Z",
        "metadata": {"honeypot_id": "HP-CHD-04", "dropped_binary": "IndiaPost_Delivery.apk"}
    },
    {
        "id": 14,
        "ip": "117.211.90.130",
        "hostname": "bot-relay-node.guwahati.in",
        "asn": "AS9829 BSNL",
        "isp": "BSNL Assam Telecom",
        "city": "Guwahati",
        "state": "Assam",
        "pincode": "781001",
        "latitude": 26.1445,
        "longitude": 91.7362,
        "attack_type": "DDOS_BOTNET",
        "severity": "HIGH",
        "risk_score": 79.0,
        "attack_count": 1670,
        "target_sector": "Govt Services",
        "malicious_request_sample": "UDP Flooding: 24,000 pkts/sec targeting state portal ingress gateway",
        "active_campaign": "International Parcel Customs Fee Trap",
        "linked_case_numbers": ["CS-1032"],
        "status": "BLOCKED_BY_FIREWALL",
        "last_seen": "2026-10-02T10:20:15Z",
        "metadata": {"firewall_filter": "BGP FlowSpec Drop", "duration_mins": 45}
    },
    {
        "id": 15,
        "ip": "114.143.198.62",
        "hostname": "credential-harvester.pune.biz",
        "asn": "AS4755 Tata Communications",
        "isp": "Tata Tele Pune",
        "city": "Pune",
        "state": "Maharashtra",
        "pincode": "411057",
        "latitude": 18.5912,
        "longitude": 73.7389,
        "attack_type": "BRUTE_FORCE_STUFFER",
        "severity": "HIGH",
        "risk_score": 85.2,
        "attack_count": 2210,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /api/v1/auth/credential-probe HTTP/1.1 (Simulated Bot Token Spraying)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1025"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:47:00Z",
        "metadata": {"user_agent": "Python-urllib/3.10", "fail_ratio": 0.98}
    },
    {
        "id": 16,
        "ip": "49.207.180.15",
        "hostname": "fastag-skimmer-node.jaipur.net",
        "asn": "AS9498 Bharti Airtel",
        "isp": "Airtel Broadband Rajasthan",
        "city": "Jaipur",
        "state": "Rajasthan",
        "pincode": "302001",
        "latitude": 26.9124,
        "longitude": 75.7873,
        "attack_type": "UPI_MULE_VECTOR",
        "severity": "CRITICAL",
        "risk_score": 92.4,
        "attack_count": 1890,
        "target_sector": "Public Utilities",
        "malicious_request_sample": "POST /toll/fastag/recharge-bypass HTTP/1.1 (Unauthorized UPI redirection)",
        "active_campaign": "Fastag Recharge Skimmer Syndicate",
        "linked_case_numbers": ["CS-1033"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:50:45Z",
        "metadata": {"spoofed_vpa": "fastagrecharge@ibl", "daily_skim": "₹1,42,000"}
    },
    {
        "id": 17,
        "ip": "103.85.12.94",
        "hostname": "alwar-extortion-c2.in",
        "asn": "AS132203 Excitel Broadband",
        "isp": "Excitel Broadband",
        "city": "Alwar",
        "state": "Rajasthan",
        "pincode": "301001",
        "latitude": 27.5530,
        "longitude": 76.6346,
        "attack_type": "MALWARE_C2",
        "severity": "CRITICAL",
        "risk_score": 93.8,
        "attack_count": 3120,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /apk/trojan/sync-contacts HTTP/1.1 (Instant loan blackmail APK sync hook)",
        "active_campaign": "Instant Loan APK Extortion Ring",
        "linked_case_numbers": ["CS-1034"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:52:19Z",
        "metadata": {"apk_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    },
    {
        "id": 18,
        "ip": "103.41.96.22",
        "hostname": "deoghar-fake-callcenter.net",
        "asn": "AS133982 Bharti Airtel",
        "isp": "Airtel Broadband Jharkhand",
        "city": "Deoghar",
        "state": "Jharkhand",
        "pincode": "814112",
        "latitude": 24.4826,
        "longitude": 86.6975,
        "attack_type": "PHISHING_HOST",
        "severity": "HIGH",
        "risk_score": 88.5,
        "attack_count": 1430,
        "target_sector": "Govt Services",
        "malicious_request_sample": "POST /pmkisan/ekyc-update HTTP/1.1 (Fake Aadhaar Biometric Harvesting)",
        "active_campaign": "PM-Kisan Impersonation Nexus",
        "linked_case_numbers": ["CS-1035"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:46:12Z",
        "metadata": {"spoofed_authority": "PM-KISAN DBT Portal", "lure_format": "Hindi SMS"}
    },
    {
        "id": 19,
        "ip": "182.70.144.60",
        "hostname": "asansol-sim-relay.in",
        "asn": "AS9498 Bharti Airtel",
        "isp": "Airtel Broadband Bengal",
        "city": "Asansol",
        "state": "West Bengal",
        "pincode": "713301",
        "latitude": 23.6739,
        "longitude": 86.9524,
        "attack_type": "SIM_BOX_RELAY",
        "severity": "HIGH",
        "risk_score": 82.0,
        "attack_count": 1190,
        "target_sector": "Telecommunications",
        "malicious_request_sample": "POST /sim/pool/session-inject HTTP/1.1 (Forwarding 60 OTP intercept requests)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1026"],
        "status": "HONEYPOT_TRAPPED",
        "last_seen": "2026-10-02T13:35:50Z",
        "metadata": {"intercept_carrier": "Prepaid SIM Array", "intercept_speed": "< 400ms"}
    },
    {
        "id": 20,
        "ip": "125.19.16.85",
        "hostname": "delhi-central-c2.gov-phish.net",
        "asn": "AS9498 Bharti Airtel",
        "isp": "Airtel Business Delhi",
        "city": "New Delhi",
        "state": "Delhi",
        "pincode": "110001",
        "latitude": 28.6139,
        "longitude": 77.2090,
        "attack_type": "MALWARE_C2",
        "severity": "CRITICAL",
        "risk_score": 98.2,
        "attack_count": 5620,
        "target_sector": "Govt Services",
        "malicious_request_sample": "POST /c2/agent/heartbeat HTTP/1.1 (Remote Access Trojan orchestrating 350 zombies)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1024", "CS-1029"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:54:15Z",
        "metadata": {"c2_heartbeat_interval": "15s", "payload_encrypted": "AES-256-CBC"}
    },
    {
        "id": 21,
        "ip": "117.240.18.99",
        "hostname": "chennai-botnet-node.south.net",
        "asn": "AS9829 BSNL",
        "isp": "BSNL Tamil Nadu Circle",
        "city": "Chennai",
        "state": "Tamil Nadu",
        "pincode": "600001",
        "latitude": 13.0827,
        "longitude": 80.2707,
        "attack_type": "DDOS_BOTNET",
        "severity": "MEDIUM",
        "risk_score": 76.0,
        "attack_count": 1850,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "GET /ebank/gateway/ping HTTP/1.1 (HTTP GET flood: 12,000 req/sec)",
        "active_campaign": "State Electricity Billing Lure",
        "linked_case_numbers": ["CS-1031"],
        "status": "BLOCKED_BY_FIREWALL",
        "last_seen": "2026-10-02T12:00:00Z",
        "metadata": {"ddos_vector": "HTTP L7 Slowloris + GET Flood"}
    },
    {
        "id": 22,
        "ip": "103.240.232.18",
        "hostname": "lucknow-mule-endpoint.in",
        "asn": "AS133982 Bharti Airtel",
        "isp": "Bharti Airtel UP East",
        "city": "Lucknow",
        "state": "Uttar Pradesh",
        "pincode": "226001",
        "latitude": 26.8467,
        "longitude": 80.9462,
        "attack_type": "UPI_MULE_VECTOR",
        "severity": "HIGH",
        "risk_score": 86.4,
        "attack_count": 1270,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /upi/collect/automated HTTP/1.1 (VPA Spoofing: payment_intercept_hook)",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1027"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:44:30Z",
        "metadata": {"merchant_terminal": "MID-LKO-9941"}
    },
    {
        "id": 23,
        "ip": "115.111.42.105",
        "hostname": "ahmedabad-credential-box.org",
        "asn": "AS17488 Hathway Cable and Datacom",
        "isp": "Hathway Gujarat",
        "city": "Ahmedabad",
        "state": "Gujarat",
        "pincode": "380001",
        "latitude": 23.0225,
        "longitude": 72.5714,
        "attack_type": "BRUTE_FORCE_STUFFER",
        "severity": "MEDIUM",
        "risk_score": 73.0,
        "attack_count": 940,
        "target_sector": "E-Commerce / Logistics",
        "malicious_request_sample": "POST /checkout/account/validate HTTP/1.1 (Card Testing & CVV enumeration)",
        "active_campaign": "International Parcel Customs Fee Trap",
        "linked_case_numbers": ["CS-1032"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:36:12Z",
        "metadata": {"card_bins": ["438628", "524108"]}
    },
    {
        "id": 24,
        "ip": "117.200.78.212",
        "hostname": "kochi-fake-gateway.net",
        "asn": "AS9829 BSNL",
        "isp": "BSNL Kerala Telecom",
        "city": "Kochi",
        "state": "Kerala",
        "pincode": "682001",
        "latitude": 9.9312,
        "longitude": 76.2673,
        "attack_type": "FAKE_KYC_GATEWAY",
        "severity": "LOW",
        "risk_score": 64.0,
        "attack_count": 310,
        "target_sector": "Telecommunications",
        "malicious_request_sample": "GET /sim-activation/verify-aadhaar?ph=9845123049 HTTP/1.1",
        "active_campaign": "Operation Phantom KYC",
        "linked_case_numbers": ["CS-1028"],
        "status": "BLOCKED_BY_FIREWALL",
        "last_seen": "2026-10-02T09:15:30Z",
        "metadata": {"action": "ISP DNS Sinkholed"}
    },
    {
        "id": 25,
        "ip": "103.58.118.73",
        "hostname": "bhopal-phish-hub.in",
        "asn": "AS132203 Excitel Broadband",
        "isp": "Excitel Broadband MP",
        "city": "Bhopal",
        "state": "Madhya Pradesh",
        "pincode": "462001",
        "latitude": 23.2599,
        "longitude": 77.4126,
        "attack_type": "PHISHING_HOST",
        "severity": "HIGH",
        "risk_score": 80.5,
        "attack_count": 680,
        "target_sector": "Govt Services",
        "malicious_request_sample": "GET /scholarship/portal/login?redirect=malicious_host HTTP/1.1",
        "active_campaign": "PM-Kisan Impersonation Nexus",
        "linked_case_numbers": ["CS-1035"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:41:20Z",
        "metadata": {"harvested_records": 19}
    },
    {
        "id": 26,
        "ip": "103.80.194.50",
        "hostname": "bbsr-loan-shark-c2.net",
        "asn": "AS55836 Reliance Jio",
        "isp": "Reliance Jio Odisha",
        "city": "Bhubaneswar",
        "state": "Odisha",
        "pincode": "751001",
        "latitude": 20.2961,
        "longitude": 85.8245,
        "attack_type": "MALWARE_C2",
        "severity": "HIGH",
        "risk_score": 85.0,
        "attack_count": 1580,
        "target_sector": "Banking & Financial",
        "malicious_request_sample": "POST /device/telemetry/dump HTTP/1.1 (Exfiltrating SMS inbox and contacts)",
        "active_campaign": "Instant Loan APK Extortion Ring",
        "linked_case_numbers": ["CS-1034"],
        "status": "ACTIVE_ATTACKING",
        "last_seen": "2026-10-02T13:49:50Z",
        "metadata": {"loan_apk_package": "com.cashfast.rupee.loan"}
    }
]

# Enrich INITIAL_THREAT_NODES with lat, lng, primary_case_id, primary_case_number, linked_case_ids
for _node in INITIAL_THREAT_NODES:
    _node["lat"] = float(_node["latitude"])
    _node["lng"] = float(_node["longitude"])
    _linked_nums = _node.get("linked_case_numbers", [])
    _primary_num = _node.get("primary_case_number") or (_linked_nums[0] if _linked_nums else "CS-1024")
    _linked_ids = [DEFAULT_CASE_MAP.get(num, int(num[3:]) - 1023 if str(num).startswith("CS-") and str(num)[3:].isdigit() else 1) for num in _linked_nums]
    _primary_id = _node.get("primary_case_id") or (_linked_ids[0] if _linked_ids else 1)
    _node["primary_case_number"] = _primary_num
    _node["primary_case_id"] = _primary_id
    _node["linked_case_ids"] = _linked_ids
    _node["linked_case_numbers"] = _linked_nums


class ThreatMapService:
    """
    Threat intelligence service managing cyber attacker IPs, telemetry,
    live malicious feeds, and firewall mitigation actions.
    """
    # In-memory store mirroring DB for zero-latency fallback and resilience
    _memory_nodes: Dict[int, Dict[str, Any]] = {n["id"]: dict(n) for n in INITIAL_THREAT_NODES}
    _blocked_counter: int = 1420

    @classmethod
    def ensure_seeded(cls, db: Optional[Session] = None) -> int:
        """
        Idempotently seeds ThreatNode records and synchronized IP_ADDRESS Entity records
        in the relational database.
        """
        if db is None:
            return len(cls._memory_nodes)

        # Check and migrate table schema in SQLite if columns are missing
        try:
            conn = db.connection()
            col_info = conn.execute(text("PRAGMA table_info(threat_nodes);")).fetchall()
            col_names = [c[1] for c in col_info]
            if col_names and "pincode" not in col_names:
                conn.execute(text("ALTER TABLE threat_nodes ADD COLUMN pincode VARCHAR(20) DEFAULT '110001';"))
            if col_names and "primary_case_id" not in col_names:
                conn.execute(text("ALTER TABLE threat_nodes ADD COLUMN primary_case_id INTEGER;"))
            if col_names and "primary_case_number" not in col_names:
                conn.execute(text("ALTER TABLE threat_nodes ADD COLUMN primary_case_number VARCHAR(50);"))
            if col_names and "linked_case_ids" not in col_names:
                conn.execute(text("ALTER TABLE threat_nodes ADD COLUMN linked_case_ids JSON DEFAULT '[]';"))
            db.commit()
            logger.info("ThreatMapService: Verified threat_nodes table schema.")
        except Exception as e:
            logger.debug(f"ThreatMapService: schema check notice: {e}")

        # Build dynamic case map from DB cases
        case_map = dict(DEFAULT_CASE_MAP)
        try:
            db_cases = db.query(Case).all()
            for c in db_cases:
                case_map[c.case_number] = c.id
        except Exception as e:
            logger.debug(f"ThreatMapService: Case map query note: {e}")

        count = 0
        try:
            for item in INITIAL_THREAT_NODES:
                linked_nums = item.get("linked_case_numbers", [])
                primary_num = item.get("primary_case_number") or (linked_nums[0] if linked_nums else "CS-1024")
                linked_ids = [case_map.get(num, int(num[3:]) - 1023 if str(num).startswith("CS-") and str(num)[3:].isdigit() else 1) for num in linked_nums]
                primary_id = item.get("primary_case_id") or (case_map.get(primary_num) if primary_num in case_map else (linked_ids[0] if linked_ids else 1))

                existing_node = db.query(ThreatNode).filter(ThreatNode.ip == item["ip"]).first()
                if not existing_node:
                    node_obj = ThreatNode(
                        ip=item["ip"],
                        hostname=item["hostname"],
                        asn=item["asn"],
                        isp=item["isp"],
                        city=item["city"],
                        state=item["state"],
                        pincode=item.get("pincode", "110001"),
                        latitude=item["latitude"],
                        longitude=item["longitude"],
                        attack_type=item["attack_type"],
                        severity=item["severity"],
                        risk_score=item["risk_score"],
                        attack_count=item["attack_count"],
                        target_sector=item["target_sector"],
                        malicious_request_sample=item["malicious_request_sample"],
                        active_campaign=item["active_campaign"],
                        primary_case_id=primary_id,
                        primary_case_number=primary_num,
                        linked_case_ids=linked_ids,
                        linked_case_numbers=linked_nums,
                        status=item["status"],
                        last_seen=datetime.fromisoformat(item["last_seen"].replace("Z", "+00:00")),
                        meta_data=item["metadata"]
                    )
                    db.add(node_obj)
                    count += 1
                else:
                    # Update fields
                    existing_node.hostname = item["hostname"]
                    existing_node.asn = item["asn"]
                    existing_node.isp = item["isp"]
                    existing_node.city = item["city"]
                    existing_node.state = item["state"]
                    existing_node.pincode = item.get("pincode", "110001")
                    existing_node.latitude = item["latitude"]
                    existing_node.longitude = item["longitude"]
                    existing_node.attack_type = item["attack_type"]
                    existing_node.severity = item["severity"]
                    existing_node.risk_score = item["risk_score"]
                    existing_node.attack_count = max(existing_node.attack_count, item["attack_count"])
                    existing_node.target_sector = item["target_sector"]
                    existing_node.malicious_request_sample = item["malicious_request_sample"]
                    existing_node.active_campaign = item["active_campaign"]
                    existing_node.primary_case_id = primary_id
                    existing_node.primary_case_number = primary_num
                    existing_node.linked_case_ids = linked_ids
                    existing_node.linked_case_numbers = linked_nums
                    existing_node.meta_data = item["metadata"]

                # Ensure Entity sync for graph exploration and global entity lookups
                norm_ip = item["ip"].strip().lower()
                ent = db.query(Entity).filter(
                    Entity.entity_type == "IP_ADDRESS",
                    Entity.normalized_value == norm_ip
                ).first()
                if not ent:
                    ent = Entity(
                        entity_type="IP_ADDRESS",
                        value=item["ip"],
                        normalized_value=norm_ip,
                        risk_score=item["risk_score"],
                        meta_data={
                            "role": "ATTACKER_INFRASTRUCTURE",
                            "city": item["city"],
                            "state": item["state"],
                            "pincode": item.get("pincode", "110001"),
                            "asn": item["asn"],
                            "isp": item["isp"],
                            "attack_type": item["attack_type"],
                            "severity": item["severity"],
                            "campaign": item["active_campaign"],
                            "target_sector": item["target_sector"]
                        }
                    )
                    db.add(ent)
                else:
                    ent.risk_score = max(ent.risk_score, item["risk_score"])
                    md = dict(ent.meta_data or {})
                    md.update({
                        "role": "ATTACKER_INFRASTRUCTURE",
                        "city": item["city"],
                        "state": item["state"],
                        "pincode": item.get("pincode", "110001"),
                        "asn": item["asn"],
                        "isp": item["isp"],
                        "attack_type": item["attack_type"],
                        "severity": item["severity"],
                        "campaign": item["active_campaign"]
                    })
                    ent.meta_data = md

            db.commit()
            logger.info(f"ThreatMapService: Seeded {count} new threat nodes and updated IP entities.")

            # Organically wire attacker IP topology into Fraud Graph and link financial transactions
            cls.wire_graph_topology(db)
        except Exception as e:
            logger.warning(f"ThreatMapService: DB seeding warning: {e}")
            db.rollback()

        return count

    @classmethod
    def wire_graph_topology(cls, db: Session) -> Dict[str, int]:
        """
        Connects all 26 authentic Indian attacker IP entities into the Fraud Graph
        relationships table, links financial transactions to physical attacker IPs,
        and establishes multi-hop investigation chains.
        """
        aux_domains = [
            {"entity_type": "DOMAIN", "value": "bijli-bill-alert.in", "risk_score": 92.0, "metadata": {"campaign": "State Electricity Billing Lure", "registrar": "GoDaddy India", "category": "Phishing"}},
            {"entity_type": "DOMAIN", "value": "power-bill-disconnection.org", "risk_score": 89.0, "metadata": {"campaign": "State Electricity Billing Lure", "registrar": "Public Domain Registry", "category": "Phishing"}},
            {"entity_type": "DOMAIN", "value": "customs-duty-clearance.net", "risk_score": 94.0, "metadata": {"campaign": "International Parcel Customs Fee Trap", "registrar": "Namecheap", "category": "Phishing"}},
            {"entity_type": "DOMAIN", "value": "fastag-quick-recharge.in", "risk_score": 93.0, "metadata": {"campaign": "Fastag Recharge Skimmer Syndicate", "registrar": "BigRock", "category": "Phishing"}},
            {"entity_type": "DOMAIN", "value": "rupee-instant-loan.org", "risk_score": 96.0, "metadata": {"campaign": "Instant Loan APK Extortion Ring", "registrar": "Tucows", "category": "Malware C2"}},
            {"entity_type": "DOMAIN", "value": "pmkisan-ekyc-portal.org", "risk_score": 91.0, "metadata": {"campaign": "PM-Kisan Impersonation Nexus", "registrar": "Dynadot", "category": "Credential Harvesting"}},
        ]

        # 1. Ensure auxiliary campaign entities exist
        for ad in aux_domains:
            existing = db.query(Entity).filter(
                Entity.entity_type == ad["entity_type"],
                Entity.value == ad["value"]
            ).first()
            if not existing:
                db.add(Entity(
                    entity_type=ad["entity_type"],
                    value=ad["value"],
                    normalized_value=ad["value"].lower().strip(),
                    risk_score=ad["risk_score"],
                    meta_data=ad["metadata"]
                ))
        db.commit()

        # Build entity map
        all_ents = db.query(Entity).all()
        ent_by_type_val = {(e.entity_type, e.value.lower().strip()): e.id for e in all_ents}
        ent_by_val = {e.value.lower().strip(): e.id for e in all_ents}

        rules = [
            # Operation Phantom KYC: Core C2 Jamtara
            ("secure-kyc-update.com", "DOMAIN", "RESOLVES_TO", "198.51.100.10", "IP_ADDRESS", 0.99, {"city": "Jamtara", "ttl": 300}),
            ("DEV-SIM-1000", "DEVICE", "ROUTED_THROUGH", "198.51.100.10", "IP_ADDRESS", 0.96, {"protocol": "TCP/443"}),
            ("centralmule99@okaxis", "UPI_ID", "ACCESSED_FROM", "198.51.100.10", "IP_ADDRESS", 0.95, {"channel": "UPI"}),
            ("SIM-ACC-MULE-HUB-891", "BANK_ACCOUNT", "ACCESSED_FROM", "198.51.100.10", "IP_ADDRESS", 0.94, {"channel": "NETBANKING"}),
            ("198.51.100.10", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 1.0, {"source": "CERT-In Feed"}),
            ("198.51.100.10", "IP_ADDRESS", "REPORTED_IN", "CS-1025", "CASE", 0.95, {}),
            ("198.51.100.10", "IP_ADDRESS", "REPORTED_IN", "CS-1026", "CASE", 0.95, {}),
            ("198.51.100.10", "IP_ADDRESS", "REPORTED_IN", "CS-1027", "CASE", 0.95, {}),
            ("198.51.100.10", "IP_ADDRESS", "REPORTED_IN", "CS-1028", "CASE", 0.95, {}),

            # Karmatanr, Jamtara
            ("verify-portal-in.net", "DOMAIN", "RESOLVES_TO", "103.15.28.45", "IP_ADDRESS", 0.98, {"city": "Karmatanr"}),
            ("+919119540831", "PHONE", "ROUTED_THROUGH", "103.15.28.45", "IP_ADDRESS", 0.95, {}),
            ("103.15.28.45", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 0.95, {}),
            ("103.15.28.45", "IP_ADDRESS", "REPORTED_IN", "CS-1026", "CASE", 0.92, {}),

            # Nuh / Mewat
            ("+919686579303", "PHONE", "ROUTED_THROUGH", "49.36.128.91", "IP_ADDRESS", 0.97, {"city": "Nuh"}),
            ("49.36.128.91", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 0.96, {}),
            ("49.36.128.91", "IP_ADDRESS", "REPORTED_IN", "CS-1028", "CASE", 0.94, {}),

            # Bharatpur
            ("kycpaydesk@paytm", "UPI_ID", "ACCESSED_FROM", "103.242.116.14", "IP_ADDRESS", 0.97, {}),
            ("SIM-ACC-LAYER1-A-101", "BANK_ACCOUNT", "ACCESSED_FROM", "103.242.116.14", "IP_ADDRESS", 0.96, {}),
            ("103.242.116.14", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 0.97, {}),
            ("103.242.116.14", "IP_ADDRESS", "REPORTED_IN", "CS-1027", "CASE", 0.93, {}),

            # Gurugram C2
            ("quick-kyc-auth.org", "DOMAIN", "RESOLVES_TO", "122.161.49.202", "IP_ADDRESS", 0.98, {"city": "Gurugram"}),
            ("SIM-ACC-CIRCULAR-A", "BANK_ACCOUNT", "ACCESSED_FROM", "122.161.49.202", "IP_ADDRESS", 0.94, {}),
            ("122.161.49.202", "IP_ADDRESS", "REPORTED_IN", "CS-1025", "CASE", 0.98, {}),
            ("122.161.49.202", "IP_ADDRESS", "REPORTED_IN", "CS-1029", "CASE", 0.95, {}),

            # Kolkata Sector V Gateway
            ("secure-kyc-update.com", "DOMAIN", "RESOLVES_TO", "182.74.88.115", "IP_ADDRESS", 0.95, {"city": "Kolkata"}),
            ("182.74.88.115", "IP_ADDRESS", "REPORTED_IN", "CS-1025", "CASE", 0.94, {}),
            ("182.74.88.115", "IP_ADDRESS", "REPORTED_IN", "CS-1026", "CASE", 0.91, {}),

            # Surat Cash-out
            ("SIM-ACC-CASH-OUT-999", "BANK_ACCOUNT", "ACCESSED_FROM", "115.110.201.78", "IP_ADDRESS", 0.97, {}),
            ("115.110.201.78", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 0.95, {}),

            # Lucknow Layering
            ("SIM-ACC-LAYER1-B-102", "BANK_ACCOUNT", "ACCESSED_FROM", "103.240.232.18", "IP_ADDRESS", 0.94, {}),
            ("103.240.232.18", "IP_ADDRESS", "REPORTED_IN", "CS-1026", "CASE", 0.93, {}),
            ("103.240.232.18", "IP_ADDRESS", "REPORTED_IN", "CS-1027", "CASE", 0.91, {}),

            # Pune
            ("SIM-ACC-LAYER1-C-103", "BANK_ACCOUNT", "ACCESSED_FROM", "114.143.198.62", "IP_ADDRESS", 0.93, {}),
            ("114.143.198.62", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 0.92, {}),
            ("114.143.198.62", "IP_ADDRESS", "REPORTED_IN", "CS-1027", "CASE", 0.90, {}),

            # Asansol SIM Box
            ("+919026855092", "PHONE", "ROUTED_THROUGH", "182.70.144.60", "IP_ADDRESS", 0.94, {}),
            ("182.70.144.60", "IP_ADDRESS", "REPORTED_IN", "CS-1024", "CASE", 0.93, {}),
            ("182.70.144.60", "IP_ADDRESS", "REPORTED_IN", "CS-1028", "CASE", 0.91, {}),

            # New Delhi ATO C2
            ("DEV-SIM-1000", "DEVICE", "ROUTED_THROUGH", "125.19.16.85", "IP_ADDRESS", 0.93, {}),
            ("125.19.16.85", "IP_ADDRESS", "REPORTED_IN", "CS-1025", "CASE", 0.96, {}),
            ("125.19.16.85", "IP_ADDRESS", "REPORTED_IN", "CS-1029", "CASE", 0.98, {}),

            # Kochi
            ("117.200.78.212", "IP_ADDRESS", "REPORTED_IN", "CS-1028", "CASE", 0.90, {}),

            # Campaign 2: State Electricity Billing
            ("bijli-bill-alert.in", "DOMAIN", "RESOLVES_TO", "103.21.58.12", "IP_ADDRESS", 0.98, {"city": "Mumbai"}),
            ("bijli-bill-alert.in", "DOMAIN", "RESOLVES_TO", "183.82.112.55", "IP_ADDRESS", 0.97, {"city": "Hyderabad"}),
            ("power-bill-disconnection.org", "DOMAIN", "RESOLVES_TO", "183.82.112.55", "IP_ADDRESS", 0.96, {}),
            ("103.21.58.12", "IP_ADDRESS", "REPORTED_IN", "CS-1030", "CASE", 0.97, {}),
            ("103.21.58.12", "IP_ADDRESS", "REPORTED_IN", "CS-1031", "CASE", 0.95, {}),
            ("183.82.112.55", "IP_ADDRESS", "REPORTED_IN", "CS-1031", "CASE", 0.96, {}),
            ("106.51.72.33", "IP_ADDRESS", "REPORTED_IN", "CS-1030", "CASE", 0.94, {}),
            ("117.250.64.19", "IP_ADDRESS", "REPORTED_IN", "CS-1030", "CASE", 0.92, {}),
            ("+919295310485", "PHONE", "ROUTED_THROUGH", "117.250.64.19", "IP_ADDRESS", 0.93, {"role": "BULK_LURE_DISPATCH"}),
            ("117.240.18.99", "IP_ADDRESS", "REPORTED_IN", "CS-1030", "CASE", 0.92, {}),
            ("117.240.18.99", "IP_ADDRESS", "REPORTED_IN", "CS-1031", "CASE", 0.90, {}),

            # Campaign 3: Parcel Customs
            ("customs-duty-clearance.net", "DOMAIN", "RESOLVES_TO", "122.173.80.41", "IP_ADDRESS", 0.98, {"city": "Chandigarh"}),
            ("customs-duty-clearance.net", "DOMAIN", "RESOLVES_TO", "117.211.90.130", "IP_ADDRESS", 0.95, {"city": "Guwahati"}),
            ("122.173.80.41", "IP_ADDRESS", "REPORTED_IN", "CS-1032", "CASE", 0.96, {}),
            ("117.211.90.130", "IP_ADDRESS", "REPORTED_IN", "CS-1032", "CASE", 0.95, {}),
            ("103.112.214.88", "IP_ADDRESS", "REPORTED_IN", "CS-1032", "CASE", 0.93, {}),
            ("115.111.42.105", "IP_ADDRESS", "REPORTED_IN", "CS-1032", "CASE", 0.91, {}),

            # Fastag Recharge
            ("fastag-quick-recharge.in", "DOMAIN", "RESOLVES_TO", "49.207.180.15", "IP_ADDRESS", 0.97, {"city": "Jaipur"}),
            ("49.207.180.15", "IP_ADDRESS", "REPORTED_IN", "CS-1033", "CASE", 0.97, {}),

            # Instant Loan Extortion
            ("rupee-instant-loan.org", "DOMAIN", "RESOLVES_TO", "103.85.12.94", "IP_ADDRESS", 0.97, {"city": "Alwar"}),
            ("rupee-instant-loan.org", "DOMAIN", "RESOLVES_TO", "103.80.194.50", "IP_ADDRESS", 0.95, {"city": "Bhubaneswar"}),
            ("103.85.12.94", "IP_ADDRESS", "REPORTED_IN", "CS-1034", "CASE", 0.97, {}),
            ("103.80.194.50", "IP_ADDRESS", "REPORTED_IN", "CS-1034", "CASE", 0.95, {}),

            # PM-Kisan Impersonation
            ("pmkisan-ekyc-portal.org", "DOMAIN", "RESOLVES_TO", "103.41.96.22", "IP_ADDRESS", 0.96, {"city": "Deoghar"}),
            ("pmkisan-ekyc-portal.org", "DOMAIN", "RESOLVES_TO", "103.58.118.73", "IP_ADDRESS", 0.94, {"city": "Bhopal"}),
            ("103.41.96.22", "IP_ADDRESS", "REPORTED_IN", "CS-1035", "CASE", 0.96, {}),
            ("103.58.118.73", "IP_ADDRESS", "REPORTED_IN", "CS-1035", "CASE", 0.94, {}),

            # Campaign mule operator sessions
            ("SIM-ACC-CIRCULAR-B", "BANK_ACCOUNT", "ACCESSED_FROM", "122.161.49.202", "IP_ADDRESS", 0.94, {}),
            ("SIM-ACC-CIRCULAR-C", "BANK_ACCOUNT", "ACCESSED_FROM", "122.161.49.202", "IP_ADDRESS", 0.94, {}),
            ("SIM-ACC-EBILL-MULE-401", "BANK_ACCOUNT", "ACCESSED_FROM", "103.240.232.18", "IP_ADDRESS", 0.96, {"action": "UPI Layering Initiation"}),
            ("SIM-ACC-CUSTOMS-402", "BANK_ACCOUNT", "ACCESSED_FROM", "103.112.214.88", "IP_ADDRESS", 0.95, {"action": "Duty Fee Collection"}),
            ("SIM-ACC-FASTAG-403", "BANK_ACCOUNT", "ACCESSED_FROM", "49.207.180.15", "IP_ADDRESS", 0.96, {"action": "Toll Recharge Skim"}),
            ("SIM-ACC-LOAN-404", "BANK_ACCOUNT", "ACCESSED_FROM", "103.85.12.94", "IP_ADDRESS", 0.96, {"action": "Extortion Settlement Desk"}),
            ("SIM-ACC-KISAN-405", "BANK_ACCOUNT", "ACCESSED_FROM", "103.41.96.22", "IP_ADDRESS", 0.95, {"action": "Installment Diversion"}),
            ("quickflow88@ybl", "UPI_ID", "ACCESSED_FROM", "103.240.232.18", "IP_ADDRESS", 0.95, {}),
            ("clearancefast@ibl", "UPI_ID", "ACCESSED_FROM", "103.112.214.88", "IP_ADDRESS", 0.95, {}),

            # Campaign attacker handsets
            ("+919796233790", "PHONE", "ROUTED_THROUGH", "125.19.16.85", "IP_ADDRESS", 0.94, {"role": "SIM_SWAP_DISPATCH"}),
            ("+919262950628", "PHONE", "ROUTED_THROUGH", "103.85.12.94", "IP_ADDRESS", 0.93, {"role": "RECOVERY_AGENT_HARASSMENT"}),
            ("+919239670711", "PHONE", "ROUTED_THROUGH", "122.173.80.41", "IP_ADDRESS", 0.92, {"role": "CUSTOMS_AGENT_IMPERSONATION"}),
            ("+919149827706", "PHONE", "ROUTED_THROUGH", "49.207.180.15", "IP_ADDRESS", 0.92, {"role": "FASTAG_LURE_DISPATCH"}),
            ("+919790779946", "PHONE", "ROUTED_THROUGH", "103.41.96.22", "IP_ADDRESS", 0.93, {"role": "GOVT_SCHEME_IMPERSONATION"}),
        ]

        rels_created = 0
        for src_val, src_type, rel_type, tgt_val, tgt_type, conf, meta in rules:
            src_id = ent_by_type_val.get((src_type, src_val.lower().strip())) or ent_by_val.get(src_val.lower().strip())
            tgt_id = ent_by_type_val.get((tgt_type, tgt_val.lower().strip())) or ent_by_val.get(tgt_val.lower().strip())

            if not tgt_id and tgt_type == "CASE":
                case_row = db.query(Case).filter(Case.case_number.ilike(tgt_val.strip())).first()
                if case_row:
                    case_ent = db.query(Entity).filter(Entity.entity_type == "CASE", Entity.value == case_row.case_number).first()
                    if not case_ent:
                        case_ent = Entity(
                            entity_type="CASE",
                            value=case_row.case_number,
                            normalized_value=case_row.case_number.lower(),
                            risk_score=case_row.risk_score,
                            meta_data={"case_id": case_row.id, "title": case_row.title}
                        )
                        db.add(case_ent)
                        db.flush()
                    tgt_id = case_ent.id
                    ent_by_type_val[("CASE", tgt_val.lower().strip())] = tgt_id
                    ent_by_val[tgt_val.lower().strip()] = tgt_id

            if not src_id or not tgt_id:
                continue

            existing_rel = db.query(Relationship).filter(
                Relationship.source_entity_id == src_id,
                Relationship.target_entity_id == tgt_id,
                Relationship.relationship_type == rel_type
            ).first()

            if not existing_rel:
                db.add(Relationship(
                    source_entity_id=src_id,
                    target_entity_id=tgt_id,
                    relationship_type=rel_type,
                    confidence=conf,
                    meta_data=meta
                ))
                rels_created += 1

        db.commit()

        # --- Victim linkage: connect case victims to the attacker infrastructure ---
        # that hosted their lure, drove the hijacked session on their account, and
        # delivered the SMS. (session_ip, lure_domain, session_origin) per case.
        victim_sessions = {
            "CS-1024": ("198.51.100.10", "secure-kyc-update.com", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1025": ("198.51.100.10", "secure-kyc-update.com", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1026": ("103.15.28.45", "verify-portal-in.net", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1027": ("122.161.49.202", "quick-kyc-auth.org", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1028": ("198.51.100.10", "secure-kyc-update.com", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1029": ("125.19.16.85", None, "RAT_REMOTE_SESSION"),
            "CS-1030": ("183.82.112.55", "bijli-bill-alert.in", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1031": ("183.82.112.55", "bijli-bill-alert.in", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1032": ("122.173.80.41", "customs-duty-clearance.net", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1033": ("49.207.180.15", "fastag-quick-recharge.in", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1034": ("103.85.12.94", "rupee-instant-loan.org", "PHISHING_CREDENTIAL_REPLAY"),
            "CS-1035": ("103.41.96.22", "pmkisan-ekyc-portal.org", "PHISHING_CREDENTIAL_REPLAY"),
        }

        def rel_exists(src_id: int, tgt_id: int, rel_type: str) -> bool:
            return db.query(Relationship).filter(
                Relationship.source_entity_id == src_id,
                Relationship.target_entity_id == tgt_id,
                Relationship.relationship_type == rel_type
            ).first() is not None

        def add_rel(src_id: Optional[int], tgt_id: Optional[int], rel_type: str, conf: float, meta: Dict[str, Any]) -> int:
            if src_id is None or tgt_id is None or rel_exists(src_id, tgt_id, rel_type):
                return 0
            db.add(Relationship(
                source_entity_id=src_id,
                target_entity_id=tgt_id,
                relationship_type=rel_type,
                confidence=conf,
                meta_data=meta
            ))
            return 1

        case_numbers = {c.id: c.case_number for c in db.query(Case).all()}
        victims_linked = 0

        for c_num, (session_ip, lure_domain, session_origin) in victim_sessions.items():
            case_ent_id = ent_by_type_val.get(("CASE", c_num.lower())) or ent_by_val.get(c_num.lower())
            case_ip_id = ent_by_val.get(session_ip)
            if not case_ent_id or not case_ip_id:
                continue

            lure_ent_id = ent_by_val.get(lure_domain.lower()) if lure_domain else None
            channel = "NETBANKING" if c_num in ("CS-1024", "CS-1025", "CS-1028", "CS-1029") else "UPI"

            person_ids = {
                r.source_entity_id for r in db.query(Relationship).filter(
                    Relationship.target_entity_id == case_ent_id,
                    Relationship.relationship_type == "REPORTED_IN"
                ).all()
            }
            for p_id in person_ids:
                if db.query(Entity).filter(Entity.id == p_id, Entity.entity_type == "PERSON").first() is None:
                    continue

                if lure_ent_id:
                    victims_linked += add_rel(p_id, lure_ent_id, "TARGETED_BY", 0.94, {"case": c_num, "lure_url": f"https://{lure_domain}"})
                else:
                    dev_id = ent_by_val.get("dev-sim-1000")
                    victims_linked += add_rel(p_id, dev_id, "TARGETED_BY", 0.93, {"case": c_num, "vector": "SIM_SWAP_ATO"})

                for own in db.query(Relationship).filter(
                    Relationship.source_entity_id == p_id,
                    Relationship.relationship_type == "OWNS"
                ).all():
                    victims_linked += add_rel(
                        own.target_entity_id, case_ip_id, "ACCESSED_FROM", 0.95,
                        {"case": c_num, "session_origin": session_origin, "channel": channel}
                    )

        # Contact chains: lure sender handsets to victim handsets, from message logs.
        contacts_linked = 0
        for msg in db.query(Message).all():
            if not msg.sender_phone or not msg.receiver_phone:
                continue
            src_id = ent_by_val.get(msg.sender_phone.lower().strip())
            tgt_id = ent_by_val.get(msg.receiver_phone.lower().strip())
            if src_id is not None and tgt_id is not None:
                contacts_linked += add_rel(src_id, tgt_id, "CONTACTED", 0.98, {"channel": msg.channel, "case": case_numbers.get(msg.case_id)})
        db.commit()

        # Bind transaction telemetry to attacker infrastructure: prefer the account
        # session edge (operator origin), else the case's primary attacker IP.
        accessed_from: Dict[int, int] = {}
        for r in db.query(Relationship).filter(Relationship.relationship_type == "ACCESSED_FROM").all():
            accessed_from.setdefault(r.source_entity_id, r.target_entity_id)

        device_ent_id = ent_by_val.get("dev-sim-1000")
        c2_ip_ids = {ent_by_val.get(ip) for ip in ("198.51.100.10", "125.19.16.85")} - {None}

        tx_updated = 0
        for tx in db.query(Transaction).all():
            if tx.ip_id:
                continue
            ip_ent_id = accessed_from.get(tx.sender_entity_id)
            if ip_ent_id is None and tx.case_id:
                session_ip = victim_sessions.get(case_numbers.get(tx.case_id, ""), (None,))[0]
                ip_ent_id = ent_by_val.get(session_ip) if session_ip else None
            if ip_ent_id:
                tx.ip_id = ip_ent_id
                if device_ent_id and tx.device_id is None and ip_ent_id in c2_ip_ids:
                    tx.device_id = device_ent_id
                tx_updated += 1
        db.commit()

        logger.info(
            f"ThreatMapService: Wired topology ({rels_created} new edges, {victims_linked} victim links, "
            f"{contacts_linked} contact chains, {tx_updated} transactions bound to attacker IPs)."
        )
        return {"relationships_created": rels_created, "transactions_linked": tx_updated}

    @classmethod
    def get_attackers(
        cls,
        db: Optional[Session] = None,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        campaign: Optional[str] = None,
        pincode: Optional[str] = None,
        min_risk: Optional[float] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Retrieves filtered list of attacker nodes from DB (with fallback to resilient memory cache).
        """
        results: List[Dict[str, Any]] = []

        if db is not None:
            try:
                # Check if threat_nodes has rows; auto-seed if needed
                total_in_db = db.query(ThreatNode).count()
                if total_in_db == 0:
                    cls.ensure_seeded(db)

                q = db.query(ThreatNode)
                if severity:
                    q = q.filter(ThreatNode.severity == severity.upper())
                if attack_type:
                    q = q.filter(ThreatNode.attack_type == attack_type.upper())
                if campaign:
                    q = q.filter(ThreatNode.active_campaign.ilike(f"%{campaign}%"))
                if pincode:
                    q = q.filter(ThreatNode.pincode == pincode.strip())
                if min_risk is not None:
                    q = q.filter(ThreatNode.risk_score >= min_risk)
                if search:
                    s_pat = f"%{search.strip()}%"
                    q = q.filter(
                        (ThreatNode.ip.ilike(s_pat)) |
                        (ThreatNode.hostname.ilike(s_pat)) |
                        (ThreatNode.city.ilike(s_pat)) |
                        (ThreatNode.state.ilike(s_pat)) |
                        (ThreatNode.pincode.ilike(s_pat)) |
                        (ThreatNode.isp.ilike(s_pat)) |
                        (ThreatNode.asn.ilike(s_pat)) |
                        (ThreatNode.active_campaign.ilike(s_pat))
                    )

                nodes = q.order_by(ThreatNode.risk_score.desc(), ThreatNode.attack_count.desc()).offset(offset).limit(limit).all()
                if nodes:
                    for n in nodes:
                        d = n.to_dict()
                        results.append(d)
                        # sync memory node status
                        cls._memory_nodes[n.id] = d
                    return results
            except Exception as e:
                logger.warning(f"Error querying ThreatNode from DB: {e}. Falling back to memory store.")

        # Fallback to memory nodes
        filtered = list(cls._memory_nodes.values())
        if severity:
            sev_up = severity.upper()
            filtered = [n for n in filtered if n.get("severity", "").upper() == sev_up]
        if attack_type:
            at_up = attack_type.upper()
            filtered = [n for n in filtered if n.get("attack_type", "").upper() == at_up]
        if campaign:
            camp_lower = campaign.lower()
            filtered = [n for n in filtered if camp_lower in n.get("active_campaign", "").lower()]
        if pincode:
            p_strip = pincode.strip()
            filtered = [n for n in filtered if n.get("pincode", "").strip() == p_strip]
        if min_risk is not None:
            filtered = [n for n in filtered if n.get("risk_score", 0.0) >= min_risk]
        if search:
            s_low = search.strip().lower()
            filtered = [
                n for n in filtered
                if s_low in n.get("ip", "").lower() or
                   s_low in (n.get("hostname") or "").lower() or
                   s_low in n.get("city", "").lower() or
                   s_low in n.get("state", "").lower() or
                   s_low in n.get("pincode", "").lower() or
                   s_low in n.get("isp", "").lower() or
                   s_low in n.get("asn", "").lower() or
                   s_low in (n.get("active_campaign") or "").lower()
            ]

        filtered.sort(key=lambda x: (x.get("risk_score", 0), x.get("attack_count", 0)), reverse=True)
        return filtered[offset: offset + limit]

    @classmethod
    def get_stats(cls, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Calculates summary KPIs and geographical/typological distributions.
        """
        nodes = cls.get_attackers(db=db, limit=500)
        total_attackers = len(nodes)
        active_attacks = sum(1 for n in nodes if n.get("status") == "ACTIVE_ATTACKING")
        critical_threats = sum(1 for n in nodes if n.get("severity") == "CRITICAL")
        
        # Calculate blocked requests from blocked nodes and cumulative firewall drops
        blocked_nodes_attacks = sum(n.get("attack_count", 0) for n in nodes if n.get("status") == "BLOCKED_BY_FIREWALL")
        total_blocked_requests = cls._blocked_counter + blocked_nodes_attacks

        avg_risk_score = (
            round(sum(n.get("risk_score", 0.0) for n in nodes) / total_attackers, 1)
            if total_attackers > 0 else 0.0
        )

        # Attack type counts
        attack_type_map: Dict[str, int] = {}
        for n in nodes:
            t = n.get("attack_type", "UNKNOWN")
            attack_type_map[t] = attack_type_map.get(t, 0) + 1
        top_attack_types = [
            {"type": k, "count": v}
            for k, v in sorted(attack_type_map.items(), key=lambda x: x[1], reverse=True)
        ]

        # Top Hotspots (grouped by city)
        city_map: Dict[str, Dict[str, Any]] = {}
        for n in nodes:
            c = n.get("city", "Unknown")
            if c not in city_map:
                lat_v = float(n.get("latitude") or n.get("lat") or 0.0)
                lng_v = float(n.get("longitude") or n.get("lng") or 0.0)
                city_map[c] = {
                    "city": c,
                    "state": n.get("state", ""),
                    "pincode": n.get("pincode", ""),
                    "count": 0,
                    "latitude": lat_v,
                    "longitude": lng_v,
                    "lat": lat_v,
                    "lng": lng_v,
                }
            city_map[c]["count"] += 1

        top_hotspots = sorted(city_map.values(), key=lambda x: x["count"], reverse=True)

        # Severity breakdown
        severity_map: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for n in nodes:
            sev = n.get("severity", "MEDIUM").upper()
            severity_map[sev] = severity_map.get(sev, 0) + 1

        # Sector breakdown
        sector_map: Dict[str, int] = {}
        for n in nodes:
            sec = n.get("target_sector", "General")
            sector_map[sec] = sector_map.get(sec, 0) + 1

        # Status breakdown
        status_map: Dict[str, int] = {"ACTIVE_ATTACKING": 0, "HONEYPOT_TRAPPED": 0, "BLOCKED_BY_FIREWALL": 0}
        for n in nodes:
            st = n.get("status", "ACTIVE_ATTACKING")
            status_map[st] = status_map.get(st, 0) + 1

        blocked_ips = [n["ip"] for n in nodes if n.get("status") == "BLOCKED_BY_FIREWALL"]
        # Velocity estimate: ~1,420 attacks/min across coordinated honeypots & ingress sensors
        active_attacks_per_min = max(850, active_attacks * 85)

        return {
            "total_attackers": total_attackers,
            "active_attacks": active_attacks,
            "critical_threats": critical_threats,
            "top_attack_types": top_attack_types,
            "top_hotspots": top_hotspots[:10],
            "total_blocked_requests": total_blocked_requests,
            "avg_risk_score": avg_risk_score,
            "active_attacks_per_min": active_attacks_per_min,
            "blocked_ips": blocked_ips,
            "severity_breakdown": severity_map,
            "target_sector_breakdown": sector_map,
            "status_breakdown": status_map,
        }

    @classmethod
    def get_live_feed(cls, db: Optional[Session] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Generates recent live cyber malicious attack events from attacker infrastructure.
        Preserves accurate attacker IPs, hotspots, payloads and timestamps.
        Zero victim personal information.
        """
        nodes = cls.get_attackers(db=db, limit=50)
        if not nodes:
            nodes = list(cls._memory_nodes.values())

        now = datetime.now(timezone.utc)
        events = []
        
        target_labels = {
            "Banking & Financial": ["SBI NetBanking Gateway", "HDFC UPI Ingress Node", "Axis NetPass API", "ICICI Core Switch", "NPCI UPI Router"],
            "Public Utilities": ["State Power Billing Portal", "Discom E-Bill API", "Municipal Water Gateway", "Fastag Toll Switch"],
            "E-Commerce / Logistics": ["IndiaPost Delivery Hub", "Customs Clearance Inbound API", "Bluedart Parcel Router", "Paytm Checkout Engine"],
            "Telecommunications": ["Airtel Pre-paid Core IMS", "Jio VoLTE Signaling Gateway", "SMS OTP Shortcode Gateway", "SIM Swapping Hub"],
            "Govt Services": ["PM-Kisan DBT Portal", "Aadhaar e-KYC Verification API", "State Scholarship Portal", "EPFO Member Passbook API"]
        }

        # Select a realistic set of nodes
        for i in range(min(limit, len(nodes))):
            node = nodes[i % len(nodes)]
            # Stagger timestamps realistically within the last 15 minutes
            offset_seconds = (i * 35) + (i % 5) * 12
            evt_time = now - timedelta(seconds=offset_seconds)
            
            targets = target_labels.get(node.get("target_sector"), ["Enterprise Payment Gateway"])
            target_desc = targets[i % len(targets)]

            is_blocked = (
                node.get("status") == "BLOCKED_BY_FIREWALL" or
                (node.get("severity") == "CRITICAL" and i % 3 == 0) or
                (node.get("status") == "HONEYPOT_TRAPPED")
            )

            if node.get("status") == "BLOCKED_BY_FIREWALL":
                action = "BLOCKED_BY_FIREWALL"
            elif node.get("status") == "HONEYPOT_TRAPPED":
                action = "HONEYPOT_REDIRECT"
            elif is_blocked:
                action = "BLOCKED_BY_WAF"
            else:
                action = "RATE_LIMITED_MONITORED"

            evt_id = f"EVT-IN-{10000 + i * 37}"
            lat_v = float(node.get("lat") or node.get("latitude") or 22.5937)
            lng_v = float(node.get("lng") or node.get("longitude") or 78.9629)
            events.append({
                "id": evt_id,
                "event_id": evt_id,
                "timestamp": evt_time.isoformat(),
                "attacker_ip": node["ip"],
                "hostname": node.get("hostname"),
                "city": node["city"],
                "state": node["state"],
                "pincode": node.get("pincode"),
                "location": f"{node['city']}, {node['state']} ({node.get('pincode', '')})",
                "latitude": lat_v,
                "longitude": lng_v,
                "lat": lat_v,
                "lng": lng_v,
                "attack_type": node["attack_type"],
                "severity": node["severity"],
                "target": target_desc,
                "malicious_request_sample": node.get("malicious_request_sample"),
                "payload_sample": node.get("malicious_request_sample"),
                "blocked_status": is_blocked,
                "action_taken": action,
                "primary_case_id": node.get("primary_case_id"),
                "primary_case_number": node.get("primary_case_number"),
                "linked_case_ids": node.get("linked_case_ids", []),
                "linked_case_numbers": node.get("linked_case_numbers", [])
            })

        # Return sorted descending by timestamp
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events

    @classmethod
    def block_attacker(
        cls,
        db: Optional[Session] = None,
        attacker_id: Optional[int] = None,
        ip: Optional[str] = None,
        reason: Optional[str] = None,
        firewall_rule: Optional[str] = "DROP"
    ) -> Optional[Dict[str, Any]]:
        """
        Simulates perimeter firewall / ISP null-route mitigation for an attacker IP.
        Updates status to 'BLOCKED_BY_FIREWALL'.
        """
        target_dict: Optional[Dict[str, Any]] = None

        # 1. Update in DB if available
        if db is not None:
            try:
                node = None
                if attacker_id:
                    node = db.query(ThreatNode).filter(ThreatNode.id == attacker_id).first()
                if not node and ip:
                    node = db.query(ThreatNode).filter(ThreatNode.ip == ip.strip()).first()

                if node:
                    node.status = "BLOCKED_BY_FIREWALL"
                    node.attack_count = node.attack_count + 1
                    meta = dict(node.meta_data or {})
                    meta["blocked_at"] = datetime.now(timezone.utc).isoformat()
                    meta["block_reason"] = reason or "SIEM threat score exceeded threshold"
                    meta["firewall_rule"] = firewall_rule or "DROP"
                    node.meta_data = meta
                    db.commit()
                    target_dict = node.to_dict()
            except Exception as e:
                logger.error(f"Error blocking attacker in DB: {e}")
                db.rollback()

        # 2. Update memory store
        if not target_dict:
            for nid, n in cls._memory_nodes.items():
                if (attacker_id and nid == attacker_id) or (ip and n["ip"] == ip.strip()):
                    n["status"] = "BLOCKED_BY_FIREWALL"
                    n["attack_count"] = n.get("attack_count", 0) + 1
                    n.setdefault("metadata", {})["blocked_at"] = datetime.now(timezone.utc).isoformat()
                    n["metadata"]["block_reason"] = reason or "SIEM threat score exceeded threshold"
                    target_dict = dict(n)
                    break
        else:
            cls._memory_nodes[target_dict["id"]] = dict(target_dict)

        if not target_dict:
            return None

        cls._blocked_counter += 1
        rule_id = f"FW-BLOCK-{abs(hash(target_dict['ip'])) % 90000 + 10000}"

        return {
            "success": True,
            "message": f"Attacker IP {target_dict['ip']} ({target_dict['city']}) successfully blocked on perimeter firewalls.",
            "attacker": target_dict,
            "firewall_rule_id": rule_id,
            "action": "BLOCKED_BY_FIREWALL",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
