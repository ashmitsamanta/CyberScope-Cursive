import os
import sys
import json
import random
import argparse
from datetime import datetime, timedelta, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def generate_synthetic_dataset(profile: str = "demo", num_accounts: int = 100, num_transactions: int = 300):
    """
    Deterministic synthetic fraud dataset generator with planted behavioral patterns.
    Ensures zero real PII or bank connectivity.
    Seed is strictly fixed at 42.
    """
    random.seed(42)
    base_time = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)

    # 1. Infrastructure pools (all purely synthetic)
    phones = [f"+91{random.randint(9000000000, 9999999999)}" for _ in range(35)]
    domains = [
        "secure-kyc-update.com",
        "verify-portal-in.net",
        "quick-kyc-auth.org",
        "urgent-ebill-pay.co",
        "parcel-customs-clear.net",
        "bank-alert-update.in",
        "reward-points-claim.top",
        "tax-refund-portal.org",
    ]
    upis = [
        "centralmule99@okaxis",
        "kycpaydesk@paytm",
        "clearancefast@ibl",
        "quickflow88@ybl",
        "securehub@icici",
        "paydesk42@okhdfcbank",
        "merchanttrust@sbi",
    ]
    devices = [f"DEV-SIM-{1000 + i:04d}" for i in range(25)]
    ip_addresses = [f"198.51.100.{10 + i}" for i in range(30)]

    entities = []
    relationships = []
    transactions = []
    cases = []
    messages = []
    indicators = []
    campaigns = []

    entity_id_counter = 1

    def make_entity(etype: str, val: str, risk: float, meta=None):
        nonlocal entity_id_counter
        eid = entity_id_counter
        entity_id_counter += 1
        e = {
            "id": eid,
            "entity_type": etype,
            "value": val,
            "normalized_value": val.lower(),
            "risk_score": risk,
            "metadata": meta or {}
        }
        entities.append(e)
        return e

    # -------------------------------------------------------------
    # CAMPAIGN 1: Operation Phantom KYC (Curated Primary Demo Scenario)
    # -------------------------------------------------------------
    camp_kyc = {
        "id": 1,
        "campaign_id": "CAMP-PHANTOM-KYC",
        "name": "Operation Phantom KYC",
        "description": "Coordinated cyber-fraud ring impersonating major public banks with urgent KYC deactivation threats.",
        "risk_score": 92.0,
        "case_count": 5,
        "entity_count": 22,
        "status": "ACTIVE",
        "first_seen": (base_time + timedelta(days=2)).isoformat(),
        "last_seen": (base_time + timedelta(days=15)).isoformat(),
        "shared_indicators": {
            "domains": ["secure-kyc-update.com", "verify-portal-in.net", "quick-kyc-auth.org"],
            "phones": [phones[0], phones[1], phones[2]],
            "upi_ids": ["centralmule99@okaxis", "kycpaydesk@paytm"],
            "devices": [devices[0], devices[1]]
        }
    }
    campaigns.append(camp_kyc)

    # Core Infrastructure Entities for Phantom KYC
    ent_dom1 = make_entity("DOMAIN", "secure-kyc-update.com", 88.0, {"tld": ".com", "registrar": "Simulated Registrar"})
    ent_dom2 = make_entity("DOMAIN", "verify-portal-in.net", 85.0)
    ent_dom3 = make_entity("DOMAIN", "quick-kyc-auth.org", 80.0)

    ent_phone1 = make_entity("PHONE", phones[0], 85.0, {"carrier": "Synthetic Telecom A"})
    ent_phone2 = make_entity("PHONE", phones[1], 80.0)
    ent_phone3 = make_entity("PHONE", phones[2], 75.0)

    ent_upi1 = make_entity("UPI_ID", "centralmule99@okaxis", 90.0, {"bank": "Axis Simulation"})
    ent_upi2 = make_entity("UPI_ID", "kycpaydesk@paytm", 82.0)

    ent_dev1 = make_entity("DEVICE", devices[0], 75.0, {"os": "Android 13"})
    ent_ip1 = make_entity("IP_ADDRESS", ip_addresses[0], 70.0)

    # Secondary Mules for Phantom KYC Money Flow
    mule_acc_hub = make_entity("BANK_ACCOUNT", "SIM-ACC-MULE-HUB-891", 88.0, {"branch": "Metro Cyber Hub"})
    mule_layer1_a = make_entity("BANK_ACCOUNT", "SIM-ACC-LAYER1-A-101", 72.0)
    mule_layer1_b = make_entity("BANK_ACCOUNT", "SIM-ACC-LAYER1-B-102", 72.0)
    mule_layer1_c = make_entity("BANK_ACCOUNT", "SIM-ACC-LAYER1-C-103", 70.0)
    mule_exit_1 = make_entity("BANK_ACCOUNT", "SIM-ACC-CASH-OUT-999", 85.0)

    # Relationship links between campaign infrastructure
    for dom in [ent_dom1, ent_dom2, ent_dom3]:
        relationships.append({"source_entity_id": ent_phone1["id"], "target_entity_id": dom["id"], "relationship_type": "RESOLVES_TO", "confidence": 0.95})
        relationships.append({"source_entity_id": dom["id"], "target_entity_id": ent_upi1["id"], "relationship_type": "ASSOCIATED_WITH", "confidence": 0.90})

    relationships.append({"source_entity_id": ent_upi1["id"], "target_entity_id": mule_acc_hub["id"], "relationship_type": "LINKED_TO", "confidence": 0.98})
    relationships.append({"source_entity_id": ent_dev1["id"], "target_entity_id": mule_acc_hub["id"], "relationship_type": "USED_BY", "confidence": 0.95})

    # 5 Victims of Phantom KYC
    victim_names = [
        ("Rajiv Sharma", "CS-1024", 48500.0, "Urgent: Your SBI account will be suspended within 2 hours. Update KYC at https://secure-kyc-update.com immediately or pay ₹500 fee to centralmule99@okaxis."),
        ("Meera Sen", "CS-1025", 52000.0, "Official Bank Alert: Mandatory Aadhaar-PAN link failed. Verify immediately at https://secure-kyc-update.com to prevent debit freeze."),
        ("Anand Verma", "CS-1026", 35000.0, "Notice: Electricity supply scheduled for disconnection due to unpaid invoice. Verify payment via https://verify-portal-in.net or contact 9000000001."),
        ("Sunita Patil", "CS-1027", 49500.0, "Dear customer, your credit card loyalty reward points expire today. Claim refund of ₹5,000 at https://quick-kyc-auth.org now."),
        ("Kavita Rao", "CS-1028", 41000.0, "SBI Security Warning: Suspicious transaction detected. Re-verify identity at https://secure-kyc-update.com.")
    ]

    for idx, (v_name, c_num, s_amt, msg_txt) in enumerate(victim_names):
        v_person = make_entity("PERSON", v_name, 10.0)
        v_acc = make_entity("BANK_ACCOUNT", f"SIM-ACC-VICTIM-{200 + idx}", 15.0)
        v_phone = make_entity("PHONE", phones[10 + idx], 10.0)

        relationships.append({"source_entity_id": v_person["id"], "target_entity_id": v_acc["id"], "relationship_type": "OWNS", "confidence": 1.0})
        relationships.append({"source_entity_id": v_person["id"], "target_entity_id": v_phone["id"], "relationship_type": "USED_BY", "confidence": 1.0})

        # Case record
        case_risk = 84.0 if idx == 0 else (91.0 if idx == 1 else 76.0)
        case_sev = "HIGH" if case_risk < 90 else "CRITICAL"
        case_t = base_time + timedelta(days=3 + idx, hours=idx * 2)

        c_obj = {
            "id": idx + 1,
            "case_number": c_num,
            "title": f"Simulated KYC Suspension Alert - Victim {v_name.split()[0]}",
            "description": msg_txt,
            "status": "INVESTIGATING" if idx == 0 else "NEW",
            "severity": case_sev,
            "source": "VICTIM_COMPLAINT_PORTAL",
            "risk_score": case_risk,
            "campaign_id": camp_kyc["id"],
            "created_at": case_t.isoformat(),
            "updated_at": case_t.isoformat(),
            "metadata": {"victim_name": v_name, "stolen_amount": s_amt}
        }
        cases.append(c_obj)

        c_ent = make_entity("CASE", c_num, case_risk, {"title": c_obj["title"]})

        # Link victim to case
        relationships.append({"source_entity_id": v_person["id"], "target_entity_id": c_ent["id"], "relationship_type": "REPORTED_IN", "confidence": 1.0})
        relationships.append({"source_entity_id": ent_phone1["id"], "target_entity_id": c_ent["id"], "relationship_type": "REPORTED_IN", "confidence": 1.0})
        relationships.append({"source_entity_id": ent_dom1["id"], "target_entity_id": c_ent["id"], "relationship_type": "REPORTED_IN", "confidence": 0.95})
        relationships.append({"source_entity_id": ent_upi1["id"], "target_entity_id": c_ent["id"], "relationship_type": "REPORTED_IN", "confidence": 0.95})

        # Message
        messages.append({
            "id": len(messages) + 1,
            "timestamp": case_t.isoformat(),
            "sender_phone": ent_phone1["value"],
            "receiver_phone": v_phone["value"],
            "channel": "SMS",
            "subject": "Urgent Bank Notice",
            "content": msg_txt,
            "url": "https://secure-kyc-update.com",
            "case_id": c_obj["id"]
        })

        # Initial fraud transaction: Victim -> Mule Hub
        tx_time = case_t + timedelta(minutes=12)
        tx_obj = {
            "id": len(transactions) + 1,
            "transaction_ref": f"TX-SIM-{9000 + len(transactions):04d}",
            "timestamp": tx_time.isoformat(),
            "sender_entity_id": v_acc["id"],
            "receiver_entity_id": mule_acc_hub["id"],
            "amount": s_amt,
            "currency": "INR",
            "channel": "UPI",
            "case_id": c_obj["id"],
            "status": "FLAGGED",
            "metadata": {"channel_desc": "Immediate Payment Service"}
        }
        transactions.append(tx_obj)
        relationships.append({
            "source_entity_id": v_acc["id"],
            "target_entity_id": mule_acc_hub["id"],
            "relationship_type": "TRANSFERRED_TO",
            "confidence": 1.0,
            "metadata": {"amount": s_amt}
        })

    # Pattern B & C: Rapid Mule Fan-Out from Mule Hub
    fanout_time = base_time + timedelta(days=3, hours=1)
    split_amounts = [18500.0, 15000.0, 15000.0]
    mule_targets = [mule_layer1_a, mule_layer1_b, mule_layer1_c]

    for m_tgt, amt in zip(mule_targets, split_amounts):
        fanout_time += timedelta(minutes=4)
        tx_fan = {
            "id": len(transactions) + 1,
            "transaction_ref": f"TX-SIM-{9000 + len(transactions):04d}",
            "timestamp": fanout_time.isoformat(),
            "sender_entity_id": mule_acc_hub["id"],
            "receiver_entity_id": m_tgt["id"],
            "amount": amt,
            "currency": "INR",
            "channel": "IMPS",
            "case_id": 1,
            "status": "FLAGGED",
            "metadata": {"layering_hop": 2}
        }
        transactions.append(tx_fan)
        relationships.append({
            "source_entity_id": mule_acc_hub["id"],
            "target_entity_id": m_tgt["id"],
            "relationship_type": "TRANSFERRED_TO",
            "confidence": 0.95
        })

        # Forward to final cash out node
        tx_exit = {
            "id": len(transactions) + 1,
            "transaction_ref": f"TX-SIM-{9000 + len(transactions):04d}",
            "timestamp": (fanout_time + timedelta(minutes=8)).isoformat(),
            "sender_entity_id": m_tgt["id"],
            "receiver_entity_id": mule_exit_1["id"],
            "amount": amt - 500.0,
            "currency": "INR",
            "channel": "NEFT",
            "case_id": 1,
            "status": "FLAGGED",
            "metadata": {"layering_hop": 3}
        }
        transactions.append(tx_exit)
        relationships.append({
            "source_entity_id": m_tgt["id"],
            "target_entity_id": mule_exit_1["id"],
            "relationship_type": "TRANSFERRED_TO",
            "confidence": 0.95
        })

    # Pattern H: Circular movement simulation (A -> B -> C -> A)
    circ_a = make_entity("BANK_ACCOUNT", "SIM-ACC-CIRCULAR-A", 65.0)
    circ_b = make_entity("BANK_ACCOUNT", "SIM-ACC-CIRCULAR-B", 65.0)
    circ_c = make_entity("BANK_ACCOUNT", "SIM-ACC-CIRCULAR-C", 65.0)

    # Campaign mule accounts receiving victim payouts from the secondary campaigns.
    # The threat-map wirer binds each of these to its operator IP via ACCESSED_FROM.
    mule_ebill = make_entity("BANK_ACCOUNT", "SIM-ACC-EBILL-MULE-401", 78.0, {"branch": "Synthetic UPOS Branch"})
    mule_customs = make_entity("BANK_ACCOUNT", "SIM-ACC-CUSTOMS-402", 76.0)
    mule_fastag = make_entity("BANK_ACCOUNT", "SIM-ACC-FASTAG-403", 80.0)
    mule_loan = make_entity("BANK_ACCOUNT", "SIM-ACC-LOAN-404", 84.0)
    mule_kisan = make_entity("BANK_ACCOUNT", "SIM-ACC-KISAN-405", 77.0)

    upi_ebill = make_entity("UPI_ID", "quickflow88@ybl", 84.0)
    upi_customs = make_entity("UPI_ID", "clearancefast@ibl", 82.0)
    relationships.append({"source_entity_id": upi_ebill["id"], "target_entity_id": mule_ebill["id"], "relationship_type": "LINKED_TO", "confidence": 0.97})
    relationships.append({"source_entity_id": upi_customs["id"], "target_entity_id": mule_customs["id"], "relationship_type": "LINKED_TO", "confidence": 0.97})

    # Per-campaign attacker handsets. Victim-facing CONTACTED edges are added below;
    # ROUTED_THROUGH links to SIM-box / C2 IPs are added by the threat-map wirer.
    ent_phone_simswap = make_entity("PHONE", phones[3], 82.0, {"role": "SIM_SWAP_DISPATCH", "carrier": "Synthetic Telecom B"})
    ent_phone_ebill = make_entity("PHONE", phones[4], 80.0, {"role": "BULK_LURE_DISPATCH", "carrier": "Synthetic Telecom C"})
    ent_phone_loan = make_entity("PHONE", phones[5], 81.0, {"role": "RECOVERY_AGENT_HARASSMENT", "carrier": "Synthetic Telecom D"})
    ent_phone_customs = make_entity("PHONE", phones[6], 78.0, {"role": "CUSTOMS_AGENT_IMPERSONATION", "carrier": "Synthetic Telecom E"})
    ent_phone_fastag = make_entity("PHONE", phones[7], 76.0, {"role": "FASTAG_LURE_DISPATCH", "carrier": "Synthetic Telecom F"})
    ent_phone_kisan = make_entity("PHONE", phones[8], 81.0, {"role": "GOVT_SCHEME_IMPERSONATION", "carrier": "Synthetic Telecom G"})

    c_tx1 = {
        "id": len(transactions) + 1,
        "transaction_ref": f"TX-SIM-{9000 + len(transactions):04d}",
        "timestamp": (base_time + timedelta(days=6)).isoformat(),
        "sender_entity_id": circ_a["id"],
        "receiver_entity_id": circ_b["id"],
        "amount": 25000.0,
        "currency": "INR",
        "channel": "UPI",
        "status": "FLAGGED"
    }
    c_tx2 = {
        "id": len(transactions) + 2,
        "transaction_ref": f"TX-SIM-{9000 + len(transactions) + 1:04d}",
        "timestamp": (base_time + timedelta(days=6, minutes=10)).isoformat(),
        "sender_entity_id": circ_b["id"],
        "receiver_entity_id": circ_c["id"],
        "amount": 24800.0,
        "currency": "INR",
        "channel": "UPI",
        "status": "FLAGGED"
    }
    c_tx3 = {
        "id": len(transactions) + 3,
        "transaction_ref": f"TX-SIM-{9000 + len(transactions) + 2:04d}",
        "timestamp": (base_time + timedelta(days=6, minutes=22)).isoformat(),
        "sender_entity_id": circ_c["id"],
        "receiver_entity_id": circ_a["id"],
        "amount": 24500.0,
        "currency": "INR",
        "channel": "UPI",
        "status": "FLAGGED"
    }
    transactions.extend([c_tx1, c_tx2, c_tx3])
    relationships.append({"source_entity_id": circ_a["id"], "target_entity_id": circ_b["id"], "relationship_type": "TRANSFERRED_TO", "confidence": 1.0})
    relationships.append({"source_entity_id": circ_b["id"], "target_entity_id": circ_c["id"], "relationship_type": "TRANSFERRED_TO", "confidence": 1.0})
    relationships.append({"source_entity_id": circ_c["id"], "target_entity_id": circ_a["id"], "relationship_type": "TRANSFERRED_TO", "confidence": 1.0})

    # -------------------------------------------------------------
    # CAMPAIGN 2 & 3: Secondary Campaigns to meet exact distribution
    # -------------------------------------------------------------
    camp_util = {
        "id": 2,
        "campaign_id": "CAMP-ELECTRICITY-SPOOF",
        "name": "State Electricity Billing Lure",
        "description": "SMS phishing network threatening immediate power cut at midnight for unpaid fake arrears.",
        "risk_score": 78.0,
        "case_count": 8,
        "entity_count": 18,
        "status": "MONITORED",
        "first_seen": (base_time + timedelta(days=5)).isoformat(),
        "last_seen": (base_time + timedelta(days=18)).isoformat(),
        "shared_indicators": {"domains": ["urgent-ebill-pay.co"], "upi_ids": ["quickflow88@ybl"]}
    }
    camp_parcel = {
        "id": 3,
        "campaign_id": "CAMP-PARCEL-CUSTOMS",
        "name": "International Parcel Customs Fee Trap",
        "description": "Victims notified of detained overseas consignment requiring urgent clearance fee payment.",
        "risk_score": 74.0,
        "case_count": 6,
        "entity_count": 14,
        "status": "MONITORED",
        "first_seen": (base_time + timedelta(days=7)).isoformat(),
        "last_seen": (base_time + timedelta(days=19)).isoformat(),
        "shared_indicators": {"domains": ["parcel-customs-clear.net"], "upi_ids": ["clearancefast@ibl"]}
    }
    camp_fastag = {
        "id": 4,
        "campaign_id": "CAMP-FASTAG-SKIMMER",
        "name": "Fastag Recharge Skimmer Syndicate",
        "description": "Cloned FASTag recharge portals intercepting UPI collect approvals from vehicle owners.",
        "risk_score": 81.0,
        "case_count": 1,
        "entity_count": 8,
        "status": "ACTIVE",
        "first_seen": (base_time + timedelta(days=10)).isoformat(),
        "last_seen": (base_time + timedelta(days=17)).isoformat(),
        "shared_indicators": {"domains": ["fastag-quick-recharge.in"], "upi_ids": ["fastagrecharge@ibl"]}
    }
    camp_loan = {
        "id": 5,
        "campaign_id": "CAMP-LOAN-APK-EXTORTION",
        "name": "Instant Loan APK Extortion Ring",
        "description": "Predatory instant-loan APKs exfiltrating contact lists, followed by recovery-agent extortion cycles.",
        "risk_score": 88.0,
        "case_count": 1,
        "entity_count": 9,
        "status": "ACTIVE",
        "first_seen": (base_time + timedelta(days=11)).isoformat(),
        "last_seen": (base_time + timedelta(days=20)).isoformat(),
        "shared_indicators": {"domains": ["rupee-instant-loan.org"], "apk_package": "com.cashfast.rupee.loan"}
    }
    camp_kisan = {
        "id": 6,
        "campaign_id": "CAMP-PMKISAN-EKYC",
        "name": "PM-Kisan Impersonation Nexus",
        "description": "Fake PM-Kisan eKYC portals harvesting Aadhaar OTPs to hold farmer installment payouts.",
        "risk_score": 79.0,
        "case_count": 1,
        "entity_count": 8,
        "status": "MONITORED",
        "first_seen": (base_time + timedelta(days=12)).isoformat(),
        "last_seen": (base_time + timedelta(days=18)).isoformat(),
        "shared_indicators": {"domains": ["pmkisan-ekyc-portal.org"], "lure_format": "Hindi SMS"}
    }
    campaigns.extend([camp_util, camp_parcel, camp_fastag, camp_loan, camp_kisan])

    # -------------------------------------------------------------
    # Generate background cases to reach EXACTLY:
    # 42 total cases
    # 7 high risk (70 - 89)
    # 2 critical (>= 90)
    # 3 campaigns
    # -------------------------------------------------------------
    # Already created 5 cases in Phantom KYC:
    # Case 1: 84 (High)
    # Case 2: 91 (Critical)
    # Case 3: 76 (High)
    # Case 4: 76 (High)
    # Case 5: 76 (High)
    # Current counts: 4 High, 1 Critical, 0 Medium, 0 Low. Total: 5 cases.
    # We need:
    # 2 Critical total -> 1 more Critical (>= 90)
    # 7 High total -> 3 more High (70-89)
    # Remaining 42 - 2 - 7 = 33 cases distributed between Medium (e.g. 18) and Low (e.g. 15).

    # 1 more Critical Case
    c_crit2 = {
        "id": 6,
        "case_number": "CS-1029",
        "title": "Corporate Executive ATO & Rapid Wire Siphon",
        "description": "Simulated multi-channel Account Takeover targeting treasury executive with simultaneous SIM swap and ₹2,50,000 transfer.",
        "status": "ESCALATED",
        "severity": "CRITICAL",
        "source": "TRANSACTION_MONITORING_SIEM",
        "risk_score": 94.0,
        "campaign_id": None,
        "created_at": (base_time + timedelta(days=8)).isoformat(),
        "updated_at": (base_time + timedelta(days=8)).isoformat(),
        "metadata": {"victim_name": "Arjun Mehta", "stolen_amount": 250000.0, "attack_vector": "SIM_SWAP_ATO"}
    }
    cases.append(c_crit2)

    # 3 more High Risk Cases
    high_scenarios = [
        ("CS-1030", "Electricity Disconnection Phishing - Cluster Case A", 82.0, camp_util["id"], "Deepak Yadav", 18700.0),
        ("CS-1031", "Electricity Disconnection Phishing - Cluster Case B", 78.0, camp_util["id"], "Farida Khan", 9450.0),
        ("CS-1032", "Detained Consignment Duty Scam - Case Alpha", 75.0, camp_parcel["id"], "Rohit Malhotra", 14999.0),
    ]
    for cid, ctitle, crisk, camp_ref, v_name, s_amt in high_scenarios:
        cases.append({
            "id": len(cases) + 1,
            "case_number": cid,
            "title": ctitle,
            "description": f"Simulated report: {ctitle}.",
            "status": "INVESTIGATING",
            "severity": "HIGH",
            "source": "AUTOMATED_CORRELATION",
            "risk_score": crisk,
            "campaign_id": camp_ref,
            "created_at": (base_time + timedelta(days=9 + len(cases) % 5)).isoformat(),
            "updated_at": (base_time + timedelta(days=9 + len(cases) % 5)).isoformat(),
            "metadata": {"victim_name": v_name, "stolen_amount": s_amt}
        })

    # Campaign cases CS-1033 .. CS-1035 backed by the Fastag / Loan / PM-Kisan campaigns
    campaign_cases = [
        ("CS-1033", "FASTag Recharge Skim - UPI Collect Abuse", 81.0, camp_fastag["id"], "Priyanka Deshmukh", 12400.0),
        ("CS-1034", "Instant Loan APK Extortion - Contact List Weaponized", 88.0, camp_loan["id"], "Imran Sheikh", 45000.0),
        ("CS-1035", "PM-Kisan eKYC Hold - Aadhaar OTP Harvest", 79.0, camp_kisan["id"], "Lakshmi Prasad", 23800.0),
    ]
    for cid, ctitle, crisk, camp_ref, v_name, s_amt in campaign_cases:
        cases.append({
            "id": len(cases) + 1,
            "case_number": cid,
            "title": ctitle,
            "description": f"Simulated report: {ctitle}.",
            "status": "INVESTIGATING",
            "severity": "HIGH",
            "source": "AUTOMATED_CORRELATION",
            "risk_score": crisk,
            "campaign_id": camp_ref,
            "created_at": (base_time + timedelta(days=10 + len(cases) % 4)).isoformat(),
            "updated_at": (base_time + timedelta(days=10 + len(cases) % 4)).isoformat(),
            "metadata": {"victim_name": v_name, "stolen_amount": s_amt}
        })

    # Now generate remaining 30 cases (Medium: 40-68, Low: 10-38)
    for i in range(30):
        c_num = f"CS-{1036 + i}"
        is_med = i < 18  # 18 medium, 15 low
        c_risk = round(random.uniform(42.0, 65.0), 1) if is_med else round(random.uniform(12.0, 36.0), 1)
        c_sev = "MEDIUM" if is_med else "LOW"
        c_status = random.choice(["NEW", "RESOLVED", "FALSE_POSITIVE", "INVESTIGATING"])

        c_t = base_time + timedelta(days=random.randint(1, 22), hours=random.randint(1, 23))
        cases.append({
            "id": len(cases) + 1,
            "case_number": c_num,
            "title": f"Incident Report {c_num} - {'Suspicious Velocity' if is_med else 'Unrecognized Verification SMS'}",
            "description": f"Synthetic incident telemetry for case {c_num}.",
            "status": c_status,
            "severity": c_sev,
            "source": random.choice(["FRAUD_INBOX", "CUSTOMER_PORTAL", "GATEWAY_ALERT"]),
            "risk_score": c_risk,
            "campaign_id": 2 if i in (2, 3, 4) else (3 if i in (5, 6) else None),
            "created_at": c_t.isoformat(),
            "updated_at": c_t.isoformat()
        })

    # -------------------------------------------------------------
    # Victims for curated cases CS-1029 .. CS-1035 (person, account, phone,
    # lure message, and payout transaction, following the Phantom KYC pattern).
    # CONTACTED / ROUTED_THROUGH edges to attacker infrastructure are added by
    # ThreatMapService.wire_graph_topology, which owns the attacker IP topology.
    # -------------------------------------------------------------
    secondary_victims = [
        (6, "CS-1029", "Arjun Mehta", 250000.0, circ_a, ent_phone_simswap, "NEFT",
         "NetBanking Beneficiary Alert",
         "Alert: A new payee was linked to your corporate netbanking profile after a SIM re-registration event and an OTP for a Rs 2,50,000 transfer was auto-forwarded. If not initiated by you, call your relationship manager immediately.",
         None),
        (7, "CS-1030", "Deepak Yadav", 18700.0, mule_ebill, ent_phone_ebill, "UPI",
         "Electricity Disconnection Notice",
         "Notice: Power supply at your premises is scheduled for disconnection tonight at 9 PM for unpaid arrears of Rs 1,870. Settle immediately at https://bijli-bill-alert.in to restore supply.",
         "https://bijli-bill-alert.in"),
        (8, "CS-1031", "Farida Khan", 9450.0, mule_ebill, ent_phone_ebill, "UPI",
         "Electricity Disconnection Notice",
         "Final reminder: your electricity account is overdue by Rs 945 and disconnection is scheduled tonight. Clear the bill at https://bijli-bill-alert.in before 9 PM.",
         "https://bijli-bill-alert.in"),
        (9, "CS-1032", "Rohit Malhotra", 14999.0, mule_customs, ent_phone_customs, "UPI",
         "Customs Clearance Required",
         "Your inbound international parcel (AWB IN984128) is held at the customs facility. Pay the clearance duty of Rs 14,999 at https://customs-duty-clearance.net to schedule delivery.",
         "https://customs-duty-clearance.net"),
        (10, "CS-1033", "Priyanka Deshmukh", 12400.0, mule_fastag, ent_phone_fastag, "UPI",
         "FASTag Recharge Failure",
         "Your vehicle RC DL-3S-AB-4471 risks blacklisting due to a failed FASTag recharge. Complete the pending recharge of Rs 12,400 at https://fastag-quick-recharge.in within 4 hours.",
         "https://fastag-quick-recharge.in"),
        (11, "CS-1034", "Imran Sheikh", 45000.0, mule_loan, ent_phone_loan, "UPI",
         "Loan Recovery Escalation",
         "Recovery escalation: your outstanding loan dues have moved to the legal desk. Settle Rs 45,000 via https://rupee-instant-loan.org/settle within 24 hours to stop contact-list escalation.",
         "https://rupee-instant-loan.org/settle"),
        (12, "CS-1035", "Lakshmi Prasad", 23800.0, mule_kisan, ent_phone_kisan, "UPI",
         "PM-Kisan Installment Hold",
         "PM-Kisan: your 18th installment is on hold pending eKYC re-verification. Complete Aadhaar OTP verification at https://pmkisan-ekyc-portal.org today to release the payout.",
         "https://pmkisan-ekyc-portal.org"),
    ]

    for v_idx, (c_id, c_num, v_name, s_amt, receiver_ent, attacker_phone, tx_channel, msg_subject, msg_text, msg_url) in enumerate(secondary_victims):
        v_person = make_entity("PERSON", v_name, 10.0)
        v_acc = make_entity("BANK_ACCOUNT", f"SIM-ACC-VICTIM-{210 + v_idx}", 15.0)
        v_phone = make_entity("PHONE", phones[15 + v_idx], 10.0)

        relationships.append({"source_entity_id": v_person["id"], "target_entity_id": v_acc["id"], "relationship_type": "OWNS", "confidence": 1.0})
        relationships.append({"source_entity_id": v_person["id"], "target_entity_id": v_phone["id"], "relationship_type": "USED_BY", "confidence": 1.0})

        case_meta = next(cs for cs in cases if cs["case_number"] == c_num)
        c_ent = make_entity("CASE", c_num, case_meta["risk_score"], {"title": case_meta["title"]})
        relationships.append({"source_entity_id": v_person["id"], "target_entity_id": c_ent["id"], "relationship_type": "REPORTED_IN", "confidence": 1.0})

        messages.append({
            "id": len(messages) + 1,
            "timestamp": case_meta["created_at"],
            "sender_phone": attacker_phone["value"],
            "receiver_phone": v_phone["value"],
            "channel": "SMS",
            "subject": msg_subject,
            "content": msg_text,
            "url": msg_url,
            "case_id": c_id
        })

        tx_time = datetime.fromisoformat(case_meta["created_at"]) + timedelta(minutes=25)
        transactions.append({
            "id": len(transactions) + 1,
            "transaction_ref": f"TX-SIM-{9000 + len(transactions):04d}",
            "timestamp": tx_time.isoformat(),
            "sender_entity_id": v_acc["id"],
            "receiver_entity_id": receiver_ent["id"],
            "amount": s_amt,
            "currency": "INR",
            "channel": tx_channel,
            "case_id": c_id,
            "status": "FLAGGED",
            "metadata": {"channel_desc": "Immediate Payment Service" if tx_channel == "UPI" else "National Electronic Funds Transfer"}
        })
        relationships.append({
            "source_entity_id": v_acc["id"],
            "target_entity_id": receiver_ent["id"],
            "relationship_type": "TRANSFERRED_TO",
            "confidence": 1.0,
            "metadata": {"amount": s_amt}
        })

    # Add background normal accounts and transactions
    for i in range(40):
        acc = make_entity("BANK_ACCOUNT", f"SIM-ACC-NORM-{500 + i}", 10.0)
        # Random normal transaction
        tx = {
            "id": len(transactions) + 1,
            "transaction_ref": f"TX-SIM-{9000 + len(transactions):04d}",
            "timestamp": (base_time + timedelta(days=random.randint(1, 20))).isoformat(),
            "sender_entity_id": acc["id"],
            "receiver_entity_id": mule_acc_hub["id"] if i % 10 == 0 else (acc["id"] + 1 if i < 39 else acc["id"] - 1),
            "amount": float(random.randint(500, 12000)),
            "currency": "INR",
            "channel": random.choice(["UPI", "IMPS", "NEFT"]),
            "status": "SUCCESS"
        }
        transactions.append(tx)

    # Compile dataset package
    dataset = {
        "metadata": {
            "benchmark_version": "1.0.0",
            "seed": 42,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "profile": profile,
            "planted_scenario": "Operation Phantom KYC",
            "total_cases": len(cases),
            "total_entities": len(entities),
            "total_relationships": len(relationships),
            "total_transactions": len(transactions),
            "total_campaigns": len(campaigns)
        },
        "cases": cases,
        "entities": entities,
        "relationships": relationships,
        "transactions": transactions,
        "messages": messages,
        "campaigns": campaigns
    }

    return dataset


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CYBERSCOPE Synthetic Dataset Generator")
    parser.add_argument("--profile", type=str, default="demo", help="Profile (demo, standard, full)")
    parser.add_argument("--accounts", type=int, default=100)
    parser.add_argument("--transactions", type=int, default=300)
    parser.add_argument("--output", type=str, default="data/synthetic/benchmark_dataset.json")

    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    data = generate_synthetic_dataset(profile=args.profile, num_accounts=args.accounts, num_transactions=args.transactions)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    meta = data["metadata"]
    print(f"Generated synthetic benchmark dataset: {args.output}")
    print(f"Cases: {meta['total_cases']} | Entities: {meta['total_entities']} | Transactions: {meta['total_transactions']} | Campaigns: {meta['total_campaigns']}")
