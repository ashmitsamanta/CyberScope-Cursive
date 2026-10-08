import re
from typing import Dict, Any, List


class CommunicationAnalyzer:
    """
    Deterministic rule-based communication content analyzer.
    Detects scam language markers, authority impersonation, credential harvesting,
    and coercive urgency without relying on unstable stochastic LLMs.
    """

    PATTERNS = {
        "URGENCY": [
            r"\b(immediate(?:ly)?|urgent(?:ly)?|within (?:1|2|5|10|24) (?:hours?|mins?|minutes?)|expires? (?:today|soon|within)|act now|last chance|final notice)\b",
            r"\b(block(?:ed)?|suspend(?:ed)?|terminat(?:ed|ing)|deactivat(?:ed)?|stop(?:ped)?)\s+(?:within|in|today)\b",
        ],
        "IMPERSONATION": [
            r"\b(rbi|reserve bank|income tax department|sbi|hdfc|icici|axis bank|police cyber cell|cbi|electricity board|customs|courier customs|telecom department|trai)\b",
            r"\b(official notification|security team|fraud prevention department|customer care)\b",
        ],
        "ACCOUNT_THREAT": [
            r"\b(account (?:will be )?blocked|sim (?:card )?deactivated|card disabled|freeze account|restricted access|blacklisted)\b",
            r"\b(penalty of rs|fine imposed|legal action initiated|warrant)\b",
        ],
        "VERIFICATION_SCAM": [
            r"\b(update kyc|kyc expired|pan verification|aadhaar link(?:ed)?|biometric update|profile verification)\b",
            r"\b(click here to verify|mandatory verification|re-activate account)\b",
        ],
        "CREDENTIAL_REQUEST": [
            r"\b(share otp|enter pin|submit password|send cvv|card details|login credential|anydesk|teamviewer|rustdesk)\b",
        ],
        "PAYMENT_REQUEST": [
            r"\b(pay immediately|processing fee|refund fee|clearance charge|security deposit|refundable amount|pay rs\.?|transfer now)\b",
        ],
        "LOTTERY_REFUND_BAIT": [
            r"\b(won a lottery|cashback credited|reward points expire|unclaimed refund|lottery prize|credited to your wallet)\b",
        ]
    }

    SUSPICIOUS_DOMAINS_TLD = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".icu", ".vip"
    }

    @classmethod
    def analyze(cls, content: str, url: str = None) -> Dict[str, Any]:
        if not content:
            content = ""

        findings: List[Dict[str, Any]] = []
        text_lower = content.lower()
        matched_categories = []
        total_suspicion_score = 0.0

        for category, regex_list in cls.PATTERNS.items():
            cat_matches = []
            for pat in regex_list:
                matches = re.findall(pat, text_lower, re.IGNORECASE)
                if matches:
                    cat_matches.extend(matches if isinstance(matches[0], str) else [m[0] for m in matches])

            if cat_matches:
                unique_matches = list(set(cat_matches))
                score_weight = 15.0 if category in ("CREDENTIAL_REQUEST", "ACCOUNT_THREAT", "VERIFICATION_SCAM") else 10.0
                total_suspicion_score += score_weight
                matched_categories.append(category)
                findings.append({
                    "category": category,
                    "weight": score_weight,
                    "matched_tokens": unique_matches,
                    "explanation": f"Observed {category.replace('_', ' ').lower()} trigger terms: '{', '.join(unique_matches[:3])}'"
                })

        # URL inspection
        if url:
            url_lower = url.lower()
            if any(url_lower.endswith(tld) or f"{tld}/" in url_lower for tld in cls.SUSPICIOUS_DOMAINS_TLD):
                findings.append({
                    "category": "SUSPICIOUS_LINK",
                    "weight": 20.0,
                    "matched_tokens": [url],
                    "explanation": "Target link uses a high-risk dynamic TLD commonly associated with short-lived phishing sites."
                })
                total_suspicion_score += 20.0
                matched_categories.append("SUSPICIOUS_LINK")

            # Check if domain mimics financial institutions
            for bank in ["sbi", "hdfc", "icici", "rbi", "kyc", "bank", "paytm"]:
                if bank in url_lower and not any(legit in url_lower for legit in [f"{bank}.co.in", f"{bank}.com"]):
                    findings.append({
                        "category": "TYPOSQUATTING_LINK",
                        "weight": 25.0,
                        "matched_tokens": [url],
                        "explanation": f"Domain mimics brand '{bank}' but does not match authorized legitimate domain."
                    })
                    total_suspicion_score += 25.0
                    matched_categories.append("TYPOSQUATTING_LINK")
                    break

        capped_score = min(100.0, total_suspicion_score)
        
        return {
            "suspicion_score": capped_score,
            "categories": matched_categories,
            "is_suspicious": capped_score >= 25.0,
            "findings": findings,
            "message_length": len(content),
        }
