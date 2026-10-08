import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional


def normalize_phone(phone: str) -> str:
    """
    Normalizes synthetic phone numbers into standard E.164-like format (+91xxxxxxxxxx).
    Handles spaces, dashes, leading zeroes, country code prefixes.
    """
    if not phone:
        return ""
    # Remove all whitespace, dashes, brackets, dots
    cleaned = re.sub(r"[\s\-\(\)\.]", "", str(phone).strip())
    
    # Check if starts with +91
    if cleaned.startswith("+91"):
        digits = cleaned[3:]
    elif cleaned.startswith("91") and len(cleaned) == 12:
        digits = cleaned[2:]
    elif cleaned.startswith("0") and len(cleaned) == 11:
        digits = cleaned[1:]
    else:
        digits = cleaned.lstrip("+")
    
    # If 10 digits, prepend standard synthetic India country code +91
    if len(digits) == 10 and digits.isdigit():
        return f"+91{digits}"
    
    # Fallback to +digits if alphanumeric or international
    return f"+{digits}" if not digits.startswith("+") else digits


def normalize_domain(domain_or_url: str) -> str:
    """
    Extracts and normalizes domain from URL or domain string.
    Lowercases, strips www., removes ports and paths.
    """
    if not domain_or_url:
        return ""
    raw = domain_or_url.strip().lower()
    
    # If it doesn't look like a URL scheme, add dummy scheme for urlparse
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
        
    try:
        parsed = urlparse(raw)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        # Remove port if present
        netloc = netloc.split(":")[0]
        # Strip leading www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc.strip("/")
    except Exception:
        # Fallback regex
        match = re.search(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+)", domain_or_url.lower())
        return match.group(1) if match else domain_or_url.lower().strip()


def normalize_url(url: str) -> str:
    """
    Normalizes a full URL: canonical scheme (https/http), lowercase domain, strip trailing slash.
    """
    if not url:
        return ""
    raw = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url.strip().rstrip("/")


def normalize_upi(upi_id: str) -> str:
    """
    Normalizes UPI identifiers: user@handle -> lowercase, stripped.
    e.g. 'Payee123@OKAXIS' -> 'payee123@okaxis'
    """
    if not upi_id:
        return ""
    return str(upi_id).strip().lower()


def normalize_email(email: str) -> str:
    """
    Normalizes email: lowercase, stripped.
    """
    if not email:
        return ""
    return str(email).strip().lower()


def normalize_bank_account(account: str) -> str:
    """
    Normalizes synthetic bank account number: removes spaces/dashes, uppercase alphanumeric.
    """
    if not account:
        return ""
    return re.sub(r"[\s\-\.]", "", str(account).strip()).upper()


def normalize_entity_value(entity_type: str, value: str) -> str:
    """Universal dispatcher for deterministic entity normalization."""
    t = entity_type.upper()
    if t == "PHONE":
        return normalize_phone(value)
    elif t == "DOMAIN":
        return normalize_domain(value)
    elif t == "URL":
        return normalize_url(value)
    elif t == "UPI_ID":
        return normalize_upi(value)
    elif t == "EMAIL":
        return normalize_email(value)
    elif t == "BANK_ACCOUNT":
        return normalize_bank_account(value)
    elif t in ("IP_ADDRESS", "DEVICE"):
        return str(value).strip().lower()
    return str(value).strip()


class EntityExtractor:
    """
    Deterministic rule-based entity extractor from raw unformatted text
    (e.g., SMS messages, emails, complaints).
    """

    # Regex definitions (hardened against ReDoS with non-overlapping linear segment parsing)
    PHONE_REGEX = re.compile(
        r"(?:\+?91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}\b|\b(?:\+?1[\-\s]?)?[2-9]\d{2}[\-\s]?\d{3}[\-\s]?\d{4}\b"
    )
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
    # Non-overlapping hostname segments eliminate catastrophic backtracking:
    URL_REGEX = re.compile(
        r"\b(?:https?://|www\.)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}(?:/[^\s]*)?\b",
        re.IGNORECASE
    )
    UPI_REGEX = re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,64}@(?!gmail|yahoo|outlook|hotmail)[a-zA-Z0-9]{2,32}\b",
        re.IGNORECASE
    )
    AMOUNT_REGEX = re.compile(
        r"(?:₹|Rs\.?|INR)\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        re.IGNORECASE
    )

    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[Any]]:
        if not text:
            return {
                "phones": [], "emails": [], "urls": [], "domains": [],
                "upi_ids": [], "amounts": []
            }

        # Guard against unbounded input length abuse
        bounded_text = str(text)[:50000]

        extracted: Dict[str, List[Any]] = {
            "phones": [],
            "emails": [],
            "urls": [],
            "domains": [],
            "upi_ids": [],
            "amounts": [],
        }

        # 1. URLs & Domains
        found_urls = cls.URL_REGEX.findall(bounded_text)
        for u in found_urls:
            norm_u = normalize_url(u)
            if norm_u not in extracted["urls"]:
                extracted["urls"].append(norm_u)
            dom = normalize_domain(u)
            if dom and dom not in extracted["domains"]:
                extracted["domains"].append(dom)

        # 2. UPI IDs (must be checked before emails, or exclude standard email domains)
        found_upis = cls.UPI_REGEX.findall(text)
        for upi in found_upis:
            norm_upi = normalize_upi(upi)
            if norm_upi not in extracted["upi_ids"]:
                extracted["upi_ids"].append(norm_upi)

        # 3. Emails (exclude any matching UPIs)
        found_emails = cls.EMAIL_REGEX.findall(text)
        for em in found_emails:
            norm_em = normalize_email(em)
            if norm_em not in extracted["upi_ids"] and norm_em not in extracted["emails"]:
                extracted["emails"].append(norm_em)

        # 4. Phones
        found_phones = cls.PHONE_REGEX.findall(text)
        for p in found_phones:
            norm_p = normalize_phone(p)
            if norm_p and norm_p not in extracted["phones"]:
                extracted["phones"].append(norm_p)

        # 5. Currency Amounts
        found_amounts = cls.AMOUNT_REGEX.findall(text)
        for amt_str in found_amounts:
            try:
                amt_clean = amt_str.replace(",", "")
                val = float(amt_clean)
                if val not in extracted["amounts"]:
                    extracted["amounts"].append(val)
            except ValueError:
                continue

        return extracted
