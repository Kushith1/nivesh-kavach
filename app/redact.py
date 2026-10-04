"""
Redaction module for Nivesh Kavach.
Redacts personal identifiable information (PII) before analysis:
- Indian mobile numbers: [PHONE]
- 12-digit Aadhaar-like numbers: [ID]
- PAN cards: [PAN]
- UPI IDs: [UPI]
- Email addresses: [EMAIL]
- 9-18 digit account numbers: [ACCOUNT]
- OTP patterns: [OTP]
"""

import re
from typing import Tuple, Dict

# Regex patterns compiled for efficiency
OTP_PATTERN = re.compile(
    r"(?i)\b(?:otp(?:\s+is|\s*[:=-])?\s*|[a-z]*one\s*time\s*password\s*(?:is|[:=-])?\s*|ओटीपी(?:\s*है|\s*[:=-])?\s*)(\d{4,8})\b"
)
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
UPI_PATTERN = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,64}@(?!gov\.in|nic\.in|com\b|net\b|org\b|co\b|in\b|edu\b|io\b)[a-zA-Z0-9]{2,30}\b"
)
PAN_PATTERN = re.compile(
    r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}\b"
)
AADHAAR_PATTERN = re.compile(
    r"(?<!\d)[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}(?!\d)"
)
PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:(?:\+|00)91[-\s]?)?[6-9]\d{4}[-\s]?\d{5}(?!\d)"
)
ACCOUNT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])\d{9,18}(?![A-Za-z0-9])"
)


def redact_text(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Redacts sensitive personal information from raw text.
    Returns:
        (redacted_text, redaction_counts)
    """
    if not text:
        return "", {}

    counts: Dict[str, int] = {
        "OTP": 0,
        "EMAIL": 0,
        "UPI": 0,
        "PAN": 0,
        "ID": 0,
        "PHONE": 0,
        "ACCOUNT": 0,
    }

    # 1. OTP pattern replacement
    def otp_sub(match: re.Match) -> str:
        counts["OTP"] += 1
        full_match = match.group(0)
        otp_digits = match.group(1)
        return full_match.replace(otp_digits, "[OTP]")

    redacted = OTP_PATTERN.sub(otp_sub, text)

    # 2. Email pattern replacement
    def email_sub(match: re.Match) -> str:
        counts["EMAIL"] += 1
        return "[EMAIL]"

    redacted = EMAIL_PATTERN.sub(email_sub, redacted)

    # 3. UPI pattern replacement
    def upi_sub(match: re.Match) -> str:
        counts["UPI"] += 1
        return "[UPI]"

    redacted = UPI_PATTERN.sub(upi_sub, redacted)

    # 4. PAN pattern replacement
    def pan_sub(match: re.Match) -> str:
        counts["PAN"] += 1
        return "[PAN]"

    redacted = PAN_PATTERN.sub(pan_sub, redacted)

    # 5. Aadhaar pattern replacement
    def aadhaar_sub(match: re.Match) -> str:
        counts["ID"] += 1
        return "[ID]"

    redacted = AADHAAR_PATTERN.sub(aadhaar_sub, redacted)

    # 6. Phone number replacement
    def phone_sub(match: re.Match) -> str:
        counts["PHONE"] += 1
        return "[PHONE]"

    redacted = PHONE_PATTERN.sub(phone_sub, redacted)

    # 7. Bank account numbers (9-18 digits)
    def account_sub(match: re.Match) -> str:
        counts["ACCOUNT"] += 1
        return "[ACCOUNT]"

    redacted = ACCOUNT_PATTERN.sub(account_sub, redacted)

    # Clean up empty counts
    final_counts = {k: v for k, v in counts.items() if v > 0}
    return redacted, final_counts
