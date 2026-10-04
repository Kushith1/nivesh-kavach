"""
Guardrail output filter module for Nivesh Kavach.
Enforces strict regulatory compliance over all LLM-generated text:
- Blocks buy/sell/hold recommendations
- Blocks target price or stop-loss mentions
- Blocks price/return predictions ("will rise", "will fall", "will double", etc.)
- Blocks unauthorized external URLs (only URLs explicitly present in cards.json are permitted)
- Replaces offending strings with a safe fallback message
"""

import re
import json
from pathlib import Path
from typing import Set, Any, Dict, List

# Load allowed URLs directly from cards.json
CARDS_FILE = Path(__file__).parent / "cards.json"


def get_allowed_urls() -> Set[str]:
    """Extracts all official URLs authorized in cards.json."""
    urls = set()
    if CARDS_FILE.exists():
        try:
            with open(CARDS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.values():
                    for lang in ["en", "hi"]:
                        if lang in item and "url" in item[lang]:
                            urls.add(item[lang]["url"].strip())
        except Exception:
            pass
    # Fallback to hardcoded list in case of reading issues
    urls.update({
        "https://www.sebi.gov.in",
        "https://siportal.sebi.gov.in/intermediary/sebi-check",
        "https://cybercrime.gov.in",
        "https://scores.sebi.gov.in"
    })
    return urls


ALLOWED_URLS = get_allowed_urls()

# Regex patterns for prohibited financial advice and return predictions
PROHIBITED_PATTERNS = [
    # Buy / Sell / Hold advice
    re.compile(r"\b(?:strong\s+)?(?:buy|sell|hold)\s+(?:call|recommendation|rating|stock|shares?|token|coin)\b", re.IGNORECASE),
    re.compile(r"\b(?:we\s+recommend\s+(?:buying|selling|investing)|you\s+should\s+(?:buy|sell|invest\s+in))\b", re.IGNORECASE),
    re.compile(r"(?:खरीदें|बेचें|होल्ड\s*करें|शेयर\s*खरीदने\s*की\s*सलाह)", re.IGNORECASE),
    
    # Target price and stop loss
    re.compile(r"\b(?:target\s*price|target\s*of\s*(?:rs\.?|₹|\$)?\s*\d+|stop\s*loss)\b", re.IGNORECASE),
    re.compile(r"(?:टारगेट\s*प्राइस|स्टॉप\s*लॉस)", re.IGNORECASE),
    
    # Predictions of market movement
    re.compile(r"\b(?:will|is\s+going\s+to)\s+(?:rise|fall|double|triple|surge|skyrocket|crash|moon|zoom)\b", re.IGNORECASE),
    re.compile(r"\b(?:price\s+will\s+reach|guaranteed\s+profit\s+of)\b", re.IGNORECASE),
    re.compile(r"(?:कीमत\s*बढ़ेगी|दोगुनी\s*होगी|गिरावट\s*आएगी|मुनाफा\s*होगा)", re.IGNORECASE),

    # Recommendations of specific brokers or schemes
    re.compile(r"\b(?:best\s+broker|recommended\s+platform|join\s+this\s+scheme)\b", re.IGNORECASE),
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)

SAFE_FALLBACK_TEXT = "[Content removed: Prohibited investment advice or prediction filtered by safety guardrail]"
SAFE_URL_FALLBACK = "https://www.sebi.gov.in"


def filter_text(text: str) -> str:
    """
    Applies guardrail filter to a single string:
    1. Replaces prohibited advice / predictions with SAFE_FALLBACK_TEXT
    2. Strips or replaces unauthorized URLs not present in cards.json
    """
    if not isinstance(text, str) or not text:
        return text

    filtered = text

    # Filter prohibited advice/predictions
    for pattern in PROHIBITED_PATTERNS:
        filtered = pattern.sub(SAFE_FALLBACK_TEXT, filtered)

    # Filter URLs not in cards.json
    def url_replacer(match: re.Match) -> str:
        url = match.group(0).rstrip(".,;!?:")
        # Check against allowed URLs or authorized domains
        for allowed in ALLOWED_URLS:
            if url.startswith(allowed):
                return match.group(0)
        return f"[Link removed by security policy; visit official portal: {SAFE_URL_FALLBACK}]"

    filtered = URL_PATTERN.sub(url_replacer, filtered)
    return filtered


def filter_structure(obj: Any) -> Any:
    """
    Recursively applies the guardrail filter to dictionaries, lists, and strings.
    """
    if isinstance(obj, str):
        return filter_text(obj)
    elif isinstance(obj, list):
        return [filter_structure(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: filter_structure(v) for k, v in obj.items()}
    return obj
