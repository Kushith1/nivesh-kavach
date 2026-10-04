"""
URL string analysis module for Nivesh Kavach.
CRITICAL HARD RULE: NEVER fetch or open user-submitted URLs.
Analyse URL string only!
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple

# Official recognized domains and their legitimate subdomains
OFFICIAL_DOMAINS = {
    "sebi.gov.in",
    "nsdl.co.in",
    "cdslindia.com",
    "nseindia.com",
    "bseindia.com",
    "rbi.org.in",
    "cybercrime.gov.in",
    "scores.sebi.gov.in",
}

# Known URL shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "rb.gy", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "v.gd"
}

# Suspicious high-abuse TLDs
SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "buzz", "click", "club", "site", "vip",
    "live", "loan", "work", "date", "racing", "download", "stream",
    "rest", "gq", "cf", "tk", "ml", "ga"
}

# Sensitive finance keywords
FINANCE_KEYWORDS = {
    "sebi", "nsdl", "cdsl", "rbi", "invest", "vip", "profit",
    "ipo", "trade", "wealth", "stock", "share", "crypto", "forex", "return", "bonus"
}

OFFICIAL_BRANDS = ["sebi", "nsdl", "cdsl", "nseindia", "bseindia", "rbi"]

IPV4_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes basic Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def is_official_domain(host: str) -> bool:
    """Checks whether the host is exactly an official domain or subdomain of one."""
    host = host.lower().strip(".")
    for official in OFFICIAL_DOMAINS:
        if host == official or host.endswith("." + official):
            return True
    return False


def extract_urls(text: str) -> List[str]:
    """Finds URLs or domain-like strings in text."""
    url_pattern = re.compile(
        r"(?:https?://|www\.)[^\s/$.?#].[^\s]*|"
        r"\b[a-zA-Z0-9.-]+\.(?:com|org|net|in|gov\.in|co\.in|xyz|top|icu|buzz|click|site|vip|me|info|biz)\b(?:/[^\s]*)?",
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def analyze_url_string(url_str: str, language: str = "en") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Performs purely static, string-level heuristic inspection of a URL.
    Does NOT connect to or resolve the domain.
    """
    signals: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {
        "url_submitted": url_str,
        "is_official": False,
        "host": ""
    }

    if not url_str:
        return signals, metadata

    raw = url_str.strip()
    if not (raw.startswith("http://") or raw.startswith("https://")):
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().strip(".")
        metadata["host"] = host
        metadata["scheme"] = parsed.scheme
    except Exception:
        return signals, metadata

    if not host:
        return signals, metadata

    # Check if genuinely official
    if is_official_domain(host):
        metadata["is_official"] = True
        return signals, metadata

    # 1. IP-address host check
    if IPV4_REGEX.match(host):
        signals.append({
            "id": "URL_IP_HOST",
            "category": "suspicious_url",
            "weight": 30,
            "severity": "high",
            "evidence": host,
            "why_dangerous": (
                "The link uses a raw IP address instead of a registered domain name. Legitimate financial institutions always use verified domain names."
                if language == "en" else
                "यह लिंक किसी पंजीकृत डोमेन नाम के बजाय सीधे आईपी पते का उपयोग करता है। आधिकारिक वित्तीय संस्थान हमेशा अधिकृत डोमेन का उपयोग करते हैं।"
            ),
            "source": "rule"
        })

    # 2. Punycode check (homograph attacks)
    if "xn--" in host:
        signals.append({
            "id": "URL_PUNYCODE",
            "category": "suspicious_url",
            "weight": 32,
            "severity": "high",
            "evidence": host,
            "why_dangerous": (
                "The domain contains punycode ('xn--'), often used in homograph phishing attacks to spoof legitimate websites using visually identical characters."
                if language == "en" else
                "डोमेन में प्यूनिकोड ('xn--') मौजूद है, जिसका उपयोग अक्सर धोखाधड़ी में असली वेबसाइटों जैसे दिखने वाले नकली अक्षर बनाने के लिए किया जाता है।"
            ),
            "source": "rule"
        })

    # 3. URL shorteners
    if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
        signals.append({
            "id": "URL_SHORTENER",
            "category": "suspicious_url",
            "weight": 18,
            "severity": "medium",
            "evidence": host,
            "why_dangerous": (
                "The link uses a URL shortener to hide the real destination website. Scammers use this to evade security filters."
                if language == "en" else
                "यह लिंक यूआरएल शॉर्टनर का उपयोग करता है जिससे असली वेबसाइट छुप जाती है। सुरक्षा जांच से बचने के लिए ठग ऐसा करते हैं।"
            ),
            "source": "rule"
        })

    # 4. Insecure HTTP (no HTTPS)
    if parsed.scheme == "http" and not (host in ("localhost", "127.0.0.1")):
        signals.append({
            "id": "URL_NO_HTTPS",
            "category": "suspicious_url",
            "weight": 12,
            "severity": "medium",
            "evidence": parsed.scheme + "://",
            "why_dangerous": (
                "The link uses unencrypted HTTP instead of secure HTTPS. Legitimate banking and investment portals strictly enforce HTTPS."
                if language == "en" else
                "यह लिंक असुरक्षित HTTP प्रोटोकॉल पर है (HTTPS नहीं)। सभी वैध बैंक और निवेश संस्थान सुरक्षित HTTPS का उपयोग करते हैं।"
            ),
            "source": "rule"
        })

    # 5. Suspicious high-abuse TLDs
    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append({
            "id": "URL_SUSPICIOUS_TLD",
            "category": "suspicious_url",
            "weight": 22,
            "severity": "high",
            "evidence": f".{tld}",
            "why_dangerous": (
                f"The domain uses a high-risk generic extension (.{tld}) commonly purchased anonymously by cyber criminals."
                if language == "en" else
                f"डोमेन उच्च जोखिम वाले एक्सटेंशन (.{tld}) पर पंजीकृत है, जिसे धोखाधड़ी करने वाले अक्सर सस्ते में गुमनाम रूप से खरीदते हैं।"
            ),
            "source": "rule"
        })

    # 6. Excessive hyphens or digits in domain
    hyphen_count = host.count("-")
    digit_count = sum(ch.isdigit() for ch in host)
    if hyphen_count >= 3 or digit_count >= 5:
        signals.append({
            "id": "URL_HIGH_HYPHENS_OR_DIGITS",
            "category": "suspicious_url",
            "weight": 16,
            "severity": "medium",
            "evidence": host,
            "why_dangerous": (
                f"The domain contains unusually many hyphens ({hyphen_count}) or numbers ({digit_count}), typical of algorithmically generated scam landing pages."
                if language == "en" else
                f"डोमेन में असामान्य रूप से कई हाइफ़न ({hyphen_count}) या संख्याएँ ({digit_count}) हैं, जो नकली पेजों की पहचान होती है।"
            ),
            "source": "rule"
        })

    # 7. More than 3 subdomains (>3 dot-separated levels before suffix)
    parts = host.split(".")
    if len(parts) > 4:
        signals.append({
            "id": "URL_EXCESSIVE_SUBDOMAINS",
            "category": "suspicious_url",
            "weight": 15,
            "severity": "medium",
            "evidence": host,
            "why_dangerous": (
                "The URL uses deeply nested subdomains to confuse mobile users into seeing only the first part of the address."
                if language == "en" else
                "इस लिंक में अत्यधिक सब-डोमेन हैं ताकि मोबाइल स्क्रीन पर असली पता छिप जाए और उपयोगकर्ता भ्रमित हो जाए।"
            ),
            "source": "rule"
        })

    # 8. Finance keywords in non-official domain
    found_finance = [kw for kw in FINANCE_KEYWORDS if kw in host]
    if found_finance:
        signals.append({
            "id": "URL_FINANCE_KEYWORD_MISUSE",
            "category": "suspicious_url",
            "weight": 20,
            "severity": "high",
            "evidence": f"keywords: {', '.join(found_finance)} in {host}",
            "why_dangerous": (
                f"The domain includes financial buzzwords ({', '.join(found_finance)}) on an unofficial website to create a false impression of authority."
                if language == "en" else
                f"गैर-आधिकारिक वेबसाइट के डोमेन में वित्तीय शब्दों ({', '.join(found_finance)}) का इस्तेमाल विश्वास जीतने के इरादे से किया गया है।"
            ),
            "source": "rule"
        })

    # 9. Lookalike of official domains:
    # Check brand-in-domain
    for brand in OFFICIAL_BRANDS:
        if brand in host and not is_official_domain(host):
            signals.append({
                "id": "URL_BRAND_IMPERSONATION",
                "category": "impersonation",
                "weight": 30,
                "severity": "high",
                "evidence": f"'{brand}' found in non-official domain '{host}'",
                "why_dangerous": (
                    f"The link uses the official regulator or exchange name '{brand}' in an unofficial web address. This is a severe phishing indicator."
                    if language == "en" else
                    f"लिंक अनधिकृत पते में नियामक/एक्सचेंज '{brand}' के नाम का उपयोग करता है। यह गंभीर फ़िशिंग का संकेत है।"
                ),
                "source": "rule"
            })
            break

    # Check edit distance <= 2 against official domains
    main_domain_part = parts[0] if parts else ""
    for official in OFFICIAL_DOMAINS:
        off_main = official.split(".")[0]
        # Compare main label
        dist = levenshtein_distance(main_domain_part, off_main)
        if 0 < dist <= 2 and abs(len(main_domain_part) - len(off_main)) <= 2:
            signals.append({
                "id": "URL_TYPOSQUATTING",
                "category": "impersonation",
                "weight": 32,
                "severity": "high",
                "evidence": f"'{host}' is suspiciously similar to official '{official}' (edit distance {dist})",
                "why_dangerous": (
                    f"The web address looks like a deliberate typo or clone of the official portal {official}."
                    if language == "en" else
                    f"यह वेब पता आधिकारिक पोर्टल {official} की नकल या मिलता-जुलता नकली पता प्रतीत होता है।"
                ),
                "source": "rule"
            })
            break

    return signals, metadata
