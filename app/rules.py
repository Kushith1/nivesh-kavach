"""
Rule engine for Nivesh Kavach.
Matches English, Hinglish (Roman Hindi), and Devanagari Hindi patterns against redacted text.
Extracts matched evidence spans and generates explainable warning signals.
"""

import re
import unicodedata
from typing import List, Dict, Any, Tuple

# Devanagari digit to ASCII mapping
DEVA_TO_ASCII_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

# Registration number pattern e.g., INZ000186937, INH000000001, INP..., INA...
REGISTRATION_PATTERN = re.compile(r"\bIN[A-Z]\d{9}\b", re.IGNORECASE)


def normalize_text(text: str) -> str:
    """
    Normalizes text for rule matching:
    1. Lowercase
    2. Convert Devanagari digits to ASCII
    3. Remove Devanagari nuktas (making ज़=ज, क़=क, ख़=ख, ग़=ग, फ़=फ)
    4. Collapse multiple whitespace characters into single space
    """
    if not text:
        return ""

    # Convert to lowercase
    normalized = text.lower()

    # Translate Devanagari digits to ASCII digits
    normalized = normalized.translate(DEVA_TO_ASCII_DIGITS)

    # Decompose unicode to separate base char and nukta (\u093c)
    decomposed = unicodedata.normalize("NFD", normalized)
    # Remove nukta mark
    no_nukta = "".join(ch for ch in decomposed if ch != "\u093c")
    # Recompose
    normalized = unicodedata.normalize("NFC", no_nukta)

    # Collapse whitespace
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


# Definition of rules across 16 categories
RULES_CONFIG = [
    {
        "id": "RULE_GUARANTEED_RETURNS",
        "category": "guaranteed_returns",
        "weight": 28,
        "severity": "high",
        "patterns": [
            r"\b(100%|guaranteed|assured|fixed)\s+(returns?|profit|gain|income|faayda)\b",
            r"\b(guaranteed|assured)\s+(?:.*?\s+)?(?:paisa|munafa|return|profit)\b",
            r"\b(pakka\s+munafa|fixed\s+return|pakka\s+profit)\b",
            r"(गारंटी|पक्का\s*मुनाफा|100%\s*मुनाफा|तय\s*रिटर्न|निश्चित\s*मुनाफा|पक्का\s*फायदा)",
            r"\bpromise\s+(?:of\s+)?(?:guaranteed|high|fixed)\s+returns?\b",
        ],
        "en": {
            "why_dangerous": "Market-linked investments can NEVER offer guaranteed returns by law. Legitimate equity/derivatives markets inherently carry risk of loss."
        },
        "hi": {
            "why_dangerous": "शेयर बाज़ार या वित्तीय बाज़ार में कानूनन कोई भी निश्चित मुनाफे की गारंटी नहीं दे सकता। बाज़ार से जुड़े हर निवेश में जोखिम होता है।"
        }
    },
    {
        "id": "RULE_UNREALISTIC_RETURNS",
        "category": "unrealistic_returns",
        "weight": 25,
        "severity": "high",
        "patterns": [
            r"\b(?:\d+[%]|rs\.?\s*[\d,]+|[\d,]+\s*(?:hazaar|k|rupaye)?)\s*(?:daily|per\s*day|weekly|per\s*month|har\s*din|har\s*hafte|roz)\b",
            r"\b(?:daily|roz)\s+(?:earn\s+)?(?:\d+|rs\.?\s*\d+|kamao|kamaaye|kamaein)\b",
            r"\b(?:paisa|money|amount)\s+(?:double|triple|dugna|2x|3x|10x)\b",
            r"(रोज़\s*(?:[\d,]+\s*)?(?:कमाएं|कमाओ)|हर\s*(?:दिन|हफ्ते|महीने)\s*[\d,]+[%]?|पैसा\s*(?:डबल|दोगुना))",
            r"\b(?:double\s+your\s+money|turn\s+\d+\s+into\s+\d+)\b",
            r"\b(?:5000|10000|20000|50000)\s*(?:roz|daily|kamao)\b",
        ],
        "en": {
            "why_dangerous": "Extravagant daily, weekly, or doubling returns are typical mathematical hallmarks of fraudulent Ponzi or advance-fee scams."
        },
        "hi": {
            "why_dangerous": "रोज़ाना या हर हफ्ते भारी रिटर्न या पैसा दोगुना करने का वादा पोंजी स्कीम या ठगी की प्रमुख निशानी है।"
        }
    },
    {
        "id": "RULE_RISK_FREE",
        "category": "risk_free",
        "weight": 20,
        "severity": "high",
        "patterns": [
            r"\b(?:risk[- ]free|zero\s*risk|no\s*risk|100%\s*safe|no\s*loss)\b",
            r"\b(?:bina\s*risk|koi\s*nuksan\s*nahi|zero\s*loss)\b",
            r"(रिस्क\s*फ्री|बिना\s*(?:किसी\s*)?जोखिम|कोई\s*नुकसान\s*नहीं|शून्य\s*जोखिम)",
        ],
        "en": {
            "why_dangerous": "Claims of 'zero risk' or 'no loss' are misleading and strictly illegal in market securities trading."
        },
        "hi": {
            "why_dangerous": "'बिना किसी जोखिम' या 'शून्य नुकसान' का दावा पूरी तरह भ्रामक और गैरकानूनी है। कोई भी वास्तविक निवेश जोखिम-मुक्त नहीं होता।"
        }
    },
    {
        "id": "RULE_URGENCY",
        "category": "urgency",
        "weight": 14,
        "severity": "medium",
        "patterns": [
            r"\b(?:limited\s+seats?|hurry\s+up|last\s+chance|valid\s+today\s+only|offer\s+ends|before\s+midnight)\b",
            r"\b(?:jaldi\s+karo|aaj\s+hi|sirf\s+aaj|aakhiri\s+mauka|few\s+seats\s+left|turant\s+unblock)\b",
            r"(जल्दी\s*करें|आज\s*ही|सिर्फ़\s*आज|आख़िरी\s*मौका|सीमित\s*सीटें|\d+\s*सीट\s*बाकी)",
        ],
        "en": {
            "why_dangerous": "Artificial urgency (e.g., 'limited seats', 'today only') is a psychological pressure tactic to stop you from thinking and checking facts."
        },
        "hi": {
            "why_dangerous": "कृत्रिम जल्दबाजी ('सीमित सीटें', 'सिर्फ आज ही मौका') एक मनोवैज्ञानिक दबाव है ताकि आप बिना सोचे-समझे पैसे भेज दें।"
        }
    },
    {
        "id": "RULE_IMMEDIATE_TRANSFER",
        "category": "immediate_transfer",
        "weight": 22,
        "severity": "high",
        "patterns": [
            r"\b(?:transfer\s+(?:now|immediately|funds|rs|money)|send\s+money\s+now)\b",
            r"\b(?:abhi\s+(?:paise\s+)?transfer\s+karo|turant\s+transfer|bhejo)\b",
            r"(अभी\s*पैसे\s*(?:भेजें|डालें)|तुरंत\s*(?:पैसे\s*)?(?:भेजें|डालें|ट्रांसफर\s*करें|भुगतान))",
        ],
        "en": {
            "why_dangerous": "Demands for urgent direct bank or UPI fund transfers prevent you from verifying credentials and consulting financial advisors."
        },
        "hi": {
            "why_dangerous": "तुरंत व्यक्तिगत खाते या यूपीआई में पैसे ट्रांसफर करने का दबाव धोखाधड़ी में पीड़ितों को सोचने का समय न देने के लिए डाला जाता है।"
        }
    },
    {
        "id": "RULE_CREDENTIAL_REQUEST",
        "category": "credential_request",
        "weight": 35,
        "severity": "high",
        "patterns": [
            r"\b(?:otp\s*(?:batao|bataiye|share|send)|share\s*(?:your\s*)?(?:pin|password|cvv|otp))\b",
            r"\b(?:enter|provide|tell)\s+(?:your\s+)?(?:otp|pin|password|mpin)\b",
            r"(ओटीपी\s*(?:बताएं|बताओ|भेजें|साझा\s*करें)|पिन\s*(?:बताएं|भेजें)|पासवर्ड\s*(?:बताएं|भेजें))",
        ],
        "en": {
            "why_dangerous": "CRITICAL RISK: Legitimate institutions NEVER request OTP, PIN, password, or CVV. Disclosing OTP allows attackers to siphon all your funds."
        },
        "hi": {
            "why_dangerous": "गंभीर खतरा: कोई भी बैंक या संस्था कभी भी OTP, पासवर्ड या पिन नहीं मांगती। OTP साझा करते ही आपका खाता खाली किया जा सकता है।"
        }
    },
    {
        "id": "RULE_SEBI_CLAIM",
        "category": "sebi_claim",
        "weight": 18,
        "severity": "medium",
        "patterns": [
            r"\b(?:sebi|rbi|nsdl|cdsl|gov(?:ernment)?)\s*(?:approved|registered|certified|licensed|recognized)\b",
            r"\b(?:sebi\s*reg(?:istration)?|government\s*approved)\b",
            r"(सेबी\s*रजिस्टर्ड|सेबी\s*से\s*मान्यता|सरकारी\s*मंज़ूरी|आरबीआई\s*अनुमोदित)",
            r"\bin[a-z]\d{9}\b",
        ],
        "en": {
            "why_dangerous": "Scammers frequently copy legitimate SEBI registration numbers or forge regulatory certificates to manufacture instant credibility."
        },
        "hi": {
            "why_dangerous": "धोखेबाज अक्सर लोगों का विश्वास जीतने के लिए फर्जी या दूसरों के सेबी (SEBI) रजिस्ट्रेशन नंबर का झूठा हवाला देते हैं।"
        }
    },
    {
        "id": "RULE_IMPERSONATION",
        "category": "impersonation",
        "weight": 20,
        "severity": "high",
        "patterns": [
            r"\b(?:official\s+sebi|rbi\s+officer|sebi\s+team|cyber\s+police\s+officer|institutional\s+desk)\b",
            r"\b(?:sebi\s+authorized|ceo\s+direct|fund\s+manager\s+desk|official\s+rbi)\b",
            r"(सेबी\s*अधिकारी|आरबीआई\s*ऑफिसर|सरकारी\s*अधिकारी)",
        ],
        "en": {
            "why_dangerous": "Regulatory bodies like SEBI or RBI never contact individuals to recommend stocks, provide investment tips, or demand fees."
        },
        "hi": {
            "why_dangerous": "सेबी या आरबीआई के अधिकारी कभी भी व्यक्तिगत रूप से स्टॉक टिप्स देने या पैसे निवेश करवाने के लिए संपर्क नहीं करते।"
        }
    },
    {
        "id": "RULE_INSIDER_TIPS",
        "category": "insider_tips",
        "weight": 24,
        "severity": "high",
        "patterns": [
            r"\b(?:operator\s+tip|insider\s+(?:tip|news|information)|sure\s*shot\s*(?:tip|call)?|vip\s+tip|jackpot\s+call)\b",
            r"\b(?:pakki\s+tip|super\s+tip|operator\s+call|sure\s+profit\s+call)\b",
            r"(सुपर\s*टिप|पक्की\s*टिप|ऑपरेटर\s*(?:टिप|कॉल)?|इनसाइडर\s*(?:टिप|न्यूज़)|जैकपॉट\s*कॉल)",
        ],
        "en": {
            "why_dangerous": "Promising insider or operator tips is often a pump-and-dump trap where fraudsters lure retail buyers before dumping illiquid shares."
        },
        "hi": {
            "why_dangerous": "'ऑपरेटर टिप' या 'इनसाइडर टिप' का झांसा देकर नकली मांग बनाई जाती है, फिर धोखेबाज अपने शेयर बेचकर भाग जाते हैं।"
        }
    },
    {
        "id": "RULE_GROUP_FUNNEL",
        "category": "group_funnel",
        "weight": 16,
        "severity": "medium",
        "patterns": [
            r"\b(?:join\s+(?:our\s+)?(?:group|channel|community|vip\s+group)|telegram\s+group|whatsapp\s+group)\b",
            r"\b(?:group\s+join\s+karo|join\s+kijiye|channel\s+link|join\s+group)\b",
            r"(ग्रुप\s*जॉइन\s*करें|टेलीग्राम\s*ग्रुप|व्हाट्सऐप\s*ग्रुप|ग्रुप\s*में\s*जुड़ें)",
            r"(?:t\.me/|chat\.whatsapp\.com/|wa\.me/)",
        ],
        "en": {
            "why_dangerous": "Directing victims to unmoderated WhatsApp or Telegram groups isolates them where fraudsters orchestrate fake social proof with bot accounts."
        },
        "hi": {
            "why_dangerous": "व्हाट्सएप या टेलीग्राम ग्रुप में जोड़कर धोखेबाज अपने ही साथियों और बॉट्स के जरिए फर्जी मुनाफे का दिखावा करते हैं।"
        }
    },
    {
        "id": "RULE_REFERRAL_SCHEME",
        "category": "referral_scheme",
        "weight": 18,
        "severity": "medium",
        "patterns": [
            r"\b(?:refer\s+(?:and|&)\s+earn|add\s+members?|downline|referral\s+commission|multi\s*level)\b",
            r"\b(?:member\s+jodo|chain\s+system|referral\s+bonus|har\s+member\s+pe)\b",
            r"(रेफर\s*करें\s*और\s*कमाएं|मेंबर\s*(?:जोड़ें|जोडो)|चेन\s*सिस्टम|रेफरल\s*कमीशन)",
        ],
        "en": {
            "why_dangerous": "Multilevel pyramid schemes focus on member recruitment commissions rather than legitimate investment activities, leading to inevitable collapse."
        },
        "hi": {
            "why_dangerous": "लोगों को जोड़ने पर कमीशन का वादा पिरामिड या पोंजी स्कीम का रूप होता है, जो बाद में सभी का पैसा लेकर डूब जाती हैं।"
        }
    },
    {
        "id": "RULE_FAKE_TESTIMONIAL",
        "category": "fake_testimonial",
        "weight": 15,
        "severity": "medium",
        "patterns": [
            r"\b(?:my\s+(?:uncle|friend|brother|sister)\s+earned|profit\s+screenshot|proof\s+of\s+payment|live\s+withdrawal\s+proof|live\s+proof)\b",
            r"\b(?:screenshot\s+dekho|proof\s+bhi\s+hai|kamai\s+ka\s+proof)\b",
            r"(मुनाफे\s*का\s*सबूत|स्क्रीनशॉट\s*देखें|पेमेंट\s*प्रूफ|इन्होंने\s*कमाया)",
        ],
        "en": {
            "why_dangerous": "Fictional success stories and edited account balance screenshots are manufactured to manipulate fear of missing out (FOMO)."
        },
        "hi": {
            "why_dangerous": "कमाई के फर्जी स्क्रीनशॉट और दोस्तों/रिश्तेदारों के नाम पर मुनाफे के झूठे किस्से पीड़ितों को झांसे में लेने के लिए बनाए जाते हैं।"
        }
    },
    {
        "id": "RULE_APP_INSTALL",
        "category": "app_install",
        "weight": 26,
        "severity": "high",
        "patterns": [
            r"\b(?:\.apk\b|install\s+(?:.*?\s+)?(?:app|apk)|download\s+.*?(?:apk|app)|new\s+.*?trading\s+app|\btrading\s+app\b)\b",
            r"\b(?:app\s+download\s+karo|apk\s+file|install\s+kijiye)\b",
            r"(ऐप\s*इंस्टॉल\s*करें|एपीके\s*डाउनलोड|नया\s*ट्रेडिंग\s*ऐप|\.apk)",
        ],
        "en": {
            "why_dangerous": "Installing apps outside official app stores (APKs) frequently infects devices with banking Trojans, keyloggers, and SMS interceptors."
        },
        "hi": {
            "why_dangerous": "आधिकारिक स्टोर (Play Store) के बाहर से APK या अज्ञात ट्रेडिंग ऐप डाउनलोड करने से फोन में मैलवेयर आ सकता है जो OTP चुरा लेता है।"
        }
    },
    {
        "id": "RULE_ADVANCE_FEE",
        "category": "advance_fee",
        "weight": 28,
        "severity": "high",
        "patterns": [
            r"\b(?:pay\s+.*?(?:fee|tax|charge|deposit)\s+to\s+withdraw|withdrawal\s+fee|release\s+fee)\b",
            r"\b(?:withdrawal\s+ke\s+liye\s+fees|tax\s+jama\s+karo|paise\s+nikalne\s+ke\s+liye)\b",
            r"(?:निकासी|पैसे\s*निकालने|विड्रॉल)\s*के\s*लिए\s*.*?(?:फीस|टैक्स|चार्ज|शुल्क)",
        ],
        "en": {
            "why_dangerous": "Demanding advance fees, taxes, or release charges to unblock frozen profit balances is a classic sign of an extortionate scam."
        },
        "hi": {
            "why_dangerous": "कथित मुनाफा या निवेश निकालने के लिए अग्रिम टैक्स या फीस मांगना धोखाधड़ी है। पैसे देने के बाद भी कोई निकासी नहीं होती।"
        }
    },
    {
        "id": "RULE_FOREIGN_OR_CRYPTO_DOUBLE",
        "category": "foreign_or_crypto_double",
        "weight": 24,
        "severity": "high",
        "patterns": [
            r"\b(?:crypto\s+doubling|bitcoin\s+multiplier|forex\s+guaranteed|binary\s+options\s+profit)\b",
            r"\b(?:usdt\s+investment|mining\s+profit\s+guarantee)\b",
            r"(क्रिप्टो\s*डबल|बिटकॉइन\s*मुनाफा|फॉरेक्स\s*ट्रेडिंग\s*गारंटी)",
        ],
        "en": {
            "why_dangerous": "Unregulated foreign exchange and crypto doubling platforms target victims with offshore fake dashboards offering zero legal recourse."
        },
        "hi": {
            "why_dangerous": "अनधिकृत विदेशी मुद्रा और क्रिप्टो दोगुना करने वाली फर्जी वेबसाइटें बिना किसी नियामक सुरक्षा के लोगों का धन हड़प लेती हैं।"
        }
    },
    {
        "id": "RULE_SECRECY",
        "category": "secrecy",
        "weight": 20,
        "severity": "high",
        "patterns": [
            r"\b(?:don'?t\s+tell\s+anyone|keep\s+(?:it\s+)?secret|keep\s+confidential|secret\s+group)\b",
            r"\b(?:kisi\s+ko\s+mat\s+batana|kisi\s+se\s+share\s+mat\s+karo|gupt\s+rakhein)\b",
            r"(किसी\s*को\s*मत\s*बता(?:ना|एं)|गुप्त\s*रखें|सीक्रेट\s*रखें|किसी\s*से\s*शेयर\s*न\s*करें)",
        ],
        "en": {
            "why_dangerous": "Demands for secrecy are designed to isolate you from seeking second opinions from family, bank managers, or registered advisors."
        },
        "hi": {
            "why_dangerous": "'किसी को मत बताना' या बात छुपाने को कहना धोखेबाजों की चाल होती है ताकि आप परिवार या बैंक से सलाह न ले सकें।"
        }
    },
]


def extract_claims_to_verify(text: str, language: str = "en") -> List[Dict[str, str]]:
    """
    Extracts explicit claims that can and should be verified independently,
    such as registration-number-like strings IN[A-Z]\\d{9}.
    NEVER validates or endorses the claim.
    """
    claims = []
    reg_matches = REGISTRATION_PATTERN.findall(text)
    for reg in set(reg_matches):
        if language == "hi":
            claims.append({
                "claim": f"संदेश में पंजीकरण संख्या '{reg}' का दावा किया गया है।",
                "how_to_verify": f"सेबी की आधिकारिक वेबसाइट (sebi.gov.in) पर जाकर 'Recognised Intermediaries' सूची में इस नंबर '{reg}' को खोजें और जांचें कि क्या संस्था का नाम और पता पूरी तरह मेल खाता है।"
            })
        else:
            claims.append({
                "claim": f"Message claims registration number '{reg}'.",
                "how_to_verify": f"Look up '{reg}' directly in the official SEBI Intermediaries Directory on sebi.gov.in. Verify that the registered company name, address, and verified domains match exactly."
            })

    # Check for general SEBI / RBI / Govt registration claims without specific number
    if not reg_matches and re.search(r"(?:\b(sebi|rbi|nsdl|government)\b|सेबी|आरबीआई|एनएसडीएल|सरकार)", text, re.IGNORECASE):
        if language == "hi":
            claims.append({
                "claim": "संदेश में सेबी/आरबीआई/सरकारी अनुमोदन या पंजीकरण का दावा है।",
                "how_to_verify": "संदेश भेजने वाले का आधिकारिक सेबी पंजीकरण नंबर और पंजीकृत ईमेल/वेबसाइट मांगें, फिर उसे sebi.gov.in पर आधिकारिक सूची से सत्यापित करें।"
            })
        else:
            claims.append({
                "claim": "Message claims government or regulatory registration (SEBI/RBI).",
                "how_to_verify": "Demand the entity's exact SEBI Registration Number and verify it independently on sebi.gov.in before trusting any communication."
            })

    return claims


def evaluate_rules(text: str, language: str = "en") -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """
    Evaluates rule base on redacted text.
    Returns:
        (signals, claims_to_verify)
    """
    if not text:
        return [], []

    normalized = normalize_text(text)
    signals = []
    seen_categories = set()

    for rule in RULES_CONFIG:
        matched_span = None

        # Check each pattern against normalized text
        for pat in rule["patterns"]:
            match = re.search(pat, normalized, re.IGNORECASE)
            if match:
                matched_span = match.group(0)
                break

        if matched_span:
            cat = rule["category"]
            why_dangerous = rule[language]["why_dangerous"] if language in rule else rule["en"]["why_dangerous"]

            # Avoid duplicate signals for the same category in rule matches
            if cat not in seen_categories:
                seen_categories.add(cat)
                signals.append({
                    "id": rule["id"],
                    "category": cat,
                    "weight": rule["weight"],
                    "severity": rule["severity"],
                    "evidence": matched_span,
                    "why_dangerous": why_dangerous,
                    "source": "rule"
                })

    claims = extract_claims_to_verify(text, language=language)
    return signals, claims
