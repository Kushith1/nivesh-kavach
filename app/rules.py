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

# Registration number pattern e.g., INZ000186937, INA000000000, INH000000001, INB...
REGISTRATION_PATTERN = re.compile(r"\bIN[ABHZ]\d{9}\b", re.IGNORECASE)
REG_NO_PREFIX_PATTERN = re.compile(
    r"(?:Registration\s*No\.?|रजिस्ट्रेशन\s*नंबर)\s*[:=-]?\s*([A-Za-z0-9]+)",
    re.IGNORECASE
)

# Negation patterns for OTP and credential requests
NEGATION_OTP_PATTERNS = [
    re.compile(
        r"\b(?:never|do\s+not|don'?t|should\s+not|must\s+not|not)\s+(?:to\s+)?(?:share|give|tell|disclose|send|provide)\b.*?\b(?:otp|pin|password|cvv|credentials?)\b",
        re.IGNORECASE
    ),
    re.compile(
        r"\b(?:otp|pin|password|cvv|credentials?)\b.*?\b(?:never|do\s+not|don'?t|should\s+not|must\s+not)\s+(?:share|give|tell|disclose|send)\b",
        re.IGNORECASE
    ),
    re.compile(r"never\s+share\s+(?:your\s+)?(?:otp|pin|password)", re.IGNORECASE),
    re.compile(
        r"(?:कभी\s*भी\s*)?(?:किसी\s*(?:को|के\s*साथ)\s*)?(?:भी\s*)?(?:ओटीपी|otp|पिन|पासवर्ड).*?(?:न|ना|मत)\s*(?:बताएं|बताओ|दें|साझा|शेयर)",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:न|ना|मत)\s*(?:बताएं|बताओ|दें|साझा\s*करें|शेयर\s*करें).*?(?:ओटीपी|otp|पिन|पासवर्ड)",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:ओटीपी|otp|पिन|पासवर्ड).*?(?:साझा\s*(?:न|ना|मत)|शेयर\s*(?:न|ना|मत))",
        re.IGNORECASE
    ),
]


def is_negated_credential_match(text: str, start: int, end: int) -> bool:
    """Check only the sentence surrounding one credential match.

    This avoids suppressing a real OTP request merely because another sentence
    correctly warns the reader not to share an OTP.
    """
    sentence_start = max(text.rfind(".", 0, start), text.rfind("!", 0, start), text.rfind("?", 0, start)) + 1
    ends = [p for p in (text.find(".", end), text.find("!", end), text.find("?", end)) if p != -1]
    sentence_end = min(ends) if ends else len(text)
    sentence = text[sentence_start:sentence_end]
    return any(pattern.search(sentence) for pattern in NEGATION_OTP_PATTERNS)


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


# Definition of rules across 18 categories
# Note: For Devanagari patterns, NEVER use \b word boundaries as Python regex \b fails on Unicode Devanagari.
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
            r"गारंटी",
            r"पक्का\s*मुनाफा",
            r"100%\s*मुनाफा",
            r"तय\s*रिटर्न",
            r"निश्चित\s*मुनाफा",
            r"पक्का\s*फायदा",
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
            r"रोज़\s*(?:[\d,]+\s*)?(?:कमाएं|कमाओ)",
            r"हर\s*(?:दिन|हफ्ते|महीने)\s*[\d,]+[%]?",
            r"पैसा\s*(?:डबल|दोगुना)",
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
            r"रिस्क\s*फ्री",
            r"बिना\s*(?:किसी\s*)?जोखिम",
            r"कोई\s*नुकसान\s*नहीं",
            r"शून्य\s*जोखिम",
        ],
        "en": {
            "why_dangerous": "Claims of 'zero risk' or 'no loss' are misleading and strictly illegal in market securities trading."
        },
        "hi": {
            "why_dangerous": "'बिना किसी जोखिम' या 'शून्य नुकसान' का दावा पूरी तरह भ्रामक और गैरकानूनी है। कोई भी वास्तविक निवेश जोखिम-मुक्त नहीं होता।"
        }
    },
    {
        "id": "RULE_ADVANCE_FEE",
        "category": "advance_fee",
        "weight": 32,
        "severity": "high",
        "patterns": [
            # English & Hinglish
            r"\b(?:pay|deposit|send|transfer)\s+(?:(?:a|an|the|rs\.?|₹|inr)\s+)?(?:[\d,]+\s+)?(?:processing|registration|clearance|release|verification|activation|withdrawal|tax)\s+(?:fees?|charges?|amount)\b",
            r"\b(?:pay|deposit|send|transfer)\s+(?:rs\.?|₹|inr)?\s*[\d,]+\s+to\s+(?:release|keep|unlock|claim|withdraw|protect)\b",
            r"\bto\s+(?:release|keep|unlock|claim|withdraw)\s+.*?\b(?:pay|deposit|send|transfer)\b",
            r"\b(?:withdrawal\s+fee|release\s+fee|processing\s+fee|activation\s+fee|clearance\s+fee)\b",
            r"\b(?:withdrawal\s+ke\s+liye\s+fees|tax\s+jama\s+karo|paise\s+nikalne\s+ke\s+liye\s+fees)\b",
            r"\bpay\s+(?:rs\.?|inr)?\s*[\d,]+\s+(?:fees?|charges?)\s+to\s+(?:release|keep|unlock|claim|withdraw)\b",
            # Hindi (no \b)
            r"प्रोसेसिंग\s*फीस",
            r"(?:फीस|शुल्क|टैक्स|चार्ज)\s*(?:जमा\s*करें|भेजें|डालें)",
            r"[\d,]+\s*रुपये\s*(?:जमा\s*करें|भेजें|डालें)",
            r"(?:मुनाफ़ा|मुनाफा|पैसे|फंड|शेयर|खाता)\s*(?:पाने|निकालने|सुरक्षित\s*रखने|अनलॉक)\s*के\s*लिए\s*.*?(?:फीस|शुल्क|टैक्स|चार्ज|रुपये\s*(?:जमा|भेजें))",
            r"(?:निकासी|पैसे\s*निकालने|विड्रॉल)\s*के\s*लिए\s*.*?(?:फीस|टैक्स|चार्ज|शुल्क)",
        ],
        "en": {
            "why_dangerous": "Advance-fee fraud: Demanding upfront 'processing', 'release', or 'tax' fees before releasing profits or protecting accounts is an extortionate scam."
        },
        "hi": {
            "why_dangerous": "अग्रिम शुल्क (Advance Fee): मुनाफा निकालने या खाता सुरक्षित करने के नाम पर प्रोसेसिंग फीस, टैक्स या शुल्क मांगना ठगी का स्पष्ट संकेत है।"
        }
    },
    {
        "id": "RULE_CREDENTIAL_REQUEST",
        "category": "credential_request",
        "weight": 35,
        "severity": "high",
        "patterns": [
            # English: share/send/tell/give/enter/read out + the OTP/PIN/password/CVV
            r"\b(?:share|send|tell|give|enter|read\s+out|provide)\s+(?:the\s+|your\s+|this\s+|that\s+)?(?:otp|pin|password|cvv|mpin)\b",
            r"\b(?:the\s+)?otp\s+(?:you\s+)?(?:receive|received|sent|get)\b",
            r"\b(?:otp|pin|password)\s*(?:batao|bataiye|share|send|bhejo)\b",
            r"(?:ओटीपी|otp).*?(?:साझा|बताएं|भेजें|दें)",
            # Hindi (no \b)
            r"(?:आया\s+)?(?:ओटीपी|otp|पिन|पासवर्ड|सीवीवी).*?(?:बताएं|बताओ|भेजें|दर्ज\s*करें|साझा\s*करें)",
            r"(?:ओटीपी|otp|पिन|पासवर्ड)\s*(?:हमें\s*)?(?:बताएं|बताओ|भेजें|दर्ज\s*करें|साझा\s*करें)",
        ],
        "en": {
            "why_dangerous": "CRITICAL RISK: Legitimate institutions NEVER ask for OTPs, PINs, or passwords. Disclosing OTP allows cybercriminals to siphon all your funds."
        },
        "hi": {
            "why_dangerous": "गंभीर खतरा: कोई भी बैंक या संस्था कभी भी OTP, पासवर्ड या पिन नहीं मांगती। OTP बताते ही आपका बैंक खाता खाली हो सकता है।"
        }
    },
    {
        "id": "RULE_URGENCY",
        "category": "urgency",
        "weight": 18,
        "severity": "medium",
        "patterns": [
            r"\bwithin\s+\d+\s+(?:hours?|hrs?|minutes?|mins?|days?)\b",
            r"\b(?:limited\s+seats?|hurry\s+up|last\s+chance|valid\s+today\s+only|offer\s+ends|before\s+midnight)\b",
            r"\b(?:call\s+(?:[\d\s]+\s+)?now|act\s+now|today\s+only|will\s+be\s+(?:blocked|suspended|frozen|closed))\b",
            r"\b(?:jaldi\s+karo|aaj\s+hi|sirf\s+aaj|aakhiri\s+mauka|few\s+seats\s+left|turant\s+unblock)\b",
            r"\d+\s*घंटे\s*में",
            # Hindi (no \b)
            r"अगले\s+\d+\s*(?:घंटे|घंटो|मिनट|दिनों?)\s*में",
            r"जल्दी\s*करें",
            r"आज\s*ही",
            r"सिर्फ़\s*आज",
            r"आख़िरी\s*मौका",
            r"सीमित\s*सीटें",
            r"\d+\s*सीट\s*बाकी",
            r"(?:तुरंत|अभी)\s*(?:[\d\s]+\s*पर\s*)?(?:कॉल\s*करें|संपर्क\s*करें)",
            r"(?:खाता\s*)?(?:बंद\s*हो\s*जाएगा|निलंबित\s*हो\s*जाएगा|ब्लॉक\s*हो\s*जाएगा)",
        ],
        "en": {
            "why_dangerous": "Artificial urgency (tight deadlines like 'within 2 hours' or 'account will be blocked') is designed to panic you into paying without thinking."
        },
        "hi": {
            "why_dangerous": "कृत्रिम जल्दबाजी ('अगले 2 घंटे में', 'खाता बंद हो जाएगा') एक मनोवैज्ञानिक दबाव है ताकि आप घबराकर बिना सोचे पैसे भेज दें।"
        }
    },
    {
        "id": "RULE_UNSOLICITED_WINDFALL",
        "category": "unsolicited_windfall",
        "weight": 24,
        "severity": "high",
        "patterns": [
            r"\b(?:allotment\s+(?:of\s+.*?\s+)?(?:is\s+)?approved|ipo\s+allotment\s+approved)\b",
            r"\bprofit\s+(?:of\s+.*?\s+)?(?:is\s+)?released\b",
            r"\b(?:you\s+have\s+won|lottery\s+winner|congratulations)\b",
            # Hindi (no \b)
            r"बधाई\s*हो",
            r"अलॉटमेंट\s*(?:मंज़ूर|मंजूर)",
            r"मुनाफ़ा\s*पाने\s*के\s*लिए",
            r"मुनाफा\s*पाने\s*के\s*लिए",
            r"इनाम\s*जीता",
        ],
        "en": {
            "why_dangerous": "Unsolicited profit or IPO allotment approvals are bait used to fabricate greed before demanding advance fees."
        },
        "hi": {
            "why_dangerous": "बिना आवेदन के 'आईपीओ अलॉटमेंट' या 'मुनाफा मंजूर' होने की बधाई देना पीड़ितों को लालच में फंसाने की साजिश होती है।"
        }
    },
    {
        "id": "RULE_ACCOUNT_THREAT",
        "category": "account_threat",
        "weight": 24,
        "severity": "high",
        "patterns": [
            r"\b(?:account|demat\s+account)\s+(?:is\s+)?(?:under\s+verification|suspended|blocked|frozen|disabled)\b",
            r"\b(?:kyc\s+(?:is\s+)?expired|kyc\s+suspended)\b",
            r"\bkeep\s+your\s+shares\s+safe\b",
            # Hindi (no \b)
            r"(?:डीमैट\s*)?खाता\s*सत्यापन\s*में",
            r"(?:डीमैट\s*)?खाता\s*(?:बंद|ब्लॉक|निलंबित)",
            r"शेयर\s*सुरक्षित\s*रखने\s*के\s*लिए",
            r"केवाईसी\s*समाप्त",
        ],
        "en": {
            "why_dangerous": "False security threats claiming your demat or bank account is 'under verification' or 'at risk' induce panic to extort compliance fees."
        },
        "hi": {
            "why_dangerous": "खाता 'सत्यापन में है' या 'शेयर सुरक्षित रखें' का झूठा भय दिखाकर ठग पीड़ितों से अवैध रूप से पैसे वसूलते हैं।"
        }
    },
    {
        "id": "RULE_IMPERSONATION",
        "category": "impersonation",
        "weight": 26,
        "severity": "high",
        "patterns": [
            r"\b(?:official\s+notice|government\s+of\s+india|investor\s+cell|investor\s+service\s+cent(?:er|re))\b",
            r"\b(?:notice\s+from\s+(?:nsdl|sebi|rbi|income\s*tax))\b",
            r"\b(?:official\s+sebi|rbi\s+officer|sebi\s+team|cyber\s+police\s+officer|institutional\s+desk)\b",
            r"\b(?:sebi\s+authorized|ceo\s+direct|fund\s+manager\s+desk|official\s+rbi)\b",
            # Hindi (no \b)
            r"भारत\s*सरकार",
            r"निवेशक\s*सेवा\s*केंद्र",
            r"(?:सेबी|एनएसडीएल|आरबीआई)\s*(?:और\s*(?:सेबी|एनएसडीएल|आरबीआई)\s*)?की\s*ओर\s*से",
            r"(?:की\s*ओर\s*से\s*सूचना|आधिकारिक\s*सूचना)",
            r"सेबी\s*अधिकारी",
            r"आरबीआई\s*ऑफिसर",
            r"सरकारी\s*अधिकारी",
        ],
        "en": {
            "why_dangerous": "Impersonating institutions like SEBI, NSDL, or Government of India gives an illicit aura of official authority to deceive investors."
        },
        "hi": {
            "why_dangerous": "सेबी, एनएसडीएल या भारत सरकार जैसी संस्थाओं के नाम का दुरुपयोग कर धोखेबाज फर्जी अधिकार जताते हैं।"
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
            r"\b(?:registration\s*no\.?|reg\s*no\.?)\s*[:=-]?\s*[a-z0-9]+\b",
            r"\bin[abhz]\d{9}\b",
            # Hindi (no \b)
            r"सेबी\s*रजिस्टर्ड",
            r"सेबी\s*से\s*मान्यता",
            r"सरकारी\s*मंज़ूरी",
            r"सरकारी\s*मंजूरी",
            r"आरबीआई\s*अनुमोदित",
            r"रजिस्ट्रेशन\s*नंबर",
            r"पंजीकरण\s*संख्या",
        ],
        "en": {
            "why_dangerous": "Fraudsters cite forged or borrowed SEBI/NSDL registration numbers to create false trust. A quoted registration number is NEVER proof."
        },
        "hi": {
            "why_dangerous": "धोखेबाज विश्वास जीतने के लिए फर्जी या चुराए गए रजिस्ट्रेशन नंबर का हवाला देते हैं। संदेश में लिखा नंबर असली होने का प्रमाण नहीं है।"
        }
    },
    {
        "id": "RULE_FAKE_TESTIMONIAL",
        "category": "fake_testimonial",
        "weight": 18,
        "severity": "medium",
        "patterns": [
            r"\bsee\s+how\s+.*?\s+earned\s+.*?\b",
            r"\b(?:earned|made)\s+(?:rs\.?|₹)?\s*[\d,]+\s*(?:lakh|k|crore)?\s*(?:in\s+.*?(?:week|day|month))\b",
            r"\b\d+\s+days?,\s*(?:rs\.?|₹)?\s*[\d,]+\s+earned\b",
            r"\b(?:now\s+)?(?:he|she|they)\s+(?:is\s+|are\s+)?advising\s+others\b",
            r"\b(?:my\s+)?\d+k?\s*(?:became|turned\s+into)\s*\d+k?\b",
            r"\b(?:my\s+(?:uncle|friend|brother|sister)\s+earned|profit\s+screenshot|proof\s+of\s+payment|live\s+withdrawal\s+proof|live\s+proof)\b",
            r"\b(?:screenshot\s+dekho|proof\s+bhi\s+hai|kamai\s+ka\s+proof)\b",
            # Hindi (no \b)
            r"(?:देखिए|देखें)\s+.*?\s+ने\s+.*?(?:कमाए|कमाया)",
            r"मुनाफे\s*का\s*सबूत",
            r"स्क्रीनशॉट\s*देखें",
            r"पेमेंट\s*प्रूफ",
            r"इन्होंने\s*कमाया",
        ],
        "en": {
            "why_dangerous": "Fabricated testimonials (e.g. 'Mr. Sharma earned Rs 3 lakh in one week') are psychological traps to induce fear of missing out (FOMO)."
        },
        "hi": {
            "why_dangerous": "कमाई के फर्जी उदाहरण ('शर्मा जी ने एक हफ्ते में 3 लाख कमाए') लोगों को लालच में फंसाने के लिए गढ़े जाते हैं।"
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
            r"अभी\s*पैसे\s*(?:भेजें|डालें)",
            r"तुरंत\s*(?:पैसे\s*)?(?:भेजें|डालें|ट्रांसफर\s*करें|भुगतान)",
        ],
        "en": {
            "why_dangerous": "Demands for urgent direct fund transfers bypass institutional verification and cooling-off safeguards."
        },
        "hi": {
            "why_dangerous": "तुरंत पैसे भेजने या ट्रांसफर करने का दबाव पीड़ितों को सोचने और जांच करने का मौका न देने के लिए डाला जाता है।"
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
            r"सुपर\s*टिप",
            r"पक्की\s*टिप",
            r"ऑपरेटर\s*(?:टिप|कॉल)?",
            r"इनसाइडर\s*(?:टिप|न्यूज़)",
            r"जैकपॉट\s*कॉल",
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
            r"\b(?:joining|joined)\s+(?:our\s+)?(?:group|channel|community|vip\s+group)\b",
            r"\b(?:group\s+join\s+karo|join\s+kijiye|channel\s+link|join\s+group)\b",
            r"ग्रुप\s*जॉइन\s*करें",
            r"टेलीग्राम\s*ग्रुप",
            r"व्हाट्सऐप\s*ग्रुप",
            r"ग्रुप\s*में\s*जुड़ें",
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
        "id": "RULE_GAMING_WINNINGS_LURE",
        "category": "gaming_winnings_lure",
        "weight": 35,
        "severity": "high",
        "patterns": [
            r"\b(?:use\s+it\s+to\s+)?play\s+games?\s+and\s+win\s+(?:big|cash|money|prizes?)\b",
            r"\b(?:you\s+still\s+have|available)\s+(?:rs\.?|₹)?\s*[\d,]+\s+in\s+your\s+balance\b",
            r"\b(?:wallet|game|bonus)\s+balance\b.*?\bwin\s+(?:big|cash|money|prizes?)\b",
            r"\bwin\s+big\b"
        ],
        "en": {
            "why_dangerous": "Game-balance and 'win big' messages often lure users into betting, fake reward, or withdrawal-fee scams through disguised links."
        },
        "hi": {
            "why_dangerous": "गेम बैलेंस और बड़ी जीत के संदेश अक्सर नकली इनाम, बेटिंग या पैसे निकालने की फीस वाली ठगी में फंसाते हैं।"
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
            r"रेफर\s*करें\s*और\s*कमाएं",
            r"मेंबर\s*(?:जोड़ें|जोडो)",
            r"चेन\s*सिस्टम",
            r"रेफरल\s*कमीशन",
        ],
        "en": {
            "why_dangerous": "Multilevel pyramid schemes focus on member recruitment commissions rather than legitimate investment activities, leading to inevitable collapse."
        },
        "hi": {
            "why_dangerous": "लोगों को जोड़ने पर कमीशन का वादा पिरामिड या पोंजी स्कीम का रूप होता है, जो बाद में सभी का पैसा लेकर डूब जाती हैं।"
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
            r"ऐप\s*इंस्टॉल\s*करें",
            r"एपीके\s*डाउनलोड",
            r"नया\s*ट्रेडिंग\s*ऐप",
            r"\.apk",
        ],
        "en": {
            "why_dangerous": "Installing apps outside official app stores (APKs) frequently infects devices with banking Trojans, keyloggers, and SMS interceptors."
        },
        "hi": {
            "why_dangerous": "आधिकारिक स्टोर (Play Store) के बाहर से APK या अज्ञात ट्रेडिंग ऐप डाउनलोड करने से फोन में मैलवेयर आ सकता है जो OTP चुरा लेता है।"
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
            r"क्रिप्टो\s*डबल",
            r"बिटकॉइन\s*मुनाफा",
            r"फॉरेक्स\s*ट्रेडिंग\s*गारंटी",
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
            r"किसी\s*को\s*मत\s*बता(?:ना|एं)",
            r"गुप्त\s*रखें",
            r"सीक्रेट\s*रखें",
            r"किसी\s*से\s*शेयर\s*न\s*करें",
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
    such as registration-number-like strings (IN[ABHZ]\\d{9}) or 'Registration No.' mentions.
    NEVER validates or endorses the claim.
    """
    claims = []
    seen = set()

    # Find IN[ABHZ]\d{9} patterns
    reg_matches = REGISTRATION_PATTERN.findall(text)
    for reg in reg_matches:
        reg_clean = reg.strip()
        if reg_clean and reg_clean not in seen:
            seen.add(reg_clean)
            if language == "hi":
                claims.append({
                    "claim": f"संदेश में पंजीकरण संख्या '{reg_clean}' का दावा किया गया है।",
                    "how_to_verify": f"sebi.gov.in पर आधिकारिक 'Recognised Intermediaries' सूची में इस नंबर '{reg_clean}' को खोजें। याद रखें: किसी अनधिकृत संदेश में लिखा नंबर असली होने का प्रमाण नहीं है।"
                })
            else:
                claims.append({
                    "claim": f"Message claims registration number '{reg_clean}'.",
                    "how_to_verify": f"Look up '{reg_clean}' directly in the official SEBI Intermediaries Directory on sebi.gov.in. A registration number quoted in a message is NEVER proof of legitimacy."
                })

    # Find 'Registration No.' prefix pattern
    prefix_matches = REG_NO_PREFIX_PATTERN.findall(text)
    for p_val in prefix_matches:
        p_clean = p_val.strip()
        if p_clean and p_clean not in seen:
            seen.add(p_clean)
            if language == "hi":
                claims.append({
                    "claim": f"संदेश में रजिस्ट्रेशन नंबर '{p_clean}' का दावा है।",
                    "how_to_verify": f"सेबी की आधिकारिक वेबसाइट sebi.gov.in पर जाकर सत्यापित करें कि क्या '{p_clean}' वास्तविक पंजीकृत मध्यस्थ से मेल खाता है।"
                })
            else:
                claims.append({
                    "claim": f"Message claims registration number '{p_clean}'.",
                    "how_to_verify": f"Verify on the official regulator portal (sebi.gov.in) whether registration '{p_clean}' matches the entity and domain exactly."
                })

    # General regulatory/authority claim
    if not claims and re.search(r"(?:\b(sebi|rbi|nsdl|government)\b|सेबी|आरबीआई|एनएसडीएल|सरकार)", text, re.IGNORECASE):
        # Exclude benign advisory disclaimer checking: "जांच लें कि ... पंजीकृत है या नहीं" or public interest notices
        if not re.search(r"(?:जांच\s*लें|चेक\s*करें|check\s*whether|जनहित|public\s*(?:investor\s*)?advisory).*?(?:पंजीकृत|registered)?", text, re.IGNORECASE):
            if language == "hi":
                claims.append({
                    "claim": "संदेश में सेबी/आरबीआई/एनएसडीएल/सरकारी संस्था से संबद्ध होने का दावा है।",
                    "how_to_verify": "वास्तविक नियामक कभी भी व्यक्तिगत रूप से संपर्क करके पैसे, फीस या ओटीपी नहीं मांगते। आधिकारिक पोर्टल से संपर्क विवरण सत्यापित करें।"
                })
            else:
                claims.append({
                    "claim": "Message claims authority or regulation by SEBI, RBI, NSDL, or Government.",
                    "how_to_verify": "Legitimate regulatory bodies never initiate direct messages demanding fees, OTPs, or immediate fund transfers."
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
        cat = rule["category"]

        # Skip impersonation and sebi_claim on official public interest advisories
        if cat in ("impersonation", "sebi_claim") and re.search(
            r"जनहित\s*में\s*जारी|public\s*(?:investor\s*)?advisory|public\s*interest\s*(?:notice|message)",
            text,
            re.IGNORECASE
        ):
            continue

        matched_span = None

        # Check each pattern against normalized text
        for pat in rule["patterns"]:
            match = re.search(pat, normalized, re.IGNORECASE)
            if match:
                if cat == "credential_request" and is_negated_credential_match(
                    normalized, match.start(), match.end()
                ):
                    continue
                matched_span = match.group(0)
                break

        if matched_span:
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
