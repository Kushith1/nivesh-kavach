"""
Debug script to diagnose why E2, E4, H1, H4 are scored Low.
"""

import sys

from app.redact import redact_text
from app.rules import evaluate_rules, normalize_text
from app.scoring import compute_score, determine_risk_level

MESSAGES = {
    "E2": (
        "Dear investor, your IPO allotment of 500 shares is approved. To release your profit of Rs 85,000, "
        "pay a processing fee of Rs 4,999 to UPI ID verify.fees@fakebank within 2 hours. "
        "Share the OTP you receive to confirm. - Investor Cell",
        "en"
    ),
    "E4": (
        "Official notice from NSDL and Government of India: your demat account is under verification. "
        "Pay Rs 999 to keep your shares safe. See how Mr. Sharma earned Rs 3 lakh in one week with our Premium Plan. "
        "Registration No. INA000000000. Call 90000 12345 now.",
        "en"
    ),
    "H1": (
        "बधाई हो! आपका IPO अलॉटमेंट मंज़ूर हो गया है। 85,000 रुपये का मुनाफ़ा पाने के लिए अगले 2 घंटे में "
        "4,999 रुपये प्रोसेसिंग फीस भेजें। पुष्टि के लिए आपके फ़ोन पर आया ओटीपी हमें बताएं। - निवेशक सेवा केंद्र",
        "hi"
    ),
    "H4": (
        "सेबी और एनएसडीएल की ओर से सूचना: आपका डीमैट खाता सत्यापन में है। अपने शेयर सुरक्षित रखने के लिए "
        "999 रुपये जमा करें। देखिए शर्मा जी ने सिर्फ़ एक हफ्ते में 3 लाख रुपये कमाए। "
        "रजिस्ट्रेशन नंबर INA000000000। अभी 90000 12345 पर कॉल करें।",
        "hi"
    )
}

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def diagnose():
    print("=" * 80)
    print("NIVESH KAVACH - RULE ENGINE DIAGNOSTIC REPORT")
    print("=" * 80)

    for msg_id, (raw_text, lang) in MESSAGES.items():
        print(f"\n[{msg_id}] ({lang.upper()})")
        print("ORIGINAL TEXT:")
        print(f"  {raw_text}")
        
        redacted_text, redaction_counts = redact_text(raw_text)
        print("REDACTED TEXT:")
        print(f"  {redacted_text}")
        print(f"  Redaction counts: {redaction_counts}")

        normalized = normalize_text(redacted_text)
        print("NORMALIZED TEXT:")
        print(f"  {normalized}")

        signals, claims = evaluate_rules(redacted_text, language=lang)
        print("FIRED RULES:")
        if signals:
            for s in signals:
                print(f"  - ID: {s['id']} | Weight: {s['weight']} | Cat: {s['category']} | Evidence: '{s['evidence']}'")
        else:
            print("  (None)")

        print("CLAIMS TO VERIFY:")
        if claims:
            for c in claims:
                print(f"  - Claim: {c['claim']}")
        else:
            print("  (None)")

        score = compute_score(signals, [])
        risk = determine_risk_level(score, language=lang)
        print(f"SCORE: {score}/100")
        print(f"RISK LEVEL: {risk['level']} ({risk['headline']})")
        print("-" * 80)

if __name__ == "__main__":
    diagnose()
