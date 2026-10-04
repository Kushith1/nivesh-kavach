"""
Unit tests for app/rules.py across all 16 categories and normalization
"""

from app.rules import normalize_text, evaluate_rules, extract_claims_to_verify


def test_normalize_text():
    raw = "  गारंटी   और  फ़ायदा ०१२३४  "
    norm = normalize_text(raw)
    assert "01234" in norm
    assert "  " not in norm
    # Nukta stripped (फ़ -> फ)
    assert "फायदा" in norm


def test_rule_guaranteed_returns():
    texts = [
        "100% guaranteed profit in equity trading",
        "Sir pakka munafa hoga fixed return",
        "गारंटीड रिटर्न और पक्का मुनाफा"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "guaranteed_returns" for s in signals), f"Failed for {t}"


def test_rule_unrealistic_returns():
    texts = [
        "Earn 10% daily return on your deposit",
        "Roz 5000 kamao without effort",
        "पैसा डबल होगा मात्र 7 दिनों में"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "unrealistic_returns" for s in signals), f"Failed for {t}"


def test_rule_risk_free():
    texts = [
        "Completely risk free trading plan",
        "Zero risk zero loss investment",
        "बिना किसी जोखिम के निवेश करें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "risk_free" for s in signals), f"Failed for {t}"


def test_rule_urgency():
    texts = [
        "Only limited seats available hurry up",
        "Sirf aaj hi mauka hai aakhiri mauka",
        "आज ही जुड़ें, सिर्फ 20 सीट बाकी"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "urgency" for s in signals), f"Failed for {t}"


def test_rule_immediate_transfer():
    texts = [
        "Transfer money immediately to book profit",
        "Abhi paise transfer karo account me",
        "तुरंत पैसे भेजें और ट्रेड शुरू करें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "immediate_transfer" for s in signals), f"Failed for {t}"


def test_rule_credential_request():
    texts = [
        "Share your OTP to activate bonus",
        "OTP batao turant",
        "ओटीपी बताएं खाता सक्रिय करने के लिए"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "credential_request" for s in signals), f"Failed for {t}"


def test_credential_negation_is_scoped_to_its_sentence():
    signals, _ = evaluate_rules("Never share your OTP with anyone. Share the OTP you receive to confirm.")
    assert any(s["category"] == "credential_request" for s in signals)

    signals, _ = evaluate_rules("Never share your OTP with anyone.")
    assert not any(s["category"] == "credential_request" for s in signals)


def test_rule_sebi_claim_and_extraction():
    text = "We are SEBI approved advisor with registration INZ000186937."
    signals, claims = evaluate_rules(text)
    assert any(s["category"] == "sebi_claim" for s in signals)
    assert len(claims) >= 1
    assert "INZ000186937" in claims[0]["claim"]
    assert "sebi.gov.in" in claims[0]["how_to_verify"]


def test_rule_impersonation():
    texts = [
        "Official SEBI officer contacting you",
        "RBI officer high return fund announcement",
        "सेबी अधिकारी से सीधी बात"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "impersonation" for s in signals), f"Failed for {t}"


def test_rule_insider_tips():
    texts = [
        "Operator tip for tomorrow upper circuit",
        "Sure shot call with guaranteed 100% gain",
        "पक्की टिप और ऑपरेटर कॉल"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "insider_tips" for s in signals), f"Failed for {t}"


def test_rule_group_funnel():
    texts = [
        "Join our VIP Telegram group https://t.me/profitpool",
        "Join our group on WhatsApp chat.whatsapp.com/123",
        "व्हाट्सऐप ग्रुप में जुड़ें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "group_funnel" for s in signals), f"Failed for {t}"


def test_rule_referral_scheme():
    texts = [
        "Refer and earn 10% commission on every member added",
        "Member jodo aur commission kamao",
        "रेफर करें और कमाएं"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "referral_scheme" for s in signals), f"Failed for {t}"


def test_rule_fake_testimonial():
    texts = [
        "Live proof: my uncle earned 5 lakhs last week",
        "Payment proof and screenshot dekho",
        "मुनाफे का सबूत देखें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "fake_testimonial" for s in signals), f"Failed for {t}"


def test_rule_app_install():
    texts = [
        "Download our new trading app APK file",
        "Install this private app outside play store",
        "एपीके डाउनलोड करें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "app_install" for s in signals), f"Failed for {t}"


def test_rule_advance_fee():
    texts = [
        "Pay 2500 fee to withdraw your earnings",
        "Withdrawal ke liye fees jama karo",
        "निकासी के लिए टैक्स फीस तुरंत ट्रांसफर करें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "advance_fee" for s in signals), f"Failed for {t}"


def test_rule_crypto_double():
    texts = [
        "Crypto doubling platform 2x returns",
        "Forex guaranteed daily returns",
        "क्रिप्टो डबल करने की योजना"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "foreign_or_crypto_double" for s in signals), f"Failed for {t}"


def test_rule_secrecy():
    texts = [
        "Don't tell anyone about this secret trade",
        "Kisi ko mat batana keep confidential",
        "किसी को मत बताना गुप्त रखें"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "secrecy" for s in signals), f"Failed for {t}"


def test_rule_unsolicited_windfall():
    texts = [
        "Your IPO allotment of 500 shares is approved",
        "Your profit of Rs 85,000 is released",
        "Congratulations you have won lottery",
        "बधाई हो! आपका IPO अलॉटमेंट मंज़ूर हो गया है",
        "85,000 रुपये का मुनाफ़ा पाने के लिए"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "unsolicited_windfall" for s in signals), f"Failed for {t}"


def test_rule_account_threat():
    texts = [
        "Your demat account is under verification",
        "Pay Rs 999 to keep your shares safe",
        "आपका डीमैट खाता सत्यापन में है",
        "अपने शेयर सुरक्षित रखने के लिए"
    ]
    for t in texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "account_threat" for s in signals), f"Failed for {t}"


def test_negation_guard_credential_request():
    negated_texts = [
        "Never share your OTP with anyone.",
        "Do not share OTP or PIN with strangers.",
        "Please never share your password.",
        "किसी को भी OTP न बताएं।",
        "कभी भी अपना बैंक पासवर्ड या गोपनीय जानकारी किसी के साथ साझा न करें।",
        "कृपया किसी के साथ OTP साझा न करें।"
    ]
    for t in negated_texts:
        signals, _ = evaluate_rules(t)
        assert not any(s["category"] == "credential_request" for s in signals), f"False positive credential_request on: {t}"


def test_credential_request_strengthened():
    request_texts = [
        "Share the OTP you receive to confirm.",
        "पुष्टि के लिए आपके फ़ोन पर आया ओटीपी हमें बताएं।",
        "Enter the OTP you receive now.",
        "ओटीपी हमें बताएं"
    ]
    for t in request_texts:
        signals, _ = evaluate_rules(t)
        assert any(s["category"] == "credential_request" for s in signals), f"Failed to detect credential_request on: {t}"


def test_scam_messages_e2_e4_h1_h4():
    from app.redact import redact_text
    from app.scoring import compute_score, determine_risk_level

    scams = {
        "E2": (
            "Dear investor, your IPO allotment of 500 shares is approved. To release your profit of Rs 85,000, pay a processing fee of Rs 4,999 to UPI ID verify.fees@fakebank within 2 hours. Share the OTP you receive to confirm. - Investor Cell",
            "en"
        ),
        "E4": (
            "Official notice from NSDL and Government of India: your demat account is under verification. Pay Rs 999 to keep your shares safe. See how Mr. Sharma earned Rs 3 lakh in one week with our Premium Plan. Registration No. INA000000000. Call 90000 12345 now.",
            "en"
        ),
        "H1": (
            "बधाई हो! आपका IPO अलॉटमेंट मंज़ूर हो गया है। 85,000 रुपये का मुनाफ़ा पाने के लिए अगले 2 घंटे में 4,999 रुपये प्रोसेसिंग फीस भेजें। पुष्टि के लिए आपके फ़ोन पर आया ओटीपी हमें बताएं। - निवेशक सेवा केंद्र",
            "hi"
        ),
        "H4": (
            "सेबी और एनएसडीएल की ओर से सूचना: आपका डीमैट खाता सत्यापन में है। अपने शेयर सुरक्षित रखने के लिए 999 रुपये जमा करें। देखिए शर्मा जी ने सिर्फ़ एक हफ्ते में 3 लाख रुपये कमाए। रजिस्ट्रेशन नंबर INA000000000। अभी 90000 12345 पर कॉल करें।",
            "hi"
        ),
    }

    for name, (text, lang) in scams.items():
        redacted, _ = redact_text(text)
        signals, claims = evaluate_rules(redacted, language=lang)
        score = compute_score(signals, [])
        risk = determine_risk_level(score, language=lang)
        assert risk["level"] in ("High", "Very High"), f"{name} scored {score} ({risk['level']}), expected High or Very High"


def test_benign_messages_b1_b2():
    from app.redact import redact_text
    from app.scoring import compute_score, determine_risk_level

    benigns = {
        "B1": (
            "Your SIP of Rs 500 will be debited on 5 Oct. Investments are subject to market risk. Never share your OTP with anyone.",
            "en"
        ),
        "B2": (
            "निवेश करने से पहले जांच लें कि सलाहकार SEBI के पास पंजीकृत है या नहीं। किसी को भी OTP न बताएं।",
            "hi"
        ),
    }

    for name, (text, lang) in benigns.items():
        redacted, _ = redact_text(text)
        signals, claims = evaluate_rules(redacted, language=lang)
        score = compute_score(signals, [])
        risk = determine_risk_level(score, language=lang)
        assert risk["level"] == "Low", f"{name} scored {score} ({risk['level']}), expected Low"
        assert score == 0, f"{name} should have 0 score, got {score}"

