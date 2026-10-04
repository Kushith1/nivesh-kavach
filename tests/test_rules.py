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
