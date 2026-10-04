from app.redact import redact_text
from app.rules import evaluate_rules
from app.scoring import compute_score, determine_risk_level
from app.urlcheck import analyze_url_string, extract_urls


def analyze_text(text: str):
    redacted_text, _ = redact_text(text)
    rule_signals, _ = evaluate_rules(redacted_text)
    url_signals = []
    for url in extract_urls(redacted_text):
        signals, _ = analyze_url_string(url)
        url_signals.extend(signals)
    signals = rule_signals + url_signals
    score = compute_score(signals, [])
    risk = determine_risk_level(score)
    return signals, score, risk


def categories(signals):
    return {signal["category"] for signal in signals}


def test_gaming_balance_shortlink_lure_is_not_low_risk():
    text = (
        "Kushith: Good afternoon, you still have Rs.1800 in your balance. "
        "Use it to play games and win big. Good luck! cutt.ly/4rXvce5D Arcane"
    )

    signals, score, risk = analyze_text(text)

    assert "gaming_winnings_lure" in categories(signals)
    assert "suspicious_url" in categories(signals)
    assert score >= 45
    assert risk["level"] in {"High", "Very High"}


def test_earned_social_proof_group_link_lure_is_not_low_risk():
    text = (
        "3 days, 17460 earned, and now he's advising others! "
        "It all started by joining our group. https://ducclinkdo.com/ax9e"
    )

    signals, score, risk = analyze_text(text)

    cats = categories(signals)
    assert "fake_testimonial" in cats
    assert "group_funnel" in cats
    assert "suspicious_url" in cats
    assert score >= 45
    assert risk["level"] in {"High", "Very High"}
