"""
Unit tests for app/scoring.py (deterministic scoring and risk levels)
"""

from app.scoring import (
    compute_score,
    determine_risk_level,
    evaluate_confidence,
    get_official_links_and_steps
)


def test_compute_score_diminishing_returns():
    # Empty signals
    assert compute_score([], []) == 0

    # Single high weight signal
    s1 = [{"id": "R1", "category": "guaranteed_returns", "weight": 28}]
    score1 = compute_score(s1, [])
    assert score1 == 28

    # Multiple signals with diminishing returns
    s2 = [
        {"id": "R1", "category": "guaranteed_returns", "weight": 28},
        {"id": "R2", "category": "credential_request", "weight": 35},
        {"id": "R3", "category": "advance_fee", "weight": 28},
    ]
    score2 = compute_score(s2, [])
    # 35 + 28*0.75 (21) + 28*0.5 (14) = 70
    assert 65 <= score2 <= 75

    # Capped at 100
    huge_signals = [{"id": f"R{i}", "category": f"cat_{i}", "weight": 40} for i in range(10)]
    assert compute_score(huge_signals, [{"category": "extra"}]) <= 100


def test_determine_risk_levels():
    l_low = determine_risk_level(15, "en")
    assert l_low["level"] == "Low"
    assert "No strong warning signs" in l_low["headline"]

    l_med = determine_risk_level(30, "en")
    assert l_med["level"] == "Medium"

    l_high = determine_risk_level(55, "en")
    assert l_high["level"] == "High"

    l_vhigh = determine_risk_level(85, "en")
    assert l_vhigh["level"] == "Very High"


def test_confidence_evaluation():
    rule_signals = [
        {"category": "guaranteed_returns", "weight": 28},
        {"category": "credential_request", "weight": 35}
    ]
    ai_signals = [{"category": "urgency"}]

    # High confidence: >= 2 categories and AI agrees
    conf = evaluate_confidence(
        rule_signals=rule_signals,
        ai_signals=ai_signals,
        ai_available=True,
        content_unclear=False,
        raw_length=120,
        language="en"
    )
    assert conf["level"] == "High"
    assert len(conf["reasons"]) >= 2

    # Low confidence on unclear or very short input
    conf_short = evaluate_confidence(
        rule_signals=rule_signals,
        ai_signals=ai_signals,
        ai_available=True,
        content_unclear=True,
        raw_length=15,
        language="en"
    )
    assert conf_short["level"] == "Low"


def test_cards_mapping():
    signals = [{"category": "sebi_claim"}, {"category": "credential_request"}]
    links, steps = get_official_links_and_steps(signals, language="en")
    assert len(links) >= 1
    assert any("sebi.gov.in" in l["url"] for l in links)
    assert any("cybercrime.gov.in" in l["url"] for l in links)
    assert len(steps) >= 1
