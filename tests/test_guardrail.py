"""
Unit tests for app/guardrail.py output filter
"""

from app.guardrail import filter_text, filter_structure, SAFE_FALLBACK_TEXT


def test_guardrail_blocks_buy_sell_advice():
    prohibited = [
        "Strong buy call for tomorrow",
        "We recommend buying these shares immediately",
        "You should sell your holdings right now",
        "यह शेयर तुरंत खरीदें"
    ]
    for p in prohibited:
        res = filter_text(p)
        assert SAFE_FALLBACK_TEXT in res
        assert "buy" not in res.lower() or SAFE_FALLBACK_TEXT in res


def test_guardrail_blocks_target_prices_and_predictions():
    prohibited = [
        "Target price of Rs 500 within one week",
        "Stock will rise 50% tomorrow",
        "Crypto will double in 24 hours",
        "कीमत दोगुनी होगी"
    ]
    for p in prohibited:
        res = filter_text(p)
        assert SAFE_FALLBACK_TEXT in res


def test_guardrail_blocks_unauthorized_urls():
    bad_url_text = "Check our platform at https://unauthorized-trader-bot.net/api"
    res = filter_text(bad_url_text)
    assert "https://unauthorized-trader-bot.net" not in res
    assert "https://www.sebi.gov.in" in res


def test_guardrail_preserves_allowed_official_urls():
    allowed_text = "Please check the official portal at https://www.sebi.gov.in for registration status."
    res = filter_text(allowed_text)
    assert "https://www.sebi.gov.in" in res


def test_guardrail_filter_structure():
    data = {
        "summary": "Strong buy recommendation on ABC Corp.",
        "links": ["https://malicious-scam.com/register"],
        "safe_note": "Market risks apply."
    }
    filtered = filter_structure(data)
    assert SAFE_FALLBACK_TEXT in filtered["summary"]
    assert "https://malicious-scam.com" not in filtered["links"][0]
    assert filtered["safe_note"] == "Market risks apply."
