"""Regression checks for previously under-scored phishing messages."""

import json
from pathlib import Path

from app.redact import redact_text
from app.rules import evaluate_rules
from app.scoring import compute_score, determine_risk_level


def _sample_by_id(sample_id: str) -> dict:
    source = Path(__file__).with_name("samples.json")
    data = json.loads(source.read_text(encoding="utf-8"))
    for group in ("scam_samples", "benign_samples"):
        for sample in data[group]:
            if sample["id"] == sample_id:
                return sample
    raise AssertionError(f"Missing sample {sample_id}")


def _risk_for(sample: dict) -> dict:
    redacted, _ = redact_text(sample["text"])
    signals, _ = evaluate_rules(redacted, language=sample["language"])
    return determine_risk_level(compute_score(signals, []), sample["language"])


def test_under_scored_scam_regressions_are_high_risk():
    for sample_id in ("E2", "E4", "H1", "H4"):
        assert _risk_for(_sample_by_id(sample_id))["score"] >= 45


def test_otp_awareness_messages_remain_low_risk():
    for sample_id in ("B1", "B2"):
        assert _risk_for(_sample_by_id(sample_id))["score"] < 20
