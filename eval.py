"""
Evaluation script for Nivesh Kavach.
Computes and reports scam recall and benign false-positive rate over tests/samples.json.
Note: Small sample size (synthetic test set).
"""

import json
from pathlib import Path
from app.redact import redact_text
from app.rules import evaluate_rules
from app.urlcheck import analyze_url_string, extract_urls
from app.scoring import compute_score, determine_risk_level

SAMPLES_FILE = Path(__file__).parent / "tests" / "samples.json"


def evaluate_sample(sample_dict: dict) -> dict:
    text = sample_dict.get("text", "")
    url = sample_dict.get("url", "")
    lang = sample_dict.get("language", "en")

    # 1. Redaction
    redacted_text, _ = redact_text(text)

    # 2. URL analysis
    url_signals = []
    if url:
        u_sigs, _ = analyze_url_string(url, language=lang)
        url_signals.extend(u_sigs)

    for emb_url in extract_urls(redacted_text):
        if emb_url != url:
            u_sigs, _ = analyze_url_string(emb_url, language=lang)
            for s in u_sigs:
                if not any(existing["id"] == s["id"] for existing in url_signals):
                    url_signals.append(s)

    # 3. Rule matching
    rule_signals, claims = evaluate_rules(redacted_text, language=lang)
    all_signals = rule_signals + url_signals

    # 4. Scoring
    score = compute_score(all_signals, [])
    risk = determine_risk_level(score, language=lang)

    return {
        "id": sample_dict.get("id"),
        "score": score,
        "level": risk["level"],
        "headline": risk["headline"],
        "signal_count": len(all_signals),
        "categories": [s["category"] for s in all_signals]
    }


def run_evaluation():
    if not SAMPLES_FILE.exists():
        print(f"Error: {SAMPLES_FILE} not found.")
        return

    with open(SAMPLES_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    scam_samples = data.get("scam_samples", [])
    benign_samples = data.get("benign_samples", [])
    ambiguous_samples = data.get("ambiguous_samples", [])

    print("=" * 70)
    print("       NIVESH KAVACH - BENCHMARK & EVALUATION REPORT")
    print("=" * 70)
    print(f"Test Set Summary: {len(scam_samples)} Scam, {len(benign_samples)} Benign, {len(ambiguous_samples)} Ambiguous")
    print("Note: Small sample size (synthetic/fictional validation set for SANGYAN hackathon).\n")

    # 1. Evaluate Scam Samples
    print("-" * 70)
    print("1. SCAM SAMPLES EVALUATION")
    print("-" * 70)
    scam_detected_high = 0
    scam_detected_any = 0

    for s in scam_samples:
        res = evaluate_sample(s)
        is_high = res["score"] >= 45
        is_any = res["score"] >= 20
        if is_high:
            scam_detected_high += 1
        if is_any:
            scam_detected_any += 1

        status = "PASSED (High Risk)" if is_high else ("FLAGGED (Medium)" if is_any else "MISSED")
        print(f"[{s['id']}] Score: {res['score']:2d}/100 | Level: {res['level']:<9} | Status: {status}")
        print(f"       Categories: {res['categories']}")

    scam_recall_high = (scam_detected_high / len(scam_samples)) * 100 if scam_samples else 0
    scam_recall_any = (scam_detected_any / len(scam_samples)) * 100 if scam_samples else 0

    # 2. Evaluate Benign Samples
    print("\n" + "-" * 70)
    print("2. BENIGN SAMPLES EVALUATION (False Positive Check)")
    print("-" * 70)
    benign_fp_high = 0
    benign_fp_any = 0

    for b in benign_samples:
        res = evaluate_sample(b)
        is_high = res["score"] >= 45
        is_any = res["score"] >= 20
        if is_high:
            benign_fp_high += 1
        if is_any:
            benign_fp_any += 1

        status = "CLEAN (Low Risk)" if not is_any else ("FALSE POSITIVE" if is_high else "WARNING")
        print(f"[{b['id']}] Score: {res['score']:2d}/100 | Level: {res['level']:<9} | Status: {status}")

    benign_fpr_high = (benign_fp_high / len(benign_samples)) * 100 if benign_samples else 0
    benign_fpr_any = (benign_fp_any / len(benign_samples)) * 100 if benign_samples else 0

    # 3. Evaluate Ambiguous Samples
    print("\n" + "-" * 70)
    print("3. AMBIGUOUS SAMPLES EVALUATION")
    print("-" * 70)
    for a in ambiguous_samples:
        res = evaluate_sample(a)
        print(f"[{a['id']}] Score: {res['score']:2d}/100 | Level: {res['level']:<9} | Categories: {res['categories']}")

    # Summary Metrics
    print("\n" + "=" * 70)
    print("                     EVALUATION SUMMARY")
    print("=" * 70)
    print(f"Total Scam Samples Analyzed         : {len(scam_samples)}")
    print(f"Scam Recall (High/Very High Risk)   : {scam_recall_high:.1f}% ({scam_detected_high}/{len(scam_samples)})")
    print(f"Scam Recall (Any Warning >= 20)     : {scam_recall_any:.1f}% ({scam_detected_any}/{len(scam_samples)})")
    print("-" * 70)
    print(f"Total Benign Samples Analyzed       : {len(benign_samples)}")
    print(f"Benign False-Positive Rate (High)   : {benign_fpr_high:.1f}% ({benign_fp_high}/{len(benign_samples)})")
    print(f"Benign False-Positive Rate (Any>=20): {benign_fpr_any:.1f}% ({benign_fp_any}/{len(benign_samples)})")
    print("=" * 70)


if __name__ == "__main__":
    run_evaluation()
