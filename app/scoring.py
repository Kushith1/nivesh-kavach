"""
Deterministic scoring and risk classification module for Nivesh Kavach.
Calculates risk score using diminishing returns, assigns standardized risk levels,
evaluates confidence with transparent reasons, and maps relevant official cards.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

CARDS_FILE = Path(__file__).parent / "cards.json"


def load_cards() -> Dict[str, Any]:
    if CARDS_FILE.exists():
        with open(CARDS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


CARDS_DATA = load_cards()


def compute_score(
    rule_signals: List[Dict[str, Any]],
    ai_extra_signals: List[Dict[str, Any]],
    content_unclear: bool = False
) -> int:
    """
    Computes a deterministic score (0-100) using diminishing returns.
    """
    if not rule_signals and not ai_extra_signals:
        return 0

    # Sort rule weights descending
    weights = sorted([s.get("weight", 15) for s in rule_signals], reverse=True)
    rule_score = 0.0

    # Diminishing returns factors
    decay_factors = [1.0, 0.75, 0.50, 0.35]
    for i, w in enumerate(weights):
        if i < len(decay_factors):
            rule_score += w * decay_factors[i]
        else:
            rule_score += w * 0.20

    # Cap rule score contribution at 88
    rule_score = min(88.0, rule_score)

    # AI extra signals contribution (capped at 25)
    ai_score = min(25.0, len(ai_extra_signals) * 12.0)

    total = int(round(rule_score + ai_score))
    return min(100, max(0, total))


def determine_risk_level(score: int, language: str = "en") -> Dict[str, Any]:
    """
    Categorizes score into one of four standard levels:
    - < 20: "No strong warning signs found (this does NOT mean it is safe)"
    - 20-44: "Some warning signs"
    - 45-69: "High risk"
    - 70+: "Very high risk"
    """
    if score < 20:
        return {
            "level": "Low",
            "score": score,
            "headline": (
                "No strong warning signs found (this does NOT mean it is safe)"
                if language == "en" else
                "कोई मजबूत चेतावनी संकेत नहीं मिला (इसका मतलब यह सुरक्षित है, ऐसा नहीं है)"
            )
        }
    elif score < 45:
        return {
            "level": "Medium",
            "score": score,
            "headline": (
                "Some warning signs detected"
                if language == "en" else
                "कुछ संदिग्ध चेतावनी संकेत पाए गए हैं"
            )
        }
    elif score < 70:
        return {
            "level": "High",
            "score": score,
            "headline": (
                "High risk: Multiple red flags identified"
                if language == "en" else
                "उच्च जोखिम: कई गंभीर चेतावनी संकेत मिले हैं"
            )
        }
    else:
        return {
            "level": "Very High",
            "score": score,
            "headline": (
                "Very high risk: Critical scam indicators present"
                if language == "en" else
                "अत्यधिक जोखिम: गंभीर धोखाधड़ी के स्पष्ट संकेत उपस्थित हैं"
            )
        }


def evaluate_confidence(
    rule_signals: List[Dict[str, Any]],
    ai_signals: List[Dict[str, Any]],
    ai_available: bool,
    content_unclear: bool,
    raw_length: int,
    language: str = "en"
) -> Dict[str, Any]:
    """
    Evaluates confidence:
    - High only if >= 2 independent categories fire AND AI agrees;
    - Low if input is short/unclear or rules and AI disagree;
    - Medium otherwise.
    Provides clear, human-understandable reasons.
    """
    reasons: List[str] = []
    unique_rule_categories = set(s.get("category") for s in rule_signals)
    category_count = len(unique_rule_categories)

    # 1. Category count evaluation
    if category_count >= 2:
        if language == "hi":
            reasons.append(f"{category_count} स्वतंत्र श्रेणी के चेतावनी संकेत मिले।")
        else:
            reasons.append(f"{category_count} independent warning categories triggered.")
    elif category_count == 1:
        if language == "hi":
            reasons.append("केवल 1 चेतावनी श्रेणी ट्रिगर हुई।")
        else:
            reasons.append("Only 1 warning category was detected.")
    else:
        if language == "hi":
            reasons.append("नियमों के आधार पर कोई चेतावनी संकेत नहीं मिला।")
        else:
            reasons.append("No heuristic rule flags triggered.")

    # 2. Input brevity / clarity
    if content_unclear:
        if language == "hi":
            reasons.append("इनपुट सामग्री अधूरी या अस्पष्ट प्रतीत होती है।")
        else:
            reasons.append("Submitted content was flagged as unclear or incomplete.")
    if raw_length < 30 and raw_length > 0:
        if language == "hi":
            reasons.append("इनपुट संदेश काफी संक्षिप्त है।")
        else:
            reasons.append("Input text is very brief, limiting analysis depth.")

    # 3. AI alignment
    ai_disagree = False
    if not ai_available:
        if language == "hi":
            reasons.append("एआई विश्लेषण उपलब्ध नहीं था; मूल्यांकन केवल नियमों पर आधारित है।")
        else:
            reasons.append("AI analysis was unavailable; evaluation relies purely on deterministic rules.")
    else:
        if category_count > 0 and len(ai_signals) > 0:
            if language == "hi":
                reasons.append("एआई और नियम-आधारित जांच दोनों ने जोखिम की पुष्टि की।")
            else:
                reasons.append("AI analysis corroborated the rule-based red flags.")
        elif category_count >= 2 and len(ai_signals) == 0:
            ai_disagree = True
            if language == "hi":
                reasons.append("नियमों ने संकेत पकड़े परंतु एआई ने अतिरिक्त पुष्टि नहीं की।")
            else:
                reasons.append("Heuristic rules detected flags, but AI analysis found no additional signals.")
        elif category_count == 0 and len(ai_signals) >= 2:
            ai_disagree = True
            if language == "hi":
                reasons.append("एआई ने चेतावनी पाई परंतु विशिष्ट नियम मेल नहीं खाए।")
            else:
                reasons.append("AI flagged suspicious traits that did not match rigid regex patterns.")

    # Determine confidence level
    if content_unclear or raw_length < 25 or ai_disagree:
        level = "Low"
    elif category_count >= 2 and ai_available and len(ai_signals) > 0 and not content_unclear:
        level = "High"
    else:
        level = "Medium"

    return {
        "level": level,
        "reasons": reasons
    }


def get_official_links_and_steps(
    all_signals: List[Dict[str, Any]],
    language: str = "en"
) -> Tuple[List[Dict[str, str]], List[str]]:
    """
    Selects official links and actionable next steps strictly from cards.json
    based on the active signal categories.
    """
    cards = load_cards()
    active_categories = set(s.get("category") for s in all_signals)

    selected_links = []
    selected_steps = []
    seen_urls = set()
    seen_steps = set()

    # Always consider general warning cards if signals exist
    for card_id, card in cards.items():
        card_cats = set(card.get("categories", []))
        # Match if any category intersects, or if high risk always include report_fraud
        if (card_cats & active_categories) or (not active_categories and card_id == "verify_registration"):
            lang_data = card.get(language, card.get("en", {}))
            url = lang_data.get("url")
            label = lang_data.get("label")
            note = lang_data.get("note")
            action = lang_data.get("action")

            if url and url not in seen_urls:
                seen_urls.add(url)
                selected_links.append({
                    "label": label,
                    "url": url,
                    "note": note
                })

            if action and action not in seen_steps:
                seen_steps.add(action)
                selected_steps.append(action)

    # If no signals at all, provide basic verification step
    if not selected_steps:
        if language == "hi":
            selected_steps.append("किसी भी अपरिचित योजना में धन लगाने से पहले आधिकारिक सेबी पोर्टल पर मध्यस्थ का विवरण जांचें।")
            selected_links.append({
                "label": "सेबी पंजीकृत मध्यस्थ निर्देशिका",
                "url": "https://www.sebi.gov.in",
                "note": "हमेशा आधिकारिक निर्देशिका से सीधे जांच करें।"
            })
        else:
            selected_steps.append("Always verify any investment intermediary directly on the official SEBI portal before committing funds.")
            selected_links.append({
                "label": "SEBI Registered Intermediaries Directory",
                "url": "https://www.sebi.gov.in",
                "note": "Verify directly on the official regulator directory."
            })

    return selected_links, selected_steps
