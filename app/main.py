"""
FastAPI application for Nivesh Kavach.
Tagline: "Pause. Check. Then decide."
Provides POST /api/analyze and serves static frontend assets.
Strictly abides by:
- No database, no logging of user content
- In-memory cache keyed by hash of REDACTED input, TTL 10 min
- Never fetch or open user-submitted URLs
- Zero financial advice, predictions, or broker promotions
"""

import os
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.redact import redact_text
from app.rules import evaluate_rules
from app.urlcheck import analyze_url_string, extract_urls
from app.llm import analyze_with_gemini
from app.scoring import (
    compute_score,
    determine_risk_level,
    evaluate_confidence,
    get_official_links_and_steps
)
from app.guardrail import filter_structure

# Load environment variables
load_dotenv()

BASE_DIR = Path(__file__).parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Nivesh Kavach",
    description="Safety checker for suspicious investment messages, screenshots, and links for Indian retail investors.",
    version="1.0.0"
)

# CORS middleware for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache: hash -> (result_dict, expiration_timestamp)
CACHE: Dict[str, tuple[Dict[str, Any], float]] = {}
CACHE_TTL_SECONDS = 600  # 10 minutes
MAX_CACHE_ENTRIES = 500

# Anonymous scan metrics (NO user content stored)
ANONYMOUS_METRICS = {
    "total_scans": 0,
    "high_risk_flagged": 0
}

SIGNAL_WEIGHTS = {
    "credential_request": (35, "high"),
    "advance_fee": (32, "high"),
    "impersonation": (30, "high"),
    "suspicious_url": (30, "high"),
    "unrealistic_returns": (25, "high"),
    "unsolicited_windfall": (24, "high"),
    "account_threat": (24, "high"),
    "urgency": (18, "medium"),
    "group_funnel": (16, "medium"),
    "fake_testimonial": (18, "medium"),
    "sebi_claim": (18, "medium"),
    "image_review_needed": (45, "high"),
}


def cleanup_expired_cache():
    """Removes expired entries from in-memory cache."""
    now = time.time()
    expired_keys = [k for k, (_, exp) in CACHE.items() if now > exp]
    for k in expired_keys:
        CACHE.pop(k, None)
    if len(CACHE) > MAX_CACHE_ENTRIES:
        # Evict oldest 50 entries
        sorted_keys = sorted(CACHE.keys(), key=lambda k: CACHE[k][1])
        for k in sorted_keys[:50]:
            CACHE.pop(k, None)


DISCLAIMERS = {
    "en": "Nivesh Kavach is an AI-assisted educational tool designed to help spot common financial warning signs. It does NOT provide investment advice, predict returns, or guarantee legal legitimacy. In case of financial fraud, immediately call national helpline 1930.",
    "hi": "निवेश कवच एक शैक्षणिक सुरक्षा टूल है जो वित्तीय धोखाधड़ी के सामान्य संकेतों की पहचान में सहायता करता है। यह कोई निवेश सलाह नहीं देता और न ही कानूनी प्रमाण पत्र है। वित्तीय धोखाधड़ी की स्थिति में तुरंत राष्ट्रीय हेल्पलाइन 1930 पर कॉल करें।"
}


@app.post("/api/analyze")
async def analyze_endpoint(
    text: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    language: Optional[str] = Form("en")
):
    """
    Main analysis endpoint. Accepts text, url, and/or image (max 4 MB).
    At least one input required.
    """
    lang = "hi" if language and language.strip().lower() == "hi" else "en"

    # Validation: at least one input required
    has_text = bool(text and text.strip())
    has_url = bool(url and url.strip())
    has_image = bool(image and image.filename)

    if not (has_text or has_url or has_image):
        raise HTTPException(
            status_code=400,
            detail="At least one input (text, url, or image) is required."
        )

    # 1. Read and validate image (if present)
    image_bytes: Optional[bytes] = None
    image_mime: Optional[str] = None
    image_hash_part = ""

    if has_image:
        content_type = image.content_type or ""
        if content_type not in ["image/jpeg", "image/png", "image/jpg", "image/webp"]:
            raise HTTPException(
                status_code=400,
                detail="Unsupported image format. Please upload a PNG or JPG image."
            )

        raw_bytes = await image.read()
        if len(raw_bytes) > 4 * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail="Image exceeds maximum allowed size of 4 MB."
            )
        image_bytes = raw_bytes
        image_mime = content_type
        image_hash_part = hashlib.sha256(raw_bytes).hexdigest()[:16]

    # 2. Text redaction
    raw_text = (text or "").strip()
    redacted_text, redaction_counts = redact_text(raw_text)

    # 3. URL string extraction and analysis
    submitted_url = (url or "").strip()
    url_signals = []
    url_meta = {}

    if submitted_url:
        u_sigs, u_meta = analyze_url_string(submitted_url, language=lang)
        url_signals.extend(u_sigs)
        url_meta = u_meta

    # Check for embedded URLs within the input text
    embedded_urls = extract_urls(redacted_text)
    for emb_url in embedded_urls:
        if emb_url != submitted_url:
            emb_sigs, _ = analyze_url_string(emb_url, language=lang)
            for s in emb_sigs:
                if not any(existing["id"] == s["id"] for existing in url_signals):
                    url_signals.append(s)

    # 4. Check in-memory cache using hash of REDACTED input
    cleanup_expired_cache()
    cache_key_material = f"{redacted_text}|{submitted_url}|{lang}|{image_hash_part}"
    cache_key = hashlib.sha256(cache_key_material.encode("utf-8")).hexdigest()

    if cache_key in CACHE:
        cached_res, exp = CACHE[cache_key]
        if time.time() < exp:
            return JSONResponse(content=cached_res)

    # 5. Rule evaluation on redacted text
    rule_signals, rule_claims = evaluate_rules(redacted_text, language=lang)

    # Combine rule signals from text and URL
    all_rule_signals = rule_signals + url_signals

    # 6. Gemini heuristic analysis
    # Provide existing rule signals so AI can focus on nuanced/unstructured traits
    ai_available, ai_result = analyze_with_gemini(
        redacted_text=redacted_text,
        language=lang,
        image_bytes=image_bytes,
        image_mime=image_mime,
        existing_signals=all_rule_signals
    )

    ai_extra_signals = ai_result.get("extra_signals", [])
    content_unclear = ai_result.get("content_unclear", False)
    plain_explanation = ai_result.get("plain_explanation", "")

    # Format AI extra signals
    formatted_ai_signals = []
    for sig in ai_extra_signals:
        cat = sig.get("category", "unverified_claim")
        weight, severity = SIGNAL_WEIGHTS.get(cat, (14, "medium"))
        formatted_ai_signals.append({
            "id": f"AI_{cat.upper()}",
            "category": cat,
            "weight": weight,
            "severity": severity,
            "evidence": sig.get("evidence_quote", ""),
            "why_dangerous": sig.get("why_dangerous", ""),
            "source": "ai"
        })

    if has_image and not has_text and not has_url and not (all_rule_signals or formatted_ai_signals):
        all_rule_signals.append({
            "id": "IMAGE_REVIEW_NEEDED",
            "category": "image_review_needed",
            "weight": 45,
            "severity": "high",
            "evidence": "image-only upload",
            "why_dangerous": (
                "The screenshot could not be read confidently by the analyzer. Do not treat this as safe; type or paste the visible text/link for a stronger check."
                if lang == "en" else
                "स्क्रीनशॉट को जांच प्रणाली स्पष्ट रूप से पढ़ नहीं पाई। इसे सुरक्षित न मानें; बेहतर जांच के लिए दिखाई देने वाला टेक्स्ट या लिंक टाइप/पेस्ट करें।"
            ),
            "source": "rule"
        })

    # Combine all signals
    all_signals = all_rule_signals + formatted_ai_signals

    # Combine claims to verify
    ai_claims = ai_result.get("claims_to_verify", [])
    all_claims = rule_claims + ai_claims

    # De-duplicate claims
    unique_claims = []
    seen_claim_texts = set()
    for c in all_claims:
        claim_str = c.get("claim", "").strip()
        if claim_str and claim_str not in seen_claim_texts:
            seen_claim_texts.add(claim_str)
            unique_claims.append(c)

    # 7. Scoring
    score = compute_score(
        rule_signals=all_rule_signals,
        ai_extra_signals=formatted_ai_signals,
        content_unclear=content_unclear
    )
    risk_info = determine_risk_level(
        score, language=lang, ai_signal_count=len(formatted_ai_signals)
    )

    # 8. Confidence evaluation
    raw_length = len(raw_text) + (len(submitted_url) if submitted_url else 0)
    confidence = evaluate_confidence(
        rule_signals=all_rule_signals,
        ai_signals=formatted_ai_signals,
        ai_available=ai_available,
        content_unclear=content_unclear,
        raw_length=raw_length,
        language=lang
    )

    # 9. Official links and actionable next steps
    official_links, next_steps = get_official_links_and_steps(
        all_signals=all_signals,
        language=lang
    )

    # If plain_explanation is empty or AI was unavailable, create structured explanation
    if not plain_explanation or not ai_available:
        if lang == "hi":
            if score >= 45:
                plain_explanation = f"इस संदेश में {len(all_signals)} गंभीर चेतावनी संकेत पाए गए हैं। इसमें बिना जोखिम या भारी मुनाफे का दावा किया गया है जो पोंजी स्कीम की ओर इशारा करता है।"
            else:
                plain_explanation = "संदेश में कुछ संदिग्ध संकेत हो सकते हैं। किसी भी अनजान व्यक्ति के कहने पर वित्तीय लेन-देन न करें।"
        else:
            if score >= 45:
                plain_explanation = f"This content exhibits {len(all_signals)} red flags including unrealistic return claims and pressure tactics commonly observed in financial fraud."
            else:
                plain_explanation = "No overwhelming fraud patterns were detected, but always independently verify regulatory registrations before investing."

    # 10. Assemble final response
    response_data = {
        "risk": risk_info,
        "signals": all_signals,
        "claims_to_verify": unique_claims,
        "plain_explanation": plain_explanation,
        "next_steps": next_steps,
        "confidence": confidence,
        "official_links": official_links,
        "disclaimer": DISCLAIMERS[lang],
        "ai_available": ai_available
    }

    # Apply guardrail filter over entire response payload
    filtered_response = filter_structure(response_data)

    # Update anonymous metrics
    ANONYMOUS_METRICS["total_scans"] += 1
    if score >= 45:
        ANONYMOUS_METRICS["high_risk_flagged"] += 1

    # Save to in-memory cache
    CACHE[cache_key] = (filtered_response, time.time() + CACHE_TTL_SECONDS)

    return JSONResponse(content=filtered_response)


@app.get("/api/metrics")
async def metrics_endpoint():
    """Returns anonymous aggregated scan counters. No PII or user content."""
    return ANONYMOUS_METRICS


# Mount static directory
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root_index():
    """Serves the single-page application."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Nivesh Kavach API is running. Static assets pending."}
