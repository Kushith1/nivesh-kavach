"""
Gemini integration module using official google-genai SDK.
Performs strictly bounded heuristic safety analysis:
- Temperature 0.2
- Structured Pydantic JSON schema
- Only identifies warning signs and quotes verbatim evidence
- Never provides investment advice, predictions, or evaluations of securities
- Graceful degradation on 429/errors returning ai_available=False
"""

import os
import json
import logging
from typing import List, Optional, Tuple, Dict, Any
from pydantic import BaseModel, Field

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

from app.guardrail import filter_structure

logger = logging.getLogger(__name__)


class ExtraSignal(BaseModel):
    category: str = Field(
        ...,
        description="Standardized category of suspicious trait (e.g. urgency, unrealistic_returns, impersonation, advance_fee, credential_request, unverified_claim)"
    )
    evidence_quote: str = Field(
        ...,
        description="Exact verbatim quote from the content demonstrating the warning sign. Do NOT alter, summarize, or translate this quote."
    )
    why_dangerous: str = Field(
        ...,
        description="Clear explanation of why this pattern is dangerous for retail investors."
    )


class ClaimToVerify(BaseModel):
    claim: str = Field(
        ...,
        description="Specific fact or registration claim made in the message."
    )
    how_to_verify: str = Field(
        ...,
        description="Step-by-step guidance on how the user can independently verify this claim via official portals."
    )


class GeminiAnalysisOutput(BaseModel):
    extra_signals: List[ExtraSignal] = Field(
        default_factory=list,
        description="Additional warning signs not already captured by rigid rules."
    )
    claims_to_verify: List[ClaimToVerify] = Field(
        default_factory=list,
        description="Claims of registration, approval, or affiliations that require independent verification."
    )
    plain_explanation: str = Field(
        ...,
        description="Grade-6 reading level explanation in short simple sentences in the user's requested language and script (Devanagari for Hindi)."
    )
    content_unclear: bool = Field(
        ...,
        description="Set to true if the input was too short, garbled, ambiguous, or lacks context."
    )


SYSTEM_PROMPT = """You are Nivesh Kavach, a safety assistant for Indian retail investors.
Your ONLY role is to spot warning signs and explain risks of fraud in suspicious investment messages, screenshots, and links.

ABSOLUTE HARD RULES:
1. NEVER give buy, sell, or hold advice, price/return predictions, or recommend/promote any security, broker, product, or scheme.
2. NEVER judge whether any stock, company, or security is good or bad.
3. NEVER predict whether any asset or market will rise, fall, crash, or surge.
4. Quote evidence verbatim from the content without translating, summarizing, or altering the exact quotes.
5. Say "not sure" or mark content_unclear=true instead of guessing when context is insufficient.
6. Do NOT invent or hallucinate URLs, regulations, section numbers, or registration data.
7. Write the plain_explanation in the requested language (English or Hindi in Devanagari script) at a Grade-6 reading level using short, simple sentences. Avoid English technical jargon in Hindi (or explain briefly in brackets).
8. If the content is genuine or benign (e.g. a routine bank alert, genuine regulatory awareness note, normal transaction debit SMS), state clearly that it appears to be a routine notification with no obvious scam patterns, while reminding that genuine alerts never ask for OTPs or urgent unauthorized transfers.
"""


def get_client() -> Optional[Any]:
    """Initializes and returns GenAI Client if GEMINI_API_KEY is configured."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not genai:
        return None
    try:
        return genai.Client(api_key=api_key)
    except Exception as e:
        logger.error(f"Failed to initialize GenAI client: {e}")
        return None


def analyze_with_gemini(
    redacted_text: str,
    language: str = "en",
    image_bytes: Optional[bytes] = None,
    image_mime: Optional[str] = None,
    existing_signals: Optional[List[Dict[str, Any]]] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Calls Gemini model with structured output.
    Returns:
        (ai_available, result_dict)
    On any error, missing key, or rate limit: returns (False, fallback_dict)
    """
    fallback_message = (
        "Detailed explanation unavailable right now."
        if language == "en" else
        "विस्तृत विवरण अभी उपलब्ध नहीं है।"
    )

    client = get_client()
    if not client:
        return False, {
            "extra_signals": [],
            "claims_to_verify": [],
            "plain_explanation": fallback_message,
            "content_unclear": False
        }

    model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    existing_categories = [s.get("category") for s in (existing_signals or [])]
    user_prompt = f"""
Language requested: {'Hindi (write explanation in Devanagari script)' if language == 'hi' else 'English'}.
Existing warning categories already detected by rule engine: {', '.join(existing_categories) if existing_categories else 'None'}.

Content to analyze:
\"\"\"{redacted_text}\"\"\"

Analyze the above content. Identify any additional suspicious traits or nuance, extract any claims that need independent verification, and explain the warning signs clearly for a normal retail saver.
"""

    contents: List[Any] = []
    if image_bytes and image_mime and types:
        try:
            image_part = types.Part.from_bytes(data=image_bytes, mime_type=image_mime)
            contents.append(image_part)
        except Exception as e:
            logger.warning(f"Failed to create Part from image bytes: {e}")

    contents.append(user_prompt)

    try:
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=GeminiAnalysisOutput,
        )

        response = client.models.generate_content(
            model=model_name,
            contents=contents,
            config=config,
        )

        if not response or not response.text:
            return False, {
                "extra_signals": [],
                "claims_to_verify": [],
                "plain_explanation": fallback_message,
                "content_unclear": False
            }

        parsed = json.loads(response.text)

        # Apply guardrail filter over all generated strings
        filtered = filter_structure(parsed)

        return True, filtered

    except Exception as exc:
        logger.warning(f"Gemini API call failed or rate-limited: {exc}")
        return False, {
            "extra_signals": [],
            "claims_to_verify": [],
            "plain_explanation": fallback_message,
            "content_unclear": False
        }
