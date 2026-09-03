import json
import re
from datetime import datetime, timezone
from pathlib import Path

from google import genai
from google.genai import types
from groq import Groq
from pydantic import BaseModel, Field

from app.config import settings

gemini_client = genai.Client(api_key=settings.gemini_api_key)
groq_client = Groq(api_key=settings.groq_api_key)

GEMINI_MODEL = "gemini-3.6-flash"
GROQ_MODEL = "openai/gpt-oss-120b" 

GEMINI_TIMEOUT_SECONDS = 30

INPUT_PRICE_PER_MILLION = 1.50
OUTPUT_PRICE_PER_MILLION = 7.50

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "llm_cost_log.jsonl"


class LLMAnalysis(BaseModel):
    tactics_detected: list[str] = Field(
        description=(
            "Scam tactics found in the wording. Only use these exact values: "
            "'urgency', 'too_good_to_be_true', 'requests_sensitive_info', "
            "'generic_greeting'. Empty list if none apply."
        )
    )
    named_entities: list[str] = Field(
        description="Names of people or organizations mentioned, for separate OSINT lookup."
    )
    summary: str = Field(description="One-sentence plain-language explanation of the assessment.")
    llm_confidence: float = Field(
        description="0.0 to 1.0 confidence this form is a scam, based on wording alone."
    )


SYSTEM_PROMPT = """You are a narrow-purpose classifier. You are given the \
title, description, and questions of a Google Form. Your only job is to:

1. Identify which of these scam tactics are present in the form's wording:
   - urgency (artificial time pressure, "act now", "expires soon")
   - too_good_to_be_true (unearned prizes, free money, guaranteed winnings)
   - requests_sensitive_info (asks for bank details, SSN, passwords, OTPs)
   - generic_greeting (impersonal, no specific recipient name, mass-blast tone)
2. Extract any named people or organizations mentioned, so they can be
   looked up separately.
3. Give a one-sentence plain-language summary of your assessment.
4. Give your own confidence (0.0-1.0) that this form is a scam, based
   purely on the wording — you are not checking any links or reputation,
   that happens elsewhere in the system.

Respond with JSON matching this exact shape, and nothing else — no markdown
fences, no commentary before or after:
{"tactics_detected": [...], "named_entities": [...], "summary": "...", "llm_confidence": 0.0}

Do not invent facts you cannot verify from the text. If nothing looks
suspicious, return an empty tactics_detected list and a low confidence
score."""


def _build_prompt(title: str, description: str, questions: list[str]) -> str:
    questions_block = "\n".join(f"- {q}" for q in questions) or "(none listed)"
    return (
        f"Form title: {title}\n"
        f"Form description: {description or '(none)'}\n"
        f"Form questions:\n{questions_block}"
    )


def _extract_json_block(raw: str) -> str:
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in model output: {raw!r}")
    return match.group(0)


def _log_cost(cost_entry: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(cost_entry) + "\n")


def _try_groq(prompt: str) -> LLMAnalysis | None:
    try:
        completion = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        raw = completion.choices[0].message.content
        cleaned = _extract_json_block(raw)
        analysis = LLMAnalysis.model_validate_json(cleaned)

        usage = completion.usage
        _log_cost({
            "provider": "groq",
            "model": GROQ_MODEL,
            "input_tokens": usage.prompt_tokens,
            "output_tokens": usage.completion_tokens,
            "estimated_cost_usd": 0.0,  # Groq free tier
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return analysis
    except Exception as e:
        print(f"[llm] Groq failed, falling back to Gemini: {e}")
        return None


def _try_gemini(prompt: str) -> LLMAnalysis | None:
    try:
        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=LLMAnalysis,
                http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_SECONDS * 1000),
            ),
        )
        analysis = LLMAnalysis.model_validate_json(response.text)

        usage = response.usage_metadata
        input_tokens = usage.prompt_token_count or 0
        output_tokens = usage.candidates_token_count or 0
        estimated_cost = (
            input_tokens / 1_000_000 * INPUT_PRICE_PER_MILLION
            + output_tokens / 1_000_000 * OUTPUT_PRICE_PER_MILLION
        )
        _log_cost({
            "provider": "gemini",
            "model": GEMINI_MODEL,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "estimated_cost_usd": round(estimated_cost, 6),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return analysis
    except Exception as e:
        print(f"[llm] Gemini also failed: {e}")
        return None


def classify_form(title: str, description: str, questions: list[str]) -> LLMAnalysis:
    prompt = _build_prompt(title, description, questions)

    result = _try_groq(prompt)
    if result is not None:
        return result

    result = _try_gemini(prompt)
    if result is not None:
        return result

    raise RuntimeError("Both LLM providers (Groq and Gemini) failed to classify this form.")