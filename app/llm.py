import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from google import genai
from google.genai import types
from groq import Groq
from pydantic import BaseModel, Field

from app.config import settings
from app.keys import BYOKKeys

GEMINI_MODEL = "gemini-3.6-flash"
GROQ_MODEL = "openai/gpt-oss-120b"
GEMINI_TIMEOUT_SECONDS = 15

INPUT_PRICE_PER_MILLION = 1.50
OUTPUT_PRICE_PER_MILLION = 7.50

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "llm_cost_log.jsonl"

T = TypeVar("T", bound=BaseModel)


def _resolve_gemini_key(keys: BYOKKeys | None) -> str | None:
    if keys and keys.gemini_api_key:
        return keys.gemini_api_key
    return settings.gemini_api_key  # dev fallback only


def _resolve_groq_key(keys: BYOKKeys | None) -> str | None:
    if keys and keys.groq_api_key:
        return keys.groq_api_key
    return settings.groq_api_key  # dev fallback only


def _log_cost(cost_entry: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(cost_entry) + "\n")


def _extract_json_block(raw: str) -> str:
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in model output: {raw!r}")
    return match.group(0)


def _try_groq_structured(system_prompt: str, user_prompt: str, schema_cls: type[T], log_tag: str, groq_key: str | None) -> T | None:
    if not groq_key:
        return None
    try:
        client = Groq(api_key=groq_key)
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        raw = completion.choices[0].message.content
        cleaned = _extract_json_block(raw)
        result = schema_cls.model_validate_json(cleaned)

        usage = completion.usage
        _log_cost({
            "provider": "groq", "model": GROQ_MODEL, "task": log_tag,
            "input_tokens": usage.prompt_tokens, "output_tokens": usage.completion_tokens,
            "estimated_cost_usd": 0.0, "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return result
    except Exception as e:
        print(f"[llm:{log_tag}] Groq failed, falling back to Gemini: {e}")
        return None


def _try_gemini_structured(system_prompt: str, user_prompt: str, schema_cls: type[T], log_tag: str, gemini_key: str | None) -> T | None:
    if not gemini_key:
        return None
    try:
        client = genai.Client(api_key=gemini_key)
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=schema_cls,
                http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_SECONDS * 1000),
            ),
        )
        result = schema_cls.model_validate_json(response.text)

        usage = response.usage_metadata
        input_tokens = usage.prompt_token_count or 0
        output_tokens = usage.candidates_token_count or 0
        estimated_cost = (
            input_tokens / 1_000_000 * INPUT_PRICE_PER_MILLION
            + output_tokens / 1_000_000 * OUTPUT_PRICE_PER_MILLION
        )
        _log_cost({
            "provider": "gemini", "model": GEMINI_MODEL, "task": log_tag,
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "estimated_cost_usd": round(estimated_cost, 6), "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return result
    except Exception as e:
        print(f"[llm:{log_tag}] Gemini also failed: {e}")
        return None


def _classify(system_prompt: str, user_prompt: str, schema_cls: type[T], log_tag: str, keys: BYOKKeys | None) -> T:
    groq_key = _resolve_groq_key(keys)
    gemini_key = _resolve_gemini_key(keys)

    result = _try_groq_structured(system_prompt, user_prompt, schema_cls, log_tag, groq_key)
    if result is not None:
        return result
    result = _try_gemini_structured(system_prompt, user_prompt, schema_cls, log_tag, gemini_key)
    if result is not None:
        return result

    if not groq_key and not gemini_key:
        raise RuntimeError("No LLM API key available. Set your Gemini or Groq key in the extension options.")
    raise RuntimeError(f"Both LLM providers failed for task '{log_tag}'.")


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


CLASSIFY_SYSTEM_PROMPT = """You are a narrow-purpose classifier. You are given the \
title, description, and questions of a Google Form. Your only job is to:

1. Identify which of these scam tactics are present in the form's wording:
   - urgency (artificial time pressure, "act now", "expires soon")
   - too_good_to_be_true (unearned prizes, free money, guaranteed winnings)
   - requests_sensitive_info (asks for bank details, SSN, passwords, OTPs)
   - generic_greeting (impersonal, no specific recipient name, mass-blast tone)
2. Extract any named people or organizations mentioned, so they can be
   looked up separately. Only extract real proper names of people or
   organizations - do NOT extract generic field/topic labels, acronyms for
   academic fields, or common phrases. Do NOT extract major well-known
   trusted platforms/services (Google, Google Forms, Google Classroom,
   Google Sheets, Microsoft, Zoom, YouTube, Gmail, Moodle, WhatsApp) as
   named entities - they are not suspicious just for being mentioned or
   linked to.
3. Give a one-sentence plain-language summary of your assessment.
4. Give your own confidence (0.0-1.0) that this form is a scam, based
   purely on the wording - you are not checking any links or reputation,
   that happens elsewhere in the system.

Respond with JSON matching this exact shape, and nothing else - no markdown
fences, no commentary before or after:
{"tactics_detected": [...], "named_entities": [...], "summary": "...", "llm_confidence": 0.0}

Do not invent facts you cannot verify from the text. If nothing looks
suspicious, return an empty tactics_detected list and a low confidence
score."""


def _build_classify_prompt(title: str, description: str, questions: list[str]) -> str:
    questions_block = "\n".join(f"- {q}" for q in questions) or "(none listed)"
    return (
        f"Form title: {title}\n"
        f"Form description: {description or '(none)'}\n"
        f"Form questions:\n{questions_block}"
    )


def classify_form(title: str, description: str, questions: list[str], keys: BYOKKeys | None = None) -> LLMAnalysis:
    prompt = _build_classify_prompt(title, description, questions)
    return _classify(CLASSIFY_SYSTEM_PROMPT, prompt, LLMAnalysis, log_tag="classify_form", keys=keys)


class EntityRelevance(BaseModel):
    is_relevant: bool = Field(
        description=(
            "True ONLY if the search results genuinely show this specific entity "
            "is accused of or associated with scams/fraud/complaints - not merely "
            "that the search words appear somewhere nearby. Be skeptical, "
            "especially of well-known trusted platforms and generic terms."
        )
    )
    reason: str = Field(description="One short sentence explaining the judgment.")
    evidence_snippet: str | None = Field(
        default=None,
        description="If is_relevant is true, the exact quoted sentence from the "
        "results that supports the accusation. Null if not relevant.",
    )
    evidence_url: str | None = Field(
        default=None,
        description="If is_relevant is true, the source URL (copied exactly from "
        "the provided list) the evidence_snippet came from. Null if not relevant.",
    )


RELEVANCE_SYSTEM_PROMPT = """You are given a name or organization that was \
searched alongside the words "scam", "fraud", or "complaint", and the top \
search results (snippet + source URL) returned. Judge whether those results \
genuinely show this specific entity is associated with scam/fraud reports — \
not just that the search words appear somewhere on the page.

Be skeptical by default. Well-known trusted platforms, generic terms, and \
acronyms often produce coincidental matches unrelated to the entity being \
fraudulent.

If you judge it relevant, you MUST quote the exact supporting sentence as \
evidence_snippet and copy the matching source URL exactly from the list as \
evidence_url. If not relevant, both must be null - never claim relevance \
without a real quote to back it up.

Respond with JSON matching this exact shape, and nothing else:
{"is_relevant": false, "reason": "...", "evidence_snippet": null, "evidence_url": null}"""


def judge_entity_relevance(entity_name: str, results: list[dict], keys: BYOKKeys | None = None) -> EntityRelevance:
    if not results:
        return EntityRelevance(is_relevant=False, reason="No search results to judge.")

    numbered = "\n---\n".join(
        f"[{i+1}] URL: {r.get('url', '')}\nSnippet: {r.get('snippet', '')}"
        for i, r in enumerate(results)
    )
    prompt = f'Entity searched: "{entity_name}"\n\nSearch results:\n{numbered}'
    return _classify(RELEVANCE_SYSTEM_PROMPT, prompt, EntityRelevance, log_tag="judge_entity_relevance", keys=keys)