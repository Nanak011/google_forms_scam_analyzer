from app.llm import LLMAnalysis


def combine_signals(analysis: LLMAnalysis, osint: dict) -> dict:
    """Combines LLM wording-based confidence with OSINT reputation signals
    into one final verdict. LLM confidence is the starting point (it reads
    the actual scam tactics in the text); OSINT signals push that number
    up when independent evidence agrees, but never silently override it -
    every adjustment is logged as a visible reason."""

    confidence = analysis.llm_confidence
    reasons: list[str] = list(analysis.tactics_detected)
    if analysis.summary:
        reasons.append(analysis.summary)

    safe_browsing = osint.get("safe_browsing", {})
    if safe_browsing.get("flagged"):
        threats = ", ".join(safe_browsing.get("threat_types", []))
        reasons.append(f"Link flagged by Google Safe Browsing: {threats}")
        confidence = max(confidence, 0.95)

    virustotal = osint.get("virustotal", {})
    if virustotal.get("flagged"):
        count = virustotal.get("malicious_count", 0)
        total = virustotal.get("total_engines", 0)
        reasons.append(f"Flagged malicious by {count}/{total} security vendors (VirusTotal)")
        confidence = max(confidence, 0.9)

    urlscan = osint.get("urlscan", {})
    if urlscan.get("has_history") is False:
        reasons.append("Domain has no prior scan history - newly seen or rarely visited")
        confidence = min(1.0, confidence + 0.1)

    entity_checks = osint.get("named_entity_checks", {})
    for entity_name, result in entity_checks.items():
        if result.get("result_count", 0) > 0 and not result.get("error"):
            reasons.append(f'"{entity_name}" appears in existing scam/fraud-related search results')
            confidence = min(1.0, confidence + 0.1)

    verdict = _verdict_from_confidence(confidence)

    return {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "reasons": reasons,
        "named_entities": analysis.named_entities,
    }


def _verdict_from_confidence(confidence: float) -> str:
    if confidence >= 0.7:
        return "scam"
    if confidence <= 0.3:
        return "legit"
    return "uncertain"