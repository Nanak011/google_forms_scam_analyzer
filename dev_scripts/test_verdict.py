from app.llm import LLMAnalysis
from app.verdict import combine_signals

print("=== Case 1: LLM uncertain wording, but OSINT flags the link hard ===")
analysis = LLMAnalysis(
    tactics_detected=[],
    named_entities=[],
    summary="Wording seems mostly neutral.",
    llm_confidence=0.4,
)
osint = {
    "safe_browsing": {"flagged": True, "threat_types": ["SOCIAL_ENGINEERING"]},
    "virustotal": {"flagged": False, "malicious_count": 0, "total_engines": 91},
    "urlscan": {"has_history": True, "scan_count": 50},
    "named_entity_checks": {},
}
print(combine_signals(analysis, osint))

print("\n=== Case 2: LLM confident it's a scam, OSINT clean (link itself not yet blacklisted) ===")
analysis = LLMAnalysis(
    tactics_detected=["urgency", "too_good_to_be_true", "requests_sensitive_info"],
    named_entities=["Acme Bank Support"],
    summary="Classic prize scam wording with urgency and sensitive info requests.",
    llm_confidence=0.9,
)
osint = {
    "safe_browsing": {"flagged": False, "threat_types": []},
    "virustotal": {"flagged": False, "malicious_count": 0, "total_engines": 91},
    "urlscan": {"has_history": False, "scan_count": 0},
    "named_entity_checks": {
        "Acme Bank Support": {"result_count": 2, "top_snippets": ["reported scam"]}
    },
}
print(combine_signals(analysis, osint))

print("\n=== Case 3: everything genuinely clean ===")
analysis = LLMAnalysis(
    tactics_detected=[],
    named_entities=[],
    summary="Routine course feedback survey, no suspicious language.",
    llm_confidence=0.05,
)
osint = {
    "safe_browsing": {"flagged": False, "threat_types": []},
    "virustotal": {"flagged": False, "malicious_count": 0, "total_engines": 91},
    "urlscan": {"has_history": True, "scan_count": 500},
    "named_entity_checks": {},
}
print(combine_signals(analysis, osint))