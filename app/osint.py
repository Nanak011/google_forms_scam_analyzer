import httpx

from app.config import settings

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(url: str) -> dict:
    """Returns {'flagged': bool, 'threat_types': list[str]}"""
    if not settings.google_safe_browsing_api_key:
        return {"flagged": False, "threat_types": [], "error": "no_api_key"}

    payload = {
        "client": {"clientId": "google-forms-scam-analyzer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    response = httpx.post(
        SAFE_BROWSING_URL,
        params={"key": settings.google_safe_browsing_api_key},
        json=payload,
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()

    matches = data.get("matches", [])
    threat_types = [m["threatType"] for m in matches]
    return {"flagged": len(matches) > 0, "threat_types": threat_types}