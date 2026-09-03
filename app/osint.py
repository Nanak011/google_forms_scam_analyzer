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

def check_virustotal(url: str) -> dict:
    """Returns {'flagged': bool, 'malicious_count': int, 'total_engines': int}"""
    if not settings.virustotal_api_key:
        return {"flagged": False, "malicious_count": 0, "total_engines": 0, "error": "no_api_key"}

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    response = httpx.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=10,
    )

    if response.status_code == 404:
        httpx.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": settings.virustotal_api_key},
            data={"url": url},
            timeout=10,
        )
        return {"flagged": False, "malicious_count": 0, "total_engines": 0, "note": "not_yet_analyzed"}

    response.raise_for_status()
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    return {"flagged": malicious > 0, "malicious_count": malicious, "total_engines": total}