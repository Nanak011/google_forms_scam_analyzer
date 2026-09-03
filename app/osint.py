import httpx

from app.config import settings

from urllib.parse import urlparse


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



# def check_urlscan(url: str) -> dict:
#     """Returns first-seen / page-identity signals for a domain, using
#     urlscan.io's search API (existing scan history, not a live re-scan —
#     instant, no wait)."""
#     if not settings.urlscan_api_key:
#         return {"new_domain": None, "scan_count": 0, "error": "no_api_key"}

#     domain = urlparse(url).netloc
#     if not domain:
#         return {"new_domain": None, "scan_count": 0, "error": "invalid_url"}

#     response = httpx.get(
#         "https://urlscan.io/api/v1/search/",
#         headers={"API-Key": settings.urlscan_api_key},
#         params={"q": f"domain:{domain}", "size": 10},
#         timeout=10,
#     )
#     response.raise_for_status()
#     data = response.json()
#     results = data.get("results", [])

#     if not results:
#         return {"new_domain": True, "scan_count": 0, "first_seen": None}

#     dates = [r["task"]["time"] for r in results if "task" in r and "time" in r["task"]]
#     earliest = min(dates) if dates else None
#     page_title = results[0].get("page", {}).get("title")

#     return {
#         "new_domain": False,
#         "scan_count": len(results),
#         "first_seen": earliest,
#         "page_title": page_title,
#     }

def check_urlscan(url: str) -> dict:
    """Returns whether a domain has any scan history on urlscan.io.
    Note: their search API only sorts newest-first with no ascending
    option, so a precise 'first ever seen' date isn't retrievable without
    paging through potentially thousands of results — not practical per
    request. Presence/absence of history and an approximate result count
    are the reliable signals available here.

    Fails soft: any network/timeout error returns a neutral result rather
    than crashing the caller, since this check runs off the main request
    path and one slow provider shouldn't block the others."""
    if not settings.urlscan_api_key:
        return {"has_history": None, "scan_count": 0, "error": "no_api_key"}

    domain = urlparse(url).netloc
    if not domain:
        return {"has_history": None, "scan_count": 0, "error": "invalid_url"}

    try:
        response = httpx.get(
            "https://urlscan.io/api/v1/search/",
            headers={"API-Key": settings.urlscan_api_key},
            params={"q": f"domain:{domain}", "size": 1},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        total = data.get("total", 0)
        return {"has_history": total > 0, "scan_count": total}
    except httpx.TimeoutException:
        return {"has_history": None, "scan_count": 0, "error": "timeout"}
    except httpx.HTTPError as e:
        return {"has_history": None, "scan_count": 0, "error": f"request_failed: {e}"}



from tavily import TavilyClient

tavily_client = TavilyClient(api_key=settings.tavily_api_key) if settings.tavily_api_key else None


def check_named_entity(entity_name: str) -> dict:
    """Runs a targeted search for a named person/org extracted by the LLM,
    looking for existing scam reports. Returns top result snippets so the
    caller can judge relevance — this does NOT itself decide scam/not-scam,
    since a hit could be a false positive (e.g. a real org impersonated by
    someone else)."""
    if not tavily_client:
        return {"query": None, "result_count": 0, "top_snippets": [], "error": "no_api_key"}

    query = f'"{entity_name}" scam OR fraud OR complaint'

    try:
        response = tavily_client.search(
            query=query,
            max_results=3,
            search_depth="basic",
        )
        results = response.get("results", [])
        snippets = [r.get("content", "")[:300] for r in results]
        return {"query": query, "result_count": len(results), "top_snippets": snippets}
    except Exception as e:
        return {"query": query, "result_count": 0, "top_snippets": [], "error": f"request_failed: {e}"}