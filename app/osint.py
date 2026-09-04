import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
from tavily import TavilyClient

from app.config import settings
from app.keys import BYOKKeys

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+')


def extract_urls(*texts: str) -> list[str]:
    urls = set()
    for text in texts:
        if not text:
            continue
        for match in URL_REGEX.findall(text):
            urls.add(match.rstrip(".,;)"))
    return list(urls)


# def _resolve(byok_value: str | None, dev_fallback: str | None) -> str | None:
#     return byok_value or dev_fallback


def _resolve(byok_value: str | None, dev_fallback: str | None, allow_server_fallback: bool = True) -> str | None:
    if byok_value:
        return byok_value
    if allow_server_fallback:
        return dev_fallback
    return None



def check_safe_browsing(url: str, api_key: str | None = None, allow_server_fallback: bool = True) -> dict:
    key = _resolve(api_key, settings.google_safe_browsing_api_key, allow_server_fallback)
    if not key:
        return {"flagged": False, "threat_types": [], "error": "no_api_key"}

    payload = {
        "client": {"clientId": "google-forms-scam-analyzer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = httpx.post(SAFE_BROWSING_URL, params={"key": key}, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])
        return {"flagged": len(matches) > 0, "threat_types": [m["threatType"] for m in matches]}
    except Exception as e:
        return {"flagged": False, "threat_types": [], "error": f"request_failed: {e}"}



def check_virustotal(url: str, api_key: str | None = None, allow_server_fallback: bool = True) -> dict:
    key = _resolve(api_key, settings.virustotal_api_key, allow_server_fallback)
    if not key:
        return {"flagged": False, "malicious_count": 0, "total_engines": 0, "error": "no_api_key"}

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": key}, timeout=10,
        )
        if response.status_code == 404:
            httpx.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": key}, data={"url": url}, timeout=10,
            )
            return {"flagged": False, "malicious_count": 0, "total_engines": 0, "note": "not_yet_analyzed"}

        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        return {"flagged": malicious > 0, "malicious_count": malicious, "total_engines": sum(stats.values())}
    except Exception as e:
        return {"flagged": False, "malicious_count": 0, "total_engines": 0, "error": f"request_failed: {e}"}



def check_urlscan(url: str, api_key: str | None = None, allow_server_fallback: bool = True) -> dict:
    key = _resolve(api_key, settings.urlscan_api_key, allow_server_fallback)
    if not key:
        return {"has_history": None, "scan_count": 0, "error": "no_api_key"}

    domain = urlparse(url).netloc
    if not domain:
        return {"has_history": None, "scan_count": 0, "error": "invalid_url"}

    try:
        response = httpx.get(
            "https://urlscan.io/api/v1/search/",
            headers={"API-Key": key}, params={"q": f"domain:{domain}", "size": 1}, timeout=20,
        )
        response.raise_for_status()
        total = response.json().get("total", 0)
        return {"has_history": total > 0, "scan_count": total}
    except httpx.TimeoutException:
        return {"has_history": None, "scan_count": 0, "error": "timeout"}
    except Exception as e:
        return {"has_history": None, "scan_count": 0, "error": f"request_failed: {e}"}



def check_named_entity(entity_name: str, api_key: str | None = None, allow_server_fallback: bool = True) -> dict:
    key = _resolve(api_key, settings.tavily_api_key, allow_server_fallback)
    if not key:
        return {"query": None, "result_count": 0, "top_results": [], "error": "no_api_key"}

    query = f'"{entity_name}" scam OR fraud OR complaint'
    try:
        client = TavilyClient(api_key=key)
        response = client.search(query=query, max_results=3, search_depth="basic")
        results = response.get("results", [])
        top_results = [{"snippet": r.get("content", "")[:400], "url": r.get("url", "")} for r in results]
        return {"query": query, "result_count": len(results), "top_results": top_results}
    except Exception as e:
        return {"query": query, "result_count": 0, "top_results": [], "error": f"request_failed: {e}"}



def run_osint_checks(url: str, named_entities: list[str], embedded_urls: list[str] | None = None, keys: BYOKKeys | None = None, allow_server_fallback: bool = True) -> dict:
    keys = keys or BYOKKeys()
    embedded_urls = (embedded_urls or [])[:3]
    checked_entities = named_entities[:3]
    skipped_entities = named_entities[3:]
    results = {}

    with ThreadPoolExecutor(max_workers=8) as pool:
        form_url_futures = {
            pool.submit(check_safe_browsing, url, keys.safe_browsing_api_key, allow_server_fallback): "safe_browsing",
            pool.submit(check_virustotal, url, keys.virustotal_api_key, allow_server_fallback): "virustotal",
            pool.submit(check_urlscan, url, keys.urlscan_api_key, allow_server_fallback): "urlscan",
        }
        entity_futures = {
            pool.submit(check_named_entity, name, keys.tavily_api_key, allow_server_fallback): name
            for name in checked_entities
        }
        embedded_futures = {}
        for u in embedded_urls:
            embedded_futures[pool.submit(check_safe_browsing, u, keys.safe_browsing_api_key, allow_server_fallback)] = (u, "safe_browsing")
            embedded_futures[pool.submit(check_virustotal, u, keys.virustotal_api_key, allow_server_fallback)] = (u, "virustotal")
            embedded_futures[pool.submit(check_urlscan, u, keys.urlscan_api_key, allow_server_fallback)] = (u, "urlscan")

        for future in as_completed(form_url_futures):
            check_name = form_url_futures[future]
            try:
                results[check_name] = future.result()
            except Exception as e:
                results[check_name] = {"error": f"unexpected_failure: {e}"}

        entity_results = {}
        for future in as_completed(entity_futures):
            name = entity_futures[future]
            try:
                entity_results[name] = future.result()
            except Exception as e:
                entity_results[name] = {"error": f"unexpected_failure: {e}"}
        results["named_entity_checks"] = entity_results
        results["named_entity_checks_skipped"] = skipped_entities

        embedded_results = {}
        for future in as_completed(embedded_futures):
            u, check_name = embedded_futures[future]
            embedded_results.setdefault(u, {})
            try:
                embedded_results[u][check_name] = future.result()
            except Exception as e:
                embedded_results[u][check_name] = {"error": f"unexpected_failure: {e}"}
        results["embedded_link_checks"] = embedded_results

    return results