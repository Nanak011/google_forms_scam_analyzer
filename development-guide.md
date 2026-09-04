# Development Guide - build log

This is the stage-by-stage build history of this project (M2 → M4), kept as evidence of process and reasoning. For how to actually run the app, see [README.md](./README.md).

## Concepts:

| Concept | Where |
|---|---|
| API endpoints | `app/main.py` - `POST /analyze`, `GET /analyze/{hash}`, `GET /health`, request/response validated via Pydantic |
| Database | `app/db.py` - SQLAlchemy `scans` + `rate_limits` tables, SQLite locally |
| LLM integration | `app/llm.py` - Groq (`openai/gpt-oss-120b`) primary, Gemini 3.6 Flash fallback on failure, structured JSON via schema, cost logged per provider to `logs/llm_cost_log.jsonl` |
| Caching | `app/main.py` - content-hash lookup in `scans` table before recomputing |
| Background jobs | `app/main.py` - OSINT checks run as a true FastAPI `BackgroundTasks` job after the fast LLM-only response |

## M2 Stage 1 - Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## M2 Stage 2
Copy `.env.example` to `.env` and fill in your own API keys if you want to test LLM/OSINT calls locally (optional - real usage is BYOK via the extension, not this file).

## M2 Stage 3
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Visit `http://localhost:8000/health` - should return `{"status":"ok"}`.
Interactive API docs at `http://localhost:8000/docs`.

## M2 Stage 3b
added settings.port in main.py
```bash
python -m app.main
```
Should show same result as M2 Stage 3.

## M2 Stage 4
Made Dockerfile, docker-compose.yml, and .dockerignore.

### Run with Docker
Start Docker Desktop first, then:
```bash
docker compose up --build
```
Visit `http://localhost:8000/health`.

Same results as M2 Stage 3.

## M2 Stage 5
SQLAlchemy scans table, added test_db and check_db to add a dummy row to the table and check the total rows.
```bash
python dev_scripts/test_db.py
```
Should return `Inserted row: 1 uncertain 0.5 2026-09-02 10:34:50.629664`

```bash
python dev_scripts/check_db.py
```
Should return `Total rows: 1`

## M2 Stage 6
> **Note:** CORS is currently open (`*`) for local development. This will be locked to the extension's specific origin before publishing.

Added CORS middleware in main.py.
Verify nothing broke:
```bash
python -m app.main
```
Visit `http://localhost:8000/health` - should still return `{"status":"ok"}`.

## M2 Stage 7
`/analyze` endpoint with dummy verdict:
Complete body request with required fields responds with a 200 response body.
Incomplete request sends a 422 response.

## M2 Stage 8
Wired the DB and `/analyze` together.
Request comes in → check cache → if new, "compute" a verdict → store it → return it.
Dummy logic at this stage (no real LLM/OSINT yet), but the shape of caching becomes real.

`compute_content_hash` deliberately hashes only title, description, and questions, and excludes `form_url` on purpose so that the same form scanned from two different links still hits the cache, since it's the same scam content either way.

Delete the previous `dev.db`, run `python -m app.main`.

Test the cache-miss/cache-hit cycle via `http://localhost:8000/docs`, POSTing:
```json
{
  "form_url": "https://forms.google.com/example",
  "title": "You've won a $500 gift card!",
  "description": "Click here to claim your prize before it expires",
  "questions": ["Full name", "Bank account number", "SSN"]
}
```
First call → `"cached": false`. Second call, identical body → `"cached": true`. Third call, changed `form_url`, identical content → `"cached": true`. Fourth call, changed title → `"cached": false`.

## M3 Stage 1 - confirm Gemini API key + gemini-3.6-flash working

Confirmed API access works before wiring anything into the real pipeline. Added `GEMINI_API_KEY` and `GROQ_API_KEY` to `.env` (free keys: https://aistudio.google.com/apikey, https://console.groq.com/keys).

```bash
python dev_scripts/test_llm.py
```
Should print a short one-word response, confirming the Gemini key and SDK work.

## M3 Stage 2 - LLM integration: tactic classification + entity extraction

Built `app/llm.py`: structured JSON output via Pydantic schema, narrow single-purpose prompt (classify scam tactics, extract named entities, one-sentence summary, confidence score), cost logged per call to `logs/llm_cost_log.jsonl`.

**Provider order:** Groq (`openai/gpt-oss-120b`) primary, Gemini 3.6 Flash fallback (15s timeout) if Groq fails. This is the reverse of the original plan (Gemini primary) - during development, Gemini's free tier returned frequent `503 UNAVAILABLE` errors under load, sometimes taking minutes to fail, so Groq was moved to primary for reliability. Gemini remains a genuine fallback, not dead code.

```bash
python dev_scripts/test_llm_classify.py
```
Should print two JSON results: a scammy example with several `tactics_detected` and high `llm_confidence`, and a legit example with an empty `tactics_detected` list and low `llm_confidence`.

## M3 Stage 3 - wire classify_form into /analyze, replacing dummy verdict

Replaced the dummy verdict in `POST /analyze` with a real call to `classify_form`. Added `verdict_from_confidence`: LLM confidence ≥ 0.7 → `"scam"`, ≤ 0.3 → `"legit"`, otherwise `"uncertain"`. Cached responses now also return `named_entities`.

Delete `dev.db` for a clean test, run the server, POST a scammy example via `/docs` twice - first call returns a real verdict with `"cached": false`; second returns the same result with `"cached": true`.

## M3 Stage 4 - Background jobs: OSINT integration (part 1 - Google Safe Browsing)

Built `app/osint.py`: reputation checks run separately from LLM classification, combining into one signal set.

Get a free Safe Browsing API key at https://console.cloud.google.com/ (enable "Safe Browsing API" from the API Library).

**Scope:** four OSINT checks total - Google Safe Browsing, VirusTotal, urlscan.io, and (originally) Google Custom Search on extracted named entities. This stage covers the first.

Tested against Google's official Safe Browsing test URLs:
```bash
python dev_scripts/test_osint.py
```
Should return `{"flagged": True, "threat_types": ["MALWARE"]}` for the known-bad test URL, and `{"flagged": False, "threat_types": []}` for a known-clean URL.

## M3 Stage 5 - Background jobs: OSINT integration (part 2 - VirusTotal)

Free API key at https://www.virustotal.com/gui/join-us.

Added `check_virustotal` - queries aggregated reputation across 90+ security vendors. Unanalyzed URLs are submitted for analysis and return a neutral result rather than a false negative.

```bash
python dev_scripts/test_osint.py
```
Should return `{"flagged": False, ...}` for a clean URL and `{"flagged": True, "malicious_count": >0, ...}` for the EICAR test URL.

## M3 Stage 6 - Background jobs: OSINT integration (part 3 - urlscan.io)

Free API key at https://urlscan.io/user/signup.

Added `check_urlscan` - checks whether a domain has existing scan history.

Discovered urlscan's search API only sorts newest-first with no ascending option, so computing a true "first seen" date would require paging through potentially thousands of results - impractical per request. Scope adjusted to "has scan history + approximate count" instead.

Fails soft on timeout/network errors - verified against both a fast query (succeeds) and a slow one (google.com, times out under load, handled gracefully).

## M3 Stage 7 - Background jobs: OSINT integration (part 4 - named-entity search)

Originally planned as Google Custom Search JSON API. Discovered Google has restricted this API to existing customers only - new Programmable Search Engine projects get a 403 regardless of correct configuration. Swapped to Tavily, purpose-built for this exact pattern, genuine free tier, no card.

`check_named_entity` searches `"{name}" scam OR fraud OR complaint`, returning raw result snippets - it does not itself decide relevance; that judgment happens later.

## M3 Stage 8 - Background jobs: combine OSINT checks concurrently

Added `run_osint_checks` - runs all four OSINT checks via `ThreadPoolExecutor` rather than sequentially. Each check fails soft internally. Entity checks capped (later raised from 3 → 5 in Stage 18).

Combined check against a real URL completed in ~2s, confirming true parallelism.

## M3 Stage 9 - Combine LLM + OSINT signals into final verdict

Added `app/verdict.py` - `combine_signals` takes LLM analysis + OSINT results, produces one final verdict/confidence/reasons. LLM confidence is the baseline; strong OSINT signals (Safe Browsing/VirusTotal flags) raise the confidence floor via `max()`; weaker signals (no scan history, entity hit) nudge it additively. Every adjustment is logged as a visible reason.

## M3 Stage 10 - Full pipeline: async background jobs + combined verdict

Rewired `/analyze`: LLM classification runs synchronously (a few seconds), returns immediately with `status: "pending_osint"`. OSINT runs as a genuine FastAPI `BackgroundTasks` job *after* the response is sent - decoupled from the request, not just concurrent within it. Added `GET /analyze/{content_hash}` for polling.

DB schema updated: `Scan` now stores `form_url`, `status`, raw `llm_signals`, and `osint_signals`.

## M3 Stage 11 - Chrome extension: skeleton

Manifest V3, minimal permissions (`activeTab`, `storage` only), `host_permissions` scoped to `localhost:8000`.

## M3 Stage 12 - Chrome extension: content script (form extraction)

`extension/content.js` reads a live form's title/description/questions without relying on Google's unstable CSS classes - instead reads `<meta itemprop="name/description">` and `FB_PUBLIC_LOAD_DATA_`, both stable and present on every Google Form.

## M3 Stage 13 - End-to-end wiring: popup ↔ backend, live results

Connected popup to backend for real. Live polling every ~2.5s until OSINT completes. State persistence via `chrome.storage.local` so closing the popup mid-scan doesn't lose progress. Force-rescan flag for testing.

**Embedded link checking:** originally only the form's own URL (always `docs.google.com`, always trusted) was reputation-checked - close to useless as a signal. `extract_urls()` now pulls URLs mentioned in the form's text and checks those instead.

**Entity relevance fixes:** found real false positives (generic/trusted terms flagged from coincidental keyword co-occurrence). Fixed by excluding trusted platforms from entity extraction, and requiring the relevance-judging LLM call to quote exact evidence before flagging anything.

**Bug fixes:** 4th+ entities (beyond the cap) no longer show "pending" forever. Background job wrapped in error handling so a scan always reaches a final state.

## M3 Stage 14 - BYOK: per-user API keys, no shared server secrets

Every LLM/OSINT function accepts an optional per-request key: header-supplied (extension) → `.env` fallback (local dev only).

Added `extension/options.html`/`options.js` - settings page, keys stored only in `chrome.storage.local`, sent only as request headers, never persisted server-side. `app/keys.py` - `BYOKKeys` model. Missing optional keys degrade gracefully (that check is skipped). Missing LLM key returns a proper 400, not a 500.

## M3 Stage 15 - Reduce LLM score variance

`temperature=0` on both providers. Reduces but doesn't eliminate run-to-run variance - LLM APIs don't guarantee full determinism even at temp 0.

## M3 Stage 16 - Rate limiting on shared server keys

`app/ratelimit.py` - per-IP daily counter, active only when `ENABLE_RATE_LIMIT=true` (deploy-only, left `false` locally). Anyone with their own LLM key bypasses the limit. Exceeding it returns 429 with a clear message.

## M3 Stage 17 - Extend rate limit to OSINT server-key fallback

Stage 16 only gated LLM calls. Fixed: `allow_server_fallback` now flows through the whole OSINT pipeline - server-side OSINT keys are only available during a user's free trial (no own LLM key, under the cap). Once a user brings their own LLM key, server OSINT keys stop being available to them.

## M3 Stage 18 - Fix: embedded links in answer options weren't extracted

`content.js` only read question titles, not answer-choice text - so a scam link presented as a multiple-choice option (a real disguise pattern) was invisible to the backend. Fixed by also extracting option text. Verified against a form with two known-malicious links (PhishTank-sourced) as answer choices - both now correctly flagged.

Also raised the named-entity check cap from 3 to 5.