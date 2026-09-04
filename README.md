# Google Forms Scam Analyzer

A Chrome extension + local backend that checks whether a Google Form you've is a scam before you fill it in.

FlyRank Backend Internship - "Your 10x Solution" capstone.

📄 Full problem statement, 10x claim, and concepts:
[My 10x Solution - Gurunanak Surname.md](./My%2010x%20Solution%20-%20Gurunanak%20Adhikari.md)

## Concepts:

| Concept | Where |
|---|---|
| API endpoints | `app/main.py` - `POST /analyze`, `GET /health`, request/response validated via Pydantic |
| Database | `app/db.py` - SQLAlchemy `scans` table, SQLite locally |
| LLM integration | `app/llm.py` - Groq (`openai/gpt-oss-120b`) primary, Gemini 3.6 Flash fallback (15s timeout) on failure, structured JSON via schema + regex safety net, cost logged per provider to `logs/llm_cost_log.jsonl` |
| Caching | `app/main.py` - content-hash lookup in `scans` table before recomputing |
| Background jobs | *(planned)* |

## M2 Stage 1
## Setup

```bash
python -m venv .venv
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

## M2 stage 4
Made Dockerfile, dockercompose.yml, and dockerignore.

### Run with Docker (recommended)
Run Docker Desktop
```bash
docker compose up --build
```
Visit `http://localhost:8000/health`. 

Same results as M2 Stage 3

## M2 Stage 5
SQLAlchemy scans table, added test_db and check-db to add a dummy row to the table and check the total rows. 
```bash
python test_db.py
```
Should return Inserted row: 1 uncertain 0.5 2026-09-02 10:34:50.629664

``` bash
python check_db.py
```
Should return Total rows: 1

## M2 Stage 6
> **Note:** CORS is currently open (`*`) for local development. This will be locked to the extension's specific origin before publishing.

Added CORS middleware in main.py
Verify nothing broke after, run:
``` bash
python -m app.main
```
Visit http://localhost:8000/health - should still return {"status":"ok"}.

## M2 Stage 7
/analyze endpoint with dummy verdict:
Complete body request with required fields responds with 200 response body.
Incomplete request sends 422 response.

## M2 Stage 8
Wired the DB and /analyze together. 
Request comes in → check cache → if new, "compute" a verdict → store it → return it. 
Dummy logic for now (no real LLM/OSINT), but the shape of caching becomes real.


`compute_content_hash` deliberately hashes only title, description, and questions, and excludes form_url on purpose so that the same form scanned from two different links still hits the cache, since it's the same scam content either way. 

Delete the previous dev.db,
Run ``` python -m app.main ```

Test the cache-miss cache-hit cycle. 
Go to http://localhost:8000/docs and POST the same body below twice:
{
  "form_url": "https://forms.google.com/example",
  "title": "You've won a $500 gift card!",
  "description": "Click here to claim your prize before it expires",
  "questions": ["Full name", "Bank account number", "SSN"]
}

First call → expect "cached": false
Second call, identical body → expect "cached": true
Third call, change the form_url, identical body → expect "cached": true
Fourth call, change the title with other content same → expect "cached": false

## M3 Stage 1 - confirm Gemini API key + gemini-3.6-flash working
LLM provider smoke test

Confirmed API access works before wiring anything into the real pipeline.
Added `GEMINI_API_KEY` and `GROQ_API_KEY` to `.env` (get free keys at
https://aistudio.google.com/apikey and https://console.groq.com/keys )

```bash
python test_llm.py
```
Should print a short one-word response, confirming the Gemini key and SDK work.

## M3 Stage 2 - LLM integration- tactic classification + entity extraction

Built `app/llm.py`: structured JSON output via Pydantic schema, narrow single-purpose prompt (classify scam tactics, extract named entities, one-sentence summary, confidence score), cost logged per call to
`logs/llm_cost_log.jsonl`.

**Provider order:** Groq (`openai/gpt-oss-120b`) primary, Gemini 3.6 Flash fallback (15s timeout) if Groq fails. This is the reverse of the original plan (Gemini primary) - during development, Gemini's free tier returned frequent `503 UNAVAILABLE` errors under load, sometimes taking minutes to fail, so Groq was moved to primary for reliability. Gemini remains as a genuine fallback, not dead code.

```bash
python test_llm_classify.py
```
Should print two JSON results: a scammy example with several
`tactics_detected` and high `llm_confidence`, and a legit example with an empty `tactics_detected` list and low `llm_confidence`. Check the cost log:
```bash
type logs\llm_cost_log.jsonl
```

## M3 Stage 3 - wire classify_form into /analyze, replacing dummy verdict

Replaced the dummy verdict in `POST /analyze` with a real call to `classify_form`. Added `verdict_from_confidence`: LLM confidence ≥ 0.7 → `"scam"`, ≤ 0.3 → `"legit"`, otherwise `"uncertain"` (thresholds are a starting point, not tuned against real data yet). Cached responses now also return `named_entities`, not just the verdict.

Delete `dev.db` for a clean test, run the server, POST a scammy example 

{
  "form_url": "string",
  "title": "You've won a $500 gift card!",
  "description": "Click here to claim your prize before it expires tonight",
  "questions": ["Full name", "Bank account number", "SSN"]
}

via `/docs` twice - first call returns a real verdict with actual reasons from the LLM and `"cached": false`; second call returns the same result with `"cached": true`.


## M3 Stage 4 - Background jobs: OSINT integration (part 1 - Google Safe Browsing)

Built `app/osint.py`: reputation checks run separately from the LLM classification, combining into one signal set (background jobs concept - external API latency varies, so these run off the main synchronous path).

Get a free Safe Browsing API key from https://console.cloud.google.com/, enable "Safe Browsing API" from the API Library, create an API key and add it to the environment variable. 

**Scope:** four OSINT checks total, matching the original one-pager:
- Google Safe Browsing (URL/domain threat lists)
- VirusTotal (aggregated reputation across 70+ security vendors)
- urlscan.io (domain first-seen date, page identity)
- Google Custom Search (targeted queries on the LLM-extracted named entities, e.g. `"Acme Bank Support" scam`). 

This stage covers the first of the four.

Tested against Google's official Safe Browsing test URLs (designed to deliberately trigger known threat-type matches, so no real malicious URL is needed for testing):

```bash
python test_osint.py
```
Should return `{"flagged": True, "threat_types": ["MALWARE"]}` for the
known-bad test URL, and `{"flagged": False, "threat_types": []}` for a
known-clean URL.

## M3 Stage 5 - Background jobs: OSINT integration (part 2 - VirusTotal)

Get a free API key at https://www.virustotal.com/gui/join-us and add to .env

Added `check_virustotal` to `app/osint.py` - queries VirusTotal's aggregated reputation across 90+ security vendors. If a URL hasn't been analyzed before, submits it for analysis and returns a neutral result rather than a false negative (`"not_yet_analyzed"`).

Tested against a known-clean URL and the industry-standard EICAR test URL (a harmless file specifically designed to trigger antivirus detections, used instead of a real malicious sample):

```bash
python test_osint.py
```
Should return `{"flagged": False, ...}` for the clean URL and `{"flagged": True, "malicious_count": >0, ...}` for the EICAR URL.


## M3 Stage 6 - Background jobs: OSINT integration (part 3 - urlscan.io)

Get a free API key at https://urlscan.io/user/signup, add to .env

Added `check_urlscan` to `app/osint.py` - checks whether a domain has existing scan history via urlscan.io's search API.

Note: originally attempted to compute a domain's first-seen date, but discovered urlscan's search API only sorts results newest-first with no ascending option - computing "first seen" would require paging back through potentially thousands of results, impractical per request. Scope adjusted to "has scan history" + approximate count instead, which the API supports reliably.

Fails soft on timeout/network errors - returns a neutral result rather than crashing, since this runs off the main request path and one slow provider shouldn't block the others. Verified against both a fast query (rare domain, succeeds) and a slow one (google.com, times out under load, handled gracefully - proves the fail-soft path, not just the happy path).

```bash
python test_osint.py
```


## M3 Stage 7 - Background jobs: OSINT integration (part 4 - named-entity search)

Originally planned as Google Custom Search JSON API. Discovered Google has restricted this API to existing customers only - new Programmable Search Engine projects receive a 403 regardless of correct configuration (confirmed via community reports, not a local misconfiguration). Swapped to Tavily - a search API purpose-built for this exact pattern (query in, ranked web snippets out), genuine free tier, no card required. Same function signature and role in the pipeline, different provider.

`check_named_entity` takes a name/org extracted by the LLM and searches for `"{name}" scam OR fraud OR complaint`, returning top result snippets as raw evidence - it does not itself decide scam/not-scam, since a search hit could be a false positive (e.g. a real org impersonated by someone else). That judgment happens when signals are combined.

```bash
python test_osint.py
```
Should return real snippets for a known scam-adjacent phrase, and unrelated (non-scam) content for a genuine institution name - confirming it doesn't false-positive on any searchable name.


## M3 Stage 8 - Background jobs: combine OSINT checks concurrently

Added `run_osint_checks` to `app/osint.py` - runs Safe Browsing, VirusTotal, urlscan.io, and Tavily entity checks concurrently via `ThreadPoolExecutor` rather than sequentially. Each check already fails soft internally, so one slow/broken provider degrades that signal without blocking the others. Entity checks capped at 3 named entities per scan to protect free-tier quota.

```bash
python test_osint.py
```
Combined check against a real URL completed in ~2s - confirms checks run in parallel (urlscan alone can take several seconds against high-traffic domains; serial execution would show the sum of all four).


## M3 Stage 9 - Combine LLM + OSINT signals into final verdict

Added `app/verdict.py` - `combine_signals` takes the LLM's wording-based analysis and the OSINT reputation results, and produces one final verdict/confidence/reasons output. LLM confidence is the baseline (it reads the actual scam tactics in the text); OSINT signals push confidence up when independent evidence agrees, with every adjustment logged as a visible, human-readable reason - nothing is silently overridden.

```bash
python test_verdict.py
```
Three scenarios tested: OSINT correcting an uncertain LLM read into a confident scam verdict (link independently flagged by Safe Browsing), multiple corroborating signals stacking to high confidence, and a clean case staying untouched.

## M3 Stage 10 - Full pipeline: async background jobs + combined verdict

Rewired `/analyze` into the real architecture from the original one-pager:
LLM classification runs synchronously (the part the user waits on, a few seconds), returns a verdict immediately with `status: "pending_osint"`.
OSINT checks (`run_osint_checks`) run as a genuine FastAPI `BackgroundTasks` job *after* the response is already sent — not just concurrent within the request, actually decoupled from it. Once OSINT finishes, the scan's DB row is updated with the combined verdict and `status: "complete"`.

Added `GET /analyze/{content_hash}` for the client to poll for the updated result. Cache logic now returns whatever the *current* state of a scan is (pending or complete) rather than forcing a redo.

DB schema updated: `Scan` now stores `form_url`, `status`, raw `llm_signals` (needed to re-run `combine_signals` once OSINT lands), and `osint_signals`, alongside the existing verdict/confidence/reasons.

Tested: POST returns fast with `pending_osint`; polling GET a few seconds later returns `complete` with OSINT-adjusted confidence/reasons; a repeat POST with identical content returns instantly from cache regardless of processing state.


## M3 Stage 11 - Chrome extension: skeleton

Created `extension/` - Manifest V3, minimal permissions (`activeTab`, `storage` only - no broad `<all_urls>` access), `host_permissions` scoped to `localhost:8000` for now (updated to the deployed URL when hosted).

### Run the extension (dev)

1. Start the backend first (see Setup above - `docker compose up` or `python -m app.main`).
2. Go to `chrome://extensions`, enable **Developer mode**.
3. Click **Load unpacked**, select the `extension/` folder.

Verified: extension loads with no errors, popup opens, background service worker starts cleanly (checked via each console).


## M3 Stage 12 - Chrome extension: content script (form extraction)

Added `extension/content.js` - reads a live Google Form's title, description, and questions. Deliberately does NOT rely on Google's CSS classes (auto-generated, minified, unstable across builds). Instead reads:
- `<meta itemprop="name">` / `<meta itemprop="description">` (schema.org, standard on every Form)
- `FB_PUBLIC_LOAD_DATA_` - the JS data array Google's own frontend uses to render the form, present on every Google Form page

Verified on a real form (not written for this specific form): correctly extracted title, description, form_url, and all question text via the page's own DevTools console.




## M3 Stage 13 - End-to-end wiring: popup ↔ backend, live results

Connected the popup to the backend for real, replacing manual `/docs` testing entirely:

- `popup.js` reads the active tab's form via the content script, POSTs to `/analyze`, and renders the verdict.
- **Live polling**: since `/analyze` returns fast (LLM-only) while OSINT runs as a true background job, the popup polls `GET /analyze/{hash}` every ~2.5s until `status: "complete"`, so the verdict visibly refines instead of the user having to guess or reopen manually.
- **State persistence**: the popup remembers the last-scanned content hash per form URL (`chrome.storage.local`) and checks current status immediately on open - closing the popup mid-scan no longer loses progress, since the backend keeps working regardless.
- **Force-rescan**: a `force` flag bypasses the cache for testing, since identical content otherwise correctly returns the cached result.

### Embedded link checking (architecture fix)

Originally only the Google Form's own URL was reputation-checked - always `docs.google.com`, one of the most trusted domains on the internet, so this was structurally close to useless as a signal. Now `extract_urls()` pulls any URLs mentioned in the form's title/description/questions (e.g. an embedded "verify here" or payment link) and runs Safe Browsing + VirusTotal + urlscan.io against those instead.

### Entity relevance: false positives + transparency

Found and fixed real false positives: 
generic/trusted terms ("Google", "Google Classroom", "Moodle", "HCI") were being flagged as scam-linked purely from coincidental keyword co-occurrence in search results.
Fixed by: 
(1) excluding well-known trusted platforms from entity extraction in the LLM prompt, 
(2) requiring the relevance-judging LLM call to quote an exact supporting sentence + source URL before it's allowed mark something relevant - no evidence, no flag. 
The popup now displays that quoted evidence directly under any flagged entity, so a verdict is never just "trust me."

### Bug fixes

- A 4th+ named entity (beyond the 3-per-scan cap) previously showed "pending" forever, indistinguishable from a genuinely stuck check. Now correctly labeled "Not checked (limit reached)".
- The background job previously had no top-level error handling - if entity-relevance calls failed (e.g. rate limits), the whole job died silently and the scan stayed stuck in `pending_osint` permanently. Now wrapped so a scan always reaches a final state, degrading gracefully if some part of OSINT fails.

Verified against multiple real (non-test) Google Forms filled previously, confirming: legitimate forms return low confidence with no false flags, an embedded link in a real form gets checked independently of the form's own URL, and rescanning after a fix actually reflects the new result instead of the stale cache.


## M3 Stage 14 - BYOK: per-user API keys, no shared server secrets

Backend no longer relies solely on server-side `.env` keys for real usage. Every LLM/OSINT function now accepts an optional per-request key, resolved in this order: 
header-supplied key (from the extension) → `.env` fallback (local dev convenience only, never required).

- Added `extension/options.html` / `options.js` - a settings page where the user pastes their own free API keys (Gemini/Groq required for classification; Safe Browsing, VirusTotal, urlscan.io, Tavily optional and additive). Keys are stored only in `chrome.storage.local` - never sent anywhere except as request headers to the user's own locally-run backend, never persisted server-side, never logged.
- `app/keys.py` - `BYOKKeys` model carrying the six possible keys through the request → background job pipeline.
- Missing optional OSINT keys degrade gracefully: that specific check is skipped (shown in the popup as "Skipped - no key set"), classification still runs normally. Only an LLM key (Gemini or Groq) is actually required.
- Missing/invalid LLM key returns a proper `400` with a real explanation ("No LLM API key found. Add your Gemini or Groq API key in the extension's settings.") instead of an opaque `500`.

Tested: blanked `.env`'s LLM keys entirely, confirmed scanning fails with the correct message; added keys via the options page, confirmed scanning works purely from BYOK with no server-side keys involved at all.


## M3 Stage 15 - Reduce LLM Score Variance

- LLM calls now use `temperature=0` to reduce (not eliminate - LLM APIs don't guarantee full determinism even at temp 0) run-to-run confidence variance on identical input.

Still not perfect and subject to future enhancement.


## M3 Stage 16 - Rate limiting on shared server keys

Added `app/ratelimit.py` - a simple per-IP daily counter (SQLite-backed, same DB as everything else) protecting the LLM calls that fall back to the server's own `.env` keys once deployed. Only active when `ENABLE_RATE_LIMIT=true` (left `false` for local dev - no limit while testing locally).

Anyone who supplies their own Gemini or Groq key in the extension's settings bypasses the limit entirely, since they're spending their own quota, not the server's. Exceeding the free limit returns a `429` with a clear message pointing the user to add their own key.

**Known limitation, documented:** the limiter currently only gates LLM calls. OSINT checks (Safe Browsing, VirusTotal, urlscan.io, Tavily) still fall back to server keys for every request regardless of LLM-key status, protected only by each provider's own free-tier caps (Safe Browsing ~10k/day, VirusTotal ~500/day, etc.), not by this application's own limiter. Addressed in the next stage.







