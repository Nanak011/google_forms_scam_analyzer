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