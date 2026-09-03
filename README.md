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
