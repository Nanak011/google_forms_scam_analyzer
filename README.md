# Google Forms Scam Analyzer

A Chrome extension + local backend that checks whether a Google Form you've is a scam before you fill it in.

FlyRank Backend Internship - "Your 10x Solution" capstone.

📄 Full problem statement, 10x claim, and concepts:
[My 10x Solution - Gurunanak Surname.md](./My%2010x%20Solution%20-%20Gurunanak%20Adhikari.md)

## Concepts:

| Concept | Where |
|---|---|
| API endpoints | `app/main.py` - `/health` live, `/analyze` in progress |
| Database | *(in progress)* |
| LLM integration | *(planned)* |
| Caching | *(planned)* |
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
Should show same result as stage 3.

