# Google Forms Scam Analyzer

A Chrome extension + local backend that checks whether a Google Form is a scam - verdict with reasons.

FlyRank Backend Internship - "Your 10x Solution" capstone.

📄 Full problem statement, 10x claim, and concepts:
[My 10x Solution - Gurunanak Adhikari.md](./My%2010x%20Solution%20-%20Gurunanak%20Adhikari.md)
🛠 Full stage-by-stage build log: [development-guide.md](./development-guide.md)

## Quick start

### 1. Start the backend

You have two options - pick whichever you already have installed. Both end up running the exact same server on `http://localhost:8000`.

**Before either option:** make sure nothing else on your machine is already using port 8000 (a previous run you forgot to stop, another local project, etc.) - if `http://localhost:8000/health` shows something unexpected or the server fails to start, that's the most likely reason. Stop whatever's using it, or change `PORT` in `.env` and the port mapping in `docker-compose.yml` to something else, like `8001`.

**Option A - Docker (recommended, no Python setup needed)**

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed. **Open the Docker Desktop app first and make sure it's running** - the `docker compose` command below will fail with a connection error if Docker Desktop isn't actually open in the background, even if it's installed.

```bash
git clone https://github.com/Nanak011/google_forms_scam_analyzer
cd google_forms_scam_analyzer
cp .env.example .env
docker compose up --build
```

**Option B - Python directly (no Docker)**

Requires Python 3.11+ installed.

```bash
git clone https://github.com/Nanak011/google_forms_scam_analyzer
cd google_forms_scam_analyzer
python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m app.main
```

The `venv` step creates an isolated Python environment just for this project's dependencies, so they don't clash with anything else Python-related on your machine - standard practice, not optional, if you're going the non-Docker route. You'll need to run the `venv\Scripts\activate` line again each time you open a new terminal to work on this.

**Either way, confirm it's running:** open `http://localhost:8000/health` in a browser - should show `{"status":"ok"}`.

### 2. Load the extension

- Go to `chrome://extensions`, enable **Developer mode** (top-right toggle)
- Click **Load unpacked**, select the `extension/` folder from this repo

### 3. Add your API key

- Click the extension icon in Chrome's toolbar → **API key settings**
- Paste a free **Gemini** or **Groq** key (required for classification) - [Gemini](https://aistudio.google.com/apikey) / [Groq](https://console.groq.com/keys), 
- Optional, for full reputation-check coverage: [Safe Browsing](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com), [VirusTotal](https://www.virustotal.com/gui/join-us), [urlscan.io](https://urlscan.io/user/signup), [Tavily](https://tavily.com). Skipping any of these just means that specific check is skipped; classification still works fully without them.
- Click Save

### 4. Try it

Open one of the demo forms below, click the extension icon, click **Scan this form**.

## Demo forms

| Form | Expected result |
|---|---|
| [Discord Nitro Subscription Giveaway](https://docs.google.com/forms/d/e/1FAIpQLSdaatu-fMV7do9RCzyNl83ibaTEFUqmVWs5LjrJLuLg5SoH_Q/viewform) | **SCAM** - urgency, too-good-to-be-true, requests sensitive info, two embedded links flagged by VirusTotal |
| [User Perception Study on Virtual Laboratory Learning Systems](https://docs.google.com/forms/d/e/1FAIpQLSfd8kwEt01GcyClLpsjK5jGpgxtBN8aQPlJ26OfH8ifcSKIRQ/viewform?usp=publish-editor) | **LEGIT** - routine academic survey, no red flags |

⚠️ The Discord Nitro demo form contains two real phishing URLs (sourced from PhishTank, already public) as answer choices, used to test the link-reputation checks. Don't click them - just scan the form.

## The 10x claim - honestly measured

For a technically-aware person, manually skimming a form for obvious red flags takes well under a minute. This tool isn't claiming to out-race that fast human judgment - what it actually replaces is the **step people skip**: most people don't reliably check embedded links or search a mentioned name before filling in a form, even when they're capable of it, because it's mildly effortful and easy to forget under time pressure. 
This tool automates that check every time, in about 10 seconds, with zero effort aftr setup - link reputation, named-entity search, and wording analysis, done consistently instead of only when someone happens to remember to be
careful. The value isn't raw speed alone - it's making a good habit effortless enough to actually happen every time.

## Concepts implemented

| Concept | Where it lives |
|---|---|
| API endpoints | `app/main.py` - `POST /analyze`, `GET /analyze/{hash}`, `GET /health` |
| Database | `app/db.py` - SQLAlchemy `scans` + `rate_limits` tables, SQLite |
| LLM integration | `app/llm.py` - Groq primary / Gemini fallback, structured JSON output, cost logged per call |
| Caching | Content-hash lookup, `app/main.py` |
| Background jobs | `app/main.py` - OSINT (Safe Browsing, VirusTotal, urlscan.io, Tavily) runs async via FastAPI `BackgroundTasks`, after the fast LLM-only response |

## Limitations

This is a heuristic tool - pattern-matching on wording plus reputation lookups - not a trained classifier validated against a labeled scam dataset. It flags common, recognizable scam patterns; it won't catch everything, and it can occasionally misjudge unfamiliar wording. OSINT checks are only as good as free-tier API coverage and can miss very new or short-lived scams that haven't been reported anywhere yet. Confidence scores can vary somewhat between runs of the same form. Treat the verdict as a strong signal to look closer, not a guarantee.