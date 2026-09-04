# My 10x Solution (M1)

## The problem

People regularly receive Google Form links via email, text, or social media — scholarship applications, "you've won a prize," job application requests, "verify your account" forms. Checking whether one is a scam means reading it carefully, manually searching the linked domain, and googling any names or organizations mentioned - a careful person spends several minutes doing this, and most people skip it entirely because it's tedious. That skipped step is exactly where scams succeed.

## Who has this problem

Anyone who receives an unsolicited Google Form link and has no quick way to sanity-check it before entering personal information - students, job seekers, people responding to "giveaway" or "survey reward" links, employees receiving fake internal-looking forms.

## The 10x claim

For a technically-aware person, manually skimming a form for obvious red flags takes well under a minute. This tool isn't claiming to be faster than fast human judgment - it replaces the step people actually skip: reliably checking embedded links and searching mentioned names before filling in a form, something most people are capable of but rarely bother with under time pressure. This tool does that check automatically, every time, in about 10 seconds - the value is consistency and convenience, not raw speed.

## The 5 concepts

| # | Concept | How it's implemented |
|---|---|---|
| 1 | **API endpoints** | `POST /analyze` accepts a form URL and its extracted content; returns a verdict with reasons |
| 2 | **Database** | Every scan (content hash, extracted signals, verdict, timestamp) is stored - this is what makes caching possible and survives a restart |
| 3 | **LLM integration** | One narrow job: given form title/description/questions, classify scam tactics present (urgency, too-good-to-be-true, request for sensitive info, generic/impersonal greeting), extract any named people/organizations mentioned, and return a structured JSON verdict with a confidence score — validated against a schema, cost logged per call |
| 4 | **Caching** | If a form's content hash has been scanned before, return the cached verdict instantly - no re-running the LLM or OSINT checks for a form seen twice |
| 5 | **Background jobs** | OSINT/reputation checks (Google Safe Browsing, VirusTotal, urlscan.io, and targeted Google Custom Search queries on any extracted names/orgs) run asynchronously off the main request path, since external API latency varies; the client polls or receives the combined verdict once the job completes |

`llm_confidence` represents the LLM's estimated probability the form is a scam, based on wording alone (0.0–1.0), not the model's certainty about its own answer. OSINT signals then adjust this baseline upward when independent evidence agrees. Scores can vary somewhat between runs of the same form, partly from LLM sampling and partly from which provider (Groq or Gemini) answers a given request, since they're different underlying models with different calibration.

## How I implemented it

**Architecture:** a Chrome extension (Manifest V3) reads a live Google Form's title, description, and questions directly from the page's own `FB_PUBLIC_LOAD_DATA_` (the data Google's own frontend uses to render the form) rather than fragile, auto-generated CSS selectors. It sends that to a locally-run FastAPI backend, which classifies the wording via an LLM, runs four OSINT reputation checks concurrently as a background job, and
combines both into one verdict the extension polls for and displays.

**BYOK by design:** since this isn't a hosted service, every API key (LLM and OSINT) is supplied by the user through the extension's settings page, sent per-request as headers, and never stored server-side. The
backend falls back to my own `.env` keys only for local development convenience - never a requirement for a real user.

**On key transport security:** BYOK keys travel as HTTP headers, which is standard practice (the same pattern Groq/OpenAI/Stripe use for their own API keys) - the actual protection is TLS encryption on the connection, not obscurity. Locally this is not an issue (loopback traffic never leaves the machine); once deployed, HTTPS (provided automatically by Render) ensures headers are encrypted in transit. Server-side, keys are never logged or
persisted - confirmed no logging middleware inspects request headers.

**Engineering notes:**

- **Provider fallback order was reversed mid-build.** Originally planned Gemini as primary with Groq as fallback; Gemini's free tier proved unreliable (frequent 503s, multi-minute timeouts) under real testing, so Groq became primary and Gemini the fallback instead - a decision made from evidence, not the original plan.
- **A planned dependency (Google Custom Search) turned out to be unavailable** - Google restricted the JSON API to existing customers only partway through 2026. Diagnosed via community reports rather than assuming local misconfiguration, and swapped to Tavily, a purpose-built alternative, without changing the pipeline's shape.
- **Found and fixed real false positives** in the entity-reputation check: generic/trusted terms ("HCI", "Google Classroom") were getting flagged from coincidental keyword co-occurrence in search results, not genuine association with fraud. Fixed by requiring the relevance judgment to quote exact supporting evidence before it's allowed to flag anything - no quote, no flag.
- **A real extraction bug**: scam links disguised as multiple-choice answer options (not just plain text) were invisible to the backend for several build stages, since only question titles were being read from the form's data. Fixed once discovered via testing against a form with real (PhishTank-sourced) phishing links as answer choices.
- **Rate limiting protects shared server keys, not the user's own.** Anyone using their own free API key bypasses all limits, since they're spending their own quota; the limiter exists only to bound cost/abuse on the free-trial keys I'd provide if this is ever deployed live.

Full run instructions are in [README.md](./README.md).

## Non-goal

**No user accounts, no saved personal scan history.** This is a single-scan, stateless-from-the-user's-perspective tool - you scan a form, you get a verdict, that's the whole interaction. (Note: the database above stores scans internally for caching/deduplication purposes, not as user-facing accounts or history - there is no login, no "my past scans" page.)

## Architecture sketch

```
Chrome Extension (content script reads the visible Google Form)
   └─► POST /analyze { form_url, title, description, questions[] }
         ├─ content_hash exists in DB? → return cached verdict immediately
         └─ else:
              ├─ LLM call: tactic classification + named entity extraction
              │    → structured JSON, schema-validated, cost logged
              ├─ enqueue background job: OSINT checks
              │    ├─ Google Safe Browsing (link reputation)
              │    ├─ VirusTotal (domain reputation)
              │    ├─ urlscan.io (first-seen, page identity)
              │    └─ Tavily Search 
              ├─ combine LLM signals + OSINT signals → verdict + confidence
              ├─ store in DB (content_hash, verdict, signals, timestamp)
              └─ return verdict to extension
```

## Non-negotiable ethical boundary

This tool analyzes the *content of a form a user is about to fill out* - it never scrapes other users' submitted answers, never touches real social media accounts, and only queries official, ToS-compliant APIs (Google Safe Browsing, VirusTotal, urlscan.io, Tavily API) - no direct scraping of search engines or social platforms.
