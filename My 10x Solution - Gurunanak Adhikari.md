# My 10x Solution — One-Pager (M1)

## The problem

People regularly receive Google Form links via email, text, or social media — scholarship applications, "you've won a prize," job application requests, "verify your account" forms. Checking whether one is a scam means reading it carefully, manually searching the linked domain, and googling any names or organizations mentioned — a careful person spends several minutes doing this, and most people skip it entirely because it's tedious. That skipped step is exactly where scams succeed.

## Who has this problem

Anyone who receives an unsolicited Google Form link and has no quick way to sanity-check it before entering personal information — students, job seekers, people responding to "giveaway" or "survey reward" links, employees receiving fake internal-looking forms.

## The 10x claim

Manually vetting a suspicious form — reading it, checking the link, searching mentioned names — takes several minutes of effort most people skip. This tool produces a scam/legit/uncertain verdict, with named reasons, in the time it takes a browser popup to load.

## The 5 concepts (no swaps needed)

| # | Concept | How it's implemented |
|---|---|---|
| 1 | **API endpoints** | `POST /analyze` accepts a form URL and its extracted content; returns a verdict with reasons |
| 2 | **Database** | Every scan (content hash, extracted signals, verdict, timestamp) is stored — this is what makes caching possible and survives a restart |
| 3 | **LLM integration** | One narrow job: given form title/description/questions, classify scam tactics present (urgency, too-good-to-be-true, request for sensitive info, generic/impersonal greeting), extract any named people/organizations mentioned, and return a structured JSON verdict with a confidence score — validated against a schema, cost logged per call |
| 4 | **Caching** | If a form's content hash has been scanned before, return the cached verdict instantly — no re-running the LLM or OSINT checks for a form seen twice |
| 5 | **Background jobs** | OSINT/reputation checks (Google Safe Browsing, VirusTotal, urlscan.io, and targeted Google Custom Search queries on any extracted names/orgs) run asynchronously off the main request path, since external API latency varies; the client polls or receives the combined verdict once the job completes |

## Non-goal

**No user accounts, no saved personal scan history.** This is a single-scan, stateless-from-the-user's-perspective tool — you scan a form, you get a verdict, that's the whole interaction. (Note: the database above stores scans internally for caching/deduplication purposes, not as user-facing accounts or history — there is no login, no "my past scans" page.)

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
              │    └─ Google Custom Search (targeted queries on extracted names/orgs)
              ├─ combine LLM signals + OSINT signals → verdict + confidence
              ├─ store in DB (content_hash, verdict, signals, timestamp)
              └─ return verdict to extension
```

## Non-negotiable ethical boundary

This tool analyzes the *content of a form a user is about to fill out* — it never scrapes other users' submitted answers, never touches real social media accounts, and only queries official, ToS-compliant APIs (Google Safe Browsing, VirusTotal, urlscan.io, Google Custom Search JSON API) — no direct scraping of search engines or social platforms.
