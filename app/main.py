# import hashlib
# import json

# from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel, Field
# from sqlalchemy.orm import Session

# from app.config import settings
# from app.db import Scan, SessionLocal, get_db, init_db
# from app.llm import LLMAnalysis, classify_form, judge_entity_relevance
# from app.osint import run_osint_checks
# from app.verdict import combine_signals

# app = FastAPI(title="Google Forms Scam Analyzer")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=False,
#     allow_methods=["GET", "POST"],
#     allow_headers=["*"],
# )


# @app.on_event("startup")
# def on_startup():
#     init_db()


# class AnalyzeRequest(BaseModel):
#     form_url: str
#     title: str
#     description: str = ""
#     questions: list[str] = Field(default_factory=list)


# # class AnalyzeResponse(BaseModel):
# #     content_hash: str
# #     status: str  # "pending_osint" | "complete"
# #     verdict: str
# #     confidence: float
# #     reasons: list[str]
# #     named_entities: list[str]
# #     cached: bool

# class AnalyzeResponse(BaseModel):
#     content_hash: str
#     status: str
#     verdict: str
#     confidence: float
#     reasons: list[str]
#     named_entities: list[str]
#     cached: bool
#     checks: dict = Field(default_factory=dict)  # raw per-provider OSINT results, for transparency


# def compute_content_hash(payload: AnalyzeRequest) -> str:
#     raw = json.dumps(
#         {
#             "title": payload.title,
#             "description": payload.description,
#             "questions": payload.questions,
#         },
#         sort_keys=True,
#     )
#     return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# # def _scan_to_response(scan: Scan, cached: bool) -> AnalyzeResponse:
# #     llm_signals = json.loads(scan.llm_signals)
# #     return AnalyzeResponse(
# #         content_hash=scan.content_hash,
# #         status=scan.status,
# #         verdict=scan.verdict,
# #         confidence=scan.confidence,
# #         reasons=json.loads(scan.reasons),
# #         named_entities=llm_signals.get("named_entities", []),
# #         cached=cached,
# #     )

# def _scan_to_response(scan: Scan, cached: bool) -> AnalyzeResponse:
#     llm_signals = json.loads(scan.llm_signals)
#     osint_signals = json.loads(scan.osint_signals) if scan.osint_signals else {}
#     return AnalyzeResponse(
#         content_hash=scan.content_hash,
#         status=scan.status,
#         verdict=scan.verdict,
#         confidence=scan.confidence,
#         reasons=json.loads(scan.reasons),
#         named_entities=llm_signals.get("named_entities", []),
#         cached=cached,
#         checks=osint_signals,
#     )


# # def run_osint_background_job(content_hash: str):
# #     """Runs AFTER the HTTP response has already been sent to the client.
# #     Opens its own DB session - the request-scoped one from Depends(get_db)
# #     is already closed by the time this executes."""
# #     db = SessionLocal()
# #     try:
# #         scan = db.query(Scan).filter_by(content_hash=content_hash).first()
# #         if scan is None:
# #             return

# #         llm_signals = json.loads(scan.llm_signals)
# #         analysis = LLMAnalysis(**llm_signals)

# #         osint_result = run_osint_checks(scan.form_url, analysis.named_entities)
# #         combined = combine_signals(analysis, osint_result)

# #         scan.verdict = combined["verdict"]
# #         scan.confidence = combined["confidence"]
# #         scan.reasons = json.dumps(combined["reasons"])
# #         scan.osint_signals = json.dumps(osint_result)
# #         scan.status = "complete"
# #         db.commit()
# #     finally:
# #         db.close()



# def run_osint_background_job(content_hash: str):
#     db = SessionLocal()
#     try:
#         scan = db.query(Scan).filter_by(content_hash=content_hash).first()
#         if scan is None:
#             return

#         llm_signals = json.loads(scan.llm_signals)
#         analysis = LLMAnalysis(**llm_signals)

#         osint_result = run_osint_checks(scan.form_url, analysis.named_entities)

#         # NEW: judge whether each entity's search hits are actually relevant,
#         # instead of blindly trusting "result_count > 0".
#         for entity_name, result in osint_result.get("named_entity_checks", {}).items():
#             if result.get("result_count", 0) > 0 and not result.get("error"):
#                 relevance = judge_entity_relevance(entity_name, result.get("top_snippets", []))
#                 result["relevant"] = relevance.is_relevant
#                 result["relevance_reason"] = relevance.reason
#             else:
#                 result["relevant"] = False

#         combined = combine_signals(analysis, osint_result)

#         scan.verdict = combined["verdict"]
#         scan.confidence = combined["confidence"]
#         scan.reasons = json.dumps(combined["reasons"])
#         scan.osint_signals = json.dumps(osint_result)
#         scan.status = "complete"
#         db.commit()
#     finally:
#         db.close()


# @app.get("/health")
# def health():
#     return {"status": "ok"}


# @app.post("/analyze", response_model=AnalyzeResponse)
# def analyze(
#     payload: AnalyzeRequest,
#     background_tasks: BackgroundTasks,
#     db: Session = Depends(get_db),
# ):
#     content_hash = compute_content_hash(payload)

#     existing = db.query(Scan).filter_by(content_hash=content_hash).first()
#     if existing:
#         return _scan_to_response(existing, cached=True)

 
#     analysis = classify_form(payload.title, payload.description, payload.questions)
#     combined = combine_signals(analysis, osint={})

#     scan = Scan(
#         content_hash=content_hash,
#         form_url=payload.form_url,
#         status="pending_osint",
#         verdict=combined["verdict"],
#         confidence=combined["confidence"],
#         reasons=json.dumps(combined["reasons"]),
#         llm_signals=json.dumps(analysis.model_dump()),
#         osint_signals="{}",
#     )
#     db.add(scan)
#     db.commit()
#     db.refresh(scan)

#     background_tasks.add_task(run_osint_background_job, content_hash)

#     return _scan_to_response(scan, cached=False)


# @app.get("/analyze/{content_hash}", response_model=AnalyzeResponse)
# def get_analysis(content_hash: str, db: Session = Depends(get_db)):
#     scan = db.query(Scan).filter_by(content_hash=content_hash).first()
#     if scan is None:
#         raise HTTPException(status_code=404, detail="No scan found for this content hash")
#     return _scan_to_response(scan, cached=True)


# if __name__ == "__main__":
#     import uvicorn

#     uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)



import hashlib
import json

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Scan, SessionLocal, get_db, init_db
from app.keys import BYOKKeys
from app.llm import LLMAnalysis, classify_form, judge_entity_relevance
from app.osint import extract_urls, run_osint_checks
from app.verdict import combine_signals

app = FastAPI(title="Google Forms Scam Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


class AnalyzeRequest(BaseModel):
    form_url: str
    title: str
    description: str = ""
    questions: list[str] = Field(default_factory=list)
    force: bool = False


class AnalyzeResponse(BaseModel):
    content_hash: str
    status: str
    verdict: str
    confidence: float
    reasons: list[str]
    named_entities: list[str]
    cached: bool
    checks: dict = Field(default_factory=dict)



def _keys_from_headers(
    x_gemini_key: str | None,
    x_groq_key: str | None,
    x_safe_browsing_key: str | None,
    x_virustotal_key: str | None,
    x_urlscan_key: str | None,
    x_tavily_key: str | None,
) -> BYOKKeys:
    return BYOKKeys(
        gemini_api_key=x_gemini_key,
        groq_api_key=x_groq_key,
        safe_browsing_api_key=x_safe_browsing_key,
        virustotal_api_key=x_virustotal_key,
        urlscan_api_key=x_urlscan_key,
        tavily_api_key=x_tavily_key,
    )

def compute_content_hash(payload: AnalyzeRequest) -> str:
    raw = json.dumps(
        {"title": payload.title, "description": payload.description, "questions": payload.questions},
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verdict_from_confidence(confidence: float) -> str:
    if confidence >= 0.7:
        return "scam"
    if confidence <= 0.3:
        return "legit"
    return "uncertain"


def _scan_to_response(scan: Scan, cached: bool) -> AnalyzeResponse:
    llm_signals = json.loads(scan.llm_signals)
    osint_signals = json.loads(scan.osint_signals) if scan.osint_signals else {}
    return AnalyzeResponse(
        content_hash=scan.content_hash,
        status=scan.status,
        verdict=scan.verdict,
        confidence=scan.confidence,
        reasons=json.loads(scan.reasons),
        named_entities=llm_signals.get("named_entities", []),
        cached=cached,
        checks=osint_signals,
    )


# def run_osint_background_job(content_hash: str):
#     """Runs after the HTTP response is sent. Guaranteed to always reach a
#     final 'complete' state, even if OSINT calls or relevance judging fail —
#     a scan must never get permanently stuck in 'pending_osint'."""
#     db = SessionLocal()
#     try:
#         scan = db.query(Scan).filter_by(content_hash=content_hash).first()
#         if scan is None:
#             return

#         llm_signals = json.loads(scan.llm_signals)
#         analysis = LLMAnalysis(**llm_signals)
#         embedded_urls = json.loads(scan.embedded_urls or "[]")

#         try:
#             osint_result = run_osint_checks(scan.form_url, analysis.named_entities, embedded_urls)
#         except Exception as e:
#             print(f"[background_job] OSINT checks failed entirely: {e}")
#             osint_result = {}

#         # for entity_name, result in osint_result.get("named_entity_checks", {}).items():
#         #     if result.get("result_count", 0) > 0 and not result.get("error"):
#         #         try:
#         #             relevance = judge_entity_relevance(entity_name, result.get("top_snippets", []))
#         #             result["relevant"] = relevance.is_relevant
#         #             result["relevance_reason"] = relevance.reason
#         #         except Exception as e:
#         #             print(f"[background_job] relevance judgment failed for '{entity_name}': {e}")
#         #             result["relevant"] = False
#         #             result["relevance_reason"] = "Could not verify (check failed)"
#         #     else:
#         #         result["relevant"] = False

#         for entity_name, result in osint_result.get("named_entity_checks", {}).items():
#             if result.get("result_count", 0) > 0 and not result.get("error"):
#                 try:
#                     relevance = judge_entity_relevance(entity_name, result.get("top_results", []))
#                     result["relevant"] = relevance.is_relevant
#                     result["relevance_reason"] = relevance.reason
#                     result["evidence_snippet"] = relevance.evidence_snippet
#                     result["evidence_url"] = relevance.evidence_url
#                 except Exception as e:
#                     print(f"[background_job] relevance judgment failed for '{entity_name}': {e}")
#                     result["relevant"] = False
#                     result["relevance_reason"] = "Could not verify (check failed)"
#             else:
#                 result["relevant"] = False



def run_osint_background_job(content_hash: str, keys: BYOKKeys):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter_by(content_hash=content_hash).first()
        if scan is None:
            return

        llm_signals = json.loads(scan.llm_signals)
        analysis = LLMAnalysis(**llm_signals)
        embedded_urls = json.loads(scan.embedded_urls or "[]")

        try:
            osint_result = run_osint_checks(scan.form_url, analysis.named_entities, embedded_urls, keys=keys)
        except Exception as e:
            print(f"[background_job] OSINT checks failed entirely: {e}")
            osint_result = {}

        for entity_name, result in osint_result.get("named_entity_checks", {}).items():
            if result.get("result_count", 0) > 0 and not result.get("error"):
                try:
                    relevance = judge_entity_relevance(entity_name, result.get("top_results", []), keys=keys)
                    result["relevant"] = relevance.is_relevant
                    result["relevance_reason"] = relevance.reason
                    result["evidence_snippet"] = relevance.evidence_snippet
                    result["evidence_url"] = relevance.evidence_url
                except Exception as e:
                    print(f"[background_job] relevance judgment failed for '{entity_name}': {e}")
                    result["relevant"] = False
                    result["relevance_reason"] = "Could not verify (check failed)"
            else:
                result["relevant"] = False

        try:
            combined = combine_signals(analysis, osint_result)
        except Exception as e:
            print(f"[background_job] combine_signals failed: {e}")
            combined = {
                "verdict": scan.verdict,
                "confidence": scan.confidence,
                "reasons": json.loads(scan.reasons) + ["Reputation checks could not fully complete."],
                "named_entities": analysis.named_entities,
            }

        scan.verdict = combined["verdict"]
        scan.confidence = combined["confidence"]
        scan.reasons = json.dumps(combined["reasons"])
        scan.osint_signals = json.dumps(osint_result)
        scan.status = "complete"
        db.commit()
    except Exception as e:
        print(f"[background_job] unexpected top-level failure: {e}")
        try:
            scan = db.query(Scan).filter_by(content_hash=content_hash).first()
            if scan and scan.status != "complete":
                reasons = json.loads(scan.reasons) if scan.reasons else []
                reasons.append("Reputation checks failed to complete.")
                scan.reasons = json.dumps(reasons)
                scan.status = "complete"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


# @app.post("/analyze", response_model=AnalyzeResponse)
# def analyze(payload: AnalyzeRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
#     content_hash = compute_content_hash(payload)

#     existing = db.query(Scan).filter_by(content_hash=content_hash).first()
#     if existing and not payload.force:
#         return _scan_to_response(existing, cached=True)
#     if existing and payload.force:
#         db.delete(existing)
#         db.commit()

#     analysis = classify_form(payload.title, payload.description, payload.questions)
#     combined = combine_signals(analysis, osint={})

#     embedded_urls = extract_urls(payload.title, payload.description, *payload.questions)
#     embedded_urls = [u for u in embedded_urls if u != payload.form_url]

#     scan = Scan(
#         content_hash=content_hash,
#         form_url=payload.form_url,
#         status="pending_osint",
#         verdict=combined["verdict"],
#         confidence=combined["confidence"],
#         reasons=json.dumps(combined["reasons"]),
#         llm_signals=json.dumps(analysis.model_dump()),
#         osint_signals="{}",
#         embedded_urls=json.dumps(embedded_urls),
#     )
#     db.add(scan)
#     db.commit()
#     db.refresh(scan)

#     background_tasks.add_task(run_osint_background_job, content_hash)

#     return _scan_to_response(scan, cached=False)




@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    x_gemini_key: str | None = Header(None),
    x_groq_key: str | None = Header(None),
    x_safe_browsing_key: str | None = Header(None),
    x_virustotal_key: str | None = Header(None),
    x_urlscan_key: str | None = Header(None),
    x_tavily_key: str | None = Header(None),
):
    keys = _keys_from_headers(x_gemini_key, x_groq_key, x_safe_browsing_key, x_virustotal_key, x_urlscan_key, x_tavily_key)
    if not (keys.gemini_api_key or keys.groq_api_key or settings.gemini_api_key or settings.groq_api_key):
        raise HTTPException(
            status_code=400,
            detail="No LLM API key found. Add your Gemini or Groq API key in the extension's settings.",
        )

    content_hash = compute_content_hash(payload)

    existing = db.query(Scan).filter_by(content_hash=content_hash).first()
    if existing and not payload.force:
        return _scan_to_response(existing, cached=True)
    if existing and payload.force:
        db.delete(existing)
        db.commit()

    try:
        analysis = classify_form(payload.title, payload.description, payload.questions, keys=keys)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    combined = combine_signals(analysis, osint={})

    embedded_urls = extract_urls(payload.title, payload.description, *payload.questions)
    embedded_urls = [u for u in embedded_urls if u != payload.form_url]

    scan = Scan(
        content_hash=content_hash,
        form_url=payload.form_url,
        status="pending_osint",
        verdict=combined["verdict"],
        confidence=combined["confidence"],
        reasons=json.dumps(combined["reasons"]),
        llm_signals=json.dumps(analysis.model_dump()),
        osint_signals="{}",
        embedded_urls=json.dumps(embedded_urls),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(run_osint_background_job, content_hash, keys)

    return _scan_to_response(scan, cached=False)



@app.get("/analyze/{content_hash}", response_model=AnalyzeResponse)
def get_analysis(content_hash: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(content_hash=content_hash).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this content hash")
    return _scan_to_response(scan, cached=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)