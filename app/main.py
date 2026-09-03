import hashlib
import json

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Scan, SessionLocal, get_db, init_db
from app.llm import LLMAnalysis, classify_form
from app.osint import run_osint_checks
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


class AnalyzeResponse(BaseModel):
    content_hash: str
    status: str  # "pending_osint" | "complete"
    verdict: str
    confidence: float
    reasons: list[str]
    named_entities: list[str]
    cached: bool


def compute_content_hash(payload: AnalyzeRequest) -> str:
    raw = json.dumps(
        {
            "title": payload.title,
            "description": payload.description,
            "questions": payload.questions,
        },
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _scan_to_response(scan: Scan, cached: bool) -> AnalyzeResponse:
    llm_signals = json.loads(scan.llm_signals)
    return AnalyzeResponse(
        content_hash=scan.content_hash,
        status=scan.status,
        verdict=scan.verdict,
        confidence=scan.confidence,
        reasons=json.loads(scan.reasons),
        named_entities=llm_signals.get("named_entities", []),
        cached=cached,
    )


def run_osint_background_job(content_hash: str):
    """Runs AFTER the HTTP response has already been sent to the client.
    Opens its own DB session - the request-scoped one from Depends(get_db)
    is already closed by the time this executes."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter_by(content_hash=content_hash).first()
        if scan is None:
            return

        llm_signals = json.loads(scan.llm_signals)
        analysis = LLMAnalysis(**llm_signals)

        osint_result = run_osint_checks(scan.form_url, analysis.named_entities)
        combined = combine_signals(analysis, osint_result)

        scan.verdict = combined["verdict"]
        scan.confidence = combined["confidence"]
        scan.reasons = json.dumps(combined["reasons"])
        scan.osint_signals = json.dumps(osint_result)
        scan.status = "complete"
        db.commit()
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    content_hash = compute_content_hash(payload)

    existing = db.query(Scan).filter_by(content_hash=content_hash).first()
    if existing:
        return _scan_to_response(existing, cached=True)

 
    analysis = classify_form(payload.title, payload.description, payload.questions)
    combined = combine_signals(analysis, osint={})

    scan = Scan(
        content_hash=content_hash,
        form_url=payload.form_url,
        status="pending_osint",
        verdict=combined["verdict"],
        confidence=combined["confidence"],
        reasons=json.dumps(combined["reasons"]),
        llm_signals=json.dumps(analysis.model_dump()),
        osint_signals="{}",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(run_osint_background_job, content_hash)

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