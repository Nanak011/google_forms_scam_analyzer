import hashlib
import json

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Scan, get_db, init_db
from app.llm import classify_form

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


def verdict_from_confidence(confidence: float) -> str:
    if confidence >= 0.7:
        return "scam"
    if confidence <= 0.3:
        return "legit"
    return "uncertain"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    content_hash = compute_content_hash(payload)

    existing = db.query(Scan).filter_by(content_hash=content_hash).first()
    if existing:
        signals = json.loads(existing.signals)
        return AnalyzeResponse(
            verdict=existing.verdict,
            confidence=existing.confidence,
            reasons=signals.get("reasons", []),
            named_entities=signals.get("named_entities", []),
            cached=True,
        )

    analysis = classify_form(payload.title, payload.description, payload.questions)

    verdict = verdict_from_confidence(analysis.llm_confidence)
    reasons = analysis.tactics_detected + [analysis.summary]
    signals = {"reasons": reasons, "named_entities": analysis.named_entities}

    scan = Scan(
        content_hash=content_hash,
        verdict=verdict,
        confidence=analysis.llm_confidence,
        signals=json.dumps(signals),
    )
    db.add(scan)
    db.commit()

    return AnalyzeResponse(
        verdict=verdict,
        confidence=analysis.llm_confidence,
        reasons=reasons,
        named_entities=analysis.named_entities,
        cached=False,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)