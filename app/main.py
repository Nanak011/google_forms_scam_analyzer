import hashlib
import json

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Scan, get_db, init_db

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
    cached: bool


def compute_content_hash(payload: AnalyzeRequest) -> str:
    """Hash the form's actual content, not the URL - so the same form
    scanned from two different links still hits the cache."""
    raw = json.dumps(
        {
            "title": payload.title,
            "description": payload.description,
            "questions": payload.questions,
        },
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    content_hash = compute_content_hash(payload)

    existing = db.query(Scan).filter_by(content_hash=content_hash).first()
    if existing:
        return AnalyzeResponse(
            verdict=existing.verdict,
            confidence=existing.confidence,
            reasons=json.loads(existing.signals),
            cached=True,
        )

    verdict = "uncertain"
    confidence = 0.5
    reasons = ["dummy response - real logic not wired in yet"]

    scan = Scan(
        content_hash=content_hash,
        verdict=verdict,
        confidence=confidence,
        signals=json.dumps(reasons),
    )
    db.add(scan)
    db.commit()

    return AnalyzeResponse(
        verdict=verdict, confidence=confidence, reasons=reasons, cached=False
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)