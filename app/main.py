from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.config import settings

app = FastAPI(title="Google Forms Scam Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    form_url: str
    title: str
    description: str = ""
    questions: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    verdict: str          # "scam" | "legit" | "uncertain"
    confidence: float
    reasons: list[str]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    
    return AnalyzeResponse(
        verdict="uncertain",
        confidence=0.5,
        reasons=["dummy response — real logic not wired in yet"],
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)