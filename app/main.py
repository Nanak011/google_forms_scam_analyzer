from fastapi import FastAPI

from app.config import settings

app = FastAPI(title="Google Forms Scam Analyzer")


@app.get("/health")
def health():
    return {"status": "ok"}