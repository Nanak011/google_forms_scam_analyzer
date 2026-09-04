from pydantic import BaseModel


class BYOKKeys(BaseModel):
    gemini_api_key: str | None = None
    groq_api_key: str | None = None
    safe_browsing_api_key: str | None = None
    virustotal_api_key: str | None = None
    urlscan_api_key: str | None = None
    tavily_api_key: str | None = None