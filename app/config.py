from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Core app settings
    database_url: str = "sqlite:///./dev.db"
    port: int = 8000

    gemini_api_key: str | None = None
    groq_api_key: str | None = None
    google_safe_browsing_api_key: str | None = None
    virustotal_api_key: str | None = None
    urlscan_api_key: str | None = None
    # google_cse_api_key: str | None = None
    # google_cse_cx: str | None = None
    tavily_api_key: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()