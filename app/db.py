from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, String, Text, DateTime, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.config import settings

BASE_DIR = Path(__file__).resolve().parent.parent


def _resolve_database_url(url: str) -> str:
    prefix = "sqlite:///./"
    if url.startswith(prefix):
        rel_path = url[len(prefix):]
        abs_path = BASE_DIR / rel_path
        return f"sqlite:///{abs_path}"
    return url


def _connect_args(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


RESOLVED_DATABASE_URL = _resolve_database_url(settings.database_url)

engine = create_engine(
    RESOLVED_DATABASE_URL,
    connect_args=_connect_args(RESOLVED_DATABASE_URL),
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    form_url: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending_osint")  # pending_osint | complete
    verdict: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    reasons: Mapped[str] = mapped_column(Text)                # JSON list of strings
    llm_signals: Mapped[str] = mapped_column(Text)             # JSON: raw LLM analysis, needed to redo the combine once OSINT finishes
    osint_signals: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    embedded_urls: Mapped[str] = mapped_column(Text, default="[]")

def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()