from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, String, Text, DateTime, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.config import settings

BASE_DIR = Path(__file__).resolve().parent.parent  # project root, one level up from app/


def _resolve_database_url(url: str) -> str:
    """Turn a relative sqlite URL into an absolute path based on the project
    root, so it works the same no matter where the script is run from."""
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
    verdict: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    signals: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()