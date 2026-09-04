from datetime import date

from sqlalchemy import Date, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, SessionLocal


class RateLimitEntry(Base):
    __tablename__ = "rate_limits"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    day: Mapped[date] = mapped_column(Date, index=True)
    count: Mapped[int] = mapped_column(Integer, default=0)


def check_and_increment(ip_address: str, daily_limit: int) -> tuple[bool, int]:
    db = SessionLocal()
    try:
        today = date.today()
        entry = db.query(RateLimitEntry).filter_by(ip_address=ip_address, day=today).first()
        if entry is None:
            entry = RateLimitEntry(ip_address=ip_address, day=today, count=0)
            db.add(entry)
        if entry.count >= daily_limit:
            return False, entry.count
        entry.count += 1
        db.commit()
        return True, entry.count
    finally:
        db.close()