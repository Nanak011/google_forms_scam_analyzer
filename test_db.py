from app.db import init_db, SessionLocal, Scan

init_db()

db = SessionLocal()
db.add(Scan(
    content_hash="test123",
    verdict="uncertain",
    confidence=0.5,
    signals='["dummy"]',
))
db.commit()

row = db.query(Scan).filter_by(content_hash="test123").first()
print("Inserted row:", row.id, row.verdict, row.confidence, row.created_at)
db.close()