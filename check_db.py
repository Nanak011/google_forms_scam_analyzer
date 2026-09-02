from app.db import SessionLocal, Scan

db = SessionLocal()
print("Total rows:", db.query(Scan).count())
db.close()