"""
Seed the database with sample scam reports for testing
Run: python seed_data.py
"""
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import init_db, SessionLocal, ScamReport, AnalysisLog
from datetime import datetime, timedelta
import random
import uuid

def seed():
    init_db()
    db = SessionLocal()

    # Load sample reports
    sample_path = os.path.join(os.path.dirname(__file__), "../data/sample_reports.json")
    try:
        with open(sample_path) as f:
            samples = json.load(f)
    except FileNotFoundError:
        samples = []

    for s in samples:
        existing = db.query(ScamReport).filter_by(report_id=s["report_id"]).first()
        if not existing:
            report = ScamReport(
                id=str(uuid.uuid4()),
                report_id=s["report_id"],
                scam_type=s["scam_type"],
                confidence_score=s["confidence_score"],
                risk_level=s["risk_level"],
                input_type=s["input_type"],
                input_hash=s.get("input_hash", "seeded"),
                explanation=s["explanation"],
                keywords_found=s.get("keywords_found", []),
                url_indicators={},
                anomaly_indicators={},
                reporter_note=s.get("reporter_note"),
                status=s.get("status", "pending"),
                created_at=datetime.fromisoformat(s["created_at"])
            )
            db.add(report)

    # Generate random analysis logs for chart data
    scam_types = [
        "Investment/Crypto Scam", "Phishing/OTP Fraud", "KYC Update Scam",
        "Fake Job/Recruitment Scam", "Customer-Care/Remote Access Scam",
        "Legitimate", "Legitimate", "Legitimate"
    ]
    risk_levels = ["Low", "Medium", "High", "Critical"]

    for i in range(200):
        days_ago = random.randint(0, 30)
        log = AnalysisLog(
            id=str(uuid.uuid4()),
            input_type=random.choice(["text", "url", "network_log"]),
            input_hash=f"hash_{uuid.uuid4().hex[:8]}",
            scam_type=random.choice(scam_types),
            confidence_score=round(random.uniform(0.1, 0.98), 3),
            risk_level=random.choice(risk_levels),
            processing_time_ms=round(random.uniform(200, 1200), 2),
            created_at=datetime.utcnow() - timedelta(days=days_ago, hours=random.randint(0, 23))
        )
        db.add(log)

    db.commit()
    db.close()
    print("✅ Database seeded successfully!")
    print(f"   - {len(samples)} sample reports loaded")
    print(f"   - 200 analysis logs generated")

if __name__ == "__main__":
    seed()
