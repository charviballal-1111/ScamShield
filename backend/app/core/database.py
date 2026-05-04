"""
Database configuration - SQLite for development, PostgreSQL for production
"""
from sqlalchemy import create_engine, Column, String, Float, DateTime, Text, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import uuid

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scam_detection.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String, unique=True, index=True)
    scam_type = Column(String, index=True)
    confidence_score = Column(Float)
    risk_level = Column(String, index=True)
    input_type = Column(String)  # text, url, network_log
    input_hash = Column(String)  # anonymized hash of input
    explanation = Column(Text)
    keywords_found = Column(JSON)
    url_indicators = Column(JSON)
    anomaly_indicators = Column(JSON)
    reporter_note = Column(Text, nullable=True)
    status = Column(String, default="pending")  # pending, reviewed, confirmed, dismissed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AnalysisLog(Base):
    __tablename__ = "analysis_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    input_type = Column(String)
    input_hash = Column(String)
    scam_type = Column(String)
    confidence_score = Column(Float)
    risk_level = Column(String)
    processing_time_ms = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
