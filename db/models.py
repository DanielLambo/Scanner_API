"""
SQLAlchemy ORM models for scanner feedback database
"""
from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, ForeignKey
from db.database import Base
from uuid import uuid4
from datetime import datetime


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    created_at = Column(DateTime, default=datetime.utcnow)
    email_hash = Column(String)  # sha256 of email_address, never raw
    scam_score = Column(Float)
    risk_level = Column(String)
    signals = Column(Text)  # JSON blob of full response
    confidence = Column(Float)
    models_agree = Column(Boolean, default=True)


class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"))
    verdict = Column(String)  # TP | FP | FN | TN
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActiveLearningQueue(Base):
    __tablename__ = "active_learning_queue"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"))
    confidence = Column(Float)
    ensemble_disagreement = Column(Float)
    reason = Column(String)  # "low_confidence" | "high_disagreement" | "both"
    reviewed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
