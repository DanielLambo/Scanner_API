"""
CRUD operations for scanner feedback database
"""
import hashlib
import json
from uuid import uuid4
from sqlalchemy import select, func
from db.models import Scan, Feedback, ActiveLearningQueue


async def save_scan(db, response, email_address: str = None) -> str:
    """Save a scan result to the database, return the scan_id."""
    # Hash email_address with sha256 if provided
    email_hash = None
    if email_address:
        email_hash = hashlib.sha256(email_address.encode()).hexdigest()

    # Serialize response to JSON for signals field
    try:
        signals_json = json.dumps(response.model_dump())
    except AttributeError:
        signals_json = json.dumps(response.dict())

    # Extract confidence from content_analysis if available
    confidence = 0.0
    if response.content_analysis is not None:
        confidence = response.content_analysis.confidence

    scan_id = str(uuid4())
    scan = Scan(
        id=scan_id,
        email_hash=email_hash,
        scam_score=response.scam_score,
        risk_level=response.risk_level,
        signals=signals_json,
        confidence=confidence,
        models_agree=True,
    )
    db.add(scan)
    await db.commit()
    return scan_id


async def save_feedback(db, scan_id: str, verdict: str, notes: str = None) -> bool:
    """Save feedback for a scan. Returns True on success, False if scan not found."""
    valid_verdicts = {"TP", "FP", "FN", "TN"}
    if verdict not in valid_verdicts:
        raise ValueError(f"verdict must be one of {valid_verdicts}, got '{verdict}'")

    # Check scan_id exists
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    existing = result.scalar_one_or_none()
    if existing is None:
        return False

    feedback = Feedback(
        id=str(uuid4()),
        scan_id=scan_id,
        verdict=verdict,
        notes=notes,
    )
    db.add(feedback)
    await db.commit()
    return True


async def add_to_active_learning(db, scan_id: str, confidence: float, disagreement: float) -> None:
    """Add a scan to the active learning queue based on confidence/disagreement thresholds."""
    if confidence < 0.65 and disagreement > 0.3:
        reason = "both"
    elif confidence < 0.65:
        reason = "low_confidence"
    else:
        reason = "high_disagreement"

    item = ActiveLearningQueue(
        id=str(uuid4()),
        scan_id=scan_id,
        confidence=confidence,
        ensemble_disagreement=disagreement,
        reason=reason,
        reviewed=False,
    )
    db.add(item)
    await db.commit()


async def get_review_queue(db, limit: int = 50) -> list:
    """Return unreviewed active learning queue items ordered by created_at desc."""
    result = await db.execute(
        select(ActiveLearningQueue)
        .where(ActiveLearningQueue.reviewed == False)
        .order_by(ActiveLearningQueue.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "confidence": row.confidence,
            "ensemble_disagreement": row.ensemble_disagreement,
            "reason": row.reason,
            "reviewed": row.reviewed,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


async def get_feedback_stats(db) -> dict:
    """Return aggregate statistics about scans, feedback, and the active learning queue."""
    # total_scans
    total_scans_result = await db.execute(select(func.count()).select_from(Scan))
    total_scans = total_scans_result.scalar()

    # total_feedback
    total_feedback_result = await db.execute(select(func.count()).select_from(Feedback))
    total_feedback = total_feedback_result.scalar()

    # verdict_counts
    verdict_counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for verdict in verdict_counts:
        count_result = await db.execute(
            select(func.count()).select_from(Feedback).where(Feedback.verdict == verdict)
        )
        verdict_counts[verdict] = count_result.scalar()

    # queue_size (unreviewed)
    queue_size_result = await db.execute(
        select(func.count()).select_from(ActiveLearningQueue).where(ActiveLearningQueue.reviewed == False)
    )
    queue_size = queue_size_result.scalar()

    # reviewed_count
    reviewed_count_result = await db.execute(
        select(func.count()).select_from(ActiveLearningQueue).where(ActiveLearningQueue.reviewed == True)
    )
    reviewed_count = reviewed_count_result.scalar()

    return {
        "total_scans": total_scans,
        "total_feedback": total_feedback,
        "verdict_counts": verdict_counts,
        "queue_size": queue_size,
        "reviewed_count": reviewed_count,
    }
