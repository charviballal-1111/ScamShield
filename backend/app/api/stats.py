"""
Statistics and Analytics API endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from datetime import datetime, timedelta
from collections import Counter

from app.core.database import get_db, ScamReport, AnalysisLog
from app.models.schemas import StatsResponse

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: Session = Depends(get_db)):
    """Get aggregated statistics for dashboard"""
    total_analyses = db.query(AnalysisLog).count()
    total_reports = db.query(ScamReport).count()

    # Scams by type
    type_counts = db.query(
        ScamReport.scam_type, func.count(ScamReport.id).label("count")
    ).group_by(ScamReport.scam_type).all()
    scams_by_type = {row.scam_type: row.count for row in type_counts}

    # Scams by risk level
    risk_counts = db.query(
        ScamReport.risk_level, func.count(ScamReport.id).label("count")
    ).group_by(ScamReport.risk_level).all()
    scams_by_risk = {row.risk_level: row.count for row in risk_counts}

    # Recent trend (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_logs = db.query(AnalysisLog).filter(
        AnalysisLog.created_at >= seven_days_ago
    ).all()

    trend_by_day: dict = {}
    for log in recent_logs:
        day = log.created_at.strftime("%Y-%m-%d")
        trend_by_day[day] = trend_by_day.get(day, 0) + 1

    recent_trend = [
        {"date": day, "count": count}
        for day, count in sorted(trend_by_day.items())
    ]

    # Top keywords across all reports
    all_keywords = []
    reports = db.query(ScamReport).all()
    for r in reports:
        if r.keywords_found:
            all_keywords.extend(r.keywords_found)

    kw_counter = Counter(all_keywords)
    top_keywords = [
        {"keyword": kw, "count": cnt}
        for kw, cnt in kw_counter.most_common(10)
    ]

    # Average confidence
    avg_conf = db.query(func.avg(ScamReport.confidence_score)).scalar() or 0.0

    return StatsResponse(
        total_analyses=total_analyses,
        total_reports=total_reports,
        scams_by_type=scams_by_type,
        scams_by_risk=scams_by_risk,
        recent_trend=recent_trend,
        top_keywords=top_keywords,
        avg_confidence=round(float(avg_conf), 3)
    )


@router.get("/stats/summary")
async def get_summary(db: Session = Depends(get_db)):
    """Quick summary for header stats"""
    total = db.query(ScamReport).count()
    high_risk = db.query(ScamReport).filter(
        ScamReport.risk_level.in_(["High", "Critical"])
    ).count()
    today = datetime.utcnow().date()
    today_count = db.query(ScamReport).filter(
        func.date(ScamReport.created_at) == today
    ).count()
    pending = db.query(ScamReport).filter(ScamReport.status == "pending").count()

    return {
        "total_reports": total,
        "high_risk_count": high_risk,
        "reports_today": today_count,
        "pending_review": pending
    }
