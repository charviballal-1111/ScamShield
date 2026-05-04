"""
Scam Reports API endpoints
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
import uuid

from app.core.database import get_db, ScamReport
from app.models.schemas import ReportScamRequest, ReportResponse, ScamReportOut

router = APIRouter()


@router.post("/report", response_model=ReportResponse)
async def submit_report(request: ReportScamRequest, db: Session = Depends(get_db)):
    """Submit a scam report"""
    report_id = f"SCM-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"

    report = ScamReport(
        report_id=report_id,
        scam_type=request.scam_type,
        confidence_score=request.confidence_score or 0.0,
        risk_level=request.risk_level,
        input_type=request.input_type,
        input_hash=request.analysis_id or "manual",
        explanation=request.explanation,
        keywords_found=request.keywords_found or [],
        url_indicators=request.url_indicators or {},
        anomaly_indicators=request.anomaly_indicators or {},
        reporter_note=request.reporter_note,
        status="pending"
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return ReportResponse(
        report_id=report_id,
        status="submitted",
        message=f"Report {report_id} submitted successfully. Our team will review it shortly.",
        created_at=report.created_at
    )


@router.get("/reports", response_model=List[ScamReportOut])
async def get_reports(
    db: Session = Depends(get_db),
    scam_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0)
):
    """Get list of reported scams with optional filters"""
    query = db.query(ScamReport)

    if scam_type:
        query = query.filter(ScamReport.scam_type.ilike(f"%{scam_type}%"))
    if risk_level:
        query = query.filter(ScamReport.risk_level == risk_level)
    if status:
        query = query.filter(ScamReport.status == status)

    reports = query.order_by(ScamReport.created_at.desc()).offset(offset).limit(limit).all()
    return reports


@router.get("/reports/{report_id}", response_model=ScamReportOut)
async def get_report(report_id: str, db: Session = Depends(get_db)):
    """Get a specific report by ID"""
    report = db.query(ScamReport).filter(ScamReport.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.patch("/reports/{report_id}/status")
async def update_report_status(report_id: str, status: str, db: Session = Depends(get_db)):
    """Update report status (admin action)"""
    valid_statuses = ["pending", "reviewed", "confirmed", "dismissed"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {valid_statuses}")

    report = db.query(ScamReport).filter(ScamReport.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.status = status
    report.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"Report {report_id} status updated to '{status}'"}
