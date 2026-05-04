"""
Analysis API endpoints
"""
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import time
import uuid

from app.core.database import get_db, AnalysisLog
from app.models.schemas import (
    AnalyzeTextRequest, AnalyzeURLRequest, AnalyzeNetworkLogRequest,
    AnalysisResponse
)
from app.services.detector import (
    NLPScamDetector, URLAnalyzer, NetworkAnomalyDetector,
    determine_risk_level, generate_explanation, generate_recommendations,
    anonymize_input
)

router = APIRouter()
nlp_detector = NLPScamDetector()
url_analyzer = URLAnalyzer()
anomaly_detector = NetworkAnomalyDetector()


def build_response(result: dict, recommendations: list, explanation: str,
                   processing_time: float) -> AnalysisResponse:
    risk_level = determine_risk_level(result["confidence_score"], result["scam_type"])
    analysis_id = str(uuid.uuid4())[:12].upper()

    return AnalysisResponse(
        analysis_id=analysis_id,
        scam_type=result["scam_type"],
        confidence_score=result["confidence_score"],
        risk_level=risk_level,
        explanation=explanation,
        keywords_found=result.get("keywords_found", []),
        url_analysis=result.get("url_analysis"),
        anomaly_analysis=result.get("anomaly_analysis"),
        recommendations=recommendations,
        input_type=result["input_type"],
        processing_time_ms=round(processing_time, 2),
        timestamp=datetime.utcnow()
    )


@router.post("/analyze/text", response_model=AnalysisResponse)
async def analyze_text(request: AnalyzeTextRequest, db: Session = Depends(get_db)):
    """Analyze SMS/email text for scam content"""
    start = time.time()

    result = nlp_detector.analyze(request.content)
    risk_level = determine_risk_level(result["confidence_score"], result["scam_type"])
    explanation = generate_explanation(
        result["scam_type"], result["keywords_found"],
        result["confidence_score"], "text"
    )
    recommendations = generate_recommendations(result["scam_type"], risk_level)
    processing_time = (time.time() - start) * 1000

    # Log anonymized analysis
    log = AnalysisLog(
        input_type="text",
        input_hash=anonymize_input(request.content),
        scam_type=result["scam_type"],
        confidence_score=result["confidence_score"],
        risk_level=risk_level,
        processing_time_ms=processing_time
    )
    db.add(log)
    db.commit()

    return build_response(result, recommendations, explanation, processing_time)


@router.post("/analyze/url", response_model=AnalysisResponse)
async def analyze_url(request: AnalyzeURLRequest, db: Session = Depends(get_db)):
    """Analyze a URL for phishing/scam indicators"""
    start = time.time()

    result = url_analyzer.analyze(request.url)
    risk_level = determine_risk_level(result["confidence_score"], result["scam_type"])
    explanation = generate_explanation(
        result["scam_type"], result["keywords_found"],
        result["confidence_score"], "URL",
        result.get("url_analysis")
    )
    recommendations = generate_recommendations(result["scam_type"], risk_level)
    processing_time = (time.time() - start) * 1000

    log = AnalysisLog(
        input_type="url",
        input_hash=anonymize_input(request.url),
        scam_type=result["scam_type"],
        confidence_score=result["confidence_score"],
        risk_level=risk_level,
        processing_time_ms=processing_time
    )
    db.add(log)
    db.commit()

    return build_response(result, recommendations, explanation, processing_time)


@router.post("/analyze/network", response_model=AnalysisResponse)
async def analyze_network_log(request: AnalyzeNetworkLogRequest, db: Session = Depends(get_db)):
    """Analyze network logs for anomalous behavior"""
    start = time.time()

    if len(request.logs) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 log entries allowed")

    result = anomaly_detector.analyze(request.logs, request.time_window_minutes)
    risk_level = determine_risk_level(result["confidence_score"], result["scam_type"])
    explanation = generate_explanation(
        result["scam_type"], result["keywords_found"],
        result["confidence_score"], "network log",
        result.get("anomaly_analysis")
    )
    recommendations = generate_recommendations(result["scam_type"], risk_level)
    processing_time = (time.time() - start) * 1000

    log = AnalysisLog(
        input_type="network_log",
        input_hash=anonymize_input(str(len(request.logs))),
        scam_type=result["scam_type"],
        confidence_score=result["confidence_score"],
        risk_level=risk_level,
        processing_time_ms=processing_time
    )
    db.add(log)
    db.commit()

    return build_response(result, recommendations, explanation, processing_time)
