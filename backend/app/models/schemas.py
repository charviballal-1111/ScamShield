"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ScamType(str, Enum):
    INVESTMENT_CRYPTO = "Investment/Crypto Scam"
    FAKE_JOB = "Fake Job/Recruitment Scam"
    CUSTOMER_CARE = "Customer-Care/Remote Access Scam"
    PHISHING_OTP = "Phishing/OTP Fraud"
    SIM_SWAPPING = "SIM Swapping"
    CUSTOMS_HOAX = "Customs Violation Hoax"
    SOCIAL_SCAM = "Friend-in-Need Social Scam"
    KYC_UPDATE = "KYC Update Scam"
    UNKNOWN = "Unknown/Suspicious"
    LEGITIMATE = "Legitimate"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class InputType(str, Enum):
    TEXT = "text"
    URL = "url"
    NETWORK_LOG = "network_log"


# ── Request Schemas ──────────────────────────────────────────────────────────

class AnalyzeTextRequest(BaseModel):
    content: str = Field(..., min_length=10, max_length=10000, description="SMS/Email text content")
    language: Optional[str] = Field("en", description="Language code (en, hi, te, etc.)")

    @validator("content")
    def sanitize_content(cls, v):
        return v.strip()


class AnalyzeURLRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")

    @validator("url")
    def validate_url(cls, v):
        v = v.strip()
        if not v.startswith(("http://", "https://", "www.")):
            raise ValueError("URL must start with http://, https://, or www.")
        return v


class AnalyzeNetworkLogRequest(BaseModel):
    logs: List[Dict[str, Any]] = Field(..., description="Network log entries")
    time_window_minutes: Optional[int] = Field(60, ge=1, le=1440)


class ReportScamRequest(BaseModel):
    analysis_id: Optional[str] = None
    scam_type: str
    risk_level: str
    input_type: str
    explanation: str
    reporter_note: Optional[str] = Field(None, max_length=2000)
    keywords_found: Optional[List[str]] = []
    url_indicators: Optional[Dict[str, Any]] = {}
    anomaly_indicators: Optional[Dict[str, Any]] = {}
    confidence_score: Optional[float] = 0.0


# ── Response Schemas ──────────────────────────────────────────────────────────

class URLAnalysisDetail(BaseModel):
    domain: str
    is_ip_address: bool
    has_suspicious_tld: bool
    has_typosquatting: bool
    has_misleading_keywords: bool
    subdomain_count: int
    path_suspicious: bool
    typosquatting_target: Optional[str] = None
    suspicious_patterns: List[str] = []


class AnomalyDetail(BaseModel):
    total_requests: int
    unique_ips: int
    requests_per_minute: float
    spike_detected: bool
    repeated_failures: bool
    suspicious_endpoints: List[str] = []
    anomaly_score: float


class AnalysisResponse(BaseModel):
    analysis_id: str
    scam_type: str
    confidence_score: float
    risk_level: str
    explanation: str
    keywords_found: List[str] = []
    url_analysis: Optional[URLAnalysisDetail] = None
    anomaly_analysis: Optional[AnomalyDetail] = None
    recommendations: List[str] = []
    input_type: str
    processing_time_ms: float
    timestamp: datetime


class ReportResponse(BaseModel):
    report_id: str
    status: str
    message: str
    created_at: datetime


class ScamReportOut(BaseModel):
    id: str
    report_id: str
    scam_type: str
    confidence_score: float
    risk_level: str
    input_type: str
    explanation: str
    keywords_found: Optional[List[str]] = []
    reporter_note: Optional[str] = None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_analyses: int
    total_reports: int
    scams_by_type: Dict[str, int]
    scams_by_risk: Dict[str, int]
    recent_trend: List[Dict[str, Any]]
    top_keywords: List[Dict[str, Any]]
    avg_confidence: float
