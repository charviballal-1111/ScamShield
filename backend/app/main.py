"""
AI Scam Detection and Reporting System - FastAPI Backend
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
import logging
from datetime import datetime

from app.api.analyze import router as analyze_router
from app.api.reports import router as reports_router
from app.api.stats import router as stats_router
from app.core.database import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AI Scam Detection API",
    description="Analyzes inputs to detect and classify scams using NLP and ML",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router, prefix="/api", tags=["Analysis"])
app.include_router(reports_router, prefix="/api", tags=["Reports"])
app.include_router(stats_router, prefix="/api", tags=["Statistics"])


@app.on_event("startup")
async def startup_event():
    logger.info("Starting AI Scam Detection API...")
    init_db()
    logger.info("Database initialized.")


@app.get("/")
async def root():
    return {
        "message": "AI Scam Detection API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
