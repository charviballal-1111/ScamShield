# 🛡 ScamShield — AI-Based Scam Detection & Reporting System

ScamShield is an AI-powered system that detects, analyzes, and helps report scams across text messages, URLs, and network activity in real time.

---

## 📁 Project Structure

```
scam-detection/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entry point
│   │   ├── api/
│   │   │   ├── analyze.py       # POST /analyze/* endpoints
│   │   │   ├── reports.py       # POST /report, GET /reports
│   │   │   └── stats.py         # GET /stats
│   │   ├── core/
│   │   │   └── database.py      # SQLAlchemy models + DB setup
│   │   ├── models/
│   │   │   └── schemas.py       # Pydantic request/response schemas
│   │   └── services/
│   │       └── detector.py      # AI/ML detection engine
│   ├── seed_data.py             # Populate DB with sample data
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   └── ScamShieldApp.jsx        # Complete React application
├── data/
│   ├── sample_reports.json      # Sample scam report dataset
│   └── sample_network_log.json  # Sample network log for testing
└── README.md
```

---

## 🚀 Quick Start

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env if needed (default uses SQLite)

# Seed database with sample data
python seed_data.py

# Start the API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API available at: http://localhost:8000  
Swagger docs: http://localhost:8000/docs

---

### Frontend Setup

**Option A — Use the React artifact directly in Claude.ai**
The `ScamShieldApp.jsx` file works as a standalone Claude artifact with full mock AI built in (no backend needed).

**Option B — Run with Vite**
```bash
cd frontend

# Initialize a Vite + React project
npm create vite@latest . -- --template react
npm install

# Replace src/App.jsx with ScamShieldApp.jsx content
cp ../ScamShieldApp.jsx src/App.jsx

# Start dev server
npm run dev
```

Frontend available at: http://localhost:5173

---

## 🧠 AI/ML Detection Engine

### 1. NLP Text Classifier (`detector.py`)
- **TF-IDF scoring** with weighted keyword matching
- **Regex pattern library** for 8 scam categories
- **Urgency marker detection** (ALL CAPS, multiple !, "urgent", "immediately")
- **Legitimate signal checking** (official terms, unsubscribe links, etc.)
- Covers: Investment Scams, Phishing, KYC Fraud, Job Scams, Remote Access, SIM Swap, Customs Hoax, Social Scams

### 2. URL Analyzer
- IP address detection (direct IP URLs are suspicious)
- Suspicious TLD checking (`.xyz`, `.tk`, `.ml`, `.ga`, etc.)
- Typosquatting detection for 10+ major brands
- Subdomain flooding detection
- Trust-keyword abuse detection (`secure-login`, `bank-verify`, etc.)
- HTTP vs HTTPS protocol check

### 3. Network Log Anomaly Detector
- Traffic spike detection (>50 req/min threshold)
- Brute force detection (failure rate >30%)
- Suspicious endpoint monitoring (`/transfer`, `/otp`, `/kyc`, etc.)
- Single-IP concentration analysis

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze/text` | Analyze SMS/email text |
| `POST` | `/api/analyze/url` | Analyze a URL |
| `POST` | `/api/analyze/network` | Analyze network logs |
| `POST` | `/api/report` | Submit a scam report |
| `GET` | `/api/reports` | List reports (filterable) |
| `GET` | `/api/reports/{id}` | Get specific report |
| `PATCH` | `/api/reports/{id}/status` | Update report status |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/stats/summary` | Quick summary counts |
| `GET` | `/health` | Health check |

### Example Request — Text Analysis
```bash
curl -X POST http://localhost:8000/api/analyze/text \
  -H "Content-Type: application/json" \
  -d '{
    "content": "URGENT: Your KYC is pending. Account will be blocked. Click: http://secure-bank.xyz/update"
  }'
```

### Example Response
```json
{
  "analysis_id": "ABC123DEF456",
  "scam_type": "KYC Update Scam",
  "confidence_score": 0.87,
  "risk_level": "High",
  "explanation": "This text shows characteristics of KYC Update Scam...",
  "keywords_found": ["KYC update", "account will be blocked", "urgent action"],
  "recommendations": [
    "KYC updates are never done via SMS/email links",
    "Visit your bank branch directly for KYC"
  ],
  "processing_time_ms": 12.4,
  "timestamp": "2024-06-01T10:00:00"
}
```

### Example Request — URL Analysis
```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-hdtfc-login.xyz/verify-account"}'
```

### Example Request — Network Log Analysis
```bash
curl -X POST http://localhost:8000/api/analyze/network \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {"ip": "192.168.1.1", "endpoint": "/login", "status_code": 401},
      {"ip": "192.168.1.1", "endpoint": "/login", "status_code": 401},
      {"ip": "192.168.1.1", "endpoint": "/otp/verify", "status_code": 400}
    ],
    "time_window_minutes": 5
  }'
```

---

## 📊 Scam Categories Detected

| Category | Detection Method |
|----------|-----------------|
| Investment/Crypto Scam | NLP keywords + patterns |
| Phishing/OTP Fraud | NLP + URL analysis |
| KYC Update Scam | NLP keywords + urgency |
| Fake Job/Recruitment Scam | NLP keywords + patterns |
| Customer-Care/Remote Access | NLP + anomaly detection |
| SIM Swapping | NLP patterns |
| Customs Violation Hoax | NLP keywords |
| Friend-in-Need Social Scam | NLP social patterns |

---

## 🗄️ Database

**Development**: SQLite (`scam_detection.db` — created automatically)

**Production** (PostgreSQL):
```bash
# In .env:
DATABASE_URL=postgresql://user:password@localhost:5432/scam_db

# Create database
createdb scam_db
```

**Schema**:
- `scam_reports` — Submitted reports with anonymized hashes
- `analysis_logs` — All analysis requests for statistics

---

## 🔐 Security & Privacy

- **No PII stored** — Input content is SHA-256 hashed before storage
- **Rate limiting** — 30 requests/minute per IP (configurable)
- **CORS** configured for localhost development
- **Input validation** — Pydantic schemas on all endpoints
- **SQL injection protection** — SQLAlchemy ORM

---

## 🌍 Sample Test Inputs

### Scam Text (KYC)
```
URGENT: Dear Customer, your KYC is pending. Your SBI account will be blocked within 24 hours. Click here to update immediately: http://secure-sbi-kyc.xyz/update
```

### Scam Text (Investment)
```
💰 Guaranteed 3x returns on crypto! Invest just ₹5000 and earn ₹15000 in 7 days! Limited time offer. WhatsApp us now!
```

### Suspicious URL
```
http://secure-hdtfc-login.xyz/verify-account?token=abc
```

### Network Log (brute force)
See `data/sample_network_log.json`

---

## 📞 Cybercrime Reporting Resources

- **National Cybercrime Helpline**: 1930
- **Cybercrime Portal**: https://cybercrime.gov.in
- **RBI Ombudsman**: https://rbi.org.in/ombudsman
- **CERT-In**: https://www.cert-in.org.in

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React + Recharts (self-contained) |
| Backend | Python 3.11 + FastAPI |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | SQLAlchemy 2.0 |
| Validation | Pydantic v2 |
| Rate Limiting | SlowAPI |
| AI/ML | Custom TF-IDF + Pattern Matching |

