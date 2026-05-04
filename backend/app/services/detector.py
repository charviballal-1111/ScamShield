"""
AI/ML Scam Detection Engine
- NLP-based text classification (TF-IDF + pattern matching)
- URL analysis (domain checks, typosquatting detection)
- Network log anomaly detection
"""
import re
import math
import hashlib
import unicodedata
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
from collections import Counter


# ── Scam Pattern Database ─────────────────────────────────────────────────────

SCAM_PATTERNS = {
    "Investment/Crypto Scam": {
        "weight": 1.0,
        "keywords": [
            "guaranteed returns", "guaranteed profit", "double your money", "triple investment",
            "crypto investment", "bitcoin opportunity", "ethereum mining", "NFT profit",
            "high returns", "risk-free investment", "passive income", "financial freedom",
            "limited time offer", "exclusive investment", "pump and dump", "get rich quick",
            "forex trading", "trading signals", "100% profit", "10x returns", "make money fast",
            "investment scheme", "ponzi", "pyramid scheme", "multi-level marketing", "MLM",
            "refer friends", "recruitment bonus", "wealth creation", "financial advisor contact"
        ],
        "patterns": [
            r"\d+[xX×]\s*(returns?|profit|gain)",
            r"(earn|make)\s+\$[\d,]+\s*(per|a)\s*(day|week|month)",
            r"invest\s+(only\s+)?\$[\d,]+",
            r"(guaranteed|assured)\s+\d+%",
            r"bitcoin|ethereum|crypto.*wallet.*send",
        ]
    },
    "Phishing/OTP Fraud": {
        "weight": 1.0,
        "keywords": [
            "verify your account", "account suspended", "click here immediately",
            "your account will be closed", "update your details", "confirm your identity",
            "OTP", "one time password", "enter code", "verification code",
            "bank account suspended", "urgent action required", "click the link",
            "login to verify", "password reset", "security alert", "unusual activity",
            "your card is blocked", "re-verify", "authenticate now",
            "dear customer", "dear user", "valued customer", "billing issue",
        ],
        "patterns": [
            r"(click|tap|open)\s+(here|this\s+link|below)",
            r"(account|card|wallet)\s+(blocked|suspended|locked|disabled)",
            r"(verify|confirm|update)\s+(your\s+)?(account|details|information)",
            r"(enter|provide|share)\s+(your\s+)?(otp|pin|password|cvv)",
            r"http[s]?://[^\s]*\.(xyz|tk|ml|ga|cf|gq|top|info)[^\s]*",
        ]
    },
    "Fake Job/Recruitment Scam": {
        "weight": 0.9,
        "keywords": [
            "work from home", "earn from home", "part time job", "data entry job",
            "no experience required", "immediate joining", "urgent hiring",
            "earn per day", "typing job", "copy paste job", "online job",
            "job offer letter", "appointment letter", "registration fee",
            "training fee", "security deposit", "advance payment",
            "HR manager", "recruitment agency", "job consultancy fee",
            "form filling job", "ad posting job", "simple task earn",
        ],
        "patterns": [
            r"(earn|make)\s+Rs\.?\s*[\d,]+\s*(per|a)\s*(day|hour|week)",
            r"(earn|make)\s+\$[\d,]+\s*(per|a)\s*(day|hour|week)",
            r"(no\s+experience|fresher|no\s+qualification)\s+(required|needed)",
            r"(registration|training|security)\s+(fee|deposit|charge)",
            r"(whatsapp|telegram|signal)\s+(me|us|at|number)",
        ]
    },
    "KYC Update Scam": {
        "weight": 1.0,
        "keywords": [
            "KYC update", "KYC pending", "KYC expired", "know your customer",
            "update KYC", "complete KYC", "bank KYC", "payment KYC",
            "Aadhaar update", "PAN update", "document upload",
            "account will be blocked", "services will be discontinued",
            "immediately update", "last chance", "final warning",
            "NEFT blocked", "UPI blocked", "net banking disabled",
        ],
        "patterns": [
            r"kyc\s+(update|verification|pending|expired)",
            r"(aadhaar|pan|passport)\s+(update|verify|link)",
            r"(bank|account)\s+(will\s+be\s+)?(blocked|suspended|closed)\s+(if|unless)",
            r"(update|complete)\s+(your\s+)?(kyc|details)\s+(within|before|by)",
        ]
    },
    "Customer-Care/Remote Access Scam": {
        "weight": 0.95,
        "keywords": [
            "customer care", "technical support", "helpline number",
            "call us immediately", "refund process", "download app",
            "AnyDesk", "TeamViewer", "QuickSupport", "remote access",
            "screen share", "remote assistance", "we will help you",
            "refund of", "compensation amount", "lottery prize",
            "you have won", "congratulations you won", "claim your prize",
        ],
        "patterns": [
            r"(anydesk|teamviewer|quicksupport|remote\s+desktop)",
            r"(download|install)\s+(this\s+)?(app|software|tool)",
            r"(call|contact)\s+(our\s+)?(helpline|support|number)",
            r"(you\s+have\s+won|congratulations|lucky\s+winner)",
            r"refund\s+of\s+Rs\.?\s*[\d,]+",
        ]
    },
    "SIM Swapping": {
        "weight": 1.0,
        "keywords": [
            "SIM swap", "SIM replacement", "port your number", "MNP",
            "mobile number portability", "network upgrade", "update SIM",
            "new SIM card", "SIM blocked", "recharge failed",
            "send SMS to", "reply with", "last 4 digits",
            "telecom operator", "service provider", "network issue",
        ],
        "patterns": [
            r"(sim\s+swap|sim\s+replacement|port\s+(your\s+)?number)",
            r"(send\s+sms|reply\s+with|text)\s+.*\s+to\s+\d+",
            r"(last|final)\s+\d+\s+digits\s+of\s+(your\s+)?(sim|number|aadhaar)",
            r"(network|service|sim)\s+(upgrade|update|replacement)",
        ]
    },
    "Customs Violation Hoax": {
        "weight": 0.9,
        "keywords": [
            "customs department", "parcel held", "package seized",
            "customs clearance", "pay customs duty", "release your package",
            "courier held", "delivery blocked", "customs fine",
            "illegal item found", "contraband", "customs officer",
            "pay penalty", "customs fee", "international parcel",
            "CBIC", "customs authority", "FedEx customs", "DHL customs",
        ],
        "patterns": [
            r"(parcel|package|courier|shipment)\s+(held|seized|blocked)",
            r"(pay|deposit)\s+(customs|duty|fine|penalty)\s+(of\s+)?(Rs\.?\s*[\d,]+|\$[\d,]+)",
            r"(customs|cbic|revenue\s+department)\s+(officer|authority|official)",
            r"(illegal|contraband|prohibited)\s+(item|goods|material)\s+found",
        ]
    },
    "Friend-in-Need Social Scam": {
        "weight": 0.85,
        "keywords": [
            "I am in trouble", "need urgent help", "send money urgently",
            "stranded", "lost my wallet", "phone stolen", "mugged",
            "hospital emergency", "accident happened", "stuck abroad",
            "need loan", "borrow money", "transfer money",
            "I will return", "pay you back", "urgent transfer",
            "Paytm", "PhonePe", "UPI send", "Google Pay",
        ],
        "patterns": [
            r"(send|transfer|pay)\s+(me\s+)?(Rs\.?\s*[\d,]+|\$[\d,]+)\s+(urgently|immediately|asap)",
            r"(stuck|stranded|trapped)\s+(at|in|abroad|overseas)",
            r"(i\s+am\s+in|facing)\s+(trouble|emergency|crisis|danger)",
            r"(hospital|accident|emergency)\s+(please\s+)?(help|send|transfer)",
        ]
    }
}

# Legitimate indicator keywords
LEGITIMATE_INDICATORS = [
    "terms and conditions", "privacy policy", "unsubscribe",
    "official website", "registered company", "CIN:", "GST:",
    "corporate office", "annual report", "board of directors",
    "regulatory approval", "SEBI registered", "RBI approved",
    "contact@", "support@", "info@", "noreply@",
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
                   ".click", ".download", ".stream", ".racing", ".win",
                   ".loan", ".review", ".science", ".work"]

TYPOSQUATTING_TARGETS = {
    "google": ["g00gle", "go0gle", "googie", "g0ogle", "googl3"],
    "facebook": ["faceb00k", "facebok", "faceboook", "faceb0ok"],
    "amazon": ["amaz0n", "amazzon", "amaazon", "arnaz0n"],
    "paytm": ["pa1tm", "paytm2", "paytml", "paytmm"],
    "sbi": ["sb1", "sbii", "sbl", "s-bi"],
    "hdfc": ["hdtc", "hdfcc", "hdtfc"],
    "icici": ["icicii", "icic1", "lclci"],
    "paypal": ["paypa1", "paypall", "paypa1l"],
    "netflix": ["netfl1x", "nettflix", "netfliix"],
    "microsoft": ["micros0ft", "microsooft", "micosoft"],
}


# ── NLP Text Analyzer ─────────────────────────────────────────────────────────

class NLPScamDetector:
    """TF-IDF style scoring with pattern matching for scam text detection"""

    def __init__(self):
        self.patterns = SCAM_PATTERNS

    def preprocess(self, text: str) -> str:
        text = text.lower()
        text = unicodedata.normalize('NFKD', text)
        text = re.sub(r'[^\w\s@./:-]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def compute_tfidf_score(self, text: str, keywords: List[str]) -> Tuple[float, List[str]]:
        words = text.split()
        doc_len = max(len(words), 1)
        found_keywords = []
        score = 0.0

        for kw in keywords:
            kw_lower = kw.lower()
            count = text.count(kw_lower)
            if count > 0:
                found_keywords.append(kw)
                tf = count / doc_len
                # Simplified IDF boost for rarer, more specific phrases
                idf = math.log(1 + len(kw.split()))
                score += tf * idf * 10

        return score, found_keywords

    def compute_pattern_score(self, text: str, patterns: List[str]) -> Tuple[float, int]:
        matches = 0
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches += 1
        return matches * 0.3, matches

    def check_urgency_markers(self, text: str) -> float:
        urgency_patterns = [
            r'\b(urgent|immediately|asap|right\s+now|don\'t\s+delay|act\s+now)\b',
            r'\b(last\s+chance|limited\s+time|expires?\s+today|final\s+warning)\b',
            r'[A-Z]{4,}',  # ALL CAPS words
            r'!{2,}',       # Multiple exclamation marks
        ]
        score = 0.0
        for p in urgency_patterns:
            if re.search(p, text):
                score += 0.15
        return min(score, 0.4)

    def check_legitimate_signals(self, text: str) -> float:
        score = 0.0
        text_lower = text.lower()
        for indicator in LEGITIMATE_INDICATORS:
            if indicator.lower() in text_lower:
                score += 0.1
        return min(score, 0.5)

    def analyze(self, text: str) -> Dict[str, Any]:
        processed = self.preprocess(text)
        scores = {}
        all_found_keywords = []

        for scam_type, data in self.patterns.items():
            kw_score, found_kws = self.compute_tfidf_score(processed, data["keywords"])
            pattern_score, pattern_count = self.compute_pattern_score(processed, data["patterns"])
            total_score = (kw_score + pattern_score) * data["weight"]
            scores[scam_type] = {
                "score": total_score,
                "keywords": found_kws,
                "pattern_hits": pattern_count
            }
            all_found_keywords.extend(found_kws)

        urgency_boost = self.check_urgency_markers(text)
        legit_penalty = self.check_legitimate_signals(processed)

        best_scam = max(scores, key=lambda k: scores[k]["score"])
        best_score = scores[best_scam]["score"]

        # Normalize to 0-1 confidence
        raw_confidence = min(best_score + urgency_boost - legit_penalty * 0.5, 1.0)
        raw_confidence = max(raw_confidence, 0.0)

        if best_score < 0.05:
            scam_type = "Legitimate"
            confidence = 1.0 - raw_confidence
        else:
            scam_type = best_scam
            confidence = raw_confidence

        return {
            "scam_type": scam_type,
            "confidence_score": round(confidence, 3),
            "keywords_found": list(set(all_found_keywords[:15])),
            "all_scores": {k: round(v["score"], 3) for k, v in scores.items()},
            "input_type": "text"
        }


# ── URL Analyzer ──────────────────────────────────────────────────────────────

class URLAnalyzer:
    """Domain and URL pattern analysis for phishing detection"""

    def analyze(self, url: str) -> Dict[str, Any]:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return self._suspicious_result(url, "Could not parse URL")

        indicators = []
        score = 0.0

        # Check IP address usage
        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', domain))
        if is_ip:
            indicators.append("Uses IP address instead of domain name")
            score += 0.35

        # Check suspicious TLD
        has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            indicators.append(f"Uses suspicious TLD")
            score += 0.3

        # Typosquatting check
        typosquatting_target = None
        base_domain = domain.split(":")[0].replace("www.", "")
        for brand, variants in TYPOSQUATTING_TARGETS.items():
            if any(v in base_domain for v in variants):
                typosquatting_target = brand
                indicators.append(f"Possible typosquatting of '{brand}'")
                score += 0.4
                break
            # Also check Levenshtein-like distance
            if brand in base_domain and brand != base_domain.split(".")[0]:
                indicators.append(f"Domain contains brand name '{brand}' suspiciously")
                score += 0.2

        # Subdomain count
        subdomains = domain.split(".")[:-2] if not is_ip else []
        subdomain_count = len(subdomains)
        if subdomain_count > 2:
            indicators.append(f"Excessive subdomains ({subdomain_count})")
            score += 0.2

        # Misleading keywords in domain
        misleading_keywords = ["secure", "login", "verify", "update", "account",
                               "banking", "payment", "support", "helpdesk", "official"]
        has_misleading_keywords = any(kw in base_domain for kw in misleading_keywords)
        if has_misleading_keywords:
            indicators.append("Domain contains trust-inducing keywords")
            score += 0.25

        # Path analysis
        suspicious_path_terms = ["login", "verify", "update", "confirm", "secure",
                                  "account", "password", "otp", "kyc", "auth"]
        path_suspicious = any(term in path or term in query for term in suspicious_path_terms)
        if path_suspicious:
            indicators.append("Suspicious path/query parameters")
            score += 0.15

        # URL length check
        if len(url) > 100:
            indicators.append("Unusually long URL")
            score += 0.1

        # HTTP (not HTTPS)
        if url.startswith("http://"):
            indicators.append("Uses insecure HTTP protocol")
            score += 0.15

        confidence = min(score, 1.0)
        scam_type = "Phishing/OTP Fraud" if confidence > 0.3 else "Legitimate"

        return {
            "scam_type": scam_type,
            "confidence_score": round(confidence, 3),
            "keywords_found": indicators,
            "url_analysis": {
                "domain": domain,
                "is_ip_address": is_ip,
                "has_suspicious_tld": has_suspicious_tld,
                "has_typosquatting": typosquatting_target is not None,
                "has_misleading_keywords": has_misleading_keywords,
                "subdomain_count": subdomain_count,
                "path_suspicious": path_suspicious,
                "typosquatting_target": typosquatting_target,
                "suspicious_patterns": indicators
            },
            "input_type": "url"
        }

    def _suspicious_result(self, url: str, reason: str) -> Dict[str, Any]:
        return {
            "scam_type": "Unknown/Suspicious",
            "confidence_score": 0.6,
            "keywords_found": [reason],
            "url_analysis": {
                "domain": url, "is_ip_address": False,
                "has_suspicious_tld": True, "has_typosquatting": False,
                "has_misleading_keywords": False, "subdomain_count": 0,
                "path_suspicious": False, "typosquatting_target": None,
                "suspicious_patterns": [reason]
            },
            "input_type": "url"
        }


# ── Network Log Anomaly Detector ──────────────────────────────────────────────

class NetworkAnomalyDetector:
    """Statistical anomaly detection on network traffic logs"""

    SUSPICIOUS_ENDPOINTS = [
        "/transfer", "/send", "/pay", "/withdraw", "/otp",
        "/verify", "/confirm", "/update", "/kyc", "/password",
        "/login", "/auth", "/token", "/session"
    ]

    def analyze(self, logs: List[Dict], time_window_minutes: int = 60) -> Dict[str, Any]:
        if not logs:
            return self._empty_result()

        ips = [log.get("ip", log.get("source_ip", "unknown")) for log in logs]
        endpoints = [log.get("endpoint", log.get("path", "/")) for log in logs]
        status_codes = [log.get("status_code", log.get("status", 200)) for log in logs]
        timestamps = [log.get("timestamp", log.get("time", "")) for log in logs]

        total_requests = len(logs)
        unique_ips = len(set(ips))
        requests_per_minute = total_requests / max(time_window_minutes, 1)

        # Detect traffic spikes (>50 req/min is suspicious)
        spike_detected = requests_per_minute > 50

        # Detect brute force / repeated failures
        failure_codes = [s for s in status_codes if str(s).startswith(("4", "5"))]
        failure_rate = len(failure_codes) / max(total_requests, 1)
        repeated_failures = failure_rate > 0.3

        # Find suspicious endpoint hits
        suspicious_hits = []
        for ep in endpoints:
            ep_lower = str(ep).lower()
            for sus_ep in self.SUSPICIOUS_ENDPOINTS:
                if sus_ep in ep_lower:
                    suspicious_hits.append(ep)
                    break

        # IP concentration (one IP making too many requests)
        ip_counts = Counter(ips)
        top_ip_share = ip_counts.most_common(1)[0][1] / max(total_requests, 1) if ip_counts else 0
        concentrated_traffic = top_ip_share > 0.5 and total_requests > 10

        # Compute anomaly score
        anomaly_score = 0.0
        if spike_detected:
            anomaly_score += 0.3
        if repeated_failures:
            anomaly_score += 0.25
        if suspicious_hits:
            anomaly_score += min(len(suspicious_hits) / 5 * 0.3, 0.3)
        if concentrated_traffic:
            anomaly_score += 0.25
        if unique_ips == 1 and total_requests > 100:
            anomaly_score += 0.2

        anomaly_score = min(anomaly_score, 1.0)

        scam_type = "Customer-Care/Remote Access Scam" if anomaly_score > 0.5 else (
            "Unknown/Suspicious" if anomaly_score > 0.2 else "Legitimate"
        )

        indicators = []
        if spike_detected:
            indicators.append(f"Traffic spike: {requests_per_minute:.1f} req/min")
        if repeated_failures:
            indicators.append(f"High failure rate: {failure_rate:.0%}")
        if suspicious_hits:
            indicators.append(f"Suspicious endpoints hit: {len(set(suspicious_hits))}")
        if concentrated_traffic:
            indicators.append(f"Single IP making {top_ip_share:.0%} of requests")

        return {
            "scam_type": scam_type,
            "confidence_score": round(anomaly_score, 3),
            "keywords_found": indicators,
            "anomaly_analysis": {
                "total_requests": total_requests,
                "unique_ips": unique_ips,
                "requests_per_minute": round(requests_per_minute, 2),
                "spike_detected": spike_detected,
                "repeated_failures": repeated_failures,
                "suspicious_endpoints": list(set(suspicious_hits))[:10],
                "anomaly_score": round(anomaly_score, 3)
            },
            "input_type": "network_log"
        }

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "scam_type": "Legitimate",
            "confidence_score": 0.0,
            "keywords_found": [],
            "anomaly_analysis": {
                "total_requests": 0, "unique_ips": 0,
                "requests_per_minute": 0.0, "spike_detected": False,
                "repeated_failures": False, "suspicious_endpoints": [],
                "anomaly_score": 0.0
            },
            "input_type": "network_log"
        }


# ── Risk Level & Recommendation Engine ───────────────────────────────────────

def determine_risk_level(confidence: float, scam_type: str) -> str:
    if scam_type == "Legitimate":
        return "Low"
    if confidence >= 0.8:
        return "Critical"
    elif confidence >= 0.6:
        return "High"
    elif confidence >= 0.35:
        return "Medium"
    else:
        return "Low"


def generate_explanation(scam_type: str, keywords: List[str], confidence: float,
                          input_type: str, extra: Optional[Dict] = None) -> str:
    if scam_type == "Legitimate":
        return "No significant scam indicators found. The content appears legitimate."

    base = f"This {input_type} shows characteristics of **{scam_type}** with {confidence:.0%} confidence. "

    if keywords:
        top_kws = keywords[:5]
        base += f"Key indicators detected: {', '.join(top_kws[:3])}. "

    type_explanations = {
        "Investment/Crypto Scam": "Promises of unrealistic returns, investment opportunities, or cryptocurrency schemes are common fraud tactics.",
        "Phishing/OTP Fraud": "This content attempts to steal credentials or OTPs by impersonating legitimate services.",
        "Fake Job/Recruitment Scam": "Fraudulent job offers requesting upfront fees or personal data are a major scam category.",
        "KYC Update Scam": "Fake KYC update requests are used to harvest banking credentials and personal documents.",
        "Customer-Care/Remote Access Scam": "Fake support services may attempt to gain remote access to your device.",
        "SIM Swapping": "SIM swap attacks allow fraudsters to hijack your phone number and bypass 2FA.",
        "Customs Violation Hoax": "Fake customs notices demand payments for fictitious parcel releases.",
        "Friend-in-Need Social Scam": "Social engineering via fake distress messages to extract money transfers.",
        "Unknown/Suspicious": "Suspicious patterns detected. Exercise caution before proceeding."
    }

    base += type_explanations.get(scam_type, "Exercise caution with this content.")
    return base


def generate_recommendations(scam_type: str, risk_level: str) -> List[str]:
    common = [
        "Do not share OTPs, passwords, or banking credentials with anyone",
        "Verify the sender's identity through official channels",
    ]

    type_recs = {
        "Investment/Crypto Scam": [
            "Never invest based on unsolicited messages",
            "Check SEBI registration before investing",
            "Report to cybercrime.gov.in or call 1930",
        ],
        "Phishing/OTP Fraud": [
            "Do not click links in suspicious emails/SMS",
            "Check URL authenticity before entering credentials",
            "Enable 2FA on all banking accounts",
        ],
        "Fake Job/Recruitment Scam": [
            "Never pay fees for job offers",
            "Verify company existence on MCA India",
            "Report to local police and cybercrime portal",
        ],
        "KYC Update Scam": [
            "KYC updates are never done via SMS/email links",
            "Visit your bank branch directly for KYC",
            "Call your bank's official number to verify",
        ],
        "Customer-Care/Remote Access Scam": [
            "Never install remote access apps on request",
            "Official companies never ask for remote control",
            "Hang up and call the official number",
        ],
        "SIM Swapping": [
            "Contact your telecom operator immediately",
            "Set a SIM lock/PIN with your operator",
            "Check your phone for service loss",
        ],
    }

    recs = common + type_recs.get(scam_type, ["Report to cybercrime.gov.in or call 1930"])
    if risk_level in ("High", "Critical"):
        recs.insert(0, "⚠️ HIGH RISK: Do not engage with this content")
    return recs[:5]


# ── Anonymization ─────────────────────────────────────────────────────────────

def anonymize_input(content: str) -> str:
    """Create a SHA-256 hash of content for storage without storing PII"""
    return hashlib.sha256(content.encode()).hexdigest()[:16]
