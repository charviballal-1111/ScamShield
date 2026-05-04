import { useState, useEffect, useCallback, useRef } from "react";

// ── Constants ──────────────────────────────────────────────────────────────
const API_BASE = "http://localhost:8000/api";

const SCAM_TYPES = [
  "Investment/Crypto Scam",
  "Phishing/OTP Fraud",
  "Fake Job/Recruitment Scam",
  "KYC Update Scam",
  "Customer-Care/Remote Access Scam",
  "SIM Swapping",
  "Customs Violation Hoax",
  "Friend-in-Need Social Scam",
  "Unknown/Suspicious",
  "Legitimate",
];

const RISK_COLORS = {
  Critical: { bg: "#1a0a0a", text: "#ff4d4d", badge: "#3d0f0f", border: "#7a1f1f" },
  High: { bg: "#1a1000", text: "#ff9500", badge: "#3d2500", border: "#7a4d00" },
  Medium: { bg: "#0d1a00", text: "#88d400", badge: "#1f3d00", border: "#3d7a00" },
  Low: { bg: "#001a1a", text: "#00d4aa", badge: "#003d3d", border: "#007a6e" },
};

const SCAM_ICONS = {
  "Investment/Crypto Scam": "₿",
  "Phishing/OTP Fraud": "🎣",
  "Fake Job/Recruitment Scam": "💼",
  "KYC Update Scam": "🪪",
  "Customer-Care/Remote Access Scam": "🖥",
  "SIM Swapping": "📱",
  "Customs Violation Hoax": "📦",
  "Friend-in-Need Social Scam": "👤",
  "Unknown/Suspicious": "⚠",
  "Legitimate": "✓",
};

const normalizeNetworkLogs = (content) => {
  const parsed = typeof content === "string" ? JSON.parse(content) : content;
  return Array.isArray(parsed) ? parsed : [parsed];
};

// ── Mock API (works without backend) ──────────────────────────────────────
const mockAnalyze = async (type, content) => {
  await new Promise(r => setTimeout(r, 1200 + Math.random() * 800));
  const scamTypes = SCAM_TYPES.filter(t => t !== "Legitimate");
  
  const textPatterns = [
    { match: /kyc|verify.*account|account.*block/i, type: "KYC Update Scam", conf: 0.87 },
    { match: /crypto|bitcoin|invest.*return|guaranteed.*profit/i, type: "Investment/Crypto Scam", conf: 0.91 },
    { match: /otp|click.*link|password.*reset|verify.*identity/i, type: "Phishing/OTP Fraud", conf: 0.83 },
    { match: /work.*home|earn.*day|job.*offer|registration.*fee/i, type: "Fake Job/Recruitment Scam", conf: 0.78 },
    { match: /anydesk|teamviewer|remote.*access|refund.*process/i, type: "Customer-Care/Remote Access Scam", conf: 0.89 },
    { match: /sim.*swap|port.*number|network.*upgrade/i, type: "SIM Swapping", conf: 0.82 },
    { match: /customs|parcel.*held|package.*seized/i, type: "Customs Violation Hoax", conf: 0.76 },
    { match: /stranded|send.*money|need.*help.*urgent/i, type: "Friend-in-Need Social Scam", conf: 0.71 },
  ];

  const urlPatterns = [
    { match: /\.xyz|\.tk|\.ml|\.ga/i, type: "Phishing/OTP Fraud", conf: 0.85 },
    { match: /secure.*login|bank.*update|verify.*account/i, type: "Phishing/OTP Fraud", conf: 0.88 },
    { match: /g00gle|amaz0n|paypa1|hdtfc/i, type: "Phishing/OTP Fraud", conf: 0.94 },
  ];

  let scamType = "Legitimate";
  let confidence = 0.12;
  let keywords = [];

  const input = String(content).toLowerCase();

  if (type === "url") {
    for (const p of urlPatterns) {
      if (p.match.test(input)) {
        scamType = p.type;
        confidence = p.conf + (Math.random() * 0.06 - 0.03);
        keywords = ["Suspicious domain pattern", "Typosquatting detected", "Misleading keywords"];
        break;
      }
    }
    if (scamType === "Legitimate") {
      scamType = Math.random() > 0.6 ? "Phishing/OTP Fraud" : "Legitimate";
      confidence = scamType === "Legitimate" ? 0.08 + Math.random() * 0.1 : 0.45 + Math.random() * 0.3;
      keywords = scamType !== "Legitimate" ? ["Suspicious URL structure", "Non-standard TLD"] : [];
    }
  } else if (type === "network") {
    const logs = normalizeNetworkLogs(content);
    const failures = logs.filter(l => String(l.status_code || l.status || 200).startsWith("4")).length;
    const suspiciousEps = logs.filter(l => /login|transfer|otp|kyc|password|unknown domain/i.test(`${l.endpoint || ""} ${l.activity || ""}`)).length;
    const rapidRequests = logs.filter(l => Number(l.requests_per_minute || 0) >= 500).length;
    const suspiciousStatus = logs.filter(l => /suspicious|blocked|malicious/i.test(String(l.status || ""))).length;
    if (failures / logs.length > 0.3 || suspiciousEps > 3 || rapidRequests > 0 || suspiciousStatus > 0) {
      scamType = "Customer-Care/Remote Access Scam";
      confidence = 0.6 + Math.min((failures + rapidRequests + suspiciousStatus) / logs.length * 0.18, 0.35);
      keywords = [
        ...(failures ? [`${failures} failed requests`] : []),
        ...(suspiciousEps ? [`${suspiciousEps} suspicious endpoint/activity matches`] : []),
        ...(rapidRequests ? [`${rapidRequests} rapid request spike detected`] : []),
        ...(suspiciousStatus ? [`${suspiciousStatus} suspicious status flag`] : []),
        "Traffic anomaly detected",
      ];
    }
  } else {
    for (const p of textPatterns) {
      if (p.match.test(input)) {
        scamType = p.type;
        confidence = p.conf + (Math.random() * 0.06 - 0.03);
        const scamData = {
          "KYC Update Scam": ["KYC update", "account will be blocked", "urgent action"],
          "Investment/Crypto Scam": ["guaranteed returns", "crypto investment", "double your money"],
          "Phishing/OTP Fraud": ["verify your account", "click here", "OTP code"],
          "Fake Job/Recruitment Scam": ["work from home", "earn per day", "registration fee"],
          "Customer-Care/Remote Access Scam": ["AnyDesk", "remote access", "refund process"],
          "SIM Swapping": ["SIM swap", "network upgrade", "last 4 digits"],
          "Customs Violation Hoax": ["customs department", "parcel held", "pay duty"],
          "Friend-in-Need Social Scam": ["stranded", "need help urgently", "send money"],
        };
        keywords = scamData[scamType] || [];
        break;
      }
    }
  }

  const risk = confidence >= 0.8 ? "Critical" : confidence >= 0.6 ? "High" : confidence >= 0.35 ? "Medium" : "Low";

  const explanations = {
    "Legitimate": "No significant scam indicators found. The content appears to be legitimate.",
    "KYC Update Scam": "This message uses KYC-related urgency tactics to harvest banking credentials. Banks never request KYC via SMS/email links.",
    "Investment/Crypto Scam": "Promises of guaranteed or unusually high returns are hallmarks of investment fraud. No legitimate investment guarantees profits.",
    "Phishing/OTP Fraud": "This content attempts to steal sensitive credentials by impersonating legitimate services. The URL/text contains known phishing indicators.",
    "Fake Job/Recruitment Scam": "Fraudulent job offers typically request upfront fees. Legitimate employers never charge candidates for recruitment.",
    "Customer-Care/Remote Access Scam": "Requests for remote access software installation are a major red flag. Legitimate support teams do not need AnyDesk/TeamViewer access.",
    "SIM Swapping": "SIM swap attacks hijack your phone number to bypass two-factor authentication. Never share SIM details via SMS.",
    "Customs Violation Hoax": "Fake customs notices demand payments for fictitious parcel releases. Customs authorities communicate through official registered mail.",
    "Friend-in-Need Social Scam": "This message uses social engineering to impersonate a distressed contact. Always verify via a separate communication channel before transferring money.",
  };

  return {
    analysis_id: Math.random().toString(36).substr(2, 12).toUpperCase(),
    scam_type: scamType,
    confidence_score: Math.min(Math.max(confidence, 0.01), 0.99),
    risk_level: risk,
    explanation: explanations[scamType] || explanations["Legitimate"],
    keywords_found: keywords,
    input_type: type,
    processing_time_ms: 800 + Math.random() * 600,
    timestamp: new Date().toISOString(),
    recommendations: scamType === "Legitimate" ? ["Content appears safe. Exercise general caution online."] : [
      "Do not share OTPs or banking credentials",
      "Verify sender identity through official channels",
      "Report to cybercrime.gov.in or call 1930",
      "Block and report the sender immediately",
    ],
  };
};

const MOCK_REPORTS = [
  { id: "r1", report_id: "SCM-20240601-AA1B2C", scam_type: "Investment/Crypto Scam", confidence_score: 0.92, risk_level: "Critical", input_type: "text", status: "confirmed", created_at: "2024-06-01T10:23:45", explanation: "Crypto investment scam with guaranteed returns promise." },
  { id: "r2", report_id: "SCM-20240602-BB3D4E", scam_type: "Phishing/OTP Fraud", confidence_score: 0.88, risk_level: "High", input_type: "url", status: "confirmed", created_at: "2024-06-02T14:11:02", explanation: "Phishing URL impersonating SBI bank login." },
  { id: "r3", report_id: "SCM-20240603-CC5F6G", scam_type: "KYC Update Scam", confidence_score: 0.79, risk_level: "High", input_type: "text", status: "pending", created_at: "2024-06-03T09:55:30", explanation: "KYC fraud threatening account blockage." },
  { id: "r4", report_id: "SCM-20240604-DD7H8I", scam_type: "Fake Job/Recruitment Scam", confidence_score: 0.81, risk_level: "High", input_type: "text", status: "confirmed", created_at: "2024-06-04T16:42:11", explanation: "Data entry job scam requesting registration fee." },
  { id: "r5", report_id: "SCM-20240605-EE9J0K", scam_type: "Customer-Care/Remote Access Scam", confidence_score: 0.87, risk_level: "Critical", input_type: "text", status: "confirmed", created_at: "2024-06-05T11:20:55", explanation: "Fake Amazon support requesting AnyDesk installation." },
  { id: "r6", report_id: "SCM-20240606-FF1L2M", scam_type: "SIM Swapping", confidence_score: 0.74, risk_level: "High", input_type: "text", status: "reviewed", created_at: "2024-06-06T08:35:22", explanation: "SIM swap attempt via SMS." },
  { id: "r7", report_id: "SCM-20240607-GG3N4O", scam_type: "Customs Violation Hoax", confidence_score: 0.83, risk_level: "High", input_type: "text", status: "pending", created_at: "2024-06-07T13:18:44", explanation: "Fake customs fine demand." },
  { id: "r8", report_id: "SCM-20240608-HH5P6Q", scam_type: "Friend-in-Need Social Scam", confidence_score: 0.69, risk_level: "Medium", input_type: "text", status: "dismissed", created_at: "2024-06-08T17:05:33", explanation: "Facebook message requesting urgent money transfer." },
];

const MOCK_STATS = {
  total_analyses: 2847,
  total_reports: 1293,
  scams_by_type: {
    "Phishing/OTP Fraud": 412, "Investment/Crypto Scam": 318, "KYC Update Scam": 267,
    "Fake Job/Recruitment Scam": 198, "Customer-Care/Remote Access Scam": 145,
    "SIM Swapping": 89, "Customs Violation Hoax": 76, "Friend-in-Need Social Scam": 54,
  },
  scams_by_risk: { Critical: 289, High: 541, Medium: 334, Low: 129 },
  recent_trend: [
    { date: "Apr 24", count: 38 }, { date: "Apr 25", count: 52 }, { date: "Apr 26", count: 41 },
    { date: "Apr 27", count: 67 }, { date: "Apr 28", count: 58 }, { date: "Apr 29", count: 73 },
    { date: "Apr 30", count: 84 },
  ],
  avg_confidence: 0.78,
};

const ACTIVITY_STORAGE_KEY = "scamshield_user_activity";
const STORAGE_RESET_KEY = "scamshield_storage_reset_applied";
const STORAGE_RESET_VERSION = "2026-05-04-clear-dashboard";

const clearLocalStorageOnce = () => {
  if (typeof window === "undefined") return;
  if (localStorage.getItem(STORAGE_RESET_KEY) === STORAGE_RESET_VERSION) return;
  localStorage.clear();
  localStorage.setItem(STORAGE_RESET_KEY, STORAGE_RESET_VERSION);
};

clearLocalStorageOnce();

const emptyActivity = () => ({ analyses: [], reports: [] });

const readUserActivity = () => {
  if (typeof window === "undefined") return emptyActivity();
  try {
    const stored = JSON.parse(localStorage.getItem(ACTIVITY_STORAGE_KEY) || "{}");
    return {
      analyses: Array.isArray(stored.analyses) ? stored.analyses : [],
      reports: Array.isArray(stored.reports) ? stored.reports : [],
    };
  } catch {
    return emptyActivity();
  }
};

const riskCounts = () => ({ Critical: 0, High: 0, Medium: 0, Low: 0 });

const uniqueBy = (items, getKey) => {
  const seen = new Set();
  return items.filter(item => {
    const key = getKey(item);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const buildUserStats = ({ analyses, reports }) => {
  const uniqueAnalyses = uniqueBy(analyses, item => item.analysis_id || item.id);
  const uniqueReports = uniqueBy(reports, item => item.report_id || item.id);
  const scamsByType = {};
  const scamsByRisk = riskCounts();
  const lastSevenDays = Array.from({ length: 7 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (6 - i));
    return {
      key: date.toISOString().slice(0, 10),
      label: date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      count: 0,
    };
  });

  uniqueAnalyses.forEach(item => {
    if (item.scam_type && item.scam_type !== "Legitimate") {
      scamsByType[item.scam_type] = (scamsByType[item.scam_type] || 0) + 1;
    }
    if (item.risk_level && scamsByRisk[item.risk_level] !== undefined) {
      scamsByRisk[item.risk_level] += 1;
    }
    const day = new Date(item.created_at || item.timestamp).toISOString().slice(0, 10);
    const trendDay = lastSevenDays.find(d => d.key === day);
    if (trendDay) trendDay.count += 1;
  });

  const avgConfidence = uniqueAnalyses.length
    ? uniqueAnalyses.reduce((sum, item) => sum + Number(item.confidence_score || 0), 0) / uniqueAnalyses.length
    : 0;

  return {
    total_analyses: uniqueAnalyses.length,
    total_reports: uniqueReports.length,
    scams_by_type: scamsByType,
    scams_by_risk: scamsByRisk,
    recent_trend: lastSevenDays.map(({ label, count }) => ({ date: label, count })),
    avg_confidence: avgConfidence,
  };
};

const buildRecentAlerts = ({ analyses, reports }) => {
  const uniqueReports = uniqueBy(reports, item => item.report_id || item.id);
  const reportAnalysisIds = new Set(uniqueReports.map(report => report.analysis_id).filter(Boolean));
  const reportAlerts = uniqueReports.map(report => ({ ...report, source: "report" }));
  const analysisAlerts = uniqueBy(analyses, item => item.analysis_id || item.id)
    .filter(item => item.scam_type !== "Legitimate")
    .filter(item => !reportAnalysisIds.has(item.analysis_id))
    .map(item => ({
      ...item,
      id: item.analysis_id,
      report_id: item.analysis_id,
      status: "analyzed",
      created_at: item.created_at || item.timestamp,
      source: "analysis",
    }));

  return [...reportAlerts, ...analysisAlerts]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5);
};

const formatDateTime = (value) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString([], {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const useIsMobile = () => {
  const getIsMobile = () => typeof window !== "undefined" && window.matchMedia("(max-width: 760px)").matches;
  const [isMobile, setIsMobile] = useState(getIsMobile);

  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    const media = window.matchMedia("(max-width: 760px)");
    const update = () => setIsMobile(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return isMobile;
};

// ── Styles ─────────────────────────────────────────────────────────────────
const S = {
  app: {
    minHeight: "100vh",
    background: "#080b0f",
    color: "#e2e8f0",
    fontFamily: "'Syne', 'Space Grotesk', sans-serif",
    display: "flex",
  },
  sidebar: {
    width: 240,
    minHeight: "100vh",
    background: "#0d1117",
    borderRight: "1px solid #1e2533",
    display: "flex",
    flexDirection: "column",
    padding: "24px 0",
    flexShrink: 0,
    position: "sticky",
    top: 0,
    height: "100vh",
    overflowY: "auto",
  },
  main: { flex: 1, padding: "32px 40px", overflowX: "hidden", maxWidth: 1200 },
  logo: {
    padding: "0 24px 24px",
    borderBottom: "1px solid #1e2533",
    marginBottom: 8,
  },
  navItem: (active) => ({
    display: "flex", alignItems: "center", gap: 12,
    padding: "11px 24px", cursor: "pointer",
    color: active ? "#00d4aa" : "#94a3b8",
    background: active ? "rgba(0,212,170,0.08)" : "transparent",
    borderLeft: active ? "2px solid #00d4aa" : "2px solid transparent",
    fontSize: 14, fontWeight: active ? 600 : 400,
    transition: "all 0.15s", userSelect: "none",
  }),
  card: {
    background: "#0d1117",
    border: "1px solid #1e2533",
    borderRadius: 12,
    padding: "24px",
  },
  statCard: (color) => ({
    background: "#0d1117",
    border: `1px solid ${color}40`,
    borderRadius: 12,
    padding: "20px 24px",
    borderLeft: `3px solid ${color}`,
  }),
  btn: (variant = "primary") => ({
    padding: "10px 20px",
    borderRadius: 8,
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 14,
    transition: "all 0.15s",
    ...(variant === "primary" ? {
      background: "linear-gradient(135deg, #00d4aa, #0099cc)",
      color: "#080b0f",
    } : variant === "danger" ? {
      background: "rgba(255,77,77,0.15)",
      color: "#ff4d4d",
      border: "1px solid #7a1f1f",
    } : {
      background: "rgba(255,255,255,0.05)",
      color: "#e2e8f0",
      border: "1px solid #1e2533",
    }),
  }),
  input: {
    width: "100%",
    background: "#080b0f",
    border: "1px solid #1e2533",
    borderRadius: 8,
    padding: "12px 16px",
    color: "#e2e8f0",
    fontSize: 14,
    outline: "none",
    boxSizing: "border-box",
    fontFamily: "inherit",
  },
  badge: (risk) => {
    const c = RISK_COLORS[risk] || RISK_COLORS.Low;
    return {
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "3px 10px", borderRadius: 20,
      fontSize: 11, fontWeight: 700, letterSpacing: "0.05em",
      background: c.badge, color: c.text, border: `1px solid ${c.border}`,
    };
  },
  h1: { fontSize: 28, fontWeight: 700, margin: "0 0 4px", letterSpacing: "-0.02em" },
  h2: { fontSize: 20, fontWeight: 700, margin: "0 0 16px", letterSpacing: "-0.01em" },
  label: { fontSize: 12, color: "#64748b", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8, display: "block" },
};

// ── Mini Components ────────────────────────────────────────────────────────
function Toast({ toasts, remove }) {
  return (
    <div style={{ position: "fixed", top: 20, right: 20, zIndex: 9999, display: "flex", flexDirection: "column", gap: 8 }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          background: t.type === "error" ? "#1a0a0a" : t.type === "warn" ? "#1a1000" : "#001a13",
          border: `1px solid ${t.type === "error" ? "#7a1f1f" : t.type === "warn" ? "#7a4d00" : "#007a6e"}`,
          borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", gap: 10,
          fontSize: 14, color: "#e2e8f0", minWidth: 280, maxWidth: 380,
          animation: "slideIn 0.2s ease",
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        }}>
          <span style={{ fontSize: 18 }}>{t.type === "error" ? "🚨" : t.type === "warn" ? "⚠️" : "✅"}</span>
          <span style={{ flex: 1 }}>{t.message}</span>
          <span onClick={() => remove(t.id)} style={{ cursor: "pointer", color: "#64748b", fontSize: 16 }}>×</span>
        </div>
      ))}
    </div>
  );
}

function BarChart({ data, height = 120 }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 6, height, padding: "0 4px" }}>
      {data.map((d, i) => (
        <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
          <div style={{
            width: "100%", background: `rgba(0,212,170,${0.4 + (d.count / max) * 0.6})`,
            borderRadius: "4px 4px 0 0",
            height: `${(d.count / max) * (height - 28)}px`,
            minHeight: 4,
            transition: "height 0.5s ease",
          }} />
          <span style={{ fontSize: 10, color: "#64748b" }}>{d.date || d.label}</span>
        </div>
      ))}
    </div>
  );
}

function DonutChart({ data }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const colors = ["#00d4aa", "#ff9500", "#ff4d4d", "#a78bfa", "#38bdf8", "#4ade80", "#fb7185", "#fbbf24"];
  let offset = 0;
  const R = 60, cx = 80, cy = 80, strokeW = 22;
  const circumference = 2 * Math.PI * R;

  const segments = Object.entries(data).map(([label, value], i) => {
    const pct = value / total;
    const seg = { label, value, pct, dasharray: `${pct * circumference} ${circumference}`, dashoffset: -offset * circumference, color: colors[i % colors.length] };
    offset += pct;
    return seg;
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
      <svg width={160} height={160} viewBox="0 0 160 160">
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="#1e2533" strokeWidth={strokeW} />
        {segments.map((s, i) => (
          <circle key={i} cx={cx} cy={cy} r={R} fill="none" stroke={s.color} strokeWidth={strokeW}
            strokeDasharray={s.dasharray} strokeDashoffset={s.dashoffset}
            style={{ transformOrigin: `${cx}px ${cy}px`, transform: "rotate(-90deg)", transition: "all 0.5s" }} />
        ))}
        <text x={cx} y={cy - 6} textAnchor="middle" fill="#e2e8f0" fontSize={20} fontWeight={700}>{total.toLocaleString()}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="#64748b" fontSize={11}>scans</text>
      </svg>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
        {segments.slice(0, 6).map((s, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: s.color, flexShrink: 0 }} />
            <span style={{ fontSize: 12, color: "#94a3b8", flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.label}</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: s.color }}>{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConfidenceMeter({ score }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? "#ff4d4d" : pct >= 60 ? "#ff9500" : pct >= 35 ? "#88d400" : "#00d4aa";
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
        <span style={{ fontSize: 13, color: "#94a3b8" }}>Confidence Score</span>
        <span style={{ fontSize: 22, fontWeight: 800, color }}>{pct}%</span>
      </div>
      <div style={{ height: 8, background: "#1e2533", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: `linear-gradient(90deg, ${color}88, ${color})`, borderRadius: 4, transition: "width 1s ease" }} />
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16, padding: "32px 0" }}>
      <div style={{
        width: 48, height: 48, borderRadius: "50%",
        border: "3px solid #1e2533",
        borderTop: "3px solid #00d4aa",
        animation: "spin 0.8s linear infinite",
      }} />
      <span style={{ color: "#64748b", fontSize: 14 }}>Analyzing with AI…</span>
    </div>
  );
}

// ── Pages ─────────────────────────────────────────────────────────────────

function Dashboard({ setPage, activity, isMobile }) {
  const stats = buildUserStats(activity);
  const alerts = buildRecentAlerts(activity);
  const cardStyle = isMobile ? { ...S.card, padding: 16 } : S.card;

  const statCards = [
    { label: "Total Analyses", value: stats.total_analyses.toLocaleString(), color: "#00d4aa", icon: "🔍" },
    { label: "Reports Filed", value: stats.total_reports.toLocaleString(), color: "#a78bfa", icon: "📋" },
    { label: "High/Critical Risk", value: (stats.scams_by_risk.Critical + stats.scams_by_risk.High).toString(), color: "#ff4d4d", icon: "🚨" },
    { label: "Avg Confidence", value: `${Math.round(stats.avg_confidence * 100)}%`, color: "#ff9500", icon: "🎯" },
  ];

  return (
    <div>
      <div style={{ marginBottom: isMobile ? 24 : 32 }}>
        <h1 style={S.h1}>Threat Intelligence Dashboard</h1>
        <p style={{ color: "#64748b", margin: 0 }}>Real-time scam detection and reporting system</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr 1fr" : "repeat(auto-fit, minmax(200px, 1fr))", gap: isMobile ? 12 : 16, marginBottom: isMobile ? 20 : 32 }}>
        {statCards.map((c, i) => (
          <div key={i} style={S.statCard(c.color)}>
            <div style={{ fontSize: 24, marginBottom: 8 }}>{c.icon}</div>
            <div style={{ fontSize: isMobile ? 24 : 28, fontWeight: 800, color: c.color, letterSpacing: "-0.02em" }}>{c.value}</div>
            <div style={{ fontSize: 13, color: "#64748b", marginTop: 4 }}>{c.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: isMobile ? 16 : 24, marginBottom: 24 }}>
        <div style={cardStyle}>
          <h2 style={S.h2}>Activity (Last 7 Days)</h2>
          <BarChart data={stats.recent_trend} height={isMobile ? 120 : 140} />
        </div>
        <div style={cardStyle}>
          <h2 style={S.h2}>Detected Scams by Type</h2>
          <DonutChart data={stats.scams_by_type} />
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: isMobile ? "flex-start" : "center", gap: 12, marginBottom: 20, flexDirection: isMobile ? "column" : "row" }}>
          <h2 style={{ ...S.h2, margin: 0 }}>Recent Alerts</h2>
          <button style={S.btn("secondary")} onClick={() => setPage("analytics")}>View All →</button>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {alerts.map(r => (
            <div key={r.id} style={{
              display: "flex", alignItems: isMobile ? "flex-start" : "center", gap: 16, flexDirection: isMobile ? "column" : "row",
              padding: "14px 16px", background: "#080b0f", borderRadius: 8,
              border: "1px solid #1e2533",
            }}>
              <div style={{ fontSize: 24, width: 36, textAlign: "center" }}>{SCAM_ICONS[r.scam_type] || "⚠"}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 2 }}>{r.scam_type}</div>
                <div style={{ fontSize: 12, color: "#64748b", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{r.explanation}</div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
                <span style={S.badge(r.risk_level)}>{r.risk_level}</span>
                <span style={{ fontSize: 11, color: "#475569" }}>{formatDateTime(r.created_at)}</span>
              </div>
            </div>
          ))}
          {alerts.length === 0 && (
            <div style={{ textAlign: "center", padding: "32px", color: "#64748b" }}>
              Your dashboard will populate after you run scans or submit reports.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScanPage({ setPage, setSharedResult, addToast, recordAnalysis, isMobile }) {
  const [tab, setTab] = useState("text");
  const [textInput, setTextInput] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [networkInput, setNetworkInput] = useState("");
  const [loading, setLoading] = useState(false);
  const fileRef = useRef();

  const tabStyle = (t) => ({
    padding: "8px 18px", borderRadius: 6, cursor: "pointer",
    background: tab === t ? "#00d4aa" : "transparent",
    color: tab === t ? "#080b0f" : "#64748b",
    fontWeight: tab === t ? 700 : 400,
    border: tab === t ? "none" : "1px solid #1e2533",
    fontSize: 13, transition: "all 0.15s",
  });

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setNetworkInput(ev.target.result);
    reader.readAsText(file);
  };

  const analyze = async () => {
    const content = tab === "text" ? textInput : tab === "url" ? urlInput : networkInput;
    if (!content.trim()) { addToast("Please enter content to analyze", "error"); return; }
    let networkLogs = null;
    if (tab === "network") {
      try { networkLogs = normalizeNetworkLogs(content); } catch { addToast("Network log must be valid JSON", "error"); return; }
    }
    setLoading(true);
    try {
      let result;
      try {
        const body = tab === "text" ? { content } : tab === "url" ? { url: content } : { logs: networkLogs, time_window_minutes: 60 };
        const endpoint = tab === "network" ? "network" : tab;
        const res = await fetch(`${API_BASE}/analyze/${endpoint}`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        if (!res.ok) throw new Error("API error");
        result = await res.json();
      } catch {
        result = await mockAnalyze(tab, tab === "network" ? networkLogs : content);
      }
      recordAnalysis(result);
      setSharedResult(result);
      addToast(
        result.scam_type === "Legitimate" ? "✓ No threats detected" : `⚠ ${result.scam_type} detected!`,
        result.scam_type === "Legitimate" ? "success" : result.risk_level === "Critical" ? "error" : "warn"
      );
      setPage("results");
    } catch (e) {
      addToast("Analysis failed. Please try again.", "error");
    }
    setLoading(false);
  };

  const sampleTexts = {
    text: "URGENT: Dear Customer, your KYC is pending. Your bank account will be blocked within 24 hours. Click here to update immediately: http://secure-bank-kyc.xyz/update",
    url: "http://secure-hdtfc-login.xyz/verify-account?token=abc123",
    network: JSON.stringify([
      { ip: "192.168.1.100", endpoint: "/api/login", status_code: 401, timestamp: "2024-06-01T10:00:01Z" },
      { ip: "192.168.1.100", endpoint: "/api/login", status_code: 401, timestamp: "2024-06-01T10:00:03Z" },
      { ip: "192.168.1.100", endpoint: "/api/otp/verify", status_code: 400, timestamp: "2024-06-01T10:00:05Z" },
      { ip: "192.168.1.100", endpoint: "/api/transfer", status_code: 200, timestamp: "2024-06-01T10:00:07Z" },
      { ip: "192.168.1.100", endpoint: "/api/kyc/update", status_code: 200, timestamp: "2024-06-01T10:00:09Z" },
    ], null, 2),
  };

  return (
    <div>
      <div style={{ marginBottom: isMobile ? 24 : 32 }}>
        <h1 style={S.h1}>Scan for Scams</h1>
        <p style={{ color: "#64748b", margin: 0 }}>Paste text, URL, or upload network logs to analyze</p>
      </div>

      <div style={isMobile ? { ...S.card, padding: 16 } : S.card}>
        <div style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
          {["text", "url", "network"].map(t => (
            <button key={t} style={{ ...tabStyle(t), flex: isMobile ? "1 1 140px" : "0 0 auto" }} onClick={() => setTab(t)}>
              {t === "text" ? "📝 SMS/Email Text" : t === "url" ? "🔗 URL" : "📊 Network Logs"}
            </button>
          ))}
        </div>

        {tab === "text" && (
          <div>
            <label style={S.label}>Message Content (SMS / Email)</label>
            <textarea
              value={textInput}
              onChange={e => setTextInput(e.target.value)}
              placeholder="Paste suspicious SMS, email, or WhatsApp message here..."
              style={{ ...S.input, height: 200, resize: "vertical" }}
            />
          </div>
        )}
        {tab === "url" && (
          <div>
            <label style={S.label}>Suspicious URL</label>
            <input
              type="text"
              value={urlInput}
              onChange={e => setUrlInput(e.target.value)}
              placeholder="https://suspicious-link.xyz/verify"
              style={S.input}
            />
          </div>
        )}
        {tab === "network" && (
          <div>
            <label style={S.label}>Network Log (JSON format)</label>
            <div style={{ marginBottom: 12, display: "flex", gap: 8 }}>
              <button style={S.btn("secondary")} onClick={() => fileRef.current.click()}>
                📁 Upload JSON/CSV
              </button>
              <input ref={fileRef} type="file" accept=".json,.csv" onChange={handleFileUpload} style={{ display: "none" }} />
            </div>
            <textarea
              value={networkInput}
              onChange={e => setNetworkInput(e.target.value)}
              placeholder='[{"ip": "192.168.1.1", "endpoint": "/login", "status_code": 401, ...}]'
              style={{ ...S.input, height: 200, resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
            />
          </div>
        )}

        <div style={{ display: "flex", gap: 12, marginTop: 20, flexWrap: "wrap", flexDirection: isMobile ? "column" : "row" }}>
          <button style={{ ...S.btn(), fontSize: 15, padding: "12px 28px", width: isMobile ? "100%" : "auto" }} onClick={analyze} disabled={loading}>
            {loading ? "Analyzing…" : "🔍 Analyze Now"}
          </button>
          <button style={{ ...S.btn("secondary"), width: isMobile ? "100%" : "auto" }} onClick={() => {
            if (tab === "text") setTextInput(sampleTexts.text);
            else if (tab === "url") setUrlInput(sampleTexts.url);
            else setNetworkInput(sampleTexts.network);
          }}>
            Load Sample
          </button>
        </div>

        {loading && <Spinner />}
      </div>
    </div>
  );
}

function ResultsPage({ result, setPage, addToast, isMobile }) {
  if (!result) return (
    <div style={{ textAlign: "center", padding: "80px 0" }}>
      <div style={{ fontSize: 64, marginBottom: 16 }}>🔍</div>
      <h2 style={{ ...S.h2, color: "#64748b" }}>No Analysis Yet</h2>
      <p style={{ color: "#475569" }}>Go to the Scan page to analyze content</p>
      <button style={{ ...S.btn(), marginTop: 16 }} onClick={() => setPage("scan")}>Start Scanning</button>
    </div>
  );

  const riskColors = RISK_COLORS[result.risk_level] || RISK_COLORS.Low;
  const isScam = result.scam_type !== "Legitimate";

  return (
    <div>
      <div style={{ marginBottom: isMobile ? 24 : 32 }}>
        <h1 style={S.h1}>Analysis Results</h1>
        <p style={{ color: "#64748b", margin: 0 }}>ID: {result.analysis_id} · {new Date(result.timestamp).toLocaleString()}</p>
      </div>

      <div style={{ ...S.card, padding: isMobile ? 16 : 24, borderLeft: `4px solid ${riskColors.text}`, marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 20, flexWrap: "wrap" }}>
          <div style={{ fontSize: 48 }}>{SCAM_ICONS[result.scam_type] || "⚠"}</div>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8, flexWrap: "wrap" }}>
              <h2 style={{ ...S.h2, margin: 0, color: riskColors.text }}>{result.scam_type}</h2>
              <span style={S.badge(result.risk_level)}>{result.risk_level} Risk</span>
            </div>
            <ConfidenceMeter score={result.confidence_score} />
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: isMobile ? 16 : 24, marginBottom: 24 }}>
        <div style={isMobile ? { ...S.card, padding: 16 } : S.card}>
          <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16, color: "#94a3b8" }}>📋 EXPLANATION</h3>
          <p style={{ fontSize: 14, lineHeight: 1.7, color: "#cbd5e1", margin: 0 }}>{result.explanation}</p>
        </div>
        <div style={isMobile ? { ...S.card, padding: 16 } : S.card}>
          <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16, color: "#94a3b8" }}>🔑 INDICATORS DETECTED</h3>
          {result.keywords_found?.length > 0 ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {result.keywords_found.map((kw, i) => (
                <span key={i} style={{
                  padding: "4px 10px", borderRadius: 4, fontSize: 12,
                  background: "rgba(255,149,0,0.1)", color: "#ff9500",
                  border: "1px solid rgba(255,149,0,0.2)",
                }}>{kw}</span>
              ))}
            </div>
          ) : (
            <p style={{ color: "#64748b", fontSize: 14 }}>No specific indicators flagged</p>
          )}
        </div>
      </div>

      {result.url_analysis && (
        <div style={{ ...S.card, padding: isMobile ? 16 : 24, marginBottom: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16, color: "#94a3b8" }}>🌐 URL ANALYSIS</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
            {[
              { label: "IP Address", value: result.url_analysis.is_ip_address, isBool: true },
              { label: "Suspicious TLD", value: result.url_analysis.has_suspicious_tld, isBool: true },
              { label: "Typosquatting", value: result.url_analysis.has_typosquatting, isBool: true },
              { label: "Misleading Keywords", value: result.url_analysis.has_misleading_keywords, isBool: true },
              { label: "Subdomain Count", value: result.url_analysis.subdomain_count },
              { label: "Suspicious Path", value: result.url_analysis.path_suspicious, isBool: true },
            ].map((item, i) => (
              <div key={i} style={{ background: "#080b0f", borderRadius: 8, padding: "12px 14px", border: "1px solid #1e2533" }}>
                <div style={{ fontSize: 11, color: "#64748b", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontWeight: 700, fontSize: 15, color: item.isBool ? (item.value ? "#ff4d4d" : "#00d4aa") : "#e2e8f0" }}>
                  {item.isBool ? (item.value ? "YES ⚠" : "No ✓") : item.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {result.anomaly_analysis && (
        <div style={{ ...S.card, padding: isMobile ? 16 : 24, marginBottom: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16, color: "#94a3b8" }}>📊 ANOMALY ANALYSIS</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
            {[
              { label: "Total Requests", value: result.anomaly_analysis.total_requests },
              { label: "Unique IPs", value: result.anomaly_analysis.unique_ips },
              { label: "Req/Min", value: result.anomaly_analysis.requests_per_minute },
              { label: "Traffic Spike", value: result.anomaly_analysis.spike_detected, isBool: true },
              { label: "Repeated Failures", value: result.anomaly_analysis.repeated_failures, isBool: true },
              { label: "Anomaly Score", value: `${Math.round(result.anomaly_analysis.anomaly_score * 100)}%` },
            ].map((item, i) => (
              <div key={i} style={{ background: "#080b0f", borderRadius: 8, padding: "12px 14px", border: "1px solid #1e2533" }}>
                <div style={{ fontSize: 11, color: "#64748b", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontWeight: 700, fontSize: 15, color: item.isBool ? (item.value ? "#ff4d4d" : "#00d4aa") : "#e2e8f0" }}>
                  {item.isBool ? (item.value ? "YES ⚠" : "No ✓") : item.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ ...S.card, padding: isMobile ? 16 : 24, marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16, color: "#94a3b8" }}>🛡 RECOMMENDATIONS</h3>
        <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 10 }}>
          {(result.recommendations || []).map((rec, i) => (
            <li key={i} style={{ display: "flex", gap: 10, fontSize: 14, color: "#cbd5e1" }}>
              <span style={{ color: "#00d4aa", flexShrink: 0 }}>→</span>
              {rec}
            </li>
          ))}
        </ul>
      </div>

      {isScam && (
        <div style={{ display: "flex", gap: 12, flexDirection: isMobile ? "column" : "row" }}>
          <button style={{ ...S.btn(), fontSize: 15, padding: "12px 28px", width: isMobile ? "100%" : "auto" }} onClick={() => setPage("report")}>
            📋 Report This Scam
          </button>
          <button style={{ ...S.btn("secondary"), width: isMobile ? "100%" : "auto" }} onClick={() => setPage("scan")}>
            🔍 Scan Another
          </button>
        </div>
      )}
    </div>
  );
}

function ReportPage({ result, addToast, recordReport, isMobile }) {
  const [form, setForm] = useState({
    scam_type: result?.scam_type || "",
    risk_level: result?.risk_level || "Medium",
    input_type: result?.input_type || "text",
    explanation: result?.explanation || "",
    reporter_note: "",
    confidence_score: result?.confidence_score || 0,
    keywords_found: result?.keywords_found || [],
    analysis_id: result?.analysis_id || "",
  });
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [reportId, setReportId] = useState("");

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const submit = async () => {
    if (!form.scam_type || !form.explanation) { addToast("Please fill in required fields", "error"); return; }
    setLoading(true);
    try {
      let data;
      try {
        const res = await fetch(`${API_BASE}/report`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form),
        });
        data = await res.json();
      } catch {
        data = { report_id: `SCM-${new Date().toISOString().slice(0,10).replace(/-/g,"")}-${Math.random().toString(36).substr(2,6).toUpperCase()}`, status: "submitted" };
      }
      recordReport(form, data);
      setReportId(data.report_id);
      setSubmitted(true);
      addToast(`Report ${data.report_id} submitted!`, "success");
    } catch {
      addToast("Submission failed. Please retry.", "error");
    }
    setLoading(false);
  };

  if (submitted) return (
    <div style={{ textAlign: "center", padding: "80px 0" }}>
      <div style={{ fontSize: 64, marginBottom: 16 }}>✅</div>
      <h2 style={S.h2}>Report Submitted!</h2>
      <p style={{ color: "#64748b", marginBottom: 8 }}>Your report ID:</p>
      <div style={{ ...S.statCard("#00d4aa"), display: "inline-block", padding: "12px 28px", marginBottom: 24 }}>
        <span style={{ fontSize: 20, fontWeight: 800, color: "#00d4aa" }}>{reportId}</span>
      </div>
      <p style={{ color: "#64748b" }}>Our team will review and take action within 24–48 hours.</p>
      <div style={{ marginTop: 16 }}>
        <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" style={{ color: "#00d4aa", fontSize: 14 }}>
          Also report to National Cybercrime Portal →
        </a>
      </div>
    </div>
  );

  return (
    <div>
      <div style={{ marginBottom: isMobile ? 24 : 32 }}>
        <h1 style={S.h1}>Report a Scam</h1>
        <p style={{ color: "#64748b", margin: 0 }}>Help protect others by reporting scam activity</p>
      </div>

      <div style={isMobile ? { ...S.card, padding: 16 } : S.card}>
        <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: 20, marginBottom: 20 }}>
          <div>
            <label style={S.label}>Scam Type *</label>
            <select value={form.scam_type} onChange={e => update("scam_type", e.target.value)} style={{ ...S.input, cursor: "pointer" }}>
              <option value="">Select type…</option>
              {SCAM_TYPES.filter(t => t !== "Legitimate").map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label style={S.label}>Risk Level</label>
            <select value={form.risk_level} onChange={e => update("risk_level", e.target.value)} style={{ ...S.input, cursor: "pointer" }}>
              {["Low", "Medium", "High", "Critical"].map(r => <option key={r}>{r}</option>)}
            </select>
          </div>
          <div>
            <label style={S.label}>Input Type</label>
            <select value={form.input_type} onChange={e => update("input_type", e.target.value)} style={{ ...S.input, cursor: "pointer" }}>
              <option value="text">Text (SMS/Email)</option>
              <option value="url">URL</option>
              <option value="network_log">Network Log</option>
            </select>
          </div>
          <div>
            <label style={S.label}>Analysis ID</label>
            <input value={form.analysis_id} onChange={e => update("analysis_id", e.target.value)} placeholder="Auto-filled from scan" style={S.input} />
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={S.label}>Explanation / Summary *</label>
          <textarea value={form.explanation} onChange={e => update("explanation", e.target.value)}
            placeholder="Describe why this is suspicious..." rows={4}
            style={{ ...S.input, resize: "vertical" }} />
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={S.label}>Your Notes (optional)</label>
          <textarea value={form.reporter_note} onChange={e => update("reporter_note", e.target.value)}
            placeholder="How did you receive this? Any additional context..."
            rows={3} style={{ ...S.input, resize: "vertical" }} />
        </div>

        <div style={{ padding: "16px", background: "#080b0f", borderRadius: 8, border: "1px solid #1e2533", marginBottom: 20 }}>
          <div style={{ fontSize: 12, color: "#64748b", marginBottom: 8 }}>🔐 Privacy Notice</div>
          <div style={{ fontSize: 13, color: "#94a3b8" }}>
            Your personal information is not stored. Reports are anonymized and used only to improve scam detection.
          </div>
        </div>

        <button style={{ ...S.btn(), fontSize: 15, padding: "12px 32px", width: isMobile ? "100%" : "auto" }} onClick={submit} disabled={loading}>
          {loading ? "Submitting…" : "📋 Submit Report"}
        </button>
      </div>
    </div>
  );
}

function AnalyticsPage({ addToast, activity, isMobile }) {
  const reports = activity.reports;
  const [filter, setFilter] = useState({ type: "", risk: "", status: "" });

  const filtered = reports.filter(r =>
    (!filter.type || r.scam_type.includes(filter.type)) &&
    (!filter.risk || r.risk_level === filter.risk) &&
    (!filter.status || r.status === filter.status)
  );

  const statusColors = {
    submitted: "#38bdf8", confirmed: "#00d4aa", pending: "#ff9500", reviewed: "#a78bfa", dismissed: "#64748b"
  };

  return (
    <div>
      <div style={{ marginBottom: isMobile ? 24 : 32 }}>
        <h1 style={S.h1}>Analytics & Reports</h1>
        <p style={{ color: "#64748b", margin: 0 }}>View and manage all reported scams</p>
      </div>

      <div style={{ ...S.card, padding: isMobile ? 16 : 24, marginBottom: 24 }}>
        <h3 style={{ ...S.h2, marginBottom: 16 }}>Filters</h3>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", flexDirection: isMobile ? "column" : "row" }}>
          <select value={filter.type} onChange={e => setFilter(f => ({ ...f, type: e.target.value }))}
            style={{ ...S.input, width: isMobile ? "100%" : "auto", minWidth: isMobile ? 0 : 200 }}>
            <option value="">All Types</option>
            {SCAM_TYPES.filter(t => t !== "Legitimate").map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={filter.risk} onChange={e => setFilter(f => ({ ...f, risk: e.target.value }))}
            style={{ ...S.input, width: isMobile ? "100%" : "auto", minWidth: isMobile ? 0 : 140 }}>
            <option value="">All Risk Levels</option>
            {["Critical", "High", "Medium", "Low"].map(r => <option key={r}>{r}</option>)}
          </select>
          <select value={filter.status} onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}
            style={{ ...S.input, width: isMobile ? "100%" : "auto", minWidth: isMobile ? 0 : 140 }}>
            <option value="">All Statuses</option>
            {["submitted", "pending", "reviewed", "confirmed", "dismissed"].map(s => <option key={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div style={isMobile ? { ...S.card, padding: 16 } : S.card}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
          <h2 style={{ ...S.h2, margin: 0 }}>Reports ({filtered.length})</h2>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1e2533" }}>
                {["Report ID", "Type", "Risk", "Input", "Status", "Date", "Action"].map(h => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: "#64748b", fontWeight: 600, fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr key={r.id} style={{ borderBottom: "1px solid #1e2533", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                  <td style={{ padding: "12px", fontFamily: "monospace", color: "#a78bfa", fontSize: 12 }}>{r.report_id}</td>
                  <td style={{ padding: "12px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span>{SCAM_ICONS[r.scam_type]}</span>
                      <span style={{ fontSize: 12 }}>{r.scam_type.split("/")[0]}</span>
                    </div>
                  </td>
                  <td style={{ padding: "12px" }}><span style={S.badge(r.risk_level)}>{r.risk_level}</span></td>
                  <td style={{ padding: "12px", color: "#64748b", textTransform: "capitalize" }}>{r.input_type}</td>
                  <td style={{ padding: "12px" }}>
                    <span style={{ color: statusColors[r.status] || "#64748b", fontWeight: 600, textTransform: "capitalize" }}>
                      ● {r.status}
                    </span>
                  </td>
                  <td style={{ padding: "12px", color: "#64748b" }}>{new Date(r.created_at).toLocaleDateString()}</td>
                  <td style={{ padding: "12px" }}>
                    <button style={{ ...S.btn("secondary"), padding: "4px 10px", fontSize: 12 }}
                      onClick={() => addToast(`Viewing ${r.report_id}`, "success")}>
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>No reports match the filters</div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── App Shell ─────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState("dashboard");
  const [sharedResult, setSharedResult] = useState(null);
  const [toasts, setToasts] = useState([]);
  const [activity, setActivity] = useState(readUserActivity);
  const isMobile = useIsMobile();

  const addToast = useCallback((message, type = "success") => {
    const id = Date.now();
    setToasts(t => [...t, { id, message, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4000);
  }, []);

  const removeToast = useCallback((id) => setToasts(t => t.filter(x => x.id !== id)), []);

  const saveActivity = useCallback((updater) => {
    setActivity(current => {
      const next = typeof updater === "function" ? updater(current) : updater;
      localStorage.setItem(ACTIVITY_STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const recordAnalysis = useCallback((result) => {
    saveActivity(current => ({
      ...current,
      analyses: [
        {
          ...result,
          id: result.analysis_id,
          created_at: result.timestamp || new Date().toISOString(),
        },
        ...current.analyses.filter(item => item.analysis_id !== result.analysis_id),
      ],
    }));
  }, [saveActivity]);

  const recordReport = useCallback((form, data) => {
    saveActivity(current => ({
      ...current,
      reports: [
        {
          id: data.report_id,
          report_id: data.report_id,
          scam_type: form.scam_type,
          confidence_score: form.confidence_score,
          risk_level: form.risk_level,
          input_type: form.input_type,
          status: data.status || "submitted",
          created_at: new Date().toISOString(),
          explanation: form.explanation,
          keywords_found: form.keywords_found,
          analysis_id: form.analysis_id,
        },
        ...current.reports.filter(item => item.report_id !== data.report_id),
      ],
    }));
  }, [saveActivity]);

  const navItems = [
    { id: "dashboard", icon: "⬡", label: "Dashboard" },
    { id: "scan", icon: "◎", label: "Scan Input" },
    { id: "results", icon: "◈", label: "Results" },
    { id: "report", icon: "◻", label: "Report Scam" },
    { id: "analytics", icon: "◫", label: "Analytics" },
  ];

  const pageProps = {
    setPage,
    setSharedResult,
    addToast,
    result: sharedResult,
    activity,
    recordAnalysis,
    recordReport,
    isMobile,
  };

  const appStyle = isMobile ? { ...S.app, flexDirection: "column" } : S.app;
  const sidebarStyle = isMobile ? {
    ...S.sidebar,
    width: "100%",
    minHeight: "auto",
    height: "auto",
    position: "sticky",
    top: 0,
    zIndex: 20,
    padding: "14px 0 8px",
    borderRight: "none",
    borderBottom: "1px solid #1e2533",
    overflowX: "auto",
    overflowY: "hidden",
  } : S.sidebar;
  const logoStyle = isMobile ? {
    ...S.logo,
    padding: "0 16px 12px",
    marginBottom: 6,
    borderBottom: "none",
  } : S.logo;
  const navItemStyle = (active) => isMobile ? {
    ...S.navItem(active),
    padding: "9px 12px",
    borderLeft: "none",
    borderBottom: active ? "2px solid #00d4aa" : "2px solid transparent",
    whiteSpace: "nowrap",
    flex: "0 0 auto",
  } : S.navItem(active);
  const mainStyle = isMobile ? {
    ...S.main,
    width: "100%",
    maxWidth: "100%",
    padding: "20px 16px 32px",
  } : S.main;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&display=swap');
        * { box-sizing: border-box; }
        body { margin: 0; background: #080b0f; }
        button:hover { opacity: 0.88; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        input::placeholder, textarea::placeholder { color: #475569; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e2533; border-radius: 4px; }
        select option { background: #0d1117; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes slideIn { from { transform: translateX(20px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
      `}</style>
      <Toast toasts={toasts} remove={removeToast} />
      <div style={appStyle}>
        <nav style={sidebarStyle}>
          <div style={logoStyle}>
            <div style={{ fontSize: isMobile ? 18 : 20, fontWeight: 800, color: "#00d4aa", letterSpacing: "-0.02em" }}>
              🛡 ScamShield
            </div>
            <div style={{ fontSize: 11, color: "#64748b", marginTop: 4 }}>AI Detection System</div>
          </div>
          <div style={{ display: "flex", flexDirection: isMobile ? "row" : "column", overflowX: isMobile ? "auto" : "visible" }}>
            {navItems.map(n => (
              <div key={n.id} style={navItemStyle(page === n.id)} onClick={() => setPage(n.id)}>
                <span style={{ fontSize: 18 }}>{n.icon}</span>
                <span>{n.label}</span>
              </div>
            ))}
          </div>
          {!isMobile && <div style={{ flex: 1 }} />}
          <div style={{ display: isMobile ? "none" : "block", padding: "16px 24px", borderTop: "1px solid #1e2533", fontSize: 11, color: "#475569" }}>
            <div style={{ marginBottom: 4 }}>🔒 Data Anonymized</div>
            <div>v1.0.0 · cybercrime.gov.in</div>
          </div>
        </nav>
        <main style={mainStyle}>
          {page === "dashboard" && <Dashboard {...pageProps} />}
          {page === "scan" && <ScanPage {...pageProps} />}
          {page === "results" && <ResultsPage {...pageProps} />}
          {page === "report" && <ReportPage {...pageProps} />}
          {page === "analytics" && <AnalyticsPage {...pageProps} />}
        </main>
      </div>
    </>
  );
}
