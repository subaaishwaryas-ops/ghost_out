from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from typing import List, Optional
from datetime import datetime
import re

# ─────────────────────────────────────────────
#   App Initialization
# ─────────────────────────────────────────────
app = FastAPI(
    title="GhostOut NLP Engine",
    description="Real-time threat detection for women's online safety 🛡️",
    version="1.0.0"
)

analyzer = SentimentIntensityAnalyzer()

# ─────────────────────────────────────────────
#   Threat Keyword Boosters
#   VADER is general-purpose — we boost it with
#   domain-specific harassment/stalking keywords
# ─────────────────────────────────────────────
THREAT_KEYWORDS = [
    # Direct threats
    "kill", "hurt", "destroy", "stalk", "follow you",
    "know where you live", "find you", "watch you",
    # Harassment patterns
    "you'll regret", "pay for this", "won't get away",
    "make your life", "ruin you", "expose you",
    # Grooming signals
    "don't tell anyone", "our secret", "only i understand you",
    "no one loves you like", "you need me",
    # Manipulation
    "you're nothing without", "no one will believe you",
    "you're crazy", "just testing you"
]

ESCALATION_PHRASES = [
    "last warning", "final chance", "i know your",
    "i've been watching", "i'm outside", "come outside"
]

# ─────────────────────────────────────────────
#   Request & Response Models
# ─────────────────────────────────────────────

class MessageRequest(BaseModel):
    message: str
    sender_id: Optional[str] = "unknown"
    platform: Optional[str] = "unknown"    # instagram / whatsapp / twitter

class ChatHistoryRequest(BaseModel):
    messages: List[str]
    sender_id: Optional[str] = "unknown"
    platform: Optional[str] = "unknown"

class ThreatResponse(BaseModel):
    message: str
    vader_scores: dict
    threat_keyword_hits: List[str]
    escalation_hits: List[str]
    threat_score: float           # 0–100
    threat_level: str             # SAFE / SUSPICIOUS / DANGEROUS
    recommended_action: str
    analyzed_at: str

class ChatHistoryResponse(BaseModel):
    total_messages: int
    overall_threat_score: float
    threat_level: str
    escalation_detected: bool
    pattern_summary: str
    per_message_scores: List[dict]
    recommended_action: str
    analyzed_at: str

# ─────────────────────────────────────────────
#   Core Threat Scoring Logic
# ─────────────────────────────────────────────

def calculate_threat_score(
    vader_compound: float,
    keyword_hits: List[str],
    escalation_hits: List[str]
) -> float:
    # VADER negativity
    vader_threat = max(0, (-vader_compound + 1) / 2 * 100) * 0.20

    # Each keyword hit = 35 points, capped at 100
    keyword_score = min(len(keyword_hits) * 35, 100) * 0.50

    # Escalation is most severe
    escalation_score = min(len(escalation_hits) * 50, 100) * 0.30

    total = vader_threat + keyword_score + escalation_score
    return round(min(total, 100), 2)

def get_threat_level(score: float) -> tuple[str, str]:
    """
    Maps numeric score to threat level + recommended action.
    Returns (threat_level, recommended_action)
    """
    if score <= 30:
        return (
            "🟢 SAFE",
            "No action needed. Message appears non-threatening."
        )
    elif score <= 65:
        return (
            "🟡 SUSPICIOUS",
            "Monitor this sender. Consider restricting their messages."
        )
    else:
        return (
            "🔴 DANGEROUS",
            "ALERT: Block this sender immediately. Save evidence & report to cybercrime.gov.in"
        )


def extract_keyword_hits(message: str, keyword_list: List[str]) -> List[str]:
    """Case-insensitive keyword matching."""
    message_lower = message.lower()
    return [kw for kw in keyword_list if kw in message_lower]


def clean_message(message: str) -> str:
    """Basic text normalization."""
    message = re.sub(r'http\S+', '', message)       # remove URLs
    message = re.sub(r'@\w+', '', message)           # remove mentions
    message = re.sub(r'\s+', ' ', message).strip()   # normalize whitespace
    return message

# ─────────────────────────────────────────────
#   API Endpoints
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "GhostOut 🛡️",
        "engine": "NLP Threat Detection — Day 1",
        "status": "Heartbeat running ✅",
        "endpoints": ["/analyze", "/analyze-chat", "/health"]
    }


@app.get("/health")
def health_check():
    return {"status": "healthy", "engine": "VADER + FastAPI", "timestamp": datetime.utcnow().isoformat()}


# ── Endpoint 1: Single Message Analysis ──────
@app.post("/analyze", response_model=ThreatResponse)
def analyze_message(request: MessageRequest):
    """
    Analyzes a single message in real-time.
    Use this for: DMs, comments, individual chat messages.
    """
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    clean = clean_message(request.message)

    # VADER scoring
    scores = analyzer.polarity_scores(clean)

    # Keyword detection
    keyword_hits = extract_keyword_hits(clean, THREAT_KEYWORDS)
    escalation_hits = extract_keyword_hits(clean, ESCALATION_PHRASES)

    # Final threat score
    threat_score = calculate_threat_score(
        scores["compound"],
        keyword_hits,
        escalation_hits
    )

    threat_level, action = get_threat_level(threat_score)

    return ThreatResponse(
        message=request.message,
        vader_scores=scores,
        threat_keyword_hits=keyword_hits,
        escalation_hits=escalation_hits,
        threat_score=threat_score,
        threat_level=threat_level,
        recommended_action=action,
        analyzed_at=datetime.utcnow().isoformat()
    )


# ── Endpoint 2: Chat History Analysis ────────
@app.post("/analyze-chat", response_model=ChatHistoryResponse)
def analyze_chat_history(request: ChatHistoryRequest):
    """
    Analyzes an entire chat history to detect:
    - Escalation patterns over time
    - Average threat trajectory
    - Overall risk assessment
    Use this for: reviewing conversation history with a suspicious sender.
    """
    if not request.messages:
        raise HTTPException(status_code=400, detail="Message list cannot be empty.")

    per_message_scores = []
    all_scores = []
    escalation_detected = False
    all_keyword_hits = []

    for i, msg in enumerate(request.messages):
        clean = clean_message(msg)
        scores = analyzer.polarity_scores(clean)
        keyword_hits = extract_keyword_hits(clean, THREAT_KEYWORDS)
        escalation_hits = extract_keyword_hits(clean, ESCALATION_PHRASES)

        if escalation_hits:
            escalation_detected = True

        threat_score = calculate_threat_score(
            scores["compound"],
            keyword_hits,
            escalation_hits
        )

        all_scores.append(threat_score)
        all_keyword_hits.extend(keyword_hits)

        per_message_scores.append({
            "index": i + 1,
            "message_preview": msg[:60] + "..." if len(msg) > 60 else msg,
            "threat_score": threat_score,
            "threat_level": get_threat_level(threat_score)[0],
            "keyword_hits": keyword_hits
        })

    # Overall score: weighted toward recent messages (recency bias)
    # Recent messages carry more weight in escalation detection
    weights = [0.5 + (i / len(all_scores)) for i in range(len(all_scores))]
    weighted_score = sum(s * w for s, w in zip(all_scores, weights)) / sum(weights)
    overall_score = round(min(weighted_score, 100), 2)

    threat_level, action = get_threat_level(overall_score)

    # Pattern summary
    if overall_score > 65:
        pattern = "⚠️ Dangerous escalation pattern detected across conversation history."
    elif overall_score > 30:
        pattern = "⚡ Suspicious pattern — tone is becoming increasingly negative over time."
    else:
        pattern = "✅ Conversation appears non-threatening overall."

    return ChatHistoryResponse(
        total_messages=len(request.messages),
        overall_threat_score=overall_score,
        threat_level=threat_level,
        escalation_detected=escalation_detected,
        pattern_summary=pattern,
        per_message_scores=per_message_scores,
        recommended_action=action,
        analyzed_at=datetime.utcnow().isoformat()
    )


# ─────────────────────────────────────────────
#   Run Locally
#   uvicorn ghostout_nlp_engine:app --reload
# ───────────────────────────────