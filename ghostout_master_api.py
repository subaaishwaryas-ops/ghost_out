# ============================================================
#   GhostOut — Day 4: Master API "The Brain"
#   Combines ALL 3 Engines into ONE Threat Report
#   Stack: FastAPI + httpx
# ============================================================
#
#   SETUP:
#   pip install httpx fastapi uvicorn
#
#   Make sure all 3 engines are running:
#   Port 8000 → ghostout_nlp_engine.py
#   Port 8001 → ghostout_graph_engine_v2.py
#   Port 8002 → ghostout_predator_db.py
#
#   Run: uvicorn ghostout_master_api:app --reload --port 8003
#   Docs: http://127.0.0.1:8003/docs
# ============================================================

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import httpx
import asyncio

# ─────────────────────────────────────────────
#   App Initialization
# ─────────────────────────────────────────────
app = FastAPI(
    title="GhostOut Master API",
    description="Combined Threat Intelligence — All Engines in One 🧠",
    version="4.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#   Engine URLs
# ─────────────────────────────────────────────
NLP_ENGINE_URL      = "http://127.0.0.1:8000"
GRAPH_ENGINE_URL    = "http://127.0.0.1:8001"
PREDATOR_DB_URL     = "http://127.0.0.1:8002"

# ─────────────────────────────────────────────
#   Request & Response Models
# ─────────────────────────────────────────────

class FullThreatRequest(BaseModel):
    # Account details
    user_id: str
    platform: str
    account_age_days: int
    followers: int
    following: int
    post_count: int
    profile_pic: bool = True
    bio: Optional[str] = ""

    # Message to analyze
    message: Optional[str] = ""

    # Chat history (optional)
    chat_history: Optional[List[str]] = []

class FullThreatResponse(BaseModel):
    user_id: str
    platform: str

    # Individual engine scores
    nlp_threat_score: float
    nlp_threat_level: str
    bot_score: float
    bot_likelihood: str
    is_in_predator_db: bool
    predator_db_reports: int

    # Master combined score
    master_threat_score: float
    master_threat_level: str

    # Details
    red_flags: List[str]
    recommended_actions: List[str]
    analyzed_at: str

# ─────────────────────────────────────────────
#   Master Threat Score Calculation
# ─────────────────────────────────────────────

def calculate_master_score(
    nlp_score: float,
    bot_score: float,
    db_reports: int
) -> float:
    """
    Combines all 3 engine scores into one master score.
    Weights:
      NLP Score  → 35%
      Bot Score  → 35%
      DB Reports → 30%
    """
    # DB score: each report adds 25 points, capped at 100
    db_score = min(db_reports * 25, 100)

    master = (
        nlp_score * 0.35 +
        bot_score * 0.35 +
        db_score  * 0.30
    )
    return round(min(master, 100), 2)


def get_master_threat_level(score: float) -> tuple[str, List[str]]:
    """Returns threat level + list of recommended actions."""
    if score <= 30:
        return "🟢 SAFE", [
            "No immediate action needed.",
            "Stay cautious with unknown accounts."
        ]
    elif score <= 60:
        return "🟡 SUSPICIOUS", [
            "Restrict this account's messages.",
            "Do not share personal information.",
            "Monitor further interactions."
        ]
    elif score <= 80:
        return "🟠 DANGEROUS", [
            "Block this account immediately.",
            "Save all evidence — screenshots & messages.",
            "Report to platform support.",
            "Consider filing a complaint at cybercrime.gov.in"
        ]
    else:
        return "🔴 PREDATOR", [
            "🚨 BLOCK IMMEDIATELY.",
            "Do NOT engage further.",
            "Save ALL evidence right now.",
            "File complaint: cybercrime.gov.in",
            "Contact local cyber cell if threatened.",
            "Share warning anonymously on GhostOut community."
        ]

# ─────────────────────────────────────────────
#   Engine Callers (Async)
# ─────────────────────────────────────────────

async def call_nlp_engine(message: str, user_id: str, platform: str) -> dict:
    """Calls Day 1 NLP Engine."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{NLP_ENGINE_URL}/analyze",
                json={
                    "message": message,
                    "sender_id": user_id,
                    "platform": platform
                }
            )
            return response.json()
    except Exception:
        return {"threat_score": 0, "threat_level": "⚪ UNKNOWN", "threat_keyword_hits": []}


async def call_graph_engine(
    user_id: str, platform: str,
    account_age_days: int, followers: int,
    following: int, post_count: int,
    profile_pic: bool, bio: str
) -> dict:
    """Calls Day 2 Graph Engine."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GRAPH_ENGINE_URL}/add-account",
                json={
                    "user_id": user_id,
                    "platform": platform,
                    "account_age_days": account_age_days,
                    "followers": followers,
                    "following": following,
                    "post_count": post_count,
                    "profile_pic": profile_pic,
                    "bio": bio
                }
            )
            return response.json()
    except Exception:
        return {"bot_score": 0, "bot_likelihood": "⚪ UNKNOWN", "red_flags": []}


async def call_predator_db(user_id: str, platform: str) -> dict:
    """Calls Day 3 Predator DB."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{PREDATOR_DB_URL}/check",
                json={
                    "user_id": user_id,
                    "platform": platform
                }
            )
            return response.json()
    except Exception:
        return {"is_flagged": False, "total_reports": 0, "danger_level": "⚪ UNKNOWN"}

# ─────────────────────────────────────────────
#   API Endpoints
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "GhostOut 🛡️",
        "engine": "Master API — The Brain",
        "status": "All Systems Active ✅",
        "engines_connected": {
            "nlp_engine":   f"{NLP_ENGINE_URL}/docs",
            "graph_engine": f"{GRAPH_ENGINE_URL}/docs",
            "predator_db":  f"{PREDATOR_DB_URL}/docs"
        },
        "endpoints": ["/analyze-threat", "/engines-status", "/health"]
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy ✅",
        "master_api": "running",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/engines-status")
async def engines_status():
    """Check if all 3 engines are running."""
    status = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, url in [
            ("nlp_engine",   NLP_ENGINE_URL),
            ("graph_engine", GRAPH_ENGINE_URL),
            ("predator_db",  PREDATOR_DB_URL)
        ]:
            try:
                r = await client.get(f"{url}/health")
                status[name] = "✅ Running" if r.status_code == 200 else "❌ Error"
            except Exception:
                status[name] = "❌ Offline"
    return status


# ── Master Endpoint: Full Threat Analysis ────
@app.post("/analyze-threat", response_model=FullThreatResponse)
async def analyze_threat(request: FullThreatRequest):
    """
    🧠 THE BRAIN — Calls all 3 engines simultaneously
    and returns a single combined threat report.
    """
    message = request.message or "No message provided"

    # ── Call all 3 engines in PARALLEL ──────
    nlp_result, graph_result, db_result = await asyncio.gather(
        call_nlp_engine(message, request.user_id, request.platform),
        call_graph_engine(
            request.user_id, request.platform,
            request.account_age_days, request.followers,
            request.following, request.post_count,
            request.profile_pic, request.bio or ""
        ),
        call_predator_db(request.user_id, request.platform)
    )

    # ── Extract scores ───────────────────────
    nlp_score  = nlp_result.get("threat_score", 0)
    nlp_level  = nlp_result.get("threat_level", "⚪ UNKNOWN")
    bot_score  = graph_result.get("bot_score", 0)
    bot_level  = graph_result.get("bot_likelihood", "⚪ UNKNOWN")
    is_flagged = db_result.get("is_flagged", False)
    db_reports = db_result.get("total_reports", 0)

    # ── Combine red flags from all engines ───
    red_flags = []
    red_flags.extend(graph_result.get("red_flags", []))
    if nlp_result.get("threat_keyword_hits"):
        red_flags.append(f"⚠️ Threat keywords detected: {', '.join(nlp_result['threat_keyword_hits'])}")
    if nlp_result.get("escalation_hits"):
        red_flags.append(f"🚨 Escalation phrases: {', '.join(nlp_result['escalation_hits'])}")
    if is_flagged:
        red_flags.append(f"🔴 Account reported {db_reports} time(s) by community!")

    # ── Calculate master score ───────────────
    master_score = calculate_master_score(nlp_score, bot_score, db_reports)
    master_level, actions = get_master_threat_level(master_score)

    return FullThreatResponse(
        user_id=request.user_id,
        platform=request.platform,
        nlp_threat_score=nlp_score,
        nlp_threat_level=nlp_level,
        bot_score=bot_score,
        bot_likelihood=bot_level,
        is_in_predator_db=is_flagged,
        predator_db_reports=db_reports,
        master_threat_score=master_score,
        master_threat_level=master_level,
        red_flags=red_flags,
        recommended_actions=actions,
        analyzed_at=datetime.utcnow().isoformat()
    )

# ─────────────────────────────────────────────
#   Run: uvicorn ghostout_master_api:app --reload --port 8003
# ─────────────────────────────────────────────