# ============================================================
#   GhostOut — Day 2: Graph Engine "The Web"
#   Bot Farm & Fake Account Network Detection
#   Stack: FastAPI + Neo4j Aura
# ============================================================
#
#   SETUP:
#   pip install neo4j python-dotenv fastapi uvicorn
#   Add to .env:
#     NEO4J_URI=neo4j+s://xxxxxx.databases.neo4j.io
#     NEO4J_USER=neo4j
#     NEO4J_PASSWORD=your-password
#
#   Run: uvicorn ghostout_graph_engine:app --reload --port 8001
#   Docs: http://127.0.0.1:8001/docs
# ============================================================

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from neo4j import GraphDatabase
from typing import List, Optional
from datetime import datetime
from dotenv import load_dotenv
import os
import hashlib

# ─────────────────────────────────────────────
#   Load Environment Variables
# ─────────────────────────────────────────────
load_dotenv()

NEO4J_URI      = os.getenv("NEO4J_URI")
NEO4J_USER     = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# ─────────────────────────────────────────────
#   App Initialization
# ─────────────────────────────────────────────
app = FastAPI(
    title="GhostOut Graph Engine",
    description="Bot Farm & Fake Account Network Detection 🕸️",
    version="2.0.0"
)

# ─────────────────────────────────────────────
#   Neo4j Connection
# ─────────────────────────────────────────────
driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASSWORD),
    max_connection_lifetime=30,
    connection_timeout=30,
    encrypted=True
)

def get_session():
    return driver.session()

# ─────────────────────────────────────────────
#   Privacy — Hash Account IDs
#   We never store raw usernames/IDs
#   SHA-256 hash = privacy safe ✅
# ─────────────────────────────────────────────
def hash_id(platform: str, user_id: str) -> str:
    raw = f"{platform}:{user_id}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]  # short hash for readability

# ─────────────────────────────────────────────
#   Request & Response Models
# ─────────────────────────────────────────────

class AccountNode(BaseModel):
    user_id: str
    platform: str                          # instagram / twitter / whatsapp
    account_age_days: int
    follower_count: int
    following_count: int
    post_count: int
    profile_pic: bool = True               # has profile picture?
    bio: Optional[str] = ""

class InteractionEdge(BaseModel):
    from_user_id: str
    to_user_id: str
    platform: str
    interaction_type: str                  # message / follow / comment / like
    count: int = 1                         # how many times?

class NetworkAnalysisRequest(BaseModel):
    accounts: List[AccountNode]
    interactions: List[InteractionEdge]

class BotScoreResponse(BaseModel):
    user_id: str
    hashed_id: str
    platform: str
    bot_score: float                       # 0-100
    bot_level: str                         # HUMAN / SUSPICIOUS / BOT
    red_flags: List[str]
    recommended_action: str

class NetworkAnalysisResponse(BaseModel):
    total_accounts: int
    bot_farms_detected: int
    suspicious_clusters: List[dict]
    individual_scores: List[BotScoreResponse]
    analyzed_at: str

# ─────────────────────────────────────────────
#   Bot Detection Logic
#   Scores each account based on behavior signals
# ─────────────────────────────────────────────

def calculate_bot_score(account: AccountNode) -> tuple[float, List[str]]:
    """
    Analyzes account signals to detect fake/bot profiles.
    Returns (bot_score, red_flags)
    """
    score = 0.0
    red_flags = []

    # ── Signal 1: Follow Ratio ──────────────────
    # Bots follow thousands but have few followers
    if account.follower_count > 0:
        ratio = account.following_count / account.follower_count
        if ratio > 10:
            score += 30
            red_flags.append(f"⚠️ Suspicious follow ratio: {ratio:.1f}x (following >> followers)")
        elif ratio > 5:
            score += 15
            red_flags.append(f"⚡ High follow ratio: {ratio:.1f}x")
    else:
        score += 20
        red_flags.append("⚠️ Zero followers — likely new bot account")

    # ── Signal 2: Account Age vs Activity ───────
    # New accounts with high activity = bot signal
    if account.account_age_days < 30 and account.post_count > 50:
        score += 25
        red_flags.append("⚠️ New account with unusually high post activity")
    elif account.account_age_days < 7:
        score += 20
        red_flags.append("⚡ Very new account (less than 7 days old)")

    # ── Signal 3: No Profile Picture ────────────
    if not account.profile_pic:
        score += 15
        red_flags.append("⚠️ No profile picture — common bot signal")

    # ── Signal 4: Empty Bio ──────────────────────
    if not account.bio or len(account.bio.strip()) == 0:
        score += 10
        red_flags.append("⚡ Empty bio")

    # ── Signal 5: Abnormal Post Count ───────────
    if account.post_count == 0 and account.following_count > 100:
        score += 20
        red_flags.append("⚠️ Follows many accounts but never posted")

    return round(min(score, 100), 2), red_flags


def get_bot_level(score: float) -> tuple[str, str]:
    if score <= 30:
        return "🟢 HUMAN", "No action needed."
    elif score <= 65:
        return "🟡 SUSPICIOUS", "Monitor this account. Consider restricting interactions."
    else:
        return "🔴 BOT", "Block immediately. Report to platform. Do not engage."

# ─────────────────────────────────────────────
#   Neo4j Graph Operations
# ─────────────────────────────────────────────

def create_account_node(session, account: AccountNode, hashed_id: str, bot_score: float):
    """Creates or updates an Account node in Neo4j."""
    session.run("""
        MERGE (a:Account {hashed_id: $hashed_id})
        SET a.platform = $platform,
            a.account_age_days = $account_age_days,
            a.follower_count = $follower_count,
            a.following_count = $following_count,
            a.post_count = $post_count,
            a.bot_score = $bot_score,
            a.updated_at = $updated_at
    """, {
        "hashed_id": hashed_id,
        "platform": account.platform,
        "account_age_days": account.account_age_days,
        "follower_count": account.follower_count,
        "following_count": account.following_count,
        "post_count": account.post_count,
        "bot_score": bot_score,
        "updated_at": datetime.utcnow().isoformat()
    })


def create_interaction_edge(session, from_hash: str, to_hash: str, interaction: InteractionEdge):
    """Creates an interaction edge between two accounts."""
    session.run("""
        MATCH (a:Account {hashed_id: $from_hash})
        MATCH (b:Account {hashed_id: $to_hash})
        MERGE (a)-[r:INTERACTED_WITH {type: $interaction_type}]->(b)
        SET r.count = $count,
            r.platform = $platform
    """, {
        "from_hash": from_hash,
        "to_hash": to_hash,
        "interaction_type": interaction.interaction_type,
        "count": interaction.count,
        "platform": interaction.platform
    })


def detect_bot_farms(session) -> List[dict]:
    """
    Detects clusters of bot accounts targeting same victims.
    A bot farm = 3+ suspicious accounts interacting with same target.
    """
    result = session.run("""
        MATCH (bot:Account)-[:INTERACTED_WITH]->(victim:Account)
        WHERE bot.bot_score > 65
        WITH victim, COUNT(bot) AS bot_count, COLLECT(bot.hashed_id) AS bots
        WHERE bot_count >= 2
        RETURN victim.hashed_id AS victim_id,
               bot_count,
               bots
        ORDER BY bot_count DESC
    """)

    clusters = []
    for record in result:
        clusters.append({
            "victim_id": record["victim_id"],
            "attacking_bots": record["bot_count"],
            "bot_ids": record["bots"],
            "severity": "🔴 HIGH" if record["bot_count"] >= 3 else "🟡 MEDIUM"
        })
    return clusters

# ─────────────────────────────────────────────
#   API Endpoints
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "GhostOut 🛡️",
        "engine": "Graph Engine — Day 2",
        "status": "Bot Farm Detector Running ✅",
        "endpoints": ["/analyze-network", "/bot-farms", "/health"]
    }


@app.get("/health")
def health():
    try:
        with get_session() as session:
            session.run("RETURN 1")
        return {"status": "healthy", "neo4j": "connected ✅", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Neo4j connection failed: {str(e)}")


# ── Endpoint 1: Analyze Full Network ─────────
@app.post("/analyze-network", response_model=NetworkAnalysisResponse)
def analyze_network(request: NetworkAnalysisRequest):
    """
    Analyzes a network of accounts and their interactions.
    Detects bots, fake profiles and coordinated bot farms.
    """
    if not request.accounts:
        raise HTTPException(status_code=400, detail="No accounts provided.")

    individual_scores = []
    hash_map = {}  # user_id → hashed_id

    with get_session() as session:

        # Step 1: Score each account & store in Neo4j
        for account in request.accounts:
            hashed_id = hash_id(account.platform, account.user_id)
            hash_map[account.user_id] = hashed_id

            bot_score, red_flags = calculate_bot_score(account)
            bot_level, action = get_bot_level(bot_score)

            # Store in Neo4j graph
            create_account_node(session, account, hashed_id, bot_score)

            individual_scores.append(BotScoreResponse(
                user_id=account.user_id,
                hashed_id=hashed_id,
                platform=account.platform,
                bot_score=bot_score,
                bot_level=bot_level,
                red_flags=red_flags,
                recommended_action=action
            ))

        # Step 2: Create interaction edges
        for interaction in request.interactions:
            from_hash = hash_map.get(interaction.from_user_id)
            to_hash = hash_map.get(interaction.to_user_id)
            if from_hash and to_hash:
                create_interaction_edge(session, from_hash, to_hash, interaction)

        # Step 3: Detect bot farms
        clusters = detect_bot_farms(session)

    return NetworkAnalysisResponse(
        total_accounts=len(request.accounts),
        bot_farms_detected=len(clusters),
        suspicious_clusters=clusters,
        individual_scores=individual_scores,
        analyzed_at=datetime.utcnow().isoformat()
    )


# ── Endpoint 2: Get All Bot Farms ─────────────
@app.get("/bot-farms")
def get_bot_farms():
    """Returns all detected bot farm clusters from the graph."""
    with get_session() as session:
        clusters = detect_bot_farms(session)
    return {
        "bot_farms_detected": len(clusters),
        "clusters": clusters,
        "retrieved_at": datetime.utcnow().isoformat()
    }


# ── Endpoint 3: Get High Risk Accounts ────────
@app.get("/high-risk-accounts")
def get_high_risk_accounts():
    """Returns all accounts with bot_score > 65."""
    with get_session() as session:
        result = session.run("""
            MATCH (a:Account)
            WHERE a.bot_score > 65
            RETURN a.hashed_id AS id,
                   a.platform AS platform,
                   a.bot_score AS score
            ORDER BY a.bot_score DESC
        """)
        accounts = [{"id": r["id"], "platform": r["platform"], "score": r["score"]} for r in result]

    return {
        "high_risk_count": len(accounts),
        "accounts": accounts
    }

# ─────────────────────────────────────────────
#   Run on port 8001 (Day 1 uses 8000)
#   uvicorn ghostout_graph_engine:app --reload --port 8001
# ─────────────────────────────────────────────