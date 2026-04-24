# ============================================================
#   GhostOut — Day 2: Graph Engine V2 "The Network Hunter"
#   Bot Farm & Fake Account Network Detection
#   Stack: FastAPI + NetworkX (No external DB needed!)
# ============================================================
#
#   SETUP:
#   pip install networkx fastapi uvicorn
#
#   Run: uvicorn ghostout_graph_engine_v2:app --reload --port 8001
#   Docs: http://127.0.0.1:8001/docs
# ============================================================

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import hashlib
import networkx as nx

# ─────────────────────────────────────────────
#   App Initialization
# ─────────────────────────────────────────────
app = FastAPI(
    title="GhostOut Graph Engine V2",
    description="Bot Farm & Fake Account Network Detection 🕸️",
    version="2.0.0"
)

# ─────────────────────────────────────────────
#   In-Memory Graph Database
#   NetworkX DiGraph = Directed Graph
#   Nodes = Accounts
#   Edges = Interactions between accounts
# ─────────────────────────────────────────────
graph = nx.DiGraph()

# ─────────────────────────────────────────────
#   Privacy: Hash Account IDs
#   SHA-256 — never store raw usernames
# ─────────────────────────────────────────────
def hash_account_id(platform: str, user_id: str) -> str:
    raw = f"{platform.lower()}:{user_id.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

# ─────────────────────────────────────────────
#   Request & Response Models
# ─────────────────────────────────────────────

class AccountNode(BaseModel):
    user_id: str
    platform: str
    account_age_days: int
    followers: int
    following: int
    post_count: int
    profile_pic: bool = True
    bio: Optional[str] = ""

class InteractionEdge(BaseModel):
    from_user_id: str
    to_user_id: str
    platform: str
    interaction_type: str
    count: int = 1

class NetworkAnalysisRequest(BaseModel):
    accounts: List[AccountNode]
    interactions: List[InteractionEdge]

class BotScoreResponse(BaseModel):
    user_id: str
    hashed_id: str
    bot_score: float
    bot_likelihood: str
    red_flags: List[str]
    analyzed_at: str

class NetworkAnalysisResponse(BaseModel):
    total_accounts: int
    total_interactions: int
    bot_farm_detected: bool
    suspicious_accounts: List[BotScoreResponse]
    network_risk_score: float
    network_summary: str
    graph_stats: dict
    analyzed_at: str

# ─────────────────────────────────────────────
#   Bot Detection Logic
# ─────────────────────────────────────────────

def calculate_bot_score(account: AccountNode) -> tuple[float, List[str]]:
    score = 0.0
    red_flags = []

    # Signal 1: Follow ratio
    if account.following > 0:
        ratio = account.followers / account.following
        if ratio < 0.1:
            score += 25
            red_flags.append("⚠️ Extremely low follower/following ratio")
        elif ratio < 0.3:
            score += 15
            red_flags.append("⚠️ Suspicious follower/following ratio")

    # Signal 2: New account + high activity
    if account.account_age_days < 30 and account.post_count > 50:
        score += 20
        red_flags.append("⚠️ New account with unusually high post count")

    # Signal 3: No profile picture
    if not account.profile_pic:
        score += 15
        red_flags.append("⚠️ No profile picture")

    # Signal 4: Empty bio
    if not account.bio or len(account.bio.strip()) < 5:
        score += 10
        red_flags.append("⚠️ Empty or minimal bio")

    # Signal 5: Very new account
    if account.account_age_days < 7:
        score += 20
        red_flags.append("🚨 Account created less than 7 days ago")

    # Signal 6: Zero posts
    if account.post_count == 0:
        score += 10
        red_flags.append("⚠️ Account has zero posts")

    # Signal 7: Mass following
    if account.following > 5000:
        score += 15
        red_flags.append("⚠️ Following unusually large number of accounts")

    return round(min(score, 100), 2), red_flags


def get_bot_likelihood(score: float) -> str:
    if score <= 30:
        return "🟢 LOW"
    elif score <= 60:
        return "🟡 MEDIUM"
    else:
        return "🔴 HIGH"


def detect_bot_farm(g: nx.DiGraph) -> bool:
    """
    Bot farm = 3 or more HIGH risk accounts
    all sending interactions TO the same target account.
    This is the core graph detection algorithm.
    """
    for node in g.nodes():
        # Get all accounts pointing TO this node
        predecessors = list(g.predecessors(node))
        # Check how many of those are HIGH risk bots
        bot_attackers = [
            p for p in predecessors
            if g.nodes[p].get("bot_score", 0) > 60
        ]
        if len(bot_attackers) >= 3:
            return True
    return False

# ─────────────────────────────────────────────
#   API Endpoints
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "GhostOut 🛡️",
        "engine": "Graph Engine V2 — NetworkX",
        "status": "Network Hunter Running ✅",
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "endpoints": ["/add-account", "/analyze-network", "/graph-stats", "/health"]
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy ✅",
        "engine": "NetworkX in-memory graph",
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/graph-stats")
def graph_stats():
    """Returns current state of the in-memory graph."""
    if graph.number_of_nodes() == 0:
        return {"message": "Graph is empty — add accounts first!"}

    return {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "all_accounts": [
            {
                "hashed_id": node,
                "bot_score": graph.nodes[node].get("bot_score", 0),
                "platform": graph.nodes[node].get("platform", "unknown"),
                "bot_likelihood": get_bot_likelihood(
                    graph.nodes[node].get("bot_score", 0)
                )
            }
            for node in graph.nodes()
        ]
    }


# ── Endpoint: Add Single Account ─────────────
@app.post("/add-account", response_model=BotScoreResponse)
def add_account(account: AccountNode):
    """
    Adds a single account to the graph & calculates bot score.
    """
    hashed_id = hash_account_id(account.platform, account.user_id)
    bot_score, red_flags = calculate_bot_score(account)
    bot_likelihood = get_bot_likelihood(bot_score)

    # Add node to in-memory graph
    graph.add_node(
        hashed_id,
        platform=account.platform,
        bot_score=bot_score,
        created_at=datetime.utcnow().isoformat()
    )

    return BotScoreResponse(
        user_id=account.user_id,
        hashed_id=hashed_id,
        bot_score=bot_score,
        bot_likelihood=bot_likelihood,
        red_flags=red_flags,
        analyzed_at=datetime.utcnow().isoformat()
    )


# ── Endpoint: Full Network Analysis ──────────
@app.post("/analyze-network", response_model=NetworkAnalysisResponse)
def analyze_network(request: NetworkAnalysisRequest):
    """
    Full network analysis — detects bot farms targeting a victim.
    Submit multiple accounts + interactions to map the network.
    """
    if not request.accounts:
        raise HTTPException(status_code=400, detail="No accounts provided.")

    suspicious_accounts = []
    all_scores = []
    account_hashes = {}

    # Step 1: Add all accounts as graph nodes
    for account in request.accounts:
        hashed_id = hash_account_id(account.platform, account.user_id)
        bot_score, red_flags = calculate_bot_score(account)
        bot_likelihood = get_bot_likelihood(bot_score)
        account_hashes[account.user_id] = hashed_id
        all_scores.append(bot_score)

        graph.add_node(
            hashed_id,
            platform=account.platform,
            bot_score=bot_score,
            created_at=datetime.utcnow().isoformat()
        )

        if bot_score > 30:
            suspicious_accounts.append(BotScoreResponse(
                user_id=account.user_id,
                hashed_id=hashed_id,
                bot_score=bot_score,
                bot_likelihood=bot_likelihood,
                red_flags=red_flags,
                analyzed_at=datetime.utcnow().isoformat()
            ))

    # Step 2: Add interaction edges
    for edge in request.interactions:
        from_hash = account_hashes.get(edge.from_user_id)
        to_hash = account_hashes.get(edge.to_user_id)
        if from_hash and to_hash:
            graph.add_edge(
                from_hash,
                to_hash,
                interaction_type=edge.interaction_type,
                count=edge.count
            )

    # Step 3: Detect bot farm
    bot_farm_detected = detect_bot_farm(graph)

    # Network risk score
    network_risk = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0

    # Summary
    if bot_farm_detected:
        summary = "🚨 BOT FARM DETECTED — Multiple fake accounts coordinating to target a victim!"
    elif network_risk > 60:
        summary = "⚠️ HIGH RISK — Multiple suspicious accounts in this network."
    elif network_risk > 30:
        summary = "⚡ MODERATE RISK — Some suspicious accounts detected."
    else:
        summary = "✅ Network appears mostly legitimate."

    return NetworkAnalysisResponse(
        total_accounts=len(request.accounts),
        total_interactions=len(request.interactions),
        bot_farm_detected=bot_farm_detected,
        suspicious_accounts=suspicious_accounts,
        network_risk_score=network_risk,
        network_summary=summary,
        graph_stats={
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges()
        },
        analyzed_at=datetime.utcnow().isoformat()
    )

# ─────────────────────────────────────────────
#   Run: uvicorn ghostout_graph_engine_v2:app --reload --port 8001
# ─────────────────────────────────────────────