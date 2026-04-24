# ============================================================
#   GhostOut — Day 3: Predator Database "The Shield"
#   Privacy-Safe Community Blocklist
#   Stack: FastAPI + TinyDB + SHA-256 Hashing
# ============================================================
#
#   SETUP:
#   pip install tinydb fastapi uvicorn
#
#   Run: uvicorn ghostout_predator_db:app --reload --port 8002
#   Docs: http://127.0.0.1:8002/docs
# ============================================================

from fastapi import FastAPI, HTTPException
from fasapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from tinydb import TinyDB, Query
from typing import List, Optional
from datetime import datetime
import hashlib
import os

# ─────────────────────────────────────────────
#   App Initialization
# ─────────────────────────────────────────────
app = FastAPI(
    title="GhostOut Predator DB",
    description="Privacy-Safe Community Predator Blocklist 🔒",
    version="3.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#   TinyDB Setup
#   Stores data in a local JSON file
#   Zero network needed!
# ─────────────────────────────────────────────
db = TinyDB("ghostout_predator_db.json")
predators_table = db.table("predators")
reports_table   = db.table("reports")
evidence_table  = db.table("evidence")

# ─────────────────────────────────────────────
#   Privacy: SHA-256 Hashing
#   We NEVER store raw usernames or IDs
#   Only hashes — cannot be reverse engineered
# ─────────────────────────────────────────────
def hash_predator_id(platform: str, user_id: str) -> str:
    """
    Creates a privacy-safe hash of predator identity.
    SHA-256(platform:user_id) → 64 char hex string
    """
    raw = f"{platform.lower()}:{user_id.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def hash_reporter_id(reporter_id: str) -> str:
    """Hashes reporter identity to protect victims too."""
    return hashlib.sha256(reporter_id.encode()).hexdigest()[:16]

# ─────────────────────────────────────────────
#   Request & Response Models
# ─────────────────────────────────────────────

class ReportRequest(BaseModel):
    predator_user_id: str
    platform: str                    # instagram / whatsapp / twitter
    reporter_id: str                 # victim's anonymous ID
    incident_type: str               # harassment / stalking / threats / grooming
    description: str
    evidence_urls: Optional[List[str]] = []

class CheckRequest(BaseModel):
    user_id: str
    platform: str

class EvidenceRequest(BaseModel):
    predator_user_id: str
    platform: str
    evidence_items: List[str]        # screenshots, message logs, etc.
    reporter_id: str

class ReportResponse(BaseModel):
    message: str
    predator_hash: str
    report_id: str
    total_reports_against: int
    danger_level: str
    analyzed_at: str

class CheckResponse(BaseModel):
    user_id: str
    platform: str
    is_flagged: bool
    total_reports: int
    danger_level: str
    incident_types: List[str]
    first_reported: Optional[str]
    last_reported: Optional[str]
    recommended_action: str
    checked_at: str

class EvidenceResponse(BaseModel):
    evidence_id: str
    predator_hash: str
    items_stored: int
    legal_package_ready: bool
    cybercrime_portal: str
    stored_at: str

# ─────────────────────────────────────────────
#   Danger Level Logic
# ─────────────────────────────────────────────

def get_danger_level(report_count: int) -> tuple[str, str]:
    """
    Maps report count to danger level + action.
    Returns (danger_level, recommended_action)
    """
    if report_count == 0:
        return "⚪ UNKNOWN", "No reports yet — stay cautious."
    elif report_count == 1:
        return "🟡 SUSPICIOUS", "1 report filed. Monitor interactions carefully."
    elif report_count <= 3:
        return "🟠 DANGEROUS", "Multiple reports! Restrict this account immediately."
    else:
        return "🔴 PREDATOR", "ALERT! Known predator — Block immediately & report to cybercrime.gov.in"

# ─────────────────────────────────────────────
#   API Endpoints
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "GhostOut 🛡️",
        "engine": "Predator DB — Day 3",
        "status": "Shield Active ✅",
        "total_predators": len(predators_table),
        "total_reports": len(reports_table),
        "endpoints": ["/report", "/check", "/store-evidence", "/stats", "/health"]
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy ✅",
        "engine": "TinyDB + SHA-256",
        "total_predators_tracked": len(predators_table),
        "total_reports": len(reports_table),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/stats")
def get_stats():
    """Returns database statistics."""
    all_predators = predators_table.all()
    if not all_predators:
        return {"message": "No reports yet — database is empty."}

    return {
        "total_unique_predators": len(all_predators),
        "total_reports": len(reports_table),
        "total_evidence_packages": len(evidence_table),
        "platforms_covered": list(set(
            p.get("platform", "unknown") for p in all_predators
        )),
        "most_reported": max(
            all_predators,
            key=lambda x: x.get("report_count", 0)
        ).get("report_count", 0)
    }


# ── Endpoint 1: Report a Predator ────────────
@app.post("/report", response_model=ReportResponse)
def report_predator(request: ReportRequest):
    """
    Anonymously report a predator account.
    Identity is hashed — reporter stays protected.
    """
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="Description cannot be empty.")

    # Hash both predator and reporter identities
    predator_hash = hash_predator_id(request.platform, request.predator_user_id)
    reporter_hash = hash_reporter_id(request.reporter_id)
    report_id     = f"RPT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    # Check if predator already exists in DB
    Predator = Query()
    existing = predators_table.get(Predator.predator_hash == predator_hash)

    if existing:
        # Update existing predator record
        new_count = existing["report_count"] + 1
        incident_types = list(set(
            existing.get("incident_types", []) + [request.incident_type]
        ))
        predators_table.update(
            {
                "report_count": new_count,
                "incident_types": incident_types,
                "last_reported": datetime.utcnow().isoformat()
            },
            Predator.predator_hash == predator_hash
        )
    else:
        # New predator — add to DB
        new_count = 1
        predators_table.insert({
            "predator_hash": predator_hash,
            "platform": request.platform,
            "report_count": 1,
            "incident_types": [request.incident_type],
            "first_reported": datetime.utcnow().isoformat(),
            "last_reported": datetime.utcnow().isoformat()
        })

    # Store the individual report
    reports_table.insert({
        "report_id": report_id,
        "predator_hash": predator_hash,
        "reporter_hash": reporter_hash,
        "incident_type": request.incident_type,
        "description_length": len(request.description),
        "has_evidence": len(request.evidence_urls) > 0,
        "reported_at": datetime.utcnow().isoformat()
    })

    danger_level, _ = get_danger_level(new_count)

    return ReportResponse(
        message="✅ Report filed successfully. Thank you for keeping the community safe.",
        predator_hash=predator_hash[:16] + "...",   # partial hash for privacy
        report_id=report_id,
        total_reports_against=new_count,
        danger_level=danger_level,
        analyzed_at=datetime.utcnow().isoformat()
    )


# ── Endpoint 2: Check if Account is Flagged ──
@app.post("/check", response_model=CheckResponse)
def check_account(request: CheckRequest):
    """
    Check if an account has been reported by the community.
    Safe to use — only hashes are compared, never raw IDs.
    """
    predator_hash = hash_predator_id(request.platform, request.user_id)

    Predator = Query()
    existing = predators_table.get(Predator.predator_hash == predator_hash)

    if not existing:
        return CheckResponse(
            user_id=request.user_id,
            platform=request.platform,
            is_flagged=False,
            total_reports=0,
            danger_level="⚪ UNKNOWN",
            incident_types=[],
            first_reported=None,
            last_reported=None,
            recommended_action="No reports found. Stay cautious with unknown accounts.",
            checked_at=datetime.utcnow().isoformat()
        )

    report_count = existing.get("report_count", 0)
    danger_level, action = get_danger_level(report_count)

    return CheckResponse(
        user_id=request.user_id,
        platform=request.platform,
        is_flagged=True,
        total_reports=report_count,
        danger_level=danger_level,
        incident_types=existing.get("incident_types", []),
        first_reported=existing.get("first_reported"),
        last_reported=existing.get("last_reported"),
        recommended_action=action,
        checked_at=datetime.utcnow().isoformat()
    )


# ── Endpoint 3: Store Evidence Package ───────
@app.post("/store-evidence", response_model=EvidenceResponse)
def store_evidence(request: EvidenceRequest):
    """
    Securely stores evidence items with timestamps.
    Creates a legal evidence package for cybercrime reporting.
    """
    if not request.evidence_items:
        raise HTTPException(status_code=400, detail="No evidence items provided.")

    predator_hash = hash_predator_id(request.platform, request.predator_user_id)
    reporter_hash = hash_reporter_id(request.reporter_id)
    evidence_id   = f"EVD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    # Hash each evidence item for tamper-proof storage
    hashed_evidence = [
        {
            "item_hash": hashlib.sha256(item.encode()).hexdigest(),
            "item_length": len(item),
            "timestamp": datetime.utcnow().isoformat()
        }
        for item in request.evidence_items
    ]

    evidence_table.insert({
        "evidence_id": evidence_id,
        "predator_hash": predator_hash,
        "reporter_hash": reporter_hash,
        "platform": request.platform,
        "evidence_count": len(request.evidence_items),
        "hashed_evidence": hashed_evidence,
        "created_at": datetime.utcnow().isoformat()
    })

    return EvidenceResponse(
        evidence_id=evidence_id,
        predator_hash=predator_hash[:16] + "...",
        items_stored=len(request.evidence_items),
        legal_package_ready=True,
        cybercrime_portal="https://cybercrime.gov.in",
        stored_at=datetime.utcnow().isoformat()
    )

# ─────────────────────────────────────────────
#   Run: uvicorn ghostout_predator_db:app --reload --port 8002
# ─────────────────────────────────────────────