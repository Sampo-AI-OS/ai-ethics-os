import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db, health_check, engine
from models.audit_session import (
    Base as AuditBase,
    AuditSessionRead,
    EvidenceBlockRead,
)
from models.ethical_rule import Base as RuleBase, EthicsRule, EthicsRuleCreate, EthicsRuleRead, EthicsScoreRequest, EthicsScoreResponse
from models.user import Base as UserBase, User, UserCreate, UserRead, Token
from services.ethics_scoring import calculate_score, EU_AI_ACT_RULES
from services.certificate import verify_certificate_fingerprint
from utils.config import get_current_user

# ---------- App bootstrap ----------

app = FastAPI(
    title="AI Ethics OS — EU AI Act Compliance Engine",
    description="Score AI systems against EU AI Act requirements (Articles 5, 9-15, Annex III).",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables on startup (MVP — use Alembic for production migrations)
@app.on_event("startup")
def create_tables() -> None:
    RuleBase.metadata.create_all(bind=engine)
    UserBase.metadata.create_all(bind=engine)
    AuditBase.metadata.create_all(bind=engine)
    _seed_eu_rules()


def _seed_eu_rules() -> None:
    """Insert EU AI Act baseline rules if the table is empty."""
    db: Session = next(get_db())
    try:
        existing = db.execute(select(EthicsRule)).scalars().first()
        if existing:
            return
        for rule_data in EU_AI_ACT_RULES:
            db.add(EthicsRule(**rule_data))
        db.commit()
    finally:
        db.close()


# ---------- Auth helpers ----------

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ---------- Auth routes ----------

@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["Auth"])
def register(body: UserCreate, db: Session = Depends(get_db)) -> User:
    """Register a new analyst account."""
    existing = db.execute(select(User).where(User.email == body.email)).scalars().first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    user = User(
        id=str(uuid.uuid4()),
        email=body.email,
        hashed_password=_hash_password(body.password),
        full_name=body.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token, tags=["Auth"])
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)) -> dict:
    """Authenticate and receive a Bearer token."""
    user = db.execute(select(User).where(User.email == form.username)).scalars().first()
    if not user or not _verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = _create_token({"sub": user.id, "email": user.email, "role": user.role})
    return {"access_token": token}


# ---------- Rules routes ----------

@app.get("/rules", response_model=list[EthicsRuleRead], tags=["Rules"])
def list_rules(db: Session = Depends(get_db)) -> list:
    """Return all EU AI Act compliance rules."""
    return db.execute(select(EthicsRule)).scalars().all()


@app.post("/rules", response_model=EthicsRuleRead, status_code=status.HTTP_201_CREATED, tags=["Rules"])
def create_rule(
    body: EthicsRuleCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> EthicsRule:
    """Add a custom compliance rule (requires authentication)."""
    if db.get(EthicsRule, body.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Rule ID already exists")
    rule = EthicsRule(**body.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@app.get("/rules/{rule_id}", response_model=EthicsRuleRead, tags=["Rules"])
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> EthicsRule:
    rule = db.get(EthicsRule, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@app.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Rules"])
def delete_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> None:
    rule = db.get(EthicsRule, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    db.delete(rule)
    db.commit()


# ---------- Scoring route ----------

@app.post("/score", response_model=EthicsScoreResponse, tags=["Compliance"])
def score_model(
    body: EthicsScoreRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Score an AI system against EU AI Act requirements.

    Supply `model_details` as a dict describing your AI system.
    Returns a risk classification and per-article compliance score.
    """
    rules = [r.to_dict() for r in db.execute(select(EthicsRule)).scalars().all()]
    if not rules:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No rules loaded yet")
    result = calculate_score(body.model_details, rules)
    return {
        "model_id": body.model_id,
        "total_possible": 100,
        "current_score": result["score"],
        "risk_classification": result["risk_classification"],
        "compliance_guidance": result["compliance_guidance"],
        "analysis": result["analysis"],
        "violation_rules": result["violations"],
        "remediation_hints": result["remediation_hints"],
        "timestamp": datetime.utcnow(),
    }


# ---------- Demo scenarios ----------

DEMO_SCENARIOS = {
    "hr_screening": {
        "name": "HR Candidate Screening AI",
        "eu_annex_iii": "Employment (Annex III §4)",
        "model_details": {
            "has_risk_management_system": False,
            "has_technical_documentation": False,
            "has_human_oversight": False,
            "uses_biometric_data": False,
            "logs_decisions": False,
            "uses_demographic_features": True,
            "has_explainability": False,
            "has_bias_testing": False,
            "deployed_in_public_space": False,
            "affects_fundamental_rights": True,
        },
    },
    "credit_scoring": {
        "name": "Credit Scoring AI",
        "eu_annex_iii": "Essential Services (Annex III §5)",
        "model_details": {
            "has_risk_management_system": True,
            "has_technical_documentation": True,
            "has_human_oversight": True,
            "uses_biometric_data": False,
            "logs_decisions": True,
            "uses_demographic_features": False,
            "has_explainability": True,
            "has_bias_testing": True,
            "deployed_in_public_space": False,
            "affects_fundamental_rights": True,
        },
    },
    "social_scoring": {
        "name": "Social Scoring System",
        "eu_annex_iii": "Prohibited (Article 5)",
        "model_details": {
            "has_risk_management_system": False,
            "has_technical_documentation": False,
            "has_human_oversight": False,
            "uses_biometric_data": True,
            "logs_decisions": False,
            "uses_demographic_features": True,
            "has_explainability": False,
            "has_bias_testing": False,
            "deployed_in_public_space": True,
            "affects_fundamental_rights": True,
            "is_social_scoring": True,
        },
    },
}


@app.get("/demo/scenarios", tags=["Demo"])
def list_demo_scenarios() -> dict:
    """List pre-built EU AI Act demo scenarios."""
    return {k: {"name": v["name"], "eu_annex_iii": v["eu_annex_iii"]} for k, v in DEMO_SCENARIOS.items()}


@app.post("/demo/run/{scenario_id}", response_model=EthicsScoreResponse, tags=["Demo"])
def run_demo_scenario(scenario_id: str, db: Session = Depends(get_db)) -> dict:
    """Run a pre-built demo scenario against EU AI Act rules (no auth required)."""
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scenario '{scenario_id}' not found")
    rules = [r.to_dict() for r in db.execute(select(EthicsRule)).scalars().all()]
    result = calculate_score(scenario["model_details"], rules)
    return {
        "model_id": scenario["name"],
        "total_possible": 100,
        "current_score": result["score"],
        "risk_classification": result["risk_classification"],
        "compliance_guidance": result["compliance_guidance"],
        "analysis": result["analysis"],
        "violation_rules": result["violations"],
        "remediation_hints": result["remediation_hints"],
        "timestamp": datetime.utcnow(),
    }


# ---------- Health ----------

@app.get("/health", tags=["Ops"])
def health() -> dict:
    return {"status": "ok", "db": "connected" if health_check() else "unreachable"}


# ---------- Audit routes (Behavioral Evidence Architecture) ----------

class AuditSessionLaunch(BaseModel):
    """Request body for launching a new audit session."""
    ethics_identity: str
    target_name: str
    target_base_url: str
    target_auth_header: Optional[str] = None
    # Comma-separated list of scenario IDs; omit to run all scenarios
    scenario_ids: Optional[str] = None


def _audit_feature_omitted() -> None:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "The live audit runner and proprietary scenario library are intentionally omitted from this public portfolio edition. "
            "This repository demonstrates the scoring product and selected evidence-chain concepts without shipping the full audit core."
        ),
    )


@app.get("/audit/scenarios", tags=["Audit"])
def list_scenarios() -> dict:
    """Public portfolio edition intentionally omits the live audit scenario library."""
    _audit_feature_omitted()


@app.get("/audit/scenarios/by-article", tags=["Audit"])
def scenarios_by_article() -> dict:
    """Public portfolio edition intentionally omits the live audit scenario library."""
    _audit_feature_omitted()


@app.post("/audit/sessions", response_model=AuditSessionRead, status_code=status.HTTP_202_ACCEPTED, tags=["Audit"])
async def launch_audit(
    body: AuditSessionLaunch,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
) -> AuditSessionRead:
    """
    Public portfolio edition intentionally omits the live audit runner.
    """
    _audit_feature_omitted()


@app.get("/audit/sessions", response_model=list[AuditSessionRead], tags=["Audit"])
def list_sessions(
    current_user: dict = Depends(get_current_user),
) -> list:
    """Public portfolio edition intentionally omits live audit sessions."""
    _audit_feature_omitted()


@app.get("/audit/sessions/{session_id}", response_model=AuditSessionRead, tags=["Audit"])
def get_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Public portfolio edition intentionally omits live audit sessions."""
    _audit_feature_omitted()


@app.get("/audit/sessions/{session_id}/evidence", response_model=list[EvidenceBlockRead], tags=["Audit"])
def get_evidence(
    session_id: str,
    current_user: dict = Depends(get_current_user),
) -> list:
    """Public portfolio edition intentionally omits live evidence data."""
    _audit_feature_omitted()


@app.post("/audit/sessions/{session_id}/certificate", tags=["Audit"])
def issue_certificate(
    session_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Public portfolio edition intentionally omits certificate issuance from live audit runs."""
    _audit_feature_omitted()


@app.get("/audit/verify/{session_id}", tags=["Audit"])
def public_verify(session_id: str) -> dict:
    """Public portfolio edition intentionally omits live audit-session verification."""
    _audit_feature_omitted()


@app.post("/audit/verify/certificate", tags=["Audit"])
def verify_cert(certificate: dict) -> dict:
    """
    Verify a certificate JSON payload by re-deriving its SHA-256 fingerprint.

    Accepts the full certificate JSON and returns whether it is genuine.
    No database access required — pure cryptographic verification.
    """
    valid, computed = verify_certificate_fingerprint(certificate)
    return {
        "valid": valid,
        "claimed_fingerprint": certificate.get("fingerprint"),
        "computed_fingerprint": computed,
        "compliance_guidance": certificate.get("compliance", {}).get("compliance_guidance"),
        "message": (
            "Certificate is genuine — fingerprint matches."
            if valid
            else "VERIFICATION FAILED — certificate fingerprint does not match content."
        ),
    }

