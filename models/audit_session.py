"""
Audit session and evidence block models.

An AuditSession represents one complete compliance test run by an
ethics-identity user (e.g. harrisampoaios@ethicsos.eu) against a
target AI service.

Each HTTP exchange during that session is recorded as an EvidenceBlock.
Blocks form a cryptographic hash chain: tampering with any block
invalidates all subsequent blocks, making the evidence tamper-evident
without requiring a full external blockchain.
"""

import hashlib
import json
from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# ── SQLAlchemy ORM ────────────────────────────────────────────────────────────

class AuditSession(Base):
    """One complete test run for a customer's AI service."""

    __tablename__ = "audit_sessions"

    id = Column(String(36), primary_key=True)
    ethics_identity = Column(String(255), nullable=False, index=True)
    # e.g. "harrisampoaios@ethicsos.eu"

    target_name = Column(String(255), nullable=False)
    # Human-readable name, e.g. "Acme Corp HR Screening API v2"

    target_base_url = Column(String(512), nullable=False)
    # The customer's API root, e.g. "https://api.acme.com/ai"

    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    status = Column(String(32), nullable=False, default="running")
    # running | completed | error

    overall_result = Column(String(16), nullable=True)
    # PASS | FAIL | PARTIAL

    compliance_score = Column(Float, nullable=True)
    # 0.0 – 100.0

    certificate_hash = Column(String(64), nullable=True)
    # SHA-256 fingerprint of the final certificate JSON

    chain_head_hash = Column(String(64), nullable=True)
    # Hash of the last EvidenceBlock — proves chain integrity


class EvidenceBlock(Base):
    """
    One HTTP exchange captured during an audit session.

    Blocks are chained: block_hash = SHA256(prev_hash + payload_hash + metadata).
    Any modification to a block breaks the chain from that point forward.
    """

    __tablename__ = "evidence_blocks"

    id = Column(String(36), primary_key=True)
    session_id = Column(String(36), nullable=False, index=True)

    sequence = Column(Integer, nullable=False)
    # Order within the session (0-based)

    scenario_id = Column(String(64), nullable=False)
    # e.g. "AIA-ART10-BIAS-001"

    eu_article = Column(String(16), nullable=False)
    # e.g. "Art. 10"

    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    # ── Request (stored by hash only — no PII retained) ──────────────────────
    request_method = Column(String(8), nullable=False)
    request_url_hash = Column(String(64), nullable=False)
    # SHA-256 of the full URL (including path/query — no PII)
    request_body_hash = Column(String(64), nullable=False)
    # SHA-256 of the request body

    # ── Response ────────────────────────────────────────────────────────────
    response_status = Column(Integer, nullable=True)
    response_body_hash = Column(String(64), nullable=True)
    response_latency_ms = Column(Integer, nullable=True)

    # ── Test outcome ─────────────────────────────────────────────────────────
    result = Column(String(8), nullable=False)   # PASS | FAIL | ERROR
    metric_name = Column(String(64), nullable=True)   # e.g. "disparate_impact_ratio"
    metric_value = Column(Float, nullable=True)
    metric_threshold = Column(Float, nullable=True)
    detail = Column(Text, nullable=True)         # Human-readable finding

    # ── Chain ────────────────────────────────────────────────────────────────
    prev_hash = Column(String(64), nullable=False)
    # "GENESIS" for the first block, otherwise the previous block's block_hash

    block_hash = Column(String(64), nullable=False, unique=True)
    # SHA-256(prev_hash + request_body_hash + response_body_hash + result + timestamp)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class AuditSessionCreate(BaseModel):
    ethics_identity: str
    target_name: str
    target_base_url: str
    target_auth_header: Optional[str] = None
    # Bearer token or API key to call the customer service — stored in memory only,
    # never persisted to the database.


class AuditSessionRead(BaseModel):
    id: str
    ethics_identity: str
    target_name: str
    target_base_url: str
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    overall_result: Optional[str]
    compliance_score: Optional[float]
    compliance_guidance: Optional[str] = None
    certificate_hash: Optional[str]
    chain_head_hash: Optional[str]

    model_config = {"from_attributes": True}


class EvidenceBlockRead(BaseModel):
    id: str
    session_id: str
    sequence: int
    scenario_id: str
    eu_article: str
    timestamp: datetime
    request_method: str
    request_url_hash: str
    request_body_hash: str
    response_status: Optional[int]
    response_latency_ms: Optional[int]
    result: str
    metric_name: Optional[str]
    metric_value: Optional[float]
    metric_threshold: Optional[float]
    detail: Optional[str]
    prev_hash: str
    block_hash: str

    model_config = {"from_attributes": True}


# ── Hash utilities ────────────────────────────────────────────────────────────

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_block_hash(
    prev_hash: str,
    request_body_hash: str,
    response_body_hash: str,
    result: str,
    timestamp: datetime,
) -> str:
    """
    Deterministic hash that binds all material fields of one evidence block.
    Any change to any input produces a completely different output.
    """
    payload = json.dumps(
        {
            "prev": prev_hash,
            "req": request_body_hash,
            "res": response_body_hash,
            "result": result,
            "ts": timestamp.isoformat(),
        },
        sort_keys=True,
    )
    return sha256(payload)


def verify_chain(blocks: list[EvidenceBlock]) -> tuple[bool, Optional[int]]:
    """
    Walk the block chain and verify no block has been tampered with.

    Returns (True, None) if the chain is intact.
    Returns (False, first_broken_sequence) if a break is detected.
    """
    prev = "GENESIS"
    for block in sorted(blocks, key=lambda b: b.sequence):
        expected = compute_block_hash(
            prev_hash=prev,
            request_body_hash=block.request_body_hash,
            response_body_hash=block.response_body_hash or "",
            result=block.result,
            timestamp=block.timestamp,
        )
        if expected != block.block_hash:
            return False, block.sequence
        prev = block.block_hash
    return True, None
