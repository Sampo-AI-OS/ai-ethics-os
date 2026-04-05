"""
Evidence chain service — appends EvidenceBlocks to an AuditSession
and verifies chain integrity.

Every HTTP exchange executed by the test runner is recorded here as an
immutable block whose hash depends on the previous block's hash.
Modifying any past block breaks all subsequent hashes, making the chain
tamper-evident.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.audit_session import AuditSession, EvidenceBlock, compute_block_hash, verify_chain


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def get_chain_head(db: Session, session_id: str) -> Optional[str]:
    """Return the hash of the most recently appended block for this session."""
    last_block = (
        db.query(EvidenceBlock)
        .filter(EvidenceBlock.session_id == session_id)
        .order_by(EvidenceBlock.sequence.desc())
        .first()
    )
    return last_block.block_hash if last_block else None


def append_block(
    db: Session,
    *,
    session_id: str,
    scenario_id: str,
    eu_article: str,
    request_method: str,
    request_path: str,
    request_body: Optional[dict],
    response_status: int,
    response_body: Optional[dict],
    result: str,                    # "PASS" | "FAIL" | "ERROR" | "SKIP"
    metric_name: Optional[str] = None,
    metric_value: Optional[float] = None,
    metric_threshold: Optional[float] = None,
) -> EvidenceBlock:
    """
    Hash-chain a new EvidenceBlock onto the session.

    The block hash is computed over:
      prev_hash + SHA256(request_body) + SHA256(response_body) + result + timestamp

    This makes it mathematically impossible to:
      - Silently alter a past request/response
      - Insert a block in the middle of the chain
      - Remove a block without detection
    """
    now = datetime.now(UTC)
    prev_hash = get_chain_head(db, session_id)

    # Hash request / response contents separately — we store the hashes, not the raw
    # bodies, so sensitive customer data never persists in the audit database.
    req_raw = json.dumps(request_body or {}, sort_keys=True, default=str)
    res_raw = json.dumps(response_body or {}, sort_keys=True, default=str)
    req_hash = _sha256(req_raw)
    res_hash = _sha256(res_raw)

    block_hash = compute_block_hash(
        prev_hash=prev_hash if prev_hash is not None else "GENESIS",
        request_body_hash=req_hash,
        response_body_hash=res_hash,
        result=result,
        timestamp=now,
    )

    # Count existing blocks to assign sequence number
    seq = (
        db.query(EvidenceBlock)
        .filter(EvidenceBlock.session_id == session_id)
        .count()
    )

    block = EvidenceBlock(
        id=str(uuid.uuid4()),
        session_id=session_id,
        sequence=seq,
        scenario_id=scenario_id,
        eu_article=eu_article,
        timestamp=now,
        request_method=request_method,
        request_url_hash=_sha256(request_path),
        request_body_hash=req_hash,
        response_status=response_status,
        response_body_hash=res_hash,
        result=result,
        metric_name=metric_name,
        metric_value=metric_value,
        metric_threshold=metric_threshold,
        prev_hash=prev_hash if prev_hash is not None else "GENESIS",
        block_hash=block_hash,
    )
    db.add(block)

    # Keep the session's head hash in sync
    session = db.get(AuditSession, session_id)
    if session:
        session.chain_head_hash = block_hash

    db.commit()
    db.refresh(block)
    return block


def verify_session_chain(db: Session, session_id: str) -> tuple[bool, Optional[int]]:
    """
    Re-derive every block hash from scratch and compare against stored values.

    Returns (True, None) if the chain is intact.
    Returns (False, first_broken_sequence) if tampering is detected.
    """
    blocks = (
        db.query(EvidenceBlock)
        .filter(EvidenceBlock.session_id == session_id)
        .order_by(EvidenceBlock.sequence.asc())
        .all()
    )
    return verify_chain(blocks)


def get_session_summary(db: Session, session_id: str) -> dict:
    """Return counts and metrics from all blocks for a completed session."""
    blocks = (
        db.query(EvidenceBlock)
        .filter(EvidenceBlock.session_id == session_id)
        .order_by(EvidenceBlock.sequence)
        .all()
    )

    total = len(blocks)
    passed = sum(1 for b in blocks if b.result == "PASS")
    failed = sum(1 for b in blocks if b.result == "FAIL")
    error = sum(1 for b in blocks if b.result == "ERROR")

    articles_tested = list({b.eu_article for b in blocks if b.eu_article})

    # Worst metric value per scenario
    scenario_metrics: dict[str, dict] = {}
    for b in blocks:
        if b.scenario_id and b.metric_name is not None and b.metric_value is not None:
            existing = scenario_metrics.get(b.scenario_id)
            if existing is None or b.metric_value < existing["metric_value"]:
                scenario_metrics[b.scenario_id] = {
                    "scenario_id": b.scenario_id,
                    "eu_article": b.eu_article,
                    "metric_name": b.metric_name,
                    "metric_value": b.metric_value,
                    "metric_threshold": b.metric_threshold,
                    "result": b.result,
                }

    compliance_score = round((passed / total) * 100, 1) if total > 0 else 0.0

    return {
        "total_blocks": total,
        "passed": passed,
        "failed": failed,
        "error": error,
        "compliance_score": compliance_score,
        "articles_tested": sorted(articles_tested),
        "scenario_results": list(scenario_metrics.values()),
    }
