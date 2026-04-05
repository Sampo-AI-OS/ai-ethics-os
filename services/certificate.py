"""
Certificate service — generates a verifiable compliance certificate for a
completed AuditSession.

The certificate is a JSON document whose SHA-256 fingerprint is stored in
the AuditSession record.  Anyone can re-derive the fingerprint from the
certificate payload, providing cryptographic proof that the document has
not been altered since issue.
"""

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from models.audit_session import AuditSession, EvidenceBlock
from services.evidence_chain import get_session_summary, verify_session_chain


ISSUER = "EthicsOS Compliance Platform"
CERTIFICATE_VERSION = "1.0"


def _build_certificate_guidance(summary: dict) -> dict:
    scenario_results = summary.get("scenario_results", [])
    failed_scenarios = [item for item in scenario_results if item.get("result") == "FAIL"]
    top_failed = []
    for item in failed_scenarios[:3]:
        scenario_id = item.get("scenario_id")
        top_failed.append(
            {
                "scenario_id": scenario_id,
                "name": scenario_id,
                "article": item.get("eu_article"),
                "metric": item.get("metric_name"),
                "value": item.get("metric_value"),
                "threshold": item.get("metric_threshold"),
            }
        )

    score = summary.get("compliance_score", 0.0)
    articles = ", ".join(summary.get("articles_tested", [])) or "none"

    if failed_scenarios:
        summary_text = (
            f"This audit is useful for both independent assurance and development-time remediation. The tested service scored {score}/100 across {articles}. "
            f"The most important failing scenarios should be addressed before treating the system as deployment-ready."
        )
        hard_boundary = (
            "Do not treat a passing subset of controls as approval if failing scenarios still show prohibited behavior, missing explanations, absent override capability, incomplete logging, or discriminatory outcomes."
        )
    else:
        summary_text = (
            f"This audit did not detect failing scenarios in the tested control set and the service scored {score}/100 across {articles}. "
            f"Use this as development guidance as well as audit evidence: keep the tested safeguards intact as the product evolves."
        )
        hard_boundary = (
            "Do not weaken the controls that produced this result, and do not introduce new capabilities that would create prohibited practices or erode traceability, explainability, oversight, fairness, or robustness."
        )

    return {
        "summary": summary_text,
        "top_findings": top_failed,
        "hard_boundary": hard_boundary,
    }


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_certificate(db: Session, session_id: str) -> dict:
    """
    Generate and persist a compliance certificate for a completed audit session.

    The certificate JSON is deterministically ordered and hashed.
    The resulting fingerprint is stored in AuditSession.certificate_hash so that
    anyone with the certificate JSON can verify its authenticity by re-hashing.

    Returns the full certificate dict (suitable for JSON API response / PDF render).
    """
    session: AuditSession = db.get(AuditSession, session_id)
    if not session:
        raise ValueError(f"Session {session_id} not found")
    if session.status != "completed":
        raise ValueError(f"Session {session_id} is not completed (status={session.status})")

    # Verify chain integrity before issuing certificate
    chain_valid, broken_at = verify_session_chain(db, session_id)
    if not chain_valid:
        raise ValueError(
            f"Evidence chain integrity failure at block sequence {broken_at}. "
            "Certificate cannot be issued for a tampered session."
        )

    summary = get_session_summary(db, session_id)

    blocks: list[EvidenceBlock] = (
        db.query(EvidenceBlock)
        .filter(EvidenceBlock.session_id == session_id)
        .order_by(EvidenceBlock.sequence.asc())
        .all()
    )

    # Build evidence digest — a compact, hash-only representation of the chain
    evidence_digest = [
        {
            "seq": b.sequence,
            "scenario_id": b.scenario_id,
            "eu_article": b.eu_article,
            "result": b.result,
            "block_hash": b.block_hash,
        }
        for b in blocks
    ]

    issued_at = datetime.now(UTC).isoformat()

    certificate_body = {
        "version": CERTIFICATE_VERSION,
        "issuer": ISSUER,
        "issued_at": issued_at,
        "subject": {
            "ethics_identity": session.ethics_identity,
            "target_name": session.target_name,
            "target_base_url": session.target_base_url,
        },
        "audit_session": {
            "session_id": session.id,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "status": session.status,
        },
        "compliance": {
            "overall_result": session.overall_result,
            "compliance_score": session.compliance_score,
            "total_evidence_blocks": summary["total_blocks"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "errors": summary["error"],
            "articles_tested": summary["articles_tested"],
            "scenario_results": summary["scenario_results"],
            "compliance_guidance": _build_certificate_guidance(summary),
        },
        "chain": {
            "head_hash": session.chain_head_hash,
            "chain_valid": chain_valid,
            "evidence_digest": evidence_digest,
        },
    }

    # Deterministic JSON serialisation for stable hashing
    canonical_json = json.dumps(certificate_body, sort_keys=True, ensure_ascii=False)
    fingerprint = _sha256(canonical_json)

    # Attach fingerprint to certificate and persist to session
    certificate_body["fingerprint"] = fingerprint
    certificate_body["verify_instruction"] = (
        "To verify: remove the 'fingerprint' field, re-serialise with sorted keys, "
        "and compute SHA-256. The result must equal this fingerprint value."
    )

    session.certificate_hash = fingerprint
    db.commit()

    return certificate_body


def verify_certificate_fingerprint(certificate: dict) -> tuple[bool, str]:
    """
    Standalone verifier — takes a certificate dict and re-derives its fingerprint.

    Replicates the logic used during issuance so that any third party can
    verify authenticity without access to the database.

    Returns (True, fingerprint) if the certificate is genuine,
    or (False, computed_fingerprint) to show where it diverges.
    """
    claimed = certificate.get("fingerprint")
    if not claimed:
        return False, ""

    # Reconstruct exactly what was hashed during issuance
    body_without_fingerprint = {
        k: v for k, v in certificate.items()
        if k not in ("fingerprint", "verify_instruction")
    }
    canonical_json = json.dumps(body_without_fingerprint, sort_keys=True, ensure_ascii=False)
    computed = _sha256(canonical_json)

    return computed == claimed, computed
