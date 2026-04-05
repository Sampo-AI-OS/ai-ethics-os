"""
EU AI Act compliance scoring engine.

Each rule maps to a specific EU AI Act article or Annex III requirement.
`model_details` is a flat dict of boolean/string flags describing the AI system under review.
"""

from typing import Any


_RULE_TITLES: dict[str, str] = {
    "AIA-ART5-001": "Social scoring is prohibited",
    "AIA-ART5-002": "Real-time public biometric identification is prohibited",
    "AIA-ART9-001": "Risk management system is missing",
    "AIA-ART10-001": "Protected demographic features lack mitigation",
    "AIA-ART10-002": "Bias testing is not documented",
    "AIA-ART11-001": "Technical documentation is missing",
    "AIA-ART12-001": "Decision logging is missing",
    "AIA-ART13-001": "Explainability is missing",
    "AIA-ART14-001": "Human oversight is missing",
    "AIA-ART15-001": "Accuracy and robustness controls are missing",
}

# ---------------------------------------------------------------------------
# EU AI Act baseline rules (seeded into the database on first startup)
# ---------------------------------------------------------------------------

EU_AI_ACT_RULES: list[dict[str, Any]] = [
    # --- Prohibited practices (Article 5) ---
    {
        "id": "AIA-ART5-001",
        "category": "Prohibited Practice",
        "severity": 5,
        "eu_article": "Art. 5",
        "risk_level": "Prohibited",
        "rule_text": "The system must not be a social scoring system that evaluates individuals based on social behaviour or personal characteristics.",
        "dynamic_params": {"check_key": "is_social_scoring", "expected": False},
    },
    {
        "id": "AIA-ART5-002",
        "category": "Prohibited Practice",
        "severity": 5,
        "eu_article": "Art. 5",
        "risk_level": "Prohibited",
        "rule_text": "The system must not perform real-time remote biometric identification in publicly accessible spaces for law enforcement.",
        "dynamic_params": {"check_key": "is_realtime_biometric_public", "expected": False},
    },
    # --- Risk Management (Article 9) ---
    {
        "id": "AIA-ART9-001",
        "category": "Risk Management",
        "severity": 4,
        "eu_article": "Art. 9",
        "risk_level": "High",
        "rule_text": "A documented risk management system must be established and maintained throughout the AI system lifecycle.",
        "dynamic_params": {"check_key": "has_risk_management_system", "expected": True},
    },
    # --- Data Governance (Article 10) ---
    {
        "id": "AIA-ART10-001",
        "category": "Data Governance",
        "severity": 4,
        "eu_article": "Art. 10",
        "risk_level": "High",
        "rule_text": "The system must not use protected demographic features (race, sex, age) as training features without documented bias mitigation.",
        "dynamic_params": {"check_key": "uses_demographic_features", "expected": False},
    },
    {
        "id": "AIA-ART10-002",
        "category": "Data Governance",
        "severity": 3,
        "eu_article": "Art. 10",
        "risk_level": "High",
        "rule_text": "Bias detection and mitigation must be documented and tested on training, validation, and test datasets.",
        "dynamic_params": {"check_key": "has_bias_testing", "expected": True},
    },
    # --- Technical Documentation (Article 11) ---
    {
        "id": "AIA-ART11-001",
        "category": "Documentation",
        "severity": 3,
        "eu_article": "Art. 11",
        "risk_level": "High",
        "rule_text": "Comprehensive technical documentation (Annex IV) must be prepared before market placement.",
        "dynamic_params": {"check_key": "has_technical_documentation", "expected": True},
    },
    # --- Record Keeping (Article 12) ---
    {
        "id": "AIA-ART12-001",
        "category": "Record Keeping",
        "severity": 3,
        "eu_article": "Art. 12",
        "risk_level": "High",
        "rule_text": "The system must automatically log events and decisions to ensure traceability and post-deployment risk review.",
        "dynamic_params": {"check_key": "logs_decisions", "expected": True},
    },
    # --- Transparency (Article 13) ---
    {
        "id": "AIA-ART13-001",
        "category": "Transparency",
        "severity": 3,
        "eu_article": "Art. 13",
        "risk_level": "High",
        "rule_text": "The system must provide sufficient explainability so that deployers can interpret and challenge its outputs.",
        "dynamic_params": {"check_key": "has_explainability", "expected": True},
    },
    # --- Human Oversight (Article 14) ---
    {
        "id": "AIA-ART14-001",
        "category": "Human Oversight",
        "severity": 4,
        "eu_article": "Art. 14",
        "risk_level": "High",
        "rule_text": "The system must be designed to allow trained human operators to override or disregard its outputs.",
        "dynamic_params": {"check_key": "has_human_oversight", "expected": True},
    },
    # --- Accuracy & Robustness (Article 15) ---
    {
        "id": "AIA-ART15-001",
        "category": "Accuracy & Robustness",
        "severity": 3,
        "eu_article": "Art. 15",
        "risk_level": "High",
        "rule_text": "Accuracy metrics and robustness thresholds must be defined, tested, and documented for the intended use case.",
        "dynamic_params": {"check_key": "has_accuracy_metrics", "expected": True},
    },
]

# Remediation hints keyed by rule ID
_REMEDIATION: dict[str, str] = {
    "AIA-ART5-001": "Remove social scoring functionality entirely - this practice is banned under EU AI Act Art. 5.",
    "AIA-ART5-002": "Disable real-time biometric identification in public spaces or obtain explicit judicial authorisation.",
    "AIA-ART9-001": "Establish a documented risk management system covering the full AI lifecycle (ISO/IEC 23894 is a useful framework).",
    "AIA-ART10-001": "Remove protected demographic features from model inputs or document a rigorous bias impact assessment.",
    "AIA-ART10-002": "Implement bias detection across training/validation/test splits and document results in the technical file.",
    "AIA-ART11-001": "Create an Annex IV-compliant technical documentation file before deployment.",
    "AIA-ART12-001": "Enable automatic event logging for all model decisions; retain logs for at least 6 months.",
    "AIA-ART13-001": "Add a model explainability layer (e.g., SHAP, LIME) and surface explanations to end users.",
    "AIA-ART14-001": "Implement a human-in-the-loop override mechanism with clear UI affordances for operators.",
    "AIA-ART15-001": "Define accuracy KPIs, run robustness tests, and publish performance thresholds in the technical file.",
}


# ---------------------------------------------------------------------------
# Core violation check
# ---------------------------------------------------------------------------

def check_violation(model_details: dict[str, Any], rule: dict[str, Any]) -> float:
    """
    Return 1.0 if the rule is violated, 0.0 if it is satisfied.

    Rules carry a `dynamic_params` dict with:
      - `check_key`: the key to look up in `model_details`
      - `expected`: the value that means *compliant*
    """
    params = rule.get("dynamic_params") or {}
    check_key = params.get("check_key")
    expected = params.get("expected")

    if check_key is None:
        return 0.0  # no machine-checkable condition — assume compliant

    actual = model_details.get(check_key)
    if actual is None:
        # Key not provided — treat as unknown/non-compliant for high-severity rules
        return 0.5 if rule.get("severity", 1) >= 4 else 0.0

    return 0.0 if actual == expected else 1.0


# ---------------------------------------------------------------------------
# Composite scorer
# ---------------------------------------------------------------------------

def calculate_score(model_details: dict[str, Any], rules: list[dict[str, Any]]) -> dict:
    """
    Calculate an EU AI Act compliance score (0–100) for an AI system.

    Returns:
        score               — integer 0–100 (higher = more compliant)
        risk_classification — Prohibited / High-Risk / Limited / Minimal
        violations          — list of violated rule IDs
        remediation_hints   — actionable fix descriptions per violation
        detailed_scores     — per-rule violation score (for charting)
    """
    if not rules:
        return {
            "score": 0,
            "risk_classification": "Unknown",
            "violations": [],
            "remediation_hints": [],
            "detailed_scores": [],
            "analysis": "No rules were available, so the system could not be assessed. Load a rule set before interpreting the result.",
            "compliance_guidance": "No rules were available, so the system could not be assessed. Load a rule set before interpreting the result.",
        }

    violations: list[str] = []
    remediation_hints: list[str] = []
    detailed_scores: list[dict] = []
    weighted_penalty = 0.0
    max_weight = 0.0

    for rule in rules:
        weight = rule.get("severity", 1) / 5.0  # normalise to 0..1
        max_weight += weight
        v = check_violation(model_details, rule)
        weighted_penalty += weight * v
        detailed_scores.append({"rule_id": rule["id"], "violation": v, "severity": rule.get("severity")})
        # A partial penalty (e.g. missing high-severity input data) should lower confidence
        # without being reported as a confirmed legal violation.
        if v >= 1.0:
            violations.append(rule["id"])
            if rule["id"] in _REMEDIATION:
                remediation_hints.append(_REMEDIATION[rule["id"]])

    compliance_ratio = 1.0 - (weighted_penalty / max_weight) if max_weight else 1.0
    score = round(compliance_ratio * 100)

    # Risk classification
    prohibited_violations = [
        r for r in violations if r.startswith("AIA-ART5")
    ]
    if prohibited_violations:
        risk_classification = "Prohibited"
    elif score < 60:
        risk_classification = "High-Risk - Non-Compliant"
    elif score < 80:
        risk_classification = "High-Risk - Needs Review"
    else:
        risk_classification = "High-Risk - Compliant"

    guidance = _build_compliance_guidance(risk_classification, score, violations)

    return {
        "score": score,
        "risk_classification": risk_classification,
        "violations": violations,
        "remediation_hints": remediation_hints,
        "detailed_scores": detailed_scores,
        "analysis": guidance,
        "compliance_guidance": guidance,
    }


def _top_violation_titles(violations: list[str], limit: int = 3) -> str:
    if not violations:
        return "none"
    titles = [_RULE_TITLES.get(rule_id, rule_id) for rule_id in violations[:limit]]
    return "; ".join(titles)


def _build_compliance_guidance(risk_classification: str, score: int, violations: list[str]) -> str:
    article_refs = ", ".join(sorted({rule_id.split("-")[1] for rule_id in violations})) if violations else "none"
    top_findings = _top_violation_titles(violations)

    if risk_classification == "Prohibited":
        return (
            f"This result means the system crosses a prohibited line under the EU AI Act, not merely a high-risk compliance gap. "
            f"Confirmed violations were detected in {article_refs}. The most important findings are: {top_findings}. In practical terms, documentation, logging, or oversight would not make this use acceptable while a prohibited capability remains present. "
            f"The immediate boundary is clear: remove the prohibited functionality first, then reassess the remaining high-risk obligations."
        )

    if risk_classification == "High-Risk - Non-Compliant":
        return (
            f"This result means the use case may be legally assessable as high-risk, but the current control set is materially insufficient. "
            f"The score is {score}/100 and confirmed gaps were found in {article_refs}. The most important findings are: {top_findings}. A user should read this as a warning that the system is not ready to rely on for regulated deployment. "
            f"The boundary not to cross is treating a deployable high-risk system as compliant before governance, transparency, oversight, and robustness controls are in place."
        )

    if risk_classification == "High-Risk - Needs Review":
        return (
            f"This result means the system does not show a prohibited practice in this demo, but it still has meaningful compliance gaps. "
            f"The score is {score}/100 and the open issues were found in {article_refs}. The most important findings are: {top_findings}. This is the zone where users should not over-trust a partly positive score: the system may be close to acceptable, but it is still missing safeguards that matter in practice. "
            f"The boundary not to cross is assuming partial compliance is equivalent to approval."
        )

    if risk_classification == "High-Risk - Compliant":
        return (
            f"This result means the system appears compliant against the controls modeled in this demo, not that it is harmless or exempt from scrutiny. "
            f"The score is {score}/100 and no confirmed rule breaches were detected. In plain terms, the current input suggests that prohibited practices were avoided and the main high-risk controls were present. This field is intended to support both audit interpretation and development-time design review. "
            f"The boundary not to cross is introducing prohibited capabilities, weakening oversight, or removing documentation, logging, explainability, bias testing, or robustness controls after deployment."
        )

    return "This result is informational only. Review the underlying rule coverage before relying on the score."
