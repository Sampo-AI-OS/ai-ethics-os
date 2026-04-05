import pytest
from models.ethical_rule import EthicsRule
from services.ethics_scoring import calculate_score, check_violation, EU_AI_ACT_RULES


# ---------- check_violation ----------

def test_check_violation_compliant():
    rule = EU_AI_ACT_RULES[2]  # AIA-ART9-001 — expects has_risk_management_system=True
    assert check_violation({"has_risk_management_system": True}, rule) == 0.0


def test_check_violation_non_compliant():
    rule = EU_AI_ACT_RULES[2]
    assert check_violation({"has_risk_management_system": False}, rule) == 1.0


def test_check_violation_missing_key_high_severity():
    rule = EU_AI_ACT_RULES[2]  # severity 4 — unknown → 0.5 penalty
    result = check_violation({}, rule)
    assert result == 0.5


def test_check_violation_missing_key_low_severity():
    rule = {**EU_AI_ACT_RULES[2], "severity": 2}
    result = check_violation({}, rule)
    assert result == 0.0


# ---------- calculate_score — happy path ----------

def test_fully_compliant_system():
    model_details = {
        "is_social_scoring": False,
        "is_realtime_biometric_public": False,
        "has_risk_management_system": True,
        "uses_demographic_features": False,
        "has_bias_testing": True,
        "has_technical_documentation": True,
        "logs_decisions": True,
        "has_explainability": True,
        "has_human_oversight": True,
        "has_accuracy_metrics": True,
    }
    result = calculate_score(model_details, EU_AI_ACT_RULES)
    assert result["score"] == 100
    assert result["violations"] == []
    assert "Compliant" in result["risk_classification"]
    assert result["compliance_guidance"] == result["analysis"]
    assert "not that it is harmless" in result["analysis"]


def test_prohibited_system_detected():
    model_details = {
        "is_social_scoring": True,
        "is_realtime_biometric_public": False,
        "has_risk_management_system": False,
        "uses_demographic_features": True,
        "has_bias_testing": False,
        "has_technical_documentation": False,
        "logs_decisions": False,
        "has_explainability": False,
        "has_human_oversight": False,
        "has_accuracy_metrics": False,
    }
    result = calculate_score(model_details, EU_AI_ACT_RULES)
    assert result["risk_classification"] == "Prohibited"
    assert "AIA-ART5-001" in result["violations"]
    assert result["score"] < 40
    assert "Social scoring is prohibited" in result["compliance_guidance"]
    assert "crosses a prohibited line" in result["analysis"]


def test_partial_compliance_triggers_review():
    model_details = {
        "is_social_scoring": False,
        "is_realtime_biometric_public": False,
        "has_risk_management_system": True,
        "uses_demographic_features": False,
        "has_bias_testing": True,
        "has_technical_documentation": False,
        "logs_decisions": False,
        "has_explainability": False,
        "has_human_oversight": True,
        "has_accuracy_metrics": False,
    }
    result = calculate_score(model_details, EU_AI_ACT_RULES)
    assert 40 < result["score"] < 90
    assert len(result["violations"]) > 0
    assert len(result["remediation_hints"]) == len(result["violations"])


def test_empty_rules_returns_unknown():
    result = calculate_score({"any_key": True}, [])
    assert result["score"] == 0
    assert result["risk_classification"] == "Unknown"


def test_rule_to_dict_preserves_dynamic_params():
    rule = EthicsRule(
        id="AIA-ART9-001",
        category="Risk Management",
        severity=4,
        rule_text="A documented risk management system must exist.",
        eu_article="Art. 9",
        risk_level="High",
        dynamic_params={"check_key": "has_risk_management_system", "expected": True},
    )

    assert rule.to_dict()["dynamic_params"] == {
        "check_key": "has_risk_management_system",
        "expected": True,
    }


# ---------- Demo scenarios ----------

HR_SCREENING = {
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
}

CREDIT_SCORING = {
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
}


def test_hr_screening_is_non_compliant():
    result = calculate_score(HR_SCREENING, EU_AI_ACT_RULES)
    assert result["score"] < 60
    assert "AIA-ART14-001" in result["violations"]  # no human oversight


def test_credit_scoring_is_mostly_compliant():
    result = calculate_score(CREDIT_SCORING, EU_AI_ACT_RULES)
    assert result["score"] >= 70
    assert "AIA-ART5-001" not in result["violations"]
