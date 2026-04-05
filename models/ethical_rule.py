from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, constr
from sqlalchemy import Column, Integer, String, DateTime, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass

class EthicsRule(Base):
    __tablename__ = 'ethics_rules'

    id = Column(String(32), primary_key=True)
    category = Column(String, nullable=False)  # e.g., "Privacy", "Bias"
    severity = Column(
        Integer,
        CheckConstraint("severity BETWEEN 1 AND 5", name="ck_severity_range"),
        nullable=False,
    )
    rule_text = Column(String, nullable=False)
    eu_article = Column(String, nullable=True)  # e.g., "Art. 9", "Art. 5"
    risk_level = Column(String, nullable=True)  # Prohibited / High / Limited / Minimal
    dynamic_params = Column(JSONB, nullable=True)

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'category': self.category,
            'severity': self.severity,
            'rule_text': self.rule_text,
            'eu_article': self.eu_article,
            'risk_level': self.risk_level,
            'dynamic_params': self.dynamic_params,
        }

class EthicsRuleCreate(BaseModel):
    id: str
    category: str
    severity: int
    rule_text: str
    eu_article: Optional[str] = None
    risk_level: Optional[str] = None
    dynamic_params: Optional[dict] = None


class EthicsRuleRead(EthicsRuleCreate):
    model_config = {"from_attributes": True}


class EthicsScoreRequest(BaseModel):
    model_id: constr(max_length=64)
    model_details: dict


class EthicsScoreResponse(BaseModel):
    model_id: str
    total_possible: int = 100
    current_score: int
    risk_classification: str  # Prohibited / High / Limited / Minimal
    compliance_guidance: str
    analysis: str
    violation_rules: List[str] = []
    remediation_hints: List[str] = []
    timestamp: datetime

    model_config = {"from_attributes": True}