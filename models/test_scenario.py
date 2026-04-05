"""Public-edition placeholder for the internal audit scenario library.

The full live-audit scenario set is intentionally not included in this
portfolio repository because it represents a differentiated testing asset.
The public edition retains only the data structures so the architecture is
understandable without exposing the full evaluator content.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TestRequest:
    """One HTTP request within a scenario."""
    method: str                     # GET | POST | PUT | DELETE
    path: str                       # Relative to target_base_url
    body: Optional[dict] = None     # Request body (will be hashed, not stored raw)
    headers: dict = field(default_factory=dict)
    label: str = ""                 # Human label, e.g. "CV — female candidate"


@dataclass
class TestScenario:
    id: str
    eu_article: str
    category: str
    name: str
    description: str
    metric: str                     # What is measured
    threshold: float                # Minimum passing value
    threshold_direction: str        # "min" (value must be >= threshold) or "max" (value must be <= threshold)
    requests: list[TestRequest]
    remediation: str                # What to do if this fails


ALL_SCENARIOS: dict[str, TestScenario] = {}
SCENARIOS_BY_ARTICLE: dict[str, list[str]] = {}
