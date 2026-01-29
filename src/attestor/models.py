from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Snapshot:
    account_id: str
    region: str
    generated_at: str
    iam: Dict[str, Any]
    exposure: Dict[str, Any]
    logging: Dict[str, Any]


@dataclass
class Change:
    id: str
    category: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    change_type: str


@dataclass
class Report:
    account_id: str
    region: str
    generated_at: str
    summary_counts: Dict[str, int]
    top_changes: List[Change]
    iam_changes: List[Change]
    exposure_changes: List[Change]
    logging_changes: List[Change]
    current_state_summary: Dict[str, Any]
    suppressions_applied: List[Dict[str, str]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "account_id": self.account_id,
                "region": self.region,
                "generated_at": self.generated_at,
            },
            "summary": {
                "counts": self.summary_counts,
            },
            "top_changes": [change.__dict__ for change in self.top_changes],
            "sections": {
                "iam": [change.__dict__ for change in self.iam_changes],
                "exposure": [change.__dict__ for change in self.exposure_changes],
                "logging": [change.__dict__ for change in self.logging_changes],
            },
            "appendix": {
                "current_state_summary": self.current_state_summary,
                "suppressions_applied": self.suppressions_applied,
                "limitations": self.limitations,
            },
        }
