import json
from typing import Any, Dict, List, Tuple

from attestor.models import Change


def load_exceptions(raw: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"suppressions": []}
    except json.JSONDecodeError:
        return {"suppressions": []}


def apply_exceptions(changes: List[Change], exceptions: Dict[str, Any]) -> Tuple[List[Change], List[Dict[str, str]]]:
    suppressions = exceptions.get("suppressions", [])
    applied: List[Dict[str, str]] = []
    remaining: List[Change] = []

    for change in changes:
        match = _match_suppression(change, suppressions)
        if match:
            applied.append({
                "id": change.id,
                "reason": match.get("reason", "Suppressed by policy"),
            })
        else:
            remaining.append(change)
    return remaining, applied


def _match_suppression(change: Change, suppressions: List[Dict[str, str]]) -> Dict[str, str]:
    text = f"{change.description} {change.evidence}".lower()
    for suppression in suppressions:
        if suppression.get("id") and suppression["id"] == change.id:
            return suppression
        if suppression.get("match") and suppression["match"].lower() in text:
            return suppression
    return {}
