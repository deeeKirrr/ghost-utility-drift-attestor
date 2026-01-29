from typing import Any, Dict, List

from attestor.models import Change, Report
from attestor.severity import sort_changes


LIMITATIONS = [
    "This verifies configuration signals only; it does not guarantee security, compliance, or recoverability.",
    "Some checks (S3 policy public heuristics, AWS Config) are best-effort and may be incomplete.",
]


def build_report(snapshot: Dict[str, Any], changes_by_category: Dict[str, List[Change]], suppressions: List[Dict[str, str]]) -> Report:
    all_changes = []
    for category in ["IAM", "Exposure", "Logging"]:
        all_changes.extend(changes_by_category.get(category, []))
    sorted_changes = sort_changes(all_changes)
    top_changes = sorted_changes[:10]

    summary_counts = {
        "IAM": len(changes_by_category.get("IAM", [])),
        "Exposure": len(changes_by_category.get("Exposure", [])),
        "Logging": len(changes_by_category.get("Logging", [])),
    }

    return Report(
        account_id=snapshot["account_id"],
        region=snapshot["region"],
        generated_at=snapshot["generated_at"],
        summary_counts=summary_counts,
        top_changes=top_changes,
        iam_changes=changes_by_category.get("IAM", []),
        exposure_changes=changes_by_category.get("Exposure", []),
        logging_changes=changes_by_category.get("Logging", []),
        current_state_summary=_current_state_summary(snapshot),
        suppressions_applied=suppressions,
        limitations=LIMITATIONS,
    )


def _current_state_summary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "iam": {
            "policy_attachments": len(snapshot.get("iam", {}).get("policy_attachments", [])),
            "access_keys": len(snapshot.get("iam", {}).get("access_keys", [])),
            "roles": len(snapshot.get("iam", {}).get("role_trusts", [])),
        },
        "exposure": {
            "public_security_group_rules": len(snapshot.get("exposure", {}).get("security_group_rules", [])),
            "buckets": len(snapshot.get("exposure", {}).get("s3_public_access", [])),
        },
        "logging": {
            "cloudtrail_trails": len(snapshot.get("logging", {}).get("cloudtrail_trails", [])),
            "config_enabled": snapshot.get("logging", {}).get("config_recorder", {}).get("enabled", False),
        },
    }
