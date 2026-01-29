SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def severity_for_change(change_type: str, evidence: dict) -> str:
    if change_type == "admin_grant":
        return "Critical"
    if change_type == "public_db_port":
        return "Critical"
    if change_type == "cloudtrail_disabled":
        return "Critical"

    if change_type == "public_ssh_rdp":
        return "High"
    if change_type == "wildcard_policy_attachment":
        return "High"
    if change_type == "s3_public_policy":
        return "High"

    if change_type == "public_web":
        return "Medium"
    if change_type == "cloudtrail_validation_disabled":
        return "Medium"
    if change_type == "config_disabled":
        return "Medium"
    if change_type == "trust_policy_change":
        return "Medium"

    return "Low"


def sort_changes(changes):
    return sorted(
        changes,
        key=lambda change: (SEVERITY_ORDER.get(change.severity, 0), change.id),
        reverse=True,
    )
