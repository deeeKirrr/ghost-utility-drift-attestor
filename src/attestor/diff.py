from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from attestor.models import Change
from attestor.severity import severity_for_change


def compute_changes(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, List[Change]]:
    changes: Dict[str, List[Change]] = {"IAM": [], "Exposure": [], "Logging": []}

    changes["IAM"].extend(_diff_policy_attachments(previous, current))
    changes["IAM"].extend(_diff_trusts(previous, current))
    changes["IAM"].extend(_diff_access_keys(previous, current))

    changes["Exposure"].extend(_diff_security_groups(previous, current))
    changes["Exposure"].extend(_diff_s3_public_access(previous, current))

    changes["Logging"].extend(_diff_cloudtrail(previous, current))
    changes["Logging"].extend(_diff_config(previous, current))

    return changes


def _diff_policy_attachments(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev = _index_attachments(previous)
    curr = _index_attachments(current)
    changes: List[Change] = []

    for key, item in curr.items():
        prev_item = prev.get(key)
        if not prev_item:
            change_type = _policy_change_type(item)
            changes.append(_build_change(
                "IAM",
                change_type,
                f"New policy attachment: {item['policy_name']} to {item['entity_type']} {item['entity_name']}",
                {
                    "entity_type": item["entity_type"],
                    "entity_name": item["entity_name"],
                    "policy_arn": item["policy_arn"],
                    "policy_name": item["policy_name"],
                },
            ))
        elif prev_item.get("policy_hash") != item.get("policy_hash"):
            changes.append(_build_change(
                "IAM",
                "policy_changed",
                f"Policy document changed: {item['policy_name']} on {item['entity_type']} {item['entity_name']}",
                {
                    "entity_type": item["entity_type"],
                    "entity_name": item["entity_name"],
                    "policy_arn": item["policy_arn"],
                    "policy_name": item["policy_name"],
                },
            ))
    return changes


def _policy_change_type(item: Dict[str, Any]) -> str:
    name = item["policy_name"].lower()
    arn = item["policy_arn"].lower()
    if "administratoraccess" in name or arn.endswith("administratoraccess"):
        return "admin_grant"
    if "fullaccess" in name or "poweruser" in name:
        return "wildcard_policy_attachment"
    return "policy_attachment"


def _diff_trusts(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev = _index_by_name(previous.get("iam", {}).get("role_trusts", []), "role_name")
    curr = _index_by_name(current.get("iam", {}).get("role_trusts", []), "role_name")
    changes: List[Change] = []
    for role, item in curr.items():
        prev_item = prev.get(role)
        if prev_item and prev_item.get("trust_hash") != item.get("trust_hash"):
            changes.append(_build_change(
                "IAM",
                "trust_policy_change",
                f"Role trust policy changed for {role}",
                {"role_name": role},
            ))
    return changes


def _diff_access_keys(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev_keys = {key["access_key_id"] for key in previous.get("iam", {}).get("access_keys", [])}
    changes: List[Change] = []
    now = datetime.now(timezone.utc)
    for key in current.get("iam", {}).get("access_keys", []):
        if key["access_key_id"] not in prev_keys:
            created = datetime.fromisoformat(key["create_date"])
            age_days = (now - created).days
            changes.append(_build_change(
                "IAM",
                "access_key_new",
                f"New access key created for user {key['user_name']} ({age_days} days ago)",
                {
                    "user_name": key["user_name"],
                    "access_key_id": key["access_key_id"],
                    "create_date": key["create_date"],
                },
            ))
    return changes


def _diff_security_groups(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev_rules = _index_rules(previous.get("exposure", {}).get("security_group_rules", []))
    curr_rules = _index_rules(current.get("exposure", {}).get("security_group_rules", []))
    changes: List[Change] = []
    for key, item in curr_rules.items():
        if key not in prev_rules:
            change_type = _sg_change_type(item["port"])
            changes.append(_build_change(
                "Exposure",
                change_type,
                f"Public inbound rule on {item['port']} for {item['sg_id']}",
                item,
            ))
    return changes


def _sg_change_type(port: int) -> str:
    if port in {3306, 5432, 6379}:
        return "public_db_port"
    if port in {22, 3389}:
        return "public_ssh_rdp"
    if port in {80, 443}:
        return "public_web"
    return "public_other"


def _diff_s3_public_access(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev = _index_by_name(previous.get("exposure", {}).get("s3_public_access", []), "bucket")
    curr = _index_by_name(current.get("exposure", {}).get("s3_public_access", []), "bucket")
    changes: List[Change] = []
    for bucket, item in curr.items():
        prev_item = prev.get(bucket)
        if not prev_item:
            continue
        if prev_item.get("public_policy") is False and item.get("public_policy") is True:
            changes.append(_build_change(
                "Exposure",
                "s3_public_policy",
                f"Bucket policy now appears public for {bucket}",
                {"bucket": bucket, "public_policy": True},
            ))
        if prev_item.get("public_access_block") is True and item.get("public_access_block") is False:
            changes.append(_build_change(
                "Exposure",
                "s3_public_access_block_disabled",
                f"Public access block disabled for {bucket}",
                {"bucket": bucket, "public_access_block": False},
            ))
    return changes


def _diff_cloudtrail(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev = _index_by_name(previous.get("logging", {}).get("cloudtrail_trails", []), "name")
    curr = _index_by_name(current.get("logging", {}).get("cloudtrail_trails", []), "name")
    changes: List[Change] = []
    for name, item in curr.items():
        prev_item = prev.get(name)
        if not prev_item:
            continue
        if prev_item.get("is_logging") and not item.get("is_logging"):
            changes.append(_build_change(
                "Logging",
                "cloudtrail_disabled",
                f"CloudTrail logging disabled for {name}",
                {"trail": name},
            ))
        if prev_item.get("log_file_validation") and not item.get("log_file_validation"):
            changes.append(_build_change(
                "Logging",
                "cloudtrail_validation_disabled",
                f"CloudTrail validation disabled for {name}",
                {"trail": name},
            ))
        if prev_item.get("is_multi_region") != item.get("is_multi_region"):
            changes.append(_build_change(
                "Logging",
                "cloudtrail_multi_region_changed",
                f"CloudTrail multi-region setting changed for {name}",
                {"trail": name, "is_multi_region": item.get("is_multi_region")},
            ))
    return changes


def _diff_config(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Change]:
    prev = previous.get("logging", {}).get("config_recorder", {})
    curr = current.get("logging", {}).get("config_recorder", {})
    changes: List[Change] = []
    if prev.get("enabled") and not curr.get("enabled"):
        changes.append(_build_change(
            "Logging",
            "config_disabled",
            "AWS Config recording disabled",
            {"enabled": False},
        ))
    elif prev.get("enabled") != curr.get("enabled"):
        changes.append(_build_change(
            "Logging",
            "config_changed",
            "AWS Config recorder state changed",
            {"enabled": curr.get("enabled")},
        ))
    return changes


def _build_change(category: str, change_type: str, description: str, evidence: Dict[str, Any]) -> Change:
    change_id = _change_id(category, change_type, evidence)
    severity = severity_for_change(change_type, evidence)
    return Change(
        id=change_id,
        category=category,
        severity=severity,
        description=description,
        evidence=evidence,
        change_type=change_type,
    )


def _change_id(category: str, change_type: str, evidence: Dict[str, Any]) -> str:
    parts = [category.lower(), change_type]
    for key in sorted(evidence.keys()):
        parts.append(f"{key}:{evidence[key]}")
    return ":".join(parts)


def _index_attachments(snapshot: Dict[str, Any]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    attachments = snapshot.get("iam", {}).get("policy_attachments", [])
    return {
        (item["entity_type"], item["entity_name"], item["policy_arn"]): item
        for item in attachments
    }


def _index_by_name(items: List[Dict[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
    return {item[key]: item for item in items}


def _index_rules(rules: List[Dict[str, Any]]) -> Dict[Tuple[str, int, str], Dict[str, Any]]:
    return {(rule["sg_id"], rule["port"], rule["cidr"]): rule for rule in rules}
