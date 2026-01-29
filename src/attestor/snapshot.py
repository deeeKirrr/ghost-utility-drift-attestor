import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from attestor import aws_clients

RISKY_PORTS = {22, 3389, 80, 443, 3306, 5432, 6379}


def _json_hash(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def collect_snapshot(region: str) -> Dict[str, Any]:
    sts = aws_clients.client("sts", region)
    account_id = sts.get_caller_identity()["Account"]

    iam = aws_clients.client("iam", region)
    ec2 = aws_clients.client("ec2", region)
    s3 = aws_clients.client("s3", region)
    cloudtrail = aws_clients.client("cloudtrail", region)
    config = aws_clients.client("config", region)

    snapshot = {
        "account_id": account_id,
        "region": region,
        "generated_at": _utc_now(),
        "iam": {
            "policy_attachments": _collect_policy_attachments(iam),
            "role_trusts": _collect_role_trusts(iam),
            "access_keys": _collect_access_keys(iam),
        },
        "exposure": {
            "security_group_rules": _collect_security_group_rules(ec2),
            "s3_public_access": _collect_s3_public_access(s3),
        },
        "logging": {
            "cloudtrail_trails": _collect_cloudtrail(cloudtrail),
            "config_recorder": _collect_config(config),
        },
    }
    return snapshot


def _collect_policy_attachments(iam_client) -> List[Dict[str, Any]]:
    attachments: List[Dict[str, Any]] = []
    for user in _paginate(iam_client, "list_users", "Users"):
        name = user["UserName"]
        for policy in _paginate(iam_client, "list_attached_user_policies", "AttachedPolicies", UserName=name):
            attachments.append(_policy_attachment(iam_client, "user", name, policy))

    for role in _paginate(iam_client, "list_roles", "Roles"):
        name = role["RoleName"]
        for policy in _paginate(iam_client, "list_attached_role_policies", "AttachedPolicies", RoleName=name):
            attachments.append(_policy_attachment(iam_client, "role", name, policy))

    for group in _paginate(iam_client, "list_groups", "Groups"):
        name = group["GroupName"]
        for policy in _paginate(iam_client, "list_attached_group_policies", "AttachedPolicies", GroupName=name):
            attachments.append(_policy_attachment(iam_client, "group", name, policy))

    return attachments


def _policy_attachment(iam_client, entity_type: str, entity_name: str, policy: Dict[str, Any]) -> Dict[str, Any]:
    policy_arn = policy["PolicyArn"]
    policy_meta = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy_meta["DefaultVersionId"]
    version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    document = version["PolicyVersion"]["Document"]
    return {
        "entity_type": entity_type,
        "entity_name": entity_name,
        "policy_arn": policy_arn,
        "policy_name": policy["PolicyName"],
        "policy_hash": _json_hash(document),
    }


def _collect_role_trusts(iam_client) -> List[Dict[str, Any]]:
    trusts: List[Dict[str, Any]] = []
    for role in _paginate(iam_client, "list_roles", "Roles"):
        trust_doc = role.get("AssumeRolePolicyDocument")
        trusts.append({
            "role_name": role["RoleName"],
            "trust_hash": _json_hash(trust_doc or {}),
        })
    return trusts


def _collect_access_keys(iam_client) -> List[Dict[str, Any]]:
    keys: List[Dict[str, Any]] = []
    for user in _paginate(iam_client, "list_users", "Users"):
        name = user["UserName"]
        for key in _paginate(iam_client, "list_access_keys", "AccessKeyMetadata", UserName=name):
            keys.append({
                "user_name": name,
                "access_key_id": key["AccessKeyId"],
                "create_date": key["CreateDate"].isoformat(),
            })
    return keys


def _collect_security_group_rules(ec2_client) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        sg_id = sg["GroupId"]
        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            if from_port is None or to_port is None:
                continue
            ports = set(range(from_port, to_port + 1)) & RISKY_PORTS
            if not ports:
                continue
            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr == "0.0.0.0/0":
                    for port in ports:
                        rules.append({
                            "sg_id": sg_id,
                            "port": port,
                            "protocol": permission.get("IpProtocol"),
                            "cidr": cidr,
                        })
            for ip_range in permission.get("Ipv6Ranges", []):
                cidr = ip_range.get("CidrIpv6")
                if cidr == "::/0":
                    for port in ports:
                        rules.append({
                            "sg_id": sg_id,
                            "port": port,
                            "protocol": permission.get("IpProtocol"),
                            "cidr": cidr,
                        })
    return rules


def _collect_s3_public_access(s3_client) -> List[Dict[str, Any]]:
    buckets = s3_client.list_buckets().get("Buckets", [])
    results: List[Dict[str, Any]] = []
    for bucket in buckets:
        name = bucket["Name"]
        public_access_block = _get_public_access_block(s3_client, name)
        public_policy = _bucket_has_public_policy(s3_client, name)
        results.append({
            "bucket": name,
            "public_access_block": public_access_block,
            "public_policy": public_policy,
        })
    return results


def _get_public_access_block(s3_client, bucket_name: str) -> bool:
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        return all(
            config.get(key, False)
            for key in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        )
    except ClientError:
        return False


def _bucket_has_public_policy(s3_client, bucket_name: str) -> bool:
    try:
        policy_str = s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(policy_str)
        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            if principal == "*" or principal == {"AWS": "*"}:
                return True
        return False
    except ClientError:
        return False


def _collect_cloudtrail(cloudtrail_client) -> List[Dict[str, Any]]:
    trails = cloudtrail_client.describe_trails().get("trailList", [])
    results: List[Dict[str, Any]] = []
    for trail in trails:
        status = cloudtrail_client.get_trail_status(Name=trail["TrailARN"])
        results.append({
            "name": trail["Name"],
            "is_multi_region": trail.get("IsMultiRegionTrail", False),
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
            "is_logging": status.get("IsLogging", False),
        })
    return results


def _collect_config(config_client) -> Dict[str, Any]:
    try:
        recorders = config_client.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = config_client.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        enabled = any(status.get("recording", False) for status in statuses)
        return {
            "recorders": [recorder.get("name") for recorder in recorders],
            "enabled": enabled,
        }
    except ClientError:
        return {"recorders": [], "enabled": False}


def _paginate(client, operation: str, result_key: str, **kwargs):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item
