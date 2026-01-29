import pytest

try:
    import boto3
    from botocore.stub import Stubber
except ImportError:  # pragma: no cover - optional dependency in CI
    boto3 = None
    Stubber = None


def test_collect_snapshot_stubbed(monkeypatch):
    if boto3 is None or Stubber is None:
        pytest.skip("boto3/botocore not available in test environment")
    from attestor.snapshot import collect_snapshot
    from attestor import aws_clients
    region = "us-east-1"

    sts = boto3.client("sts", region_name=region)
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    cloudtrail = boto3.client("cloudtrail", region_name=region)
    config = boto3.client("config", region_name=region)

    stubs = {
        "sts": Stubber(sts),
        "iam": Stubber(iam),
        "ec2": Stubber(ec2),
        "s3": Stubber(s3),
        "cloudtrail": Stubber(cloudtrail),
        "config": Stubber(config),
    }

    stubs["sts"].add_response("get_caller_identity", {"Account": "123456789012", "UserId": "x", "Arn": "arn"})

    stubs["iam"].add_response("list_users", {"Users": []})
    stubs["iam"].add_response("list_roles", {"Roles": []})
    stubs["iam"].add_response("list_groups", {"Groups": []})
    stubs["iam"].add_response("list_roles", {"Roles": []})
    stubs["iam"].add_response("list_users", {"Users": []})

    stubs["ec2"].add_response("describe_security_groups", {"SecurityGroups": []})
    stubs["s3"].add_response("list_buckets", {"Buckets": []})
    stubs["cloudtrail"].add_response("describe_trails", {"trailList": []})
    stubs["config"].add_response("describe_configuration_recorders", {"ConfigurationRecorders": []})
    stubs["config"].add_response("describe_configuration_recorder_status", {"ConfigurationRecordersStatus": []})

    for stub in stubs.values():
        stub.activate()

    def fake_client(service, region):
        return {
            "sts": sts,
            "iam": iam,
            "ec2": ec2,
            "s3": s3,
            "cloudtrail": cloudtrail,
            "config": config,
        }[service]

    monkeypatch.setattr(aws_clients, "client", fake_client)

    snapshot = collect_snapshot(region)

    assert snapshot["account_id"] == "123456789012"
    assert snapshot["iam"]["policy_attachments"] == []
    assert snapshot["exposure"]["security_group_rules"] == []

    for stub in stubs.values():
        stub.deactivate()
