from attestor.exceptions import apply_exceptions
from attestor.models import Change


def test_exceptions_match_id():
    change = Change(
        id="iam:admin_grant:entity_name:AppRole",
        category="IAM",
        severity="Critical",
        description="Admin grant",
        evidence={},
        change_type="admin_grant",
    )
    remaining, applied = apply_exceptions(
        [change],
        {"suppressions": [{"id": "iam:admin_grant:entity_name:AppRole", "reason": "approved"}]},
    )
    assert remaining == []
    assert applied[0]["reason"] == "approved"


def test_exceptions_match_text():
    change = Change(
        id="exposure:public_db_port:sg_id:sg-123",
        category="Exposure",
        severity="Critical",
        description="Public inbound rule on 5432 for sg-123",
        evidence={"sg_id": "sg-123"},
        change_type="public_db_port",
    )
    remaining, applied = apply_exceptions(
        [change],
        {"suppressions": [{"match": "sg-123", "reason": "temporary"}]},
    )
    assert remaining == []
    assert applied[0]["reason"] == "temporary"
