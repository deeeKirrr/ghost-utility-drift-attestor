from attestor.severity import severity_for_change


def test_severity_rules():
    assert severity_for_change("admin_grant", {}) == "Critical"
    assert severity_for_change("public_db_port", {}) == "Critical"
    assert severity_for_change("public_ssh_rdp", {}) == "High"
    assert severity_for_change("cloudtrail_validation_disabled", {}) == "Medium"
    assert severity_for_change("access_key_new", {}) == "Low"
