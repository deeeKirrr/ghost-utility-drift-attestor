import json
from pathlib import Path

from attestor.diff import compute_changes
from attestor.exceptions import apply_exceptions
from attestor.report_json import build_report


def test_fixture_report_matches_expected():
    fixtures = Path(__file__).parent / "fixtures"
    prev = json.loads((fixtures / "prev_state.json").read_text())
    curr = json.loads((fixtures / "curr_state.json").read_text())
    exceptions = json.loads((fixtures / "exceptions.json").read_text())

    changes = compute_changes(prev, curr)
    filtered, suppressions = {}, []
    for category, items in changes.items():
        remaining, applied = apply_exceptions(items, exceptions)
        filtered[category] = remaining
        suppressions.extend(applied)

    report = build_report(curr, filtered, suppressions)
    expected = json.loads((fixtures / "expected_report.json").read_text())

    assert report.to_json() == expected
