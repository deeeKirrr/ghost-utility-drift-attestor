import json
from pathlib import Path

from attestor.diff import compute_changes


def test_diff_counts():
    fixtures = Path(__file__).parent / "fixtures"
    prev = json.loads((fixtures / "prev_state.json").read_text())
    curr = json.loads((fixtures / "curr_state.json").read_text())

    changes = compute_changes(prev, curr)

    assert len(changes["IAM"]) == 3
    assert len(changes["Exposure"]) == 3
    assert len(changes["Logging"]) == 3
