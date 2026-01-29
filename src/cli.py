import argparse
import json
from pathlib import Path

from attestor.diff import compute_changes
from attestor.exceptions import apply_exceptions
from attestor.report_json import build_report
from attestor.report_pdf import render_pdf


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Utility Drift Attestor CLI")
    parser.add_argument("--fixtures", action="store_true", help="Run using local fixtures")
    parser.add_argument("--fixtures-path", default="tests/fixtures", help="Path to fixtures")
    parser.add_argument("--output-dir", default="./local-output", help="Output directory")
    args = parser.parse_args()

    if not args.fixtures:
        raise SystemExit("CLI is fixture-only by default for safety. Use the container entrypoint for live runs.")

    fixtures_path = Path(args.fixtures_path)
    prev = json.loads((fixtures_path / "prev_state.json").read_text())
    curr = json.loads((fixtures_path / "curr_state.json").read_text())
    exceptions = json.loads((fixtures_path / "exceptions.json").read_text())

    changes = compute_changes(prev, curr)
    filtered, suppressions = {}, []
    for category, items in changes.items():
        remaining, applied = apply_exceptions(items, exceptions)
        filtered[category] = remaining
        suppressions.extend(applied)

    report = build_report(curr, filtered, suppressions)
    report_json = report.to_json()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report_json, indent=2))
    render_pdf(report_json, str(output_dir / "report.pdf"))


if __name__ == "__main__":
    main()
