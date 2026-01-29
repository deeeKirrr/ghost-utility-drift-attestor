import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from attestor.config import Config
from attestor.diff import compute_changes
from attestor.exceptions import apply_exceptions
from attestor.report_json import build_report
from attestor.report_pdf import render_pdf
from attestor.s3_state import S3State
from attestor.snapshot import collect_snapshot


def run_live() -> None:
    config = Config.from_env()
    state = S3State(config.bucket, config.prefix, config.region)
    previous = state.read_state() or {}
    current = collect_snapshot(config.region)

    changes = compute_changes(previous, current)
    filtered, suppressions = _apply_suppressions(changes, state)

    report = build_report(current, filtered, suppressions)
    report_json = report.to_json()

    pdf_path = Path("/tmp/report.pdf")
    render_pdf(report_json, str(pdf_path))

    year_month = datetime.now(timezone.utc).strftime("%Y-%m")
    state.write_report(report_json, pdf_path.read_bytes(), year_month)
    state.write_state(current)


def run_fixtures(fixtures_path: Path) -> None:
    prev = json.loads((fixtures_path / "prev_state.json").read_text())
    curr = json.loads((fixtures_path / "curr_state.json").read_text())
    exceptions = json.loads((fixtures_path / "exceptions.json").read_text())

    changes = compute_changes(prev, curr)
    filtered, suppressions = _apply_suppressions(changes, None, exceptions)
    report = build_report(curr, filtered, suppressions)
    report_json = report.to_json()

    output_dir = Path("./fixture-output")
    output_dir.mkdir(exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report_json, indent=2))
    render_pdf(report_json, str(output_dir / "report.pdf"))


def _apply_suppressions(changes, state: S3State | None, exceptions_data=None):
    if exceptions_data is None and state:
        exceptions_data = state.read_exceptions()
    elif exceptions_data is None:
        exceptions_data = {"suppressions": []}

    suppressions_applied = []
    filtered_changes = {}
    for category, items in changes.items():
        remaining, applied = apply_exceptions(items, exceptions_data)
        filtered_changes[category] = remaining
        suppressions_applied.extend(applied)
    return filtered_changes, suppressions_applied


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Utility Drift Attestor")
    parser.add_argument("--fixtures", action="store_true", help="Run against local fixtures")
    parser.add_argument("--fixtures-path", default="tests/fixtures", help="Path to fixtures")
    args = parser.parse_args()

    if args.fixtures:
        run_fixtures(Path(args.fixtures_path))
    else:
        run_live()


if __name__ == "__main__":
    main()
