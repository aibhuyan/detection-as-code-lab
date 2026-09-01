"""
Console-script entry point (`uv run detection-lab`).

Mirrors run.py, but resolves the project root from the current working
directory rather than the script's own location, so the installed console
script works when invoked from the repo root. run.py remains the
script-relative entry point; both call into detection_lab.harness.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .harness import check_gates, metrics_dict, render_markdown, run


def main() -> int:
    parser = argparse.ArgumentParser(description="Detection-as-Code eval harness")
    parser.add_argument(
        "--gate", action="store_true", help="exit non-zero on gate violations"
    )
    args = parser.parse_args()

    root = Path.cwd()
    metrics = run(root)

    reports = root / "reports"
    reports.mkdir(exist_ok=True)
    md = render_markdown(metrics)
    (reports / "report.md").write_text(md)
    (reports / "metrics.json").write_text(
        json.dumps(metrics_dict(metrics), indent=2, default=str)
    )

    print(md)

    if args.gate:
        gates = yaml.safe_load((root / "gates.yml").read_text())["gates"]
        failures = check_gates(metrics, gates)
        if failures:
            print("\nGATE FAILURES:", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)
            return 1
        print("\nAll gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
