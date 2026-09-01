#!/usr/bin/env python3
"""
Entry point for the detection eval harness.

    python run.py            # run eval, write reports/, print summary
    python run.py --gate     # additionally fail (exit 1) on gate violations

Gates live in gates.yml and are what a CI job enforces on every pull request:
detections are code, so a PR that drops detection rate or floods the analyst
with false positives should not merge.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from detection_lab.harness import (
    check_gates,
    metrics_dict,
    render_markdown,
    run,
)

ROOT = Path(__file__).parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Detection-as-Code eval harness")
    parser.add_argument(
        "--gate", action="store_true", help="exit non-zero on gate violations"
    )
    args = parser.parse_args()

    metrics = run(ROOT)

    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    md = render_markdown(metrics)
    (reports / "report.md").write_text(md)
    (reports / "metrics.json").write_text(json.dumps(metrics_dict(metrics), indent=2, default=str))

    print(md)

    if args.gate:
        gates = yaml.safe_load((ROOT / "gates.yml").read_text())["gates"]
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
