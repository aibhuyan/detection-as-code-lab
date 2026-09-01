# Detection-as-code lab

Labeled logs in, Sigma rules run against them, and an eval harness scores the
rules the way a detection team is actually measured — with CI gates that block a
change from merging if it makes detections worse.

## What this demonstrates

- **Detections treated as code** — version-controlled, peer-reviewed, and
  backtested on every change, with a CI gate that fails the build on regression.
- **A from-scratch Sigma evaluator** (field/modifier matching, a `condition`
  mini-language, and `event_count` correlations) behind a pluggable engine
  interface — swap in a real engine without touching the metrics.
- **Metrics defined the way they're defended in practice** — detection rate per
  *episode*, false-positive *rate and volume*, and time-to-detect — not the
  naive versions that flatter the numbers.

The point isn't the four rules; it's the harness and the workflow around them.

## Quickstart

Uses [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                  # create the venv, install deps
uv run python data/generate_sample.py    # build the labeled corpus
uv run python run.py --gate              # backtest all rules, enforce gates
uv run pytest -q                         # rule-level unit tests
```

`uv run detection-lab --gate` runs the same harness via the installed console
script.

## Sample eval report

```
Corpus: 39 events (21 malicious / 18 benign), 6 attack episodes.

| Metric                          | Value          |
| ------------------------------- | -------------- |
| Detection rate (episode recall) | 83% (5/6)      |
| Precision                       | 100%           |
| Event false-positive rate       | 0.00% (0 FP)   |
| Benign alert volume             | 0.0 alerts/day |
| MTTD median                     | 32s            |
| MTTD p90                        | 2.0m           |

Coverage gaps: aws-exfil-01  (S3 exfiltration — no rule yet)
```

83%, not a fake 100%: one attack episode (S3 exfiltration) has no rule yet, and
the report surfaces it instead of hiding it. Closing that gap is the obvious
next rule to write.

## Architecture

```
data/*.jsonl ─► load_events ─┐
rules/*.yml  ─► load_rules ───► engine.run ─► [Alert] ─► metrics.compute ─► Metrics
                                                                              │
                                                            render_markdown / check_gates
```

```
detection_lab/
  sigma_eval.py   Dependency-free evaluator for a subset of Sigma
  engine.py       Single-event rules + event_count correlations → Alerts (pluggable)
  metrics.py      Metric definitions (read this — the naive ones lie)
  harness.py      Loads rules/data, renders the report, enforces gates
  cli.py          Console-script entry point
rules/            Sigma rules (YAML), one per file, peer-reviewable
  correlation/    Correlation rules (e.g. brute-force thresholds)
data/             Labeled corpus (JSONL) + the generator that builds it
gates.yml         Regression thresholds enforced by CI
.github/          CI workflow + PR template — the "code" in detection-as-code
run.py            Script entry point
```

The engine is pluggable and the corpus schema is fixed, so you can swap in a
real Sigma engine or a real dataset without touching the metrics. Full pipeline
walkthrough and design trade-offs: [WALKTHROUGH.md](WALKTHROUGH.md).

## Metrics, briefly

- **Detection rate (episode recall)** — fraction of attack *episodes* with ≥1
  true-positive alert. Per episode, not per event, because a good detection often
  fires once per attack (brute force fires on the 5th failure, not on all six).
- **Precision / FP rate / alert volume** — precision is TP/(TP+FP); the FP *rate*
  is benign events that triggered any alert; alert *volume* is benign alerts/day.
  A 0.2% FP rate can still bury an analyst at real volume, so both are reported.
- **MTTD** — for each detected episode, earliest alert minus the episode's first
  event: attacker dwell time before detection. Reported as median and p90.
