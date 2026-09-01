"""
Glue: load rules and the labeled corpus, run the engine, compute metrics,
render a report, and enforce regression gates for CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .engine import BuiltinEngine
from .metrics import Metrics, compute


def load_events(data_dir: Path) -> list[dict]:
    events: list[dict] = []
    for jsonl in sorted(data_dir.glob("*.jsonl")):
        with jsonl.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return events


def load_rules(rules_dir: Path) -> tuple[list[dict], list[dict]]:
    rules, correlations = [], []
    for yml in sorted(rules_dir.rglob("*.yml")):
        with yml.open() as fh:
            doc = yaml.safe_load(fh)
        if doc is None:
            continue
        if "correlation" in doc:
            correlations.append(doc)
        else:
            rules.append(doc)
    return rules, correlations


def run(project_root: Path) -> Metrics:
    events = load_events(project_root / "data")
    rules, correlations = load_rules(project_root / "rules")
    engine = BuiltinEngine(rules, correlations)
    alerts = engine.run(events)
    return compute(events, alerts)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _fmt_secs(v: float | None) -> str:
    if v is None:
        return "n/a"
    if v < 90:
        return f"{v:.0f}s"
    return f"{v / 60:.1f}m"


def render_markdown(m: Metrics) -> str:
    lines = []
    lines.append("# Detection eval report\n")
    lines.append(
        f"Corpus: **{m.total_events}** events "
        f"({m.malicious_events} malicious / {m.benign_events} benign), "
        f"**{m.total_episodes}** attack episodes.\n"
    )
    lines.append("## Headline metrics\n")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(
        f"| Detection rate (episode recall) | "
        f"{m.episode_recall:.0%} ({m.detected_episodes}/{m.total_episodes}) |"
    )
    lines.append(f"| Precision | {m.precision:.0%} |")
    lines.append(
        f"| Event false-positive rate | {m.event_fp_rate:.2%} "
        f"({m.fp_alerts} FP alerts) |"
    )
    lines.append(
        f"| Benign alert volume | {m.benign_alerts_per_day:.1f} alerts/day |"
    )
    lines.append(f"| MTTD median | {_fmt_secs(m.mttd_median_s)} |")
    lines.append(f"| MTTD p90 | {_fmt_secs(m.mttd_p90_s)} |")
    lines.append("")

    lines.append("## Per-episode\n")
    lines.append("| Episode | Technique | Detected | MTTD |")
    lines.append("| --- | --- | --- | --- |")
    for ep, info in m.per_episode.items():
        mark = "yes" if info["detected"] else "**MISS**"
        lines.append(
            f"| {ep} | {info['technique'] or ''} | {mark} | "
            f"{_fmt_secs(info['mttd_s'])} |"
        )
    lines.append("")

    lines.append("## Per-rule\n")
    lines.append("| Rule | Technique | TP alerts | FP alerts |")
    lines.append("| --- | --- | --- | --- |")
    for rid, r in sorted(m.per_rule.items()):
        lines.append(
            f"| {r['title']} | {r['technique'] or ''} | {r['tp']} | {r['fp']} |"
        )
    lines.append("")

    if m.undetected_episodes:
        lines.append("## Coverage gaps\n")
        lines.append(
            "These episodes produced no alert — either a missing rule or a "
            "detection that fired too late/narrow:\n"
        )
        for ep in m.undetected_episodes:
            lines.append(f"- {ep}")
        lines.append("")

    return "\n".join(lines)


def metrics_dict(m: Metrics) -> dict:
    return {
        "detection_rate_episode": m.episode_recall,
        "event_recall": m.event_recall,
        "precision": m.precision,
        "event_fp_rate": m.event_fp_rate,
        "benign_alerts_per_day": m.benign_alerts_per_day,
        "mttd_median_s": m.mttd_median_s,
        "mttd_p90_s": m.mttd_p90_s,
        "detected_episodes": m.detected_episodes,
        "total_episodes": m.total_episodes,
        "tp_alerts": m.tp_alerts,
        "fp_alerts": m.fp_alerts,
        "per_episode": m.per_episode,
        "per_rule": m.per_rule,
        "undetected_episodes": m.undetected_episodes,
    }


# --------------------------------------------------------------------------- #
# CI gate
# --------------------------------------------------------------------------- #
def check_gates(m: Metrics, gates: dict) -> list[str]:
    """Return a list of gate-violation messages (empty == pass)."""
    failures = []
    if m.episode_recall < gates["min_detection_rate"]:
        failures.append(
            f"detection rate {m.episode_recall:.0%} < "
            f"min {gates['min_detection_rate']:.0%}"
        )
    if m.event_fp_rate > gates["max_event_fp_rate"]:
        failures.append(
            f"event FP rate {m.event_fp_rate:.2%} > "
            f"max {gates['max_event_fp_rate']:.2%}"
        )
    if m.benign_alerts_per_day > gates["max_alerts_per_day"]:
        failures.append(
            f"benign alert volume {m.benign_alerts_per_day:.1f}/day > "
            f"max {gates['max_alerts_per_day']:.1f}/day"
        )
    if m.mttd_p90_s is not None and m.mttd_p90_s > gates["max_mttd_p90_s"]:
        failures.append(
            f"MTTD p90 {m.mttd_p90_s:.0f}s > max {gates['max_mttd_p90_s']:.0f}s"
        )
    return failures
