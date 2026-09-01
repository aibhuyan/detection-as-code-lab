"""
Turn a corpus + a list of Alerts into the numbers a detection engineer is
actually asked to defend: detection rate, false-positive rate, alert volume,
and time-to-detect. The definitions here are deliberately explicit because the
naive versions are misleading.

Key definitions
---------------
Episode:  a labeled attack (one adversary sequence). Every malicious event
          carries an `episode` id; benign events carry `episode: null`.

Detection rate (recall), episode-level:
          fraction of malicious episodes with >= 1 true-positive alert.
          This is the headline number. We report it at the episode level
          because detections often fire once per attack (e.g. a brute-force
          correlation fires on the Nth failure, not on every failure), so
          event-level recall structurally under-counts. Event-level recall is
          reported too, for transparency.

Precision:
          TP alerts / (TP alerts + FP alerts). An alert is TP if it fired on a
          malicious event, FP if it fired on a benign event.

False-positive rate:
          - event FP rate: distinct benign events that triggered >=1 alert /
            total benign events.
          - alert volume: benign alerts per day, extrapolated from the benign
            timespan. This is what a SOC feels; a 0.2% event FP rate can still
            be hundreds of pages a day at real volume.

Time-to-detect (MTTD), per detected episode:
          (earliest alert timestamp in the episode) - (episode start time),
          where episode start = timestamp of the episode's first event. We
          report median and p90 across detected episodes. Undetected episodes
          have no MTTD (you cannot time a detection that never happened); they
          are already penalized in recall.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from .sigma_eval import Alert, parse_ts


@dataclass
class Metrics:
    total_events: int
    malicious_events: int
    benign_events: int
    total_episodes: int
    detected_episodes: int
    episode_recall: float
    event_recall: float
    precision: float
    tp_alerts: int
    fp_alerts: int
    event_fp_rate: float
    benign_alerts_per_day: float
    mttd_median_s: float | None
    mttd_p90_s: float | None
    per_episode: dict = field(default_factory=dict)
    per_rule: dict = field(default_factory=dict)
    undetected_episodes: list = field(default_factory=list)


def _p90(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    # nearest-rank p90
    k = max(0, min(len(s) - 1, round(0.9 * (len(s) - 1))))
    return s[k]


def compute(events: list[dict], alerts: list[Alert]) -> Metrics:
    malicious = [e for e in events if e["label"] == "malicious"]
    benign = [e for e in events if e["label"] == "benign"]

    # Episode start times (first event per episode).
    episode_events: dict[str, list[dict]] = {}
    for e in malicious:
        ep = e.get("episode")
        if ep:
            episode_events.setdefault(ep, []).append(e)
    episode_start = {
        ep: min(parse_ts(e["timestamp"]) for e in evs)
        for ep, evs in episode_events.items()
    }
    all_episodes = set(episode_events.keys())

    # Split alerts into TP / FP by the ground-truth label of the event fired on.
    tp_alerts = [a for a in alerts if a.event_label == "malicious"]
    fp_alerts = [a for a in alerts if a.event_label == "benign"]

    # Episode-level recall.
    detected_eps = {a.event_episode for a in tp_alerts if a.event_episode}
    detected_eps &= all_episodes
    episode_recall = len(detected_eps) / len(all_episodes) if all_episodes else 0.0

    # Event-level recall (distinct malicious events with >=1 alert).
    mal_event_ids = {id(e) for e in malicious}
    alerted_mal_events = {
        a.event_index for a in tp_alerts
    }  # event_index is unique per time-sorted event
    # Map malicious events to their sorted index is handled upstream; here we
    # approximate event recall via episodes covered vs total malicious events
    # that are individually alertable is out of scope. We compute it as:
    #   distinct malicious events that produced an alert / total malicious events
    event_recall = (
        len(alerted_mal_events) / len(malicious) if malicious else 0.0
    )

    # Precision.
    precision = (
        len(tp_alerts) / (len(tp_alerts) + len(fp_alerts))
        if (tp_alerts or fp_alerts)
        else 1.0
    )

    # Event FP rate + benign alert volume.
    benign_alerted_events = {a.event_index for a in fp_alerts}
    event_fp_rate = (
        len(benign_alerted_events) / len(benign) if benign else 0.0
    )

    if benign:
        b_times = [parse_ts(e["timestamp"]) for e in benign]
        span_days = max(
            (max(b_times) - min(b_times)).total_seconds() / 86400.0, 1e-9
        )
        benign_alerts_per_day = len(fp_alerts) / span_days
    else:
        benign_alerts_per_day = 0.0

    # MTTD per detected episode.
    mttd_by_ep: dict[str, float] = {}
    for ep in detected_eps:
        first_alert = min(
            a.timestamp for a in tp_alerts if a.event_episode == ep
        )
        mttd_by_ep[ep] = (first_alert - episode_start[ep]).total_seconds()
    mttd_values = list(mttd_by_ep.values())
    mttd_median = statistics.median(mttd_values) if mttd_values else None
    mttd_p90 = _p90(mttd_values) if mttd_values else None

    # Per-rule breakdown.
    per_rule: dict[str, dict] = {}
    for a in alerts:
        r = per_rule.setdefault(
            a.rule_id, {"title": a.rule_title, "tp": 0, "fp": 0, "technique": a.technique}
        )
        if a.event_label == "malicious":
            r["tp"] += 1
        else:
            r["fp"] += 1

    per_episode = {
        ep: {
            "detected": ep in detected_eps,
            "mttd_s": mttd_by_ep.get(ep),
            "technique": episode_events[ep][0].get("technique"),
            "n_events": len(episode_events[ep]),
        }
        for ep in sorted(all_episodes)
    }

    return Metrics(
        total_events=len(events),
        malicious_events=len(malicious),
        benign_events=len(benign),
        total_episodes=len(all_episodes),
        detected_episodes=len(detected_eps),
        episode_recall=episode_recall,
        event_recall=event_recall,
        precision=precision,
        tp_alerts=len(tp_alerts),
        fp_alerts=len(fp_alerts),
        event_fp_rate=event_fp_rate,
        benign_alerts_per_day=benign_alerts_per_day,
        mttd_median_s=mttd_median,
        mttd_p90_s=mttd_p90,
        per_episode=per_episode,
        per_rule=per_rule,
        undetected_episodes=sorted(all_episodes - detected_eps),
    )
