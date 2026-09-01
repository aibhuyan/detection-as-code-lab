"""
The detection engine: given time-sorted events, a set of single-event Sigma
rules, and a set of `event_count` correlation rules, produce a list of Alerts.

This is the pluggable seam of the lab. `BuiltinEngine` uses the local
sigma_eval subset. To run real Sigma at scale you can write a ZircoliteEngine
that shells out to zircolite and adapts its JSON detections into Alert objects
(sketch at the bottom); the harness/metrics code stays identical.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime

from .sigma_eval import (
    Alert,
    logsource_matches,
    parse_timespan,
    parse_ts,
    rule_matches,
)


class BuiltinEngine:
    def __init__(self, rules: list[dict], correlations: list[dict]):
        self.rules = rules
        self.rules_by_id = {r["id"]: r for r in rules}
        self.correlations = correlations
        # Any rule referenced by a correlation is a "base" rule: it exists to
        # feed the correlation and must not alert standalone.
        self.base_ids: set[str] = set()
        for corr in correlations:
            self.base_ids.update(corr["correlation"].get("rules", []))

    # ---- single-event rules ------------------------------------------------ #
    def _run_single(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if rule["id"] in self.base_ids:
                # Base rules feed correlations; intentionally noisy, no standalone alert.
                continue
            technique = _technique_of(rule)
            for idx, ev in enumerate(events):
                if not logsource_matches(ev, rule):
                    continue
                if rule_matches(ev, rule):
                    alerts.append(
                        Alert(
                            rule_id=rule["id"],
                            rule_title=rule.get("title", rule["id"]),
                            technique=technique,
                            timestamp=parse_ts(ev["timestamp"]),
                            event_index=idx,
                            event_label=ev["label"],
                            event_episode=ev.get("episode"),
                            severity=rule.get("level", "medium"),
                        )
                    )
        return alerts

    # ---- event_count correlations ----------------------------------------- #
    def _run_correlations(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        for corr in self.correlations:
            spec = corr["correlation"]
            base = self.rules_by_id[spec["rules"][0]]
            group_by: list[str] = spec.get("group-by", spec.get("group_by", []))
            window = parse_timespan(spec["timespan"])
            threshold = int(spec["condition"]["gte"])
            technique = _technique_of(corr) or _technique_of(base)

            # Sliding window of matching-event timestamps per group.
            windows: dict[tuple, deque] = defaultdict(deque)
            fired: set[tuple] = set()  # groups already alerted (fire once per window entry)

            for idx, ev in enumerate(events):
                if not logsource_matches(ev, base):
                    continue
                if not rule_matches(ev, base):
                    continue
                key = tuple(_group_value(ev, g) for g in group_by)
                ts = parse_ts(ev["timestamp"])
                dq = windows[key]
                dq.append(ts)
                # Evict events older than the window.
                while dq and (ts - dq[0]).total_seconds() > window:
                    dq.popleft()
                if len(dq) >= threshold and key not in fired:
                    fired.add(key)
                    alerts.append(
                        Alert(
                            rule_id=corr["id"],
                            rule_title=corr.get("title", corr["id"]),
                            technique=technique,
                            timestamp=ts,  # fires on the Nth event -> realistic MTTD
                            event_index=idx,
                            event_label=ev["label"],
                            event_episode=ev.get("episode"),
                            severity=corr.get("level", "high"),
                        )
                    )
                elif len(dq) < threshold:
                    # Window fell back below threshold; allow it to fire again later.
                    fired.discard(key)
            # end events
        return alerts

    def run(self, events: list[dict]) -> list[Alert]:
        events = sorted(events, key=lambda e: parse_ts(e["timestamp"]))
        alerts = self._run_single(events) + self._run_correlations(events)
        alerts.sort(key=lambda a: a.timestamp)
        return alerts


def _technique_of(rule: dict) -> str | None:
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t"):
            # e.g. attack.t1110.001 -> T1110.001
            return tag.split(".", 1)[1].upper()
    return None


def _group_value(event: dict, dotted: str):
    from .sigma_eval import get_field

    return get_field(event, dotted)


# --------------------------------------------------------------------------- #
# Sketch of a real-engine adapter (not wired in by default).
# --------------------------------------------------------------------------- #
class ZircoliteEngine:  # pragma: no cover - reference sketch
    """
    Drop-in replacement that runs full Sigma at scale via Zircolite.

    Steps:
      1. Write events to NDJSON.
      2. subprocess.run(["python3", "zircolite.py", "--events", ndjson,
                         "--ruleset", ruleset_json, "--jsononly",
                         "--outfile", out]).
      3. Parse `out` (Zircolite JSON detections carry rule title, ATT&CK id and
         the matched rows) and map each detection back to the source event by a
         stable key to recover its ground-truth label/episode, emitting Alert
         objects the harness already understands.

    Because the harness only depends on the Alert shape, none of the metrics
    code changes when you switch engines.
    """

    def run(self, events: list[dict]) -> list[Alert]:
        raise NotImplementedError("Wire up zircolite subprocess call here.")
