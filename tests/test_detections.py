"""
Rule-level unit tests, complementing the corpus-wide backtest in run.py.

These pin specific behaviors so a future edit that breaks them fails loudly:
the brute-force threshold discriminates, the AWS-internal root event is
filtered, and the known coverage gap stays surfaced.
"""

from pathlib import Path

from detection_lab.engine import BuiltinEngine
from detection_lab.harness import load_events, load_rules
from detection_lab.metrics import compute
from detection_lab.sigma_eval import eval_condition, match_field

ROOT = Path(__file__).resolve().parents[1]


def run_corpus(mutate=None):
    events = load_events(ROOT / "data")
    rules, corrs = load_rules(ROOT / "rules")
    if mutate:
        mutate(rules, corrs)
    alerts = BuiltinEngine(rules, corrs).run(events)
    return compute(events, alerts)


def test_condition_language():
    sels = {"selection": True, "filter": True}
    assert eval_condition("selection and not filter", sels) is False
    assert eval_condition("selection", {"selection": True}) is True
    assert eval_condition("1 of sel*", {"sel_a": False, "sel_b": True}) is True
    assert eval_condition("all of sel*", {"sel_a": False, "sel_b": True}) is False


def test_field_modifiers():
    ev = {"eventName": "StopLogging", "userIdentity": {"type": "Root"}}
    assert match_field(ev, "eventName", ["StopLogging", "DeleteTrail"]) is True
    assert match_field(ev, "userIdentity.type", "Root") is True
    assert match_field(ev, "eventName|contains", "Stop") is True
    assert match_field(ev, "eventName", "DeleteTrail") is False


def test_baseline_detection_rate_and_precision():
    m = run_corpus()
    assert m.detected_episodes == 5
    assert m.total_episodes == 6
    assert m.precision == 1.0          # no false positives when tuned
    assert m.fp_alerts == 0


def test_known_coverage_gap_is_surfaced():
    m = run_corpus()
    assert "aws-exfil-01" in m.undetected_episodes


def test_bruteforce_mttd_is_measured():
    m = run_corpus()
    # brute force fires on the 5th failure at +36s / +32s from episode start
    assert m.per_episode["ssh-bruteforce-01"]["mttd_s"] == 36
    assert m.per_episode["ssh-bruteforce-02"]["mttd_s"] == 32


def test_loosening_threshold_creates_false_positives():
    def loosen(rules, corrs):
        corrs[0]["correlation"]["condition"]["gte"] = 3

    m = run_corpus(loosen)
    assert m.fp_alerts >= 1            # the 4-failure benign burst now fires
    assert m.precision < 1.0
