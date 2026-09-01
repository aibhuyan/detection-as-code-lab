"""
A compact, dependency-free evaluator for a *subset* of the Sigma specification.

Why this exists
---------------
For a self-contained lab we want to run real Sigma YAML against labeled events
without standing up a SIEM. This module implements the slice of Sigma the
shipped rules use: field/value matching with the common modifiers
(`contains`, `startswith`, `endswith`, `re`), value lists as OR, field maps as
AND, `*`/`?` wildcards, null matching, and a `condition` mini-language
(`and`/`or`/`not`, parentheses, `1 of x*`, `all of x*`, `1 of them`,
`all of them`). It also supports a minimal `event_count` correlation
(sliding window + group-by) so we can express threshold detections like SSH
brute force and get a meaningful time-to-detect.

For full spec coverage and scale, swap this engine for Zircolite or Chainsaw
(see engines.py / README). The harness treats the engine as pluggable, so the
metrics layer does not change when you swap it.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    rule_id: str
    rule_title: str
    technique: str | None
    timestamp: datetime
    event_index: int          # index into the (time-sorted) event list
    event_label: str          # "benign" | "malicious" (ground truth of the event)
    event_episode: str | None
    severity: str = "medium"


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #
def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z'."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_timespan(span: str) -> float:
    """Sigma timespan like '30s', '5m', '2h', '1d' -> seconds."""
    unit = span[-1].lower()
    qty = float(span[:-1])
    return qty * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


# --------------------------------------------------------------------------- #
# Field resolution
# --------------------------------------------------------------------------- #
def get_field(event: dict, dotted: str) -> Any:
    """Resolve a possibly dotted field path against a nested dict."""
    cur: Any = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# --------------------------------------------------------------------------- #
# Value matching
# --------------------------------------------------------------------------- #
def _as_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def match_scalar(actual: Any, expected: Any, modifier: str | None) -> bool:
    """Match one actual field value against one expected Sigma value."""
    if expected is None:
        return actual is None
    if actual is None:
        return False

    a = _as_str(actual)
    e = _as_str(expected)

    if modifier == "contains":
        return e.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    if modifier == "re":
        return re.search(e, a) is not None

    # Plain equality. Honor Sigma wildcards if present, else case-insensitive ==.
    if "*" in e or "?" in e:
        return fnmatch.fnmatch(a.lower(), e.lower())
    return a.lower() == e.lower()


def match_field(event: dict, key: str, expected: Any) -> bool:
    """
    Match a single `field|modifier: value` entry. `expected` may be a scalar,
    a list (OR semantics), or None (field must be absent/null).
    """
    if "|" in key:
        field_name, modifier = key.split("|", 1)
    else:
        field_name, modifier = key, None

    actual = get_field(event, field_name)
    values = expected if isinstance(expected, list) else [expected]
    return any(match_scalar(actual, v, modifier) for v in values)


def eval_selection(event: dict, selection: Any) -> bool:
    """
    A selection is either a map (all keys must match -> AND) or a list of maps
    (any map matches -> OR).
    """
    if isinstance(selection, list):
        return any(eval_selection(event, item) for item in selection)
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    # A bare keyword selection (list of strings) is not supported in this subset.
    return False


# --------------------------------------------------------------------------- #
# Condition mini-language
# --------------------------------------------------------------------------- #
def _expand_aggregates(condition: str, sel_names: list[str]) -> str:
    """Rewrite `1 of x*` / `all of x*` / `... of them` into boolean expressions."""

    def names_for(pattern: str) -> list[str]:
        if pattern == "them":
            return list(sel_names)
        return [n for n in sel_names if fnmatch.fnmatch(n, pattern)]

    def repl(match: re.Match) -> str:
        quant, pattern = match.group(1), match.group(2)
        names = names_for(pattern)
        if not names:
            return "False"
        joiner = " or " if quant == "1" else " and "
        return "( " + joiner.join(names) + " )"

    pattern = re.compile(r"\b(1|all)\s+of\s+([A-Za-z0-9_*?]+)")
    return pattern.sub(repl, condition)


class _CondParser:
    """Recursive-descent boolean parser: not > and > or, with parentheses."""

    def __init__(self, tokens: list[str], values: dict[str, bool]):
        self.tokens = tokens
        self.pos = 0
        self.values = values

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> bool:
        return self._or()

    def _or(self) -> bool:
        val = self._and()
        while self.peek() == "or":
            self.next()
            val = self._and() or val
        return val

    def _and(self) -> bool:
        val = self._not()
        while self.peek() == "and":
            self.next()
            val = self._not() and val
        return val

    def _not(self) -> bool:
        if self.peek() == "not":
            self.next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self.next()
        if tok == "(":
            val = self._or()
            assert self.next() == ")", "unbalanced parentheses in condition"
            return val
        if tok in ("True", "False"):
            return tok == "True"
        return self.values.get(tok, False)


def eval_condition(condition: str, sel_results: dict[str, bool]) -> bool:
    expanded = _expand_aggregates(condition, list(sel_results.keys()))
    # Tokenize: parens and words. Sigma identifiers are word-ish.
    tokens = re.findall(r"\(|\)|[A-Za-z0-9_]+", expanded)
    return _CondParser(tokens, sel_results).parse()


# --------------------------------------------------------------------------- #
# Rule evaluation
# --------------------------------------------------------------------------- #
def rule_matches(event: dict, rule: dict) -> bool:
    """Evaluate a single-event Sigma rule against one event."""
    detection = rule["detection"]
    condition = detection["condition"]
    sel_results = {
        name: eval_selection(event, body)
        for name, body in detection.items()
        if name not in ("condition", "timeframe")
    }
    return eval_condition(condition, sel_results)


def logsource_matches(event: dict, rule: dict) -> bool:
    """
    Route events to rules by logsource. The corpus tags each event with a
    `_logsource` key like 'linux/auth' or 'aws/cloudtrail'; a rule matches if
    its product[/service] prefix agrees. This keeps a CloudTrail rule from ever
    being 'tested' against auth logs (which would distort FP accounting).
    """
    ls = rule.get("logsource", {})
    product = ls.get("product")
    service = ls.get("service")
    ev_ls = event.get("_logsource", "")
    parts = ev_ls.split("/")
    ev_product = parts[0] if parts else ""
    ev_service = parts[1] if len(parts) > 1 else ""
    if product and product != ev_product:
        return False
    if service and service != ev_service:
        return False
    return True
