# How the detection lab works

This walks the whole pipeline in plain language, file by file, then explains the
handful of measurement decisions that make the numbers honest. If you read one
thing, read the two "Why" sections at the end — they are the point of the repo.

## The one-paragraph version

Labeled log events (JSONL) go in. A small Sigma evaluator decides which rules
match which events. An engine turns matches into **alerts**, handling both
single-event rules and time-windowed correlations (like brute force). A metrics
layer compares alerts against the ground-truth labels and produces the numbers a
detection engineer is actually asked to defend — detection rate, false-positive
rate, alert volume, time-to-detect. A CI gate fails the build if a change makes
those numbers worse. Detections are treated as code: version-controlled,
peer-reviewed, backtested on every change.

## The data: what a log event looks like

`data/generate_sample.py` builds a small labeled corpus into two JSONL files
(`linux_auth.jsonl`, `aws_cloudtrail.jsonl`). Every event carries its real log
fields **plus four ground-truth fields** the harness needs to score detections:

| Field        | Meaning                                                      |
| ------------ | ----------------------------------------------------------- |
| `label`      | `"benign"` or `"malicious"` — was this event part of an attack? |
| `episode`    | attack id grouping one adversary sequence (`null` if benign) |
| `technique`  | the MITRE ATT&CK id the event represents (`null` if benign)  |
| `_logsource` | `"<product>/<service>"`, e.g. `linux/auth` — routes events to rules |

The corpus is deliberately tiny and legible (39 events) so you can hold the
whole thing in your head. It is shaped to exercise the harness, not to look
impressive: two brute-force episodes that cross the threshold, a 4-failure
benign burst that must *not* fire (one short of the threshold), an AWS
service-as-root event that must be filtered out, and an S3 exfiltration episode
with **no matching rule** — an honest, visible coverage gap.

**Design decision — labels live in the data, not the rules.** Ground truth is a
property of the corpus, so any engine scored against it is measured the same
way. *Trade-off:* someone has to label data by hand (real datasets like OTRF
Security-Datasets do this for you), and a mislabeled corpus silently corrupts
every metric.

## The flow, file by file

```
data/*.jsonl ──► harness.load_events ─┐
rules/*.yml  ──► harness.load_rules ───► engine.run ──► [Alert] ──► metrics.compute ──► Metrics
                                                                                          │
                                                                    render_markdown / check_gates
```

### 1. `detection_lab/sigma_eval.py` — does *this rule* match *this event*?

A compact, dependency-free evaluator for the slice of the Sigma spec the shipped
rules use. It answers one question: given a single event and a single rule, is
it a match? The pieces:

- **`get_field(event, "userIdentity.type")`** resolves dotted paths against the
  nested event dict, returning `None` if any segment is missing.
- **`match_scalar`** compares one actual value to one expected value, honoring
  Sigma modifiers: `contains`, `startswith`, `endswith`, `re` (regex), and
  `*`/`?` wildcards. Comparisons are case-insensitive, matching Sigma's default.
- **`match_field`** handles one `field|modifier: value` entry. A list of values
  means OR ("any of these"); `None` means the field must be absent.
- **`eval_selection`** handles a named selection block: a map means AND (all keys
  must match); a list of maps means OR.
- **The condition mini-language** (`eval_condition` + `_CondParser`) evaluates the
  rule's `condition:` string — `and`/`or`/`not`, parentheses, and the Sigma
  aggregates `1 of sel*`, `all of them`, etc. `_expand_aggregates` rewrites those
  aggregates into plain boolean expressions first, then a small recursive-descent
  parser evaluates the result. Precedence is `not` > `and` > `or`, like Sigma.
- **`rule_matches`** ties it together: evaluate each named selection, then feed
  the truth values into `eval_condition`.
- **`logsource_matches`** routes events to rules by `product[/service]`, so a
  CloudTrail rule is never even tested against auth logs.

**Design decision — reimplement a Sigma *subset* instead of pulling in a real
engine.** *Trade-off:* the repo runs with zero external services and the code is
readable end to end, but it covers only the Sigma features these rules use. Full
coverage and scale come from swapping the engine (see below), which is why this
is isolated behind a clean interface.

**Design decision — `logsource_matches` is separate from rule matching.** Without
it, a benign CloudTrail event could be "tested" against an SSH rule, and every
non-match would still be a correct rejection — but a stray field collision could
produce a phantom false positive and distort FP accounting. Routing first keeps
the FP numbers meaningful. *Trade-off:* one more thing a rule author must get
right (the `logsource:` block).

### 2. `detection_lab/engine.py` — turn matches into alerts

`BuiltinEngine` takes the parsed rules and correlations and produces a
time-sorted list of `Alert` objects. Two paths:

- **`_run_single`** walks every single-event rule across every event and emits an
  alert on each match. Crucially, any rule referenced by a correlation is a
  **base rule** and is skipped here — a single failed SSH login is far too noisy
  to alert on by itself; it exists only to feed the brute-force correlation.
- **`_run_correlations`** implements Sigma `event_count`: a sliding time window
  per group (e.g. per `source_ip`). It appends each matching event's timestamp,
  evicts timestamps older than the window, and when the count reaches the
  threshold it fires **once** — with the timestamp *of the crossing event*. That
  detail is what makes time-to-detect realistic: the alert fires the moment the
  attack becomes detectable, not at the attack's start and not on every event.

Each `Alert` carries the ground-truth `event_label` and `event_episode` copied
from the event it fired on. That is the hook the metrics layer uses to decide
true vs. false positive — the engine itself never judges correctness.

**Design decision — the engine is the pluggable seam.** Everything downstream
depends only on the `Alert` shape, not on how alerts were produced. The file
ships a `ZircoliteEngine` sketch showing how to shell out to a real Sigma engine
and adapt its JSON detections into `Alert` objects. *Trade-off:* the `Alert`
contract is now load-bearing — change it and you touch every layer — but that is
exactly the boundary you *want* to be stable.

**Design decision — base rules never alert standalone.** *Trade-off:* it takes a
correlation to surface a base rule's matches, so a misconfigured correlation can
silently hide a signal; the upside is you model real detection engineering,
where the primitive ("a failed login") and the detection ("many failed logins
fast") are deliberately different things.

### 3. `detection_lab/metrics.py` — score the alerts

`compute(events, alerts)` produces a `Metrics` object. It splits alerts into true
positives (fired on a `malicious` event) and false positives (fired on a
`benign` event), then derives every headline number. The definitions are
deliberately explicit because the naive versions mislead (see the two "Why"
sections next).

### 4. `detection_lab/harness.py` — glue, report, gate

- **`load_events` / `load_rules`** read the JSONL corpus and the YAML rules
  (anything with a `correlation:` block is a correlation; everything else is a
  single-event rule).
- **`run(project_root)`** is the whole pipeline in four lines: load, build
  engine, run, compute.
- **`render_markdown`** turns `Metrics` into the human report (headline table,
  per-episode, per-rule, coverage gaps).
- **`metrics_dict`** serializes the same numbers to JSON for machines/history.
- **`check_gates`** compares metrics to the thresholds and returns a list of
  violation strings (empty == pass).

### 5. `run.py` / `detection-lab` — the entry points

`run.py` runs the pipeline, writes `reports/report.md` + `reports/metrics.json`,
prints the report, and with `--gate` exits non-zero on any gate violation (so CI
fails). `detection-lab` (the `uv run detection-lab` console script) is the same
thing resolved from the current directory instead of the script's own path.

## Why detection rate is measured *per episode*, not per event

An **episode** is one attack — a sequence of events sharing an `episode` id.
Detection rate (recall) is the fraction of malicious *episodes* with at least one
true-positive alert.

The naive alternative — per-event recall ("what fraction of malicious *events*
did we alert on?") — structurally under-counts good detections. A brute-force
correlation is *supposed* to fire once, on the 5th failure, not on all six
events in the episode. Score that per event and a correct, well-tuned detection
looks like it "missed" five of six events and scores ~17% recall. Per episode it
scores 100%, which is the truth: the attack was caught.

So episode recall is the headline. Event recall is still computed and reported —
for transparency, and because for single-event detections the two agree — but it
is not what you optimize. *Trade-off:* episode-level recall can hide *partial*
coverage (you caught the attack, but only at the last step, with lots of dwell
time). That is exactly why MTTD is reported alongside it: recall says *whether*
you caught it, MTTD says *how late*.

## Why the FP numbers are two numbers, and how MTTD is defined

**Precision** is `TP / (TP + FP)` — of the alerts you raised, how many were real.
Necessary, but it hides operational pain: precision says nothing about *how much*
noise reaches the analyst.

So the harness reports two more concrete things:

- **Event false-positive rate** — distinct benign events that triggered any alert
  ÷ total benign events. A rate.
- **Alert volume (benign alerts/day)** — false-positive alerts extrapolated to a
  per-day rate from the benign timespan. This is what a SOC actually *feels*. A
  0.2% event FP rate sounds harmless, but at real log volume it can be hundreds
  of pages a day. Rate and volume answer different questions; the gate checks
  both.

**Mean time-to-detect (MTTD)** — for each *detected* episode, the earliest alert
timestamp minus the episode's first-event timestamp. That is attacker dwell time
before the detection fires. Reported as **median** and **p90** across detected
episodes (p90 = the 90th-percentile / near-worst case). Undetected episodes have
no MTTD — you cannot time a detection that never happened, and they are already
penalized in recall, so folding a fake number in would double-count them. In the
sample corpus the multi-step AWS campaign is only caught at the "disable
CloudTrail" step, giving a realistic ~2-minute dwell time, while single-event
detections (root abuse, GuardDuty tampering) fire at ~0s.

## Why the CI gate exists

`gates.yml` sets four thresholds: minimum detection rate, maximum event FP rate,
maximum alerts/day, maximum MTTD p90. `run.py --gate` enforces them and exits
non-zero on any violation; the GitHub Actions workflow runs it on every pull
request.

The whole idea of detection-as-code is that **a detection is a change to a
system that can regress**, exactly like application code. A well-meaning tweak to
cut noise can quietly blow a hole in coverage; a broadened rule can bury the
analyst. Unit tests alone do not catch that — they check individual rule logic,
not the *system's* aggregate behavior on realistic traffic. The gate is a
regression test for the numbers that matter, so a PR literally cannot merge if it
drops detection rate or floods the queue.

*Trade-off:* a gate is only as honest as its corpus and thresholds. Too loose and
it rubber-stamps regressions; too tight and it blocks legitimate work and trains
people to bypass it. It complements, not replaces, the rule-level unit tests in
`tests/` — those pin *specific behaviors* (the threshold discriminates, the
AWS-internal root event is filtered, the coverage gap stays surfaced); the gate
guards the *aggregate*.
