# Detection change

## What does this rule detect?
<!-- One or two sentences. What adversary behavior, in plain language. -->

## ATT&CK mapping
- Technique:  <!-- e.g. T1110.001 -->
- Tactic:     <!-- e.g. Credential Access -->

## Test cases added
<!-- Detections are code: a new/changed rule must come with labeled events. -->
- [ ] Added at least one **true-positive** episode to `data/` that this rule should catch
- [ ] Added at least one **benign** event that looks similar but must NOT fire (the tuning case)

## Known false positives
<!-- What legitimate activity resembles this? How is it filtered? -->

## Backtest results
<!-- Paste the relevant rows from reports/report.md after running `python run.py`. -->
| Metric | Before | After |
| --- | --- | --- |
| Detection rate |  |  |
| Event FP rate |  |  |
| MTTD p90 |  |  |

## Reviewer checklist
- [ ] CI `detections` job is green (gates pass)
- [ ] Rule has a description, references, and `falsepositives`
- [ ] Logsource is scoped (won't run against unrelated event streams)
