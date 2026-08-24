# Changelog

All notable changes to detection-decay.

## [Unreleased]

### Migration note
- **A sixth verdict, `PROBE_ERROR`, was added.** Anything keyed on exact verdict labels must handle the full set: `HEALTHY`, `DEGRADED`, `DEAD:SOURCE`, `DEAD:FIELD`, `INSUFFICIENT_DATA`, `PROBE_ERROR`.
- **Evidence format is backward-compatible.** The new `"probe_error"` key is optional; files without it parse unchanged.
- **Unknown keys in evidence files are now rejected.** A file carrying a key the scorer does not recognise fails to parse instead of silently defaulting it. `evidence.json` lost its `_note` key for this reason; the same statement is in the README.
- **`liveness` is now required.** Omitting it previously reported `DEAD:SOURCE — agent disconnected`.
- **`Result` gained `gates` and `explanation`.** `p_source`, `p_field` and `p_behavior` are retained and now mirror the corresponding gate values. Note `p_field` is `1.0` rather than `0` when the field gate abstains — it previously carried a zero that was never used in the product.
- **Verdicts change for two input classes:** volume above 3× baseline now reports `DEGRADED` (was `HEALTHY`), and a row carrying `probe_error` reports `PROBE_ERROR` (was `DEAD:SOURCE`).

### Added
- **Run history and run-over-run change detection** (`--history <dir>`). Each run is persisted as an immutable `runs/<id>/decay.json` and indexed in a slim `history.json`; the output then leads with what moved since the previous run instead of restating the full table. Findings are matched by a fingerprint over rule, state, verdict and the decay score rounded to one decimal — an unchanged rule matches by hash, a worsened one does not, and sub-band noise does not churn. Storage is plain JSON files; the zero-dependency rule is what rules out SQLite here. Pattern borrowed from purple-loop's dashboard reporter, fingerprinting from threat-intel-arbiter's dedup key.
- **A run that measured nothing is saved but not indexed.** If every probe failed, indexing it would put a false `0.00` on the trend line. The artifact is kept — a failed run is what you want to inspect.
- **Exit codes carry the finding.** `--fail-on none|unknown|degraded|dead` exits `3` when any row is at or above the threshold. The tool always exited `0`, so it could not gate a cron job or a CI step — the single cheapest blocker to running it in production.
- **`--format json`.** `Result` carried full JSON tags but `--format json` silently rendered a terminal table and exited `0`. The report is an envelope with `version`, `evidence`, a numeric `summary` and the full results. Numbers are carried as numbers — nothing downstream should have to recover a figure by re-parsing the prose that describes it.
- **`--version`**, which `const version` existed for but nothing read.
- **Confidence, orthogonal to the verdict.** The verdict says how bad; confidence says how sure. It is discounted by a thin baseline (below `MinSample`), by any abstaining gate, and by a baseline older than 30 days — and is deliberately never folded into the score, so a thin sample cannot look like good health. Adapted from threat-intel-arbiter, where routing keys on the severity/confidence pair.
- **Evidence validation.** All problems in a file are reported at once, not one run at a time — a collector emitting a malformed file repeats the same mistake on every row. Catches negative volumes, percentages where rates belong, and missing required keys.
- **Every score explains itself.** Each gate carries the `Contribution` factors that produced it, and `Result.Explanation` is rendered from those same values — so the breakdown always reconciles with the number it explains. The final line restates the arithmetic with the real operands (`1 - (0.34 × 1.00 × 1.00) = 0.66 → DEGRADED`) so it can be checked by hand. Adapted from threat-intel-arbiter's risk engine, with multiplicative factors in place of additive ones because these gates are probabilities.
- **`PROBE_ERROR` verdict.** A failed measurement no longer masquerades as a detection outage. Previously an unreachable indexer produced `volume: 0` and reported `DEAD:SOURCE` with full confidence — paging an operator about telemetry that may be perfectly healthy.
- **Over-collection is now scored.** Volume above 3× baseline (`OverThreshold`) reports `DEGRADED`. A lost ingest filter or duplicated pipeline degrades detection through drops, rule timeouts and queue backlog; the ratio was previously clamped to 1.0, so 30× baseline scored a perfect 0.00. It is floored at `DeadThreshold` and can never read `DEAD:SOURCE` — events are demonstrably flowing.
- **Unknown tally.** Both renderers now report a count of rows that measured nothing (`INSUFFICIENT_DATA`, `PROBE_ERROR`) rather than silently omitting them from the summary.

### Fixed
- **Path traversal in run ids.** A `^[A-Za-z0-9._-]+$` guard accepts `..`, so a crafted id resolved to `runs/../decay.json` and escaped the run directory. Containment is now verified after joining the path, so widening the pattern cannot reintroduce it. (The same guard, with the same gap, appears in purple-loop's server.)
- **A corrupt trend index is rebuilt rather than fatal.** The index is written via a temp file and rename, so an interrupted run cannot leave a half-written one behind.
- **Unknown `--format` values are rejected** instead of falling through to text and exiting `0`.
- **Positional arguments are rejected.** `decay score foo.json` scored `evidence.json` and exited `0`, reporting on a file the user never named.
- **The healthy ceiling no longer erases the reason.** `MaxHealthyDecay` overwrote the specific per-gate reason with a bare `"decay 0.10 exceeds healthy threshold 0.05"`, so an operator could see that a threshold was crossed but not which gate slipped. It now appends to the gate detail. The README gate table also documented an 80% band that the 0.95 ceiling made unreachable; both now describe the same behaviour.
- **The FIELD column rendered uncoloured.** `fieldDisplay` returned CSS class names (`dead-field`, `healthy`) that were never keys in the terminal colour map, so the column printed with no styling at all. The map now covers both naming schemes.
- **`DEAD:FIELD` and `DEGRADED` were indistinguishable in a terminal** — both resolved to `\033[33m`. `amber` is now a distinct 256-colour orange.
- **The HTML hero fabricated `field 0%` for unmeasured fields.** A `null` measurement was initialised to `0.0` and printed unconditionally — the one guess the scorer is careful never to make. It now reads `n/a`, as does the volume cell for a failed probe.
- **Table borders never matched cell widths.** The LIVE column reserved 4 characters for `active` (6) and FIELD reserved 5 for `100%→0%` (7), so every row overflowed its column. Widths now agree, and `padRight` measures runes instead of bytes — a non-ASCII rule name previously misaligned the table and could be truncated mid-rune. Over-long names now truncate with an ellipsis.
- **`heroClass` removed.** It duplicated `verdictCSS` but defaulted an unrecognised verdict to green, the wrong direction to fail.

### Testing
- `assertReconciles` asserts every gate value equals the product of the factors its explanation lists, swept across all scoring paths.
- Property tests replace spot checks: verdicts are monotonic in volume, no `HEALTHY` verdict exists above the ceiling, every verdict has both a colour and a CSS class, and every table row matches the header width.
- Band boundaries are pinned at exactly `0.20` (exclusive) on both gates.
- `sortResults` extracted so `TestSortStable` exercises the real comparator; it previously copy-pasted the logic, so the sort could regress with the test still green.
- The hand-rolled `contains` helper in the test file, which reimplemented `strings.Contains`, was removed — the zero-dependency rule is about the binary, not the standard library.
- CI now runs on **every branch** (it was scoped to `main`, so feature-branch work was unverified until a PR existed), with `-race`, a gate that fails the build if a `require` block or `go.sum` ever appears, and a gate that fails if `demo/dashboard.html` is stale.
- Each fix above carries a regression test that was confirmed to fail against the unfixed code.

## [v0.2.0] — 2026-07-20

### Migration note
- **Verdict output has changed.** Rows that previously reported `HEALTHY` may now report `DEGRADED` or `DEAD:*`.  The new `DEGRADED` verdict did not exist in v0.1.x.  Anyone with alerting or dashboards keyed on exact verdict string labels must account for the five-value set: `HEALTHY`, `DEGRADED`, `DEAD:SOURCE`, `DEAD:FIELD`, `INSUFFICIENT_DATA`.
- **Evidence format is backward-compatible.** Old evidence files without the optional `"field"` key continue to parse; the scorer falls back to the neutral word `"field"` in reason strings.

### Fixed
- **Source abstention alone now blocks HEALTHY.** A row with `baseline_volume:0` and healthy field data previously fell through to HEALTHY; now correctly reports INSUFFICIENT_DATA. Zero events with no baseline is never healthy evidence.
- **Banded verdicts replace binary HEALTHY/DEAD.** P(source) and P(field) are now continuous ratios with three bands: ≥0.8 healthy, 0.2–0.8 DEGRADED, <0.2 dead. A `DEGRADED` verdict was added alongside the existing four.
- **Partial field drift now caught.** A rule with 5% field populate (95% decay) previously reported HEALTHY; now correctly reports DEAD:FIELD. This is the most common production failure — schema/decoder changes usually affect a subset of events.
- **Continuous volume scoring.** P(source) is now a ratio (volume/baseline) instead of a binary step at 10%. An 89% volume collapse now reports DEAD:SOURCE instead of HEALTHY.
- **Field name no longer hardcoded.** The `Evidence` struct gained a `Field` field; reason strings use it instead of always saying "Image". Falls back to "field" when absent.
- **Renderer agreement.** Text and HTML renderers now share a `tally()` function and use the same banding constants. The HTML hero no longer renders INSUFFICIENT_DATA with the green `.healthy` class.
- **HTML escaping.** All user-controlled values (rule, state, liveness, reason, field, evidence path) are now escaped via `html.EscapeString`, preventing XSS from index-derived input.
- **No-baseline abstention.** `volume:0, baseline_volume:0` now reports INSUFFICIENT_DATA instead of DEAD:SOURCE.
- **Stable sort.** `sort.SliceStable` with rule-name tiebreak ensures deterministic output order.
- **Dead code removed.** HTML hero no longer loops to find worst (results are pre-sorted).
- **`collect-opensearch.sh` improvements:** emits `field` in evidence JSON, documents argv credential exposure and recommends `--netrc`, documents the `exists`-counts-empty-strings limitation.

### Changed
- **Evidence format** gained an optional `"field"` key (string). Old evidence files without it continue to parse; the scorer falls back to the neutral word "field".
- **Demo dashboard and evidence** regenerated with the new field key and updated verdicts.

## [v0.1.1] — 2026-07-09

### Fixed
- `score` subcommand: flags placed after `score` were silently ignored. Both `decay score --evidence ...` and `decay --evidence ...` now work correctly.
- Empty evidence set: `renderHTML` and `renderText` no longer panic on zero rows; return a graceful "no evidence rows" message.
- Hardcoded evidence label replaced with the actual evidence file path in output.
- Case-insensitive liveness comparison: `Active` (capitalized) no longer scored as `DEAD:SOURCE`.

### Added
- `scripts/collect-opensearch.sh` — reference evidence collector that queries OpenSearch/Wazuh/Elasticsearch for live volume and field-populate measurements.
- CI: `go vet` step and full-package `go test ./...`.
- Regression tests for case-insensitive liveness, empty evidence guard, and evidence path in HTML output.

### Changed
- Screenshots converted to WebP format (smaller).
- README updated with live-collection usage and cleaner install instruction.

## [v0.1.0] — 2026-07-07

### Added
- Initial release: capability-gate scoring model (`DecayScore = 1 − P(source) · P(field) · P(behavior)`)
- Static JSON evidence scoring with CLI table + HTML dashboard
- Three demonstrated failure modes: baseline HEALTHY, source-death DEAD:SOURCE, field-drift DEAD:FIELD
- Demo `evidence.json` with real Windows Sysmon measurements
