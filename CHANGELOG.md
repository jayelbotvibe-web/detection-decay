# Changelog

All notable changes to detection-decay.

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
