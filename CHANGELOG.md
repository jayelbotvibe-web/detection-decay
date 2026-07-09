# Changelog

All notable changes to detection-decay.

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
