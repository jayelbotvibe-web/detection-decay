# CLAUDE.md — detection-decay

A CLI scorer for **silent detection failure** in SIEM pipelines. It reads a JSON evidence
file (event volume, agent liveness, field-populate rate, plus healthy baselines) and
computes `DecayScore = 1 - P(source_ok) * P(field_ok|source_ok) * P(behavior)`, assigning
each rule/state pair one of five verdicts.

Targets two failure modes volume-only monitors miss: a telemetry source dying while the
agent still reports Active, and a critical field going null at the index while events keep
flowing.

## Commands

```bash
go build ./cmd/decay                                   # build
go test ./... -v -count=1                              # test
./decay score --evidence evidence.json                 # run
./decay score --evidence evidence.json --format html --out demo/dashboard.html
go install github.com/jayelbotvibe-web/detection-decay/cmd/decay@latest
```

Format/vet gates exist **only in CI** (`.github/workflows/go.yml`) — there is no Makefile
and no lint config file:

```bash
test -z "$(gofmt -l ./cmd ./internal)"
go vet ./...
```

## Stack

Go **1.22** (`go.mod`). **Zero third-party dependencies** — no `require` block, no
`go.sum`. Stdlib only (`encoding/json`, `flag`, `html`, `sort`). Keep it that way; the
absence of dependencies is a feature of this tool.

## Architecture

- `cmd/decay/main.go` (380 lines) — entry point: flags, evidence load, sorting, text and
  HTML renderers. `const version`.
- `internal/score/score.go` (180 lines) — the model: `Evidence` and `Result` structs,
  `Score()`, `ScoreAll()`, `const MaxHealthyDecay = 0.05`
- `cmd/decay/main_test.go`, `internal/score/score_test.go` — renderer and model tests
- `scripts/collect-opensearch.sh` — reference evidence collector for
  OpenSearch/Wazuh/Elasticsearch
- `evidence.json` — demo input; `demo/dashboard.html` — generated artifact

No code generation, no `go generate`.

## The five verdicts

`HEALTHY`, `DEGRADED`, `DEAD:SOURCE`, `DEAD:FIELD`, `INSUFFICIENT_DATA`.

These strings changed in v0.2.0 — anything keyed on exact verdict labels must handle the
full five-value set. Documented as a migration note in `CHANGELOG.md`.

## Conventions

- Conventional Commits with scopes: `fix(score):`, `fix(render):`, `refactor(score):`
- Errors to `os.Stderr` via `fmt.Fprintf` with explicit exit codes: `1` for I/O and parse
  failures, `2` for usage errors. No logging framework.
- Tests are standard `TestXxx(t *testing.T)` in `_test.go` beside the source, with
  descriptive names (`TestSourceAbstainAloneInsufficientData`)
- `CHANGELOG.md` maintained Keep-a-Changelog style with migration notes

## Gotchas

- The **scorer itself has no network access and handles no credentials** — that boundary is
  stated in `SECURITY.md`. Keep it.
- `scripts/collect-opensearch.sh` needs `curl` and `jq`, plus env: `DECAY_ES_URL`
  (required, exits 2 without it), `DECAY_ES_USER`, `DECAY_ES_PASS`, optional
  `DECAY_ES_NETRC=1`, `DECAY_ES_INSECURE`, `DECAY_LIVENESS` (default `active`). The script
  warns that `-u` exposes credentials in argv and recommends `--netrc`.
- `evidence.json` is demonstration data, explicitly out of security scope.

## State

Working MVP, actively developed. CI exists and runs on push/PR to `main`. Zero TODO/FIXME
markers.

**Note the branch state:** HEAD has been sitting on `fix/verdict-thresholds`, one commit
ahead of origin and unpushed. Default branch is `main`. Other remote branches exist —
`feat/live-mode` (README says live mode "shipped on `feat/live-mode`; pending merge") and
`docs/readme-deploy`. Check where you are before committing.

Roadmap items still unfinished: P(behavior) gate, multi-rule scope, alerting, calibration loop.
