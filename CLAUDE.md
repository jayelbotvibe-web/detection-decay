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

- `cmd/decay/main.go` — entry point: flags, evidence load, sorting, text and
  HTML renderers. `const version`.
- `internal/score/score.go` — the model: `Evidence` and `Result` structs,
  `Score()`, `ScoreAll()`, `const MaxHealthyDecay = 0.05`

  Gates are the source of truth. `Score()` builds a `[]Gate` (`source`, `field`,
  `behavior`); each `Gate` holds the `[]Contribution` that produced its value, and a gate's
  value is the **product** of its factors. `Result.Explanation` is rendered from those same
  values, so the breakdown always reconciles with the number — enforced by `assertReconciles`
  in the tests. `Result.PSource/PField/PBehavior` are flat projections of the gate values,
  kept for the machine-readable surface; don't compute from them, compute from `Gates`.
- `cmd/decay/main_test.go`, `internal/score/score_test.go` — renderer and model tests
- `scripts/collect-opensearch.sh` — reference evidence collector for
  OpenSearch/Wazuh/Elasticsearch
- `evidence.json` — demo input; `demo/dashboard.html` — generated artifact

No code generation, no `go generate`.

## The six verdicts

`HEALTHY`, `DEGRADED`, `DEAD:SOURCE`, `DEAD:FIELD`, `INSUFFICIENT_DATA`, `PROBE_ERROR`.

The set grew in v0.2.0 (`DEGRADED`) and again after it (`PROBE_ERROR`) — anything keyed on
exact verdict labels must handle all six. Both changes are migration notes in `CHANGELOG.md`.

**Three invariants the scorer must never violate.** Each has a regression test that was
confirmed to fail without it:

1. **Never report a number you did not measure.** A `null` field populate abstains; a row
   with `probe_error` set reports `PROBE_ERROR` and *no decay*, because a zero you could not
   measure is not a zero you observed. Renderers print `n/a`, never `0%`.
2. **Never report `HEALTHY` above `MaxHealthyDecay`** — and when the ceiling downgrades a
   row, *append* to the per-gate detail rather than replacing it. The operator needs to know
   which gate slipped.
3. **Over-collection is never `DEAD:SOURCE`.** Events are flowing; the gate is floored at
   `DeadThreshold`.

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

Working MVP, actively developed. Zero TODO/FIXME markers.

**CI only triggers on `main`** (`.github/workflows/go.yml`), so pushes to a feature branch
run nothing until a PR is opened. Run the gates locally.

**Note for running tests here:** `/tmp` is mounted noexec in some sandboxes, which makes
`go test` fail with `fork/exec ... permission denied`. Set `GOTMPDIR` somewhere executable.

**Note the branch state.** Default branch is `main`. Work has been stacking on unpushed
branches: `fix/verdict-thresholds` (banded verdicts, PR #3) and `feat/trustworthy-verdicts`
on top of it. Check where you are before committing.

`feat/live-mode` (PR #1) is **not a merge candidate** — it branched off the *initial* commit,
so merging it would delete CI, `SECURITY.md` and `scripts/collect-opensearch.sh`, revert the
scoring model to the v0.1.x binary steps, add a `gopkg.in/yaml.v3` dependency, and hardcode
`InsecureSkipVerify: true` against what `SECURITY.md` claims. Its good ideas (live probing,
a probe-error verdict) are being reimplemented on `main` instead.

**The zero-dependency rule is a hard constraint**, not a preference. It is what pushes
history onto plain JSON run files rather than SQLite, and Sigma ingestion into a conversion
script rather than a YAML parser in the binary.

Roadmap items still unfinished: P(behavior) gate, live mode, multi-rule scope, run history,
alerting, calibration loop.
