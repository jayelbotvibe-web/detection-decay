# CLAUDE.md — detection-decay

A CLI scorer for **silent detection failure** in SIEM pipelines. It reads a JSON evidence
file (event volume, agent liveness, field-populate rate, plus healthy baselines) and
computes `DecayScore = 1 - P(source_ok) * P(field_ok|source_ok) * P(behavior)`, assigning
each rule/state pair one of six verdicts plus a confidence label.

It also records runs, derives baselines from that history, and serves a read-only dashboard
over them.

Targets two failure modes volume-only monitors miss: a telemetry source dying while the
agent still reports Active, and a critical field going null at the index while events keep
flowing.

## Commands

```bash
go build ./cmd/decay                                   # build
go test ./... -v -count=1 -race                        # test
python3 scripts/sigma_to_rules_test.py                 # test the Sigma converter

./decay score --evidence evidence.json
./decay score --evidence evidence.json --format json | jq .summary
./decay score --evidence evidence.json --format html --out demo/dashboard.html
./decay score --evidence e.json --history ./hist --fail-on dead   # exits 3 on decay
./decay calibrate --history ./hist --out baselines.json
./decay serve --history ./hist                         # http://127.0.0.1:8788
```

There is no Makefile and no lint config. The gates are gofmt and vet, run in CI and
worth running locally:

```bash
test -z "$(gofmt -l ./cmd ./internal)"
go vet ./...
```

**Running tests here:** `/tmp` is mounted noexec in some sandboxes, which makes `go test`
fail with `fork/exec ... permission denied`. Set `GOTMPDIR` somewhere executable.

## Stack

Go **1.22** (`go.mod`). **Zero third-party dependencies** — no `require` block, no
`go.sum`. Stdlib only (`encoding/json`, `flag`, `html`, `sort`, `net/http`, `embed`,
`crypto/sha256`).

This is a **hard constraint, enforced by CI**: the build fails if a `require` block or a
`go.sum` ever appears. It is what pushes run history onto plain JSON files rather than
SQLite, and Sigma parsing into a conversion script rather than a YAML library in the binary.
`scripts/sigma-to-rules.py` needs PyYAML, but it is a developer tool and never runs as part
of the binary.

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
- `internal/history/history.go` — run persistence and the trend index. Plain JSON files,
  no database: `runs/<id>/decay.json` is immutable, `history.json` is the slim index.
  Two deliberate behaviours — a run that measured nothing is saved but **not** indexed, and
  a corrupt index is rebuilt rather than fatal. `runDir` verifies path containment *after*
  joining; the id regex alone accepts `..`.
- `internal/calibrate/calibrate.go` — derives baselines from history. **Only `HEALTHY`
  observations contribute**; that is the whole point of the package. Calibrating from every
  observation makes a rolling baseline follow a dead source down until the outage reads
  healthy — silent, permanent, and worse than no calibration. `TestRatchetGuard` pins it.
  Baselines are medians, not means.
- `internal/server/server.go` + `internal/server/web/index.html` — read-only dashboard,
  `//go:embed`. Read-only by construction: every route is wrapped in `get()`, which 405s
  anything else. Handlers do **no** id sanitising of their own — `history.Store` owns that
  decision, so there is one place that defines a valid run id. Loopback-only unless
  `-allow-remote`.
- `cmd/decay/main_test.go`, `internal/score/score_test.go`, `internal/history/history_test.go`,
  `internal/calibrate/calibrate_test.go`, `internal/server/server_test.go`
- `scripts/collect-opensearch.sh` — reference evidence collector for
  OpenSearch/Wazuh/Elasticsearch. Still one rule per invocation.
- `scripts/sigma-to-rules.py` + `scripts/fieldmap-wazuh.json` — derive a rules file from
  Sigma. **The only Python, and the only PyYAML**, deliberately: Sigma is YAML and the
  binary is stdlib-only, so conversion happens here and the binary reads JSON. Tests are
  `scripts/sigma_to_rules_test.py` (stdlib `unittest`), run by the `sigma` CI job against
  vendored fixtures in `testdata/sigma/`. Nothing consumes `rules.json` yet.
- `evidence.json` — demo input; `demo/dashboard.html` — generated artifact

No code generation, no `go generate`.

## The six verdicts

`HEALTHY`, `DEGRADED`, `DEAD:SOURCE`, `DEAD:FIELD`, `INSUFFICIENT_DATA`, `PROBE_ERROR`.

The set grew in v0.2.0 (`DEGRADED`) and again in v0.3.0 (`PROBE_ERROR`) — anything keyed on
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

- The **scorer handles no credentials** — that boundary is stated in `SECURITY.md`. Keep it.
  Collection is a separate concern; only `scripts/collect-opensearch.sh` touches an indexer.
- **`decay serve` is the only listener**, it is read-only, and it binds to loopback unless
  `-allow-remote`. It has no authentication by design. If you add a route, wrap it in `get()`
  and do not let it write anything.
- `scripts/collect-opensearch.sh` needs `curl` and `jq`, plus env: `DECAY_ES_URL`
  (required, exits 2 without it), `DECAY_ES_USER`, `DECAY_ES_PASS`, optional
  `DECAY_ES_NETRC=1`, `DECAY_ES_INSECURE`, `DECAY_LIVENESS` (default `active`). The script
  warns that `-u` exposes credentials in argv and recommends `--netrc`.
- `evidence.json` is demonstration data, explicitly out of security scope.

## State

**v0.3.0**, released and tagged. `main` is current; everything below is merged. Zero
TODO/FIXME markers.

CI (`.github/workflows/go.yml`) runs on **every branch**, two jobs: `build` (gofmt, vet,
build, `go test -race`, a zero-dependency gate, and a check that `demo/dashboard.html` is
not stale) and `sigma` (the Python converter tests against fixtures in `testdata/sigma/`).

**`demo/dashboard.html` and `screenshots/*.webp` are generated artifacts.** A renderer or
version change must regenerate them or CI fails on the dashboard and the README starts
contradicting the tool.

```bash
# dashboard.html — CI fails if this is stale
./decay score --evidence evidence.json --format html --out demo/dashboard.html

# screenshots/decay-cli.webp
./decay score --evidence evidence.json | python3 scripts/ansi-to-html.py > cli.html
wkhtmltoimage --transparent --width 1900 --format png cli.html raw.png
convert raw.png -background '#0d1117' -alpha remove -trim +repage \
        -bordercolor '#0d1117' -border 32 -resize 50% -define webp:lossless=true \
        screenshots/decay-cli.webp
```

Three gotchas, each of which cost a rebuild:

- **Render at 2x and downsample.** Box-drawing characters do not tile at small font sizes;
  the table's horizontal rules come out dashed.
- **`wkhtmltoimage` cannot render `decay serve`.** Its WebKit predates `fetch()` and the
  page's CSS — it captures "loading…" on a white background. Use Firefox for anything with
  JavaScript.
- **Firefox is a snap here, and snaps cannot write into hidden directories.** Screenshotting
  to any path under `~/.cache` fails with the misleading "Firefox is already running".
  Use a non-hidden output directory.

`decay serve` needs one more step, because Firefox's `--screenshot` fires on `load` and the
page's second `fetch` has not resolved by then: capture `/api/history` and
`/api/runs/latest` from a live server, then stub `window.fetch` in a copy of the served
page. Only the transport is replaced — the page's own rendering runs unmodified.

`feat/live-mode` (PR #1) was **closed, not merged** — it branched off the *initial* commit,
so merging it would have deleted CI, `SECURITY.md` and `scripts/collect-opensearch.sh`,
reverted the scoring model to v0.1.x binary steps, added `gopkg.in/yaml.v3`, and hardcoded
`InsecureSkipVerify: true`. Its two good ideas landed independently: `PROBE_ERROR` shipped
in v0.3.0, and live collection is still to build.

### Not done yet

- **Live collection** — no built-in poller; `scripts/collect-opensearch.sh` is the reference
  collector and it still measures one rule per invocation. Nothing consumes `rules.json`.
- **Positive control / canary** — the scorer trusts that a measured zero is a real zero.
  `probe_error` is the manual escape hatch.
- **P(behavior)** — held at 1.0 and says so in every explanation.
- **Seasonality** — `calibrate` is a flat median over a window, with no time-of-day or
  day-of-week notion.
- **Alerting** — no notifier. The confidence axis exists so routing can key on
  (verdict, confidence) when it is built.
