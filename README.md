# detection-decay

> Silent detection failure monitoring for SIEM detection engineers — catches source-death and field-drift that volume-only monitors miss.

[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/jayelbotvibe-web/detection-decay/actions/workflows/go.yml/badge.svg)](https://github.com/jayelbotvibe-web/detection-decay/actions/workflows/go.yml)

**The silent-detection-failure problem.** Your SIEM agent shows Active. Event volume looks healthy. But two things can silently kill detection without any conventional monitor catching them:

1. **Source death** — the telemetry source stops sending events (log-collection config disabled, channel dropped) while the agent stays connected.
2. **Field drift** — a critical field goes null at the index (schema change, pipeline bug, decoder upgrade) while events keep flowing.

**detection-decay** solves this with a capability-gate model that decomposes detection integrity into three independent links:

```text
DecayScore = 1 - P(source_ok) * P(field_ok|source_ok) * P(behavior)
```

![Architecture](docs/architecture.svg)

> **Unlike volume-based monitors** (elastalert, Grafana alerts, Wazuh agent status checks) that only catch source death by accident, detection-decay explicitly models field-level integrity. If your Sigma rule depends on `Image` being populated and your ingest pipeline silently drops that field — no volume alert fires, but detection-decay catches it.

## Who this is for

**Detection engineers and purple teamers** running SIEM detection pipelines (Wazuh, Elastic, Splunk) who need to know when their detections silently break — not just when the agent disconnects.

## What it is (and isn't)

| This IS | This is NOT |
|---------|-------------|
| A capability-gate scoring model for detection health | A SIEM replacement or log aggregator |
| An evidence-driven decay scorer with CLI + HTML output | A real-time monitoring service (yet — see roadmap) |
| SIEM/source-agnostic (model works on any indexed telemetry) | A Sigma rule validator or detection-as-code tool |

## Scoring model

Each gate is checked independently against a healthy baseline:

| Gate | Measurement | Fails when |
|------|------------|------------|
| **P(source)** | Agent liveness + event volume | Agent disconnected (dead), volume < 20% of baseline (dead), < 80% (degraded), > 300% (degraded — over-collection) |
| **P(field)** | Field populate rate vs baseline | Field populate < 20% of baseline (dead), < 80% (degraded) |
| **P(behavior)** | Rule match freshness | Not yet modeled — held at 1.0 |

**The healthy ceiling is the binding constraint.** Gates multiply, so a row needs
`P(source) × P(field) × P(behavior) ≥ 0.95` to read `HEALTHY` — not merely every gate above
the 80% band. Two gates at 90% compound to a decay of 0.19 and report `DEGRADED`, naming
both measurements in the reason.

**Over-collection is a failure mode too.** Volume between 1× and 3× baseline is ordinary
variance. Beyond 3×, a lost ingest filter or a duplicated pipeline is degrading detection
through drops, rule timeouts and alert-queue backlog — so it scores as decay rather than as
perfect health. It never reads as `DEAD:SOURCE`: events are demonstrably flowing.

A verdict is assigned per rule-state pair: `HEALTHY`, `DEGRADED`, `DEAD:SOURCE`,
`DEAD:FIELD`, `INSUFFICIENT_DATA`, or `PROBE_ERROR`.

**`PROBE_ERROR` is not an outage.** If the measurement itself failed — indexer unreachable,
query rejected — the row reports `PROBE_ERROR` and no decay, because a zero you could not
measure is not a zero you observed. Reporting that as `DEAD:SOURCE` would page an operator
about telemetry that may be perfectly healthy.

### Confidence is separate from the verdict

The verdict says *how bad*; confidence says *how sure*. Confidence is reported alongside
the verdict and is deliberately **never folded into the score** — a thin sample must not be
able to look like good health. It is discounted by a small baseline (below 30 events), by
any gate that abstained, and by a baseline more than 30 days old.

The same finding, measured well and measured badly, reaches the same verdict:

```text
baseline 3000 events   DEAD:FIELD   decay 1.00   confidence 1.00 HIGH
baseline    4 events   DEAD:FIELD   decay 1.00   confidence 0.57 MEDIUM
```

### Every score explains itself

Each gate carries the contributions that produced it, and the explanation is rendered from
those same values — so the breakdown always reconciles with the number it explains:

```text
P(source): 0.34
  • volume 22 vs baseline 64 = 34% of baseline (×0.34)
P(field): 1.00
  • data.win.eventdata.image populate 100% vs baseline 100% = 100% of baseline (×1.00)
P(behavior): 1.00
  • rule-match freshness not yet modeled — gate held at 1.0 (×1.00)

DecayScore: 1 - (0.34 × 1.00 × 1.00) = 0.66 → DEGRADED
```

## Demonstrated failure modes

Both on real Windows Sysmon EID 1 telemetry from a Wazuh SIEM lab (the scoring model is SIEM/source-agnostic):

**Source death** — Sysmon channel collection disabled in agent config. Agent stays Active. Volume collapses 64→0.

![Source death dashboard](screenshots/decay-dashboard.webp)

**Field drift** — `data.win.eventdata.image` removed at the index via ingest pipeline. Volume stays at 234 events. Field populate collapses 100%→0%.

![CLI output](screenshots/decay-cli.webp)

## Install

Requires Go 1.22+.

```bash
git clone https://github.com/jayelbotvibe-web/detection-decay.git
cd detection-decay
go build ./cmd/decay
```

Or install directly:

```bash
go install github.com/jayelbotvibe-web/detection-decay/cmd/decay@latest
```

## Usage

Score a static evidence file (both forms work):

```bash
./decay score --evidence evidence.json
./decay --evidence evidence.json        # bare-flags form also works
```

Generate an HTML dashboard:

```bash
./decay score --evidence evidence.json --format html --out demo/dashboard.html
```

Emit a machine-readable report:

```bash
./decay score --evidence evidence.json --format json | jq '.summary'
```

### Deriving what to measure from your Sigma rules

Which field a detection depends on was hand-declared, one `--field` argument at a time —
which is why the tool was calibrated for exactly one rule. Sigma already states the answer:
every key in a rule's `detection` block is a field the rule cannot fire without.

```bash
./scripts/sigma-to-rules.py --map scripts/fieldmap-wazuh.json \
    --out rules.json path/to/your/sigma/rules/
```

```json
{
  "rule": "win_proc_create.yml",
  "product": "windows", "category": "process_creation",
  "techniques": ["t1059"],
  "filter": "data.win.system.eventID:1",
  "sigma_fields": ["Image"],
  "fields": ["data.win.eventdata.image"],
  "unmapped_fields": []
}
```

Sigma is YAML and the decay binary is stdlib-only, so the conversion happens in this script
and the binary reads JSON. It is the only place PyYAML is needed.

Field names are Sigma's, not your index's. [`scripts/fieldmap-wazuh.json`](scripts/fieldmap-wazuh.json)
translates them — a logsource can supply a `template` (a naming convention) and/or explicit
`fields` entries, which win over the template.

**Anything that resolves to neither is reported as unmapped, never guessed at.** A fabricated
field name would measure 0% populate forever and read as permanent, confident field drift —
the exact failure this tool exists to catch. The shipped map therefore covers Windows Sysmon
(where Wazuh's decoder lowercases the first letter, so `Image` → `data.win.eventdata.image`)
and deliberately leaves Linux empty: auditd field layout depends on your audit rules, and
there is no single convention worth assuming. Verify any mapping against your own index
before trusting a score built on it.

### Tracking decay over time

A single run says a rule looks dead; a series says *when it died*. Pass `--history` and each
run is persisted and indexed:

```bash
./decay score --evidence evidence-live.json --history ./decay-history
```

```text
<dir>/runs/20260824T164500Z/decay.json   full report, never rewritten
<dir>/history.json                       trend index, one row per trusted run
```

The terminal output then leads with what moved, rather than restating a table you already
read an hour ago:

```text
Changes since 20260824T154500Z
  ~ win_proc_create.yml / live — HEALTHY → DEAD:FIELD (decay 0.00 → 1.00)
  1 unchanged
```

Findings are matched by a fingerprint over the rule, state, verdict and banded decay score,
so an unchanged rule matches by hash and a worsened one does not — with no diffing code and
no bookkeeping. The score is rounded to one decimal inside the fingerprint so ordinary
measurement noise is not reported as a change every run.

Storage is plain JSON files, no database. Two behaviours worth knowing:

- **A run that measured nothing is saved but not indexed.** If every probe failed, the run
  carries no information about detection health, and indexing it would put a false `0.00`
  on the trend line. The artifact is kept — a failed run is exactly what you want to inspect.
- **A corrupt index is rebuilt, not fatal.** Losing trend history is not a reason to stop
  scoring, and refusing to run until someone hand-repairs a JSON file is the wrong trade for
  a monitoring tool.

### Wiring it into a scheduler

`--fail-on` makes the exit code carry the finding, so cron or CI can act on it:

```bash
./decay score --evidence evidence-live.json --fail-on dead || notify-oncall
```

| `--fail-on` | Exits non-zero when any row is |
|---|---|
| `none` (default) | never — report only |
| `unknown` | anything but `HEALTHY`, including `INSUFFICIENT_DATA` and `PROBE_ERROR` |
| `degraded` | `DEGRADED`, `DEAD:SOURCE` or `DEAD:FIELD` |
| `dead` | `DEAD:SOURCE` or `DEAD:FIELD` |

| Exit code | Meaning |
|---|---|
| `0` | scored successfully, nothing at or above the `--fail-on` threshold |
| `1` | could not read, parse or validate the evidence file |
| `2` | bad invocation |
| `3` | scored successfully, and found decay at or above `--fail-on` |

The evidence format is a JSON array of measurement rows:

```json
[
  {
    "rule": "win_proc_create.yml",
    "state": "field-drift",
    "liveness": "active",
    "volume": 234,
    "baseline_volume": 64,
    "field_populate": 0.0,
    "baseline_field_populate": 1.0,
    "field": "data.win.eventdata.image"
  }
]
```

Optional keys: `field` (names the field in reason strings), `baseline_age_seconds` (an old
baseline lowers confidence), and `probe_error` (a string; set it when the measurement itself
failed, and the row reports `PROBE_ERROR` instead of a fabricated outage).

Input is validated before scoring, and unknown keys are rejected. Both rules exist because
the failure mode is silent: a mistyped `volume` key used to default to `0` and report a
total source outage, and an omitted `liveness` key used to report `DEAD:SOURCE — agent
disconnected` for a row that never mentioned an agent.

### Generating evidence from a live index

`scripts/collect-opensearch.sh` measures volume and field-populate rate directly from a Wazuh indexer / OpenSearch / Elasticsearch endpoint and writes scorer-ready evidence. Credentials come from environment variables — never hardcode them:

```bash
export DECAY_ES_URL="https://127.0.0.1:9200"
export DECAY_ES_USER="admin"
export DECAY_ES_PASS="<indexer password>"

# capture a healthy baseline once
echo '{"baseline_volume": 64, "baseline_field_populate": 1.0}' > baseline.json

# collect and score
./scripts/collect-opensearch.sh \
  --index 'wazuh-alerts-*' \
  --rule win_proc_create.yml \
  --field data.win.eventdata.image \
  --filter 'data.win.system.eventID:1' \
  --window 15m \
  --baseline baseline.json \
  --out evidence-live.json

./decay score --evidence evidence-live.json
```

Requires `curl` and `jq`. Use `--insecure` (or `DECAY_ES_INSECURE=1`) for self-signed lab certificates. If zero events are returned, `field_populate` is emitted as `null` so the scorer abstains instead of guessing.

## Roadmap

- [ ] **Live mode** (`--live`) — poll the indexer directly. Prototyped on `feat/live-mode`, but that branch forked before v0.2.0 and is not merge-ready; being reimplemented on `main` with no third-party dependencies
- [ ] **P(behavior) gate** — rule match freshness scoring (time since last alert match)
- [x] **Derive fields from Sigma** — `scripts/sigma-to-rules.py` extracts the required fields, logsource and ATT&CK tags from a rule set
- [ ] **Multi-rule collection** — sweep a whole `rules.json` in one pass instead of one rule per invocation
- [x] **Run history and trend index** (`--history`) — persist each run, report what changed since the last one
- [ ] **Alerting integration** — webhook/Slack/PagerDuty when decay is detected
- [ ] **Rolling baseline calibration** — derive baselines from recorded history instead of a hand-written file
- [ ] **Positive control** — push a known-good event through the pipeline and mark the run inconclusive if it does not land
- [ ] **Closed calibration loop** — run probes, score results, feed back into baseline

## Limitations

- **Evidence-driven**: the scorer reads static JSON; live measurement is via the reference collector script (`scripts/collect-opensearch.sh`), not a built-in poller.
- **P(behavior) deferred**: alert freshness not yet modeled — the gate is held at 1.0 and says so in every explanation.
- **Single-rule scope in the collector**: `scripts/sigma-to-rules.py` derives the fields for a whole rule set, but `scripts/collect-opensearch.sh` still measures one rule per invocation — nothing yet consumes `rules.json` to sweep them.
- **Hand-maintained baselines**: `--history` records runs, but nothing yet derives a rolling baseline from them, so a fixed baseline will read a quiet weekend as `DEGRADED`. Set `baseline_age_seconds` so at least the confidence reflects it.
- **No positive control**: the scorer trusts that a measurement of zero means zero. Set `probe_error` when your collector knows better.

⭐ **Star this repo** if you've hit silent detection decay in production. [Issues](https://github.com/jayelbotvibe-web/detection-decay/issues) and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
