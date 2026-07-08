# detection-decay

**The silent-detection-failure problem.** Your SIEM agent shows Active. Event volume looks healthy. But two things can silently kill detection without any conventional monitor catching them:

1. **Source death** — the telemetry source stops sending events (log-collection config disabled, channel dropped) while the agent stays connected.
2. **Field drift** — a critical field goes null at the index (schema change, pipeline bug, decoder upgrade) while events keep flowing.

A volume-only monitor catches source death by luck but completely misses field drift. **detection-decay** solves this with a capability-gate model that decomposes detection integrity into three independent links.

```text
DecayScore = 1 - P(source_ok) * P(field_ok|source_ok) * P(behavior)
```

![Architecture](docs/architecture.svg)

Each gate is checked independently against a healthy baseline:

| Gate | Measurement | Fails when |
|------|------------|------------|
| **P(source)** | Agent liveness + event volume | Agent disconnected, or volume < 10% of baseline |
| **P(field)** | Field populate rate vs baseline | Critical field goes null on new events |
| **P(behavior)** | Rule match freshness | Deferred in MVP (= 1.0) |

A verdict is assigned per rule-state pair: `HEALTHY`, `DEAD:SOURCE`, `DEAD:FIELD`, or `INSUFFICIENT_DATA`.

Unlike volume-based monitors (elastalert, Grafana alerts, Wazuh agent status checks) that only catch source death by accident, detection-decay explicitly models field-level integrity. If your Sigma rule depends on `Image` being populated and your ingest pipeline silently drops that field, no volume alert fires — but detection-decay catches it.

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
go install github.com/jayelbotvibe-web/detection-decay/cmd/decay@v0.1.0
```

## Usage

Score a static evidence file:

```bash
./decay score --evidence evidence.json
```

Generate an HTML dashboard:

```bash
./decay score --evidence evidence.json --format html --out demo/dashboard.html
```

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
    "baseline_field_populate": 1.0
  }
]
```

## Roadmap

- [ ] **Live mode** (`--live`) — poll SIEM APIs (Wazuh, Elasticsearch, Splunk) directly instead of reading static JSON
- [ ] **P(behavior) gate** — rule match freshness scoring (time since last alert match)
- [ ] **Multi-rule scope** — calibrate across full Sigma rule sets, not just `win_proc_create.yml`
- [ ] **Alerting integration** — webhook/Slack/PagerDuty when decay is detected
- [ ] **Closed calibration loop** — run probes, score results, feed back into baseline

## Limitations

- **Evidence-driven MVP**: reads static JSON measurements, not a live SIEM.
- **P(behavior) deferred**: alert freshness not yet modeled.
- **Single-rule scope**: currently calibrated for `win_proc_create.yml` only.
- **No closed calibration loop**: the tool scores probes but does not run them.

## License

MIT — see [LICENSE](LICENSE).
