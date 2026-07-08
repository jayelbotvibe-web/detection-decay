# DEPLOYMENT — detection-decay live mode setup

Reproduce the full live pipeline: stand up a Wazuh SIEM, enroll a Sysmon endpoint, configure the tool, and score real telemetry.

## 1. Prerequisites

- **Go 1.22+** — `go version`
- **Wazuh SIEM** — single-node Docker deployment is sufficient
- **Monitored endpoint** — Windows with Sysmon enrolled as a Wazuh agent

## 2. Stand up a Wazuh lab

Use Wazuh's official [single-node Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).

### Critical: enable raw archiving

By default Wazuh only indexes **alerts** (rule-triggered events). The field-populate probe needs **raw archives** — all events, before rule matching — because a field going null is invisible in alerts (the alert just stops firing).

Two changes on the manager:

**`ossec.conf`** — enable archive logging:
```xml
<logall_json>yes</logall_json>
```

**`filebeat.yml`** — enable archive forwarding to the indexer:
```yaml
filebeat.modules:
  - module: wazuh
    archives:
      enabled: true
```

Also disable ILM (OpenSearch doesn't support it):
```yaml
setup.ilm.enabled: false
```

After both changes, restart the manager. Confirm `wazuh-archives-*` appears in the indexer.

## 3. Enroll an endpoint + Sysmon

1. Install **Sysmon** on the Windows endpoint (Sysinternals `Sysmon64.exe -i <config>`)
2. Install the **Wazuh agent**, pointing it at your manager
3. Add a `<localfile>` block in the agent's `ossec.conf` to forward the Sysmon channel:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
4. Confirm the agent is **Active** on the manager
5. Verify Sysmon Event ID 1 (process creation) events appear in `wazuh-archives-*`

## 4. Configure the tool

Copy and edit `.env.example`:
```bash
cp .env.example .env
# edit .env with your lab values
```

Environment variables:

| Variable | Purpose | Example |
|----------|---------|---------|
| `INDEXER_URL` | Wazuh indexer HTTPS endpoint | `https://<indexer-host>:9200` |
| `INDEXER_USER` | Indexer username | `admin` |
| `INDEXER_PASS` | Indexer password | `changeme` |
| `WAZUH_API_URL` | Manager API endpoint | `https://<manager-host>:55000` |
| `WAZUH_API_USER` | API username | `wazuh-wui` |
| `WAZUH_API_PASS` | API password | `changeme` |

Load them:
```bash
export $(grep -v '^#' .env | xargs)
```

**Never commit `.env`.** It's in `.gitignore`.

## 5. Configure `rules.yaml`

Map your detection rule to the SIEM fields:

```yaml
rules:
  - rule: win_proc_create.yml
    agent_id: "<your-agent-id>"          # e.g. "002"
    event_type_field: data.win.system.eventID
    event_id: 1                          # Sysmon EID 1 = process creation
    field_path: data.win.eventdata.image # the field the rule keys on
    rule_id: "92031"                     # Wazuh rule ID for LAST_MATCH (optional)
    window_minutes: 15
    baseline_volume: 64                  # calibrate from healthy state
    baseline_field_populate: 1.0         # 1.0 = 100% populated in healthy state
```

The tool probes:
- **Liveness**: Wazuh API → is the agent Active?
- **Volume**: count of `event_id` events from the agent in the window
- **Field**: fraction of those events where `field_path` is non-null

## 6. Run it

```bash
cd detection-decay
./decay score --live --config rules.yaml
```

Expected healthy output:
```
│ win_proc_create.yml / live │ active │ <N> │ 100% │ 0.00 │ HEALTHY │
```

## 7. Reproduce the two demos

### Source death — disable Sysmon collection

1. In the Wazuh agent's `ossec.conf` on the endpoint, **remove or comment out** the `<localfile>` block for `Microsoft-Windows-Sysmon/Operational`
2. Restart the Wazuh agent service
3. The agent remains **Active** — a basic liveness check sees nothing wrong
4. Run the tool: volume collapses → `DEAD:SOURCE`

Revert: restore the `<localfile>` block, restart the agent, confirm events resume.

### Field drift — drop the image field at the index

1. Create an OpenSearch ingest pipeline that removes the field:
   ```json
   PUT _ingest/pipeline/drift-drop-image
   {
     "processors": [{"remove": {"field": "data.win.eventdata.image", "ignore_failure": true}}]
   }
   ```
2. Append it to the filebeat archives pipeline OR set `index.default_pipeline`
3. New events are indexed **without** the `image` field
4. Volume stays nominal, but field populate → 0% → `DEAD:FIELD`

Revert: delete the pipeline, confirm the field repopulates in new events.

## 8. Troubleshooting

| Symptom | Check |
|---------|-------|
| `PROBE_ERROR` | Tool can't reach the SIEM — verify `INDEXER_URL`/`WAZUH_API_URL` and credentials |
| Volume = 0 (healthy lab) | `logall_json` not enabled, or filebeat archives forwarding disabled |
| Field = N/A | Archives index has no events for the configured event type |
| Agent "disconnected" | Agent not enrolled, or wrong `agent_id` in `rules.yaml` |

`PROBE_ERROR` is a **measurement failure** — the tool is reporting that it couldn't query the SIEM. It is never a detection failure. If the SIEM is healthy but the tool says `PROBE_ERROR`, check network/firewall/credentials.
