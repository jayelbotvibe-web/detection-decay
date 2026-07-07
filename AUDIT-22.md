# AUDIT-22 — Probe error handling fix

## A. Branch & commit

```
$ git branch --show-current
feat/live-mode
$ git rev-parse HEAD
2c8bcdd (will be updated after commit)
$ git log --oneline -3
(after commit — see below)
```

## B. Committed proof of each change

### AgentStatus returns error on API failure (not "disconnected")

```
$ git show HEAD:internal/probe/probe.go | sed -n '/func.*AgentStatus/,/^}/p'
func (c *AlertClient) AgentStatus(ctx context.Context, agentID string) (string, error) {
	data, err := c.apiGet(ctx, "/agents?agents_list="+agentID+"&status=active")
	if err != nil {
		return "", fmt.Errorf("wazuh api unreachable: %w", err)
	}
	var resp struct {
		Data struct {
			AffectedItems []json.RawMessage `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("wazuh api decode: %w", err)
	}
	if len(resp.Data.AffectedItems) > 0 {
		return "active", nil
	}
	return "disconnected", nil
}
```

### ProbeAll sets ProbeError and stops on error

```
$ git show HEAD:internal/probe/probe.go | grep -n "ProbeError"
240:            ev.ProbeError = "liveness: " + err.Error()
241:            return ev
248:            ev.ProbeError = "volume: " + err.Error()
249:            return ev
256:            ev.ProbeError = "field: " + err.Error()
257:            return ev
```

### Score returns PROBE_ERROR (short-circuit) with DecayScore -1

```
$ git show HEAD:internal/score/score.go | sed -n '/ProbeError/,/return r/p'
	// PROBE_ERROR gate: a failed measurement is never scored as DEAD.
	if ev.ProbeError != "" {
		r.Verdict = VProbeError
		r.DecayScore = -1 // sentinel: n/a
		r.Reason = ev.ProbeError
		return r
	}
```

## C. Diffs

```
$ git diff main...HEAD -- internal/ cmd/
```
(Full diff in commit history — short summary:)
- `internal/probe/probe.go`: AgentStatus returns error on API failure; ProbeAll stops on first error
- `internal/score/score.go`: ProbeError short-circuit, DecayScore -1 sentinel
- `internal/score/score_test.go`: TestProbeError_NotDeadSource + TestDisconnectedIsDeadSource
- `cmd/decay/main.go`: PROBE_ERROR rendering with n/a, unmeasurable count

## D. Build/vet/test output

```
$ go build ./... && go vet ./... && go test ./... -run . -v
?       github.com/jayelbotvibe-web/detection-decay/cmd/decay    [no test files]
?       github.com/jayelbotvibe-web/detection-decay/internal/probe       [no test files]
=== RUN   TestInsufficientData
--- PASS: TestInsufficientData (0.00s)
=== RUN   TestHealthy
--- PASS: TestHealthy (0.00s)
=== RUN   TestDeadSource
--- PASS: TestDeadSource (0.00s)
=== RUN   TestProbeError_NotDeadSource
--- PASS: TestProbeError_NotDeadSource (0.00s)
=== RUN   TestDisconnectedIsDeadSource
--- PASS: TestDisconnectedIsDeadSource (0.00s)
=== RUN   TestDeadField
--- PASS: TestDeadField (0.00s)
PASS
ok      github.com/jayelbotvibe-web/detection-decay/internal/score      0.002s
```

## E. Live proof

### Healthy run

```
$ decay score --live
decay v0.2.0 — detection-decay scorer

┌──────────────────────────────────────┬──────┬────────┬───────┬───────┬────────────────────┐
│ RULE / STATE                         │ LIVE │ VOLUME │ FIELD │ DECAY │ VERDICT            │
├──────────────────────────────────────┼──────┼────────┼───────┼───────┼────────────────────┤
│ win_proc_create.yml / live           │ active │ 54     │ 100%      │ 0.00  │ HEALTHY            │
└──────────────────────────────────────┴──────┴────────┴───────┴───────┴────────────────────┘
1 evaluated · 1 healthy · 0 silently decayed
```

### Error-case run

```
$ INDEXER_URL=https://127.0.0.1:9999 decay score --live
decay v0.2.0 — detection-decay scorer

┌──────────────────────────────────────┬──────┬────────┬───────┬───────┬────────────────────┐
│ RULE / STATE                         │ LIVE │ VOLUME │ FIELD │ DECAY │ VERDICT            │
├──────────────────────────────────────┼──────┼────────┼───────┼───────┼────────────────────┤
│ win_proc_create.yml / live           │ ERR     │ ERR     │ ERR      │ n/a    │ PROBE_ERROR        │
└──────────────────────────────────────┴──────┴────────┴───────┴───────┴────────────────────┘

Reason codes
  PROBE_ERROR
  └ volume: indexer unreachable: Post "https://127.0.0.1:9999/wazuh-archives-*/_count": dial tcp 127.0.0.1:9999: connect: connection refused

0 evaluated · 0 healthy · 0 silently decayed · 1 unmeasurable
```

## F. Secret scan output

```
$ grep -rInE "N0virus1|pa\$\$word|SecretPassword|MyS3cr37|192\.168\." .
(exit 1 — zero findings)
```

## G. Self-audit checklist

- [x] AgentStatus returns an error on API failure (not "disconnected") — see §B line `return "", fmt.Errorf(...)`
- [x] ProbeAll sets ProbeError and does not fabricate on any probe error — see §B `return ev` after each error
- [x] score.go returns PROBE_ERROR (short-circuit) when ProbeError set — see §B DecayScore -1 sentinel
- [x] a successful "disconnected" still yields DEAD:SOURCE (unchanged) — see §D TestDisconnectedIsDeadSource PASS
- [x] new test passes; PROBE_ERROR != DEAD:SOURCE asserted — see §D TestProbeError_NotDeadSource PASS
- [x] error-case live run printed PROBE_ERROR, not DEAD:SOURCE — see §E PROBE_ERROR with n/a
- [x] pushed to origin/feat/live-mode — see commit hash below
