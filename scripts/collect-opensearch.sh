#!/usr/bin/env bash
# collect-opensearch.sh — generate evidence.json for the decay scorer
# from a Wazuh indexer / OpenSearch / Elasticsearch endpoint.
#
# Measures, per rule you care about:
#   1. volume        — event count in the current window
#   2. field_populate — fraction of those events where the critical field exists
# and compares against a stored baseline.
#
# Credentials: NEVER hardcode. Export before running:
#   export DECAY_ES_URL="https://127.0.0.1:9200"
#   export DECAY_ES_USER="admin"
#   export DECAY_ES_PASS="..."          # or use DECAY_ES_NETRC=1 with ~/.netrc
#
# Usage:
#   ./scripts/collect-opensearch.sh \
#     --index 'wazuh-alerts-*' \
#     --rule win_proc_create.yml \
#     --field data.win.eventdata.image \
#     --filter 'data.win.system.eventID:1' \
#     --window 15m \
#     --baseline baseline.json \
#     --state current \
#     --out evidence.json
#
# Baseline file format (write it once from a known-healthy window):
#   {"baseline_volume": 64, "baseline_field_populate": 1.0}
#
# Requires: curl, jq

set -euo pipefail

INDEX="" RULE="" FIELD="" FILTER="*" WINDOW="15m"
BASELINE="" STATE="current" OUT="evidence.json" INSECURE="${DECAY_ES_INSECURE:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --index)    INDEX="$2"; shift 2 ;;
    --rule)     RULE="$2"; shift 2 ;;
    --field)    FIELD="$2"; shift 2 ;;
    --filter)   FILTER="$2"; shift 2 ;;
    --window)   WINDOW="$2"; shift 2 ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    --state)    STATE="$2"; shift 2 ;;
    --out)      OUT="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$INDEX" && -n "$RULE" && -n "$FIELD" && -n "$BASELINE" ]] || {
  echo "required: --index --rule --field --baseline" >&2; exit 2; }
[[ -n "${DECAY_ES_URL:-}" ]] || { echo "set DECAY_ES_URL" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

CURL=(curl -sS --fail-with-body)
[[ "$INSECURE" == "1" ]] && CURL+=(-k)
if [[ "${DECAY_ES_NETRC:-0}" == "1" ]]; then
  CURL+=(--netrc)
elif [[ -n "${DECAY_ES_USER:-}" ]]; then
  CURL+=(-u "${DECAY_ES_USER}:${DECAY_ES_PASS:?set DECAY_ES_PASS}")
fi

es_count() { # $1 = extra must-clause JSON ("" for none)
  local extra="$1" body
  body=$(jq -n --arg filter "$FILTER" --arg window "now-$WINDOW" --argjson extra "${extra:-null}" '
    { query: { bool: { must:
        ([ {query_string:{query:$filter}},
           {range:{"@timestamp":{gte:$window}}} ]
         + (if $extra == null then [] else [$extra] end)) } } }')
  "${CURL[@]}" -H 'Content-Type: application/json' \
    -X POST "${DECAY_ES_URL}/${INDEX}/_count" -d "$body" | jq -r '.count'
}

# 1. Agent/source liveness is environment-specific; default to "active"
#    and let volume tell the story. Override via DECAY_LIVENESS if you
#    query the Wazuh API for agent status separately.
LIVENESS="${DECAY_LIVENESS:-active}"

# 2. Volume in window
VOLUME="$(es_count "")"

# 3. Field populate rate: events where the field exists / all events
if [[ "$VOLUME" -gt 0 ]]; then
  WITH_FIELD="$(es_count "$(jq -n --arg f "$FIELD" '{exists:{field:$f}}')")"
  FIELD_POPULATE=$(jq -n --argjson a "$WITH_FIELD" --argjson b "$VOLUME" '$a / $b')
else
  FIELD_POPULATE=null   # no events → scorer must ABSTAIN, not assume 0
fi

BASE_VOL=$(jq -r '.baseline_volume' "$BASELINE")
BASE_FP=$(jq -r '.baseline_field_populate' "$BASELINE")

jq -n \
  --arg rule "$RULE" --arg state "$STATE" --arg liveness "$LIVENESS" \
  --argjson volume "$VOLUME" --argjson bvol "$BASE_VOL" \
  --argjson fp "$FIELD_POPULATE" --argjson bfp "$BASE_FP" \
  '[{ rule:$rule, state:$state, liveness:$liveness,
      volume:$volume, baseline_volume:$bvol,
      field_populate:$fp, baseline_field_populate:$bfp }]' > "$OUT"

echo "wrote $OUT (volume=$VOLUME field_populate=$FIELD_POPULATE)" >&2
