# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| v0.3.x  | ✅ |
| v0.2.x  | ❌ |

## Trust boundary

The scorer handles **no credentials**. Collection is a separate concern:
`scripts/collect-opensearch.sh` is the only component that touches an indexer, and it takes
credentials from the environment (see the warning in its header about `-u` exposing them in
`ps(1)`). The `decay` binary itself never authenticates to anything.

Two capabilities were added in v0.3.0 that earlier versions did not have, and they change
this boundary:

- **`decay serve` opens a listener.** It is read-only — every route rejects anything but
  `GET`/`HEAD` — and it **binds to loopback unless `--allow-remote` is passed**. There is
  **no authentication**. The page is a map of exactly where an estate's detection is blind,
  so treat exposing it as you would treat publishing that map. Run ids are validated and
  path containment is verified before any file is read.
- **`--history` writes to disk.** Run artifacts and the trend index are plain JSON under the
  directory you name. They contain rule names, field names and volumes from your index —
  operational detail about your telemetry, not secrets, but not nothing either. They are
  written `0644`; place the directory accordingly.

## Reporting a vulnerability

Report security issues via [GitHub issues](https://github.com/jayelbotvibe-web/detection-decay/issues) or DM [@junielkatarn](https://x.com/junielkatarn). Response within 48 hours.

## Scope

- **In scope**: input validation, scoring logic errors, path traversal in run-id handling,
  anything that causes `decay serve` to write, mutate or serve a file outside the run store,
  and any way a scoring verdict can be made to silently misreport detection health
- **Out of scope**: the `evidence.json` file shipped in the repo (demonstration data, not
  production config); exposure resulting from `--allow-remote`, which is an explicit,
  documented opt-in
- **No third-party dependencies.** `go.mod` has no `require` block and there is no `go.sum`;
  CI fails the build if either appears. Supply-chain surface is the Go standard library and
  the toolchain. (`scripts/sigma-to-rules.py` needs PyYAML, but it is a developer tool that
  never runs as part of the binary.)
