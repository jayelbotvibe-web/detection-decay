# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| v0.3.x  | ✅ |
| v0.2.x  | ❌ |

This is an MVP. The tool reads static JSON evidence files — no network listeners, no credential handling, no persistence.

## Reporting a vulnerability

Report security issues via [GitHub issues](https://github.com/jayelbotvibe-web/detection-decay/issues) or DM [@junielkatarn](https://x.com/junielkatarn). Response within 48 hours.

## Scope

- **In scope**: input validation, scoring logic errors, Go dependency vulnerabilities
- **Out of scope**: the evidence.json file shipped in the repo (demonstration data, not production config)
