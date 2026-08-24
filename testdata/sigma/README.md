# Sigma fixtures

Real Sigma rules used to exercise `scripts/sigma-to-rules.py` in CI, so the
converter is tested against rules written by someone other than the converter's
author.

Copied from [purple-loop](https://github.com/jayelbotvibe-web/purple-loop)
(`detections/`). They are checked in rather than fetched so CI does not depend on
a sibling repository being present.

`proc_creation_susp_shell.yml` is a Linux rule, kept deliberately: the shipped
Wazuh field map has no Linux mapping, so it exercises the unmapped-field path.
