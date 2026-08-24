#!/usr/bin/env python3
"""Derive a detection-decay rules file from Sigma rules.

detection-decay needs to know, per rule, which index field a detection depends
on. That was hand-declared, one --field argument at a time, which is why the
tool was calibrated for exactly one rule. Sigma already states the answer: every
key in a rule's detection block is a field the rule cannot fire without.

Sigma is YAML and the decay binary is stdlib-only, so the conversion happens
here and the binary reads JSON. This script is the only place PyYAML is needed.

  ./scripts/sigma-to-rules.py --map scripts/fieldmap-wazuh.json \
      --out rules.json path/to/sigma/rules/

Field names are Sigma's, not your index's. The map file translates them; a
logsource may supply a `template` (a naming convention) and/or explicit `fields`
entries, which win over the template. Anything that resolves to neither is
reported as unmapped rather than guessed at — a fabricated field name would
measure 0% populate forever and read as permanent field drift.
"""

import argparse
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.exit("error: PyYAML is required — pip install pyyaml")

# Sigma value modifiers, stripped from "Image|endswith" to recover "Image".
SKIP_KEYS = {"condition", "timeframe"}


def lcfirst(s):
    return s[:1].lower() + s[1:] if s else s


def field_names(node, out):
    """Collect field names from a Sigma detection selection.

    Handles the three shapes Sigma allows: a map of field->value, a list of maps
    (OR'd selections), and a bare list of keywords (full-text search, which
    names no field at all).
    """
    if isinstance(node, dict):
        for key, value in node.items():
            name = key.split("|", 1)[0].strip()
            if name:
                out.add(name)
            # `field: {nested: ...}` is rare but legal.
            if isinstance(value, (dict, list)):
                field_names(value, out)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                field_names(item, out)
    return out


def techniques(tags):
    """Extract ATT&CK technique ids from Sigma tags."""
    out = []
    for tag in tags or []:
        t = str(tag).lower()
        if t.startswith("attack.t"):
            out.append(t[len("attack."):])
    return sorted(set(out))


def resolve(sigma_fields, logsource_map):
    """Translate Sigma field names to index field names."""
    explicit = logsource_map.get("fields", {}) if logsource_map else {}
    template = logsource_map.get("template") if logsource_map else None

    mapped, unmapped = {}, []
    for name in sorted(sigma_fields):
        if name in explicit:
            mapped[name] = explicit[name]
        elif template:
            mapped[name] = template.format(field=name, lcfirst=lcfirst(name))
        else:
            unmapped.append(name)
    return mapped, unmapped


def convert(path, fieldmap):
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise ValueError("not a Sigma rule document")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("missing or malformed 'detection' block")

    fields = set()
    for key, node in detection.items():
        if key in SKIP_KEYS:
            continue
        field_names(node, fields)

    logsource = doc.get("logsource") or {}
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    key = f"{product}/{category}"

    mapped, unmapped = resolve(fields, fieldmap.get("logsources", {}).get(key))
    ls_map = fieldmap.get("logsources", {}).get(key) or {}

    return {
        "rule": os.path.basename(path),
        "path": path,
        "title": doc.get("title", ""),
        "id": doc.get("id", ""),
        "level": doc.get("level", ""),
        "product": product,
        "category": category,
        "techniques": techniques(doc.get("tags")),
        "filter": ls_map.get("filter", ""),
        # Sigma's own names, kept so a mapping can be audited against the source.
        "sigma_fields": sorted(fields),
        # What to actually measure. A rule cannot fire if any of these go null.
        "fields": [mapped[k] for k in sorted(mapped)],
        "unmapped_fields": unmapped,
    }


def collect(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.endswith((".yml", ".yaml")):
                        yield os.path.join(root, n)
        else:
            yield p


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Sigma rule files or directories")
    ap.add_argument("--map", dest="mapfile", help="field-map JSON (see scripts/fieldmap-wazuh.json)")
    ap.add_argument("--out", default="-", help="output path, or - for stdout")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if any rule has an unmapped field")
    args = ap.parse_args()

    fieldmap = {}
    if args.mapfile:
        with open(args.mapfile) as fh:
            fieldmap = json.load(fh)

    rules, failed = [], 0
    for path in collect(args.paths):
        try:
            rules.append(convert(path, fieldmap))
        except Exception as exc:  # a bad rule must not silently vanish
            print(f"warning: skipping {path}: {exc}", file=sys.stderr)
            failed += 1

    rules.sort(key=lambda r: r["rule"])
    doc = {
        "generated_by": "scripts/sigma-to-rules.py",
        "field_map": fieldmap.get("name", ""),
        "rules": rules,
    }

    out = json.dumps(doc, indent=2) + "\n"
    if args.out == "-":
        sys.stdout.write(out)
    else:
        with open(args.out, "w") as fh:
            fh.write(out)
        print(f"wrote {len(rules)} rule(s) to {args.out}", file=sys.stderr)

    # Unmapped fields are reported loudly. Measuring a field name that does not
    # exist in the index reads as 100% field drift, forever.
    unmapped = {f for r in rules for f in r["unmapped_fields"]}
    if unmapped:
        print(f"warning: {len(unmapped)} Sigma field(s) have no mapping and will not be "
              f"measured: {', '.join(sorted(unmapped))}", file=sys.stderr)
        print("         add them to the field map's 'fields' table, or set a 'template'.",
              file=sys.stderr)

    if failed:
        return 1
    if args.strict and unmapped:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
