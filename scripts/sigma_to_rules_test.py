#!/usr/bin/env python3
"""Tests for sigma-to-rules.py. Run: python3 scripts/sigma_to_rules_test.py"""

import importlib.util
import json
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("s2r", os.path.join(_HERE, "sigma-to-rules.py"))
s2r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s2r)


def fields(node):
    return sorted(s2r.field_names(node, set()))


class TestFieldExtraction(unittest.TestCase):
    def test_strips_modifiers(self):
        # "Image|endswith" names the field Image; the modifier is matching
        # semantics, which decay does not evaluate.
        self.assertEqual(fields({"Image|endswith": ["/id"]}), ["Image"])
        self.assertEqual(fields({"CommandLine|contains|all": ["a"]}), ["CommandLine"])

    def test_plain_dict(self):
        self.assertEqual(fields({"Image": "/bin/sh", "User": "root"}), ["Image", "User"])

    def test_list_of_dicts(self):
        # OR'd selections are a list of maps; every branch names fields the rule
        # depends on.
        self.assertEqual(
            fields([{"Image|endswith": "/id"}, {"ParentImage|endswith": "/sh"}]),
            ["Image", "ParentImage"],
        )

    def test_keyword_list_names_no_fields(self):
        # A full-text keyword selection has no field to measure. Returning a
        # bogus field here would produce a rule decay can never score.
        self.assertEqual(fields(["suspicious", "strings"]), [])

    def test_nested(self):
        self.assertEqual(fields({"outer": {"Inner|re": ".*"}}), ["Inner", "outer"])

    def test_empty(self):
        self.assertEqual(fields({}), [])
        self.assertEqual(fields([]), [])


class TestTechniques(unittest.TestCase):
    def test_extracts_and_normalises(self):
        self.assertEqual(
            s2r.techniques(["attack.execution", "attack.T1059.004", "attack.t1082"]),
            ["t1059.004", "t1082"],
        )

    def test_ignores_tactics_and_junk(self):
        self.assertEqual(s2r.techniques(["attack.discovery", "cve.2021.44228"]), [])
        self.assertEqual(s2r.techniques(None), [])


class TestResolve(unittest.TestCase):
    def test_template_applies_convention(self):
        mapped, unmapped = s2r.resolve(
            {"Image", "CommandLine"},
            {"template": "data.win.eventdata.{lcfirst}"},
        )
        self.assertEqual(mapped["Image"], "data.win.eventdata.image")
        self.assertEqual(mapped["CommandLine"], "data.win.eventdata.commandLine")
        self.assertEqual(unmapped, [])

    def test_explicit_overrides_template(self):
        mapped, _ = s2r.resolve(
            {"Image"},
            {"template": "data.win.eventdata.{lcfirst}", "fields": {"Image": "process.executable"}},
        )
        self.assertEqual(mapped["Image"], "process.executable")

    def test_unmapped_is_reported_not_guessed(self):
        # A fabricated field name measures 0% populate forever and reads as
        # permanent, confident field drift. Reporting it is the honest answer.
        mapped, unmapped = s2r.resolve({"Image", "ParentImage"}, {"fields": {}})
        self.assertEqual(mapped, {})
        self.assertEqual(unmapped, ["Image", "ParentImage"])

    def test_no_logsource_entry(self):
        _, unmapped = s2r.resolve({"Image"}, None)
        self.assertEqual(unmapped, ["Image"])


class TestConvert(unittest.TestCase):
    def write(self, text):
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
        fh.write(text)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    FIELDMAP = {
        "name": "test",
        "logsources": {
            "windows/process_creation": {
                "filter": "data.win.system.eventID:1",
                "template": "data.win.eventdata.{lcfirst}",
            }
        },
    }

    def test_full_rule(self):
        path = self.write(
            "title: Test Rule\n"
            "id: abc-123\n"
            "level: high\n"
            "logsource:\n  product: windows\n  category: process_creation\n"
            "detection:\n"
            "  selection:\n    Image|endswith:\n      - '\\\\net.exe'\n"
            "  parent:\n    ParentImage|endswith: '\\\\cmd.exe'\n"
            "  condition: selection and parent\n"
            "  timeframe: 5m\n"
            "tags:\n  - attack.execution\n  - attack.t1059\n"
        )
        r = s2r.convert(path, self.FIELDMAP)

        self.assertEqual(r["title"], "Test Rule")
        self.assertEqual(r["id"], "abc-123")
        self.assertEqual(r["level"], "high")
        self.assertEqual(r["techniques"], ["t1059"])
        self.assertEqual(r["filter"], "data.win.system.eventID:1")
        # condition and timeframe are directives, not fields.
        self.assertEqual(r["sigma_fields"], ["Image", "ParentImage"])
        self.assertEqual(
            r["fields"],
            ["data.win.eventdata.image", "data.win.eventdata.parentImage"],
        )
        self.assertEqual(r["unmapped_fields"], [])

    def test_missing_detection_block_raises(self):
        # A malformed rule must fail loudly, not silently produce a rule with no
        # fields — that would score as healthy forever.
        path = self.write("title: No Detection\nlogsource:\n  product: windows\n")
        with self.assertRaises(ValueError):
            s2r.convert(path, self.FIELDMAP)

    def test_unknown_logsource_reports_unmapped(self):
        path = self.write(
            "title: Linux\n"
            "logsource:\n  product: linux\n  category: process_creation\n"
            "detection:\n  selection:\n    Image|endswith: '/id'\n  condition: selection\n"
        )
        r = s2r.convert(path, self.FIELDMAP)
        self.assertEqual(r["fields"], [])
        self.assertEqual(r["unmapped_fields"], ["Image"])


class TestRealSigmaRules(unittest.TestCase):
    """The shipped field map must resolve this repo's own documented field."""

    def test_wazuh_map_matches_evidence_json(self):
        root = os.path.dirname(_HERE)
        with open(os.path.join(root, "scripts", "fieldmap-wazuh.json")) as fh:
            fieldmap = json.load(fh)

        mapped, unmapped = s2r.resolve({"Image"}, fieldmap["logsources"]["windows/process_creation"])
        self.assertEqual(unmapped, [])
        # This exact string is what evidence.json and the README document.
        self.assertEqual(mapped["Image"], "data.win.eventdata.image")

        with open(os.path.join(root, "evidence.json")) as fh:
            evidence = json.load(fh)
        self.assertIn(mapped["Image"], {row.get("field") for row in evidence})


if __name__ == "__main__":
    unittest.main(verbosity=2)
