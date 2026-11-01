"""Synthetic fixture comparison contracts; no hardware, subprocess or network."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/ops/compare-probe-fixtures.py"
spec = importlib.util.spec_from_file_location("compare_probe_fixtures", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def report():
    result = {
        key: False if key in probe.BOOLEAN_FIELDS else "PROCESS_NOT_OBSERVED"
        for key in probe.ALLOWED_FIELDS - {"recovery_tools"}
    }
    result.update(status="NO-GO", mode="HOST_DEPENDENCIES_METADATA_ONLY",
                  recovery_tools={name: "MISSING" for name in probe.ALLOWED_TOOLS})
    return result


def case(name="baseline", code=0, data=None):
    return {"name": name, "exit_code": code,
            "report": (report() if data is None and code == 0 else data)}


def fixture(cases):
    return {"schema": "nabla-yubikey/probe-fixtures/v1", "cases": cases}


class FixtureParityContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.compose = self.root / "compose.json"
        self.yubikey = self.root / "yubikey.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, old, new):
        self.compose.write_text(json.dumps(fixture(old)))
        self.yubikey.write_text(json.dumps(fixture(new)))

    def test_same_synthetic_reports_are_not_real_runtime_parity(self):
        self.write([case(), case("bad_args", 2)], [case(), case("bad_args", 2)])
        with patch("subprocess.run") as runner:
            result = probe.compare(self.compose, self.yubikey)
        runner.assert_not_called()
        self.assertEqual(result["status"], "FIXTURES_MATCH")
        self.assertTrue(result["fixture_parity_verified"])
        self.assertFalse(result["runtime_parity_verified"])
        self.assertFalse(result["hardware_mutation_authorized"])
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_only_field_paths_are_reported_not_values(self):
        before, after = report(), report()
        before["recovery_tools"]["gpg"] = "INSTALLED_UNVERIFIED"
        after["ssh_agent"] = "SOCKET_UNTRUSTED"
        self.write([case(data=before)], [case(data=after)])
        out = io.StringIO()
        with redirect_stdout(out):
            code = probe.main([
                "--compose-fixtures", str(self.compose),
                "--yubikey-fixtures", str(self.yubikey),
                "--assert-fixture-parity",
            ])
        self.assertEqual(code, 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "NO-GO")
        self.assertEqual(result["differing_cases"]["baseline"],
                         ["ssh_agent", "recovery_tools.gpg"])
        self.assertNotIn("SOCKET_UNTRUSTED", out.getvalue())
        self.assertNotIn("INSTALLED_UNVERIFIED", out.getvalue())

    def test_bad_args_and_case_set_changes_are_detected(self):
        self.write([case(), case("bad_args", 2)],
                   [case(), case("another_case", 2)])
        result = probe.compare(self.compose, self.yubikey)
        self.assertEqual(result["missing_cases"], ["bad_args"])
        self.assertEqual(result["extra_cases"], ["another_case"])
        self.assertEqual(result["status"], "NO-GO")

    def test_duplicate_and_unexpected_keys_are_rejected(self):
        for text in (
            '{"schema":"nabla-yubikey/probe-fixtures/v1","cases":[],"cases":[]}',
            json.dumps(fixture([{"name": "baseline", "exit_code": True,
                                 "report": report()}])),
            json.dumps(fixture([case("bad/path")])),
            json.dumps(fixture([case(data={**report(), "private_path": "secret"})])),
            json.dumps(fixture([case("baseline", 2, report())])),
        ):
            self.compose.write_text(text)
            self.yubikey.write_text(json.dumps(fixture([case()])))
            result = probe.compare(self.compose, self.yubikey)
            self.assertEqual(result["status"], "NO-GO")
            self.assertEqual(result["blocking"], ["FIXTURES_INVALID_OR_UNAVAILABLE"])

    def test_symlinked_and_missing_fixtures_fail_closed(self):
        self.write([case()], [case()])
        self.yubikey.unlink()
        self.yubikey.symlink_to(self.compose)
        self.assertEqual(probe.compare(self.compose, self.yubikey)["status"], "NO-GO")
        self.yubikey.unlink()
        self.assertEqual(probe.compare(self.compose, self.yubikey)["status"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
