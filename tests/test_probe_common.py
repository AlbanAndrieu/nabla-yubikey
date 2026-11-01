"""Hermetic contracts for the helpers shared by the read-only probes."""
from __future__ import annotations

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/workstation"))
import probe_common  # noqa: E402


def done(returncode: int = 0, stdout: str = "ok\n"):
    return SimpleNamespace(returncode=returncode, stdout=stdout)


class RunBoundedContracts(unittest.TestCase):
    def run_with(self, result=None, side_effect=None, **kwargs):
        with patch("shutil.which", return_value="/usr/bin/tool"), \
             patch("subprocess.run", return_value=result, side_effect=side_effect) as run:
            return probe_common.run_bounded(["tool", "info"], **kwargs), run

    def test_success_never_reads_stdin_or_stderr(self):
        value, run = self.run_with(done())
        self.assertEqual(value, "ok\n")
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertFalse(run.call_args.kwargs["check"])

    def test_fails_closed(self):
        self.assertIsNone(self.run_with(done(returncode=1))[0])
        self.assertIsNone(self.run_with(done(stdout="x" * 70000))[0])
        self.assertIsNone(self.run_with(done(stdout="a\x00b"))[0])
        self.assertIsNone(self.run_with(side_effect=subprocess.TimeoutExpired(["tool"], 15))[0])
        with patch("shutil.which", return_value=None), patch("subprocess.run") as run:
            self.assertIsNone(probe_common.run_bounded(["tool"]))
            run.assert_not_called()

    def test_accepted_exit_codes_are_explicit(self):
        self.assertEqual(self.run_with(done(returncode=1, stdout=""), ok_codes=(0, 1))[0], "")


class ParsingContracts(unittest.TestCase):
    def test_otp_requires_both_slots(self):
        self.assertEqual(probe_common.parse_otp("Slot 1: programmed\nSlot 2: empty\n"),
                         {"slot1": True, "slot2": False})
        for raw in (None, "", "Slot 1: programmed\n", "Device busy\n"):
            self.assertIsNone(probe_common.parse_otp(raw))

    def test_role_from_local_last4_mapping_never_returns_serial(self):
        role = probe_common.device_role
        self.assertEqual(role("12345678\n", "5678=principale,1111=secondaire"), "principale")
        self.assertEqual(role("12345678\n", "1111=secondaire"), "UNLABELED")
        self.assertEqual(role("12345678\n87654321\n", "5678=principale"), "UNKNOWN")
        self.assertEqual(role(None, "5678=principale"), "UNKNOWN")
        self.assertEqual(role("12345678\n", "5678=$(rm -rf)"), "UNLABELED")

    def test_verdict(self):
        self.assertEqual(probe_common.verdict({}, [], ["ADVICE"]),
                         {"status": "GO", "blocking": [], "advice": ["ADVICE"]})
        self.assertEqual(probe_common.verdict({}, ["X"], [])["status"], "NO-GO")

    def test_line_count(self):
        self.assertEqual(probe_common.line_count("a\n\nb\n"), 2)
        self.assertIsNone(probe_common.line_count(None))

    def test_main_json_exit_codes(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(probe_common.main_json(lambda: {"b": 1, "a": 2}, []), 0)
        self.assertEqual(out.getvalue(), '{"a": 2, "b": 1}\n')
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(probe_common.main_json(dict, ["--fix"]), 2)


if __name__ == "__main__":
    unittest.main()
