"""Hermetic GnuPG agent Assuan version probe; never contacts a real agent."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-gpg-agent-readonly.py"
spec = importlib.util.spec_from_file_location("gpg_agent_safe_probe", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GpgAgentProbeContracts(unittest.TestCase):
    def test_readonly_getinfo_and_no_autostart(self):
        fake = subprocess.CompletedProcess([], 0, "D 2.4.8\nOK\nOK closing connection\n", "")
        with patch.object(mod.shutil, "which", return_value="/usr/bin/gpg-connect-agent"), \
             patch.object(mod.subprocess, "run", return_value=fake) as run:
            self.assertEqual(mod.probe(), "RESPONDS_GETINFO_ONLY")
        self.assertEqual(run.call_args.args[0], [
            "gpg-connect-agent", "--no-autostart", "GETINFO version", "/bye"
        ])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertFalse(run.call_args.kwargs["check"])

    def test_missing_command_is_not_success(self):
        with patch.object(mod.shutil, "which", return_value=None), \
             patch.object(mod.subprocess, "run") as run:
            self.assertEqual(mod.probe(), "TOOL_MISSING")
        run.assert_not_called()

    def test_gpg_error_and_malformed_reply_unknown(self):
        results = (
            subprocess.CompletedProcess([], 2, "", ""),
            subprocess.CompletedProcess([], 0, "D 2.4.8\nOK\n", "error"),
            subprocess.CompletedProcess([], 0, "D wrong\nOK\n", ""),
            subprocess.CompletedProcess([], 0, "D 2.4.8\nERR 42\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        )
        with patch.object(mod.shutil, "which", return_value="/usr/bin/mock"):
            for result in results:
                with self.subTest(result=result), \
                     patch.object(mod.subprocess, "run", return_value=result):
                    self.assertEqual(mod.probe(), "UNKNOWN")

    def test_timeout_fails_closed(self):
        with patch.object(mod.shutil, "which", return_value="/usr/bin/mock"), \
             patch.object(mod.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                 ["gpg-connect-agent"], 5
             )):
            self.assertEqual(mod.probe(), "UNKNOWN")

    def test_exception_fails_closed(self):
        with patch.object(mod.shutil, "which", return_value="/usr/bin/mock"), \
             patch.object(mod.subprocess, "run", side_effect=OSError("cannot connect")):
            self.assertEqual(mod.probe(), "UNKNOWN")

    def test_main_report_only_public_status_and_stays_no_go(self):
        stdout = io.StringIO()
        with patch.object(mod.sys, "argv", ["read-only"]), \
             patch.object(mod, "probe", return_value="RESPONDS_GETINFO_ONLY"), \
             redirect_stdout(stdout):
            self.assertEqual(mod.main(), 0)
        obj = json.loads(stdout.getvalue())
        self.assertEqual(obj["status"], "NO-GO")
        self.assertFalse(obj["agent_started_by_probe"])
        self.assertFalse(obj["gpg_openpgp_card_verified"])
        self.assertFalse(obj["postgres_restore_verified"])

    def test_main_refuses_args_before_probe(self):
        with patch.object(mod.sys, "argv", ["read-only", "--pin"]), \
             patch.object(mod, "probe") as probe, redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(), 2)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
