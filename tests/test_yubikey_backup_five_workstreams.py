"""Hermetic contracts for five-track YubiKey backup preparation."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/prepare-yubikey-backup-five.py"
spec = importlib.util.spec_from_file_location("yubi_five", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def safe_output(cmd, name):
    values = {
        "dependencies": {"agent_scdaemon": "NOT_CONFIRMED", "pcscd": "PROCESS_PRESENT_UNVERIFIED",
                         "ssh_agent": "PUBLIC_IDENTITIES_PRESENT_UNVERIFIED"},
        "workstation": {"paths": {"ssh_fido_public_handle": "NOT_FOUND"},
                        "tools": {"age": "INSTALLED_UNVERIFIED", "sops": "INSTALLED_UNVERIFIED",
                                  "keepassxc": "INSTALLED_UNVERIFIED"}},
        "gpg_agent": {"gpg_agent_protocol": "RESPONDS_GETINFO_ONLY"},
        "plan": {}, "hardware": {},
    }
    return {"state": "METADATA_ONLY", "data": values[name]}


class FiveTracks(unittest.TestCase):
    def test_all_five_workstreams_report_no_go(self):
        with patch.object(mod, "capture", side_effect=safe_output), patch.object(
                mod, "inspect_escrow", return_value="NOT_CHECKED"):
            report, code = mod.collect(False)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "NO-GO")
        self.assertEqual(report["completion"], "NOT_VERIFIED")
        self.assertEqual(len(report["tracks"]), 5)
        self.assertFalse(report["hardware_mutation_authorized"])
        self.assertEqual(report["tracks"]["2_openpgp_gpg"]["scdaemon_agent"], "NOT_CONFIRMED")

    def test_host_tasks_concurrent(self):
        barrier = threading.Barrier(4)
        def task(cmd, name):
            barrier.wait(timeout=4)
            return safe_output(cmd, name)
        with patch.object(mod, "capture", side_effect=task) as runner:
            report, code = mod.collect(False)
        self.assertEqual(code, 0)
        self.assertEqual(runner.call_count, 4)
        self.assertEqual(set(report["host_gates"].values()), {"METADATA_ONLY"})

    def test_hardware_is_serial_and_opt_in(self):
        observed = []
        def task(cmd, name):
            observed.append(name)
            return safe_output(cmd, name)
        with patch.object(mod, "capture", side_effect=task):
            report, code = mod.collect(True)
        self.assertEqual(code, 0)
        self.assertEqual(observed[-1], "hardware")
        self.assertEqual(report["tracks"]["1_piv82_age"]["public_slot_inventory"], "METADATA_ONLY")

    def test_host_fail_blocks_hardware(self):
        names = []
        def task(cmd, name):
            names.append(name)
            return {"state": "UNVERIFIED"} if name == "gpg_agent" else safe_output(cmd, name)
        with patch.object(mod, "capture", side_effect=task):
            report, code = mod.collect(True)
        self.assertEqual(code, 3)
        self.assertNotIn("hardware", names)
        self.assertEqual(report["tracks"]["1_piv82_age"]["public_slot_inventory"], "NOT_CHECKED")

    def test_escrow_invalid_blocks_when_explicit_paths_supplied(self):
        with patch.object(mod, "capture", side_effect=safe_output), patch.object(
                mod, "inspect_escrow", return_value="INVALID_INPUT"):
            report, code = mod.collect(False, Path("/tmp/a.age"), Path("/tmp/b.age"))
        self.assertEqual(code, 3)
        self.assertEqual(report["status"], "NO-GO")

    def test_subprocess_errors_not_exposed(self):
        private = "/very/private/path/secret"
        result = subprocess.CompletedProcess([], 1, private, private)
        with patch.object(mod.subprocess, "run", return_value=result):
            self.assertEqual(mod.capture(("fake",), "workstation"), {"state": "UNVERIFIED"})
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps({"status": "GO"}), "")):
            self.assertEqual(mod.capture(("fake",), "workstation"), {"state": "UNVERIFIED"})

    def test_reject_single_escrow_before_any_jobs(self):
        with patch.object(mod, "collect") as collect, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                mod.main(["--escrow-a", "/tmp/a.age"])
        self.assertEqual(raised.exception.code, 2)
        collect.assert_not_called()

    def test_unknown_args_disallowed_before_probes(self):
        for args in (["--pin", "123456"], ["--piv82-generate"], ["--reset"], ["--otp2"]):
            with self.subTest(args=args), patch.object(mod, "collect") as collect, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    mod.main(args)
                self.assertEqual(raised.exception.code, 2)
                collect.assert_not_called()

    def test_output_marks_not_configured(self):
        with patch.object(mod, "collect", return_value=({"status": "NO-GO"}, 0)):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(mod.main([]), 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "NO-GO")

    def test_command_allowlist_no_writes(self):
        self.assertEqual(mod.BACKUP, "11110002")
        for cmd in mod.HOST_COMMANDS.values():
            self.assertTrue(cmd[1].endswith("-readonly.py"))
        self.assertEqual(mod.HARDWARE_COMMAND[1].split("/")[-1], "inspect-age-yubikey-piv82-secondary.py")
        self.assertEqual(mod.PIV82_PLAN[-2:], ("11110002", "--json"))


if __name__ == "__main__":
    unittest.main()
