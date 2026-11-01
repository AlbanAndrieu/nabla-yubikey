"""Hermetic contracts for aggregated read-only YubiKey diagnostics."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/diagnose-yubikey-readonly-batch.py"
spec = importlib.util.spec_from_file_location("nabla_yubikey_readonly_batch", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BatchContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = Path(self.temp.name)
        self.host_report = {
            "status": "NO-GO",
            "paths": {
                "gpg_agent_socket": "PRESENT_UNVERIFIED",
                "sops_age_identity": "PRESENT_PRIVATE_METADATA_ONLY",
                "ssh_fido_public_handle": "NOT_FOUND",
                "pam_u2f_mapping": "PRESENT_UNVERIFIED",
            },
            "tools": {"pamu2fcfg": "MISSING"},
        }
        self.applet = {
            "status": "NO-GO",
            "serial": "11110002",
            "reason": "PUBLIC_INVENTORY_ONLY_CONFIG_NOT_VERIFIED",
        }
        self.calls = []
        self.modules = {
            "inspect-yubikey-workstation-readonly.py":
                SimpleNamespace(snapshot=lambda *_: dict(self.host_report)),
            "inspect-yubikey-applications-readonly.py":
                SimpleNamespace(snapshot=self.applet_snapshot),
            "inspect-yubikey-recovery-readonly.py":
                SimpleNamespace(otp2_inventory=self.otp_snapshot,
                                escrow_inventory=self.escrow_snapshot),
        }
        self.otp_result = "PROGRAMMED_TYPE_UNVERIFIED"
        self.escrow_result = "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED"
        self.modules["inspect-gpg-agent-readonly.py"] = SimpleNamespace(
            probe=lambda: "RESPONDS_GETINFO_ONLY"
        )

    def applet_snapshot(self, serial):
        self.calls.append(("applet", serial))
        return {**self.applet, "serial": serial}, 0

    def otp_snapshot(self):
        self.calls.append(("otp",))
        return self.otp_result

    def escrow_snapshot(self, a, b):
        self.calls.append(("escrow", str(a), str(b)))
        return self.escrow_result

    def run_cli(self, argv):
        output = io.StringIO()
        def get_mod(name):
            self.calls.append(("load", name))
            return self.modules[name]
        with patch.object(module, "load", side_effect=get_mod), \
             patch.dict(os.environ, {"HOME": str(self.host)}), \
             redirect_stdout(output):
            code = module.main(argv)
        return code, json.loads(output.getvalue())

    def test_host_only_has_no_hardware_access(self):
        code, report = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertEqual(len([x for x in self.calls if x[0] == "load"]), 1)
        self.assertEqual(report["device"]["state"], "NOT_CHECKED")
        self.assertEqual(report["otp2"], "NOT_CHECKED")
        self.assertEqual(report["escrow"], "NOT_CHECKED")
        self.assertEqual(report["status"], "NO-GO")

    def test_explicit_secondary_public_snapshot_only(self):
        code, report = self.run_cli(["--hardware", "--serial", "11110002"])
        self.assertEqual(code, 0)
        self.assertIn(("applet", "11110002"), self.calls)
        self.assertNotIn(("otp",), self.calls)
        self.assertEqual(report["device"]["reason"], "PUBLIC_INVENTORY_ONLY_CONFIG_NOT_VERIFIED")
        self.assertFalse(report["hardware_mutation_authorized"])

    def test_primary_snapshot_cannot_trigger_secondary_otp(self):
        code, _ = self.run_cli(["--hardware", "--serial", "11110001"])
        self.assertEqual(code, 0)
        self.assertEqual([x for x in self.calls if x[0] == "applet"],
                         [("applet", "11110001")])
        self.assertNotIn(("otp",), self.calls)

    def test_secondary_otp_opt_in_does_not_prove_keepassxc(self):
        code, report = self.run_cli(["--hardware", "--serial", "11110002",
                                     "--otp2-secondary"])
        self.assertEqual(code, 0)
        self.assertIn(("otp",), self.calls)
        self.assertEqual(report["otp2"], "PROGRAMMED_TYPE_UNVERIFIED")
        self.assertEqual(report["completion"]["keepassxc_challenge"], "NOT_VERIFIED")

    def test_empty_otp_fails_closed(self):
        self.otp_result = "EMPTY"
        code, report = self.run_cli(["--hardware", "--serial", "11110002",
                                     "--otp2-secondary"])
        self.assertEqual(code, 3)
        self.assertIn("OTP2_PRESENCE_NOT_CONFIRMED", report["blockers"])

    def test_escrow_explicit_paths_only_and_not_restoration_proof(self):
        code, report = self.run_cli(["--escrow-a", "/mnt/a.age",
                                     "--escrow-b", "/mnt/b.age"])
        self.assertEqual(code, 0)
        self.assertIn(("escrow", "/mnt/a.age", "/mnt/b.age"), self.calls)
        self.assertNotIn(("otp",), self.calls)
        self.assertEqual(report["completion"]["age_sops_restore"], "NOT_VERIFIED")
        self.assertNotIn("/mnt/a.age", json.dumps(report))

    def test_same_filesystem_refuses_escrow_evidence(self):
        self.escrow_result = "SAME_FILESYSTEM"
        code, report = self.run_cli(["--escrow-a", "/mnt/a.age",
                                     "--escrow-b", "/mnt/b.age"])
        self.assertEqual(code, 3)
        self.assertIn("ESCROW_METADATA_INCOMPLETE", report["blockers"])

    def test_device_inventory_failure_blocks(self):
        def fail(_serial):
            raise OSError("reader problem")
        self.modules["inspect-yubikey-applications-readonly.py"] = SimpleNamespace(snapshot=fail)
        code, report = self.run_cli(["--hardware", "--serial", "11110002"])
        self.assertEqual(code, 3)
        self.assertIn("DEVICE_INSPECTION_ERROR", report["blockers"])
        self.assertEqual(report["status"], "NO-GO")

    def test_gpg_agent_probe_requires_explicit_flag(self):
        code, report = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertEqual(report["gpg_agent"], "NOT_CHECKED")
        self.assertFalse(any(x == ("load", "inspect-gpg-agent-readonly.py")
                             for x in self.calls))

    def test_gpg_agent_getinfo_does_not_prove_openpgp(self):
        code, report = self.run_cli(["--gpg-agent-probe"])
        self.assertEqual(code, 0)
        self.assertEqual(report["gpg_agent"], "RESPONDS_GETINFO_ONLY")
        self.assertEqual(report["completion"]["openpgp_sign_decrypt"], "NOT_VERIFIED")

    def test_gpg_agent_unreachable_blocks(self):
        self.modules["inspect-gpg-agent-readonly.py"] = SimpleNamespace(
            probe=lambda: "UNKNOWN"
        )
        code, report = self.run_cli(["--gpg-agent-probe"])
        self.assertEqual(code, 3)
        self.assertIn("GPG_AGENT_GETINFO_UNAVAILABLE", report["blockers"])

    def test_device_report_with_wrong_serial_is_refused(self):
        self.modules["inspect-yubikey-applications-readonly.py"] = (
            SimpleNamespace(snapshot=lambda _serial: (
                {"serial": "11110001", "status": "NO-GO"}, 0
            ))
        )
        code, report = self.run_cli(["--hardware", "--serial", "11110002"])
        self.assertEqual(code, 3)
        self.assertIn("PUBLIC_APPLET_INVENTORY_INCOMPLETE", report["blockers"])

    def test_missing_gpg_socket_is_accurately_reported(self):
        self.host_report["paths"]["gpg_agent_socket"] = "NOT_FOUND"
        _, report = self.run_cli([])
        self.assertIn("GPG_SOCKET_NOT_CONFIRMED", report["blockers"])
        self.assertEqual(report["completion"]["openpgp_sign_decrypt"], "NOT_VERIFIED")

    def test_cli_rejects_serial_without_hardware_before_any_probe(self):
        with patch.object(module, "load") as load, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                module.main(["--serial", "11110002"])
        self.assertEqual(caught.exception.code, 2)
        load.assert_not_called()

    def test_cli_rejects_secondary_otp_on_primary(self):
        with patch.object(module, "load") as load, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                module.main(["--hardware", "--serial", "11110001",
                             "--otp2-secondary"])
        self.assertEqual(caught.exception.code, 2)
        load.assert_not_called()

    def test_cli_rejects_incomplete_escrow(self):
        with patch.object(module, "load") as load, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                module.main(["--escrow-a", "/mnt/a.age"])
        self.assertEqual(caught.exception.code, 2)
        load.assert_not_called()

    def test_cli_rejects_relative_escrow(self):
        with patch.object(module, "load") as load, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                module.main(["--escrow-a", "a.age", "--escrow-b", "/mnt/b.age"])
        self.assertEqual(caught.exception.code, 2)
        load.assert_not_called()

    def test_missing_home_is_no_go_and_blocks(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"HOME": ""}), \
             patch.object(module, "load", return_value=self.modules[
                 "inspect-yubikey-workstation-readonly.py"]), redirect_stdout(out):
            code = module.main([])
        report = json.loads(out.getvalue())
        self.assertEqual(code, 3)
        self.assertIn("HOST_METADATA_UNAVAILABLE", report["blockers"])

    def test_bad_ssh_conventional_path_does_not_imply_no_ssh_keys(self):
        _, report = self.run_cli([])
        self.assertIn("CONVENTIONAL_SSH_FIDO_PUBLIC_HANDLE_NOT_FOUND",
                      report["blockers"])
        self.assertEqual(report["completion"]["ssh_fido_login"], "NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
