"""Hermetic workstation metadata diagnostics: never open any secret file."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-yubikey-workstation-readonly.py"
spec = importlib.util.spec_from_file_location("nabla_yubikey_workstation", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class WorkstationReadOnlyContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.uid = os.getuid()

    def test_absent_paths_do_not_pretend_configuration(self):
        with patch.object(mod.shutil, "which", return_value=None):
            report = mod.snapshot(self.home, self.uid)
        self.assertEqual(report["status"], "NO-GO")
        self.assertTrue(all(x == "MISSING" for x in report["tools"].values()))
        self.assertEqual(report["paths"]["gpg_agent_socket"], "UNKNOWN")
        self.assertEqual(report["gpg_agent_socket_locator"], "GPGCONF_MISSING")
        self.assertTrue(all(x == "NOT_FOUND" for k, x in report["paths"].items()
                            if k != "gpg_agent_socket"))
        self.assertFalse(report["postgres_restore_verified"])
        self.assertFalse(report["hardware_mutation_authorized"])

    def test_installed_tool_is_not_proof_of_usage(self):
        with patch.object(mod.shutil, "which", return_value="/usr/bin/mock"), \
             patch.object(mod, "gpg_agent_socket_status",
                          return_value=("NOT_FOUND", "GPGCONF")):
            report = mod.snapshot(self.home, self.uid)
        self.assertEqual(report["tools"]["age-plugin-yubikey"], "INSTALLED_UNVERIFIED")
        self.assertFalse(report["age_decrypt_verified"])

    def test_gpgconf_resolves_runtime_socket_without_starting_agent(self):
        with tempfile.TemporaryDirectory() as runtime:
            sock_path = Path(runtime) / "S.gpg-agent"
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(str(sock_path))
                result = subprocess.CompletedProcess(
                    [], 0, str(sock_path) + "\n", ""
                )
                with patch.object(mod.shutil, "which", return_value="/usr/bin/gpgconf"), \
                     patch.object(mod.subprocess, "run", return_value=result) as runner:
                    state, source = mod.gpg_agent_socket_status()
                self.assertEqual((state, source), ("PRESENT_UNVERIFIED", "GPGCONF"))
                args = runner.call_args
                self.assertEqual(args.args[0],
                                 ["gpgconf", "--list-dirs", "agent-socket"])
                self.assertEqual(args.kwargs["stdin"], subprocess.DEVNULL)
                self.assertFalse(args.kwargs["check"])
                self.assertTrue(args.kwargs["capture_output"])
                self.assertEqual(args.kwargs["timeout"], 5)

    def test_gpgconf_missing_socket_does_not_claim_agent_healthy(self):
        path = self.home / "missing" / "S.gpg-agent"
        with patch.object(mod.shutil, "which", return_value="/usr/bin/gpgconf"), \
             patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 0, str(path) + "\n", "")):
            self.assertEqual(mod.gpg_agent_socket_status(), ("NOT_FOUND", "GPGCONF"))

    def test_gpgconf_errors_and_malformed_paths_are_unknown(self):
        scenarios = (
            subprocess.CompletedProcess([], 1, "/run/user/1000/gnupg/S.gpg-agent\n", ""),
            subprocess.CompletedProcess([], 0, "/run/user/1000/gnupg/S.gpg-agent\n", "error"),
            subprocess.CompletedProcess([], 0, "relative/socket\n", ""),
            subprocess.CompletedProcess([], 0, "/one\n/two\n", ""),
            subprocess.CompletedProcess([], 0, "\n", ""),
        )
        with patch.object(mod.shutil, "which", return_value="/usr/bin/gpgconf"):
            for scenario in scenarios:
                with self.subTest(output=scenario.stdout, rc=scenario.returncode), \
                     patch.object(mod.subprocess, "run", return_value=scenario):
                    state, source = mod.gpg_agent_socket_status()
                    self.assertEqual(state, "UNKNOWN")
                    self.assertIn(source, ("GPGCONF_ERROR", "GPGCONF_INVALID_PATH"))

    def test_gpgconf_timeout_does_not_start_agent_or_report_success(self):
        with patch.object(mod.shutil, "which", return_value="/usr/bin/gpgconf"), \
             patch.object(mod.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(["gpgconf"], 5)):
            self.assertEqual(mod.gpg_agent_socket_status(),
                             ("UNKNOWN", "GPGCONF_ERROR"))

    def test_gpg_agent_socket_symlink_refused(self):
        with tempfile.TemporaryDirectory() as runtime:
            target = Path(runtime) / "S.gpg-agent"
            link = Path(runtime) / "link"
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(str(target))
                link.symlink_to(target)
                with patch.object(mod.shutil, "which", return_value="/usr/bin/gpgconf"), \
                     patch.object(mod.subprocess, "run",
                                  return_value=subprocess.CompletedProcess(
                                      [], 0, str(link) + "\n", "")):
                    self.assertEqual(
                        mod.gpg_agent_socket_status(), ("SYMLINK_REFUSED", "GPGCONF")
                    )

    def test_sops_identity_is_metadata_only(self):
        path = self.home / ".config/sops/age/keys.txt"
        path.parent.mkdir(parents=True)
        path.write_text("SECRET-NOT-TO-BE-READ")
        path.chmod(0o600)
        self.assertEqual(mod.metadata(path, "identity", self.uid), "PRESENT_PRIVATE_METADATA_ONLY")
        path.chmod(0o644)
        self.assertEqual(mod.metadata(path, "identity", self.uid), "UNEXPECTED_METADATA")

    def test_symlink_is_refused(self):
        key = self.home / "keys.txt"
        key.write_text("fake")
        link = self.home / "other.age"
        link.symlink_to(key)
        self.assertEqual(mod.metadata(link, "identity", self.uid), "SYMLINK_REFUSED")

    def test_socket_is_only_presence_proof(self):
        path = self.home / "agent.sock"
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(path))
            self.assertEqual(mod.metadata(path, "socket", self.uid), "PRESENT_UNVERIFIED")

    def test_public_handle_does_not_prove_ssh_login(self):
        path = self.home / "id_ed25519_sk.pub"
        path.write_text("public fixture")
        self.assertEqual(mod.metadata(path, "public", self.uid), "PRESENT_UNVERIFIED")

    def test_malformed_cli_does_not_scan(self):
        with patch.object(mod.sys, "argv", ["script", "--scan-secrets"]), \
             patch.object(mod, "snapshot") as read:
            self.assertEqual(mod.main(), 2)
        read.assert_not_called()

    def test_missing_home_fails_closed(self):
        with patch.object(mod.sys, "argv", ["script"]), \
             patch.dict(os.environ, {"HOME": "/unlikely_missing_nabla_yubikey_fixture_path"}), \
             patch("builtins.print") as output:
            self.assertEqual(mod.main(), 3)
        self.assertIn("HOME_UNAVAILABLE", output.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
