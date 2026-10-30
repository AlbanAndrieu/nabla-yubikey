"""Hermetic contracts: metadata-only GPG/PCSC/SSH/recovery dependencies."""
from __future__ import annotations

import importlib.util
import io
import json
import stat
import subprocess
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-yubikey-dependencies-readonly.py"
spec = importlib.util.spec_from_file_location("yubi_dependencies_readonly", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DependencyContracts(unittest.TestCase):
    def test_process_presence_is_not_card_proof(self):
        with patch.object(module.shutil, "which", return_value="/usr/bin/pgrep"), \
             patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(module.process_state("scdaemon", uid=1000), "PROCESS_PRESENT_UNVERIFIED")
        self.assertEqual(run.call_args.args[0], ["pgrep", "-x", "-u", "1000", "scdaemon"])
        for name in ("stdin", "stdout", "stderr"):
            self.assertEqual(run.call_args.kwargs[name], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 4)
        self.assertFalse(run.call_args.kwargs["check"])

    def test_process_not_observed_and_unrecognized_error(self):
        with patch.object(module.shutil, "which", return_value="/usr/bin/pgrep"):
            for rc, expected in [(1, "PROCESS_NOT_OBSERVED"), (2, "UNKNOWN")]:
                with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=rc)):
                    self.assertEqual(module.process_state("pcscd"), expected)

    def test_process_timeout_and_absent_tool_fail_closed(self):
        with patch.object(module.shutil, "which", return_value=None), \
             patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.process_state("scdaemon"), "TOOL_MISSING")
            run.assert_not_called()
        with patch.object(module.shutil, "which", return_value="pgrep"), \
             patch.object(module.subprocess, "run", side_effect=subprocess.TimeoutExpired(["pgrep"], 4)):
            self.assertEqual(module.process_state("pcscd"), "UNKNOWN")

    def test_process_unknown_name_is_never_queried(self):
        with patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.process_state("gpg-agent --kill"), "UNKNOWN")
            run.assert_not_called()

    def test_absent_ssh_socket_never_contacts_agent(self):
        with patch.dict(module.os.environ, {}, clear=True), patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.ssh_agent_state(), "SOCKET_NOT_CONFIGURED")
            run.assert_not_called()

    def test_ssh_socket_invalid_path_and_symlink_block(self):
        with patch.dict(module.os.environ, {"SSH_AUTH_SOCK": "relative"}), \
             patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.ssh_agent_state(), "UNKNOWN")
            run.assert_not_called()
        with patch.dict(module.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
             patch.object(module.Path, "lstat", return_value=SimpleNamespace(
                 st_mode=stat.S_IFLNK | 0o777, st_uid=module.os.getuid())), \
             patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.ssh_agent_state(), "SOCKET_UNTRUSTED")
            run.assert_not_called()

    def test_ssh_agent_public_only_and_masked(self):
        with patch.dict(module.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
             patch.object(module.Path, "lstat", return_value=SimpleNamespace(
                 st_mode=stat.S_IFSOCK | 0o600, st_uid=module.os.getuid())), \
             patch.object(module.shutil, "which", return_value="/usr/bin/ssh-add"), \
             patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(module.ssh_agent_state(), "PUBLIC_IDENTITIES_PRESENT_UNVERIFIED")
        self.assertEqual(run.call_args.args[0], ["ssh-add", "-l"])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_ssh_none_or_failure_is_not_success(self):
        with patch.dict(module.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
             patch.object(module.Path, "lstat", return_value=SimpleNamespace(
                 st_mode=stat.S_IFSOCK | 0o600, st_uid=module.os.getuid())), \
             patch.object(module.shutil, "which", return_value="ssh-add"):
            for rc, expected in [(1, "NO_IDENTITIES_OR_AGENT"), (2, "UNKNOWN"), (255, "UNKNOWN")]:
                with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=rc)):
                    self.assertEqual(module.ssh_agent_state(), expected)
            with patch.object(module.subprocess, "run", side_effect=OSError("secret")):
                self.assertEqual(module.ssh_agent_state(), "UNKNOWN")

    def test_recovery_tools_presence_only(self):
        with patch.object(module, "process_state", return_value="PROCESS_NOT_OBSERVED"), \
             patch.object(module, "ssh_agent_state", return_value="SOCKET_NOT_CONFIGURED"), \
             patch.object(module, "scdaemon_agent_state", return_value="NOT_CONFIRMED"), \
             patch.object(module, "postgres_versioned_tools_state", return_value="NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS"), \
             patch.object(module, "postgres_pg_config_server_tools_state", return_value="PG_CONFIG_MISSING"), \
             patch.object(module.shutil, "which", side_effect=lambda x: "/bin/fake" if x=="pg_restore" else None):
            report = module.snapshot()
        self.assertEqual(report["recovery_tools"]["pg_restore"], "INSTALLED_UNVERIFIED")
        self.assertEqual(report["recovery_tools"]["psql"], "MISSING")
        for key in ("openpgp_card_access_verified", "postgres_restore_verified",
                    "ssh_fido_login_verified", "escrow_restore_verified",
                    "hardware_mutation_authorized"):
            self.assertFalse(report[key])
        self.assertEqual(report["status"], "NO-GO")

    def test_existing_agent_reports_scd_without_start_or_card_access(self):
        response = subprocess.CompletedProcess(
            [], 0, "OK\nOK closing connection\n", "")
        with patch.object(module.shutil, "which", return_value="/usr/bin/gpg-connect-agent"), \
             patch.object(module.subprocess, "run", return_value=response) as runner:
            self.assertEqual(module.scdaemon_agent_state(),
                             "AGENT_REPORTS_SCD_RUNNING_UNVERIFIED")
        self.assertEqual(runner.call_args.args[0], [
            "gpg-connect-agent", "--no-autostart", "GETINFO scd_running", "/bye"
        ])
        self.assertEqual(runner.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(runner.call_args.kwargs["timeout"], 5)
        self.assertFalse(runner.call_args.kwargs["check"])

    def test_scd_error_or_malformed_reply_never_claims_running(self):
        cases = (
            subprocess.CompletedProcess([], 0, "ERR 123 FALSE\nOK closing connection\n", ""),
            subprocess.CompletedProcess([], 0, "OK closing connection\n", ""),
            subprocess.CompletedProcess([], 1, "OK\nOK closing connection\n", ""),
            subprocess.CompletedProcess([], 0, "OK\nOK closing connection\n", "diagnostic"),
            subprocess.CompletedProcess([], 0, "OK\nOK closing connection\nEXTRA\n", ""),
        )
        with patch.object(module.shutil, "which", return_value="gpg-connect-agent"):
            for result in cases:
                with self.subTest(result=result.returncode), \
                     patch.object(module.subprocess, "run", return_value=result):
                    self.assertNotEqual(module.scdaemon_agent_state(),
                                        "AGENT_REPORTS_SCD_RUNNING_UNVERIFIED")

    def test_scd_optional_greeting_is_not_a_false_negative(self):
        success = "OK Pleased to meet you\nOK\nOK closing connection\n"
        self.assertEqual(
            module.classify_scdaemon_assuan(success),
            "AGENT_REPORTS_SCD_RUNNING_UNVERIFIED")
        with patch.object(module.shutil, "which", return_value="gpg-connect-agent"), \
             patch.object(module.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, success, "")):
            self.assertEqual(
                module.scdaemon_agent_state(),
                "AGENT_REPORTS_SCD_RUNNING_UNVERIFIED")

    def test_scd_assuan_err_is_distinct_from_malformed(self):
        refused = "ERR 67109139 No Smartcard daemon <GPG Agent>\nOK closing connection\n"
        self.assertEqual(
            module.classify_scdaemon_assuan(refused),
            "AGENT_SCD_STATUS_REJECTED_UNVERIFIED")
        self.assertEqual(
            module.classify_scdaemon_assuan("OK random\nOK closing connection\n"),
            "NOT_CONFIRMED")
        self.assertEqual(module.classify_scdaemon_assuan(""), "NOT_CONFIRMED")

    def test_scd_assuan_bounded_and_no_success_with_extra_output(self):
        for raw in ("OK\n", "OK\nOK closing connection\nEXTRA\n",
                    "OK\nOK closing connection\nERR 1\n",
                    "OK\nOK closing connection\x00\n",
                    "OK Pleased to meet you\nD SECRET\nOK\nOK closing connection\n",
                    "OK\nOK closing connection\n" + "X" * 5000):
            with self.subTest(case=repr(raw)[:36]):
                self.assertEqual(module.classify_scdaemon_assuan(raw),
                                 "NOT_CONFIRMED")

    def test_scd_tool_missing_and_timeout_fail_closed(self):
        with patch.object(module.shutil, "which", return_value=None), \
             patch.object(module.subprocess, "run") as runner:
            self.assertEqual(module.scdaemon_agent_state(), "TOOL_MISSING")
            runner.assert_not_called()
        with patch.object(module.shutil, "which", return_value="gpg-connect-agent"), \
             patch.object(module.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(["gpg-connect-agent"], 5)):
            self.assertEqual(module.scdaemon_agent_state(), "UNKNOWN")

    def test_postgres_versioned_server_tools_metadata_only(self):
        root = MagicMock()
        root.is_symlink.return_value = False
        root.is_dir.return_value = True
        version = MagicMock()
        version.name = "18"
        version.is_symlink.return_value = False
        root.iterdir.return_value = [version]
        binaries = MagicMock()
        binaries.is_symlink.return_value = False
        version.__truediv__.return_value = binaries
        program = MagicMock()
        program.is_symlink.return_value = False
        program.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=0)
        binaries.__truediv__.return_value = program
        with patch.object(module, "Path", return_value=root), \
             patch.object(module.subprocess, "run") as runner:
            self.assertEqual(module.postgres_versioned_tools_state(),
                             "VERSIONED_SERVER_BINARIES_PRESENT_UNVERIFIED")
            runner.assert_not_called()

    def test_postgres_versioned_path_and_file_symlinks_refused(self):
        root = MagicMock()
        root.is_symlink.return_value = True
        with patch.object(module, "Path", return_value=root):
            self.assertEqual(module.postgres_versioned_tools_state(), "UNKNOWN")
        root.is_symlink.return_value = False
        root.is_dir.return_value = False
        with patch.object(module, "Path", return_value=root):
            self.assertEqual(module.postgres_versioned_tools_state(),
                             "NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS")

    def test_postgres_untrusted_binary_owner_never_present(self):
        root = MagicMock()
        root.is_symlink.return_value = False
        root.is_dir.return_value = True
        version = MagicMock()
        version.name = "18"
        version.is_symlink.return_value = False
        root.iterdir.return_value = [version]
        binaries = MagicMock()
        binaries.is_symlink.return_value = False
        version.__truediv__.return_value = binaries
        program = MagicMock()
        program.is_symlink.return_value = False
        program.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=1000)
        binaries.__truediv__.return_value = program
        with patch.object(module, "Path", return_value=root):
            self.assertEqual(module.postgres_versioned_tools_state(),
                             "NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS")

    def test_pg_config_absent_does_not_start_anything(self):
        with patch.object(module.shutil, "which", return_value=None), \
             patch.object(module.subprocess, "run") as cmd:
            self.assertEqual(module.postgres_pg_config_server_tools_state(),
                             "PG_CONFIG_MISSING")
            cmd.assert_not_called()

    def test_pg_config_reports_binaries_by_metadata_without_execution(self):
        directory = MagicMock()
        directory.is_absolute.return_value = True
        directory.is_symlink.return_value = False
        directory.is_dir.return_value = True
        binary = MagicMock()
        binary.is_symlink.return_value = False
        binary.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=0)
        directory.__truediv__.return_value = binary
        done = subprocess.CompletedProcess([], 0, "/usr/pgsql-18/bin\n", "")
        with patch.object(module.shutil, "which", return_value="/usr/bin/pg_config"), \
             patch.object(module, "Path", return_value=directory), \
             patch.object(module.subprocess, "run", return_value=done) as cmd:
            self.assertEqual(module.postgres_pg_config_server_tools_state(),
                             "PG_CONFIG_SERVER_BINARIES_PRESENT_UNVERIFIED")
        self.assertEqual(cmd.call_args.args[0], ["pg_config", "--bindir"])
        self.assertEqual(cmd.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(cmd.call_args.kwargs["timeout"], 5)
        self.assertFalse(cmd.call_args.kwargs["check"])

    def test_pg_config_client_only_and_untrusted_binary_fail_closed(self):
        directory = MagicMock()
        directory.is_absolute.return_value = True
        directory.is_symlink.return_value = False
        directory.is_dir.return_value = True
        binary = MagicMock()
        binary.is_symlink.return_value = False
        binary.lstat.side_effect = FileNotFoundError
        directory.__truediv__.return_value = binary
        done = subprocess.CompletedProcess([], 0, "/usr/bin\n", "")
        with patch.object(module.shutil, "which", return_value="pg_config"), \
             patch.object(module, "Path", return_value=directory), \
             patch.object(module.subprocess, "run", return_value=done):
            self.assertEqual(module.postgres_pg_config_server_tools_state(),
                             "PG_CONFIG_BINDIR_HAS_NO_SERVER_BINARIES")
        binary.lstat.side_effect = None
        binary.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=123456789)
        with patch.object(module.shutil, "which", return_value="pg_config"), \
             patch.object(module, "Path", return_value=directory), \
             patch.object(module.subprocess, "run", return_value=done):
            self.assertEqual(module.postgres_pg_config_server_tools_state(),
                             "PG_CONFIG_BINDIR_HAS_NO_SERVER_BINARIES")

    def test_pg_config_bad_paths_and_outputs_are_unknown(self):
        for output in ("relative\n", "bad\x00/path\n", "\n",
                       "/usr/bin\nunexpected\n", "/" * 4200):
            with self.subTest(case=repr(output)[:18]), \
                 patch.object(module.shutil, "which", return_value="pg_config"), \
                 patch.object(module.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, output, "")):
                self.assertEqual(module.postgres_pg_config_server_tools_state(), "UNKNOWN")

    def test_arguments_rejected_before_snapshot(self):
        with patch.object(module, "snapshot") as snap, redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(["--pin"]), 2)
            snap.assert_not_called()

    def test_json_report_has_no_identifiers_or_paths(self):
        with patch.object(module, "snapshot", return_value={"status": "NO-GO", "hardware_mutation_authorized": False}):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(module.main([]), 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
