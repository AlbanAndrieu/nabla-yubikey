"""Hermetic NFS server client snapshot contracts; no real server or private data."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase, main
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-usb-age-nfs-consumers.py"
spec = importlib.util.spec_from_file_location("nabla_nfs_consumer_snapshot", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Contracts(TestCase):
    def sample(self, **changes):
        report = dict(state="TCP_SNAPSHOT_OBSERVED", tcp_sessions=3,
                      unique_tcp_peers=2, nfs_export_attribution="NOT_POSSIBLE")
        report.update(changes)
        return report

    def test_check_never_ssh(self):
        with patch.object(module, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", True)), \
             patch.object(module, "query_server") as ssh, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(["--check"]), 0)
        ssh.assert_not_called()
        state = json.loads(out.getvalue())
        self.assertFalse(state["consumer_allowlist_verified"])
        self.assertFalse(state["archive_opened"])
        self.assertIsNone(state["tcp_sessions"])

    def test_missing_backup_prevents_server_probe(self):
        with patch.object(module, "preflight", return_value=("BACKUPS_UNAVAILABLE", False)), \
             patch.object(module, "query_server") as ssh, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(["--probe", "--acknowledge", module.ACK]), 3)
        ssh.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["probe_state"],
                         "SSH_OR_PREFLIGHT_UNAVAILABLE")

    def test_explicit_readonly_ack_gate(self):
        with patch.object(module, "query_server") as ssh, redirect_stderr(io.StringIO()):
            for cmd in ([], ["--probe"], ["--probe", "--acknowledge", "invalid"],
                        ["--check", "--acknowledge", module.ACK]):
                with self.subTest(cmd=cmd), self.assertRaises(SystemExit) as e:
                    module.main(cmd)
                self.assertEqual(e.exception.code, 2)
        ssh.assert_not_called()

    def test_ssh_command_is_pinned_and_stdin_only(self):
        with patch.object(module.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(self.sample()))) as runner:
            self.assertEqual(module.query_server(), self.sample())
        argv = runner.call_args.args[0]
        self.assertEqual(argv[-3:], [module.SSH_TARGET, "python3", "-"])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(runner.call_args.kwargs["input"], module.REMOTE)
        self.assertEqual(runner.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_untrusted_server_report_rejected(self):
        bad = [
            "{}",
            "secret/private-ip",
            json.dumps(self.sample(unique_tcp_peers=4)),
            json.dumps(self.sample(tcp_sessions=True)),
            json.dumps(self.sample(nfs_export_attribution="backup_export")),
            json.dumps(self.sample(client_ipv4="192.0.2.1")),
            json.dumps(self.sample(state="SS_UNAVAILABLE")),
            json.dumps(self.sample(state="UNKNOWN")),
        ]
        for value in bad:
            with self.subTest(value=value[:30]), patch.object(
                    module.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=value)):
                self.assertIsNone(module.query_server())

    def test_snapshot_is_not_complete_allowlist(self):
        with patch.object(module, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", True)), \
             patch.object(module, "query_server", return_value=self.sample()), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(["--probe", "--acknowledge", module.ACK]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["tcp_sessions"], 3)
        self.assertEqual(report["unique_tcp_peers"], 2)
        self.assertEqual(report["scope"], "ALL_NFS_EXPORTS_TCP2049_ONLY")
        self.assertFalse(report["consumer_allowlist_verified"])
        self.assertFalse(report["export_specific_clients_verified"])
        self.assertFalse(report["client_addresses_disclosed"])
        self.assertFalse(report["remote_write_performed"])

    def test_missing_ssh_fails_closed(self):
        with patch.object(module.subprocess, "run", return_value=SimpleNamespace(
                returncode=255, stdout="")) as ssh:
            self.assertIsNone(module.query_server())
        self.assertEqual(ssh.call_count, 1)

    def test_remote_python_with_fake_ss(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            script = bin_dir / "ss"
            script.write_text('#!/bin/sh\ncat "$FAKE_SS_OUTPUT"\n', encoding="utf-8")
            script.chmod(0o700)
            data = root / "ss.txt"
            env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   "FAKE_SS_OUTPUT": str(data)}
            def evaluate(lines):
                data.write_text(lines, encoding="utf-8")
                p = subprocess.run([sys.executable, "-"], input=module.REMOTE,
                                   text=True, capture_output=True, timeout=5, env=env)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertNotIn("192.0.2.10", p.stdout)
                self.assertNotIn("2001:db8::1", p.stdout)
                return json.loads(p.stdout)
            tcp = ("ESTAB 0 0 192.0.2.100:2049 192.0.2.10:50455\n"
                   "ESTAB 0 0 192.0.2.100:2049 192.0.2.10:50456\n"
                   "ESTAB 0 0 [2001:db8::3]:2049 [2001:db8::1]:31234\n")
            result = evaluate(tcp)
            self.assertEqual(result, self.sample())
            # Actual ss -H state established output commonly has FOUR fields:
            # Recv-Q Send-Q Local:Port Peer:Port (without ESTAB).
            stateless = (
                "0 0 192.0.2.100:2049 192.0.2.10:50455\n"
                "0 0 [::ffff:192.0.2.100]:2049 [::ffff:192.0.2.10]:50456\n"
                "0 0 [2001:db8::3]:2049 [2001:db8::1]:31234\n"
            )
            self.assertEqual(evaluate(stateless), self.sample())
            # Queue fields and the local NFS port must still validate.
            self.assertEqual(
                evaluate("xx 0 192.0.2.100:2049 192.0.2.10:50455\n")["state"],
                "SS_RESPONSE_UNVERIFIED")
            self.assertEqual(
                evaluate("0 0 192.0.2.100:22 192.0.2.10:50455\n")["state"],
                "SS_RESPONSE_UNVERIFIED")
            self.assertEqual(evaluate("")["state"], "TCP_SNAPSHOT_OBSERVED")
            self.assertEqual(evaluate("")["unique_tcp_peers"], 0)
            self.assertEqual(evaluate("ESTAB 0 0 192.0.2.100:22 192.0.2.10:50500\n")[
                             "state"], "SS_RESPONSE_UNVERIFIED")
            self.assertEqual(evaluate("malformed tcp payload\n")["state"],
                             "SS_RESPONSE_UNVERIFIED")


if __name__ == "__main__":
    main()
