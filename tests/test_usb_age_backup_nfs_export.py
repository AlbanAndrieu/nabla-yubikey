"""Hermetic TrueNAS NFS export audit contracts: zero real USB/NFS/SSH."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-usb-age-backup-nfs-export.py"
spec = importlib.util.spec_from_file_location("nabla_usb_nfs_export_contract", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    NAME = "usb-recovery-identity-20261028T000000Z-a1b2c3d4.age"

    @staticmethod
    def record(**update):
        result = dict(
            state="EXPORT_MATCHED", enabled=True, read_only=False, locked=False,
            client_filter="FILTER_PRESENT", hosts_restricted=True,
            networks_restricted=False, root_mapping="UNSET", all_mapping="UNSET",
            root_group_mapped=False, all_group_mapped=False, security="SYS_ONLY")
        result.update(update)
        return result

    @staticmethod
    def sample_share(**kw):
        base = dict(path="/mnt/cpool/backup/lab", enabled=True, ro=False,
                    locked=False, hosts=["host.example.invalid"], networks=[],
                    security=["SYS"], maproot_user=None, maproot_group=None,
                    mapall_user=None, mapall_group=None)
        base.update(kw)
        return base

    def test_check_never_contacts_true_nas_or_reads_backup(self):
        with patch.object(m, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
             patch.object(m, "probe") as remote, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--check"]), 0)
        remote.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report["probe_state"], "NOT_PROBED")
        self.assertFalse(report["archive_opened"])
        self.assertFalse(report["nfs_identity_mapping_verified"])

    def test_check_missing_backups_fail_closed(self):
        with patch.object(m, "preflight", return_value=("BACKUPS_ABSENT_OR_AMBIGUOUS", None)), \
             patch.object(m, "probe") as remote, redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(["--check"]), 3)
        remote.assert_not_called()

    def test_probe_needs_explicit_authorization(self):
        with redirect_stderr(io.StringIO()), patch.object(m, "probe") as remote:
            for args in ([], ["--probe"], ["--probe", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                    m.main(args)
                self.assertEqual(error.exception.code, 2)
        remote.assert_not_called()

    def test_inventory_success_is_not_policy_acceptance(self):
        with patch.object(m, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
             patch.object(m, "probe", return_value=self.record(
                 hosts_restricted=False, client_filter="ALL_CLIENTS_ALLOWED_BY_FILTERS",
                 root_mapping="SENSITIVE_OWNER", read_only=False)), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--probe", "--acknowledge", m.ACK]), 0)
        record = json.loads(output.getvalue())
        self.assertTrue(record["configuration_inventory_verified"])
        self.assertIn("NO_NFS_HOST_OR_NETWORK_FILTER", record["review_flags"])
        self.assertIn("AUTH_SYS_ALLOWED", record["review_flags"])
        self.assertIn("MAPROOT_TO_SENSITIVE_OWNER", record["review_flags"])
        self.assertIn("EXPORT_WRITABLE", record["review_flags"])
        self.assertFalse(record["negative_access_test_performed"])
        self.assertFalse(record["effective_nfs4_authorization_verified"])
        self.assertFalse(record["remote_write_performed"])

    def test_unspecified_security_flavor_remains_a_review_flag(self):
        with patch.object(m, "preflight", return_value=(
                "BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
             patch.object(m, "probe", return_value=self.record(
                 security="DEFAULT_UNVERIFIED")), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--probe", "--acknowledge", m.ACK]), 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["configuration_inventory_verified"])
        self.assertIn("NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED",
                      report["review_flags"])
        self.assertNotIn("AUTH_SYS_ALLOWED", report["review_flags"])
        self.assertFalse(report["effective_nfs4_authorization_verified"])

    def test_unavailable_response_fails_closed(self):
        with patch.object(m, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
             patch.object(m, "probe", return_value=self.record(state="EXPORT_SCHEMA_UNVERIFIED")), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--probe", "--acknowledge", m.ACK]), 3)
        self.assertFalse(json.loads(output.getvalue())["configuration_inventory_verified"])

    def test_strict_ssh_no_raw_client_or_name_in_argv(self):
        with patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(self.record()))) as call:
            self.assertEqual(m.probe(self.NAME), self.record())
        argv = call.call_args.args[0]
        self.assertEqual(argv[-3:], [m.SSH_TARGET, "python3", "-"])
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertEqual(call.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn(self.NAME, repr(argv))
        self.assertIn(self.NAME, call.call_args.kwargs["input"])

    def test_filename_validation_rejects_injection(self):
        with patch.object(m.subprocess, "run") as call:
            for value in ("../secret.age", "test.age",
                          "usb-recovery-identity-20261028T000000Z-foo.age",
                          "usb-recovery-identity-20261028T000000Z-a1b2c3d4.age;id"):
                self.assertIsNone(m.probe(value))
        call.assert_not_called()

    def test_untrusted_ssh_output_is_rejected(self):
        bad = [b"{", "{}", json.dumps({**self.record(), "state": "FAKE"}),
               json.dumps({**self.record(), "enabled": 1}),
               json.dumps({**self.record(), "root_mapping": "root"}),
               json.dumps({**self.record(), "read_only": None}),
               json.dumps({**self.record(), "client_filter": "SCHEMA_UNVERIFIED"}),
               json.dumps({**self.record(), "state": "EXPORT_MISSING"}),
               json.dumps({**self.record(), "client_ip": "192.0.2.1"})]
        for value in bad:
            with self.subTest(value=str(value)[:30]), patch.object(
                m.subprocess, "run",
                return_value=SimpleNamespace(returncode=0, stdout=value)):
                self.assertIsNone(m.probe(self.NAME))
        with patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                returncode=255, stdout="")) as call:
            self.assertIsNone(m.probe(self.NAME))
        self.assertEqual(call.call_count, 1)

    def test_synthetic_remote_export_filters_and_user_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            # macOS /var is a symlink; the remote check rightly refuses symlinked parents.
            root = Path(temp).resolve()
            export = root / "lab"
            backups = export / "secret" / "usb-recovery-backups"
            backups.mkdir(parents=True)
            (backups / self.NAME).write_bytes(b"SYNTHETIC ENCRYPTED BYTES")
            fakebin = root / "bin"
            fakebin.mkdir()
            stub = fakebin / "midclt"
            stub.write_text('#!/bin/sh\ncat "$FAKE_SHARE_JSON"\n', encoding="utf-8")
            stub.chmod(0o700)
            data = root / "shares.json"
            program = ("EXPECTED_NAME = " + json.dumps(self.NAME) + "\n" +
                m.REMOTE.replace('Path("/mnt/cpool/backup/lab")',
                                 f"Path({str(export)!r})"))
            env = dict(os.environ)
            env.update(PATH=str(fakebin) + os.pathsep + env.get("PATH", ""),
                       FAKE_SHARE_JSON=str(data))
            def execute(shares):
                # The remote program uses the synthetic lab path, not the
                # real TrueNAS export. Keep fixture metadata aligned with it.
                fixtures = [
                    {**share, "path": str(export)}
                    if share.get("path") == "/mnt/cpool/backup/lab" else share
                    for share in shares
                ]
                data.write_text(json.dumps(fixtures), encoding="utf-8")
                proc = subprocess.run([sys.executable, "-"], input=program,
                                      text=True, capture_output=True,
                                      env=env, timeout=8)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn(str(export), proc.stdout)
                self.assertNotIn(self.NAME, proc.stdout)
                self.assertNotIn("host.example.invalid", proc.stdout)
                return json.loads(proc.stdout)

            normal = execute([self.sample_share()])
            self.assertEqual(normal["state"], "EXPORT_MATCHED")
            self.assertEqual(normal["client_filter"], "FILTER_PRESENT")
            self.assertEqual(normal["security"], "SYS_ONLY")
            self.assertEqual(normal["root_mapping"], "UNSET")
            self.assertEqual(execute([self.sample_share(hosts=[], networks=[])])[
                             "client_filter"], "ALL_CLIENTS_ALLOWED_BY_FILTERS")
            owner = pwd.getpwuid(os.getuid()).pw_name
            mapped = execute([self.sample_share(mapall_user=owner)])
            self.assertEqual(mapped["all_mapping"], "SENSITIVE_OWNER")
            self.assertEqual(execute([self.sample_share(mapall_user="__absent_123")])[
                             "all_mapping"], "ACCOUNT_NOT_RESOLVED")
            self.assertEqual(execute([])["state"], "EXPORT_MISSING")
            # An unrelated share must never match the expected lab export.
            self.assertEqual(execute([self.sample_share(
                path="/mnt/unrelated-share")])["state"], "EXPORT_MISSING")
            self.assertEqual(execute([self.sample_share(), self.sample_share()])[
                             "state"], "EXPORT_AMBIGUOUS")
            self.assertEqual(execute([self.sample_share(enabled=1)])[
                             "state"], "EXPORT_SCHEMA_UNVERIFIED")
            self.assertEqual(execute([self.sample_share(security=["KRB5P"])])[
                             "security"], "KERBEROS_ONLY")
            self.assertEqual(execute([self.sample_share(security=["SYS", "SYS"])])[
                             "state"], "EXPORT_SCHEMA_UNVERIFIED")
            self.assertEqual(execute([self.sample_share(hosts=[], networks=[],
                                         security=[])])["security"], "DEFAULT_UNVERIFIED")
            (backups / self.NAME).unlink()
            (backups / self.NAME).symlink_to(export)
            self.assertEqual(execute([self.sample_share()])[
                             "state"], "SENSITIVE_FILE_UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
