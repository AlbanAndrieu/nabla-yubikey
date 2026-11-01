"""Hermetic mode-boundary contracts; no real SSH, TrueNAS or USB."""
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
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-usb-identity-backup-server-modes.py"
spec = importlib.util.spec_from_file_location("nabla_usb_truenas_server_modes", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    NAME = "usb-recovery-identity-20261028T000000Z-a1b2c3d4.age"

    @staticmethod
    def valid():
        return {"levels": [
            {"level": 0, "state": "EXPORT_DIRECTORY_PRESENT"},
            {"level": 1, "state": "PRIVATE_DIRECTORY_MODE_0700"},
            {"level": 2, "state": "PRIVATE_DIRECTORY_MODE_0700"},
            {"level": 3, "state": "PRIVATE_FILE_MODE_0600"}],
            "sensitive_owner_uniform": True}

    def test_check_no_ssh(self):
        with patch.object(m, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
             patch.object(m, "query_server") as q, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 0)
        q.assert_not_called()
        record = json.loads(out.getvalue())
        self.assertEqual(record["server_probe_state"], "NOT_PROBED")
        self.assertFalse(record["private_mode_boundary_observed"])
        self.assertFalse(record["effective_nfs4_authorization_verified"])

    def test_check_rejects_missing_backups(self):
        with patch.object(m, "preflight", return_value=("BACKUPS_ABSENT_OR_AMBIGUOUS", None)), \
             patch.object(m, "query_server") as q, redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(["--check"]), 3)
        q.assert_not_called()

    def test_probe_requires_authorization(self):
        with redirect_stderr(io.StringIO()):
            for args in ([], ["--probe"], ["--probe", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as raised:
                    m.main(args)
                self.assertEqual(raised.exception.code, 2)

    def test_full_mode_boundary_observed_but_no_effective_claim(self):
        with patch.object(m, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
             patch.object(m, "query_server", return_value=self.valid()), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--probe", "--acknowledge", m.ACK]), 0)
        record = json.loads(out.getvalue())
        self.assertTrue(record["private_mode_boundary_observed"])
        self.assertFalse(record["effective_nfs4_authorization_verified"])
        self.assertFalse(record["nfs_identity_mapping_verified"])
        self.assertFalse(record["remote_write_performed"])
        self.assertFalse(record["paths_or_uid_gid_disclosed"])
        self.assertNotIn(self.NAME, out.getvalue())

    def test_loose_parent_mode_or_mismatched_owner_fails_closed(self):
        for variant in ("parent", "file", "owner"):
            report = self.valid()
            if variant == "parent":
                report["levels"][1]["state"] = "MODE_REVIEW_REQUIRED"
            elif variant == "file":
                report["levels"][3]["state"] = "MODE_REVIEW_REQUIRED"
            else:
                report["sensitive_owner_uniform"] = False
            with self.subTest(variant=variant), \
                 patch.object(m, "preflight", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.NAME)), \
                 patch.object(m, "query_server", return_value=report), \
                 redirect_stdout(io.StringIO()) as out:
                self.assertEqual(m.main(["--probe", "--acknowledge", m.ACK]), 3)
                self.assertEqual(json.loads(out.getvalue())["status"], "REVIEW_REQUIRED")

    def test_bad_filename_refused_before_remote(self):
        with patch.object(m.subprocess, "run") as runner:
            for name in ("../secret.age", "fake.age", "usb-recovery-identity-20261028T000000Z-fake.age"):
                self.assertIsNone(m.query_server(name))
        runner.assert_not_called()

    def test_ssh_command_pinned_and_sanitized(self):
        with patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(self.valid()))) as run:
            self.assertEqual(m.query_server(self.NAME), self.valid())
        argv = run.call_args.args[0]
        self.assertEqual(argv[-3:], [m.SSH_TARGET, "python3", "-"])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertNotIn(self.NAME, repr(argv))
        self.assertIn(self.NAME, run.call_args.kwargs["input"])
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_untrusted_json_and_ssh_fail_closed(self):
        bad = [
            "private/secret/path",
            json.dumps({"levels": [self.valid()["levels"][0]]}),
            json.dumps({**self.valid(), "sensitive_owner_uniform": "yes"}),
            json.dumps({"levels": [{**x, "unexpected": "value"} if i == 2 else x
                                   for i, x in enumerate(self.valid()["levels"])],
                        "sensitive_owner_uniform": True}),
            json.dumps({"levels": [{**x, "level": True} if i == 1 else x
                                   for i, x in enumerate(self.valid()["levels"])],
                        "sensitive_owner_uniform": True}),
        ]
        for raw in bad:
            with self.subTest(raw=raw[:20]), patch.object(m.subprocess, "run",
                    return_value=SimpleNamespace(returncode=0, stdout=raw)):
                self.assertIsNone(m.query_server(self.NAME))
        with patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                returncode=255, stdout="")) as fail:
            self.assertIsNone(m.query_server(self.NAME))
        self.assertEqual(fail.call_count, 1)

    def test_remote_script_synthetic_permissions_and_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "lab"
            secret = lab / "secret"
            copies = secret / "usb-recovery-backups"
            copies.mkdir(parents=True, mode=0o700)
            lab.chmod(0o750)
            secret.chmod(0o700)
            copies.chmod(0o700)
            ciphertext = copies / self.NAME
            ciphertext.write_bytes(b"only synthetic ciphertext")
            ciphertext.chmod(0o600)
            program = ("EXPECTED_NAME = " + json.dumps(self.NAME) + "\n" +
                       m.REMOTE.replace('Path("/mnt/cpool/backup/lab")', f"Path({str(lab)!r})"))

            def run():
                proc = subprocess.run([sys.executable, "-"], input=program,
                                      text=True, capture_output=True, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn(self.NAME, proc.stdout)
                self.assertNotIn(str(lab), proc.stdout)
                return json.loads(proc.stdout)

            correct = run()
            self.assertEqual(correct, self.valid())
            copies.chmod(0o750)
            self.assertEqual(run()["levels"][2]["state"], "MODE_REVIEW_REQUIRED")
            copies.chmod(0o700)
            ciphertext.unlink()
            ciphertext.symlink_to(lab)
            self.assertEqual(run()["levels"][3]["state"], "UNTRUSTED_PATH")


if __name__ == "__main__":
    unittest.main()
