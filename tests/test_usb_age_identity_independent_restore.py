"""Hermetic restore contracts: never touch age, USB, NFS, or real identities."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = (Path(__file__).resolve().parents[1] /
          "scripts/workstation/verify-usb-age-identity-independent-backup.py")
spec = importlib.util.spec_from_file_location("independent_restore", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.local_parent = root / "local"
        self.nfs_parent = root / "nfs"
        for parent in (self.local_parent, self.nfs_parent):
            parent.mkdir(mode=0o700)
        self.local = self.local_parent / "usb-recovery-backups"
        self.nfs = self.nfs_parent / "usb-recovery-backups"
        self.local.mkdir(mode=0o700)
        self.nfs.mkdir(mode=0o700)
        self.name = "usb-recovery-identity-20261028T000000Z-a1b2c3d4.age"
        self.ciphertext = b"age-encryption.org/v1\n" + b"encrypted" * 30
        self.pair = (self.local / self.name, self.nfs / self.name)
        for path in self.pair:
            path.write_bytes(self.ciphertext)
            path.chmod(0o600)
        for key, value in (("LOCAL_PARENT", self.local_parent),
                           ("NFS_PARENT", self.nfs_parent),
                           ("LOCAL_DIR", self.local), ("NFS_DIR", self.nfs)):
            ctx = patch.object(m, key, value)
            ctx.start()
            self.addCleanup(ctx.stop)

    def pair_ready(self):
        original = Path.stat
        def different_device(path, *args, **kwargs):
            actual = original(path, *args, **kwargs)
            if path != self.nfs:
                return actual
            attrs = [getattr(actual, key) for key in
                     ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid",
                      "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")]
            attrs[2] += 1
            return os.stat_result(attrs)
        return patch.object(Path, "stat", different_device)

    def test_check_never_reads_ciphertext_or_invokes_age(self):
        with patch.object(m, "trusted_mount", return_value=True), \
             self.pair_ready(), patch.object(m, "verify") as verifier, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--check"]), 0)
        verifier.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertFalse(report["two_encrypted_backups_restored"])
        self.assertFalse(report["plaintext_written_to_disk"])

    def test_verify_requires_explicit_acknowledgement(self):
        with redirect_stderr(io.StringIO()):
            for args in (["--verify"], ["--verify", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as raised:
                    m.main(args)
                self.assertEqual(raised.exception.code, 2)

    def test_mount_required(self):
        with patch.object(m, "trusted_mount", return_value=False):
            self.assertEqual(m.encrypted_pair()[0], "NFS_EXPORT_UNVERIFIED")

    def test_mismatched_backup_names_refused(self):
        self.pair[1].rename(self.nfs / "usb-recovery-identity-20261028T000001Z-a1b2c3d4.age")
        with patch.object(m, "trusted_mount", return_value=True), self.pair_ready():
            self.assertEqual(m.encrypted_pair()[0], "BACKUP_NAMES_DIFFER")

    def test_symlink_backup_and_bad_mode_refused(self):
        self.pair[0].unlink()
        self.pair[0].symlink_to(self.pair[1])
        with patch.object(m, "trusted_mount", return_value=True), self.pair_ready():
            self.assertEqual(m.encrypted_pair()[0], "BACKUP_FILE_METADATA_UNTRUSTED")
        self.pair[0].unlink()
        self.pair[0].write_bytes(self.ciphertext)
        self.pair[0].chmod(0o644)
        with patch.object(m, "trusted_mount", return_value=True), self.pair_ready():
            self.assertEqual(m.encrypted_pair()[0], "BACKUP_FILE_METADATA_UNTRUSTED")

    def test_extra_backup_or_partial_file_refused(self):
        (self.local / ".pending-escrow-abc").write_bytes(b"partial")
        with patch.object(m, "trusted_mount", return_value=True), self.pair_ready():
            self.assertEqual(m.encrypted_pair()[0], "BACKUPS_ABSENT_OR_AMBIGUOUS")

    def test_distinct_filesystems_required(self):
        with patch.object(m, "trusted_mount", return_value=True):
            self.assertEqual(m.encrypted_pair()[0], "BACKUPS_NOT_ON_DISTINCT_FILESYSTEMS")

    def test_ciphertext_mismatch_no_decryption(self):
        self.pair[1].write_bytes(b"age-encryption.org/v1\n" + b"other" * 80)
        with patch.object(m, "recovered_recipient") as derive:
            self.assertEqual(m.verify(self.pair), "ENCRYPTED_COPIES_DIFFER")
        derive.assert_not_called()

    def test_two_successful_decryptions_required(self):
        with patch.object(m, "recovered_recipient", side_effect=["RECIPIENT_MATCH", "RECIPIENT_MATCH"]) as derive:
            self.assertEqual(m.verify(self.pair), "BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT")
        self.assertEqual(derive.call_count, 2)
        with patch.object(m, "recovered_recipient", side_effect=["RECIPIENT_MATCH", "RESTORE_FAILED"]):
            self.assertEqual(m.verify(self.pair), "RESTORE_FAILED_OR_RECIPIENT_MISMATCH")

    def test_decrypted_key_sent_only_to_age_keygen_stdin(self):
        calls = []
        def fake_run(args, **kw):
            calls.append((args, kw))
            if args[0] == "age":
                return SimpleNamespace(returncode=0, stdout=b"SYNTHETIC-PRIVATE-KEY")
            return SimpleNamespace(returncode=0, stdout=(m.EXPECTED_RECIPIENT + "\n").encode())
        with patch.object(m.subprocess, "run", side_effect=fake_run), \
             patch.object(m.os, "lseek", return_value=0):
            self.assertEqual(m.recovered_recipient(17), "RECIPIENT_MATCH")
        self.assertEqual(calls[0][0], ["age", "--decrypt"])
        self.assertEqual(calls[0][1]["stdin"], 17)
        self.assertEqual(calls[1][0], ["age-keygen", "-y"])
        self.assertEqual(calls[1][1]["input"], b"SYNTHETIC-PRIVATE-KEY")

    def test_failed_public_derivation_is_not_success(self):
        with patch.object(m.subprocess, "run", side_effect=[
            SimpleNamespace(returncode=0, stdout=b"MOCK-PRIVATE-KEY"),
            SimpleNamespace(returncode=1, stdout=b"")]), \
             patch.object(m.os, "lseek", return_value=0):
            self.assertEqual(m.recovered_recipient(4), "RESTORE_FAILED")

    def test_missing_terminal_never_invokes_decryption(self):
        with patch.object(m, "encrypted_pair", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.pair)), \
             patch.object(m.sys.stdin, "isatty", return_value=False), \
             patch.object(m, "verify") as verify, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--verify", "--acknowledge", m.ACK]), 3)
        verify.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["state"], "INTERACTIVE_TERMINAL_REQUIRED")

    def test_no_usb_dependency_or_plaintext_storage(self):
        with patch.object(m, "encrypted_pair", return_value=("BACKUP_RESTORATION_PREFLIGHT_READY", self.pair)), \
             patch.object(m.sys.stdin, "isatty", return_value=True), \
             patch.object(m.sys.stderr, "isatty", return_value=True), \
             patch.object(m, "verify", return_value="BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT"), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--verify", "--acknowledge", m.ACK]), 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["two_encrypted_backups_restored"])
        self.assertFalse(report["original_usb_required"])
        self.assertFalse(report["plaintext_written_to_disk"])
        self.assertNotIn(m.EXPECTED_RECIPIENT, output.getvalue())


if __name__ == "__main__":
    unittest.main()
