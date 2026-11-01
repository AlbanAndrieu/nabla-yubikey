"""Offline contracts: no actual USB, TrueNAS or age invocation."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

SOURCE = (Path(__file__).resolve().parents[1] /
          "scripts/workstation/backup-usb-age-identity.py")
spec = importlib.util.spec_from_file_location("nabla_usb_age_backup_contract", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.source = base / "recovery-identity.txt"
        self.source.write_bytes(b"FAKE USB SECRET IDENTITY (NOT ACTUAL AGE KEY)")
        self.source.chmod(0o600)
        self.local_parent = base / "local"
        self.nfs_parent = base / "nfs"
        for parent in (self.local_parent, self.nfs_parent):
            parent.mkdir(mode=0o700)
        self.local = self.local_parent / "usb-recovery-backups"
        self.nfs = self.nfs_parent / "usb-recovery-backups"
        for name, value in (("LOCAL_PARENT", self.local_parent),
                            ("NFS_PARENT", self.nfs_parent),
                            ("LOCAL_DIR", self.local),
                            ("NFS_DIR", self.nfs)):
            mocker = patch.object(m, name, value)
            mocker.start()
            self.addCleanup(mocker.stop)

    def helper(self, *, valid=True):
        return SimpleNamespace(
            inspect=(lambda: (
                ("USB_LUKS_MOUNT_MATCHED",
                 "USB_EXPECTED_EXT4_MOUNT_PRESENT",
                 "USB_IDENTITY_METADATA_PRESENT") if valid else
                ("USB_LUKS_UUID_NOT_ENUMERATED", "NOT_CHECKED", "NOT_CHECKED")
            )),
            expected_mount=lambda: self.source.parent,
        )

    def alternate_devices(self):
        original_stat = Path.stat
        def patched_stat(path, *args, **kwargs):
            original = original_stat(path, *args, **kwargs)
            if path != m.NFS_DIR:
                return original
            values = [getattr(original, field) for field in
                      ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid",
                       "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")]
            values[2] += 800
            return os.stat_result(values)
        return patched_stat

    def test_check_does_not_read_or_back_up_secret(self):
        with patch.object(m, "preflight", return_value=("BACKUP_PREFLIGHT_READY", self.source)), \
             patch.object(m, "backup") as runner, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 0)
        runner.assert_not_called()
        report = json.loads(out.getvalue())
        self.assertFalse(report["encrypted_copy_local_and_nfs_verified"])
        self.assertFalse(report["encrypted_backup_restoration_verified"])
        self.assertFalse(report["raw_usb_private_identity_written_to_destinations"])

    def test_write_requires_explicit_approval(self):
        with redirect_stderr(io.StringIO()):
            for args in (["--backup"],
                         ["--backup", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as e:
                    m.main(args)
                self.assertEqual(e.exception.code, 2)

    def test_missing_or_untrusted_usb_refuses_before_nfs_check(self):
        with patch.object(m, "usb_module", return_value=self.helper(valid=False)), \
             patch.object(m, "nfs_mounted") as mount:
            self.assertEqual(m.preflight()[0], "USB_IDENTITY_UNVERIFIED")
        mount.assert_not_called()

    def test_wrong_nfs_export_refused(self):
        with patch.object(m, "usb_module", return_value=self.helper()), \
             patch.object(m, "nfs_mounted", return_value=False):
            self.assertEqual(m.preflight()[0], "NFS_EXPORT_UNVERIFIED")

    def test_existing_ciphertext_refused(self):
        self.local.mkdir(mode=0o700)
        (self.local / "usb-recovery-identity-old.age").write_bytes(b"encrypted")
        with patch.object(m, "usb_module", return_value=self.helper()), \
             patch.object(m, "nfs_mounted", return_value=True):
            self.assertEqual(m.preflight()[0], "EXISTING_BACKUP_NEEDS_REVIEW")

    def test_private_directories_must_be_mode_0700(self):
        self.local.mkdir(mode=0o700)
        self.assertTrue(m.directory_trusted(self.local, private=True))
        self.local.chmod(0o755)
        self.assertFalse(m.directory_trusted(self.local, private=True))

    def test_symlink_destination_untrusted(self):
        self.local.symlink_to(self.nfs_parent, target_is_directory=True)
        self.assertEqual(m.scan_dir(self.local), "UNTRUSTED")

    def test_source_identity_must_be_regular_owned_0600(self):
        fd, before = m.source_open(self.source)
        try:
            self.assertTrue(m.unchanged(fd, before))
        finally:
            os.close(fd)
        self.source.chmod(0o640)
        with self.assertRaises(ValueError):
            m.source_open(self.source)

    def test_source_symlink_refused(self):
        path = self.source.parent / "link"
        path.symlink_to(self.source)
        with self.assertRaises(ValueError):
            m.source_open(path)

    def test_existing_destination_cannot_be_overwritten(self):
        self.local.mkdir(mode=0o700)
        temp = self.local / ".pending"
        published = self.local / "usb-recovery-identity-original.age"
        temp.write_bytes(b"new encrypted bytes")
        published.write_bytes(b"old encrypted bytes")
        with self.assertRaises(FileExistsError):
            m.publish(temp, published)
        self.assertEqual(published.read_bytes(), b"old encrypted bytes")

    def test_stage_copy_and_digest_are_identical(self):
        self.nfs.mkdir(mode=0o700)
        original = self.local_parent / "encrypted.age"
        original.write_bytes(b"age-encryption.org/v1\n" + b"fake" * 80)
        stage = m.stage_copy(original, self.nfs)
        try:
            self.assertEqual(m.digest(original), m.digest(stage))
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o600)
        finally:
            stage.unlink(missing_ok=True)

    def test_backup_only_publishes_two_identical_mock_ciphertexts(self):
        encrypted = b"age-encryption.org/v1\n" + b"CIPHERTEXT" * 28
        calls = []
        def fake_age(cmd, **kwargs):
            calls.append((cmd, kwargs))
            self.assertEqual(cmd[:2], ["age", "-p"])
            self.assertNotIn(str(self.source), cmd)
            Path(cmd[3]).write_bytes(encrypted)
            return SimpleNamespace(returncode=0)
        with patch.object(m, "preflight",
                          return_value=("BACKUP_PREFLIGHT_READY", self.source)), \
             patch.object(Path, "stat", self.alternate_devices()), \
             patch.object(m.subprocess, "run", side_effect=fake_age):
            self.assertEqual(m.backup(self.source),
                             "ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL")
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(calls[0][1]["stdin"], int)
        names = []
        for dest in (self.local, self.nfs):
            archives = list(dest.glob(m.PATTERN))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_bytes(), encrypted)
            self.assertNotIn(self.source.read_bytes(), archives[0].read_bytes())
            self.assertEqual(list(dest.glob(".pending*")), [])
            names.append(archives[0].name)
        self.assertEqual(names[0], names[1])

    def test_age_encryption_failure_leaves_no_published_backup(self):
        with patch.object(m, "preflight",
                          return_value=("BACKUP_PREFLIGHT_READY", self.source)), \
             patch.object(Path, "stat", self.alternate_devices()), \
             patch.object(m.subprocess, "run",
                          return_value=SimpleNamespace(returncode=2)):
            self.assertEqual(m.backup(self.source), "ENCRYPTION_FAILED")
        for dest in (self.local, self.nfs):
            self.assertEqual(list(dest.iterdir()), [])

    def test_no_terminal_refuses_secret_operation(self):
        with patch.object(m, "preflight",
                          return_value=("BACKUP_PREFLIGHT_READY", self.source)), \
             patch.object(m, "backup") as runner, \
             patch.object(m.sys.stdin, "isatty", return_value=False), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--backup", "--acknowledge", m.ACK]), 3)
        runner.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["state"],
                         "INTERACTIVE_TERMINAL_REQUIRED")


if __name__ == "__main__":
    unittest.main()
