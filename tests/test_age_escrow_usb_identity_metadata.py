"""Hermetic read-only SanDisk age recovery identity metadata contracts."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = (Path(__file__).resolve().parents[1] /
          "scripts/workstation/inspect-age-escrow-usb-identity.py")
spec = importlib.util.spec_from_file_location("age_escrow_usb_identity_metadata", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.mount = Path(self.temp.name) / "run" / "media" / "owner" / "NABLA_ESCROW"
        self.key = self.mount / "age-escrow" / "recovery-identity.txt"
        self.key.parent.mkdir(parents=True)
        self.key.write_bytes(b"SYNTHETIC PRIVATE IDENTITY; NOT REAL")
        self.key.chmod(0o600)

    def block_inventory(self, uuid=None, filesystem="crypto_LUKS",
                        child_mount=True, child_fstype="ext4"):
        crypt = {"type": "crypt", "fstype": child_fstype,
                 "name": "/dev/mapper/fake-secret",
                 "mountpoints": [str(self.mount)] if child_mount else [None]}
        parent = {"name": "/dev/fake1", "type": "part",
                  "fstype": filesystem, "uuid": uuid or m.LUKS_UUID,
                  "children": [crypt]}
        return {"blockdevices": [{"name": "/dev/fake", "type": "disk",
                                  "children": [parent]}]}

    def test_usb_parent_uuid_and_correct_ext4_mount_correlate(self):
        self.assertEqual(m.match_usb_mount(self.block_inventory(), self.mount),
                         "USB_LUKS_MOUNT_MATCHED")

    def test_unrelated_usb_cannot_substitute_for_expected_luks_uuid(self):
        self.assertEqual(m.match_usb_mount(
            self.block_inventory(uuid="00000000-0000-0000-0000-000000000000"),
            self.mount), "USB_LUKS_UUID_NOT_ENUMERATED")

    def test_luks_parent_has_to_be_crypto_luks(self):
        self.assertEqual(m.match_usb_mount(
            self.block_inventory(filesystem="ext4"), self.mount),
            "USB_LUKS_PARENT_UNVERIFIED")

    def test_child_mount_must_match_exact_expected_path(self):
        self.assertEqual(m.match_usb_mount(
            self.block_inventory(child_mount=False), self.mount),
            "USB_LUKS_MOUNT_UNVERIFIED")

    def test_non_ext4_mapping_is_not_trusted(self):
        self.assertEqual(m.match_usb_mount(
            self.block_inventory(child_fstype="nfs4"), self.mount),
            "USB_LUKS_MOUNT_UNVERIFIED")

    def test_path_metadata_requires_mode_0600(self):
        self.assertEqual(m.check_identity_metadata(self.mount),
                         "USB_IDENTITY_METADATA_PRESENT")
        self.key.chmod(0o640)
        self.assertEqual(m.check_identity_metadata(self.mount),
                         "USB_IDENTITY_METADATA_UNTRUSTED")

    def test_absent_identity_has_distinct_state(self):
        self.key.unlink()
        self.assertEqual(m.check_identity_metadata(self.mount),
                         "USB_IDENTITY_NOT_FOUND")

    def test_symlink_identity_not_followed(self):
        original = self.key.parent / "other"
        self.key.rename(original)
        self.key.symlink_to(original)
        self.assertEqual(m.check_identity_metadata(self.mount),
                         "USB_IDENTITY_METADATA_UNTRUSTED")

    def test_mount_parent_symlink_rejected(self):
        original = self.mount.parent / "NABLA_SAFE"
        self.mount.rename(original)
        self.mount.symlink_to(original, target_is_directory=True)
        self.assertEqual(m.check_identity_metadata(self.mount),
                         "USB_IDENTITY_PATH_UNTRUSTED")

    def test_no_archive_or_private_key_read_or_write(self):
        inventory = self.block_inventory()
        inv_response = SimpleNamespace(returncode=0,
                                       stdout=json.dumps(inventory).encode())
        mount_response = SimpleNamespace(returncode=0,
                         stdout=f"{self.mount} ext4\n")
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            return inv_response if args[0] == "lsblk" else mount_response
        with patch.object(m, "expected_mount", return_value=self.mount), \
             patch.object(m.subprocess, "run", side_effect=runner), \
             patch.object(Path, "read_bytes") as read, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 0)
        read.assert_not_called()
        self.assertEqual([x[0] for x in calls], ["lsblk", "findmnt"])
        report = json.loads(out.getvalue())
        self.assertEqual(report["identity_state"], "USB_IDENTITY_METADATA_PRESENT")
        self.assertFalse(report["identity_private_content_read"])
        self.assertFalse(report["decryption_attempted"])
        self.assertFalse(report["usb_mount_performed"])
        self.assertFalse(report["filesystem_write_performed"])
        self.assertFalse(report["restore_verified"])
        self.assertEqual(report["status"], "NO-GO")
        for forbidden in (str(self.mount), m.LUKS_UUID,
                          "/dev/mapper/fake-secret", "SYNTHETIC PRIVATE IDENTITY"):
            self.assertNotIn(forbidden, out.getvalue())

    def test_findmnt_failure_never_touches_identity(self):
        inv_response = SimpleNamespace(
            returncode=0, stdout=json.dumps(self.block_inventory()).encode())
        def runner(args, **kwargs):
            return (inv_response if args[0] == "lsblk"
                    else SimpleNamespace(returncode=1, stdout=""))
        with patch.object(m, "expected_mount", return_value=self.mount), \
             patch.object(m.subprocess, "run", side_effect=runner), \
             patch.object(m, "check_identity_metadata") as checker, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 3)
        checker.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["identity_state"],
                         "NOT_CHECKED")

    def test_duplicate_uuid_fails_closed(self):
        data = self.block_inventory()
        data["blockdevices"].append({"name": "/dev/fake-other",
                                      "type": "part", "fstype": "crypto_LUKS",
                                      "uuid": m.LUKS_UUID})
        self.assertEqual(m.match_usb_mount(data, self.mount),
                         "USB_LUKS_UUID_AMBIGUOUS")

    def test_malformed_inventory_is_refused(self):
        for invalid in (None, {}, {"blockdevices": [None]},
                        {"blockdevices": [{}] * 257}):
            with self.subTest(obj=str(invalid)[:20]):
                with self.assertRaises((ValueError, TypeError)):
                    m.walk_nodes(invalid)


if __name__ == "__main__":
    unittest.main()
