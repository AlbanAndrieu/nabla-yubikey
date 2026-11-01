"""Hermetic, read-only LUKS UUID enumeration tests; no real USB or secrets."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SRC = (Path(__file__).resolve().parents[1] /
       "scripts/workstation/diagnose-age-escrow-usb-presence.py")
spec = importlib.util.spec_from_file_location("age_escrow_usb_presence", SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def disk(*, uuid=None, fstype="crypto_LUKS", children=None, kind="part"):
    part = {"name": "/dev/sdz1", "type": kind, "fstype": fstype,
            "uuid": uuid if uuid is not None else m.EXPECTED_LUKS_UUID,
            "mountpoints": [None]}
    if children is not None:
        part["children"] = children
    return {"blockdevices": [{"name": "/dev/sdz", "type": "disk",
                              "children": [part]}]}


class Contracts(unittest.TestCase):
    def test_missing_uuid_is_not_misreported_as_missing_physical_usb(self):
        data = disk(uuid="another-historical-uuid")
        self.assertEqual(m.assess(data, False), "ESCROW_UUID_NOT_ENUMERATED")

    def test_present_partition_without_udev_symlink_is_separate_state(self):
        self.assertEqual(m.assess(disk(), False),
                         "ESCROW_LUKS_PRESENT_UDEV_LINK_MISSING")

    def test_locked_matching_luks_partition(self):
        self.assertEqual(m.assess(disk(), True), "ESCROW_LUKS_LOCKED")

    def test_unlocked_usb_not_mounted(self):
        child = {"name": "/dev/mapper/escrow", "type": "crypt",
                 "fstype": "ext4", "mountpoints": [None]}
        self.assertEqual(m.assess(disk(children=[child]), True),
                         "ESCROW_LUKS_UNLOCKED_NOT_MOUNTED")

    def test_unlocked_and_mounted_crypt_mapping(self):
        child = {"name": "/dev/mapper/escrow", "type": "crypt",
                 "fstype": "ext4", "mountpoints": ["/run/media/u/private"]}
        self.assertEqual(m.assess(disk(children=[child]), True),
                         "ESCROW_LUKS_UNLOCKED_MOUNTED")

    def test_same_uuid_unexpected_format_is_not_trusted(self):
        self.assertEqual(m.assess(disk(fstype="ext4"), True),
                         "ESCROW_UUID_UNEXPECTED_FSTYPE")

    def test_wrong_device_type_fails_closed(self):
        self.assertEqual(m.assess(disk(kind="loop"), True),
                         "ESCROW_UUID_UNEXPECTED_DEVICE_TYPE")

    def test_multiple_matches_are_ambiguous(self):
        data = disk()
        data["blockdevices"].append(
            {"name": "/dev/sdy1", "type": "part", "fstype": "crypto_LUKS",
             "uuid": m.EXPECTED_LUKS_UUID})
        self.assertEqual(m.assess(data, True), "ESCROW_UUID_AMBIGUOUS")

    def test_multiple_unlocked_mappers_are_ambiguous(self):
        child = {"type": "crypt", "mountpoints": []}
        self.assertEqual(m.assess(disk(children=[child, child]), True),
                         "ESCROW_MAPPING_AMBIGUOUS")

    def test_malformed_and_excessive_output_is_rejected(self):
        for invalid in (None, {}, {"blockdevices": [True]},
                        {"blockdevices": [{"children": [None]}]},
                        {"blockdevices": [{}] * 257}):
            with self.subTest(invalid=repr(invalid)[:30]):
                with self.assertRaises((TypeError, ValueError)):
                    m.enumerate_nodes(invalid)

    def test_invocation_is_single_redacted_lsblk_read(self):
        reply = SimpleNamespace(returncode=0, stdout=json.dumps(disk()).encode())
        with patch.object(m.subprocess, "run", return_value=reply) as runner, \
             patch.object(m, "UUID_LINK", SimpleNamespace(is_block_device=lambda: True)), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 0)
        invoked = runner.call_args.args[0]
        self.assertEqual(invoked, ["lsblk", "-J", "-p", "-o",
                                   "NAME,TYPE,FSTYPE,UUID,MOUNTPOINTS"])
        self.assertEqual(runner.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(runner.call_count, 1)
        report = json.loads(out.getvalue())
        self.assertEqual(report["state"], "ESCROW_LUKS_LOCKED")
        # Compare actual identifiers/paths, not generic words appearing in
        # deliberately descriptive JSON field names.
        for sensitive in (m.EXPECTED_LUKS_UUID, "/dev/sdz", "/dev/mapper"):
            self.assertNotIn(sensitive, out.getvalue())
        self.assertFalse(report["private_age_identity_read"])
        self.assertFalse(report["luks_unlock_attempted"])
        self.assertFalse(report["disk_mutation_performed"])

    def test_private_mountpoint_and_mapper_are_redacted(self):
        secret_mount = "/run/media/testuser/MY_PRIVATE_USB_ESCROW"
        secret_mapper = "/dev/mapper/my_private_recovery_key"
        child = {"name": secret_mapper, "type": "crypt", "fstype": "ext4",
                 "mountpoints": [secret_mount]}
        inventory = disk(children=[child])
        reply = SimpleNamespace(returncode=0,
                                stdout=json.dumps(inventory).encode())
        with patch.object(m.subprocess, "run", return_value=reply), \
             patch.object(m, "UUID_LINK",
                          SimpleNamespace(is_block_device=lambda: True)), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["state"], "ESCROW_LUKS_UNLOCKED_MOUNTED")
        self.assertFalse(report["device_paths_disclosed"])
        self.assertFalse(report["device_identifiers_disclosed"])
        for identifier in (secret_mount, secret_mapper, m.EXPECTED_LUKS_UUID):
            self.assertNotIn(identifier, out.getvalue())

    def test_empty_inventory_is_nonzero_and_no_claim_of_absent_usb(self):
        reply = SimpleNamespace(returncode=0, stdout=b'{"blockdevices":[]}')
        with patch.object(m.subprocess, "run", return_value=reply), \
             patch.object(m, "UUID_LINK", SimpleNamespace(is_block_device=lambda: False)), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 3)
        self.assertEqual(json.loads(out.getvalue())["state"],
                         "ESCROW_UUID_NOT_ENUMERATED")

    def test_lsblk_unavailable_fails_closed(self):
        with patch.object(m.subprocess, "run", side_effect=FileNotFoundError), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 3)
        self.assertEqual(json.loads(out.getvalue())["state"],
                         "LSBLK_INVENTORY_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
