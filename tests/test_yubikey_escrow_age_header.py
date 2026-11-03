"""Hermetic checks for bounded age archive header classification, no real escrow."""
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-yubikey-escrow-age-header.py"
spec = importlib.util.spec_from_file_location("nabla_escrow_age_header", SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def synthetic_header(kind: str = "X25519") -> bytes:
    return (b"age-encryption.org/v1\n" + b"-> " + kind.encode("ascii") +
            b" fixture-argument\n" + b"A" * 43 + b"\n" +
            b"--- " + b"B" * 43 + b"\n" + b"synthetic encrypted payload")


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "super-secret-age-identity.age"
        self.archive.write_bytes(synthetic_header())
        self.archive.chmod(0o600)
        self.base = SimpleNamespace(check_mount=lambda: "EXPECTED_NFS_EXPORT_MOUNTED",
                                    local_expected_filename=lambda directory:
                                        ("SOURCE_UNIQUE_AGE_FOUND", self.archive.name),
                                    LOCAL_SOURCE=self.root)
        def secure_open(path):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            return fd, os.fstat(fd)
        def unchanged(fd, original):
            info = os.fstat(fd)
            return info.st_size == original.st_size and info.st_mtime_ns == original.st_mtime_ns
        self.comp = SimpleNamespace(secure_open=secure_open, unchanged=unchanged)
        self.loader = lambda name: self.base if name.startswith("inspect-") else self.comp

    def test_age_x25519_opaque_hint(self):
        self.assertEqual(m.classify_header(synthetic_header()),
                         ("AGE_V1_HEADER_TYPE_HINT_ONLY", "X25519_IDENTITY", 1))

    def test_age_scrypt_passphrase_hint(self):
        self.assertEqual(m.classify_header(synthetic_header("scrypt")),
                         ("AGE_V1_HEADER_TYPE_HINT_ONLY", "PASSPHRASE_SCRYPT", 1))

    def test_unknown_plugin_type_does_not_disclose_name(self):
        state, family, count = m.classify_header(synthetic_header("age-plugin-private"))
        self.assertEqual((state, family, count),
                         ("AGE_V1_HEADER_TYPE_HINT_ONLY", "PLUGIN_OR_OTHER_IDENTITY", 1))

    def test_armored_header_never_assumed_to_be_binary(self):
        self.assertEqual(m.classify_header(b"-----BEGIN AGE ENCRYPTED FILE-----\nxxxx"),
                         ("ARMORED_AGE_UNINSPECTED", None, None))

    def test_truncated_and_invalid_header_fail_closed(self):
        for bad in (b"not age", b"age-encryption.org/v1\n-> X25519 xyz\n",
                    b"age-encryption.org/v1\n--- bad\n", b"age-encryption.org/v1\n-> X25519 xyz\n--- broken\n"):
            with self.subTest(bad=bad[:20]):
                self.assertIsNone(m.classify_header(bad)[1])

    def test_preflight_never_reads_archive_bytes(self):
        with patch.object(m, "load", side_effect=self.loader), \
             patch.object(Path, "read_bytes") as reader:
            self.assertEqual(m.preflight(), ("HEADER_INSPECTION_READY", self.archive))
            reader.assert_not_called()

    def test_preflight_refuses_nfs_mount_mismatch(self):
        self.base.check_mount = lambda: "UNEXPECTED_NFS_EXPORT"
        with patch.object(m, "load", side_effect=self.loader):
            state, path = m.preflight()
        self.assertEqual(state, "NFS_EXPORT_UNVERIFIED")
        self.assertIsNone(path)

    def test_preflight_rejects_group_readable_archive(self):
        self.archive.chmod(0o640)
        with patch.object(m, "load", side_effect=self.loader):
            self.assertEqual(m.preflight()[0], "AGE_SOURCE_UNTRUSTED")

    def test_check_mode_no_header_read(self):
        with patch.object(m, "load", side_effect=self.loader), \
             patch.object(m, "inspect") as inspector, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--check"]), 0)
        inspector.assert_not_called()
        parsed = json.loads(output.getvalue())
        self.assertEqual(parsed["state"], "HEADER_INSPECTION_READY")
        self.assertFalse(parsed["encrypted_header_read_attempted"])
        self.assertFalse(parsed["real_escrow_restoration_verified"])

    def test_inspect_requires_exact_ack(self):
        with redirect_stderr(io.StringIO()), patch.object(m, "inspect") as inspector:
            for args in ([], ["--inspect"], ["--inspect", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as exit_ctx:
                    m.main(args)
                self.assertEqual(exit_ctx.exception.code, 2)
            inspector.assert_not_called()

    def test_live_read_of_synthetic_header_discloses_no_private_content(self):
        with patch.object(m, "load", side_effect=self.loader), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(["--inspect", "--acknowledge", m.ACK]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["recipient_family_hint"], "X25519_IDENTITY")
        self.assertEqual(result["stanza_count"], 1)
        self.assertTrue(result["encrypted_header_read_attempted"])
        self.assertFalse(result["archive_decryption_attempted"])
        self.assertFalse(result["recovery_method_verified"])
        self.assertNotIn(self.archive.name, output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("fixture-argument", output.getvalue())

    def test_budget_is_bounded_to_first_8192_bytes(self):
        self.archive.write_bytes(synthetic_header() + b"Z" * 22000)
        self.archive.chmod(0o600)
        reads = []
        original = os.read
        def record(fd, n):
            reads.append(n)
            return original(fd, n)
        with patch.object(m, "load", side_effect=self.loader), \
             patch.object(m.os, "read", side_effect=record):
            status, family, count = m.inspect(self.archive)
        self.assertEqual(status, "AGE_V1_HEADER_TYPE_HINT_ONLY")
        self.assertEqual(family, "X25519_IDENTITY")
        self.assertLessEqual(sum(reads), m.HEADER_LIMIT)

    def test_multiple_recipient_classes_are_ambiguous(self):
        data = (b"age-encryption.org/v1\n-> X25519 a\nA\n"
                b"-> ssh-ed25519 b\nB\n--- " + b"C" * 43 + b"\n")
        self.assertEqual(m.classify_header(data),
                         ("AGE_V1_HEADER_TYPE_HINT_ONLY", "MIXED_OR_MULTIPLE_METHODS", 2))


if __name__ == "__main__":
    unittest.main()
