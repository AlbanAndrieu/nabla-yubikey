"""Hermetic contracts for USB age public-recipient attestation.

All identity data in these tests are synthetic; age-keygen is mocked.
No real key, USB volume, disk or network access is used.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/workstation/verify-age-escrow-usb-recipient.py"
spec = importlib.util.spec_from_file_location("usb_age_public_recipient_attestation", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.secret = self.root / "recovery-identity.txt"
        self.secret.write_bytes(b"SYNTHETIC PRIVATE FIXTURE NOT A REAL AGE KEY")
        self.secret.chmod(0o600)

    def cmp_helper(self):
        def secure(path):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            return fd, os.fstat(fd)
        return SimpleNamespace(
            secure_open=secure,
            unchanged=lambda fd, before: (
                os.fstat(fd).st_size == before.st_size and
                os.fstat(fd).st_mtime_ns == before.st_mtime_ns),
        )

    def test_check_only_inspects_existing_mount_and_metadata(self):
        identity = SimpleNamespace(
            inspect=lambda: ("USB_LUKS_MOUNT_MATCHED",
                             "USB_EXPECTED_EXT4_MOUNT_PRESENT",
                             "USB_IDENTITY_METADATA_PRESENT"),
            expected_mount=lambda: self.root,
        )
        with patch.object(m, "load", return_value=identity), \
             patch.object(m, "verify_public_recipient") as verifier, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]), 0)
        verifier.assert_not_called()
        record = json.loads(out.getvalue())
        self.assertEqual(record["state"], "USB_IDENTITY_READY_FOR_RECIPIENT_CHECK")
        self.assertFalse(record["private_identity_read_attempted"])
        self.assertIsNone(record["public_recipient_matches_historical"])
        self.assertFalse(record["decryption_attempted"])

    def test_missing_usb_fails_before_secret_access(self):
        helper = SimpleNamespace(
            inspect=lambda: ("USB_LUKS_UUID_NOT_ENUMERATED",
                             "NOT_CHECKED", "NOT_CHECKED"))
        with patch.object(m, "load", return_value=helper), \
             patch.object(m, "verify_public_recipient") as verifier, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--verify", "--acknowledge", m.ACK]), 3)
        verifier.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["state"], "USB_IDENTITY_PREFLIGHT_FAILED")

    def test_approval_is_mandatory_before_secret_read(self):
        with patch.object(m, "verify_public_recipient") as verifier, \
             redirect_stderr(io.StringIO()):
            for args in ([], ["--verify"], ["--verify", "--acknowledge", "wrong"],
                         ["--check", "--acknowledge", m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                    m.main(args)
                self.assertEqual(error.exception.code, 2)
        verifier.assert_not_called()

    def test_key_derivation_receives_fd_only_via_stdin_no_path_or_secret_in_argv(self):
        helper = self.cmp_helper()
        response = SimpleNamespace(returncode=0,
                        stdout=(m.EXPECTED_RECIPIENT + "\n").encode())
        with patch.object(m, "load", return_value=helper), \
             patch.object(m.subprocess, "run", return_value=response) as run:
            state = m.verify_public_recipient(self.secret)
        self.assertEqual(state, "USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL")
        command = run.call_args.args[0]
        self.assertEqual(command, ["age-keygen", "-y"])
        self.assertIsInstance(run.call_args.kwargs["stdin"], int)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn(str(self.secret), repr(command))
        self.assertNotIn("SYNTHETIC PRIVATE FIXTURE", repr(run.call_args))

    def test_different_public_recipient_is_not_a_match(self):
        other = "age1" + "q" * 58
        with patch.object(m, "load", return_value=self.cmp_helper()), \
             patch.object(m.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0,
                                                      stdout=(other+"\n").encode())):
            self.assertEqual(m.verify_public_recipient(self.secret),
                             "USB_PUBLIC_RECIPIENT_MISMATCH")

    def test_empty_invalid_or_multiple_public_lines_fail_closed(self):
        for output in (b"", b"not-age\n",
                       (m.EXPECTED_RECIPIENT + "\n" + m.EXPECTED_RECIPIENT + "\n").encode(),
                       b"\xff"):
            with self.subTest(output=output[:8]), \
                 patch.object(m, "load", return_value=self.cmp_helper()), \
                 patch.object(m.subprocess, "run",
                              return_value=SimpleNamespace(returncode=0, stdout=output)):
                self.assertEqual(m.verify_public_recipient(self.secret),
                                 "USB_RECIPIENT_DERIVATION_UNAVAILABLE")

    def test_derivation_error_never_exposes_identity(self):
        with patch.object(m, "load", return_value=self.cmp_helper()), \
             patch.object(m.subprocess, "run",
                          return_value=SimpleNamespace(returncode=1, stdout=b"")):
            self.assertEqual(m.verify_public_recipient(self.secret),
                             "USB_RECIPIENT_DERIVATION_UNAVAILABLE")

    def test_symlink_private_identity_is_refused_without_opening(self):
        linked = self.root / "linked-recovery.txt"
        linked.symlink_to(self.secret)
        # Real repository helper securely rejects symlinks.
        def secure(path):
            raise ValueError("refuse symlink")
        with patch.object(m, "load", return_value=SimpleNamespace(secure_open=secure)), \
             patch.object(m.subprocess, "run") as run:
            self.assertEqual(m.verify_public_recipient(linked),
                             "USB_RECIPIENT_DERIVATION_UNAVAILABLE")
        run.assert_not_called()

    def test_loose_identity_mode_is_refused_before_age_keygen(self):
        self.secret.chmod(0o640)
        with patch.object(m, "load", return_value=self.cmp_helper()), \
             patch.object(m.subprocess, "run") as run:
            self.assertEqual(m.verify_public_recipient(self.secret),
                             "USB_IDENTITY_METADATA_UNVERIFIED")
        run.assert_not_called()

    def test_identity_changed_while_deriving_is_not_accepted(self):
        fake = self.cmp_helper()
        fake.unchanged = lambda fd, info: False
        with patch.object(m, "load", return_value=fake), \
             patch.object(m.subprocess, "run",
                          return_value=SimpleNamespace(
                              returncode=0,
                              stdout=(m.EXPECTED_RECIPIENT+"\n").encode())):
            self.assertEqual(m.verify_public_recipient(self.secret),
                             "USB_IDENTITY_CHANGED_DURING_READ")

    def test_positive_result_does_not_claim_decryption_or_recovery(self):
        with patch.object(m, "preflight", return_value=("USB_IDENTITY_READY", self.secret)), \
             patch.object(m, "verify_public_recipient",
                          return_value="USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL"), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--verify", "--acknowledge", m.ACK]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["status"], "NO-GO")
        self.assertTrue(report["private_identity_read_attempted"])
        self.assertTrue(report["public_recipient_matches_historical"])
        self.assertFalse(report["private_identity_disclosed"])
        self.assertFalse(report["public_recipient_disclosed"])
        self.assertFalse(report["decryption_attempted"])
        self.assertFalse(report["restore_verified"])
        self.assertNotIn(str(self.secret), out.getvalue())
        self.assertNotIn(m.EXPECTED_RECIPIENT, out.getvalue())

    def test_missing_age_keygen_fails_closed(self):
        with patch.object(m, "load", return_value=self.cmp_helper()), \
             patch.object(m.subprocess, "run", side_effect=FileNotFoundError()):
            self.assertEqual(m.verify_public_recipient(self.secret),
                             "USB_RECIPIENT_DERIVATION_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
