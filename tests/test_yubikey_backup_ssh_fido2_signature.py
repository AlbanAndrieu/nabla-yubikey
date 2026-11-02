"""Hermetic contracts for existing backup SSH-FIDO2 local signing proof."""
from __future__ import annotations
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/verify-yubikey-backup-ssh-fido2-signature.py"
spec = importlib.util.spec_from_file_location("yubi_backup_fido2_signature", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.key, self.pub = mod.paths(self.home)
        # Create BOTH directories with explicit 0700 permissions.
        # Path.mkdir(parents=True) uses default permissions for parents,
        # which yields .ssh=0755 under a typical umask and invalidates tests.
        (self.home / ".ssh").mkdir(mode=0o700)
        self.key.parent.mkdir(mode=0o700)
        self.assertEqual(stat.S_IMODE((self.home / ".ssh").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.key.parent.stat().st_mode), 0o700)
        self.key.write_text("fake private handle, never an actual key")
        self.key.chmod(0o600)
        self.pub.write_text("sk-ssh-ed25519@openssh.com AAAAFAKEBASE64 backup\n")

    def fingerprint(self, expected=True):
        sha = mod.FINGERPRINT if expected else "SHA256:different"
        return subprocess.CompletedProcess([], 0, f"256 {sha} test (ED25519-SK)\n", "")

    def test_readiness_checks_exact_public_fingerprint(self):
        with patch.object(mod.shutil, "which", return_value="/usr/bin/ssh-keygen"), \
             patch.object(mod.subprocess, "run", return_value=self.fingerprint()) as runner:
            self.assertEqual(mod.local_state(self.home), "EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE")
            self.assertEqual(runner.call_args.args[0], ["ssh-keygen", "-lf", str(self.pub)])
            self.assertEqual(runner.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_readiness_rejects_wrong_fingerprint(self):
        with patch.object(mod.shutil, "which", return_value="/bin/ssh-keygen"), \
             patch.object(mod.subprocess, "run", return_value=self.fingerprint(False)):
            self.assertEqual(mod.local_state(self.home), "UNEXPECTED_PUBLIC_KEY_FINGERPRINT")

    def test_readiness_never_contacts_card(self):
        with patch.object(mod.shutil, "which", return_value="/bin/tool"), \
             patch.object(mod.subprocess, "run", return_value=self.fingerprint()) as runner:
            self.assertEqual(mod.local_state(self.home), "EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE")
        self.assertEqual(runner.call_count, 1)

    def test_intermediate_ssh_directory_must_reject_group_read_permission(self):
        # Fail closed even when the leaf key directory itself is mode 0700.
        (self.home / ".ssh").chmod(0o750)
        with patch.object(mod.shutil, "which", return_value="/bin/tool"), \
             patch.object(mod.subprocess, "run") as runner:
            self.assertEqual(mod.local_state(self.home), "UNTRUSTED_KEY_DIRECTORY")
            runner.assert_not_called()

    def test_untrusted_directory_file_and_symlink_rejected(self):
        with patch.object(mod.shutil, "which", return_value="/bin/tool"):
            self.key.parent.chmod(0o755)
            self.assertEqual(mod.local_state(self.home), "UNTRUSTED_KEY_DIRECTORY")
            self.key.parent.chmod(0o700)
            self.key.chmod(0o644)
            self.assertEqual(mod.local_state(self.home), "UNTRUSTED_KEY_FILE")
            self.key.chmod(0o600)
            self.pub.unlink()
            self.pub.symlink_to(self.key)
            self.assertEqual(mod.local_state(self.home), "UNTRUSTED_KEY_FILE")

    def test_invalid_public_key_rejected_before_ssh_keygen(self):
        self.pub.write_text("ssh-rsa AAAA\n")
        with patch.object(mod.shutil, "which", return_value="/bin/tool"), \
             patch.object(mod.subprocess, "run") as runner:
            self.assertEqual(mod.local_state(self.home), "PUBLIC_KEY_INVALID")
            runner.assert_not_called()

    def test_no_tty_blocks_cryptographic_operation(self):
        with patch.object(mod, "local_state", return_value="EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"), \
             patch.object(mod, "only_backup_card") as card:
            self.assertEqual(mod.roundtrip(self.home, tty=False), "INTERACTIVE_TTY_REQUIRED")
            card.assert_not_called()

    def test_wrong_card_blocks_cryptographic_operation(self):
        with patch.object(mod, "local_state", return_value="EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"), \
             patch.object(mod, "only_backup_card", return_value=False), \
             patch.object(mod.subprocess, "run") as runner:
            self.assertEqual(mod.roundtrip(self.home, tty=True), "EXPECTED_ONE_BACKUP_YUBIKEY")
            runner.assert_not_called()

    def test_sign_then_verify_synthetic_message_only(self):
        seen = []
        def fake_run(args, **kwargs):
            seen.append((args, kwargs))
            if args[1:3] == ["-Y", "sign"]:
                message = Path(args[-1])
                self.assertEqual(message.read_text(), "Nabla disposable SSH FIDO2 proof v1\n")
                Path(str(message) + ".sig").write_text("synthetic signature")
                return SimpleNamespace(returncode=0)
            if args[1:3] == ["-Y", "verify"]:
                self.assertEqual(kwargs["stdin"].read(),
                                 b"Nabla disposable SSH FIDO2 proof v1\n")
                self.assertIn(mod.NAMESPACE, args)
                return SimpleNamespace(returncode=0)
            raise AssertionError("unexpected command")
        with patch.object(mod, "local_state", return_value="EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"), \
             patch.object(mod, "only_backup_card", return_value=True), \
             patch.object(mod.subprocess, "run", side_effect=fake_run):
            state = mod.roundtrip(self.home, tty=True)
        self.assertEqual(state, "LOCAL_HARDWARE_SSHSIG_VERIFIED_REMOTE_LOGIN_NOT_TESTED")
        self.assertEqual(len(seen), 2)
        self.assertFalse(list(self.home.rglob("*.sig")))
        self.assertFalse((self.home / ".ssh" / "authorized_keys").exists())

    def test_sign_failure_no_retry_or_verify(self):
        with patch.object(mod, "local_state", return_value="EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"), \
             patch.object(mod, "only_backup_card", return_value=True), \
             patch.object(mod.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as runner:
            self.assertEqual(mod.roundtrip(self.home, tty=True),
                             "FIDO2_SIGNATURE_FAILED_NO_RETRY")
            self.assertEqual(runner.call_count, 1)

    def test_verification_failure_is_not_success(self):
        def fake_run(args, **kwargs):
            if args[1:3] == ["-Y", "sign"]:
                Path(str(args[-1]) + ".sig").write_text("bad signature")
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=1)
        with patch.object(mod, "local_state", return_value="EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"), \
             patch.object(mod, "only_backup_card", return_value=True), \
             patch.object(mod.subprocess, "run", side_effect=fake_run):
            self.assertEqual(mod.roundtrip(self.home, tty=True),
                             "FIDO2_SIGNATURE_VERIFICATION_FAILED")

    def test_ssh_serial_guard_uses_no_card_data_in_output(self):
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, mod.SERIAL + "\n", "private never logged")):
            self.assertFalse(mod.only_backup_card())
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, mod.SERIAL + "\n", "")) as runner:
            self.assertTrue(mod.only_backup_card())
            self.assertEqual(runner.call_args.args[0], ["ykman", "list", "--serials"])

    def test_check_and_sign_modes_are_explicit(self):
        with patch.object(mod, "roundtrip") as signer, redirect_stderr(io.StringIO()):
            for args in (["--sign"], ["--sign", "--acknowledge", "no"],
                         ["--check", "--acknowledge", "x"], ["--enroll"]):
                with self.assertRaises(SystemExit) as ctx:
                    mod.main(args)
                self.assertEqual(ctx.exception.code, 2)
            signer.assert_not_called()

    def test_check_json_never_claims_remote_login(self):
        with patch.dict(os.environ, {"HOME": str(self.home)}), \
             patch.object(mod, "local_state", return_value="EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(mod.main(["--check"]), 0)
        self.assertIn('"remote_login_verified": false', output.getvalue())
        self.assertNotIn(str(self.home), output.getvalue())


if __name__ == "__main__":
    unittest.main()
