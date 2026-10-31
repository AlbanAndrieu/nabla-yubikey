"""Hermetic contracts: KeePassXC vault diagnosis without password or challenge."""
from __future__ import annotations

import importlib.util
import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-keepassxc-readonly.py"
spec = importlib.util.spec_from_file_location("keepassxc_readonly", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

AES = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")


def entry(kind: int, key: str, value: bytes) -> bytes:
    return bytes([kind]) + struct.pack("<I", len(key)) + key.encode() + struct.pack("<I", len(value)) + value


def kdbx4(kdf: bytes = ARGON2D, memory_mib: int = 64) -> bytes:
    params = (struct.pack("<H", 0x100) + entry(0x42, "$UUID", kdf)
              + entry(0x05, "M", struct.pack("<Q", memory_mib * 1024 * 1024))
              + entry(0x05, "I", struct.pack("<Q", 65)) + b"\x00")
    fields = (bytes([2]) + struct.pack("<I", 16) + AES
              + bytes([11]) + struct.pack("<I", len(params)) + params
              + bytes([0]) + struct.pack("<I", 4) + b"\r\n\r\n")
    return struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 1, 4) + fields + b"encrypted-payload"


class Vault:
    """Temporary home with Dropbox/vault.kdbx and a key file placed by the test."""

    def __init__(self, header: bytes = kdbx4(), keyfile_dir: str = ".local/share/keepassxc",
                 db_mode: int = 0o600, ini: str = "[SSHAgent]\nEnabled=true\n"):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        (self.home / "Dropbox").mkdir()
        db = self.home / "Dropbox/vault.kdbx"
        db.write_bytes(header)
        db.chmod(db_mode)
        (self.home / keyfile_dir).mkdir(parents=True, exist_ok=True)
        key = self.home / keyfile_dir / "vault.key"
        key.write_bytes(b"k" * 64)
        key.chmod(0o600)
        (self.home / ".config/keepassxc").mkdir(parents=True)
        (self.home / ".config/keepassxc/keepassxc.ini").write_text(ini)

    def snapshot(self, ykman_otp: str = "Slot 1: programmed\nSlot 2: programmed\n", devices: int = 1):
        def run(command, **kwargs):
            if command[:2] == ["ykman", "list"]:
                return SimpleNamespace(returncode=0, stdout="YubiKey 5 NFC Serial: 12345678\n" * devices)
            return SimpleNamespace(returncode=0, stdout=ykman_otp)
        out = io.StringIO()
        with patch.object(module, "HOME", self.home), \
             patch.object(module, "CLOUD_DIRS", (self.home / "Dropbox",)), \
             patch.dict(module.os.environ, {}, clear=True), \
             patch.object(module.shutil, "which", return_value="/usr/bin/x"), \
             patch.object(module.subprocess, "run", side_effect=run), \
             redirect_stdout(out):
            module.main([])
        return out.getvalue()

    def close(self):
        self.tmp.cleanup()


class KeepassxcContracts(unittest.TestCase):
    def report(self, vault: Vault, **kwargs) -> dict:
        try:
            raw = vault.snapshot(**kwargs)
            self.assertNotIn(str(vault.home), raw)
            self.assertNotIn("12345678", raw)
            return json.loads(raw)
        finally:
            vault.close()

    def test_header_parsed_without_password(self):
        header = module.parse_header(kdbx4(ARGON2ID, 256))
        self.assertEqual(header, {"version": "4.1", "cipher": "AES-256", "kdf": "Argon2id",
                                  "memory_mib": 256, "iterations": 65})
        self.assertIsNone(module.parse_header(b"not a vault"))
        self.assertIsNone(module.parse_header(kdbx4()[:20]))

    def test_go_with_advice_and_no_path_or_serial_leak(self):
        report = self.report(Vault())
        self.assertEqual(report["status"], "GO")
        self.assertEqual(report["blocking"], [])
        self.assertEqual(sorted(report["advice"]), ["KDF_MEMORY_BELOW_256MIB", "KDF_NOT_ARGON2ID"])
        self.assertFalse(report["database_unlock_verified"])

    def test_argon2id_256_has_no_kdf_advice(self):
        report = self.report(Vault(header=kdbx4(ARGON2ID, 256)))
        self.assertNotIn("KDF_NOT_ARGON2ID", report["advice"])
        self.assertNotIn("KDF_MEMORY_BELOW_256MIB", report["advice"])

    def test_keyfile_in_cloud_or_next_to_vault_is_blocking(self):
        report = self.report(Vault(keyfile_dir="Dropbox"))
        self.assertIn("KEYFILE_LEFT_IN_CLOUD", report["blocking"])
        self.assertEqual(module.keyfile_location(Path("/v/db.kdbx"), Path("/v/db.key")), "WITH_DATABASE")
        with patch.object(module, "CLOUD_DIRS", (Path("/cloud"),)):
            self.assertEqual(module.keyfile_location(None, Path("/cloud/db.key")), "IN_CLOUD")
        self.assertEqual(module.keyfile_location(Path("/v/db.kdbx"), Path("/v/db.key")), "WITH_DATABASE")

    def test_world_readable_vault_and_missing_slot2_are_blocking(self):
        report = self.report(Vault(db_mode=0o644))
        self.assertIn("DATABASE_MODE_NOT_600", report["blocking"])
        report = self.report(Vault(), ykman_otp="Slot 1: programmed\nSlot 2: empty\n")
        self.assertIn("YUBIKEY_SLOT2_EMPTY", report["blocking"])
        report = self.report(Vault(), devices=2)
        self.assertIn("YUBIKEY_SLOT2_DEVICE_COUNT_2", report["blocking"])
        report = self.report(Vault(), ykman_otp="Device busy\n")
        self.assertIn("YUBIKEY_SLOT2_UNKNOWN", report["blocking"])

    def test_ssh_agent_disabled_is_advice(self):
        report = self.report(Vault(ini="[SSHAgent]\nEnabled=false\n"))
        self.assertIn("KEEPASSXC_SSH_AGENT_DISABLED", report["advice"])
        self.assertEqual(report["status"], "GO")

    def test_arguments_rejected(self):
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(module.main(["--unlock"]), 2)


if __name__ == "__main__":
    unittest.main()
