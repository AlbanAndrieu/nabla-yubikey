"""Hermetic contracts: read-only YubiKey applet inventory, no serial leak."""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-yubikey-applets-readonly.py"
spec = importlib.util.spec_from_file_location("yubikey_applets_readonly", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

LIST = "YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345678\n"
DEVICE = """Device type: YubiKey 5 NFC
Serial number: 12345678
Firmware version: 5.4.3
Form factor: Keychain (USB-A)

Applications\tUSB    \tNFC
Yubico OTP  \tEnabled\tEnabled
FIDO2       \tEnabled\tDisabled
PIV         \tEnabled\tEnabled
"""
FIDO = "AAGUID:             2fc0579f-8113-47ea-b116-bb5a8db9202a\nPIN:                8 attempt(s) remaining\n"
OPENPGP = "PIN tries remaining:        3\nReset code tries remaining: 0\nAdmin PIN tries remaining:  3\nKDF enabled:                False\n"
PIV = """PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key is stored on the YubiKey, protected by PIN.
Slot 9A (AUTHENTICATION):
  Subject DN:       CN=private-name
"""
OTP = "Slot 1: programmed\nSlot 2: empty\n"
OUTPUTS = {"list": LIST, "serials": "12345678\n", "info": DEVICE, "fido": FIDO, "openpgp": OPENPGP,
           "piv": PIV, "otp": OTP}


def fake_run(outputs):
    def run(command, **kwargs):
        value = outputs["serials" if command[1:] == ["list", "--serials"] else command[1]]
        if value is None:
            return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(returncode=0, stdout=value)
    return run


def snapshot_with(**overrides):
    with patch.object(module.shutil, "which", return_value="/usr/bin/ykman"), \
         patch.object(module.subprocess, "run", side_effect=fake_run({**OUTPUTS, **overrides})):
        return module.snapshot()


class AppletContracts(unittest.TestCase):
    def test_ykman_is_read_only_and_never_prompts(self):
        with patch.object(module.shutil, "which", return_value="/usr/bin/ykman"), \
             patch.object(module.subprocess, "run", side_effect=fake_run(OUTPUTS)) as run:
            module.snapshot()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands, [["ykman", "list"], ["ykman", "list", "--serials"], ["ykman", "info"],
                                    ["ykman", "fido", "info"], ["ykman", "openpgp", "info"],
                                    ["ykman", "piv", "info"], ["ykman", "otp", "info"]])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)

    def test_role_from_local_last4_mapping_never_returns_serial(self):
        self.assertEqual(module.device_role("12345678\n", "5678=principale,1111=secours"), "principale")
        self.assertEqual(module.device_role("12345678\n", "1111=secours"), "UNLABELED")
        self.assertEqual(module.device_role("12345678\n87654321\n", "5678=principale"), "UNKNOWN")
        self.assertEqual(module.device_role("12345678\n", "5678=$(rm -rf)"), "UNLABELED")
        with patch.dict(module.os.environ, {"YUBIKEY_ROLES": "5678=principale"}):
            report = snapshot_with()
        self.assertEqual(report["role"], "principale")
        self.assertEqual(report["otp"], {"slot1": True, "slot2": False})

    def test_unrecognized_otp_output_is_unreadable_not_empty(self):
        self.assertIsNone(module.parse_otp(""))
        self.assertIsNone(module.parse_otp("Slot 1: programmed\n"))
        report = snapshot_with(otp="Device busy\n")
        self.assertIsNone(report["otp"])
        self.assertIn("OTP_UNREADABLE", report["blocking"])

    def test_go_report_never_leaks_serial_subject_or_aaguid(self):
        out = io.StringIO()
        with patch.object(module.shutil, "which", return_value="/usr/bin/ykman"), \
             patch.object(module.subprocess, "run", side_effect=fake_run(OUTPUTS)), redirect_stdout(out):
            self.assertEqual(module.main([]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["status"], "GO")
        self.assertEqual(report["piv"]["slots"], ["9A"])
        self.assertEqual(report["fido"]["pin_attempts"], 8)
        self.assertEqual(report["device"]["applications"]["FIDO2"], {"usb": True, "nfc": False})
        self.assertEqual(sorted(report["advice"]), ["NFC_ENABLED", "OPENPGP_KDF_DISABLED", "OTP_USB_ENABLED"])
        for leaked in ("12345678", "private-name", "2fc0579f"):
            self.assertNotIn(leaked, out.getvalue())

    def test_device_count_must_be_one(self):
        for raw in ("", LIST * 2, None):
            report = snapshot_with(list=raw)
            self.assertEqual(report["status"], "NO-GO")
            self.assertEqual(report["blocking"], ["DEVICE_COUNT_NOT_ONE"])
            self.assertNotIn("fido", report)

    def test_blocking_findings(self):
        cases = {
            "FIDO2_PIN_NOT_SET": {"fido": "PIN:                Not set\n"},
            "FIDO2_PIN_ALMOST_BLOCKED": {"fido": "PIN:                1 attempt(s) remaining\n"},
            "OPENPGP_ADMIN_PIN_ALMOST_BLOCKED": {"openpgp": OPENPGP.replace("Admin PIN tries remaining:  3",
                                                                            "Admin PIN tries remaining:  0")},
            "PIV_DEFAULT_CREDENTIALS": {"piv": PIV + "WARNING: Using default PIN!\n"},
            "PIV_UNREADABLE": {"piv": None},
        }
        for finding, override in cases.items():
            report = snapshot_with(**override)
            self.assertEqual(report["status"], "NO-GO", finding)
            self.assertIn(finding, report["blocking"])

    def test_missing_ykman_fails_closed(self):
        with patch.object(module.shutil, "which", return_value=None), \
             patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.snapshot()["status"], "NO-GO")
            run.assert_not_called()
        with patch.object(module.shutil, "which", return_value="/usr/bin/ykman"), \
             patch.object(module.subprocess, "run", side_effect=subprocess.TimeoutExpired(["ykman"], 15)):
            self.assertIsNone(module.ykman(["list"]))

    def test_arguments_rejected(self):
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(module.main(["--reset"]), 2)


if __name__ == "__main__":
    unittest.main()
