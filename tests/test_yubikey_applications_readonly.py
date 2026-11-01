"""Synthetic YubiKey public applet inventory: no real device, network or secrets."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-yubikey-applications-readonly.py"
spec = importlib.util.spec_from_file_location("yubikey_applet_inventory", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class ApplicationInventoryContracts(unittest.TestCase):
    serial = "11110002"

    def inventory(self, overrides=None):
        serial = self.serial
        replies = {
            ("list", "--serials"): (0, serial + "\n"),
            ("--device", serial, "info"): (0, "Serial number: " + serial + "\nFirmware version: 5.4.3\n"),
            ("--device", serial, "fido", "info"): (0, "PIN is set\n"),
            ("--device", serial, "oath", "info"): (0, "OATH version 5.4.3\n"),
            ("--device", serial, "openpgp", "info"): (0, "OpenPGP version 3.4\n"),
            ("--device", serial, "piv", "info"): (0, "Management key algorithm: AES256\nManagement key is stored on the YubiKey, protected by PIN.\n"),
        }
        for slot in mod.SLOTS:
            replies[("--device", serial, "piv", "keys", "info", slot)] = (
                (0, "Key type: RSA2048\nPIN policy: ONCE\n") if slot == "9a"
                else (1, "Error: No key stored in slot " + slot + " (RETIRED2).")
            )
        replies.update(overrides or {})
        calls = []

        def fake_query(query_serial, *args):
            self.assertEqual(query_serial, serial)
            calls.append(args)
            return replies[args]

        with patch.object(mod, "query", side_effect=fake_query):
            result, code = mod.snapshot(serial)
        return result, code, calls

    def test_complete_inventory_still_no_go(self):
        report, code, commands = self.inventory()
        self.assertEqual(code, 0)
        self.assertEqual(len(commands), 11)
        self.assertEqual(report["piv_slots"]["9A"], "OCCUPIED_METADATA")
        self.assertEqual(report["piv_slots"]["83"], "EMPTY_CONFIRMED")
        self.assertEqual(report["status"], "NO-GO")
        self.assertFalse(report["hardware_mutation_authorized"])
        self.assertFalse(report["postgres_restore_verified"])

    def test_second_device_is_not_queried(self):
        report, code, calls = self.inventory({("list", "--serials"): (0, "11110001\n")})
        self.assertEqual(code, 3)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["reason"], "IDENTITY_NOT_VERIFIED")

    def test_two_devices_fail_closed(self):
        report, code, calls = self.inventory({("list", "--serials"): (0, "11110002\n11110001\n")})
        self.assertEqual(code, 3)
        self.assertEqual(len(calls), 1)

    def test_wrong_or_missing_device_identity_fails_closed(self):
        key = ("--device", self.serial, "info")
        for value in ("Serial number: 11110001\nFirmware version: 5.4.3\n", "Firmware version: 5.4.3\n", "Serial number: 11110002\nFirmware version: 5.7.4\n"):
            with self.subTest(value=value):
                result, code, calls = self.inventory({key: (0, value)})
                self.assertEqual(code, 3)
                self.assertEqual(len(calls), 2)

    def test_piv9a_missing_must_block(self):
        key = ("--device", self.serial, "piv", "keys", "info", "9a")
        result, code, _ = self.inventory({key: (1, "Error: No key stored in slot 9a (AUTHENTICATION).")})
        self.assertEqual(code, 3)
        self.assertEqual(result["reason"], "HISTORICAL_PIV9A_NOT_CONFIRMED")

    def test_unrecognized_empty_error_is_unknown(self):
        self.assertEqual(mod.slot_state("83", 1, "PCSC timeout; No key stored in slot 83 (RETIRED2)"), "UNKNOWN")
        self.assertEqual(mod.slot_state("9c", 2, "Error: No key stored in slot 9c (SIGNATURE)."), "UNKNOWN")

    def test_occupied_slot_requires_valid_key_metadata(self):
        self.assertEqual(mod.slot_state("9a", 0, "Key type: ECCP256\nTouch policy: ALWAYS"), "OCCUPIED_METADATA")
        self.assertEqual(mod.slot_state("9a", 0, "Error: Key type: ECCP256"), "UNKNOWN")

    def test_partial_applet_is_not_assumed_configured(self):
        key = ("--device", self.serial, "openpgp", "info")
        report, code, _ = self.inventory({key: (1, "No card")})
        self.assertEqual(code, 3)
        self.assertEqual(report["applications"]["openpgp"], "UNKNOWN")

    def test_policy_change_is_not_accepted(self):
        key = ("--device", self.serial, "piv", "info")
        report, code, _ = self.inventory({key: (0, "Management key algorithm: TDES\n")})
        self.assertEqual(code, 3)
        self.assertEqual(report["management"], "UNKNOWN")

    def test_subprocess_has_closed_stdin_and_strict_allowlist(self):
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ready\n", "")) as runner:
            self.assertEqual(mod.query(self.serial, "--device", self.serial, "oath", "info"), (0, "ready\n"))
        self.assertEqual(runner.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(runner.call_args.kwargs["check"])
        with self.assertRaises(ValueError):
            mod.query(self.serial, "--device", self.serial, "piv", "keys", "generate", "82")
        with self.assertRaises(ValueError):
            mod.query("00000000", "list", "--serials")

    def test_stderr_is_not_echoed_or_trusted(self):
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "FIDO status\n", "PIN requested")):
            code, output = mod.query(self.serial, "--device", self.serial, "fido", "info")
        self.assertEqual((code, output), (3, ""))

    def test_piv_empty_stderr_can_be_classified_strictly(self):
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "Error: No key stored in slot 83 (RETIRED2).")):
            code, output = mod.query(self.serial, "--device", self.serial, "piv", "keys", "info", "83")
        self.assertEqual(mod.slot_state("83", code, output), "EMPTY_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
