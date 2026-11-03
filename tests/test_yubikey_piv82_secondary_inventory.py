"""Synthetic PIV82 metadata; never calls a physical YubiKey."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/inspect-age-yubikey-piv82-secondary.py"
spec = importlib.util.spec_from_file_location("piv82_secondary", SOURCE)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class InventoryTests(unittest.TestCase):
    valid = {
        ("list", "--serials"): (0, "11110002\n", ""),
        ("--device", "11110002", "info"): (0, "Firmware version: 5.4.3\n", ""),
        ("--device", "11110002", "piv", "info"): (
            0, "Management key algorithm: AES256\n"
            "Management key is stored on the YubiKey, protected by PIN.\n", ""
        ),
        ("--device", "11110002", "piv", "keys", "info", "82"): (
            1, "", "Error: No key stored in slot 82 (RETIRED1)."
        ),
        ("--device", "11110002", "piv", "keys", "info", "9a"): (
            0, "Key type: ECCP256\nPIN policy: ALWAYS\nTouch policy: ALWAYS\n", ""
        ),
    }

    def simulate(self, overrides=None):
        outcomes = dict(self.valid)
        outcomes.update(overrides or {})
        seen = []

        def read(*args):
            seen.append(args)
            rc, stdout, stderr = outcomes[args]
            return module.CommandResult(rc, stdout, stderr)

        with patch.object(module, "run_readonly", side_effect=read):
            report, code = module.inspect()
        return report, code, seen

    def test_empty_confirmed_remains_no_go(self):
        report, code, seen = self.simulate()
        self.assertEqual(code, 0)
        self.assertEqual(report["slot82"], "EMPTY_CONFIRMED")
        self.assertEqual(report["piv9a"], "PRESENT_METADATA")
        self.assertEqual(report["management"], "AES256_PIN_PROTECTED")
        self.assertEqual(report["status"], "NO-GO")
        self.assertFalse(report["hardware_mutation_authorized"])
        self.assertEqual(len(seen), 5)

    def test_occupied_blocks_with_no_overwrite(self):
        report, code, seen = self.simulate({
            ("--device", "11110002", "piv", "keys", "info", "82"):
                (0, "Key type: ECCP256\nPIN policy: ALWAYS\n", "")
        })
        self.assertEqual((code, report["slot82"]), (4, "OCCUPIED"))
        self.assertEqual(len(seen), 4)

    def test_transport_error_with_empty_text_is_unknown(self):
        report, code, _ = self.simulate({
            ("--device", "11110002", "piv", "keys", "info", "82"):
                (1, "", "No key stored in slot 82 (RETIRED1).\nPCSC connection failed")
        })
        self.assertEqual((code, report["slot82"]), (3, "UNKNOWN"))

    def test_wrong_device_refused(self):
        report, code, seen = self.simulate({("list", "--serials"): (0, "11110001\n", "")})
        self.assertEqual(code, 3)
        self.assertEqual(len(seen), 1)

    def test_multiple_devices_refused(self):
        report, code, seen = self.simulate({
            ("list", "--serials"): (0, "11110002\n11110001\n", "")
        })
        self.assertEqual(code, 3)
        self.assertEqual(len(seen), 1)

    def test_management_algorithm_change_refused(self):
        report, code, seen = self.simulate({
            ("--device", "11110002", "piv", "info"): (0, "Management key algorithm: TDES\n", "")
        })
        self.assertEqual(code, 3)
        self.assertEqual(report["slot82"], "UNKNOWN")
        self.assertEqual(len(seen), 3)

    def test_piv9a_missing_refused(self):
        report, code, _ = self.simulate({
            ("--device", "11110002", "piv", "keys", "info", "9a"):
                (1, "", "Error: No key stored in slot 9a.")
        })
        self.assertEqual(code, 3)
        self.assertEqual(report["piv9a"], "UNKNOWN")
        self.assertEqual(report["slot82"], "EMPTY_CONFIRMED")

    def test_firmware_change_refused(self):
        _, code, seen = self.simulate({
            ("--device", "11110002", "info"): (0, "Firmware version: 5.7.4", "")
        })
        self.assertEqual(code, 3)
        self.assertEqual(len(seen), 2)

    def test_readonly_allowlist_rejects_generation(self):
        with self.assertRaises(ValueError):
            module.run_readonly("--device", "11110002", "piv", "keys", "generate", "82")

    def test_subprocess_cannot_prompt_for_pin(self):
        with patch.object(
            module.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "11110002\n", "")
        ) as runner:
            module.run_readonly("list", "--serials")
        self.assertEqual(runner.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(runner.call_args.kwargs["capture_output"])
        self.assertFalse(runner.call_args.kwargs["check"])


if __name__ == "__main__":
    unittest.main()
