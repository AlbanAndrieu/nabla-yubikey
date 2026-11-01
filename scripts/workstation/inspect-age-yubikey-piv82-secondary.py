#!/usr/bin/env python3
"""Fresh read-only PIV82 secondary inventory; no PIN, keys, or writes.

Exit 0: confirmed empty and PIV9A/AES256 baseline (still NO-GO).
Exit 3: unknown state or transport failure. Exit 4: occupied (no overwrite).
"""
from __future__ import annotations

import os
import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass

SERIAL = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
FIRMWARE = "5.4.3"
EMPTY_82 = re.compile(r"\s*(?:Error:\s*)?No key stored in slot 82 \(RETIRED1\)\.?\s*", re.I)
KEY_METADATA = re.compile(
    r"(?im)^\s*(?:Key type|Algorithm):\s*"
    r"(?:RSA\d+|ECCP256|ECCP384|EC(?:C)?[-_ ]?P(?:256|384)|ED25519|X25519)\s*$"
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_readonly(*args: str) -> CommandResult:
    """Only allow public metadata operations against the known secondary card."""
    allowed = {
        ("list", "--serials"),
        ("--device", SERIAL, "info"),
        ("--device", SERIAL, "piv", "info"),
        ("--device", SERIAL, "piv", "keys", "info", "82"),
        ("--device", SERIAL, "piv", "keys", "info", "9a"),
    }
    if args not in allowed:
        raise ValueError("operation not in read-only allowlist")
    completed = subprocess.run(
        ["ykman", *args], capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=12, check=False,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def inspect() -> tuple[dict, int]:
    result = {
        "serial": SERIAL, "firmware": "UNVERIFIED", "management": "UNKNOWN",
        "slot82": "UNKNOWN", "piv9a": "UNKNOWN", "otp2": "NOT_VERIFIED",
        "status": "NO-GO", "hardware_mutation_authorized": False,
        "reason": "UNVERIFIED",
    }
    try:
        inventory = run_readonly("list", "--serials")
        if inventory.returncode != 0 or inventory.stdout.splitlines() != [SERIAL]:
            result["reason"] = "EXPECTED_ONE_SECONDARY"
            return result, 3
        device = run_readonly("--device", SERIAL, "info")
        versions = re.findall(
            r"(?im)^Firmware version:\s*(\d+\.\d+\.\d+)\s*$", device.stdout
        )
        if device.returncode != 0 or versions != [FIRMWARE]:
            result["reason"] = "FIRMWARE_UNVERIFIED_OR_CHANGED"
            return result, 3
        result["firmware"] = FIRMWARE
        management = run_readonly("--device", SERIAL, "piv", "info")
        if management.returncode != 0 or not re.search(
            r"(?im)^Management key algorithm:\s*AES256\s*$", management.stdout
        ) or "Management key is stored on the YubiKey, protected by PIN." not in management.stdout:
            result["reason"] = "AES256_PIN_PROTECTED_NOT_CONFIRMED"
            return result, 3
        result["management"] = "AES256_PIN_PROTECTED"
        slot = run_readonly("--device", SERIAL, "piv", "keys", "info", "82")
        output = "\n".join(
            part for part in (slot.stdout.strip(), slot.stderr.strip()) if part
        )
        if slot.returncode in (0, 1) and EMPTY_82.fullmatch(output):
            result["slot82"] = "EMPTY_CONFIRMED"
        elif slot.returncode == 0 and KEY_METADATA.search(output) and not re.search(
            r"(?im)^\s*(?:error|failed):", output
        ):
            result["slot82"] = "OCCUPIED"
            result["reason"] = "PIV82_ALREADY_OCCUPIED_NO_OVERWRITE"
            return result, 4
        else:
            result["reason"] = "PIV82_UNRECOGNIZED_RESPONSE"
            return result, 3
        key9a = run_readonly("--device", SERIAL, "piv", "keys", "info", "9a")
        output9a = "\n".join(
            part for part in (key9a.stdout.strip(), key9a.stderr.strip()) if part
        )
        if key9a.returncode != 0 or not KEY_METADATA.search(output9a) or re.search(
            r"(?im)^\s*(?:error|failed):", output9a
        ):
            result["reason"] = "PIV9A_METADATA_NOT_CONFIRMED"
            return result, 3
        result["piv9a"] = "PRESENT_METADATA"
        result["reason"] = "FRESH_READ_ONLY_INVENTORY_NO_PROVISIONING_APPROVAL"
        return result, 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, ValueError, UnicodeError):
        result["reason"] = "READER_OR_TOOL_FAILURE"
        return result, 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, choices=[SERIAL])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result, code = inspect()
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"PIV82: {result['slot82']} / PIV9A: {result['piv9a']} / AES256: {result['management']}")
        print(f"NO-GO: {result['reason']}")
    return code


if __name__ == "__main__":
    sys.exit(main())
