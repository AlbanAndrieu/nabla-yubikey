#!/usr/bin/env python3
"""Inventory public YubiKey applet status, never secret data or credentials.

The result is an observation, never authorization to enroll, reset or provision.
Use with exactly one physical device. No PIN, OTP challenge or write commands.
"""
from __future__ import annotations

import os
import argparse
import json
import re
import subprocess
import sys

DEVICES = {os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002"), os.environ.get("YUBIKEY_PRIMARY_SERIAL", "11110001")}
FIRMWARE = "5.4.3"
APP_NAMES = ("fido", "oath", "openpgp", "piv")
SLOTS = ("9a", "9c", "9d", "9e", "83")
KEY = re.compile(r"(?im)^\s*(?:Key type|Algorithm):\s*(?:RSA(?:1024|2048|3072|4096)|ECCP(?:256|384)|ED25519|X25519)\s*$")
ERROR = re.compile(r"(?im)^\s*(?:error|failed|traceback|warning)\b")
SERIAL = re.compile(r"(?im)^Serial number:\s*(\d+)\s*$")
VERSION = re.compile(r"(?im)^Firmware version:\s*(\d+\.\d+\.\d+)\s*$")


def query(serial: str, *args: str) -> tuple[int, str]:
    """Allowlist only: never print stdout, which may include personal metadata."""
    allowed = {("list", "--serials"), ("--device", serial, "info")}
    allowed.update(("--device", serial, name, "info") for name in APP_NAMES)
    allowed.update(("--device", serial, "piv", "keys", "info", slot) for slot in SLOTS)
    if serial not in DEVICES or args not in allowed:
        raise ValueError("operation not permitted")
    completed = subprocess.run(
        ["ykman", *args], stdin=subprocess.DEVNULL, capture_output=True,
        text=True, timeout=12, check=False,
    )
    if len(completed.stdout) > 32768 or len(completed.stderr) > 32768:
        return 3, ""
    # Empty-slot metadata is legitimately written to stderr by some ykman versions.
    if completed.stderr.strip():
        if len(args) == 6 and args[2:5] == ("piv", "keys", "info"):
            return completed.returncode, "\n".join(
                part for part in (completed.stdout.strip(), completed.stderr.strip()) if part
            )
        return 3, ""
    return completed.returncode, completed.stdout


def slot_state(slot: str, rc: int, output: str) -> str:
    empty = re.fullmatch(
        rf"\s*(?:Error:\s*)?No key stored in slot {slot} \([A-Z0-9_]+\)\.?\s*",
        output, flags=re.IGNORECASE,
    )
    if rc in (0, 1) and empty:
        return "EMPTY_CONFIRMED"
    if rc == 0 and KEY.search(output) and not ERROR.search(output):
        return "OCCUPIED_METADATA"
    return "UNKNOWN"


def snapshot(serial: str) -> tuple[dict, int]:
    result = {
        "serial": serial,
        "firmware": "UNKNOWN",
        "applications": {name: "UNKNOWN" for name in APP_NAMES},
        "piv_slots": {slot.upper(): "UNKNOWN" for slot in SLOTS},
        "management": "UNKNOWN",
        "reason": "IDENTITY_NOT_VERIFIED",
        "status": "NO-GO",
        "fido_enrollment_verified": False,
        "openpgp_gpg_interop_verified": False,
        "postgres_restore_verified": False,
        "keepassxc_verified_by_this_check": False,
        "age_decrypt_verified": False,
        "hardware_mutation_authorized": False,
    }
    try:
        code, devices = query(serial, "list", "--serials")
        if code != 0 or devices.splitlines() != [serial]:
            return result, 3
        code, info = query(serial, "--device", serial, "info")
        if code != 0 or SERIAL.findall(info) != [serial] or VERSION.findall(info) != [FIRMWARE]:
            return result, 3
        result["firmware"] = FIRMWARE
        for name in APP_NAMES:
            code, output = query(serial, "--device", serial, name, "info")
            result["applications"][name] = (
                "RESPONDS_METADATA_ONLY" if code == 0 and output.strip()
                and not ERROR.search(output) else "UNKNOWN"
            )
            if name == "piv" and code == 0 and output.strip():
                if (re.search(r"(?im)^Management key algorithm:\s*AES256\s*$", output)
                        and "Management key is stored on the YubiKey, protected by PIN." in output):
                    result["management"] = "AES256_PIN_PROTECTED"
        if result["applications"]["piv"] != "RESPONDS_METADATA_ONLY":
            result["reason"] = "PIV_METADATA_UNAVAILABLE"
            return result, 3
        for slot in SLOTS:
            code, output = query(serial, "--device", serial, "piv", "keys", "info", slot)
            result["piv_slots"][slot.upper()] = slot_state(slot, code, output)
        if result["piv_slots"]["9A"] != "OCCUPIED_METADATA":
            result["reason"] = "HISTORICAL_PIV9A_NOT_CONFIRMED"
            return result, 3
        if result["management"] != "AES256_PIN_PROTECTED":
            result["reason"] = "MANAGEMENT_POLICY_NOT_CONFIRMED"
            return result, 3
        if (any(x == "UNKNOWN" for x in result["applications"].values())
                or any(x == "UNKNOWN" for x in result["piv_slots"].values())):
            result["reason"] = "PARTIAL_APPLET_OR_SLOT_INVENTORY"
            return result, 3
        result["reason"] = "PUBLIC_INVENTORY_ONLY_CONFIG_NOT_VERIFIED"
        return result, 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        result["reason"] = "READER_OR_TOOL_ERROR"
        return result, 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, choices=sorted(DEVICES))
    args = parser.parse_args()
    result, exit_code = snapshot(args.serial)
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
