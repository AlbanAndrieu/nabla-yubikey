#!/usr/bin/env python3
"""Inventory YubiKey applet state through read-only `ykman ... info` commands.

Never asks for a PIN, never writes to the card, and never prints the serial
number, certificate subjects or fingerprints: only counters and flags.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

COMMANDS = {
    "device": ["info"],
    "fido": ["fido", "info"],
    "openpgp": ["openpgp", "info"],
    "piv": ["piv", "info"],
}


def ykman(args: list[str]) -> str | None:
    """Run one read-only ykman command; None when its output cannot be trusted."""
    if not shutil.which("ykman"):
        return None
    try:
        done = subprocess.run(["ykman", *args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=15, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 or len(done.stdout) > 65536 or "\x00" in done.stdout:
        return None
    return done.stdout


def device_count(raw: str | None) -> int | None:
    return None if raw is None else len([line for line in raw.splitlines() if line.strip()])


def number(pattern: str, raw: str) -> int | None:
    match = re.search(pattern, raw, re.MULTILINE)
    return int(match.group(1)) if match else None


def parse_device(raw: str) -> dict:
    firmware = re.search(r"^Firmware version: ([0-9.]+)$", raw, re.MULTILINE)
    apps = {}
    in_table = False
    for line in raw.splitlines():
        if line.startswith("Applications"):
            in_table = True
            continue
        cells = [cell.strip() for cell in line.split("\t")]
        if in_table and len(cells) == 3:
            apps[cells[0]] = {"usb": cells[1] == "Enabled", "nfc": cells[2] == "Enabled"}
    return {"firmware": firmware.group(1) if firmware else None, "applications": apps}


def parse_fido(raw: str) -> dict:
    return {"pin_set": "Not set" not in raw,
            "pin_attempts": number(r"^PIN:\s+(\d+) attempt", raw)}


def parse_openpgp(raw: str) -> dict:
    return {"pin_tries": number(r"^PIN tries remaining:\s+(\d+)", raw),
            "admin_pin_tries": number(r"^Admin PIN tries remaining:\s+(\d+)", raw),
            "kdf_enabled": bool(re.search(r"^KDF enabled:\s+True", raw, re.MULTILINE))}


def parse_piv(raw: str) -> dict:
    return {"pin_tries": number(r"^PIN tries remaining:\s+(\d+)", raw),
            "puk_tries": number(r"^PUK tries remaining:\s+(\d+)", raw),
            "default_credentials": bool(re.search(r"default (PIN|PUK|Management key)", raw, re.IGNORECASE)),
            "slots": sorted(set(re.findall(r"^Slot ([0-9A-F]{2})\b", raw, re.MULTILINE)))}


def assess(report: dict) -> tuple[list[str], list[str]]:
    """Blocking findings make the inventory NO-GO; advice never does."""
    blocking, advice = [], []
    fido, openpgp, piv = report["fido"], report["openpgp"], report["piv"]
    for name in ("device", "fido", "openpgp", "piv"):
        if report[name] is None:
            blocking.append(f"{name.upper()}_UNREADABLE")
    if fido and not fido["pin_set"]:
        blocking.append("FIDO2_PIN_NOT_SET")
    counters = [("FIDO2_PIN", fido and fido["pin_attempts"]),
                ("OPENPGP_PIN", openpgp and openpgp["pin_tries"]),
                ("OPENPGP_ADMIN_PIN", openpgp and openpgp["admin_pin_tries"]),
                ("PIV_PIN", piv and piv["pin_tries"]),
                ("PIV_PUK", piv and piv["puk_tries"])]
    for name, value in counters:
        if value is not None and value <= 1:
            blocking.append(f"{name}_ALMOST_BLOCKED")
    if piv and piv["default_credentials"]:
        blocking.append("PIV_DEFAULT_CREDENTIALS")
    if openpgp and not openpgp["kdf_enabled"]:
        advice.append("OPENPGP_KDF_DISABLED")
    apps = (report["device"] or {}).get("applications", {})
    if any(state["nfc"] for state in apps.values()):
        advice.append("NFC_ENABLED")
    if apps.get("Yubico OTP", {}).get("usb"):
        advice.append("OTP_USB_ENABLED")
    return blocking, advice


def snapshot() -> dict:
    count = device_count(ykman(["list"]))
    report = {"mode": "YUBIKEY_APPLETS_READONLY", "device_count": count,
              "hardware_mutation_authorized": False}
    if count != 1:
        report.update(status="NO-GO", blocking=["DEVICE_COUNT_NOT_ONE"], advice=[])
        return report
    parsers = {"device": parse_device, "fido": parse_fido, "openpgp": parse_openpgp, "piv": parse_piv}
    for name, args in COMMANDS.items():
        raw = ykman(args)
        report[name] = parsers[name](raw) if raw is not None else None
    blocking, advice = assess(report)
    report.update(status="NO-GO" if blocking else "GO", blocking=blocking, advice=advice)
    return report


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("No arguments supported", file=sys.stderr)
        return 2
    print(json.dumps(snapshot(), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
