#!/usr/bin/env python3
"""Inventory YubiKey applet state through read-only `ykman ... info` commands.

Never asks for a PIN, never writes to the card, and never prints the serial
number, certificate subjects or fingerprints: only counters and flags.
"""
from __future__ import annotations

import re
import sys

from probe_common import line_count, main_json, parse_otp, run_bounded, verdict, yubikey_role


def ykman(args: list[str]) -> str | None:
    """Run one read-only ykman command; None when its output cannot be trusted."""
    return run_bounded(["ykman", *args])


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


# Report section -> (read-only ykman arguments, parser of its output).
SECTIONS = {
    "device": (["info"], parse_device),
    "fido": (["fido", "info"], parse_fido),
    "openpgp": (["openpgp", "info"], parse_openpgp),
    "piv": (["piv", "info"], parse_piv),
    "otp": (["otp", "info"], parse_otp),
}
# Retry counters that lock an applet when they reach 0.
COUNTERS = (("FIDO2_PIN", "fido", "pin_attempts"), ("OPENPGP_PIN", "openpgp", "pin_tries"),
            ("OPENPGP_ADMIN_PIN", "openpgp", "admin_pin_tries"), ("PIV_PIN", "piv", "pin_tries"),
            ("PIV_PUK", "piv", "puk_tries"))


def field(report: dict, section: str, key: str):
    """Value from a parsed section; None when the section was unreadable."""
    return (report.get(section) or {}).get(key)


def assess(report: dict) -> tuple[list[str], list[str]]:
    blocking = [f"{name.upper()}_UNREADABLE" for name in SECTIONS if report[name] is None]
    advice = []
    if field(report, "fido", "pin_set") is False:
        blocking.append("FIDO2_PIN_NOT_SET")
    for name, section, key in COUNTERS:
        value = field(report, section, key)
        if value is not None and value <= 1:
            blocking.append(f"{name}_ALMOST_BLOCKED")
    if field(report, "piv", "default_credentials"):
        blocking.append("PIV_DEFAULT_CREDENTIALS")
    if field(report, "openpgp", "kdf_enabled") is False:
        advice.append("OPENPGP_KDF_DISABLED")
    apps = field(report, "device", "applications") or {}
    if any(state["nfc"] for state in apps.values()):
        advice.append("NFC_ENABLED")
    if apps.get("Yubico OTP", {}).get("usb"):
        advice.append("OTP_USB_ENABLED")
    return blocking, advice


def snapshot() -> dict:
    count = line_count(ykman(["list"]))
    report = {"mode": "YUBIKEY_APPLETS_READONLY", "device_count": count,
              "hardware_mutation_authorized": False}
    if count != 1:
        return verdict(report, ["DEVICE_COUNT_NOT_ONE"], [])
    report["role"] = yubikey_role()
    for name, (args, parse) in SECTIONS.items():
        raw = ykman(args)
        report[name] = parse(raw) if raw is not None else None
    return verdict(report, *assess(report))


def main(argv: list[str] | None = None) -> int:
    return main_json(snapshot, argv)


if __name__ == "__main__":
    sys.exit(main())
