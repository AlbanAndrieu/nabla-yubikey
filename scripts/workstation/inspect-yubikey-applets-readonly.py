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
    """Run one allowlisted read-only ykman command; None when its output cannot be trusted."""
    if tuple(args) not in READ_ONLY_COMMANDS:
        return None
    return run_bounded(["ykman", *args])


def number(pattern: str, raw: str) -> int | None:
    """Exactly one counter, never the first of contradictory repeated lines."""
    matches = re.findall(pattern, raw, re.MULTILINE)
    return int(matches[0]) if len(matches) == 1 else None


def parse_device(raw: str) -> dict | None:
    firmware = re.search(r"^Firmware version: ([0-9]+(?:\.[0-9]+){2})$", raw, re.MULTILINE)
    apps = {}
    in_table = False
    for line in raw.splitlines():
        if line.startswith("Applications"):
            if in_table:
                return None
            in_table = True
            continue
        if not in_table or not line.strip():
            continue
        cells = [cell.strip() for cell in line.split("\t")]
        if (len(cells) != 3 or not cells[0] or cells[0] in apps
                or any(state not in ("Enabled", "Disabled") for state in cells[1:])):
            return None
        apps[cells[0]] = {"usb": cells[1] == "Enabled", "nfc": cells[2] == "Enabled"}
    # A truncated ykman response must not be treated as a healthy applet set.
    if firmware is None or not apps:
        return None
    return {"firmware": firmware.group(1), "applications": apps}


def parse_fido(raw: str) -> dict | None:
    """Do not treat unknown/missing PIN metadata as PIN configured."""
    attempts = re.findall(r"^PIN:\s+(\d+) attempt\(s\) remaining\s*$", raw, re.MULTILINE)
    not_set = re.findall(r"^PIN:\s+Not set\s*$", raw, re.MULTILINE)
    if len(attempts) == 1 and not not_set:
        return {"pin_set": True, "pin_attempts": int(attempts[0])}
    if len(not_set) == 1 and not attempts:
        return {"pin_set": False, "pin_attempts": None}
    return None


def parse_openpgp(raw: str) -> dict | None:
    pin = number(r"^PIN tries remaining:\s+(\d+)", raw)
    admin = number(r"^Admin PIN tries remaining:\s+(\d+)", raw)
    kdf = re.findall(r"^KDF enabled:\s+(True|False)\s*$", raw, re.MULTILINE)
    if pin is None or admin is None or len(kdf) != 1:
        return None
    return {"pin_tries": pin, "admin_pin_tries": admin,
            "kdf_enabled": kdf[0] == "True"}


def parse_piv(raw: str) -> dict | None:
    pin = number(r"^PIN tries remaining:\s+(\d+)(?:/\d+)?\s*$", raw)
    puk = number(r"^PUK tries remaining:\s+(\d+)(?:/\d+)?\s*$", raw)
    if pin is None or puk is None:
        return None
    return {"pin_tries": pin, "puk_tries": puk,
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
# Explicit allowlist: diagnostics must not accidentally grow mutating subcommands.
READ_ONLY_COMMANDS = {("list",), ("list", "--serials"), *(tuple(args) for args, _ in SECTIONS.values())}
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
    return main_json(snapshot, argv, mode="YUBIKEY_APPLETS_READONLY")


if __name__ == "__main__":
    sys.exit(main())
