#!/usr/bin/env python3
"""Inventory YubiKey applet state through read-only `ykman ... info` commands.

Never asks for a PIN, never writes to the card, and never prints the serial
number, certificate subjects or fingerprints: only counters and flags.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

COMMANDS = {
    "device": ["info"],
    "fido": ["fido", "info"],
    "openpgp": ["openpgp", "info"],
    "piv": ["piv", "info"],
    "otp": ["otp", "info"],
}
# Explicit allowlist: diagnostics must not accidentally grow mutating subcommands.
READ_ONLY_COMMANDS = {("list",), ("list", "--serials"),
                      *(tuple(args) for args in COMMANDS.values())}


def ykman(args: list[str]) -> str | None:
    """Run one allowlisted inspection command, without PIN, prompts or stderr."""
    if tuple(args) not in READ_ONLY_COMMANDS or not shutil.which("ykman"):
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


def device_role(serials: str | None, roles: str) -> str:
    """Map the serial's last 4 digits to a local label (YUBIKEY_ROLES="1234=principale,5678=secours").

    The mapping stays in the operator's environment; the serial is never returned.
    """
    lines = [] if serials is None else [line.strip() for line in serials.splitlines() if line.strip()]
    if len(lines) != 1 or not lines[0].isdigit():
        return "UNKNOWN"
    for pair in roles.split(","):
        last4, _, label = pair.strip().partition("=")
        if last4 and last4 == lines[0][-4:] and label.isidentifier():
            return label
    return "UNLABELED"


def parse_otp(raw: str) -> dict | None:
    """Require exactly one authoritative state per slot (reject duplicates)."""
    rows = re.findall(r"^Slot ([12]): (programmed|empty)$", raw, re.MULTILINE)
    if len(rows) != 2 or {slot for slot, _ in rows} != {"1", "2"}:
        return None
    return {f"slot{n}": state == "programmed" for n in ("1", "2")
            for slot, state in rows if slot == n}


def device_count(raw: str | None) -> int | None:
    return None if raw is None else len([line for line in raw.splitlines() if line.strip()])


def number(pattern: str, raw: str) -> int | None:
    match = re.search(pattern, raw, re.MULTILINE)
    return int(match.group(1)) if match else None


def parse_device(raw: str) -> dict | None:
    firmware = re.search(r"^Firmware version: ([0-9]+(?:\\.[0-9]+){2})$", raw, re.MULTILINE)
    apps = {}
    in_table = False
    for line in raw.splitlines():
        if line.startswith("Applications"):
            in_table = True
            continue
        cells = [cell.strip() for cell in line.split("\t")]
        if in_table and len(cells) == 3:
            apps[cells[0]] = {"usb": cells[1] == "Enabled", "nfc": cells[2] == "Enabled"}
    # A truncated ykman response must not be treated as a healthy applet set.
    if firmware is None or not apps:
        return None
    return {"firmware": firmware.group(1), "applications": apps}


def parse_fido(raw: str) -> dict | None:
    """Do not treat unknown/missing PIN metadata as PIN configured."""
    remaining = number(r"^PIN:\s+(\d+) attempt\\(s\\) remaining\\s*$", raw)
    if remaining is not None:
        return {"pin_set": True, "pin_attempts": remaining}
    if re.search(r"^PIN:\s+Not set\\s*$", raw, re.MULTILINE):
        return {"pin_set": False, "pin_attempts": None}
    return None


def parse_openpgp(raw: str) -> dict | None:
    pin = number(r"^PIN tries remaining:\s+(\d+)", raw)
    admin = number(r"^Admin PIN tries remaining:\s+(\d+)", raw)
    kdf = re.search(r"^KDF enabled:\s+(True|False)\\s*$", raw, re.MULTILINE)
    if pin is None or admin is None or kdf is None:
        return None
    return {"pin_tries": pin, "admin_pin_tries": admin,
            "kdf_enabled": kdf.group(1) == "True"}


def parse_piv(raw: str) -> dict | None:
    pin = number(r"^PIN tries remaining:\s+(\d+)", raw)
    puk = number(r"^PUK tries remaining:\s+(\d+)", raw)
    if pin is None or puk is None:
        return None
    return {"pin_tries": pin, "puk_tries": puk,
            "default_credentials": bool(re.search(r"default (PIN|PUK|Management key)", raw, re.IGNORECASE)),
            "slots": sorted(set(re.findall(r"^Slot ([0-9A-F]{2})\b", raw, re.MULTILINE)))}


def assess(report: dict) -> tuple[list[str], list[str]]:
    """Blocking findings make the inventory NO-GO; advice never does."""
    blocking, advice = [], []
    fido, openpgp, piv = report["fido"], report["openpgp"], report["piv"]
    for name in ("device", "fido", "openpgp", "piv", "otp"):
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
    report["role"] = device_role(ykman(["list", "--serials"]), os.environ.get("YUBIKEY_ROLES", ""))
    parsers = {"device": parse_device, "fido": parse_fido, "openpgp": parse_openpgp, "piv": parse_piv,
               "otp": parse_otp}
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
