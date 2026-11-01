"""Shared helpers for the read-only workstation probes.

Every probe prints one JSON object, exits 0 (2 on unexpected arguments) and
fails closed: an unreadable command yields None, never an optimistic value.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Callable


def run_bounded(args: list[str], timeout: int = 15, ok_codes: tuple[int, ...] = (0,),
                limit: int = 65536, require_empty_on_error: bool = False) -> str | None:
    """Run bounded metadata probes, never returning stderr or raw error output.

    The caller must use a fixed read-only command allowlist. No shell is involved.
    """
    if (not args or not all(isinstance(arg, str) and arg and "\x00" not in arg for arg in args)
            or timeout <= 0 or limit <= 0 or not ok_codes):
        return None
    if not shutil.which(args[0]):
        return None
    try:
        done = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
    if (done.returncode not in ok_codes or not isinstance(done.stdout, str)
            or len(done.stdout) > limit or "\x00" in done.stdout):
        return None
    if require_empty_on_error and done.returncode != 0 and done.stdout:
        return None
    return done.stdout


def line_count(raw: str | None) -> int | None:
    return None if raw is None else len([line for line in raw.splitlines() if line.strip()])


def parse_otp(raw: str | None) -> dict | None:
    """None unless both slots are reported: a busy device must not read as an empty slot."""
    if raw is None:
        return None
    lines = raw.splitlines()
    # Reject busy-device messages and extra/contradictory rows even if both slots appear.
    if len(lines) != 2:
        return None
    rows = [re.fullmatch(r"Slot ([12]): (programmed|empty)", line) for line in lines]
    if any(row is None for row in rows):
        return None
    states = {row.group(1): row.group(2) for row in rows}
    if len(states) != 2:
        return None
    return {f"slot{n}": states[n] == "programmed" for n in ("1", "2")}


def device_role(serials: str | None, roles: str) -> str:
    """Map the serial's last 4 digits to a local label (YUBIKEY_ROLES="1234=principale,5678=secondaire").

    The mapping stays in the operator's environment; the serial is never returned.
    """
    lines = [] if serials is None else [line.strip() for line in serials.splitlines() if line.strip()]
    if len(lines) != 1 or not lines[0].isdigit():
        return "UNKNOWN"
    # Only public role labels may enter machine-readable reports. Never echo
    # arbitrary environment text (it could be an operator secret).
    labels = {"principale", "secondaire", "secours", "primary", "backup"}
    matches = []
    for pair in roles.split(","):
        last4, sep, label = pair.strip().partition("=")
        if (sep and len(last4) == 4 and last4.isascii() and last4.isdecimal()
                and last4 == lines[0][-4:] and label in labels):
            matches.append(label)
    return matches[0] if len(matches) == 1 else ("UNKNOWN" if matches else "UNLABELED")


def yubikey_role() -> str:
    """Role of the single plugged YubiKey, so a report always says which key it describes."""
    return device_role(run_bounded(["ykman", "list", "--serials"]), os.environ.get("YUBIKEY_ROLES", ""))


def verdict(report: dict, blocking: list[str], advice: list[str]) -> dict:
    """Blocking findings make a probe NO-GO; advice never does."""
    report.update(status="NO-GO" if blocking else "GO", blocking=blocking, advice=advice)
    return report


def main_json(snapshot: Callable[[], dict], argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("No arguments supported", file=sys.stderr)
        return 2
    print(json.dumps(snapshot(), sort_keys=True))
    return 0
