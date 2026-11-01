#!/usr/bin/env python3
"""Read-only OTP2/escrow evidence. Never requests PIN, challenges, or secrets.

Exit 0 means only that requested public/metadata checks passed; always NO-GO.
Exit 3 means an incomplete or unsupported observation.
"""
from __future__ import annotations

import os
import argparse
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

SERIAL = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
FIRMWARE = "5.4.3"
OTP2 = re.compile(r"(?im)^Slot 2:\s*(programmed|empty)\s*$")
FIRMWARE_LINE = re.compile(r"(?im)^Firmware version:\s*(\d+\.\d+\.\d+)\s*$")
SERIAL_LINE = re.compile(r"(?im)^Serial number:\s*(\d+)\s*$")


def public_command(*args: str) -> tuple[int, str]:
    allowed = {
        ("list", "--serials"),
        ("--device", SERIAL, "info"),
        ("--device", SERIAL, "otp", "info"),
    }
    if args not in allowed:
        raise ValueError("unsafe or unrecognized device operation")
    done = subprocess.run(
        ["ykman", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL,
        check=False, timeout=12,
    )
    # Treat unexpected diagnostic text as an unknown state, even with exit code zero.
    if done.stderr.strip():
        return 1, ""
    return done.returncode, done.stdout


def otp2_inventory() -> str:
    try:
        rc, devices = public_command("list", "--serials")
        if rc != 0 or devices.splitlines() != [SERIAL]:
            return "UNKNOWN"
        rc, info = public_command("--device", SERIAL, "info")
        if (rc != 0 or FIRMWARE_LINE.findall(info) != [FIRMWARE]
                or SERIAL_LINE.findall(info) != [SERIAL]):
            return "UNKNOWN"
        rc, info = public_command("--device", SERIAL, "otp", "info")
        if rc != 0:
            return "UNKNOWN"
        if re.search(r"(?im)^\s*(?:error|failed|traceback)\b", info):
            return "UNKNOWN"
        states = OTP2.findall(info)
        if len(states) != 1:
            return "UNKNOWN"
        return "PROGRAMMED_TYPE_UNVERIFIED" if states[0].lower() == "programmed" else "EMPTY"
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        return "UNKNOWN"


def file_metadata(path: Path) -> tuple[bool, int, int]:
    # Require explicit absolute file paths. Neither the bytes nor filename are printed.
    if not path.is_absolute() or path.suffix != ".age":
        return False, 0, 0
    try:
        for part in (path, *path.parents):
            if part.is_symlink():
                return False, 0, 0
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_nlink != 1:
            return False, 0, 0
        return True, info.st_dev, info.st_ino
    except (OSError, ValueError):
        return False, 0, 0


def escrow_inventory(first: Path, second: Path) -> str:
    a_ok, a_dev, a_ino = file_metadata(first)
    b_ok, b_dev, b_ino = file_metadata(second)
    if not a_ok or not b_ok:
        return "UNKNOWN"
    if (a_dev, a_ino) == (b_dev, b_ino):
        return "SAME_FILE"
    if a_dev == b_dev:
        return "SAME_FILESYSTEM"
    return "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--otp2-secondary", action="store_true",
                        help="Public OTP slot-state query, secondary only; no challenge")
    parser.add_argument("--escrow-a", type=Path, help="First existing encrypted .age backup")
    parser.add_argument("--escrow-b", type=Path, help="Second existing encrypted .age backup")
    args = parser.parse_args()
    if not args.otp2_secondary and args.escrow_a is None and args.escrow_b is None:
        parser.error("select an explicit read-only check")
    if (args.escrow_a is None) != (args.escrow_b is None):
        parser.error("both --escrow-a and --escrow-b are required together")
    otp = otp2_inventory() if args.otp2_secondary else "NOT_CHECKED"
    copies = (escrow_inventory(args.escrow_a, args.escrow_b)
              if args.escrow_a is not None else "NOT_CHECKED")
    result = {
        "status": "NO-GO", "serial": SERIAL, "otp2": otp,
        "otp2_hmac_sha1_verified": False, "keepassxc_verified": False,
        "escrow": copies, "escrow_restoration_verified": False,
        "independent_physical_media_verified": False,
        "hardware_mutation_authorized": False,
    }
    print(json.dumps(result, sort_keys=True))
    otp_ok = otp in ("NOT_CHECKED", "PROGRAMMED_TYPE_UNVERIFIED")
    escrow_ok = copies in ("NOT_CHECKED", "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED")
    return 0 if otp_ok and escrow_ok else 3


if __name__ == "__main__":
    sys.exit(main())
