#!/usr/bin/env python3
"""Explicit, local-only SSH/FIDO2 backup enrollment; never overwrites existing keys.

--check does not talk to the token. --enroll requires a TTY and a fresh serial
match. It writes a new local OpenSSH key handle, not an authorized_keys entry.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

SERIAL = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
ACK = f"ENROLL_SSH_FIDO2_BACKUP_{SERIAL}"
DIRECTORY = f"nabla-yubikey-backup-{SERIAL}"
BASENAME = "id_ed25519_sk_backup"


def assess(home: Path) -> str:
    ssh = home / ".ssh"
    try:
        info = ssh.lstat()
    except FileNotFoundError:
        return "SSH_DIRECTORY_MISSING"
    except OSError:
        return "SSH_DIRECTORY_UNAVAILABLE"
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or (
            stat.S_IMODE(info.st_mode) & 0o077):
        return "SSH_DIRECTORY_UNTRUSTED"
    try:
        (ssh / DIRECTORY).lstat()
    except FileNotFoundError:
        pass
    except OSError:
        return "TARGET_UNAVAILABLE"
    else:
        return "TARGET_EXISTS_NO_OVERWRITE"
    if not shutil.which("ssh-keygen") or not shutil.which("ykman"):
        return "TOOLS_MISSING"
    return "READY_FOR_INTERACTIVE_ENROLLMENT"


def exact_card_present() -> bool:
    try:
        done = subprocess.run(
            ["ykman", "list", "--serials"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=10, check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return False
    return (done.returncode == 0 and not done.stderr.strip()
            and done.stdout.splitlines() == [SERIAL])


def enroll(home: Path, *, tty: bool) -> str:
    state = assess(home)
    if state != "READY_FOR_INTERACTIVE_ENROLLMENT":
        return state
    if not tty:
        return "INTERACTIVE_TERMINAL_REQUIRED"
    if not exact_card_present():
        return "EXPECTED_EXACTLY_ONE_BACKUP_YUBIKEY"
    target = home / ".ssh" / DIRECTORY
    try:
        target.mkdir(mode=0o700)  # Exclusive: fail if concurrent or prior run.
    except FileExistsError:
        return "TARGET_EXISTS_NO_OVERWRITE"
    except OSError:
        return "TARGET_CREATE_FAILED"
    # Do not remove target on partial failure: never replace an unknown FIDO
    # credential on the next run without operator investigation.
    private = target / BASENAME
    try:
        result = subprocess.run(
            ["ssh-keygen", "-t", "ed25519-sk", "-f", str(private),
             "-C", f"nabla-backup-yubikey-{SERIAL}"],
            timeout=180, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "ENROLLMENT_INTERRUPTED_INSPECT_TARGET"
    if result.returncode != 0:
        return "ENROLLMENT_FAILED_INSPECT_TARGET"
    try:
        priv = private.lstat()
        pub = (target / (BASENAME + ".pub")).lstat()
    except OSError:
        return "KEY_HANDLE_INCOMPLETE"
    if (not stat.S_ISREG(priv.st_mode) or not stat.S_ISREG(pub.st_mode)
            or priv.st_uid != os.getuid() or pub.st_uid != os.getuid()
            or (stat.S_IMODE(priv.st_mode) & 0o077)):
        return "KEY_HANDLE_UNTRUSTED"
    return "LOCAL_FIDO2_KEY_HANDLE_CREATED_REMOTE_LOGIN_NOT_VERIFIED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--enroll", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--acknowledge is only valid for --enroll")
    if args.enroll and args.acknowledge != ACK:
        parser.error("explicit FIDO2 backup acknowledgment required")
    home = os.environ.get("HOME", "")
    if not home or not Path(home).is_absolute():
        state = "HOME_UNAVAILABLE"
    elif args.check:
        state = assess(Path(home))
    else:
        state = enroll(Path(home), tty=sys.stdin.isatty() and sys.stdout.isatty())
    print(json.dumps({
        "serial": SERIAL, "mode": "ENROLL" if args.enroll else "CHECK",
        "state": state, "piv82_unchanged": True,
        "otp2_unchanged": True, "remote_ssh_login_verified": False,
        "sops_changed": False,
    }, sort_keys=True))
    return 0 if state in ("READY_FOR_INTERACTIVE_ENROLLMENT",
                           "LOCAL_FIDO2_KEY_HANDLE_CREATED_REMOTE_LOGIN_NOT_VERIFIED") else 3


if __name__ == "__main__":
    sys.exit(main())
