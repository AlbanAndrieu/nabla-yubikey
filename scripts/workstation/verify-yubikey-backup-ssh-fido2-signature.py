#!/usr/bin/env python3
"""Verify the already enrolled SSH/FIDO2 backup key with a synthetic message.

--check: public key fingerprint and local file metadata, no token access.
--sign: explicit, interactive, one-time SSHSIG roundtrip using only an
ephemeral fixture. May request the SSH passphrase, FIDO PIN and touch.
Never enrolls, writes a key, changes authorized_keys, or contacts a host.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SERIAL = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
FINGERPRINT = "SHA256:42+Klqmv8gwQZB+1OxRjkye3nEQF1PsMjTQwXwzoSwQ"
KEY_DIR = f"nabla-yubikey-backup-{SERIAL}"
KEY_NAME = "id_ed25519_sk_backup"
NAMESPACE = "yubikey-backup-proof@nabla.invalid"
IDENTITY = "backup-proof"
ACK = f"SIGN_EXISTING_FIDO2_BACKUP_{SERIAL}"


def paths(home: Path) -> tuple[Path, Path]:
    base = home / ".ssh" / KEY_DIR
    return base / KEY_NAME, base / (KEY_NAME + ".pub")


def local_state(home: Path) -> str:
    if not shutil.which("ssh-keygen") or not shutil.which("ykman"):
        return "TOOLS_MISSING"
    ssh = home / ".ssh"
    private, public = paths(home)
    try:
        for directory in (ssh, private.parent):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                return "UNTRUSTED_KEY_DIRECTORY"
        for path in (private, public):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_size < 1 or info.st_size > 16384):
                return "UNTRUSTED_KEY_FILE"
            if path == private and stat.S_IMODE(info.st_mode) & 0o077:
                return "UNTRUSTED_KEY_FILE"
        raw = public.read_text(encoding="ascii")
        if len(raw) > 8192 or "\n" in raw.strip() or "\x00" in raw:
            return "PUBLIC_KEY_INVALID"
        fields = raw.strip().split()
        if (len(fields) < 2 or fields[0] != "sk-ssh-ed25519@openssh.com"
                or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[1])):
            return "PUBLIC_KEY_INVALID"
        info = subprocess.run(
            ["ssh-keygen", "-lf", str(public)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=6, check=False,
        )
        if info.returncode != 0 or info.stderr.strip() or len(info.stdout) > 2048:
            return "FINGERPRINT_UNVERIFIED"
        fingerprints = re.findall(r"SHA256:[A-Za-z0-9+/=]+", info.stdout)
        if fingerprints != [FINGERPRINT] or "(ED25519-SK)" not in info.stdout:
            return "UNEXPECTED_PUBLIC_KEY_FINGERPRINT"
        return "EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE"
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return "LOCAL_KEY_UNVERIFIED"


def only_backup_card() -> bool:
    try:
        done = subprocess.run(
            ["ykman", "list", "--serials"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=10, check=False,
        )
        return (done.returncode == 0 and not done.stderr.strip()
                and done.stdout.splitlines() == [SERIAL])
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return False


def roundtrip(home: Path, *, tty: bool) -> str:
    ready = local_state(home)
    if ready != "EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE":
        return ready
    if not tty:
        return "INTERACTIVE_TTY_REQUIRED"
    if not only_backup_card():
        return "EXPECTED_ONE_BACKUP_YUBIKEY"
    private, public = paths(home)
    try:
        fields = public.read_text(encoding="ascii").split()
        with tempfile.TemporaryDirectory(prefix="nabla-fido2-proof-") as temporary:
            root = Path(temporary)
            fixture = root / "message.txt"
            signature = root / "message.txt.sig"
            signers = root / "allowed_signers"
            # Synthetic, non-personal message: never sign a real user file.
            fixture.write_text("Nabla disposable SSH FIDO2 proof v1\n", encoding="utf-8")
            signers.write_text(
                f"{IDENTITY} {fields[0]} {fields[1]}\n", encoding="ascii")
            # ssh-keygen handles interactive passphrase/PIN/touch via the TTY.
            sign = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(private),
                 "-n", NAMESPACE, str(fixture)],
                timeout=150, check=False,
            )
            if sign.returncode != 0:
                return "FIDO2_SIGNATURE_FAILED_NO_RETRY"
            info = signature.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_size < 1 or info.st_size > 65536):
                return "SIGNATURE_FILE_INVALID"
            with fixture.open("rb") as message:
                verify = subprocess.run(
                    ["ssh-keygen", "-Y", "verify",
                     "-f", str(signers), "-I", IDENTITY,
                     "-n", NAMESPACE, "-s", str(signature)],
                    stdin=message, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=15, check=False,
                )
            if verify.returncode != 0:
                return "FIDO2_SIGNATURE_VERIFICATION_FAILED"
        return "LOCAL_HARDWARE_SSHSIG_VERIFIED_REMOTE_LOGIN_NOT_TESTED"
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return "SIGNATURE_INTERRUPTED_NO_RETRY"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    opts = parser.add_mutually_exclusive_group(required=True)
    opts.add_argument("--check", action="store_true")
    opts.add_argument("--sign", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("acknowledge is only valid with --sign")
    if args.sign and args.acknowledge != ACK:
        parser.error("explicit confirmation required for hardware signature")
    home_text = os.environ.get("HOME", "")
    if not home_text or not Path(home_text).is_absolute():
        state = "HOME_UNAVAILABLE"
    elif args.check:
        state = local_state(Path(home_text))
    else:
        state = roundtrip(Path(home_text), tty=sys.stdin.isatty() and sys.stdout.isatty())
    print(json.dumps({
        "serial": SERIAL, "fingerprint": FINGERPRINT, "state": state,
        "existing_key_only": True, "enrollment_performed": False,
        "remote_login_verified": False, "hardware_mutation_authorized": False,
    }, sort_keys=True))
    return 0 if state in (
        "EXISTING_FIDO2_KEY_READY_FOR_SIGNATURE",
        "LOCAL_HARDWARE_SSHSIG_VERIFIED_REMOTE_LOGIN_NOT_TESTED",
    ) else 3


if __name__ == "__main__":
    sys.exit(main())
