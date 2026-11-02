#!/usr/bin/env python3
"""Verify restoration of two passphrase-encrypted USB identity backups without USB.

No raw identity is written to disk. Decryption is confined to process memory;
only a public age recipient is derived and compared, never printed. Run in a
private interactive terminal, with the original SanDisk disconnected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ACK = "VERIFY_BOTH_PASSPHRASE_ENCRYPTED_USB_IDENTITY_BACKUPS"
EXPECTED_RECIPIENT = "age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938"
LOCAL_PARENT = Path.home() / ".local/share/nabla"
LOCAL_DIR = LOCAL_PARENT / "usb-recovery-backups"
NFS_PARENT = Path("/media/backup/lab/secret")
NFS_DIR = NFS_PARENT / "usb-recovery-backups"
NFS_MOUNT = "/media/backup/lab"
NFS_EXPORT = "nabla:/mnt/cpool/backup/lab"
NAME = re.compile(r"usb-recovery-identity-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.age\Z")
MAX_FILE = 2 * 1024 * 1024
MAX_IDENTITY = 65536


def trusted_directory(path: Path) -> bool:
    try:
        if any(node.is_symlink() for node in (path, *path.parents)):
            return False
        info = path.lstat()
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700)
    except OSError:
        return False


def trusted_mount() -> bool:
    try:
        proc = subprocess.run(
            ["findmnt", "-n", "-T", str(NFS_PARENT), "-o", "TARGET,FSTYPE,SOURCE"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=6, check=False)
        return (proc.returncode == 0 and len(proc.stdout) < 512
                and proc.stdout.strip().split() in
                ([NFS_MOUNT, "nfs", NFS_EXPORT],
                 [NFS_MOUNT, "nfs4", NFS_EXPORT]))
    except (OSError, subprocess.TimeoutExpired):
        return False


def encrypted_pair() -> tuple[str, tuple[Path, Path] | None]:
    if not trusted_mount():
        return "NFS_EXPORT_UNVERIFIED", None
    if not all(trusted_directory(p) for p in (LOCAL_DIR, NFS_PARENT, NFS_DIR)):
        return "DESTINATION_PERMISSIONS_UNVERIFIED", None
    try:
        local_parent = LOCAL_PARENT.lstat()
        if (not stat.S_ISDIR(local_parent.st_mode)
                or local_parent.st_uid != os.getuid()
                or stat.S_IMODE(local_parent.st_mode) & 0o022
                or LOCAL_PARENT.is_symlink()):
            return "DESTINATION_PERMISSIONS_UNVERIFIED", None
        if LOCAL_DIR.stat().st_dev == NFS_DIR.stat().st_dev:
            return "BACKUPS_NOT_ON_DISTINCT_FILESYSTEMS", None
        matches = []
        for directory in (LOCAL_DIR, NFS_DIR):
            with os.scandir(directory) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 128:
                        return "BACKUPS_ABSENT_OR_AMBIGUOUS", None
            if len(names) != 1 or not NAME.fullmatch(names[0]):
                return "BACKUPS_ABSENT_OR_AMBIGUOUS", None
            archive = directory / names[0]
            info = archive.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 32 <= info.st_size <= MAX_FILE):
                return "BACKUP_FILE_METADATA_UNTRUSTED", None
            matches.append(archive)
        if matches[0].name != matches[1].name:
            return "BACKUP_NAMES_DIFFER", None
        return "BACKUP_RESTORATION_PREFLIGHT_READY", (matches[0], matches[1])
    except (OSError, ValueError):
        return "BACKUP_METADATA_UNAVAILABLE", None


def secure_open(path: Path) -> int:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or not 32 <= info.st_size <= MAX_FILE):
        raise ValueError("untrusted ciphertext")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    now = os.fstat(descriptor)
    if (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
        os.close(descriptor)
        raise ValueError("ciphertext changed")
    return descriptor


def ciphertext_digest(fd: int) -> bytes:
    value = hashlib.sha256()
    count = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 65536):
        count += len(chunk)
        if count > MAX_FILE:
            raise ValueError("oversized ciphertext")
        value.update(chunk)
    if count < 32:
        raise ValueError("invalid ciphertext length")
    os.lseek(fd, 0, os.SEEK_SET)
    return value.digest()


def recovered_recipient(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    plain = subprocess.run(
        ["age", "--decrypt"], stdin=fd, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=240, check=False)
    if plain.returncode or not 0 < len(plain.stdout) <= MAX_IDENTITY:
        return "RESTORE_FAILED"
    public = subprocess.run(
        ["age-keygen", "-y"], input=plain.stdout, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=15, check=False)
    if public.returncode or len(public.stdout) > 2048:
        return "RESTORE_FAILED"
    try:
        value = public.stdout.decode("ascii").strip()
    except UnicodeError:
        return "RESTORE_FAILED"
    return "RECIPIENT_MATCH" if value == EXPECTED_RECIPIENT else "RECIPIENT_MISMATCH"


def verify(pair: tuple[Path, Path]) -> str:
    handles: list[int] = []
    try:
        for path in pair:
            handles.append(secure_open(path))
        if ciphertext_digest(handles[0]) != ciphertext_digest(handles[1]):
            return "ENCRYPTED_COPIES_DIFFER"
        for fd in handles:
            outcome = recovered_recipient(fd)
            if outcome != "RECIPIENT_MATCH":
                return "RESTORE_FAILED_OR_RECIPIENT_MISMATCH"
        return "BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "RESTORE_UNAVAILABLE"
    finally:
        for fd in handles:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--check must not carry acknowledgement")
    if args.verify and args.acknowledge != ACK:
        parser.error("explicit confirmation required")
    state, pair = encrypted_pair()
    if args.verify and pair is not None:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            state = "INTERACTIVE_TERMINAL_REQUIRED"
        else:
            state = verify(pair)
    success = state == "BOTH_BACKUPS_RESTORED_WITH_HISTORICAL_RECIPIENT"
    print(json.dumps({
        "mode": "INDEPENDENT_USB_AGE_IDENTITY_BACKUP_RESTORE",
        "state": state,
        "two_encrypted_backups_restored": success,
        "historical_public_recipient_matched": success,
        "original_usb_required": False,
        "plaintext_written_to_disk": False,
        "private_identity_or_passphrase_disclosed": False,
        "hardware_or_sops_modified": False,
    }, sort_keys=True))
    return 0 if success or (args.check and pair is not None) else 3


if __name__ == "__main__":
    sys.exit(main())
