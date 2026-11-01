#!/usr/bin/env python3
"""Back up the existing USB age recovery identity to workstation and TrueNAS.

--check only inspects metadata. --backup requires explicit acknowledgement and
an interactive TTY. age -p receives the USB private identity on stdin and
prompts for an independent passphrase. Only encrypted data reach backup disks.
No key generation, plaintext backup, overwrites, or secret-containing logs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ACK = "CREATE_NEW_PASSPHRASE_ENCRYPTED_USB_IDENTITY_BACKUPS"
LOCAL_PARENT = Path.home() / ".local/share/nabla"
LOCAL_DIR = LOCAL_PARENT / "usb-recovery-backups"
NFS_PARENT = Path("/media/backup/lab/secret")
NFS_DIR = NFS_PARENT / "usb-recovery-backups"
NFS_MOUNT = "/media/backup/lab"
NFS_EXPORT = "nabla:/mnt/cpool/backup/lab"
PATTERN = "usb-recovery-identity-*.age"
MAX_SOURCE = 65536
MAX_CIPHERTEXT = 2 * 1024 * 1024


def usb_module():
    spec = importlib.util.spec_from_file_location(
        "nabla_escrow_usb_metadata",
        HERE / "inspect-age-escrow-usb-identity.py",
    )
    if spec is None or spec.loader is None:
        raise ValueError("usb helper missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def directory_trusted(path: Path, *, private: bool) -> bool:
    try:
        for node in (path, *path.parents):
            if node.is_symlink():
                return False
        record = path.lstat()
        if not stat.S_ISDIR(record.st_mode):
            return False
        if private and (record.st_uid != os.getuid() or
                        stat.S_IMODE(record.st_mode) != 0o700):
            return False
        return True
    except OSError:
        return False


def nfs_mounted() -> bool:
    try:
        proc = subprocess.run(
            ["findmnt", "-n", "-T", str(NFS_PARENT), "-o",
             "TARGET,FSTYPE,SOURCE"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, text=True, timeout=6, check=False,
        )
        fields = proc.stdout.strip().split()
        return (proc.returncode == 0 and len(proc.stdout) < 512
                and len(fields) == 3 and fields[0] == NFS_MOUNT
                and fields[1] in ("nfs", "nfs4")
                and fields[2] == NFS_EXPORT)
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan_dir(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    if not directory_trusted(path, private=True):
        return "UNTRUSTED"
    try:
        with os.scandir(path) as entries:
            seen = 0
            for entry in entries:
                seen += 1
                if seen > 128:
                    return "UNTRUSTED"
                if (entry.name.startswith(".") or
                        entry.name.startswith("usb-recovery-identity-")):
                    return "EXISTING_OR_PARTIAL_BACKUP"
        return "EMPTY"
    except OSError:
        return "UNTRUSTED"


def preflight() -> tuple[str, Path | None]:
    try:
        helper = usb_module()
        usb, mount, identity = helper.inspect()
        if (usb != "USB_LUKS_MOUNT_MATCHED" or
                mount != "USB_EXPECTED_EXT4_MOUNT_PRESENT" or
                identity != "USB_IDENTITY_METADATA_PRESENT"):
            return "USB_IDENTITY_UNVERIFIED", None
        if not directory_trusted(LOCAL_PARENT, private=False):
            return "LOCAL_PARENT_UNTRUSTED", None
        parent_stat = LOCAL_PARENT.lstat()
        if (parent_stat.st_uid != os.getuid() or
                stat.S_IMODE(parent_stat.st_mode) & 0o022):
            return "LOCAL_PARENT_UNTRUSTED", None
        if not nfs_mounted():
            return "NFS_EXPORT_UNVERIFIED", None
        if not directory_trusted(NFS_PARENT, private=True):
            return "NFS_PARENT_UNTRUSTED", None
        for dest in (LOCAL_DIR, NFS_DIR):
            status = scan_dir(dest)
            if status == "UNTRUSTED":
                return "DESTINATION_UNTRUSTED", None
            if status == "EXISTING_OR_PARTIAL_BACKUP":
                return "EXISTING_BACKUP_NEEDS_REVIEW", None
        return "BACKUP_PREFLIGHT_READY", (
            helper.expected_mount() / "age-escrow/recovery-identity.txt"
        )
    except (OSError, TypeError, ValueError, AttributeError, ImportError):
        return "BACKUP_PREFLIGHT_UNAVAILABLE", None


def create_private_dir(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    if not directory_trusted(path, private=True):
        raise ValueError("private destination directory not trusted")


def source_open(path: Path) -> tuple[int, os.stat_result]:
    if path.is_symlink() or any(node.is_symlink() for node in path.parents):
        raise ValueError("source path not trusted")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_SOURCE):
        raise ValueError("source metadata not trusted")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    current = os.fstat(fd)
    if ((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
         current.st_ctime_ns) !=
        (before.st_dev, before.st_ino, before.st_size,
         before.st_mtime_ns, before.st_ctime_ns)):
        os.close(fd)
        raise ValueError("source changed while opening")
    return fd, current


def unchanged(fd: int, before: os.stat_result) -> bool:
    current = os.fstat(fd)
    return (current.st_dev, current.st_ino, current.st_size,
            current.st_mtime_ns, current.st_ctime_ns) == (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns)


def digest(path: Path) -> tuple[int, bytes]:
    total = 0
    hash_obj = hashlib.sha256()
    with path.open("rb") as file:
        while block := file.read(65536):
            total += len(block)
            if total > MAX_CIPHERTEXT:
                raise ValueError("ciphertext is too large")
            hash_obj.update(block)
    if total < 32:
        raise ValueError("ciphertext too small")
    return total, hash_obj.digest()


def stage_copy(source: Path, target_dir: Path) -> Path:
    fd, name = tempfile.mkstemp(prefix=".pending-escrow-", dir=target_dir)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as inp:
            while data := inp.read(65536):
                output.write(data)
            output.flush()
            os.fsync(output.fileno())
        staged.chmod(0o600)
        if digest(staged) != digest(source):
            raise ValueError("encrypted copies do not match")
        return staged
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def publish(stage: Path, destination: Path) -> None:
    # Hard-link promotion does not overwrite an existing file.
    os.link(stage, destination, follow_symlinks=False)
    stage.unlink()


def backup(path: Path) -> str:
    previous_umask = os.umask(0o077)
    staged_local = staged_nfs = None
    fd = None
    try:
        state, expected = preflight()
        if state != "BACKUP_PREFLIGHT_READY" or expected != path:
            return "PREFLIGHT_CHANGED"
        create_private_dir(LOCAL_DIR)
        create_private_dir(NFS_DIR)
        if scan_dir(LOCAL_DIR) != "EMPTY" or scan_dir(NFS_DIR) != "EMPTY":
            return "EXISTING_BACKUP_NEEDS_REVIEW"
        if LOCAL_DIR.stat().st_dev == NFS_DIR.stat().st_dev:
            return "BACKUPS_NOT_ON_DISTINCT_FILESYSTEMS"
        fd, stat_before = source_open(path)
        temp_fd, name = tempfile.mkstemp(prefix=".pending-escrow-", dir=LOCAL_DIR)
        staged_local = Path(name)
        os.close(temp_fd)
        # age prompts on the terminal; the USB secret arrives only via stdin fd.
        proc = subprocess.run(
            ["age", "-p", "-o", str(staged_local)],
            stdin=fd, stdout=subprocess.DEVNULL, timeout=240, check=False,
        )
        if proc.returncode != 0:
            return "ENCRYPTION_FAILED"
        if not unchanged(fd, stat_before):
            return "USB_IDENTITY_CHANGED_DURING_BACKUP"
        staged_local.chmod(0o600)
        encrypted_size, encrypted_hash = digest(staged_local)
        staged_nfs = stage_copy(staged_local, NFS_DIR)
        if digest(staged_nfs) != (encrypted_size, encrypted_hash):
            return "ENCRYPTED_COPIES_DIFFER"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"usb-recovery-identity-{stamp}-{secrets.token_hex(4)}.age"
        local_final, nfs_final = LOCAL_DIR / name, NFS_DIR / name
        publish(staged_nfs, nfs_final)
        staged_nfs = None
        publish(staged_local, local_final)
        staged_local = None
        if digest(local_final) != digest(nfs_final):
            return "ENCRYPTED_COPIES_DIFFER"
        return "ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "BACKUP_INCOMPLETE_REVIEW_REQUIRED"
    finally:
        if fd is not None:
            os.close(fd)
        for stage in (staged_local, staged_nfs):
            if stage is not None:
                stage.unlink(missing_ok=True)
        os.umask(previous_umask)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--backup", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.backup and args.acknowledge != ACK:
        parser.error("--backup requires explicit acknowledgement")
    if args.check and args.acknowledge:
        parser.error("--check does not accept acknowledgement")
    state, path = preflight()
    if args.backup and path is not None and state == "BACKUP_PREFLIGHT_READY":
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            state = "INTERACTIVE_TERMINAL_REQUIRED"
        else:
            state = backup(path)
    print(json.dumps({
        "mode": "USB_AGE_INDEPENDENT_PASSPHRASE_ESCROW",
        "state": state,
        "encrypted_copy_local_and_nfs_verified":
            state == "ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL",
        "original_usb_identity_modified": False,
        "raw_usb_private_identity_written_to_destinations": False,
        "encrypted_copy_only": True,
        "encrypted_backup_restoration_verified": False,
        "files_or_private_paths_disclosed": False,
    }, sort_keys=True))
    return 0 if ((state == "BACKUP_PREFLIGHT_READY" and args.check) or
                 state == "ENCRYPTED_LOCAL_AND_NFS_BACKUPS_IDENTICAL") else 3


if __name__ == "__main__":
    sys.exit(main())
