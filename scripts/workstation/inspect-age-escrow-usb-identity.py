#!/usr/bin/env python3
"""Check mounted LUKS escrow USB and recovery age identity *metadata only*.

Never opens recovery-identity.txt or age ciphertext; no public-key derivation,
decryption, USB unlock, mount, copy, sudo, mutation, or private path disclosure.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

LUKS_UUID = "3742c7b9-ccb7-4b5e-b1db-18bcf916c548"
MAX_JSON = 131072
MAX_NODES = 256
MAX_IDENTITY_BYTES = 65536


def expected_mount() -> Path:
    return Path("/run/media") / getpass.getuser() / "NABLA_ESCROW"


def walk_nodes(data: object) -> list[dict]:
    if not isinstance(data, dict) or not isinstance(data.get("blockdevices"), list):
        raise ValueError("invalid block inventory")
    todo = data["blockdevices"][:]
    seen: list[dict] = []
    while todo:
        if len(todo) + len(seen) > MAX_NODES:
            raise ValueError("block inventory too large")
        entry = todo.pop()
        if not isinstance(entry, dict):
            raise ValueError("invalid block inventory node")
        seen.append(entry)
        children = entry.get("children") or []
        if not isinstance(children, list):
            raise ValueError("invalid block children")
        todo.extend(children)
    return seen


def match_usb_mount(data: object, mount: Path) -> str:
    """Correlate exact historical crypto_LUKS UUID to its ext4 mapper mount."""
    entries = walk_nodes(data)
    parents = [entry for entry in entries if
               isinstance(entry.get("uuid"), str)
               and entry["uuid"].lower() == LUKS_UUID]
    if not parents:
        return "USB_LUKS_UUID_NOT_ENUMERATED"
    if len(parents) != 1:
        return "USB_LUKS_UUID_AMBIGUOUS"
    parent = parents[0]
    if (parent.get("fstype") != "crypto_LUKS"
            or parent.get("type") not in ("part", "disk")):
        return "USB_LUKS_PARENT_UNVERIFIED"
    children = parent.get("children") or []
    if not isinstance(children, list):
        return "USB_LUKS_MAPPING_UNVERIFIED"
    crypt = [child for child in children if isinstance(child, dict)
             and child.get("type") == "crypt"]
    if len(crypt) != 1:
        return "USB_LUKS_MAPPING_UNVERIFIED"
    device = crypt[0]
    mounts = device.get("mountpoints")
    if (device.get("fstype") != "ext4" or not isinstance(mounts, list)
            or str(mount) not in mounts):
        return "USB_LUKS_MOUNT_UNVERIFIED"
    return "USB_LUKS_MOUNT_MATCHED"


def check_identity_metadata(mount: Path) -> str:
    """Never read the private identity, only lstat its expected location."""
    file_path = mount / "age-escrow" / "recovery-identity.txt"
    try:
        for directory in (mount, mount.parent, mount.parent.parent,
                          file_path.parent):
            if directory.is_symlink() or not stat.S_ISDIR(directory.lstat().st_mode):
                return "USB_IDENTITY_PATH_UNTRUSTED"
        record = file_path.lstat()
        if (not stat.S_ISREG(record.st_mode) or record.st_nlink != 1
                or record.st_uid != os.getuid()
                or stat.S_IMODE(record.st_mode) != 0o600
                or not 0 < record.st_size <= MAX_IDENTITY_BYTES):
            return "USB_IDENTITY_METADATA_UNTRUSTED"
        return "USB_IDENTITY_METADATA_PRESENT"
    except FileNotFoundError:
        return "USB_IDENTITY_NOT_FOUND"
    except (OSError, ValueError, TypeError):
        return "USB_IDENTITY_METADATA_UNAVAILABLE"


def inspect() -> tuple[str, str, str]:
    mount = expected_mount()
    try:
        block = subprocess.run(
            ["lsblk", "-J", "-p", "-o", "NAME,TYPE,FSTYPE,UUID,MOUNTPOINTS"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8, check=False,
        )
        if block.returncode or len(block.stdout) > MAX_JSON:
            return "USB_BLOCK_INVENTORY_UNAVAILABLE", "NOT_CHECKED", "NOT_CHECKED"
        state = match_usb_mount(json.loads(block.stdout), mount)
        if state != "USB_LUKS_MOUNT_MATCHED":
            return state, "NOT_CHECKED", "NOT_CHECKED"
        mounted = subprocess.run(
            ["findmnt", "-n", "-T", str(mount), "-o", "TARGET,FSTYPE"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=5, check=False,
        )
        if (mounted.returncode or len(mounted.stdout) > 512
                or mounted.stdout.strip().split() != [str(mount), "ext4"]):
            return state, "USB_MOUNT_SOURCE_UNVERIFIED", "NOT_CHECKED"
        return state, "USB_EXPECTED_EXT4_MOUNT_PRESENT", check_identity_metadata(mount)
    except (FileNotFoundError, ValueError, TypeError, OSError,
            UnicodeError, subprocess.TimeoutExpired):
        return "USB_BLOCK_INVENTORY_UNAVAILABLE", "NOT_CHECKED", "NOT_CHECKED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args(argv)
    state, mounted, identity = inspect()
    print(json.dumps({
        "mode": "USB_AGE_RECOVERY_IDENTITY_METADATA_ONLY",
        "status": "NO-GO",
        "usb_state": state, "mount_state": mounted,
        "identity_state": identity,
        "identity_private_content_read": False,
        "identity_recipient_derived": False,
        "archive_opened": False, "decryption_attempted": False,
        "restore_verified": False,
        "device_identifiers_disclosed": False,
        "device_paths_disclosed": False,
        "usb_identity_path_disclosed": False,
        "usb_mount_performed": False,
        "hardware_mutation_authorized": False,
        "filesystem_write_performed": False,
    }, sort_keys=True))
    return 0 if (state == "USB_LUKS_MOUNT_MATCHED"
                 and mounted == "USB_EXPECTED_EXT4_MOUNT_PRESENT"
                 and identity == "USB_IDENTITY_METADATA_PRESENT") else 3


if __name__ == "__main__":
    sys.exit(main())
