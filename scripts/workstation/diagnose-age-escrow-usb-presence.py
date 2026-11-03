#!/usr/bin/env python3
"""Read-only, redacted LUKS USB escrow discovery when /dev/disk/by-uuid is missing.

This does not unlock or mount anything. It inspects bounded lsblk JSON and the
existence of the historical LUKS UUID udev link. It never reads any identity,
secret, encrypted archive, or raw block-device content.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

# Historical LUKS partition UUID, NOT the ext4 filesystem UUID.
EXPECTED_LUKS_UUID = "3742c7b9-ccb7-4b5e-b1db-18bcf916c548"
UUID_LINK = Path("/dev/disk/by-uuid") / EXPECTED_LUKS_UUID
MAX_JSON_BYTES = 131072
MAX_DEVICES = 256


def children_of(node: dict) -> list[dict]:
    children = node.get("children", [])
    if children is None:
        return []
    if not isinstance(children, list):
        raise ValueError("malformed lsblk children")
    if not all(isinstance(item, dict) for item in children):
        raise ValueError("malformed lsblk node")
    return children


def enumerate_nodes(data: object) -> list[dict]:
    if not isinstance(data, dict) or not isinstance(data.get("blockdevices"), list):
        raise ValueError("malformed lsblk root")
    pending = data["blockdevices"][:]
    nodes: list[dict] = []
    while pending:
        if len(nodes) + len(pending) > MAX_DEVICES:
            raise ValueError("lsblk device inventory too large")
        node = pending.pop()
        if not isinstance(node, dict):
            raise ValueError("invalid lsblk device")
        nodes.append(node)
        pending.extend(children_of(node))
    return nodes


def active_mapping_state(node: dict) -> str:
    children = children_of(node)
    mappings = [c for c in children if c.get("type") == "crypt"]
    if len(mappings) > 1:
        return "ESCROW_MAPPING_AMBIGUOUS"
    if not mappings:
        return "ESCROW_LUKS_LOCKED"
    crypt = mappings[0]
    mountpoints = crypt.get("mountpoints")
    if mountpoints is None:
        mountpoints = []
    if not isinstance(mountpoints, list):
        return "ESCROW_MOUNT_METADATA_UNVERIFIED"
    if any(isinstance(mount, str) and mount.startswith("/")
           for mount in mountpoints):
        return "ESCROW_LUKS_UNLOCKED_MOUNTED"
    # A mapping can be open while the filesystem is not mounted.
    return "ESCROW_LUKS_UNLOCKED_NOT_MOUNTED"


def assess(data: object, uuid_link_present: bool) -> str:
    nodes = enumerate_nodes(data)
    matching = [node for node in nodes
                if isinstance(node.get("uuid"), str)
                and node["uuid"].casefold() == EXPECTED_LUKS_UUID]
    if len(matching) > 1:
        return "ESCROW_UUID_AMBIGUOUS"
    if not matching:
        return "ESCROW_UUID_NOT_ENUMERATED"
    match = matching[0]
    if match.get("fstype") != "crypto_LUKS":
        return "ESCROW_UUID_UNEXPECTED_FSTYPE"
    if match.get("type") not in ("part", "disk"):
        return "ESCROW_UUID_UNEXPECTED_DEVICE_TYPE"
    if not uuid_link_present:
        return "ESCROW_LUKS_PRESENT_UDEV_LINK_MISSING"
    return active_mapping_state(match)


def inspect() -> tuple[str, bool | None]:
    try:
        proc = subprocess.run(
            ["lsblk", "-J", "-p", "-o", "NAME,TYPE,FSTYPE,UUID,MOUNTPOINTS"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8, check=False,
        )
        if proc.returncode != 0 or len(proc.stdout) > MAX_JSON_BYTES:
            return "LSBLK_INVENTORY_UNAVAILABLE", None
        parsed = json.loads(proc.stdout)
        udev_link = UUID_LINK.is_block_device()
        return assess(parsed, udev_link), udev_link
    except (FileNotFoundError, OSError, ValueError, TypeError,
            subprocess.TimeoutExpired):
        return "LSBLK_INVENTORY_UNAVAILABLE", None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args(argv)
    state, link = inspect()
    print(json.dumps({
        "mode": "AGE_ESCROW_USB_LUKS_DISCOVERY_METADATA_ONLY",
        "state": state, "status": "NO-GO",
        "luks_uuid_link_present": link,
        "device_identifiers_disclosed": False,
        "device_paths_disclosed": False,
        "secret_content_opened": False,
        "private_age_identity_read": False,
        "luks_unlock_attempted": False,
        "usb_mount_attempted": False,
        "disk_mutation_performed": False,
        "decryption_attempted": False,
        "restore_verified": False,
    }, sort_keys=True))
    return 0 if state in ("ESCROW_LUKS_LOCKED",
                          "ESCROW_LUKS_UNLOCKED_MOUNTED",
                          "ESCROW_LUKS_UNLOCKED_NOT_MOUNTED") else 3


if __name__ == "__main__":
    sys.exit(main())
