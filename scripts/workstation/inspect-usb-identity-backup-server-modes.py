#!/usr/bin/env python3
"""Read-only TrueNAS-side file-mode boundary for independent encrypted USB escrow.

No chmod/chown, archive reads, secrets, usernames, UID/GID values or paths in
reports. File mode and ownership consistency are NOT effective NFS4 access tests.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SSH_TARGET = "albandrieu@172.17.0.24"
ACK = "INSPECT_USB_AGE_BACKUP_TRUENAS_MODES_READONLY"
NAME = re.compile(r"usb-recovery-identity-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.age\Z")
LEVELS = ("nfs_export", "secret_directory", "backup_directory", "encrypted_archive")
STATES = ("EXPORT_DIRECTORY_PRESENT", "PRIVATE_DIRECTORY_MODE_0700",
          "PRIVATE_FILE_MODE_0600", "MODE_REVIEW_REQUIRED",
          "UNTRUSTED_PATH", "STAT_UNAVAILABLE")

REMOTE = '''import json, stat
from pathlib import Path
root = Path("/mnt/cpool/backup/lab")
entries = (root, root / "secret", root / "secret/usb-recovery-backups",
           root / "secret/usb-recovery-backups" / EXPECTED_NAME)
out = []
owners = []
for index, path in enumerate(entries):
    result = {"level": index, "state": "STAT_UNAVAILABLE"}
    try:
        metadata = path.lstat()
        if (any(node.is_symlink() for node in (path, *path.parents))
            or not (stat.S_ISREG(metadata.st_mode) if index == 3
                    else stat.S_ISDIR(metadata.st_mode))
            or (index == 3 and metadata.st_nlink != 1)):
            result["state"] = "UNTRUSTED_PATH"
        else:
            owners.append(metadata.st_uid if index > 0 else None)
            mode = stat.S_IMODE(metadata.st_mode)
            if index == 0:
                result["state"] = "EXPORT_DIRECTORY_PRESENT"
            elif index == 3 and mode == 0o600:
                result["state"] = "PRIVATE_FILE_MODE_0600"
            elif index in (1, 2) and mode == 0o700:
                result["state"] = "PRIVATE_DIRECTORY_MODE_0700"
            else:
                result["state"] = "MODE_REVIEW_REQUIRED"
    except (OSError, ValueError):
        result["state"] = "STAT_UNAVAILABLE"
    out.append(result)
owner_uniform = (len(owners) == 4 and
                 owners[1] == owners[2] == owners[3])
print(json.dumps({"levels": out, "sensitive_owner_uniform": owner_uniform},
                 sort_keys=True))
'''


def preflight() -> tuple[str, str | None]:
    try:
        spec = importlib.util.spec_from_file_location(
            "nabla_usb_mode_metadata", HERE / "verify-usb-age-identity-independent-backup.py")
        if spec is None or spec.loader is None:
            return "BACKUP_METADATA_UNAVAILABLE", None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        state, pair = module.encrypted_pair()
        return state, pair[1].name if pair else None
    except (ImportError, OSError, AttributeError, TypeError, ValueError):
        return "BACKUP_METADATA_UNAVAILABLE", None


def query_server(name: str) -> dict | None:
    if not NAME.fullmatch(name):
        return None
    code = "EXPECTED_NAME = " + json.dumps(name) + "\n" + REMOTE
    command = ["ssh", "-T", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "NumberOfPasswordPrompts=0",
               "-o", "ConnectTimeout=5", "-o", "ClearAllForwardings=yes",
               "--", SSH_TARGET, "python3", "-"]
    try:
        result = subprocess.run(
            command, input=code, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=20, check=False)
        if result.returncode != 0 or len(result.stdout) > 4096:
            return None
        decoded = json.loads(result.stdout)
        if not isinstance(decoded, dict) or set(decoded) != {
                "levels", "sensitive_owner_uniform"}:
            return None
        records = decoded["levels"]
        if (not isinstance(records, list) or len(records) != 4 or
                type(decoded["sensitive_owner_uniform"]) is not bool):
            return None
        for index, entry in enumerate(records):
            if (not isinstance(entry, dict) or set(entry) != {"level", "state"}
                    or type(entry["level"]) is not int or entry["level"] != index
                    or entry["state"] not in STATES):
                return None
        return decoded
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--probe", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--check does not accept acknowledgement")
    if args.probe and args.acknowledge != ACK:
        parser.error("explicit read-only TrueNAS mode inventory authorization required")
    backup_state, name = preflight()
    evidence = query_server(name) if args.probe and name else None
    success = evidence is not None and evidence["sensitive_owner_uniform"] and all(
        item["state"] == expected for item, expected in zip(
            evidence["levels"], ("EXPORT_DIRECTORY_PRESENT",
                                  "PRIVATE_DIRECTORY_MODE_0700",
                                  "PRIVATE_DIRECTORY_MODE_0700",
                                  "PRIVATE_FILE_MODE_0600")))
    print(json.dumps({
        "mode": "USB_AGE_BACKUP_TRUENAS_FILE_MODE_BOUNDARY",
        "backup_state": backup_state,
        "server_probe_state": ("NOT_PROBED" if args.check else
                               ("MODE_INVENTORY_RECORDED" if evidence else "MODE_PROBE_UNAVAILABLE")),
        "levels": ([{"level": LEVELS[i], "state": r["state"]}
                    for i, r in enumerate(evidence["levels"])] if evidence else None),
        "sensitive_owner_uniform": (evidence["sensitive_owner_uniform"] if evidence else None),
        "private_mode_boundary_observed": success,
        "status": "MODE_BOUNDARY_OBSERVED" if success else "REVIEW_REQUIRED",
        "effective_nfs4_authorization_verified": False,
        "nfs_identity_mapping_verified": False,
        "private_identity_or_passphrase_read": False,
        "remote_write_performed": False,
        "paths_or_uid_gid_disclosed": False,
    }, sort_keys=True))
    if args.check:
        return 0 if name else 3
    return 0 if success else 3


if __name__ == "__main__":
    sys.exit(main())
