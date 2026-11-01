#!/usr/bin/env python3
"""Read-only TrueNAS NFS4 ACL inventory for the new encrypted USB identity backup.

Inspect file and three directory ACLs via fixed-host, pinned-key SSH. Report
only coarse metadata: no ACE, principal, file name, raw ACL, or secret output.
This is an ACL inventory, never an effective authorization proof.
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
ACK = "INSPECT_NEW_USB_IDENTITY_BACKUP_NFS4_ACLS_READONLY"
FILENAME = re.compile(r"usb-recovery-identity-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.age\Z")
LEVELS = ("nfs_export", "secret_directory", "backup_directory", "encrypted_archive")
STATES = ("NFS4_REVIEW_REQUIRED", "POTENTIAL_NONOWNER_ALLOW", "NON_NFS4_ACL",
          "ACL_READ_UNAVAILABLE", "ACL_SCHEMA_UNVERIFIED", "UNTRUSTED_PATH")

# Executed on TrueNAS using a fixed command over SSH stdin. No arbitrary path,
# external API address or shell invocation is accepted from workstation input.
REMOTE = '''import json, stat, subprocess
from pathlib import Path
root = Path("/mnt/cpool/backup/lab")
relative = (".", "secret", "secret/usb-recovery-backups",
            "secret/usb-recovery-backups/" + EXPECTED_NAME)
results = []
for index, suffix in enumerate(relative):
    item = root / suffix
    record = {"level": index, "state": "ACL_READ_UNAVAILABLE",
              "acltype": "UNKNOWN", "trivial": None,
              "ace_count": None, "potential_nonowner_allow_count": None}
    try:
        metadata = item.lstat()
        if ((index < 3 and not stat.S_ISDIR(metadata.st_mode)) or
            (index == 3 and (not stat.S_ISREG(metadata.st_mode)
                              or metadata.st_nlink != 1)) or
            any(p.is_symlink() for p in (item, *item.parents))):
            record["state"] = "UNTRUSTED_PATH"
        else:
            proc = subprocess.run(
                ["midclt", "call", "filesystem.getacl", str(item), "false", "false"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, timeout=12, check=False)
            if proc.returncode == 0 and len(proc.stdout) <= 262144:
                acl = json.loads(proc.stdout)
                if (not isinstance(acl, dict) or acl.get("path") != str(item)
                    or acl.get("acltype") not in ("NFS4", "POSIX1E", "DISABLED")
                    or type(acl.get("trivial")) is not bool):
                    record["state"] = "ACL_SCHEMA_UNVERIFIED"
                else:
                    record["acltype"] = acl["acltype"]
                    record["trivial"] = acl["trivial"]
                    if acl["acltype"] != "NFS4":
                        record["state"] = "NON_NFS4_ACL"
                    elif (not isinstance(acl.get("acl"), list)
                          or len(acl["acl"]) > 256):
                        record["state"] = "ACL_SCHEMA_UNVERIFIED"
                    else:
                        potential = 0
                        invalid = False
                        for ace in acl["acl"]:
                            if not isinstance(ace, dict):
                                invalid = True
                                break
                            tag, action = ace.get("tag"), ace.get("type")
                            perms, flags = ace.get("perms"), ace.get("flags", {})
                            if (tag not in ("owner@", "group@", "everyone@", "USER", "GROUP")
                                or action not in ("ALLOW", "DENY")
                                or not isinstance(perms, dict)
                                or not isinstance(flags, dict)):
                                invalid = True
                                break
                            if action != "ALLOW" or tag == "owner@":
                                continue
                            if flags.get("INHERIT_ONLY") is True:
                                continue
                            basic = perms.get("BASIC")
                            if index == 3:
                                allowed = (basic in ("READ", "MODIFY", "FULL_CONTROL")
                                           or perms.get("READ_DATA") is True)
                            else:
                                allowed = (basic in ("READ", "MODIFY", "FULL_CONTROL", "TRAVERSE")
                                           or perms.get("EXECUTE") is True
                                           or perms.get("READ_DATA") is True)
                            if allowed:
                                potential += 1
                        if invalid:
                            record["state"] = "ACL_SCHEMA_UNVERIFIED"
                        else:
                            record["ace_count"] = len(acl["acl"])
                            record["potential_nonowner_allow_count"] = potential
                            record["state"] = ("POTENTIAL_NONOWNER_ALLOW" if potential
                                               else "NFS4_REVIEW_REQUIRED")
            elif proc.returncode == 0:
                record["state"] = "ACL_SCHEMA_UNVERIFIED"
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        record["state"] = "ACL_READ_UNAVAILABLE"
    results.append(record)
print(json.dumps({"levels": results}, sort_keys=True))
'''


def load_backup():
    spec = importlib.util.spec_from_file_location(
        "nabla_independent_usb_backup", HERE / "verify-usb-age-identity-independent-backup.py")
    if spec is None or spec.loader is None:
        raise ImportError("missing metadata preflight")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def query_server(filename: str) -> list[dict] | None:
    if not FILENAME.fullmatch(filename):
        return None
    code = "EXPECTED_NAME = " + json.dumps(filename) + "\n" + REMOTE
    command = ["ssh", "-T", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "NumberOfPasswordPrompts=0",
               "-o", "ConnectTimeout=5", "-o", "ClearAllForwardings=yes",
               "--", SSH_TARGET, "python3", "-"]
    try:
        proc = subprocess.run(command, input=code, text=True,
                              stdin=None, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=65, check=False)
        if proc.returncode != 0 or len(proc.stdout) > 8192:
            return None
        decoded = json.loads(proc.stdout)
        levels = decoded.get("levels") if isinstance(decoded, dict) else None
        if not isinstance(levels, list) or len(levels) != 4:
            return None
        for index, r in enumerate(levels):
            if (not isinstance(r, dict) or set(r) != {
                    "level", "state", "acltype", "trivial", "ace_count",
                    "potential_nonowner_allow_count"} or
                    type(r["level"]) is not int or r["level"] != index or
                    r["state"] not in STATES or
                    r["acltype"] not in ("UNKNOWN", "NFS4", "POSIX1E", "DISABLED") or
                    (r["trivial"] is not None and type(r["trivial"]) is not bool) or
                    any(r[key] is not None and (type(r[key]) is not int or
                        not 0 <= r[key] <= 256) for key in (
                            "ace_count", "potential_nonowner_allow_count"))):
                return None
        return levels
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
        parser.error("--check does not accept an acknowledgement")
    if args.probe and args.acknowledge != ACK:
        parser.error("explicit read-only ACL authorisation required")
    state, pair = "BACKUP_PREFLIGHT_UNAVAILABLE", None
    try:
        state, pair = load_backup().encrypted_pair()
    except (OSError, ValueError, ImportError, AttributeError, TypeError):
        pass
    raw = query_server(pair[1].name) if args.probe and pair else None
    levels = None
    if raw is not None:
        levels = [{"level": LEVELS[i], "state": r["state"],
                   "acltype": r["acltype"], "trivial": r["trivial"],
                   "ace_count": r["ace_count"],
                   "potential_nonowner_allow_count": r["potential_nonowner_allow_count"]}
                  for i, r in enumerate(raw)]
    print(json.dumps({
        "mode": "NEW_USB_IDENTITY_BACKUP_NFS4_ACL_METADATA",
        "status": "REVIEW_REQUIRED", "backup_state": state,
        "acl_probe_state": "NOT_PROBED" if args.check else (
            "ACL_INVENTORY_RECORDED" if levels is not None else "ACL_PROBE_UNAVAILABLE"),
        "levels": levels, "effective_nfs4_authorization_verified": False,
        "remote_write_performed": False, "archive_opened": False,
        "secret_or_principal_disclosed": False, "acl_entries_disclosed": False,
        "passphrase_access_verified": False,
    }, sort_keys=True))
    if args.check:
        return 0 if pair is not None else 3
    return 0 if (levels is not None and all(r["state"] == "NFS4_REVIEW_REQUIRED"
                                          for r in levels)) else 3


if __name__ == "__main__":
    sys.exit(main())
