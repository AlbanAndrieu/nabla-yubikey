#!/usr/bin/env python3
"""Read-only TrueNAS native ACL inventory for an existing encrypted age escrow.

The TrueNAS filesystem.getacl API is queried via an existing trusted SSH
connection. All ACL entries, identifiers, private paths and tool stderr stay
on the server. The JSON report is coarse evidence, NOT an access decision.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

BASE = Path(__file__).with_name("inspect-yubikey-escrow-nfs-server.py")
SSH_TARGET = "albandrieu@172.17.0.24"
ACK = "INSPECT_EXISTING_TRUENAS_AGE_ESCROW_ACL_READONLY"
ALLOWED = {
    "ACL_NATIVE_REVIEW_REQUIRED",
    "ACL_POTENTIAL_NONOWNER_DATA_ALLOW",
    "ACL_TYPE_NOT_NFS4",
    "ACL_READ_UNAVAILABLE",
    "ACL_RESPONSE_UNVERIFIED",
    "ACL_UNTRUSTED_PATH",
}
MAX_JSON = 262144

REMOTE = '''import json, os, stat, subprocess
from pathlib import Path
name = EXPECTED_NAME
directory = Path("/mnt/cpool/backup/lab/secret")
output = {"state": "ACL_READ_UNAVAILABLE", "acltype": "UNKNOWN",
          "trivial": None, "ace_count": None,
          "potential_nonowner_read_allow_count": None}
try:
    if any(part.is_symlink() for part in (directory, *directory.parents)):
        output["state"] = "ACL_UNTRUSTED_PATH"
    else:
        target = directory / name
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            output["state"] = "ACL_UNTRUSTED_PATH"
        else:
            proc = subprocess.run(
                ["midclt", "call", "filesystem.getacl", str(target), "false", "false"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, check=False, timeout=12,
            )
            if proc.returncode == 0 and len(proc.stdout) <= 262144:
                acl = json.loads(proc.stdout)
                if not isinstance(acl, dict):
                    output["state"] = "ACL_RESPONSE_UNVERIFIED"
                elif (acl.get("path") != str(target)
                      or acl.get("acltype") not in ("NFS4", "POSIX1E", "DISABLED")
                      or type(acl.get("trivial")) is not bool):
                    output["state"] = "ACL_RESPONSE_UNVERIFIED"
                else:
                    output["acltype"] = acl["acltype"]
                    output["trivial"] = acl["trivial"]
                    if acl["acltype"] != "NFS4":
                        output["state"] = "ACL_TYPE_NOT_NFS4"
                    elif not isinstance(acl.get("acl"), list) or len(acl["acl"]) > 256:
                        output["state"] = "ACL_RESPONSE_UNVERIFIED"
                    else:
                        candidates = 0
                        invalid = False
                        for ace in acl["acl"]:
                            if not isinstance(ace, dict):
                                invalid = True
                                break
                            tag = ace.get("tag")
                            action = ace.get("type")
                            permissions = ace.get("perms")
                            flags = ace.get("flags", {})
                            if (tag not in ("owner@", "group@", "everyone@", "USER", "GROUP")
                                or action not in ("ALLOW", "DENY")
                                or not isinstance(permissions, dict)
                                or not isinstance(flags, dict)):
                                invalid = True
                                break
                            if action != "ALLOW" or tag == "owner@":
                                continue
                            if flags.get("INHERIT_ONLY") is True:
                                continue
                            basic = permissions.get("BASIC")
                            grants_data = (basic in ("READ", "MODIFY", "FULL_CONTROL")
                                           or permissions.get("READ_DATA") is True)
                            if grants_data:
                                candidates += 1
                        if invalid:
                            output["state"] = "ACL_RESPONSE_UNVERIFIED"
                        else:
                            output["ace_count"] = len(acl["acl"])
                            output["potential_nonowner_read_allow_count"] = candidates
                            output["state"] = ("ACL_POTENTIAL_NONOWNER_DATA_ALLOW"
                                               if candidates else "ACL_NATIVE_REVIEW_REQUIRED")
            elif proc.returncode == 0:
                output["state"] = "ACL_RESPONSE_UNVERIFIED"
except (FileNotFoundError, PermissionError, OSError, ValueError,
        subprocess.TimeoutExpired, json.JSONDecodeError):
    output["state"] = "ACL_READ_UNAVAILABLE"
print(json.dumps(output, sort_keys=True))
'''


def load_base():
    spec = importlib.util.spec_from_file_location("nabla_age_escrow_acl_base", BASE)
    if spec is None or spec.loader is None:
        raise ImportError("source metadata reader unavailable")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def query_acl(target: str, filename: str) -> dict[str, object]:
    no_result = {"state": "SSH_ACL_UNAVAILABLE", "acltype": "UNKNOWN",
                 "trivial": None, "ace_count": None,
                 "potential_nonowner_read_allow_count": None}
    if (target != SSH_TARGET
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}\.age", filename)):
        return no_result
    program = "EXPECTED_NAME = " + json.dumps(filename) + "\n" + REMOTE
    command = ["ssh", "-T", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes",
               "-o", "NumberOfPasswordPrompts=0",
               "-o", "ConnectTimeout=5",
               "-o", "ClearAllForwardings=yes", "--",
               SSH_TARGET, "python3", "-"]
    try:
        proc = subprocess.run(command, input=program, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=22, check=False)
        if proc.returncode or len(proc.stdout) > 4096:
            return no_result
        result = json.loads(proc.stdout)
        if (not isinstance(result, dict)
                or set(result) != {"state", "acltype", "trivial", "ace_count",
                                  "potential_nonowner_read_allow_count"}
                or result["state"] not in ALLOWED
                or result["acltype"] not in ("NFS4", "POSIX1E", "DISABLED", "UNKNOWN")
                or (result["trivial"] is not None
                    and type(result["trivial"]) is not bool)
                or any(result[k] is not None and
                       (type(result[k]) is not int or not 0 <= result[k] <= 256)
                       for k in ("ace_count", "potential_nonowner_read_allow_count"))):
            return no_result
        return result
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return no_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--probe", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--check cannot accept remote authorization")
    if args.probe and args.acknowledge != ACK:
        parser.error("explicit native ACL metadata authorization required")
    mount = "MOUNT_UNVERIFIED"
    source = "SOURCE_UNVERIFIED"
    filename = None
    result: dict[str, object] = {"state": "NOT_PROBED", "acltype": "UNKNOWN",
                                 "trivial": None, "ace_count": None,
                                 "potential_nonowner_read_allow_count": None}
    try:
        base = load_base()
        mount = base.check_mount()
        source, filename = base.local_expected_filename(base.LOCAL_SOURCE)
        if args.probe and mount == "EXPECTED_NFS_EXPORT_MOUNTED" and filename:
            result = query_acl(SSH_TARGET, filename)
    except (OSError, ValueError, ImportError, AttributeError, TypeError):
        pass
    print(json.dumps({
        "mode": "TRUENAS_AGE_ESCROW_NATIVE_ACL_METADATA_ONLY",
        "status": "NO-GO", "mount_state": mount, "source_state": source,
        **result, "nfs4_acl_verified": False,
        "paths_disclosed": False, "acl_entries_disclosed": False,
        "archive_opened": False, "decryption_attempted": False,
        "remote_write_performed": False, "restore_verified": False,
        "hardware_mutation_authorized": False,
    }, sort_keys=True))
    if args.check:
        return 0 if mount == "EXPECTED_NFS_EXPORT_MOUNTED" and filename else 3
    return 0 if result["state"] in ("ACL_NATIVE_REVIEW_REQUIRED",
                                     "ACL_POTENTIAL_NONOWNER_DATA_ALLOW",
                                     "ACL_TYPE_NOT_NFS4") else 3


if __name__ == "__main__":
    sys.exit(main())
