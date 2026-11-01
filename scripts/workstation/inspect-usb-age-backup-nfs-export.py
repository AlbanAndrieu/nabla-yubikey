#!/usr/bin/env python3
"""Read-only TrueNAS NFS export configuration audit for USB age identity backup.

Uses the already-trusted SSH connection and TrueNAS sharing.nfs.query. Does not
read archives, identities, ACL entries, passphrases, raw UID/GID, client IPs,
network lists, comments, hostnames or mapping account names into local output.
Inventory success is distinct from effective authorization verification.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SSH_TARGET = "albandrieu@172.17.0.24"
ACK = "INSPECT_USB_AGE_NFS_EXPORT_MAPPING_READONLY"
ALLOWED_STATES = ("EXPORT_MATCHED", "EXPORT_MISSING", "EXPORT_AMBIGUOUS",
                  "EXPORT_SCHEMA_UNVERIFIED", "EXPORT_QUERY_UNAVAILABLE",
                  "SENSITIVE_FILE_UNVERIFIED")
MAPPING = ("UNSET", "SENSITIVE_OWNER", "DIFFERENT_OWNER",
           "ACCOUNT_NOT_RESOLVED", "SCHEMA_UNVERIFIED")
CLIENT = ("ALL_CLIENTS_ALLOWED_BY_FILTERS", "FILTER_PRESENT", "SCHEMA_UNVERIFIED")
FLAVORS = ("DEFAULT_UNVERIFIED", "SYS_ONLY", "KERBEROS_ONLY",
           "MIXED_SYS_KERBEROS", "SCHEMA_UNVERIFIED")
MAX_JSON = 262144

# Fixed remote code: no user-supplied path, share ID, hostname or shell command.
# The complete sharing.nfs.query result is parsed ONLY on TrueNAS, never sent
# to the workstation. All identifiers stay on TrueNAS.
REMOTE = '''import json, pwd, stat, subprocess
from pathlib import Path
export = Path("/mnt/cpool/backup/lab")
secret = export / "secret"
copies = secret / "usb-recovery-backups"
file = copies / EXPECTED_NAME
out = {"state": "EXPORT_QUERY_UNAVAILABLE", "enabled": None, "read_only": None,
       "locked": None, "client_filter": "SCHEMA_UNVERIFIED",
       "hosts_restricted": None, "networks_restricted": None,
       "root_mapping": "SCHEMA_UNVERIFIED", "all_mapping": "SCHEMA_UNVERIFIED",
       "root_group_mapped": None, "all_group_mapped": None,
       "security": "SCHEMA_UNVERIFIED"}
try:
    metadata = file.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
        any(part.is_symlink() for part in (file, *file.parents))):
        out["state"] = "SENSITIVE_FILE_UNVERIFIED"
    else:
        proc = subprocess.run(["midclt", "call", "sharing.nfs.query"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=15, check=False)
        if proc.returncode == 0 and len(proc.stdout) <= 262144:
            response = json.loads(proc.stdout)
            if not isinstance(response, list) or len(response) > 256:
                out["state"] = "EXPORT_SCHEMA_UNVERIFIED"
            else:
                matches = [share for share in response if isinstance(share, dict)
                           and share.get("path") == str(export)]
                if len(matches) != 1:
                    out["state"] = ("EXPORT_MISSING" if not matches else "EXPORT_AMBIGUOUS")
                else:
                    share = matches[0]
                    fields = ("enabled", "ro", "hosts", "networks", "security",
                              "maproot_user", "maproot_group",
                              "mapall_user", "mapall_group")
                    valid = (all(k in share for k in fields) and
                        type(share["enabled"]) is bool and type(share["ro"]) is bool and
                        all(isinstance(share[k], list) and len(share[k]) <= 128 and
                            all(isinstance(x, str) and 0 < len(x) <= 256
                                for x in share[k])
                            for k in ("hosts", "networks")) and
                        isinstance(share["security"], list) and
                        len(share["security"]) <= 4 and
                        all(v in ("SYS", "KRB5", "KRB5I", "KRB5P")
                            for v in share["security"]) and
                        len(set(share["security"])) == len(share["security"]) and
                        all(share[k] is None or (isinstance(share[k], str)
                            and 0 < len(share[k]) <= 128)
                            for k in ("maproot_user", "maproot_group",
                                      "mapall_user", "mapall_group")) and
                        (share.get("locked") is None or
                            type(share.get("locked")) is bool))
                    if not valid:
                        out["state"] = "EXPORT_SCHEMA_UNVERIFIED"
                    else:
                        out["state"] = "EXPORT_MATCHED"
                        out["enabled"] = share["enabled"]
                        out["read_only"] = share["ro"]
                        out["locked"] = share.get("locked")
                        out["hosts_restricted"] = bool(share["hosts"])
                        out["networks_restricted"] = bool(share["networks"])
                        out["client_filter"] = ("FILTER_PRESENT" if
                            share["hosts"] or share["networks"]
                            else "ALL_CLIENTS_ALLOWED_BY_FILTERS")
                        values = set(share["security"])
                        out["security"] = ("DEFAULT_UNVERIFIED" if not values else
                            "SYS_ONLY" if values == {"SYS"} else
                            "KERBEROS_ONLY" if "SYS" not in values else
                            "MIXED_SYS_KERBEROS")
                        owner = metadata.st_uid
                        for source, target in (("maproot_user", "root_mapping"),
                                               ("mapall_user", "all_mapping")):
                            user = share[source]
                            if user is None:
                                out[target] = "UNSET"
                            else:
                                try:
                                    out[target] = ("SENSITIVE_OWNER" if
                                        pwd.getpwnam(user).pw_uid == owner
                                        else "DIFFERENT_OWNER")
                                except KeyError:
                                    out[target] = "ACCOUNT_NOT_RESOLVED"
                        out["root_group_mapped"] = share["maproot_group"] is not None
                        out["all_group_mapped"] = share["mapall_group"] is not None
        elif proc.returncode == 0:
            out["state"] = "EXPORT_SCHEMA_UNVERIFIED"
except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
    out["state"] = "EXPORT_QUERY_UNAVAILABLE"
print(json.dumps(out, sort_keys=True))
'''


def preflight() -> tuple[str, str | None]:
    try:
        spec = importlib.util.spec_from_file_location(
            "nabla_age_restore_preflight",
            HERE / "verify-usb-age-identity-independent-backup.py")
        if spec is None or spec.loader is None:
            return "BACKUP_METADATA_UNAVAILABLE", None
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        state, pair = helper.encrypted_pair()
        return state, pair[1].name if pair else None
    except (ImportError, OSError, ValueError, AttributeError, TypeError):
        return "BACKUP_METADATA_UNAVAILABLE", None


def probe(name: str) -> dict | None:
    # Same strict filename contract as the pre-existing restore and ACL probes.
    import re
    if not re.fullmatch(
        r"usb-recovery-identity-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.age", name):
        return None
    program = "EXPECTED_NAME = " + json.dumps(name) + "\n" + REMOTE
    command = ["ssh", "-T", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "NumberOfPasswordPrompts=0",
               "-o", "ConnectTimeout=5", "-o", "ClearAllForwardings=yes",
               "--", SSH_TARGET, "python3", "-"]
    try:
        proc = subprocess.run(command, input=program, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=25, check=False)
        if proc.returncode or len(proc.stdout) > 4096:
            return None
        value = json.loads(proc.stdout)
        if not isinstance(value, dict) or set(value) != {
            "state", "enabled", "read_only", "locked", "client_filter",
            "hosts_restricted", "networks_restricted", "root_mapping",
            "all_mapping", "root_group_mapped", "all_group_mapped", "security"}:
            return None
        if value["state"] not in ALLOWED_STATES or value["client_filter"] not in CLIENT:
            return None
        if (value["root_mapping"] not in MAPPING or
                value["all_mapping"] not in MAPPING or value["security"] not in FLAVORS):
            return None
        boolean_fields = ("enabled", "read_only", "hosts_restricted",
                          "networks_restricted", "root_group_mapped",
                          "all_group_mapped")
        if any(type(value[k]) is not bool and value[k] is not None
               for k in (*boolean_fields, "locked")):
            return None
        if value["state"] == "EXPORT_MATCHED":
            if (any(type(value[k]) is not bool for k in boolean_fields)
                    or value["client_filter"] == "SCHEMA_UNVERIFIED"
                    or value["security"] == "SCHEMA_UNVERIFIED"
                    or value["root_mapping"] == "SCHEMA_UNVERIFIED"
                    or value["all_mapping"] == "SCHEMA_UNVERIFIED"):
                return None
        elif (any(value[k] is not None for k in (*boolean_fields, "locked"))
              or value["client_filter"] != "SCHEMA_UNVERIFIED"
              or value["security"] != "SCHEMA_UNVERIFIED"
              or value["root_mapping"] != "SCHEMA_UNVERIFIED"
              or value["all_mapping"] != "SCHEMA_UNVERIFIED"):
            return None
        return value
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--probe", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--check does not accept remote authorization")
    if args.probe and args.acknowledge != ACK:
        parser.error("--probe requires explicit authorization")
    state, name = preflight()
    record = probe(name) if args.probe and name else None
    inventory = record is not None and record["state"] == "EXPORT_MATCHED"
    concerns = []
    if inventory:
        if record["client_filter"] == "ALL_CLIENTS_ALLOWED_BY_FILTERS":
            concerns.append("NO_NFS_HOST_OR_NETWORK_FILTER")
        if record["security"] in ("SYS_ONLY", "MIXED_SYS_KERBEROS"):
            concerns.append("AUTH_SYS_ALLOWED")
        elif record["security"] == "DEFAULT_UNVERIFIED":
            concerns.append("NFS_SECURITY_FLAVOR_DEFAULT_UNVERIFIED")
        if record["root_mapping"] == "SENSITIVE_OWNER":
            concerns.append("MAPROOT_TO_SENSITIVE_OWNER")
        if record["all_mapping"] == "SENSITIVE_OWNER":
            concerns.append("MAPALL_TO_SENSITIVE_OWNER")
        if record["read_only"] is False:
            concerns.append("EXPORT_WRITABLE")
    print(json.dumps({
        "mode": "USB_AGE_BACKUP_NFS_EXPORT_CONFIG_METADATA",
        "backup_state": state,
        "probe_state": ("NOT_PROBED" if args.check else
            record["state"] if record else "EXPORT_PROBE_UNAVAILABLE"),
        "configuration_inventory_verified": inventory,
        "configuration": record,
        "review_flags": concerns,
        "status": "REVIEW_REQUIRED",
        "effective_nfs4_authorization_verified": False,
        "nfs_identity_mapping_verified": False,
        "negative_access_test_performed": False,
        "archive_opened": False,
        "remote_write_performed": False,
        "client_addresses_or_account_names_disclosed": False,
        "private_identity_or_passphrase_read": False,
    }, sort_keys=True))
    # Successful metadata inventory is distinct from policy acceptance.
    if args.check:
        return 0 if name else 3
    return 0 if inventory else 3


if __name__ == "__main__":
    sys.exit(main())
