#!/usr/bin/env python3
"""Read-only NFS client footprint. Snapshot is not an export-specific allowlist.

Reports only counts of TCP/2049 established peers on the TrueNAS server.
Does not log addresses, names, credentials, archive metadata or SSH stderr.
Idle/intermittent clients, NFSv3 and other protocols may not be represented.
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
ACK = "INSPECT_NFS_TCP_CLIENT_FOOTPRINT_READONLY"

REMOTE = '''import ipaddress, json, subprocess
out = {"state": "SS_UNAVAILABLE", "tcp_sessions": None,
       "unique_tcp_peers": None, "nfs_export_attribution": "NOT_POSSIBLE"}
try:
    cmd = ["ss", "-H", "-t", "-n", "state", "established",
           "(", "sport", "=", ":2049", ")"]
    proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, timeout=8, check=False)
    if proc.returncode == 0 and len(proc.stdout) <= 65536:
        lines = proc.stdout.splitlines()
        if len(lines) > 1024:
            out["state"] = "TOO_MANY_TCP_SESSIONS"
        else:
            peers = set()
            valid = True
            for line in lines:
                fields = line.split()
                # With `ss -H -tn state established`, Linux normally omits
                # the state column: Recv-Q Send-Q Local Peer (four columns).
                # Some iproute2 releases print ESTAB as a fifth column.
                if len(fields) == 4:
                    queues, endpoints = fields[:2], fields[2:]
                elif len(fields) == 5 and fields[0] in ("ESTAB", "ESTABLISHED"):
                    queues, endpoints = fields[1:3], fields[3:]
                else:
                    valid = False
                    break
                if not all(value.isdecimal() for value in queues):
                    valid = False
                    break
                local, remote = endpoints
                try:
                    local_ip, local_port = local.rsplit(":", 1)
                    peer_ip, peer_port = remote.rsplit(":", 1)
                    ipaddress.ip_address(local_ip.strip("[]"))
                    peer_address = ipaddress.ip_address(peer_ip.strip("[]"))
                    if (local_port != "2049" or
                        not peer_port.isdecimal() or
                        not 1 <= int(peer_port) <= 65535):
                        valid = False
                        break
                    # IPv4 peers rendered as IPv4-mapped IPv6 must count as
                    # the same client. Raw addresses never leave TrueNAS.
                    if isinstance(peer_address, ipaddress.IPv6Address):
                        peer_address = peer_address.ipv4_mapped or peer_address
                    peers.add(peer_address)
                except (ValueError, IndexError):
                    valid = False
                    break
            if valid:
                out["state"] = "TCP_SNAPSHOT_OBSERVED"
                out["tcp_sessions"] = len(lines)
                out["unique_tcp_peers"] = len(peers)
            else:
                out["state"] = "SS_RESPONSE_UNVERIFIED"
    elif proc.returncode == 0:
        out["state"] = "SS_RESPONSE_UNVERIFIED"
except (OSError, ValueError, subprocess.TimeoutExpired):
    out["state"] = "SS_UNAVAILABLE"
print(json.dumps(out, sort_keys=True))
'''


def preflight() -> tuple[str, bool]:
    """Read-only local mount/backup metadata without opening ciphertext."""
    try:
        spec = importlib.util.spec_from_file_location(
            "nabla_age_nfs_consumer_preflight",
            HERE / "verify-usb-age-identity-independent-backup.py")
        if spec is None or spec.loader is None:
            return "BACKUP_METADATA_UNAVAILABLE", False
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        state, pair = module.encrypted_pair()
        return state, pair is not None
    except (ImportError, OSError, ValueError, TypeError, AttributeError):
        return "BACKUP_METADATA_UNAVAILABLE", False


def query_server() -> dict | None:
    command = ["ssh", "-T", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "NumberOfPasswordPrompts=0",
               "-o", "ConnectTimeout=5", "-o", "ClearAllForwardings=yes",
               "--", SSH_TARGET, "python3", "-"]
    try:
        proc = subprocess.run(command, input=REMOTE, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=16, check=False)
        if proc.returncode or len(proc.stdout) > 1024:
            return None
        report = json.loads(proc.stdout)
        if not isinstance(report, dict) or set(report) != {
                "state", "tcp_sessions", "unique_tcp_peers",
                "nfs_export_attribution"}:
            return None
        if report["nfs_export_attribution"] != "NOT_POSSIBLE":
            return None
        if report["state"] not in (
                "SS_UNAVAILABLE", "TOO_MANY_TCP_SESSIONS",
                "SS_RESPONSE_UNVERIFIED", "TCP_SNAPSHOT_OBSERVED"):
            return None
        if report["state"] == "TCP_SNAPSHOT_OBSERVED":
            count, unique = report["tcp_sessions"], report["unique_tcp_peers"]
            if (type(count) is not int or type(unique) is not int or
                    not 0 <= unique <= count <= 1024):
                return None
        elif (report["tcp_sessions"] is not None or
              report["unique_tcp_peers"] is not None):
            return None
        return report
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--probe", action="store_true")
    p.add_argument("--acknowledge")
    args = p.parse_args(argv)
    if args.check and args.acknowledge:
        p.error("--check does not accept SSH authorization")
    if args.probe and args.acknowledge != ACK:
        p.error("--probe requires explicit read-only authorization")

    backup_state, ready = preflight()
    record = query_server() if args.probe and ready else None
    observed = record is not None and record["state"] == "TCP_SNAPSHOT_OBSERVED"
    print(json.dumps({
        "mode": "TRUENAS_NFS_TCP2049_CLIENT_FOOTPRINT",
        "backup_state": backup_state,
        "probe_state": ("NOT_PROBED" if args.check else
                        record["state"] if record else "SSH_OR_PREFLIGHT_UNAVAILABLE"),
        "tcp_sessions": record["tcp_sessions"] if observed else None,
        "unique_tcp_peers": record["unique_tcp_peers"] if observed else None,
        "scope": "ALL_NFS_EXPORTS_TCP2049_ONLY",
        "consumer_allowlist_verified": False,
        "export_specific_clients_verified": False,
        "all_clients_enumerated": False,
        "client_addresses_disclosed": False,
        "archive_opened": False,
        "remote_write_performed": False,
        "status": "SNAPSHOT_ONLY_REVIEW_REQUIRED",
    }, sort_keys=True))
    if args.check:
        return 0 if ready else 3
    return 0 if observed else 3


if __name__ == "__main__":
    sys.exit(main())
