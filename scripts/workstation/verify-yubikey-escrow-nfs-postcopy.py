#!/usr/bin/env python3
"""Verify an existing encrypted age escrow pair and its TrueNAS visibility.

--check: local stat/mount only. --verify: opt-in ciphertext readback and
read-only TrueNAS SSH metadata query. Neither mode copies, decrypts or writes.
POSIX mode verification does NOT attest NFSv4 ACL entries.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
ACK = "RECHECK_EXISTING_AGE_ESCROW_CIPHERTEXT_AND_TRUENAS"
SSH_TARGET = "albandrieu@172.17.0.24"


def load(script: str):
    spec = importlib.util.spec_from_file_location(
        "nabla_escrow_postcopy_" + script.replace("-", "_").replace(".", "_"),
        HERE / script,
    )
    if spec is None or spec.loader is None:
        raise ImportError("read-only helper unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_pair() -> tuple[str, tuple[Path, Path] | None, bool, str | None]:
    """Bounded metadata checks; never read file contents or reveal filenames."""
    try:
        nfs = load("inspect-yubikey-escrow-nfs-server.py")
        if nfs.check_mount() != "EXPECTED_NFS_EXPORT_MOUNTED":
            return "UNEXPECTED_NFS_EXPORT", None, False, None
        source_state, filename = nfs.local_expected_filename(nfs.LOCAL_SOURCE)
        if source_state != "SOURCE_UNIQUE_AGE_FOUND" or not filename:
            return "SOURCE_NOT_UNIQUELY_IDENTIFIED", None, False, None
        locator = load("inspect-yubikey-escrow-pair-interactive.py")
        state, paths = locator.discover_pair(Path.home())
        if state != "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED" or paths is None:
            return "ESCROW_PAIR_METADATA_UNVERIFIED", None, False, None
        if paths[0].name != filename or paths[1].name != filename:
            return "ESCROW_PAIR_METADATA_UNVERIFIED", None, False, None
        # POSIX-only checks. NFSv4 ACL review is explicitly separate.
        for path in paths:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size < 1 or info.st_size > 16 * 1024 * 1024):
                return "ESCROW_POSIX_METADATA_UNVERIFIED", None, False, None
        return "PAIR_METADATA_READY_ACL_UNVERIFIED", paths, True, filename
    except (OSError, ValueError, ImportError, AttributeError, TypeError):
        return "POSTCOPY_METADATA_UNAVAILABLE", None, False, None


def verify_pair(paths: tuple[Path, Path], filename: str) -> tuple[str, str]:
    """Check encrypted bytes then TrueNAS metadata; no remote filesystem writes."""
    try:
        comparator = load("compare-yubikey-escrow-pair-readonly.py")
        state = comparator.compare_ciphertexts(*paths)
        if state != "ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED":
            return state, "NOT_PROBED"
        server = load("inspect-yubikey-escrow-nfs-server.py")
        remote_state, count = server.query_server(SSH_TARGET, filename)
        if remote_state != "SERVER_EXPECTED_COPY_REGULAR_NONEMPTY" or count is None or count < 1:
            return state, remote_state
        return state, remote_state
    except (OSError, ValueError, ImportError, AttributeError, TypeError):
        return "POSTCOPY_READBACK_UNAVAILABLE", "NOT_PROBED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("passive check does not accept an acknowledgment")
    if args.verify and args.acknowledge != ACK:
        parser.error("explicit ciphertext readback and remote metadata approval required")

    state, paths, mode_ok, filename = inspect_pair()
    compared = False
    integrity = "NOT_CHECKED"
    remote = "NOT_PROBED"
    if args.verify and paths is not None and filename:
        compared = True
        integrity, remote = verify_pair(paths, filename)
        if (integrity == "ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED"
                and remote == "SERVER_EXPECTED_COPY_REGULAR_NONEMPTY" and mode_ok):
            state = "POSTCOPY_CIPHERTEXT_AND_SERVER_VISIBLE_ACL_UNVERIFIED"
        else:
            state = "POSTCOPY_RECHECK_INCOMPLETE"
    elif args.verify:
        state = "POSTCOPY_PREFLIGHT_NOT_READY"

    print(json.dumps({
        "mode": "EXISTING_AGE_ESCROW_POSTCOPY_READONLY",
        "status": "NO-GO",
        "state": state,
        "ciphertext_readback_attempted": compared,
        "ciphertext_identical": (integrity == "ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED"
                                 if compared else None),
        "server_state": remote,
        "server_visibility_verified": remote == "SERVER_EXPECTED_COPY_REGULAR_NONEMPTY",
        "posix_0600_verified": mode_ok,
        "nfs4_acl_verified": False,
        "decryption_attempted": False,
        "restore_verified": False,
        "independent_recovery_verified": False,
        "paths_disclosed": False,
        "remote_write_performed": False,
        "hardware_mutation_authorized": False,
    }, sort_keys=True))
    if args.check:
        return 0 if paths is not None and mode_ok else 3
    return 0 if state == "POSTCOPY_CIPHERTEXT_AND_SERVER_VISIBLE_ACL_UNVERIFIED" else 3


if __name__ == "__main__":
    sys.exit(main())
