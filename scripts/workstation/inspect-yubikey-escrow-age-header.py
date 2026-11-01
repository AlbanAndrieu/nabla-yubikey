#!/usr/bin/env python3
"""Classify an existing age ciphertext header without decrypting it.

--check inspects only local metadata. --inspect reads at most 8192 bytes
of a locally owned 0600 archive after an explicit acknowledgment. Recipient
arguments, header bytes, encrypted payload and private paths never appear in
output. The format hint does not authenticate the archive or prove recovery.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
ACK = "INSPECT_EXISTING_ENCRYPTED_AGE_HEADER_ONLY"
HEADER_LIMIT = 8192
MAGIC = b"age-encryption.org/v1\n"
MAC = re.compile(rb"--- [A-Za-z0-9+/]{43}\n")
STANZA = re.compile(rb"-> ([^\x00-\x20\x7f]{1,100})(?: [^\x00-\x1f\x7f]{1,1024})?\n")


def load(script: str):
    spec = importlib.util.spec_from_file_location(
        "nabla_age_header_helper_" + script.replace("-", "_"), HERE / script)
    if spec is None or spec.loader is None:
        raise ImportError("age metadata helper unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight() -> tuple[str, Path | None]:
    """No encrypted bytes read; never emits source path or private filename."""
    try:
        base = load("inspect-yubikey-escrow-nfs-server.py")
        if base.check_mount() != "EXPECTED_NFS_EXPORT_MOUNTED":
            return "NFS_EXPORT_UNVERIFIED", None
        state, basename = base.local_expected_filename(base.LOCAL_SOURCE)
        if state != "SOURCE_UNIQUE_AGE_FOUND" or basename is None:
            return "AGE_SOURCE_NOT_UNIQUE", None
        source = base.LOCAL_SOURCE / basename
        if any(d.is_symlink() for d in (source.parent, *source.parent.parents)):
            return "AGE_SOURCE_UNTRUSTED", None
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or not 0 < info.st_size <= 16 * 1024 * 1024):
            return "AGE_SOURCE_UNTRUSTED", None
        return "HEADER_INSPECTION_READY", source
    except (OSError, ValueError, TypeError, AttributeError, ImportError):
        return "AGE_SOURCE_UNVERIFIED", None


def recipient_family(types: list[bytes]) -> str:
    if len(types) == 1 and types[0] == b"scrypt":
        return "PASSPHRASE_SCRYPT"
    if types and all(t == b"X25519" for t in types):
        return "X25519_IDENTITY"
    if types and all(t in (b"ssh-rsa", b"ssh-ed25519") for t in types):
        return "SSH_IDENTITY"
    if types and all(t not in (b"scrypt", b"X25519", b"ssh-rsa", b"ssh-ed25519")
                     for t in types):
        return "PLUGIN_OR_OTHER_IDENTITY"
    return "MIXED_OR_MULTIPLE_METHODS"


def classify_header(data: bytes) -> tuple[str, str | None, int | None]:
    """Bounded hint from a v1 plaintext header, not cryptographic validation."""
    if data.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----\n"):
        return "ARMORED_AGE_UNINSPECTED", None, None
    if not data.startswith(MAGIC):
        return "AGE_V1_HEADER_NOT_CONFIRMED", None, None
    lines = data[len(MAGIC):].splitlines(keepends=True)
    types: list[bytes] = []
    for line in lines[:128]:
        if MAC.fullmatch(line):
            if not types:
                return "AGE_HEADER_UNVERIFIED", None, None
            return "AGE_V1_HEADER_TYPE_HINT_ONLY", recipient_family(types), len(types)
        if line.startswith(b"---"):
            return "AGE_HEADER_UNVERIFIED", None, None
        if line.startswith(b"->"):
            match = STANZA.fullmatch(line)
            if match is None or len(types) >= 32:
                return "AGE_HEADER_UNVERIFIED", None, None
            types.append(match.group(1))
        elif line.endswith(b"\n") and not re.fullmatch(rb"[A-Za-z0-9+/]*\n", line):
            return "AGE_HEADER_UNVERIFIED", None, None
        elif not line.endswith(b"\n"):
            break
    return "AGE_HEADER_INCOMPLETE_OR_TOO_LARGE", None, None


def inspect(path: Path) -> tuple[str, str | None, int | None]:
    fd = None
    try:
        cmp = load("compare-yubikey-escrow-pair-readonly.py")
        fd, info = cmp.secure_open(path)
        budget = min(HEADER_LIMIT, info.st_size)
        chunks = []
        while budget > 0:
            chunk = os.read(fd, budget)
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
            # age v1 header-MAC marker is checked after bounded read.
        if not cmp.unchanged(fd, info):
            return "AGE_SOURCE_CHANGED_DURING_INSPECTION", None, None
        return classify_header(b"".join(chunks))
    except (OSError, ValueError, TypeError, ImportError, AttributeError):
        return "AGE_HEADER_READ_UNAVAILABLE", None, None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--inspect", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--check does not accept acknowledgment")
    if args.inspect and args.acknowledge != ACK:
        parser.error("explicit encrypted header read authorization required")
    state, source = preflight()
    hint = None
    count = None
    read = False
    if args.inspect and source is not None:
        read = True
        state, hint, count = inspect(source)
    print(json.dumps({
        "mode": "AGE_ESCROW_HEADER_TYPE_HINT_ONLY",
        "status": "NO-GO", "state": state,
        "recipient_family_hint": hint,
        "stanza_count": count,
        "encrypted_header_read_attempted": read,
        "archive_decryption_attempted": False,
        "recipient_identifiers_disclosed": False,
        "archive_header_disclosed": False,
        "paths_disclosed": False,
        "recovery_method_verified": False,
        "real_escrow_restoration_verified": False,
        "sops_configuration_changed": False,
        "hardware_mutation_authorized": False,
    }, sort_keys=True))
    if args.check:
        return 0 if source is not None else 3
    return 0 if state in ("AGE_V1_HEADER_TYPE_HINT_ONLY", "ARMORED_AGE_UNINSPECTED") else 3


if __name__ == "__main__":
    sys.exit(main())
