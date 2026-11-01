#!/usr/bin/env python3
"""Compare two existing encrypted age backups without exposing their contents.

This intentionally differs from metadata-only escrow inspection: --compare
READS the two encrypted files. Never decrypts, copies, repairs or writes them.
"""
from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

DISCOVERY = Path(__file__).with_name("inspect-yubikey-escrow-pair-interactive.py")
ACK = "COMPARE_EXISTING_ENCRYPTED_ESCROWS"
MAX_BYTES = 16 * 1024 * 1024
CHUNK = 64 * 1024


def load_locator():
    spec = importlib.util.spec_from_file_location("nabla_escrow_pair_locator", DISCOVERY)
    if spec is None or spec.loader is None:
        raise ImportError("metadata locator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover() -> tuple[str, tuple[Path, Path] | None]:
    """Use the existing unique pair selector. Return no paths in output."""
    try:
        return load_locator().discover_pair(Path.home())
    except (OSError, ValueError, ImportError, AttributeError, TypeError):
        return "DISCOVERY_UNAVAILABLE", None


def select_manual_pair(*, tty: bool, reader=None) -> tuple[str, tuple[Path, Path] | None]:
    """Read private paths from TTY (not argv) and enforce the same metadata gate."""
    if not tty:
        return "INTERACTIVE_TERMINAL_REQUIRED", None
    if reader is None:
        reader = getpass.getpass
    try:
        first = reader("Escrow age A (chemin absolu, saisie masquée) : ")
        second = reader("Escrow age B (chemin absolu, saisie masquée) : ")
        locator = load_locator()
        state = locator.classify_inputs(first, second)
        if state != "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED":
            return state, None
        return state, (Path(first), Path(second))
    except (EOFError, KeyboardInterrupt, OSError, UnicodeError,
            ValueError, ImportError, AttributeError, TypeError):
        return "MANUAL_ESCROW_INPUT_UNAVAILABLE", None


def secure_open(path: Path) -> tuple[int, os.stat_result]:
    """Open a verified regular file, never a symlink and never a FIFO."""
    # Do not follow symlinked directory components for manually provided
    # escrow paths either. O_NOFOLLOW only protects the final file name.
    if any(directory.is_symlink() for directory in (path.parent, *path.parent.parents)):
        raise ValueError("untrusted escrow parent")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size < 1 or before.st_size > MAX_BYTES):
        raise ValueError("invalid metadata")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        actual = os.fstat(fd)
        if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
                or actual.st_uid != os.getuid()
                or stat.S_IMODE(actual.st_mode) & 0o077
                or (actual.st_dev, actual.st_ino, actual.st_size,
                    actual.st_mtime_ns, actual.st_ctime_ns) !=
                   (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)):
            raise ValueError("changed metadata")
        return fd, actual
    except BaseException:
        os.close(fd)
        raise


def unchanged(fd: int, original: os.stat_result) -> bool:
    current = os.fstat(fd)
    return (current.st_dev, current.st_ino, current.st_size,
            current.st_mtime_ns, current.st_ctime_ns) == (
            original.st_dev, original.st_ino, original.st_size,
            original.st_mtime_ns, original.st_ctime_ns)


def compare_ciphertexts(a: Path, b: Path) -> str:
    """Bounded byte-for-byte comparison. Never return plaintext, hashes, paths."""
    descriptors: list[int] = []
    try:
        first, first_meta = secure_open(a)
        descriptors.append(first)
        second, second_meta = secure_open(b)
        descriptors.append(second)
        if first_meta.st_dev == second_meta.st_dev:
            return "COPIES_NOT_ON_DISTINCT_FILESYSTEMS"
        if first_meta.st_size != second_meta.st_size:
            return "ENCRYPTED_COPIES_DIFFER"
        different = False
        remaining = first_meta.st_size
        while remaining:
            length = min(CHUNK, remaining)
            left = os.read(first, length)
            right = os.read(second, length)
            if len(left) != length or len(right) != length:
                return "ENCRYPTED_COPY_READ_INCOMPLETE"
            different |= left != right
            remaining -= length
        if not unchanged(first, first_meta) or not unchanged(second, second_meta):
            return "ENCRYPTED_COPY_CHANGED_DURING_READ"
        return ("ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED" if not different
                else "ENCRYPTED_COPIES_DIFFER")
    except (OSError, ValueError):
        return "ENCRYPTED_COPY_UNVERIFIED"
    finally:
        for fd in descriptors:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--check", action="store_true")
    options.add_argument("--compare", action="store_true")
    options.add_argument("--compare-manual", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--acknowledge only valid with a compare mode")
    if (args.compare or args.compare_manual) and args.acknowledge != ACK:
        parser.error("explicit acknowledgment of encrypted file reads required")
    pair_selected = False
    if args.check:
        state = "ENCRYPTED_CONTENT_NOT_READ"
    else:
        if args.compare_manual:
            state, paths = select_manual_pair(tty=os.isatty(0) and os.isatty(2))
        else:
            state, paths = discover()
        pair_selected = paths is not None
        if pair_selected:
            state = compare_ciphertexts(*paths)
    print(json.dumps({
        "status": "NO-GO", "state": state,
        "mode": "ENCRYPTED_ESCROW_CONTENT_COMPARISON_ONLY",
        "encrypted_content_read_attempted": pair_selected,
        "encrypted_copies_identical": state == "ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED",
        "paths_disclosed": False, "digest_disclosed": False,
        "decryption_attempted": False, "restoration_verified": False,
        "independent_media_verified": False, "hardware_mutation_authorized": False,
    }, sort_keys=True))
    return 0 if state in ("ENCRYPTED_CONTENT_NOT_READ", "ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED") else 3


if __name__ == "__main__":
    sys.exit(main())
