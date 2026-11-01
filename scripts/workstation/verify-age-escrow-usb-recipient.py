#!/usr/bin/env python3
"""Opt-in public recipient attestation from the existing LUKS2 USB age identity.

--check checks existing metadata only (never opens the secret).
--verify explicitly opens the native age identity read-only, sends its open
file descriptor through stdin to age-keygen -y, and checks the resulting public
recipient against the *historical documented* recipient. The public recipient,
USB path and private identity are never printed. No age decrypt, SOPS write,
key generation, mount, or hardware mutation. A match does not prove ability to
decrypt the current NFS ciphertext.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ACK = "DERIVE_EXISTING_USB_AGE_PUBLIC_RECIPIENT_ONLY"
# Public recipient from the existing, tested manage-age-escrow-usb.sh runbook.
EXPECTED_RECIPIENT = "age10lxlddwul3eaxs8fq7sh49hcks42tamy7cke7ny945kfwxaxqfaq46a938"


def load(filename: str):
    spec = importlib.util.spec_from_file_location(
        "nabla_usb_public_key_" + filename.replace("-", "_").replace(".", "_"),
        HERE / filename,
    )
    if spec is None or spec.loader is None:
        raise ImportError("read-only helper unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight() -> tuple[str, Path | None]:
    """Verify the original LUKS UUID, mount and key metadata without key reads."""
    try:
        helper = load("inspect-age-escrow-usb-identity.py")
        usb, mount, key = helper.inspect()
        if (usb != "USB_LUKS_MOUNT_MATCHED"
                or mount != "USB_EXPECTED_EXT4_MOUNT_PRESENT"
                or key != "USB_IDENTITY_METADATA_PRESENT"):
            return "USB_IDENTITY_METADATA_UNVERIFIED", None
        return "USB_IDENTITY_READY_FOR_RECIPIENT_CHECK", (
            helper.expected_mount() / "age-escrow" / "recovery-identity.txt"
        )
    except (ImportError, OSError, ValueError, TypeError, AttributeError):
        return "USB_IDENTITY_METADATA_UNVERIFIED", None


def verify_public_recipient(path: Path) -> str:
    """No secret bytes in argv, Python data, logs, JSON or public output."""
    descriptor = None
    try:
        comparison = load("compare-yubikey-escrow-pair-readonly.py")
        descriptor, before = comparison.secure_open(path)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= 65536):
            return "USB_IDENTITY_METADATA_UNVERIFIED"
        process = subprocess.run(
            ["age-keygen", "-y"],
            stdin=descriptor, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
        if not comparison.unchanged(descriptor, before):
            return "USB_IDENTITY_CHANGED_DURING_READ"
        if process.returncode or len(process.stdout) > 2048:
            return "USB_RECIPIENT_DERIVATION_UNAVAILABLE"
        lines = process.stdout.decode("ascii").splitlines()
        if len(lines) != 1 or not lines[0].startswith("age1"):
            return "USB_RECIPIENT_DERIVATION_UNAVAILABLE"
        if lines[0] == EXPECTED_RECIPIENT:
            return "USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL"
        return "USB_PUBLIC_RECIPIENT_MISMATCH"
    except (OSError, ValueError, TypeError, ImportError, AttributeError,
            UnicodeError, subprocess.TimeoutExpired):
        return "USB_RECIPIENT_DERIVATION_UNAVAILABLE"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("metadata-only mode does not accept acknowledgment")
    if args.verify and args.acknowledge != ACK:
        parser.error("explicit approval to read the existing USB identity required")

    state, path = preflight()
    read = False
    if args.verify and path is not None:
        read = True
        state = verify_public_recipient(path)
    elif args.verify:
        state = "USB_IDENTITY_PREFLIGHT_FAILED"
    print(json.dumps({
        "mode": "USB_AGE_ESCROW_PUBLIC_RECIPIENT_ATTESTATION",
        "status": "NO-GO",
        "state": state,
        "private_identity_read_attempted": read,
        "public_recipient_compared_to_historical": read and
            state in ("USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL",
                      "USB_PUBLIC_RECIPIENT_MISMATCH"),
        "public_recipient_matches_historical":
            (state == "USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL" if read else None),
        "private_identity_disclosed": False,
        "public_recipient_disclosed": False,
        "paths_disclosed": False,
        "decryption_attempted": False,
        "restore_verified": False,
        "sops_configuration_changed": False,
        "usb_mount_or_unlock_performed": False,
        "hardware_mutation_authorized": False,
    }, sort_keys=True))
    if args.check:
        return 0 if path is not None else 3
    return 0 if state == "USB_PUBLIC_RECIPIENT_MATCHES_HISTORICAL" else 3


if __name__ == "__main__":
    sys.exit(main())
