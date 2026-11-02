#!/usr/bin/env python3
"""Offline public F9 readiness; never touches a YubiKey, PIN, or SOPS."""
from __future__ import annotations

import os
import argparse
import importlib.util
import json
from pathlib import Path
import sys

SERIAL = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
FIRMWARE = "5.4.3"
F9_SHA256 = (
    "6C:6E:14:0A:69:81:14:C3:51:14:0C:1B:68:C4:B1:16:"
    "A7:D9:B4:49:29:76:62:39:2F:61:F1:78:54:90:34:DF"
)


def verifier_module():
    script = Path(__file__).with_name("verify-age-yubikey-f9-root-offline.py")
    spec = importlib.util.spec_from_file_location("nabla_f9_verifier", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("F9 verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readiness(f9: Path, root: Path) -> dict:
    result = {
        "status": "NO-GO",
        "serial": SERIAL,
        "firmware": FIRMWARE,
        "f9_trust": "FAIL",
        "piv82": "NOT_VERIFIED",
        "age_decrypt": "NOT_VERIFIED",
        "hardware_mutation_authorized": False,
    }
    try:
        verifier = verifier_module()
        verifier.validate(
            verifier._read_public(f9),
            verifier._read_public(root),
            observed_f9_sha256=F9_SHA256,
            trusted_root_sha256=verifier.LEGACY_ROOT_SHA256,
            firmware=FIRMWARE,
        )
    except Exception as error:
        result["reason"] = f"public F9 evidence rejected: {type(error).__name__}"
    else:
        result["f9_trust"] = "PASS"
        result["reason"] = "Trusted public F9 does not prove PIV82 policies or real age decrypt"
        result["next_stage"] = "fresh read-only PIV82 inventory; separate approvals for each subsequent phase"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--f9", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = readiness(args.f9, args.root)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("F9: " + result["f9_trust"] + " / PIV82: NOT_VERIFIED / age: NOT_VERIFIED")
        print("NO-GO: " + result["reason"])
    return 0 if result["f9_trust"] == "PASS" else 3


if __name__ == "__main__":
    sys.exit(main())
