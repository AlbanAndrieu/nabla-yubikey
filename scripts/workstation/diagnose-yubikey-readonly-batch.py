#!/usr/bin/env python3
"""Aggregate existing fail-closed YubiKey read-only diagnostics.

No PIN, OTP challenge, applet enrollment, file decryption, hardware write,
GPG agent start, credential listing or secrets. Output includes no paths.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parent
SECONDARY = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
PRIMARY = os.environ.get("YUBIKEY_PRIMARY_SERIAL", "11110001")


def load(script: str):
    name = "nabla_batch_" + script.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, ROOT / script)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing diagnostic module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def evaluate(args: argparse.Namespace) -> tuple[dict, int]:
    report = {
        "status": "NO-GO", "mode": "READ_ONLY",
        "hardware_mutation_authorized": False,
        "pin_requested": False, "otp_challenge_executed": False,
        "decrypt_executed": False,
        "workstation": {"state": "UNKNOWN"},
        "device": {"state": "NOT_CHECKED"},
        "otp2": "NOT_CHECKED",
        "escrow": "NOT_CHECKED",
        "gpg_agent": "NOT_CHECKED",
        "completion": {
            "gpg_agent_functional": "NOT_VERIFIED",
            "openpgp_sign_decrypt": "NOT_VERIFIED",
            "postgres_recovery": "NOT_VERIFIED",
            "ssh_fido_login": "NOT_VERIFIED",
            "keepassxc_challenge": "NOT_VERIFIED",
            "age_sops_restore": "NOT_VERIFIED",
            "piv82_provisioning": "NOT_AUTHORIZED",
            "pam_fallback": "NOT_VERIFIED",
        },
        "blockers": [],
    }
    failures = False
    try:
        host = load("inspect-yubikey-workstation-readonly.py")
        home = Path(os.environ.get("HOME", ""))
        if not os.environ.get("HOME") or not home.is_dir():
            report["workstation"] = {"state": "UNKNOWN", "reason": "HOME_UNAVAILABLE"}
            report["blockers"].append("HOST_METADATA_UNAVAILABLE")
            failures = True
        else:
            observed = host.snapshot(home, os.getuid())
            report["workstation"] = observed
            paths = observed["paths"]
            tools = observed["tools"]
            if paths["gpg_agent_socket"] != "PRESENT_UNVERIFIED":
                report["blockers"].append("GPG_SOCKET_NOT_CONFIRMED")
            if paths["sops_age_identity"] != "PRESENT_PRIVATE_METADATA_ONLY":
                report["blockers"].append("SOPS_IDENTITY_METADATA_NOT_CONFIRMED")
            if tools.get("pamu2fcfg") == "MISSING":
                report["blockers"].append("PAM_U2F_ENROLLMENT_TOOL_MISSING")
            if paths["ssh_fido_public_handle"] == "NOT_FOUND":
                report["blockers"].append("CONVENTIONAL_SSH_FIDO_PUBLIC_HANDLE_NOT_FOUND")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        report["workstation"] = {"state": "UNKNOWN", "reason": "HOST_INSPECTION_ERROR"}
        report["blockers"].append("HOST_INSPECTION_ERROR")
        failures = True

    if args.gpg_agent_probe:
        try:
            probe_module = load("inspect-gpg-agent-readonly.py")
            status = probe_module.probe()
            report["gpg_agent"] = status
            if status != "RESPONDS_GETINFO_ONLY":
                report["blockers"].append("GPG_AGENT_GETINFO_UNAVAILABLE")
                failures = True
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            report["gpg_agent"] = "UNKNOWN"
            report["blockers"].append("GPG_AGENT_PROBE_ERROR")
            failures = True

    if args.hardware:
        try:
            module = load("inspect-yubikey-applications-readonly.py")
            details, code = module.snapshot(args.serial)
            report["device"] = details
            if details.get("serial") != args.serial:
                code = 3
            if code != 0:
                report["blockers"].append("PUBLIC_APPLET_INVENTORY_INCOMPLETE")
                failures = True
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            report["device"] = {"state": "UNKNOWN", "reason": "DEVICE_INSPECTION_ERROR"}
            report["blockers"].append("DEVICE_INSPECTION_ERROR")
            failures = True

    if args.otp2_secondary:
        try:
            module = load("inspect-yubikey-recovery-readonly.py")
            result = module.otp2_inventory()
            report["otp2"] = result
            if result != "PROGRAMMED_TYPE_UNVERIFIED":
                report["blockers"].append("OTP2_PRESENCE_NOT_CONFIRMED")
                failures = True
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            report["otp2"] = "UNKNOWN"
            report["blockers"].append("OTP2_INSPECTION_ERROR")
            failures = True

    if args.escrow_a is not None:
        try:
            module = load("inspect-yubikey-recovery-readonly.py")
            result = module.escrow_inventory(args.escrow_a, args.escrow_b)
            report["escrow"] = result
            if result != "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED":
                report["blockers"].append("ESCROW_METADATA_INCOMPLETE")
                failures = True
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            report["escrow"] = "UNKNOWN"
            report["blockers"].append("ESCROW_INSPECTION_ERROR")
            failures = True
    # These are missing functional proofs regardless of a successful inventory.
    report["blockers"].extend([
        "GPG_OPENPGP_INTEROP_NOT_VERIFIED",
        "POSTGRES_RESTORE_NOT_VERIFIED",
        "ESCROW_RESTORE_NOT_VERIFIED",
        "HARDWARE_AGE_ROUNDTRIP_NOT_VERIFIED",
        "PAM_FALLBACK_NOT_VERIFIED",
    ])
    return report, 3 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpg-agent-probe", action="store_true",
                        help="GETINFO version only, existing agent, --no-autostart")
    parser.add_argument("--hardware", action="store_true",
                        help="Read public applet and PIV metadata of one selected device")
    parser.add_argument("--serial", choices=[SECONDARY, PRIMARY],
                        help="Required explicitly for --hardware")
    parser.add_argument("--otp2-secondary", action="store_true",
                        help="Explicit additional OTP2 status reading, secondary only")
    parser.add_argument("--escrow-a", type=Path,
                        help="Absolute existing encrypted backup path (metadata only)")
    parser.add_argument("--escrow-b", type=Path,
                        help="Second backup path (metadata only)")
    args = parser.parse_args(argv)
    if args.hardware != (args.serial is not None):
        parser.error("--hardware and --serial must be supplied together")
    if args.otp2_secondary and (not args.hardware or args.serial != SECONDARY):
        parser.error(f"--otp2-secondary requires --hardware --serial {SECONDARY}")
    if (args.escrow_a is None) != (args.escrow_b is None):
        parser.error("both --escrow-a and --escrow-b are required")
    if args.escrow_a is not None and (
        not args.escrow_a.is_absolute() or not args.escrow_b.is_absolute()
    ):
        parser.error("escrow file paths must be absolute")
    report, code = evaluate(args)
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
