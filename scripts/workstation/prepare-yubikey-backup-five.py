#!/usr/bin/env python3
"""Concurrent preparation of five YubiKey backup acceptance tracks.

No PIV write, FIDO enrollment, PIN, OTP challenge, private-key access,
GPG sign/decrypt or SOPS mutation. Hardware metadata runs serially and only
on explicit opt-in. A green diagnostic is never a hardware GO.
"""
from __future__ import annotations

import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BACKUP = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
HOST_COMMANDS = {
    "dependencies": (sys.executable, "scripts/workstation/inspect-yubikey-dependencies-readonly.py"),
    "workstation": (sys.executable, "scripts/workstation/inspect-yubikey-workstation-readonly.py"),
    "gpg_agent": (sys.executable, "scripts/workstation/inspect-gpg-agent-readonly.py"),
}
PIV82_PLAN = (sys.executable, "scripts/workstation/plan-age-yubikey-piv82-transaction.py",
              "--serial", BACKUP, "--json")
HARDWARE_COMMAND = (sys.executable, "scripts/workstation/inspect-age-yubikey-piv82-secondary.py",
                    "--serial", BACKUP, "--json")
MAX_OUTPUT = 65536


def capture(command: tuple[str, ...], name: str) -> dict:
    """Only expose states needed for this report, never raw subprocess data."""
    try:
        done = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=25, check=False)
        if (done.returncode != 0 or done.stderr.strip() or
                len(done.stdout) > MAX_OUTPUT or "\x00" in done.stdout):
            return {"state": "UNVERIFIED"}
        result = json.loads(done.stdout)
        if not isinstance(result, dict) or result.get("status") != "NO-GO" or (
                result.get("hardware_mutation_authorized") is not False and name != "plan"):
            return {"state": "UNVERIFIED"}
        return {"state": "METADATA_ONLY", "data": result}
    except (ValueError, TypeError, UnicodeError, OSError, subprocess.TimeoutExpired):
        return {"state": "UNVERIFIED"}


def inspect_escrow(a: Path | None, b: Path | None) -> str:
    """Delegate existing strict pair metadata logic, never read either file."""
    if a is None and b is None:
        return "NOT_CHECKED"
    if a is None or b is None or not a.is_absolute() or not b.is_absolute():
        return "INVALID_INPUT"
    call = (sys.executable, "scripts/workstation/inspect-yubikey-recovery-readonly.py",
            "--escrow-a", str(a), "--escrow-b", str(b))
    result = capture(call, "escrow")
    if result.get("state") == "METADATA_ONLY":
        return result["data"].get("escrow", "UNKNOWN")
    return "UNVERIFIED"


def collect(hardware: bool, escrow_a: Path | None = None,
            escrow_b: Path | None = None) -> tuple[dict, int]:
    tasks = {**HOST_COMMANDS, "plan": PIV82_PLAN}
    observed = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        future_map = {pool.submit(capture, cmd, name): name for name, cmd in tasks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                observed[name] = future.result()
            except Exception:
                observed[name] = {"state": "UNVERIFIED"}
    complete = all(observed.get(x, {}).get("state") == "METADATA_ONLY" for x in tasks)
    dep = observed.get("dependencies", {}).get("data", {})
    home = observed.get("workstation", {}).get("data", {})
    agent = observed.get("gpg_agent", {}).get("data", {})
    slots = {"state": "NOT_CHECKED"}
    if hardware and complete:
        # Intentional single hardware command after all host tasks finish.
        slots = capture(HARDWARE_COMMAND, "hardware")
    escrow = inspect_escrow(escrow_a, escrow_b)
    result = {
        "status": "NO-GO", "mode": "FIVE_WORKSTREAMS_PREPARATION_ONLY",
        "serial": BACKUP, "hardware_mutation_authorized": False,
        "host_gates": {x: observed.get(x, {}).get("state", "UNVERIFIED") for x in tasks},
        "tracks": {
            "1_piv82_age": {
                "status": "NOT_PROVISIONED", "public_slot_inventory": slots.get("state"),
                "authorization": "PER_PHASE_WITH_RECOVERY_EVIDENCE",
            },
            "2_openpgp_gpg": {
                "status": "NOT_VERIFIED",
                "agent_getinfo": agent.get("gpg_agent_protocol", "UNKNOWN"),
                "scdaemon_agent": dep.get("agent_scdaemon", "UNKNOWN"),
                "pcscd": dep.get("pcscd", "UNKNOWN"),
            },
            "3_fido2_ssh": {
                "status": "NOT_ENROLLED_BY_THIS_TOOL",
                "ssh_agent": dep.get("ssh_agent", "UNKNOWN"),
                "public_handle": home.get("paths", {}).get("ssh_fido_public_handle", "UNKNOWN"),
            },
            "4_keepassxc_otp2": {
                "status": "CHALLENGE_NOT_TESTED",
                "keepassxc": home.get("tools", {}).get("keepassxc", "UNKNOWN"),
                "otp2": "NOT_CHECKED",
            },
            "5_sops_escrow": {
                "status": "DECRYPT_RESTORE_NOT_TESTED", "copies_metadata": escrow,
                "age": home.get("tools", {}).get("age", "UNKNOWN"),
                "sops": home.get("tools", {}).get("sops", "UNKNOWN"),
            },
        },
        "completion": "NOT_VERIFIED",
    }
    passed = complete and (not hardware or slots.get("state") == "METADATA_ONLY")
    if escrow_a is not None and escrow != "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED":
        passed = False
    return result, 0 if passed else 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secondary-public-inventory", action="store_true")
    parser.add_argument("--escrow-a", type=Path)
    parser.add_argument("--escrow-b", type=Path)
    args = parser.parse_args(argv)
    if (args.escrow_a is None) != (args.escrow_b is None):
        parser.error("both escrow paths are required")
    if args.escrow_a is not None and (
            not args.escrow_a.is_absolute() or not args.escrow_b.is_absolute()):
        parser.error("escrow paths must be absolute")
    report, code = collect(args.secondary_public_inventory, args.escrow_a, args.escrow_b)
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
