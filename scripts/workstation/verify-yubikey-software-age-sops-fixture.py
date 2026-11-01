#!/usr/bin/env python3
"""Verify age and SOPS software recovery using only ephemeral synthetic keys.

Never opens or decrypts existing SOPS files, private keys, backup files,
YubiKeys or other accounts. --run explicitly requires acknowledgment.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ACK = "SYNTHETIC_SOFTWARE_ONLY"
TOOLS = ("age", "age-keygen", "sops")
FIXTURE = {"fixture": "nabla-age-sops", "nonce": "synthetic-v1"}
MAX_RECIPIENT_CHARS = 200


def tool_paths() -> dict[str, str] | None:
    found = {name: shutil.which(name) for name in TOOLS}
    if any(not value or not os.path.isabs(value) for value in found.values()):
        return None
    return {name: str(path) for name, path in found.items()}


def run_command(command: list[str], env: dict[str, str], workdir: Path,
                *, recipient_output: bool = False) -> str | None:
    """Allow only an in-memory age public recipient output, never error text."""
    try:
        done = subprocess.run(
            command, env=env, cwd=workdir, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if recipient_output else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    if recipient_output:
        if not isinstance(done.stdout, bytes) or len(done.stdout) > MAX_RECIPIENT_CHARS:
            return None
        try:
            recipient = done.stdout.decode("ascii").strip()
        except UnicodeError:
            return None
        if not re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{50,120}", recipient):
            return None
        return recipient
    return "PASS"


def synthetic_roundtrip(tools: dict[str, str]) -> str:
    """Run with a sterile environment; do not inherit caller's SOPS config."""
    with tempfile.TemporaryDirectory(prefix="nabla-age-sops-synthetic-") as folder:
        root = Path(folder)
        identity = root / "ephemeral-identity.txt"
        plain = root / "plain.json"
        age_cipher = root / "fixture.age"
        age_clear = root / "age-restored.json"
        sops_cipher = root / "encrypted.sops.json"
        sops_clear = root / "sops-restored.json"
        # All files live in the isolated 0700 temporary directory.
        plain.write_text(json.dumps(FIXTURE, separators=(",", ":")) + "\n", encoding="utf-8")
        plain.chmod(0o600)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(root), "XDG_CONFIG_HOME": str(root),
            "GNUPGHOME": str(root), "SOPS_AGE_KEY_FILE": str(identity),
            "LC_ALL": "C", "SOPS_DISABLE_VERSION_CHECK": "true",
        }
        if run_command([tools["age-keygen"], "-o", str(identity)], env, root) != "PASS":
            return "SYNTHETIC_IDENTITY_GENERATION_FAILED"
        try:
            info = identity.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or (
                    stat.S_IMODE(info.st_mode) & 0o077):
                return "SYNTHETIC_IDENTITY_PERMISSIONS_INVALID"
        except OSError:
            return "SYNTHETIC_IDENTITY_PERMISSIONS_INVALID"
        recipient = run_command([tools["age-keygen"], "-y", str(identity)], env, root,
                                recipient_output=True)
        if recipient is None:
            return "SYNTHETIC_RECIPIENT_UNAVAILABLE"
        if run_command([tools["age"], "-r", recipient, "-o", str(age_cipher),
                        str(plain)], env, root) != "PASS":
            return "AGE_SYNTHETIC_ENCRYPT_FAILED"
        if run_command([tools["age"], "-d", "-i", str(identity), "-o",
                        str(age_clear), str(age_cipher)], env, root) != "PASS":
            return "AGE_SYNTHETIC_DECRYPT_FAILED"
        try:
            if not hmac.compare_digest(age_clear.read_bytes(), plain.read_bytes()):
                return "AGE_SYNTHETIC_ROUNDTRIP_MISMATCH"
        except OSError:
            return "AGE_SYNTHETIC_ROUNDTRIP_MISMATCH"
        if run_command([tools["sops"], "encrypt", "--age", recipient,
                        "--input-type", "json", "--output-type", "json",
                        "--output", str(sops_cipher), str(plain)], env, root) != "PASS":
            return "SOPS_SYNTHETIC_ENCRYPT_FAILED"
        if run_command([tools["sops"], "decrypt", "--input-type", "json",
                        "--output-type", "json", "--output", str(sops_clear),
                        str(sops_cipher)], env, root) != "PASS":
            return "SOPS_SYNTHETIC_DECRYPT_FAILED"
        try:
            if json.loads(sops_clear.read_text(encoding="utf-8")) != FIXTURE:
                return "SOPS_SYNTHETIC_ROUNDTRIP_MISMATCH"
        except (OSError, ValueError, UnicodeError):
            return "SOPS_SYNTHETIC_ROUNDTRIP_MISMATCH"
    return "AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--run", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error("--acknowledge only accepted with --run")
    if args.run and args.acknowledge != ACK:
        parser.error("synthetic-only acknowledgment required")
    tools = tool_paths()
    if tools is None:
        state = "REQUIRED_SOFTWARE_TOOLS_NOT_FOUND"
    elif args.check:
        state = "SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED"
    else:
        state = synthetic_roundtrip(tools)
    print(json.dumps({
        "mode": "SYNTHETIC_SOFTWARE_RECOVERY_ONLY",
        "status": "NO-GO", "state": state,
        "synthetic_software_roundtrip_verified": state == "AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS",
        "real_escrow_restoration_verified": False,
        "piv82_decrypt_verified": False,
        "hardware_mutation_authorized": False,
        "sops_configuration_changed": False,
    }, sort_keys=True))
    return 0 if state in ("SYNTHETIC_TOOLS_PRESENT_NOT_EXECUTED",
                           "AGE_AND_SOPS_SYNTHETIC_ROUNDTRIP_PASS") else 3


if __name__ == "__main__":
    sys.exit(main())
