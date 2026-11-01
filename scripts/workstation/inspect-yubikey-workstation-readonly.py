#!/usr/bin/env python3
"""Read-only workstation readiness: tool/path metadata; no secrets or token I/O."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

TOOLS = (
    "ykman", "gpg", "gpgconf", "pcsc_scan", "age", "age-plugin-yubikey",
    "sops", "ssh-keygen", "pamu2fcfg", "keepassxc", "cryptsetup", "lsblk",
)


def metadata(path: Path, kind: str, uid: int) -> str:
    try:
        if path.is_symlink():
            return "SYMLINK_REFUSED"
        info = path.lstat()
        if kind == "identity":
            if (stat.S_ISREG(info.st_mode) and info.st_uid == uid
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1):
                return "PRESENT_PRIVATE_METADATA_ONLY"
        elif kind == "socket" and stat.S_ISSOCK(info.st_mode):
            return "PRESENT_UNVERIFIED"
        elif kind == "public" and stat.S_ISREG(info.st_mode):
            return "PRESENT_UNVERIFIED"
        return "UNEXPECTED_METADATA"
    except FileNotFoundError:
        return "NOT_FOUND"
    except OSError:
        return "UNKNOWN"



def gpg_agent_socket_status() -> tuple[str, str]:
    """Resolve agent socket from GnuPG itself; do not launch/connect to agent."""
    if not shutil.which("gpgconf"):
        return "UNKNOWN", "GPGCONF_MISSING"
    try:
        done = subprocess.run(
            ["gpgconf", "--list-dirs", "agent-socket"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=5, check=False,
        )
        if done.returncode != 0 or done.stderr.strip():
            return "UNKNOWN", "GPGCONF_ERROR"
        raw = done.stdout
        if (len(raw) > 4096 or "\0" in raw or
                len(raw.splitlines()) != 1):
            return "UNKNOWN", "GPGCONF_INVALID_PATH"
        value = raw.strip()
        if not value or not Path(value).is_absolute():
            return "UNKNOWN", "GPGCONF_INVALID_PATH"
        return metadata(Path(value), "socket", os.getuid()), "GPGCONF"
    except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        return "UNKNOWN", "GPGCONF_ERROR"


def snapshot(home: Path, uid: int) -> dict:
    socket, origin = gpg_agent_socket_status()
    paths = {
        "sops_age_identity": metadata(home / ".config/sops/age/keys.txt", "identity", uid),
        "gpg_agent_socket": socket,
        "ssh_fido_public_handle": metadata(home / ".ssh/id_ed25519_sk.pub", "public", uid),
        "pam_u2f_mapping": metadata(home / ".config/Yubico/u2f_keys", "public", uid),
    }
    return {
        "status": "NO-GO", "mode": "HOST_METADATA_ONLY",
        "tools": {tool: "INSTALLED_UNVERIFIED" if shutil.which(tool) else "MISSING" for tool in TOOLS},
        "paths": paths,
        "gpg_agent_socket_locator": origin,
        "gpg_card_access_verified": False,
        "postgres_restore_verified": False,
        "age_decrypt_verified": False,
        "ssh_fido_auth_verified": False,
        "pam_fallback_verified": False,
        "hardware_mutation_authorized": False,
    }


def main() -> int:
    if len(sys.argv) != 1:
        print("No arguments supported", file=sys.stderr)
        return 2
    home = os.environ.get("HOME", "")
    if not home or not Path(home).is_dir():
        print(json.dumps({"status": "NO-GO", "reason": "HOME_UNAVAILABLE"}))
        return 3
    print(json.dumps(snapshot(Path(home), os.getuid()), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
