#!/usr/bin/env python3
"""Observe GPG/PCSC processes, SSH-agent and recovery tool metadata only.

Does not open secret files, start/stop daemons, query YubiKeys, enumerate
account names, request PINs, list credentials or initiate cryptography.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from probe_common import main_json

TOOLS = ("pg_restore", "pg_dump", "psql", "initdb", "pg_ctl", "age", "sops", "gpg", "ssh-add")


def process_state(name: str, uid: int | None = None) -> str:
    """Observe process existence without reading process arguments or identifiers."""
    if name not in {"scdaemon", "pcscd"}:
        return "UNKNOWN"
    if not shutil.which("pgrep"):
        return "TOOL_MISSING"
    command = ["pgrep", "-x"]
    if uid is not None:
        command += ["-u", str(uid)]
    command += [name]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "UNKNOWN"
    if result.returncode == 0:
        return "PROCESS_PRESENT_UNVERIFIED"
    if result.returncode == 1:
        return "PROCESS_NOT_OBSERVED"
    return "UNKNOWN"


def ssh_agent_state() -> str:
    """Query only public identity presence, with all ssh-add output discarded."""
    raw = os.environ.get("SSH_AUTH_SOCK", "")
    if not raw:
        return "SOCKET_NOT_CONFIGURED"
    if "\0" in raw or len(raw) > 4096 or not Path(raw).is_absolute():
        return "UNKNOWN"
    try:
        meta = Path(raw).lstat()  # Refuse links, never open the socket ourselves.
        if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid != os.getuid():
            return "SOCKET_UNTRUSTED"
    except FileNotFoundError:
        return "SOCKET_NOT_FOUND"
    except (OSError, ValueError):
        return "UNKNOWN"
    if not shutil.which("ssh-add"):
        return "TOOL_MISSING"
    try:
        result = subprocess.run(["ssh-add", "-l"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "UNKNOWN"
    if result.returncode == 0:
        return "PUBLIC_IDENTITIES_PRESENT_UNVERIFIED"
    if result.returncode == 1:
        return "NO_IDENTITIES_OR_AGENT"
    return "UNKNOWN"


def classify_scdaemon_assuan(raw: str) -> str:
    """Classify only a bounded Assuan answer; never return the raw reply.

    A negative reply does not prove that every scdaemon process is stopped.
    """
    import re

    if not isinstance(raw, str) or len(raw) > 4096 or "\x00" in raw:
        return "NOT_CONFIRMED"
    lines = raw.strip().splitlines()
    if len(lines) == 3 and lines[0] == "OK Pleased to meet you":
        lines = lines[1:]
    if len(lines) != 2 or lines[-1] != "OK closing connection":
        return "NOT_CONFIRMED"
    if lines[0] == "OK":
        return "AGENT_REPORTS_SCD_RUNNING_UNVERIFIED"
    if re.fullmatch(r"ERR [0-9]+(?: [^\r\n]{0,200})?", lines[0]):
        return "AGENT_SCD_STATUS_REJECTED_UNVERIFIED"
    return "NOT_CONFIRMED"


def scdaemon_agent_state() -> str:
    """Ask existing agent whether scdaemon already runs; never send SCD."""
    if not shutil.which("gpg-connect-agent"):
        return "TOOL_MISSING"
    try:
        done = subprocess.run(
            ["gpg-connect-agent", "--no-autostart", "GETINFO scd_running", "/bye"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=5, check=False,
        )
        if (done.returncode != 0 or done.stderr.strip()
                or len(done.stdout) > 4096 or "\x00" in done.stdout):
            return "UNKNOWN"
        return classify_scdaemon_assuan(done.stdout)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return "UNKNOWN"


def trusted_executable(binary: Path, owners: tuple[int, ...]) -> bool:
    """Inspect executable metadata only, refusing symlinks and unexpected owners."""
    if binary.is_symlink():
        return False
    try:
        info = binary.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_uid in owners
            and bool(stat.S_IMODE(info.st_mode) & 0o111))


def postgres_versioned_tools_state() -> str:
    """Stat only conventional Debian/Ubuntu root-owned server executables.

    Never enumerate database clusters, invoke initdb/pg_ctl, or reveal paths.
    """
    root = Path("/usr/lib/postgresql")
    try:
        if root.is_symlink():
            return "UNKNOWN"
        if not root.is_dir():
            return "NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS"
        partly_installed = False
        for version in root.iterdir():
            if (not version.name.isascii() or not version.name.isdecimal()
                    or len(version.name) > 3 or version.is_symlink()):
                continue
            binary_dir = version / "bin"
            if binary_dir.is_symlink():
                continue
            checks = [trusted_executable(binary_dir / name, (0,))
                      for name in ("initdb", "pg_ctl")]
            if all(checks):
                return "VERSIONED_SERVER_BINARIES_PRESENT_UNVERIFIED"
            if any(checks):
                partly_installed = True
        return ("PARTIAL_VERSIONED_SERVER_BINARIES"
                if partly_installed else "NOT_FOUND_IN_STANDARD_VERSIONED_LOCATIONS")
    except (OSError, ValueError):
        return "UNKNOWN"


def postgres_pg_config_server_tools_state() -> str:
    """Check client pg_config bindir metadata; never run server binaries.

    A client pg_config does not establish server installation or compatibility.
    """
    if not shutil.which("pg_config"):
        return "PG_CONFIG_MISSING"
    try:
        done = subprocess.run(
            ["pg_config", "--bindir"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=5, check=False,
        )
        if done.returncode != 0 or done.stderr.strip():
            return "UNKNOWN"
        raw = done.stdout
        if len(raw) > 4096 or "\x00" in raw or len(raw.splitlines()) != 1:
            return "UNKNOWN"
        value = raw.strip()
        if not value or not Path(value).is_absolute():
            return "UNKNOWN"
        directory = Path(value)
        if directory.is_symlink() or not directory.is_dir():
            return "BINDIR_UNAVAILABLE"
        found = [trusted_executable(directory / name, (0, os.getuid()))
                 for name in ("initdb", "pg_ctl")]
        if all(found):
            return "PG_CONFIG_SERVER_BINARIES_PRESENT_UNVERIFIED"
        return ("PG_CONFIG_SERVER_BINARIES_PARTIAL"
                if any(found) else "PG_CONFIG_BINDIR_HAS_NO_SERVER_BINARIES")
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return "UNKNOWN"


def snapshot() -> dict:
    return {
        "status": "NO-GO",
        "mode": "HOST_DEPENDENCIES_METADATA_ONLY",
        "scdaemon": process_state("scdaemon", uid=os.getuid()),
        "pcscd": process_state("pcscd"),
        "agent_scdaemon": scdaemon_agent_state(),
        "postgres_versioned_server_tools": postgres_versioned_tools_state(),
        "postgres_pg_config_server_tools": postgres_pg_config_server_tools_state(),
        "ssh_agent": ssh_agent_state(),
        "recovery_tools": {name: "INSTALLED_UNVERIFIED" if shutil.which(name) else "MISSING"
                           for name in TOOLS},
        "openpgp_card_access_verified": False,
        "postgres_restore_verified": False,
        "ssh_fido_login_verified": False,
        "escrow_restore_verified": False,
        "hardware_mutation_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    return main_json(snapshot, argv)


if __name__ == "__main__":
    sys.exit(main())
