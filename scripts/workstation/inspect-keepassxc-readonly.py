#!/usr/bin/env python3
"""Diagnose a KeePassXC vault protected by a key file and a YubiKey, read-only.

Reads only the unencrypted KDBX outer header, file modes, `ykman list` /
`ykman otp info` and the KeePassXC [SSHAgent] setting. Never asks for the
master password, never issues a challenge to the YubiKey and never prints
paths, serial numbers or key material.

Defaults: newest ~/Dropbox/*.kdbx and newest ~/.local/share/keepassxc/*.key,
overridable with KEEPASSXC_DB and KEEPASSXC_KEYFILE.
"""
from __future__ import annotations

import configparser
import os
import shutil
import stat
import struct
import sys
from pathlib import Path

from probe_common import line_count, main_json, parse_otp, run_bounded, verdict, yubikey_role

CIPHERS = {"31c1f2e6bf714350be5805216afc5aff": "AES-256", "d6038a2b8b6f4cb5a524339a31dbb59a": "ChaCha20",
           "ad68f29f576f4bb9a36ad47af965346c": "Twofish"}
KDFS = {"c9d9f39a628a4460bf740d08c18a4fea": "AES-KDF", "ef636ddf8c29444b91f7a9a403e30a0c": "Argon2d",
        "9e298b1956db4773b23dfc3ec6f0a1e6": "Argon2id"}
HOME = Path.home()
CLOUD_DIRS = (HOME / "Dropbox",)


def newest(directory: Path, pattern: str) -> Path | None:
    try:
        files = [p for p in directory.glob(pattern) if p.is_file() and not p.is_symlink()]
    except OSError:
        return None
    return max(files, key=lambda p: p.stat().st_mtime, default=None)


def variant_dict(data: bytes) -> dict:
    out, pos = {}, 2
    while pos < len(data):
        kind = data[pos]
        pos += 1
        if kind == 0:
            break
        klen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        key = data[pos:pos + klen].decode("ascii", "replace")
        pos += klen
        vlen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        value = data[pos:pos + vlen]
        pos += vlen
        out[key] = value.hex() if kind == 0x42 else int.from_bytes(value, "little")
    return out


def parse_header(raw: bytes) -> dict | None:
    """Parse the unencrypted outer header; None when it is not a KDBX file."""
    try:
        sig1, sig2, minor, major = struct.unpack_from("<IIHH", raw, 0)
        if (sig1, sig2) != (0x9AA2D903, 0xB54BFB67):
            return None
        info = {"version": f"{major}.{minor}"}
        size_fmt, size_len = ("<I", 4) if major >= 4 else ("<H", 2)
        pos = 12
        while pos < len(raw):
            field = raw[pos]
            size = struct.unpack_from(size_fmt, raw, pos + 1)[0]
            value = raw[pos + 1 + size_len:pos + 1 + size_len + size]
            pos += 1 + size_len + size
            if field == 0:
                return info
            if field == 2:
                info["cipher"] = CIPHERS.get(value.hex(), "unknown")
            elif field == 6:
                info["kdf"] = "AES-KDF"
            elif field == 11:
                params = variant_dict(value)
                info["kdf"] = KDFS.get(params.get("$UUID", ""), "unknown")
                if "M" in params:
                    info["memory_mib"] = params["M"] // (1024 * 1024)
                if "I" in params:
                    info["iterations"] = params["I"]
        return None
    except (struct.error, IndexError, ValueError):
        return None


def mode(path: Path | None) -> str:
    if path is None:
        return "NOT_FOUND"
    try:
        return oct(stat.S_IMODE(path.lstat().st_mode))[2:]
    except OSError:
        return "UNKNOWN"


def keyfile_location(db: Path | None, keyfile: Path | None) -> str:
    """A key file next to the vault, or in the same cloud, adds nothing if that place leaks."""
    if keyfile is None:
        return "NOT_FOUND"
    resolved = keyfile.resolve()
    if any(resolved.is_relative_to(cloud) for cloud in CLOUD_DIRS):
        return "IN_CLOUD"
    if db is not None and resolved.parent == db.resolve().parent:
        return "WITH_DATABASE"
    return "SEPARATE"


def yubikey_slot2() -> str:
    count = line_count(run_bounded(["ykman", "list"]))
    if count is None:
        return "UNKNOWN"
    if count != 1:
        return f"DEVICE_COUNT_{count}"
    slots = parse_otp(run_bounded(["ykman", "otp", "info"]))
    if slots is None:
        return "UNKNOWN"
    return "PROGRAMMED" if slots["slot2"] else "EMPTY"


def ssh_agent_setting(ini: Path) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        if not parser.read(ini, encoding="utf-8"):
            return "NOT_CONFIGURED"
    except (configparser.Error, OSError, UnicodeError):
        return "UNKNOWN"
    return "ENABLED" if parser.get("SSHAgent", "Enabled", fallback="false").lower() == "true" else "DISABLED"


def assess(report: dict) -> tuple[list[str], list[str]]:
    blocking, advice = [], []
    header = report["header"]
    if header is None:
        blocking.append("DATABASE_UNREADABLE")
    else:
        if not header["version"].startswith("4."):
            blocking.append("KDBX_BELOW_4")
        if header.get("kdf") != "Argon2id":
            advice.append("KDF_NOT_ARGON2ID")
        if header.get("memory_mib", 0) < 256:
            advice.append("KDF_MEMORY_BELOW_256MIB")
    if report["database_mode"] != "600":
        blocking.append("DATABASE_MODE_NOT_600")
    if report["keyfile_mode"] != "600":
        blocking.append("KEYFILE_MODE_NOT_600")
    if report["keyfile_location"] != "SEPARATE":
        blocking.append(f"KEYFILE_{report['keyfile_location']}")
    if report["cloud_keyfile_present"]:
        blocking.append("KEYFILE_LEFT_IN_CLOUD")
    if report["yubikey_slot2"] != "PROGRAMMED":
        blocking.append(f"YUBIKEY_SLOT2_{report['yubikey_slot2']}")
    if report["keepassxc_ssh_agent"] != "ENABLED":
        advice.append("KEEPASSXC_SSH_AGENT_DISABLED")
    if report["ssh_file_key_on_disk"]:
        advice.append("SSH_FILE_KEY_ON_DISK")
    return blocking, advice


def snapshot() -> dict:
    db = Path(os.environ["KEEPASSXC_DB"]) if os.environ.get("KEEPASSXC_DB") else newest(HOME / "Dropbox", "*.kdbx")
    keyfile = (Path(os.environ["KEEPASSXC_KEYFILE"]) if os.environ.get("KEEPASSXC_KEYFILE")
               else newest(HOME / ".local/share/keepassxc", "*.key"))
    header = None
    if db is not None:
        try:
            with db.open("rb") as handle:
                header = parse_header(handle.read(65536))
        except OSError:
            header = None
    report = {
        "mode": "KEEPASSXC_READONLY",
        "header": header,
        "database_mode": mode(db),
        "keyfile_mode": mode(keyfile),
        "keyfile_location": keyfile_location(db, keyfile),
        "cloud_keyfile_present": any(newest(cloud, "*.key") for cloud in CLOUD_DIRS),
        "yubikey_slot2": yubikey_slot2(),
        "yubikey_role": yubikey_role(),
        "keepassxc_cli": "INSTALLED_UNVERIFIED" if shutil.which("keepassxc-cli") else "MISSING",
        "keepassxc_ssh_agent": ssh_agent_setting(HOME / ".config/keepassxc/keepassxc.ini"),
        "ssh_file_key_on_disk": (HOME / ".ssh/id_ed25519").exists(),
        "database_unlock_verified": False,
        "hardware_mutation_authorized": False,
    }
    return verdict(report, *assess(report))


def main(argv: list[str] | None = None) -> int:
    return main_json(snapshot, argv)


if __name__ == "__main__":
    sys.exit(main())
