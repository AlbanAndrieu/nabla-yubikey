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
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

CIPHERS = {"31c1f2e6bf714350be5805216afc5aff": "AES-256", "d6038a2b8b6f4cb5a524339a31dbb59a": "ChaCha20",
           "ad68f29f576f4bb9a36ad47af965346c": "Twofish"}
KDFS = {"c9d9f39a628a4460bf740d08c18a4fea": "AES-KDF", "ef636ddf8c29444b91f7a9a403e30a0c": "Argon2d",
        "9e298b1956db4773b23dfc3ec6f0a1e6": "Argon2id"}
HOME = Path.home()
CLOUD_DIRS = (HOME / "Dropbox",)


def newest(directory: Path, pattern: str) -> Path | None:
    """Choose a regular, non-symlink file; tolerate concurrent backup rotation."""
    candidates: list[tuple[int, Path]] = []
    try:
        for path in directory.glob(pattern):
            try:
                meta = path.lstat()
                if stat.S_ISREG(meta.st_mode):
                    candidates.append((meta.st_mtime_ns, path))
            except OSError:
                continue
    except OSError:
        return None
    return max(candidates, default=(0, None))[1]


def variant_dict(data: bytes) -> dict | None:
    """Parse bounded KDBX variant metadata, rejecting truncated/duplicate fields."""
    if len(data) < 3 or data[:2] != bytes((0, 1)):
        return None
    out: dict[str, str | int] = {}
    pos = 2
    for _ in range(64):
        if pos >= len(data):
            return None
        kind = data[pos]
        pos += 1
        if kind == 0:
            return out if pos == len(data) else None
        if pos + 4 > len(data):
            return None
        key_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if key_len < 1 or key_len > 64 or pos + key_len + 4 > len(data):
            return None
        try:
            key = data[pos:pos + key_len].decode("ascii")
        except UnicodeDecodeError:
            return None
        pos += key_len
        value_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if key in out or value_len > 4096 or pos + value_len > len(data):
            return None
        value = data[pos:pos + value_len]
        pos += value_len
        if kind == 0x42:
            out[key] = value.hex()
        elif kind in (0x04, 0x05) and value_len == (4 if kind == 0x04 else 8):
            out[key] = int.from_bytes(value, "little")
        else:
            return None
    return None


def parse_header(raw: bytes) -> dict | None:
    """Read only a complete KDBX outer header; never inspect encrypted records."""
    if len(raw) < 12 or len(raw) > 65536:
        return None
    try:
        sig1, sig2, minor, major = struct.unpack_from("<IIHH", raw, 0)
        if (sig1, sig2) != (0x9AA2D903, 0xB54BFB67) or major not in (3, 4):
            return None
        info = {"version": f"{major}.{minor}"}
        size_fmt, size_len = ("<I", 4) if major >= 4 else ("<H", 2)
        pos = 12
        while pos + 1 + size_len <= len(raw):
            field = raw[pos]
            size = struct.unpack_from(size_fmt, raw, pos + 1)[0]
            pos += 1 + size_len
            if size > 65536 or pos + size > len(raw):
                return None
            value = raw[pos:pos + size]
            pos += size
            if field == 0:
                return info if value == b"\r\n\r\n" else None
            if field == 2:
                info["cipher"] = CIPHERS.get(value.hex(), "unknown")
            elif field == 6:
                info["kdf"] = "AES-KDF"
            elif field == 11:
                params = variant_dict(value)
                if params is None:
                    return None
                info["kdf"] = KDFS.get(params.get("$UUID", ""), "unknown")
                if "M" in params and isinstance(params["M"], int):
                    info["memory_mib"] = params["M"] // (1024 * 1024)
                if "I" in params and isinstance(params["I"], int):
                    info["iterations"] = params["I"]
        return None
    except (struct.error, IndexError, ValueError, TypeError):
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


def run(args: list[str]) -> str | None:
    if not shutil.which(args[0]):
        return None
    try:
        done = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, timeout=15, check=False)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 or len(done.stdout) > 65536:
        return None
    return done.stdout


def yubikey_slot2() -> str:
    listing = run(["ykman", "list"])
    if listing is None:
        return "UNKNOWN"
    count = len([line for line in listing.splitlines() if line.strip()])
    if count != 1:
        return f"DEVICE_COUNT_{count}"
    info = run(["ykman", "otp", "info"])
    if info is None:
        return "UNKNOWN"
    # A busy device can print something else: never read that as an empty slot.
    if "Slot 2: programmed" in info.splitlines():
        return "PROGRAMMED"
    return "EMPTY" if "Slot 2: empty" in info.splitlines() else "UNKNOWN"


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
        if header.get("cipher") not in CIPHERS.values():
            blocking.append("CIPHER_UNREADABLE")
        if header.get("kdf") not in KDFS.values() and header.get("kdf") != "AES-KDF":
            blocking.append("KDF_UNREADABLE")
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
            # Explicit paths may point to devices, FIFOs or symlinks: never open those.
            if stat.S_ISREG(db.lstat().st_mode):
                # Refuse a symlink/special-file replacement between lstat and open.
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                fd = os.open(db, flags)
                with os.fdopen(fd, "rb") as handle:
                    if stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                        header = parse_header(handle.read(65536))
        except (OSError, ValueError):
            header = None
    report = {
        "mode": "KEEPASSXC_READONLY",
        "header": header,
        "database_mode": mode(db),
        "keyfile_mode": mode(keyfile),
        "keyfile_location": keyfile_location(db, keyfile),
        "cloud_keyfile_present": any(newest(cloud, "*.key") for cloud in CLOUD_DIRS),
        "yubikey_slot2": yubikey_slot2(),
        "keepassxc_cli": "INSTALLED_UNVERIFIED" if shutil.which("keepassxc-cli") else "MISSING",
        "keepassxc_ssh_agent": ssh_agent_setting(HOME / ".config/keepassxc/keepassxc.ini"),
        "ssh_file_key_on_disk": (HOME / ".ssh/id_ed25519").exists(),
        "database_unlock_verified": False,
        "hardware_mutation_authorized": False,
    }
    blocking, advice = assess(report)
    report.update(status="NO-GO" if blocking else "GO", blocking=blocking, advice=advice)
    return report


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("No arguments supported", file=sys.stderr)
        return 2
    print(json.dumps(snapshot(), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
