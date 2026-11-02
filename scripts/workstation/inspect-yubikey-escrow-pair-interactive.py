#!/usr/bin/env python3
"""Prompt for two existing age escrow paths without leaking them to shell history.

Only metadata (lstat) of the supplied files is examined. Never opens,
decrypts, copies or rewrites the files. Two filesystems != independent media.
"""
from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SOURCE = Path(__file__).with_name("inspect-yubikey-recovery-readonly.py")
ACK = "INSPECT_EXISTING_ESCROW_METADATA"


# Workstation-specific known backup roots; filenames and private paths are
# never sent to stdout, GitHub, argv or diagnostics. No recursive scan.
DISCOVERY_LIMIT = 256


def candidate_directories(home: Path) -> tuple[Path, ...]:
    return (
        home / ".local/share/nabla/age-backups",
        Path("/media/backup/lab/secret"),
    )


def classify_backup_mount() -> str:
    """Classify the active mount only. Never report its NFS source or options."""
    try:
        done = subprocess.run(
            ["findmnt", "-n", "-T", "/media/backup/lab/secret",
             "-o", "TARGET,FSTYPE"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, check=False, timeout=5,
        )
        if done.returncode != 0 or len(done.stdout) > 4096:
            return "MOUNT_UNVERIFIED"
        lines = done.stdout.strip().splitlines()
        if len(lines) != 1:
            return "MOUNT_UNVERIFIED"
        parts = lines[0].split()
        if len(parts) != 2:
            return "MOUNT_UNVERIFIED"
        target, fstype = parts
        if target != "/media/backup/lab":
            return "UNEXPECTED_MOUNT_TARGET"
        if fstype == "nfs4":
            return "EXPECTED_NFS4_MOUNT_PRESENT"
        if fstype == "nfs":
            return "EXPECTED_NFS_MOUNT_PRESENT"
        return "EXPECTED_TARGET_NON_NFS_FILESYSTEM"
    except FileNotFoundError:
        return "FINDMNT_UNAVAILABLE"
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return "MOUNT_UNVERIFIED"


def diagnose_backup_roots(home: Path) -> dict[str, object]:
    """Inspect directory entries only; never disclose paths or basenames.

    Summaries are bounded. This does not open encrypted files or certify
    that the mounted backup is on independent physical media.
    """
    reports: list[dict[str, object]] = []
    names: list[set[str]] = []
    for directory in candidate_directories(home):
        report: dict[str, object] = {"state": "UNKNOWN", "age_files": 0}
        found: set[str] = set()
        try:
            if any(part.is_symlink() for part in (directory, *directory.parents)):
                report["state"] = "SYMLINK_DIRECTORY_UNTRUSTED"
            else:
                with os.scandir(directory) as entries:
                    for count, entry in enumerate(entries):
                        if count >= DISCOVERY_LIMIT:
                            report["state"] = "TOO_MANY_ENTRIES"
                            break
                        if entry.name.endswith(".age") and entry.is_file(follow_symlinks=False):
                            found.add(entry.name)
                    else:
                        report["state"] = "ACCESSIBLE"
            report["age_files"] = min(len(found), DISCOVERY_LIMIT)
        except FileNotFoundError:
            report["state"] = "DIRECTORY_MISSING"
        except PermissionError:
            report["state"] = "PERMISSION_DENIED"
        except (OSError, ValueError, UnicodeError):
            report["state"] = "DIRECTORY_UNAVAILABLE"
        reports.append(report)
        names.append(found if report["state"] == "ACCESSIBLE" else set())
    intersection = names[0] & names[1]
    # Only inspect the filename inferred from a unique local source.
    # Do not expose it or read any encrypted file contents.
    expected = "NOT_EVALUATED"
    if (reports[0]["state"] == "ACCESSIBLE" and
            reports[1]["state"] == "ACCESSIBLE"):
        if len(names[0]) != 1:
            expected = "NO_UNIQUE_SOURCE_FILE"
        else:
            # Backup directory was checked against symlinked parents above.
            backup_target = candidate_directories(home)[1] / next(iter(names[0]))
            try:
                info = backup_target.lstat()
                if stat.S_ISLNK(info.st_mode):
                    expected = "EXPECTED_COPY_IS_SYMLINK"
                elif not stat.S_ISREG(info.st_mode):
                    expected = "EXPECTED_COPY_NOT_REGULAR"
                elif info.st_size == 0:
                    expected = "EXPECTED_COPY_EMPTY"
                else:
                    expected = "EXPECTED_COPY_REGULAR_NONEMPTY"
            except FileNotFoundError:
                expected = "EXPECTED_COPY_MISSING"
            except PermissionError:
                expected = "EXPECTED_COPY_ACCESS_DENIED"
            except (OSError, ValueError, UnicodeError):
                expected = "EXPECTED_COPY_METADATA_UNAVAILABLE"
    return {
        "source_directory": reports[0],
        "backup_directory": reports[1],
        "matching_age_filenames": min(len(intersection), DISCOVERY_LIMIT),
        "backup_mount_state": classify_backup_mount(),
        "expected_backup_copy_state": expected,
        "home_location_consistent_with_account": _home_is_account_home(home),
        "paths_disclosed": False,
        "files_opened": False,
        "restoration_verified": False,
    }


def _home_is_account_home(home: Path) -> bool | None:
    try:
        import pwd
        return home == Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError):
        return None


def discover_pair(home: Path) -> tuple[str, tuple[Path, Path] | None]:
    """Match a single existing .age basename across the two known roots.

    Iterate directory entries only. No archives are opened, hashed, decrypted
    or copied. No directory traversal through symlinks and no name output.
    """
    roots = candidate_directories(home)
    all_candidates: list[dict[str, Path]] = []
    for directory in roots:
        try:
            # Prevent traversal of symlinked parents or directories.
            if any(part.is_symlink() for part in (directory, *directory.parents)):
                return "DISCOVERY_DIRECTORY_UNTRUSTED", None
            matches: dict[str, Path] = {}
            with os.scandir(directory) as entries:
                for index, entry in enumerate(entries):
                    if index >= DISCOVERY_LIMIT:
                        return "DISCOVERY_TOO_MANY_ENTRIES", None
                    if (entry.name.endswith(".age")
                            and entry.is_file(follow_symlinks=False)):
                        matches[entry.name] = directory / entry.name
            all_candidates.append(matches)
        except (OSError, ValueError, UnicodeError):
            return "DISCOVERY_DIRECTORY_UNAVAILABLE", None
    common = set(all_candidates[0]) & set(all_candidates[1])
    if not common:
        return "DISCOVERY_NO_MATCHING_PAIR", None
    if len(common) != 1:
        return "DISCOVERY_MULTIPLE_MATCHING_PAIRS", None
    name = next(iter(common))
    pair = (all_candidates[0][name], all_candidates[1][name])
    state = read_escrow_state(*pair)
    return state, pair if state == "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED" else None




def read_escrow_state(a: Path, b: Path) -> str:
    """Delegate existing symlink-safe stat-only policy. No raw path output."""
    try:
        spec = importlib.util.spec_from_file_location("nabla_escrow_metadata", SOURCE)
        if spec is None or spec.loader is None:
            return "METADATA_INSPECTOR_UNAVAILABLE"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return str(module.escrow_inventory(a, b))
    except (OSError, AttributeError, ValueError, ImportError, TypeError):
        return "METADATA_INSPECTOR_UNAVAILABLE"


def classify_inputs(first: str, second: str) -> str:
    if not isinstance(first, str) or not isinstance(second, str):
        return "INVALID_INPUT"
    if (not first or not second or len(first) > 4096 or len(second) > 4096
            or "\x00" in first + second or "\n" in first + second):
        return "INVALID_INPUT"
    a, b = Path(first), Path(second)
    if not a.is_absolute() or not b.is_absolute() or a.suffix != ".age" or b.suffix != ".age":
        return "INVALID_INPUT"
    if a == b:
        return "SAME_FILE"
    return read_escrow_state(a, b)


def inspect(*, tty: bool, reader=None, confirmer=None) -> str:
    if not tty:
        return "INTERACTIVE_TERMINAL_REQUIRED"
    # Keep injected test/automation readers independent of host filesystem.
    autodiscover = reader is None
    if reader is None:
        reader = getpass.getpass
    if confirmer is None:
        confirmer = input
    try:
        if autodiscover:
            found, pair = discover_pair(Path.home())
            if pair is not None:
                answer = confirmer(
                    "Deux sauvegardes .age de même nom trouvées dans les deux "
                    "répertoires connus. Vérifier leurs métadonnées ? [o/N] : "
                ).strip().lower()
                if answer in ("o", "oui", "y", "yes"):
                    return read_escrow_state(*pair)
        first = reader("Escrow age A (chemin absolu, saisie masquée) : ")
        second = reader("Escrow age B (chemin absolu, saisie masquée) : ")
        return classify_inputs(first, second)
    except (EOFError, KeyboardInterrupt, OSError, UnicodeError):
        return "INPUT_UNAVAILABLE"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    opts = parser.add_mutually_exclusive_group(required=True)
    opts.add_argument("--check", action="store_true")
    opts.add_argument("--inspect", action="store_true")
    opts.add_argument("--discover", action="store_true")
    opts.add_argument("--diagnose", action="store_true")
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    if (args.check or args.discover or args.diagnose) and args.acknowledge:
        parser.error("acknowledgment accepted only for --inspect")
    if args.inspect and args.acknowledge != ACK:
        parser.error("explicit metadata-only acknowledgment required")
    details = None
    if args.check:
        state = "PATHS_NOT_COLLECTED"
    elif args.diagnose:
        state = "DIRECTORY_METADATA_ONLY"
        details = diagnose_backup_roots(Path.home())
    elif args.discover:
        state, _ = discover_pair(Path.home())
    else:
        state = inspect(tty=os.isatty(0) and os.isatty(2))
    report = {
        "mode": "EXISTING_ESCROW_PAIR_METADATA_ONLY",
        "status": "NO-GO", "state": state,
        "paths_disclosed": False, "files_opened": False,
        "decryption_attempted": False, "independent_media_verified": False,
        "restoration_verified": False,
        "hardware_mutation_authorized": False,
    }
    if details is not None:
        report["diagnostic"] = details
    print(json.dumps(report, sort_keys=True))
    return 0 if state in ("PATHS_NOT_COLLECTED", "DIRECTORY_METADATA_ONLY",
                           "TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED") else 3


if __name__ == "__main__":
    sys.exit(main())
