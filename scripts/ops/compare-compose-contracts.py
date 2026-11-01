#!/usr/bin/env python3
"""Compare published snapshot field contracts with a sibling Compose checkout.

Static AST only: never imports the inspected script, reads secret files,
starts any services, invokes Git, or interacts with a YubiKey.
A matching field set is NOT proof of runtime or device parity.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path("scripts/workstation/inspect-yubikey-dependencies-readonly.py")
REQUIRED = frozenset(("status", "mode", "hardware_mutation_authorized"))
MAX_SOURCE_SIZE = 262144


def read_source(root: Path) -> str | None:
    """Read only the expected regular Python file, never following a symlink."""
    candidate = root / SCRIPT
    try:
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_SIZE:
            return None
        # An explicit symlink in the final component is always rejected.
        if candidate.is_symlink():
            return None
        return candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return None


def snapshot_fields(source: str) -> tuple[str, ...] | None:
    """Extract literal top-level snapshot keys without executing the module."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    snapshots = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "snapshot"
    ]
    if len(snapshots) != 1:
        return None
    returns = [
        node for node in ast.walk(snapshots[0])
        if isinstance(node, ast.Return)
    ]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Dict):
        return None
    result = returns[0].value
    if any(not isinstance(key, ast.Constant) or not isinstance(key.value, str)
           for key in result.keys):
        return None
    keys = [key.value for key in result.keys]
    if len(keys) != len(set(keys)):
        return None
    return tuple(sorted(keys))


def compare(compose_root: Path, yubikey_root: Path = ROOT) -> dict:
    """Compare only stable public schema names, not command behavior."""
    old_source = read_source(compose_root)
    new_source = read_source(yubikey_root)
    old_keys = snapshot_fields(old_source) if old_source is not None else None
    new_keys = snapshot_fields(new_source) if new_source is not None else None
    report = {
        "schema": "nabla-yubikey/compose-snapshot-contract/v1",
        "mode": "STATIC_AST_ONLY",
        "read_only": True,
        "hardware_mutation_authorized": False,
        "runtime_parity_verified": False,
        "source_path": SCRIPT.as_posix(),
        "compose_source": "AVAILABLE" if old_source is not None else "UNAVAILABLE",
        "yubikey_source": "AVAILABLE" if new_source is not None else "UNAVAILABLE",
        "compose_fields": list(old_keys or ()),
        "yubikey_fields": list(new_keys or ()),
    }
    if old_keys is None or new_keys is None:
        report.update(status="NO-GO", blocking=["SNAPSHOT_SOURCE_UNREADABLE"],
                      fields_match=False, missing_fields=[], extra_fields=[],
                      source_identical=False)
        return report
    before, after = set(old_keys), set(new_keys)
    missing, extra = sorted(before - after), sorted(after - before)
    required_missing = sorted(REQUIRED - after)
    # This can only attest a literal field contract, never interpretation.
    fields_match = not missing and not extra and not required_missing
    report.update(
        status="SCHEMA_MATCH" if fields_match else "NO-GO",
        blocking=(["REQUIRED_FIELD_MISSING"] if required_missing else []) +
                 (["SNAPSHOT_FIELDS_DIFFER"] if missing or extra else []),
        fields_match=fields_match,
        missing_fields=missing + required_missing if required_missing else missing,
        extra_fields=extra,
        source_identical=hashlib.sha256(old_source.encode()).digest() ==
                         hashlib.sha256(new_source.encode()).digest(),
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-root", type=Path, required=True,
                        help="Sibling nabla-compose checkout (static source only)")
    parser.add_argument("--assert-field-parity", action="store_true",
                        help="Exit 2 if the snapshot field sets differ")
    args = parser.parse_args(argv)
    report = compare(args.compose_root, ROOT)
    print(json.dumps(report, sort_keys=True))
    return 2 if args.assert_field_parity and not report["fields_match"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
