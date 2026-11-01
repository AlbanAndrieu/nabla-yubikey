#!/usr/bin/env python3
"""Compare saved, synthetic or pre-captured probe reports without running probes.

The input files must be curated, non-sensitive fixtures, NOT live diagnostics
containing identifiers. This tool never invokes another process, accesses
smartcards, authenticates to a host, or echoes compared values.
An equal fixture set is NOT proof of runtime equivalence or hardware health.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 131072
MAX_CASES = 64
CASE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
ALLOWED_FIELDS = frozenset({
    "status", "mode", "scdaemon", "pcscd", "agent_scdaemon",
    "postgres_versioned_server_tools", "postgres_pg_config_server_tools",
    "ssh_agent", "recovery_tools", "openpgp_card_access_verified",
    "postgres_restore_verified", "ssh_fido_login_verified",
    "escrow_restore_verified", "hardware_mutation_authorized",
})
ALLOWED_TOOLS = frozenset({
    "pg_restore", "pg_dump", "psql", "initdb", "pg_ctl", "age",
    "sops", "gpg", "ssh-add",
})
BOOLEAN_FIELDS = frozenset({
    "openpgp_card_access_verified", "postgres_restore_verified",
    "ssh_fido_login_verified", "escrow_restore_verified",
    "hardware_mutation_authorized",
})
STRING_FIELDS = ALLOWED_FIELDS - BOOLEAN_FIELDS - {"recovery_tools"}
MAX_TEXT = 100


def no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_fixtures(path: Path) -> dict[str, dict] | None:
    """Refuse symlinks, large fixtures, duplicate keys or unknown report fields."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
                return None
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return None
        parsed = json.loads(
            data.decode("utf-8"), object_pairs_hook=no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite value")),
        )
        if not isinstance(parsed, dict) or set(parsed) != {"schema", "cases"}:
            return None
        if parsed["schema"] != "nabla-yubikey/probe-fixtures/v1":
            return None
        cases = parsed["cases"]
        if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
            return None
        result = {}
        for case in cases:
            if not isinstance(case, dict) or set(case) != {"name", "exit_code", "report"}:
                return None
            name, code, report = case["name"], case["exit_code"], case["report"]
            if not isinstance(name, str) or not CASE_NAME.fullmatch(name) or name in result:
                return None
            # Reject bool (a subclass of int), negative, and other exit codes.
            if type(code) is not int or code not in (0, 2):
                return None
            if code == 2:
                if report is not None:
                    return None
            elif not valid_report(report):
                return None
            result[name] = {"exit_code": code, "report": report}
        return result
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return None


def valid_report(report: object) -> bool:
    """Only metadata contract fields, never user-defined keys or raw identifiers."""
    if not isinstance(report, dict) or set(report) != ALLOWED_FIELDS:
        return False
    if any(type(report.get(field)) is not bool for field in BOOLEAN_FIELDS):
        return False
    if report["hardware_mutation_authorized"] is not False:
        return False
    if (any(not isinstance(report.get(field), str) or
            not 1 <= len(report[field]) <= MAX_TEXT or
            not re.fullmatch(r"[A-Z0-9_-]+", report[field])
            for field in STRING_FIELDS)):
        return False
    if report["status"] != "NO-GO" or report["mode"] != "HOST_DEPENDENCIES_METADATA_ONLY":
        return False
    tools = report["recovery_tools"]
    return (
        isinstance(tools, dict) and set(tools) == ALLOWED_TOOLS
        and all(value in ("INSTALLED_UNVERIFIED", "MISSING")
                for value in tools.values())
    )


def differing_fields(before: dict, after: dict) -> list[str]:
    """List only fixed, non-sensitive field identifiers; never print values."""
    return sorted(
        field for field in ALLOWED_FIELDS - {"recovery_tools"}
        if before[field] != after[field]
    ) + [
        "recovery_tools." + tool for tool in sorted(ALLOWED_TOOLS)
        if before["recovery_tools"][tool] != after["recovery_tools"][tool]
    ]


def compare(compose_path: Path, yubikey_path: Path) -> dict:
    """Both fixture groups are separately provided, never generated from live state."""
    old, new = read_fixtures(compose_path), read_fixtures(yubikey_path)
    result = {
        "schema": "nabla-yubikey/probe-fixture-comparison/v1",
        "mode": "OFFLINE_FIXTURE_COMPARISON",
        "read_only": True, "hardware_mutation_authorized": False,
        "runtime_parity_verified": False,
        "fixture_parity_verified": False,
        "blocking": [],
        "missing_cases": [], "extra_cases": [],
        "differing_cases": {},
    }
    if old is None or new is None:
        result.update(status="NO-GO", blocking=["FIXTURES_INVALID_OR_UNAVAILABLE"])
        return result

    result["missing_cases"] = sorted(set(old) - set(new))
    result["extra_cases"] = sorted(set(new) - set(old))
    for name in sorted(set(old) & set(new)):
        paths = []
        if old[name]["exit_code"] != new[name]["exit_code"]:
            paths.append("exit_code")
        if old[name]["report"] is None or new[name]["report"] is None:
            if old[name]["report"] != new[name]["report"]:
                paths.append("report_presence")
        else:
            paths.extend(differing_fields(old[name]["report"], new[name]["report"]))
        if paths:
            result["differing_cases"][name] = paths

    matched = not (result["missing_cases"] or result["extra_cases"] or
                   result["differing_cases"])
    result["fixture_parity_verified"] = matched
    result["status"] = "FIXTURES_MATCH" if matched else "NO-GO"
    if not matched:
        result["blocking"] = ["FIXTURE_PARITY_MISMATCH"]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-fixtures", type=Path, required=True)
    parser.add_argument("--yubikey-fixtures", type=Path, required=True)
    parser.add_argument("--assert-fixture-parity", action="store_true")
    args = parser.parse_args(argv)
    report = compare(args.compose_fixtures, args.yubikey_fixtures)
    print(json.dumps(report, sort_keys=True))
    return 2 if args.assert_fixture_parity and not report["fixture_parity_verified"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
