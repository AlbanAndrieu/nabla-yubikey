#!/usr/bin/env python3
"""Run independent YubiKey readiness gates concurrently; hardware reads last.

Local-only, no account credentials, no key operations and no configuration.
Never parallelize device access: at most one secondary public inventory.
The summary always stays NO-GO regardless of successful subprocess exits.
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
SECONDARY = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
TIMEOUT_SECONDS = 150
# Each 'just' target contains synthetic tests only, without hardware access.
TEST_JOBS = {
    "recovery": ("just", "yubikey-recovery-test"),
    "applications": ("just", "yubikey-applications-test"),
    "workstation": ("just", "yubikey-workstation-test"),
    "coordinator": ("just", "yubikey-diagnostics-test"),
    "gpg_agent": ("just", "yubikey-gpg-agent-test"),
    "dependencies": ("just", "yubikey-dependencies-test"),
}
HOST_JOBS = {
    "workstation": (sys.executable, "scripts/workstation/inspect-yubikey-workstation-readonly.py"),
    "gpg_agent": (sys.executable, "scripts/workstation/inspect-gpg-agent-readonly.py"),
    "dependencies": (sys.executable, "scripts/workstation/inspect-yubikey-dependencies-readonly.py"),
}
HARDWARE_JOB = (
    sys.executable, "scripts/workstation/diagnose-yubikey-readonly-batch.py",
    "--hardware", "--serial", SECONDARY, "--gpg-agent-probe",
)


def run_job(name: str, cmd: tuple[str, ...], *, read_json: bool = False) -> dict:
    """Return only a classified result, never subprocess output or secrets."""
    try:
        result = subprocess.run(
            cmd, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=TIMEOUT_SECONDS, check=False,
        )
        if result.returncode != 0:
            return {"job": name, "state": "FAILED"}
        if not read_json:
            return {"job": name, "state": "PASS"}
        if len(result.stdout) > 65536 or "\0" in result.stdout:
            return {"job": name, "state": "UNKNOWN"}
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or payload.get("status") != "NO-GO" or (
            payload.get("hardware_mutation_authorized") is not False
        ):
            return {"job": name, "state": "UNKNOWN"}
        if name == "hardware":
            device = payload.get("device")
            if not isinstance(device, dict) or (
                device.get("serial") != SECONDARY
                or payload.get("pin_requested") is not False
                or payload.get("otp_challenge_executed") is not False
                or payload.get("decrypt_executed") is not False
            ):
                return {"job": name, "state": "UNKNOWN"}
        return {"job": name, "state": "PASS"}
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return {"job": name, "state": "UNKNOWN"}


def parallel(jobs: dict[str, tuple[str, ...]], *, read_json: bool = False) -> dict:
    """No job in either collection addresses the YubiKey hardware."""
    outcomes = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {pool.submit(run_job, name, cmd, read_json=read_json): name
                   for name, cmd in jobs.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                outcomes[name] = future.result()["state"]
            except Exception:
                outcomes[name] = "UNKNOWN"
    return {name: outcomes.get(name, "UNKNOWN") for name in jobs}


def execute(secondary: bool) -> tuple[dict, int]:
    report = {
        "status": "NO-GO",
        "mode": "PARALLEL_READ_ONLY",
        "secondary_hardware_requested": secondary,
        "serial": SECONDARY if secondary else "NOT_CHECKED",
        "hardware_mutation_authorized": False,
        "tests": {},
        "host": {},
        "hardware": "NOT_CHECKED",
        "recovery": "NOT_VERIFIED",
        "configuration": "NOT_AUTHORIZED",
    }
    report["tests"] = parallel(TEST_JOBS)
    if any(report["tests"].get(name) != "PASS" for name in TEST_JOBS):
        return report, 3

    report["host"] = parallel(HOST_JOBS, read_json=True)
    if any(report["host"].get(name) != "PASS" for name in HOST_JOBS):
        return report, 3

    # Deliberately serial: only after all non-hardware checks have completed.
    if secondary:
        report["hardware"] = run_job("hardware", HARDWARE_JOB, read_json=True)["state"]
        if report["hardware"] != "PASS":
            return report, 3
    return report, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secondary", action="store_true",
                        help="Opt-in: single secondary public device inventory after all gates")
    args = parser.parse_args(argv)
    report, code = execute(args.secondary)
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
