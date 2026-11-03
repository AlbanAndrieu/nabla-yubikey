#!/usr/bin/env python3
"""Probe an already-running GPG agent using public Assuan GETINFO only.

--no-autostart must remain present. Never accesses private keys, cards,
PINs, scdaemon or PostgreSQL backups. No diagnostic output is reproduced.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

CMD = ["gpg-connect-agent", "--no-autostart", "GETINFO version", "/bye"]
VERSION = re.compile(r"(?m)^D [0-9]+(?:\.[0-9]+){1,4}\s*$")
OK = re.compile(r"(?m)^OK(?: .*)?$")


def probe() -> str:
    if not shutil.which("gpg-connect-agent"):
        return "TOOL_MISSING"
    try:
        out = subprocess.run(
            CMD, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False, timeout=5,
        )
        if (out.returncode != 0 or out.stderr.strip()
                or len(out.stdout) > 4096 or "\0" in out.stdout):
            return "UNKNOWN"
        if VERSION.search(out.stdout) and OK.search(out.stdout):
            return "RESPONDS_GETINFO_ONLY"
        return "UNKNOWN"
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return "UNKNOWN"


def main() -> int:
    if len(sys.argv) != 1:
        print("No arguments supported", file=sys.stderr)
        return 2
    status = probe()
    print(json.dumps({
        "status": "NO-GO",
        "gpg_agent_protocol": status,
        "gpg_openpgp_card_verified": False,
        "gpg_sign_decrypt_verified": False,
        "postgres_restore_verified": False,
        "agent_started_by_probe": False,
        "hardware_mutation_authorized": False,
    }, sort_keys=True))
    return 0 if status == "RESPONDS_GETINFO_ONLY" else 3


if __name__ == "__main__":
    sys.exit(main())
