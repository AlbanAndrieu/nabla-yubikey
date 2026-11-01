#!/usr/bin/env python3
"""Optional supervised, public OpenPGP transport probe of the backup YubiKey.

--check is host-only. --probe may start scdaemon and query public card status;
never signs, decrypts, moves keys, asks PIN, or prints GPG card metadata.
"""
from __future__ import annotations
import os
import argparse
import json
import re
import shutil
import subprocess
import sys

SERIAL = os.environ.get("YUBIKEY_BACKUP_SERIAL", "11110002")
ACK = f'QUERY_OPENPGP_BACKUP_{SERIAL}'


def check() -> str:
    if not shutil.which('gpg') or not shutil.which('ykman'):
        return 'TOOLS_MISSING'
    return 'TOOLS_PRESENT_HARDWARE_NOT_CHECKED'



# All matching happens in memory. Never persist/print GnuPG stderr or card IDs.
APPLICATION_ID = re.compile(r"(?im)^Application ID\s*\.{2,}\s*:\s*D27600012401[0-9A-F]{12,52}\s*$")


def classify_card_reply(exit_code: int, stdout: str, stderr: str) -> str:
    """Only recognize strong public card evidence; bucket common failures."""
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return "OPENPGP_PROBE_UNCLASSIFIED"
    if len(stdout) > 32768 or len(stderr) > 32768 or "\x00" in (stdout + stderr):
        return "OPENPGP_PROBE_UNCLASSIFIED"
    if exit_code == 0 and not stderr.strip():
        if APPLICATION_ID.search(stdout):
            return "GPG_CARD_STATUS_RESPONDS_PUBLIC_ONLY_IDENTITY_UNVERIFIED"
        return "OPENPGP_CARD_STATUS_UNRECOGNIZED"
    diagnostic = stderr.lower()
    if re.search(r"resource busy|device busy|sharing violation|card is busy|card is being used|locked by", diagnostic):
        return "OPENPGP_READER_BUSY_UNVERIFIED"
    if re.search(r"scdaemon.*(unavailable|failed|connect|start)|can't connect to the agent|ipc connect call failed", diagnostic):
        return "OPENPGP_SCDAEMON_OR_AGENT_UNAVAILABLE"
    if re.search(r"no such device|no smartcard|no card|card not present|card has been removed|no readers? found", diagnostic):
        return "OPENPGP_DEVICE_NOT_AVAILABLE"
    if re.search(r"card error|reader error|selecting openpgp failed|selecting card failed", diagnostic):
        return "OPENPGP_CARD_OR_READER_ERROR"
    return "OPENPGP_TRANSPORT_NOT_CONFIRMED"


def probe(tty: bool) -> str:
    if check() != 'TOOLS_PRESENT_HARDWARE_NOT_CHECKED':
        return 'TOOLS_MISSING'
    if not tty:
        return 'INTERACTIVE_TERMINAL_REQUIRED'
    try:
        visible = subprocess.run(['ykman', 'list', '--serials'],
                                 stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, timeout=12, check=False)
        if visible.returncode or visible.stderr.strip() or visible.stdout.splitlines() != [SERIAL]:
            return 'EXPECTED_ONE_BACKUP_YUBIKEY'
        # May autostart scdaemon: intentionally NOT called from passive checks.
        result = subprocess.run(['gpg', '--batch', '--no-tty', '--card-status'],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=20, check=False)
        return classify_card_reply(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return 'OPENPGP_PROBE_TIMEOUT'
    except (OSError, UnicodeError, ValueError):
        return 'OPENPGP_TRANSPORT_NOT_CONFIRMED'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    opt = parser.add_mutually_exclusive_group(required=True)
    opt.add_argument('--check', action='store_true')
    opt.add_argument('--probe', action='store_true')
    parser.add_argument('--acknowledge')
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error('acknowledgment is only accepted for --probe')
    if args.probe and args.acknowledge != ACK:
        parser.error('explicit backup OpenPGP probe acknowledgment required')
    state = check() if args.check else probe(sys.stdin.isatty() and sys.stdout.isatty())
    print(json.dumps({'state': state, 'serial': SERIAL, 'status': 'NO-GO',
                      'card_private_key_tested': False,
                      'signature_verified': False,
                      'hardware_mutation_authorized': False}, sort_keys=True))
    return 0 if state in ('TOOLS_PRESENT_HARDWARE_NOT_CHECKED',
                           'GPG_CARD_STATUS_RESPONDS_PUBLIC_ONLY_IDENTITY_UNVERIFIED') else 3


if __name__ == '__main__':
    sys.exit(main())
