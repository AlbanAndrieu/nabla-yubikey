#!/usr/bin/env python3
"""Compare local NFS mount metadata with read-only TrueNAS server metadata.

Never opens an age archive, logs a private filename, accepts a new host key,
starts a service, writes data, or decrypts a secret. --probe uses SSH in
BatchMode with existing credentials only and runs a fixed Python snippet.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

LOCAL_SOURCE = Path.home() / '.local/share/nabla/age-backups'
LOCAL_BACKUP = Path('/media/backup/lab/secret')
MOUNT = '/media/backup/lab'
EXPORT = 'nabla:/mnt/cpool/backup/lab'
ACK = 'INSPECT_NFS_SERVER_METADATA_ONLY'
MAX_OUTPUT = 4096
MAX_ENTRIES = 256

REMOTE_PROBE = '''import json, os, stat
from pathlib import Path
root = Path('/mnt/cpool/backup/lab/secret')
name = EXPECTED_NAME
state = 'UNKNOWN'
count = 0
try:
    if any(x.is_symlink() for x in (root, *root.parents)):
        state = 'SERVER_DIRECTORY_SYMLINK_UNTRUSTED'
    else:
        with os.scandir(root) as entries:
            for n, entry in enumerate(entries):
                if n >= 256:
                    state = 'SERVER_DIRECTORY_TOO_MANY_ENTRIES'
                    break
                if entry.name.endswith('.age') and entry.is_file(follow_symlinks=False):
                    count += 1
            else:
                try:
                    info = (root / name).lstat()
                    if stat.S_ISLNK(info.st_mode):
                        state = 'SERVER_EXPECTED_COPY_SYMLINK'
                    elif not stat.S_ISREG(info.st_mode):
                        state = 'SERVER_EXPECTED_COPY_NOT_REGULAR'
                    elif info.st_size < 1:
                        state = 'SERVER_EXPECTED_COPY_EMPTY'
                    else:
                        state = 'SERVER_EXPECTED_COPY_REGULAR_NONEMPTY'
                except FileNotFoundError:
                    state = 'SERVER_EXPECTED_COPY_MISSING'
                except PermissionError:
                    state = 'SERVER_EXPECTED_COPY_ACCESS_DENIED'
                except OSError:
                    state = 'SERVER_EXPECTED_COPY_UNVERIFIED'
except FileNotFoundError:
    state = 'SERVER_DIRECTORY_MISSING'
except PermissionError:
    state = 'SERVER_DIRECTORY_ACCESS_DENIED'
except OSError:
    state = 'SERVER_DIRECTORY_UNVERIFIED'
print(json.dumps({'state': state, 'age_files': count}, sort_keys=True))
'''
ALLOWED_STATES = {
    'SERVER_DIRECTORY_SYMLINK_UNTRUSTED', 'SERVER_DIRECTORY_TOO_MANY_ENTRIES',
    'SERVER_EXPECTED_COPY_SYMLINK', 'SERVER_EXPECTED_COPY_NOT_REGULAR',
    'SERVER_EXPECTED_COPY_EMPTY', 'SERVER_EXPECTED_COPY_REGULAR_NONEMPTY',
    'SERVER_EXPECTED_COPY_MISSING', 'SERVER_EXPECTED_COPY_ACCESS_DENIED',
    'SERVER_EXPECTED_COPY_UNVERIFIED', 'SERVER_DIRECTORY_MISSING',
    'SERVER_DIRECTORY_ACCESS_DENIED', 'SERVER_DIRECTORY_UNVERIFIED',
}


def local_expected_filename(directory: Path) -> tuple[str, str | None]:
    try:
        if any(x.is_symlink() for x in (directory, *directory.parents)):
            return 'SOURCE_DIRECTORY_SYMLINK_UNTRUSTED', None
        candidates: list[str] = []
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_ENTRIES:
                    return 'SOURCE_TOO_MANY_ENTRIES', None
                if entry.name.endswith('.age') and entry.is_file(follow_symlinks=False):
                    candidates.append(entry.name)
        if len(candidates) != 1:
            return 'SOURCE_FILENAME_NOT_UNIQUE', None
        name = candidates[0]
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}\.age', name):
            return 'SOURCE_FILENAME_UNSAFE', None
        return 'SOURCE_UNIQUE_AGE_FOUND', name
    except (OSError, ValueError, UnicodeError):
        return 'SOURCE_UNAVAILABLE', None


def check_mount() -> str:
    try:
        proc = subprocess.run(
            ['findmnt', '-n', '-T', str(LOCAL_BACKUP), '-o', 'TARGET,FSTYPE,SOURCE'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=5, check=False,
        )
        if proc.returncode or len(proc.stdout) > MAX_OUTPUT:
            return 'MOUNT_UNVERIFIED'
        parts = proc.stdout.strip().splitlines()
        if len(parts) != 1:
            return 'MOUNT_UNVERIFIED'
        fields = parts[0].split()
        if len(fields) != 3:
            return 'MOUNT_UNVERIFIED'
        target, fs, source = fields
        if target != MOUNT or fs not in ('nfs', 'nfs4'):
            return 'UNEXPECTED_MOUNT'
        if source != EXPORT:
            return 'UNEXPECTED_NFS_EXPORT'
        return 'EXPECTED_NFS_EXPORT_MOUNTED'
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return 'MOUNT_UNVERIFIED'


def query_server(ssh_target: str, basename: str) -> tuple[str, int | None]:
    if not re.fullmatch(r'[a-zA-Z_][a-zA-Z_0-9-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.:-]{0,200}', ssh_target):
        return 'INVALID_SSH_TARGET', None
    program = 'EXPECTED_NAME = ' + json.dumps(basename) + '\n' + REMOTE_PROBE
    command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'NumberOfPasswordPrompts=0', '-o', 'ConnectTimeout=5',
               '-o', 'ClearAllForwardings=yes', '--', ssh_target, 'python3', '-']
    try:
        proc = subprocess.run(command, input=program, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=18, check=False)
        if proc.returncode or len(proc.stdout) > MAX_OUTPUT:
            return 'SSH_READONLY_PROBE_UNAVAILABLE', None
        try:
            parsed = json.loads(proc.stdout)
        except (ValueError, UnicodeError):
            return 'SSH_READONLY_PROBE_UNVERIFIED', None
        if (not isinstance(parsed, dict) or set(parsed) != {'state', 'age_files'}
                or parsed.get('state') not in ALLOWED_STATES
                or type(parsed.get('age_files')) is not int
                or not 0 <= parsed['age_files'] <= MAX_ENTRIES):
            return 'SSH_READONLY_PROBE_UNVERIFIED', None
        return parsed['state'], parsed['age_files']
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return 'SSH_READONLY_PROBE_UNAVAILABLE', None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--probe', action='store_true')
    parser.add_argument('--ssh-target')
    parser.add_argument('--acknowledge')
    args = parser.parse_args(argv)
    if args.check and (args.ssh_target or args.acknowledge):
        parser.error('--check takes no remote arguments')
    if args.probe and (not args.ssh_target or args.acknowledge != ACK):
        parser.error('--probe needs a target and exact acknowledgement')
    mount_state = check_mount()
    source_state, filename = local_expected_filename(LOCAL_SOURCE)
    server_state = 'NOT_PROBED'
    count = None
    if args.probe and mount_state == 'EXPECTED_NFS_EXPORT_MOUNTED' and filename:
        server_state, count = query_server(args.ssh_target, filename)
    print(json.dumps({
        'mode': 'YUBIKEY_AGE_ESCROW_NFS_SERVER_METADATA_ONLY',
        'status': 'NO-GO', 'mount_state': mount_state,
        'source_state': source_state, 'server_state': server_state,
        'server_age_files': count,
        'paths_disclosed': False, 'archive_opened': False,
        'remote_write_performed': False, 'decryption_attempted': False,
        'restoration_verified': False, 'hardware_mutation_authorized': False,
    }, sort_keys=True))
    if args.check:
        return 0 if mount_state == 'EXPECTED_NFS_EXPORT_MOUNTED' and filename else 3
    return 0 if server_state in ('SERVER_EXPECTED_COPY_REGULAR_NONEMPTY',
                                 'SERVER_EXPECTED_COPY_MISSING') else 3


if __name__ == '__main__':
    sys.exit(main())
