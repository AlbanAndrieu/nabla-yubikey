#!/usr/bin/env python3
"""Create a new, encrypted .age backup copy on expected NFS; never overwrite.

--check checks mount and file metadata only. --copy (TTY + acknowledgment)
reads ciphertext, stages a mode-0600 temporary file on NFS, fsyncs, compares,
atomically publishes via hard link (no replace), then verifies the final copy.
No private identity is decrypted, no keys are exported or generated.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import sys

HERE = Path(__file__).resolve().parent
ACK = 'CREATE_NEW_ENCRYPTED_AGE_ESCROW_NFS_COPY'
TARGET = Path('/media/backup/lab/secret')
MAX_BYTES = 16 * 1024 * 1024
CHUNK = 64 * 1024


def load(name: str):
    spec = importlib.util.spec_from_file_location('nabla_escrow_helper', HERE / name)
    if spec is None or spec.loader is None:
        raise ImportError('helper unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight():
    """No archive content read; protect against symlink parents and destinations."""
    try:
        base = load('inspect-yubikey-escrow-nfs-server.py')
        if base.check_mount() != 'EXPECTED_NFS_EXPORT_MOUNTED':
            return 'UNEXPECTED_NFS_EXPORT', None
        state, filename = base.local_expected_filename(base.LOCAL_SOURCE)
        if state != 'SOURCE_UNIQUE_AGE_FOUND' or not filename:
            return state, None
        src = base.LOCAL_SOURCE / filename
        if any(d.is_symlink() for d in (src.parent, *src.parent.parents,
                                         TARGET, *TARGET.parents)):
            return 'UNTRUSTED_DIRECTORY_SYMLINK', None
        if not stat.S_ISDIR(TARGET.lstat().st_mode):
            return 'TARGET_NOT_DIRECTORY', None
        info = src.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or not 0 < info.st_size <= MAX_BYTES):
            return 'SOURCE_METADATA_UNTRUSTED', None
        dst = TARGET / filename
        try:
            dst.lstat()
            return 'TARGET_ALREADY_EXISTS_NO_OVERWRITE', None
        except FileNotFoundError:
            return 'READY_TO_CREATE_ENCRYPTED_COPY', (src, filename)
    except (OSError, ImportError, ValueError, AttributeError, TypeError):
        return 'ESCROW_PREFLIGHT_UNVERIFIED', None


def unchanged(fd: int, original: os.stat_result) -> bool:
    current = os.fstat(fd)
    return (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
            current.st_ctime_ns) == (original.st_dev, original.st_ino,
                                      original.st_size, original.st_mtime_ns,
                                      original.st_ctime_ns)


def create_encrypted_copy(source: Path, name: str) -> str:
    """Transactional no-clobber publish; leave a suspicious published file untouched."""
    source_fd = dest_fd = stage_fd = None
    stage_name = '.nabla-escrow-stage-' + secrets.token_hex(16)
    stage_created = False
    durability = True
    try:
        # Use existing strict regular-file/owner/mode checks and O_NOFOLLOW.
        cmp = load('compare-yubikey-escrow-pair-readonly.py')
        source_fd, srcstat = cmp.secure_open(source)
        if not 0 < srcstat.st_size <= MAX_BYTES:
            return 'SOURCE_METADATA_UNTRUSTED'
        dest_fd = os.open(TARGET, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        deststat = os.fstat(dest_fd)
        if not stat.S_ISDIR(deststat.st_mode) or deststat.st_dev == srcstat.st_dev:
            return 'TARGET_NOT_DISTINCT_FILESYSTEM'
        # Check mount again shortly before writing; avoids blind writes under /.
        base = load('inspect-yubikey-escrow-nfs-server.py')
        if base.check_mount() != 'EXPECTED_NFS_EXPORT_MOUNTED':
            return 'NFS_MOUNT_CHANGED'
        try:
            os.stat(name, dir_fd=dest_fd, follow_symlinks=False)
            return 'TARGET_ALREADY_EXISTS_NO_OVERWRITE'
        except FileNotFoundError:
            pass
        stage_fd = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dest_fd)
        stage_created = True
        # Normalize inherited POSIX permissions before writing any ciphertext.
        # This does not independently attest NFSv4 ACL entries.
        os.fchmod(stage_fd, 0o600)
        initially = os.fstat(stage_fd)
        if (not stat.S_ISREG(initially.st_mode)
                or stat.S_IMODE(initially.st_mode) != 0o600
                or initially.st_uid != os.getuid()
                or initially.st_nlink != 1 or initially.st_size != 0):
            return 'STAGE_PERMISSIONS_OR_SIZE_UNVERIFIED'
        remaining = srcstat.st_size
        while remaining:
            block = os.read(source_fd, min(CHUNK, remaining))
            if not block:
                return 'SOURCE_CHANGED_DURING_COPY'
            remaining -= len(block)
            view = memoryview(block)
            while view:
                wrote = os.write(stage_fd, view)
                if wrote <= 0:
                    return 'STAGE_WRITE_FAILED'
                view = view[wrote:]
        if not unchanged(source_fd, srcstat):
            return 'SOURCE_CHANGED_DURING_COPY'
        # NFSv4 may inherit ACLs. Normalize the POSIX mode explicitly,
        # and refuse publication when the staging file does not remain 0600.
        os.fchmod(stage_fd, 0o600)
        staged = os.fstat(stage_fd)
        if (not stat.S_ISREG(staged.st_mode)
                or stat.S_IMODE(staged.st_mode) != 0o600
                or staged.st_uid != os.getuid()
                or staged.st_nlink != 1
                or staged.st_size != srcstat.st_size):
            return 'STAGE_PERMISSIONS_OR_SIZE_UNVERIFIED'
        os.fsync(stage_fd)
        os.close(stage_fd)
        stage_fd = None
        # Stage and final filename are resolved relative to the same open NFS dir.
        os.link(stage_name, name, src_dir_fd=dest_fd,
                dst_dir_fd=dest_fd, follow_symlinks=False)
        # Remove staging hardlink, leaving the sole published encrypted copy.
        os.unlink(stage_name, dir_fd=dest_fd)
        stage_created = False
        try:
            os.fsync(dest_fd)
        except OSError:
            durability = False
        # Even a successful publish is not recovery until readback is proven.
        result = cmp.compare_ciphertexts(source, TARGET / name)
        if result != 'ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED':
            return 'PUBLISHED_COPY_VERIFICATION_FAILED'
        if not durability:
            return 'PUBLISHED_COPY_DIRECTORY_SYNC_UNVERIFIED'
        return 'ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED'
    except FileExistsError:
        return 'TARGET_ALREADY_EXISTS_NO_OVERWRITE'
    except (OSError, ValueError, AttributeError, ImportError, TypeError):
        return 'COPY_UNVERIFIED_NO_RETRY'
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if stage_created and dest_fd is not None:
            try:
                os.unlink(stage_name, dir_fd=dest_fd)
            except OSError:
                pass  # No secret/path in JSON; manual inspection may be required.
        if source_fd is not None:
            os.close(source_fd)
        if dest_fd is not None:
            os.close(dest_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--copy', action='store_true')
    parser.add_argument('--acknowledge')
    args = parser.parse_args(argv)
    if args.check and args.acknowledge:
        parser.error('--check must not have acknowledgment')
    if args.copy and args.acknowledge != ACK:
        parser.error('explicit no-overwrite ciphertext-copy approval required')
    if args.copy and not (sys.stdin.isatty() and sys.stdout.isatty()):
        state = 'INTERACTIVE_TTY_REQUIRED'
    else:
        state, pair = preflight()
        if args.copy and pair is not None:
            state = create_encrypted_copy(*pair)
    print(json.dumps({
        'mode': 'ENCRYPTED_AGE_ESCROW_NFS_BACKUP_COPY',
        'state': state, 'status': 'NO-GO',
        'new_copy_verified': state == 'ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED',
        'source_decryption_performed': False, 'independent_age_identity_verified': False,
        'restore_verified': False, 'hardware_mutation_authorized': False,
        'sops_configuration_changed': False, 'existing_destination_overwritten': False,
        'paths_disclosed': False, 'secret_content_disclosed': False,
    }, sort_keys=True))
    return 0 if state in ('READY_TO_CREATE_ENCRYPTED_COPY',
                         'ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED') else 3


if __name__ == '__main__':
    sys.exit(main())
