"""Hermetic no-clobber encrypted NFS backup copy contracts (no actual NFS)."""
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1]/'scripts/workstation/create-yubikey-escrow-nfs-copy.py'
spec = importlib.util.spec_from_file_location('escrow_nfs_copy', SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source=self.root/'source';self.source.mkdir()
        self.target=self.root/'nfs';self.target.mkdir()
        self.file=self.source/'private.age'
        self.file.write_bytes(b'Only synthetic encrypted fixture\n'*3)
        self.file.chmod(0o600)
        self.base=SimpleNamespace(check_mount=lambda:'EXPECTED_NFS_EXPORT_MOUNTED',
                local_expected_filename=lambda p:('SOURCE_UNIQUE_AGE_FOUND','private.age'),
                LOCAL_SOURCE=self.source)
        def secure(path):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            return fd,os.fstat(fd)
        def compare(a,b):
            return ('ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED'
                    if a.read_bytes()==b.read_bytes() else 'ENCRYPTED_COPIES_DIFFER')
        self.comp=SimpleNamespace(secure_open=secure,compare_ciphertexts=compare)
        self.module_loader=lambda name: self.base if name.startswith('inspect-') else self.comp

    def test_ready_preflight_checks_metadata_without_opening_archives(self):
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader),\
             patch.object(Path,'read_bytes') as read:
            state,pair=m.preflight()
        self.assertEqual(state,'READY_TO_CREATE_ENCRYPTED_COPY')
        self.assertEqual(pair,(self.file,'private.age'))
        read.assert_not_called()

    def test_already_existing_file_must_not_be_overwritten(self):
        existing=self.target/'private.age';existing.write_bytes(b'KEEP ORIGINAL')
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader):
            state,pair=m.preflight()
        self.assertEqual(state,'TARGET_ALREADY_EXISTS_NO_OVERWRITE')
        self.assertIsNone(pair)
        self.assertEqual(existing.read_bytes(),b'KEEP ORIGINAL')

    def test_symlink_destination_is_rejected_without_following(self):
        link=self.target/'private.age'; link.symlink_to(self.file)
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader):
            state,pair=m.preflight()
        self.assertEqual(state,'TARGET_ALREADY_EXISTS_NO_OVERWRITE')
        self.assertIsNone(pair)
        self.assertEqual(self.file.read_bytes(),b'Only synthetic encrypted fixture\n'*3)

    def test_copy_publishes_atomically_and_verifies_ciphertext(self):
        real_fstat=os.fstat
        target_stat=self.target.stat()
        def distinct_dev(fd):
            st=real_fstat(fd)
            if (st.st_ino==target_stat.st_ino and stat.S_ISDIR(st.st_mode)):
                return SimpleNamespace(st_mode=st.st_mode,st_dev=st.st_dev+1)
            return st
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader), \
             patch.object(m.os,'fstat',side_effect=distinct_dev):
            result=m.create_encrypted_copy(self.file,'private.age')
        self.assertEqual(result,'ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED')
        copied=self.target/'private.age'
        self.assertEqual(copied.read_bytes(),self.file.read_bytes())
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o600)
        self.assertEqual(copied.stat().st_nlink,1)
        self.assertEqual(list(self.target.iterdir()),[copied])

    def test_fchmod_failure_blocks_publication_and_cleans_stage(self):
        real_fstat=os.fstat
        target_stat=self.target.stat()
        def distinct_dev(fd):
            st=real_fstat(fd)
            if st.st_ino==target_stat.st_ino and stat.S_ISDIR(st.st_mode):
                return SimpleNamespace(st_mode=st.st_mode,st_dev=st.st_dev+1)
            return st
        with patch.object(m,'TARGET',self.target), \
             patch.object(m,'load',side_effect=self.module_loader), \
             patch.object(m.os,'fstat',side_effect=distinct_dev), \
             patch.object(m.os,'fchmod',side_effect=PermissionError):
            state=m.create_encrypted_copy(self.file,'private.age')
        self.assertEqual(state,'COPY_UNVERIFIED_NO_RETRY')
        self.assertEqual(list(self.target.iterdir()),[])
        self.assertEqual(self.file.read_bytes(),b'Only synthetic encrypted fixture\n'*3)

    def test_stage_mode_mismatch_fails_before_publishing(self):
        real_fstat=os.fstat
        calls=0
        def bad_stage_mode(fd):
            nonlocal calls
            calls += 1
            st=real_fstat(fd)
            if calls==2:  # Opened target directory: simulate a distinct FS.
                return SimpleNamespace(st_mode=st.st_mode,st_dev=st.st_dev+1)
            if calls==3:  # Opened staging file after fchmod.
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o640,
                                       st_uid=st.st_uid,st_nlink=st.st_nlink,
                                       st_size=st.st_size)
            return st
        with patch.object(m,'TARGET',self.target), \
             patch.object(m,'load',side_effect=self.module_loader), \
             patch.object(m.os,'fstat',side_effect=bad_stage_mode):
            state=m.create_encrypted_copy(self.file,'private.age')
        self.assertEqual(state,'STAGE_PERMISSIONS_OR_SIZE_UNVERIFIED')
        self.assertFalse((self.target/'private.age').exists())
        self.assertEqual(list(self.target.iterdir()),[])

    def test_stage_mode_is_normalized_before_any_ciphertext_write(self):
        events=[]
        real_fstat=os.fstat
        real_fchmod=os.fchmod
        real_write=os.write
        target_stat=self.target.stat()
        def distinct_dev(fd):
            st=real_fstat(fd)
            if st.st_ino==target_stat.st_ino and stat.S_ISDIR(st.st_mode):
                return SimpleNamespace(st_mode=st.st_mode,st_dev=st.st_dev+1)
            return st
        def recorded_chmod(fd,mode):
            events.append(('chmod',mode))
            return real_fchmod(fd,mode)
        def recorded_write(fd,data):
            events.append(('write',len(data)))
            return real_write(fd,data)
        with patch.object(m,'TARGET',self.target), \
             patch.object(m,'load',side_effect=self.module_loader), \
             patch.object(m.os,'fstat',side_effect=distinct_dev), \
             patch.object(m.os,'fchmod',side_effect=recorded_chmod), \
             patch.object(m.os,'write',side_effect=recorded_write):
            state=m.create_encrypted_copy(self.file,'private.age')
        self.assertEqual(state,'ENCRYPTED_COPY_CREATED_BYTE_VERIFIED_RESTORE_UNVERIFIED')
        self.assertEqual(events[0],('chmod',0o600))
        self.assertTrue(any(kind=='write' for kind,_ in events))
        self.assertGreaterEqual(sum(kind=='chmod' for kind,_ in events),2)
        self.assertEqual((self.target/'private.age').read_bytes(),self.file.read_bytes())

    def test_same_filesystem_blocks_creation(self):
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader):
            result=m.create_encrypted_copy(self.file,'private.age')
        self.assertEqual(result,'TARGET_NOT_DISTINCT_FILESYSTEM')
        self.assertFalse((self.target/'private.age').exists())

    def test_rename_free_hardlink_refuses_race_when_dest_appears(self):
        real_fstat=os.fstat
        target_stat=self.target.stat()
        def distinct_dev(fd):
            st=real_fstat(fd)
            if st.st_ino==target_stat.st_ino and stat.S_ISDIR(st.st_mode):
                return SimpleNamespace(st_mode=st.st_mode,st_dev=st.st_dev+1)
            return st
        def race_link(*args,**kwargs):
            (self.target/'private.age').write_bytes(b'UNTOUCHED RACE WINNER')
            raise FileExistsError()
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader), \
             patch.object(m.os,'fstat',side_effect=distinct_dev),patch.object(m.os,'link',side_effect=race_link):
            state=m.create_encrypted_copy(self.file,'private.age')
        self.assertEqual(state,'TARGET_ALREADY_EXISTS_NO_OVERWRITE')
        self.assertEqual((self.target/'private.age').read_bytes(),b'UNTOUCHED RACE WINNER')
        self.assertEqual(list(self.target.iterdir()),[self.target/'private.age'])

    def test_bad_mount_does_not_open_source_or_copy(self):
        self.base.check_mount=lambda:'UNEXPECTED_NFS_EXPORT'
        with patch.object(m,'TARGET',self.target),patch.object(m,'load',side_effect=self.module_loader):
            state,pair=m.preflight()
        self.assertEqual(state,'UNEXPECTED_NFS_EXPORT')
        self.assertIsNone(pair)

    def test_main_cli_requires_authorization_and_tty(self):
        with redirect_stderr(io.StringIO()),patch.object(m,'create_encrypted_copy') as write:
            for args in ([],['--copy'],['--copy','--acknowledge','NO'],
                         ['--check','--acknowledge',m.ACK]):
                with self.assertRaises(SystemExit) as error:
                    m.main(args)
                self.assertEqual(error.exception.code,2)
            write.assert_not_called()
        with patch.object(m.sys.stdin,'isatty',return_value=False),\
             patch.object(m,'preflight') as pre,redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(['--copy','--acknowledge',m.ACK]),3)
        pre.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['state'],'INTERACTIVE_TTY_REQUIRED')

    def test_output_never_claims_restore_or_discloses_paths(self):
        with patch.object(m,'preflight',return_value=('READY_TO_CREATE_ENCRYPTED_COPY',(self.file,'private.age'))),\
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(['--check']),0)
        record=json.loads(output.getvalue())
        self.assertEqual(record['status'],'NO-GO')
        self.assertFalse(record['restore_verified'])
        self.assertFalse(record['sops_configuration_changed'])
        self.assertNotIn(str(self.file),output.getvalue())
        self.assertNotIn('private.age',output.getvalue())

if __name__=='__main__':
    unittest.main()
