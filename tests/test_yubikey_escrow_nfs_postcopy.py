"""Hermetic contracts for existing age escrow postcopy verification."""
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/workstation/verify-yubikey-escrow-nfs-postcopy.py'
spec = importlib.util.spec_from_file_location('nabla_escrow_postcopy', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.src=self.root/'source';self.dst=self.root/'backup'
        self.src.mkdir();self.dst.mkdir()
        self.name='synthetic-escrow.age'
        for p in (self.src/self.name,self.dst/self.name):
            p.write_bytes(b'encrypted fixture only')
            p.chmod(0o600)

    def modules(self, mount='EXPECTED_NFS_EXPORT_MOUNTED', pair='TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED'):
        server=SimpleNamespace(check_mount=lambda:mount,
                               local_expected_filename=lambda root:('SOURCE_UNIQUE_AGE_FOUND',self.name),
                               LOCAL_SOURCE=self.src)
        locator=SimpleNamespace(discover_pair=lambda home:(pair,(self.src/self.name,self.dst/self.name)
                                     if pair=='TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED' else None))
        def resolver(name):
            if name.startswith('inspect-yubikey-escrow-nfs-server'):
                return server
            if name.startswith('inspect-yubikey-escrow-pair'):
                return locator
            raise AssertionError(name)
        return resolver

    def test_metadata_only_inspects_file_modes_without_reading(self):
        with patch.object(m,'load',side_effect=self.modules()), \
             patch.object(Path,'read_bytes') as reader:
            state,paths,mode_ok,filename=m.inspect_pair()
        self.assertEqual(state,'PAIR_METADATA_READY_ACL_UNVERIFIED')
        self.assertTrue(mode_ok)
        self.assertEqual(filename,self.name)
        self.assertEqual(paths,(self.src/self.name,self.dst/self.name))
        reader.assert_not_called()

    def test_unexpected_export_blocks_metadata_pair(self):
        with patch.object(m,'load',side_effect=self.modules(mount='UNEXPECTED_NFS_EXPORT')):
            state,paths,ok,_=m.inspect_pair()
        self.assertEqual(state,'UNEXPECTED_NFS_EXPORT')
        self.assertIsNone(paths)
        self.assertFalse(ok)

    def test_unmatched_pair_does_not_claim_integrity(self):
        with patch.object(m,'load',side_effect=self.modules(pair='DISCOVERY_NO_MATCHING_PAIR')):
            state,paths,ok,_=m.inspect_pair()
        self.assertEqual(state,'ESCROW_PAIR_METADATA_UNVERIFIED')
        self.assertIsNone(paths)
        self.assertFalse(ok)

    def test_group_readable_backup_rejected(self):
        (self.dst/self.name).chmod(0o640)
        with patch.object(m,'load',side_effect=self.modules()):
            state,paths,ok,_=m.inspect_pair()
        self.assertEqual(state,'ESCROW_POSIX_METADATA_UNVERIFIED')
        self.assertIsNone(paths)
        self.assertFalse(ok)

    def test_check_does_not_trigger_ssh_or_ciphertext_read(self):
        pair=(self.src/self.name,self.dst/self.name)
        with patch.object(m,'inspect_pair',return_value=('PAIR_METADATA_READY_ACL_UNVERIFIED',pair,True,self.name)), \
             patch.object(m,'verify_pair') as verify, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--check']),0)
        verify.assert_not_called()
        record=json.loads(out.getvalue())
        self.assertFalse(record['ciphertext_readback_attempted'])
        self.assertIsNone(record['ciphertext_identical'])
        self.assertFalse(record['nfs4_acl_verified'])
        self.assertFalse(record['restore_verified'])
        self.assertEqual(record['status'],'NO-GO')

    def test_verify_requires_exact_acknowledgment(self):
        with patch.object(m,'verify_pair') as verify,redirect_stderr(io.StringIO()):
            for args in ([],['--verify'],['--verify','--acknowledge','wrong'],
                         ['--check','--acknowledge',m.ACK]):
                with self.subTest(args=args),self.assertRaises(SystemExit) as e:
                    m.main(args)
                self.assertEqual(e.exception.code,2)
        verify.assert_not_called()

    def test_positive_recheck_stays_no_go_due_to_acl_and_restore(self):
        pair=(self.src/self.name,self.dst/self.name)
        with patch.object(m,'inspect_pair',return_value=('PAIR_METADATA_READY_ACL_UNVERIFIED',pair,True,self.name)), \
             patch.object(m,'verify_pair',return_value=('ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED',
                                         'SERVER_EXPECTED_COPY_REGULAR_NONEMPTY')), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--verify','--acknowledge',m.ACK]),0)
        payload=json.loads(out.getvalue())
        self.assertEqual(payload['state'],'POSTCOPY_CIPHERTEXT_AND_SERVER_VISIBLE_ACL_UNVERIFIED')
        self.assertTrue(payload['ciphertext_identical'])
        self.assertTrue(payload['server_visibility_verified'])
        self.assertFalse(payload['nfs4_acl_verified'])
        self.assertFalse(payload['restore_verified'])
        self.assertNotIn(str(self.root),out.getvalue())
        self.assertNotIn(self.name,out.getvalue())

    def test_missing_true_nas_file_fails_and_does_not_repair(self):
        pair=(self.src/self.name,self.dst/self.name)
        with patch.object(m,'inspect_pair',return_value=('PAIR_METADATA_READY_ACL_UNVERIFIED',pair,True,self.name)), \
             patch.object(m,'verify_pair',return_value=('ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED',
                                         'SERVER_EXPECTED_COPY_MISSING')), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--verify','--acknowledge',m.ACK]),3)
        payload=json.loads(out.getvalue())
        self.assertEqual(payload['state'],'POSTCOPY_RECHECK_INCOMPLETE')
        self.assertFalse(payload['server_visibility_verified'])
        self.assertFalse(payload['remote_write_performed'])

    def test_changed_ciphertext_skips_server_probe(self):
        pair=(self.src/self.name,self.dst/self.name)
        comparator=SimpleNamespace(compare_ciphertexts=lambda a,b:'ENCRYPTED_COPIES_DIFFER')
        def modules(name):
            if name.startswith('compare-yubikey'):
                return comparator
            raise AssertionError('unexpected remote probe')
        with patch.object(m,'load',side_effect=modules):
            self.assertEqual(m.verify_pair(pair,self.name),('ENCRYPTED_COPIES_DIFFER','NOT_PROBED'))

    def test_verify_success_requires_positive_server_state(self):
        pair=(self.src/self.name,self.dst/self.name)
        comparator=SimpleNamespace(compare_ciphertexts=lambda a,b:'ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED')
        server=SimpleNamespace(query_server=lambda target,filename:('SERVER_EXPECTED_COPY_REGULAR_NONEMPTY',1))
        with patch.object(m,'load',side_effect=lambda name:comparator if name.startswith('compare-') else server):
            self.assertEqual(m.verify_pair(pair,self.name),('ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED',
                                                              'SERVER_EXPECTED_COPY_REGULAR_NONEMPTY'))

if __name__ == '__main__':
    unittest.main()
