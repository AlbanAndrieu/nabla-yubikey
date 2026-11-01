"""Hermetic contracts for bounded, metadata-only age escrow snapshot scan."""
from __future__ import annotations
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/workstation/inspect-yubikey-escrow-nfs-history.py'
spec = importlib.util.spec_from_file_location('nabla_age_history', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Contracts(unittest.TestCase):
    def test_check_never_contacts_ssh(self):
        base = SimpleNamespace(check_mount=lambda:'EXPECTED_NFS_EXPORT_MOUNTED',
                local_expected_filename=lambda path:('SOURCE_UNIQUE_AGE_FOUND','private.age'),
                LOCAL_SOURCE=Path('/a'))
        with patch.object(m, 'load_base',return_value=base), patch.object(m,'query_history') as probe, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--check']),0)
        probe.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())['state'],'NOT_PROBED')

    def test_probing_requires_explicit_authorization(self):
        with patch.object(m,'query_history') as query, redirect_stderr(io.StringIO()):
            for args in ([],['--probe'],['--probe','--acknowledge','no'],['--check','--acknowledge',m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    m.main(args)
        query.assert_not_called()

    def test_invalid_filename_or_host_fails_before_ssh(self):
        with patch.object(m.subprocess,'run') as remote:
            self.assertEqual(m.query_history('user@172.17.0.24','../escape.age')['state'],'SSH_HISTORY_UNAVAILABLE')
            self.assertEqual(m.query_history('-oProxyCommand=evil','safe.age')['state'],'SSH_HISTORY_UNAVAILABLE')
        remote.assert_not_called()

    def test_query_uses_stdin_only_with_known_host_check(self):
        data={'state':'SNAPSHOT_CANDIDATE_FOUND','snapshots_checked':3,
              'candidate_copies':1,'roots_accessible':1,'roots_missing':2,
              'page':0,'next_page':None,'more_pages':False,'inventory_truncated':False}
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(data))) as ssh:
            result=m.query_history('albandrieu@172.17.0.24','private.age')
        self.assertEqual(result,data)
        argv=ssh.call_args.args[0]
        self.assertNotIn('private.age',repr(argv))
        self.assertEqual(argv[-2:],['python3','-'])
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertEqual(ssh.call_args.kwargs['stderr'],subprocess.DEVNULL)
        self.assertIn('private.age',ssh.call_args.kwargs['input'])
        self.assertIn('PAGE = 0',ssh.call_args.kwargs['input'])

    def test_untrusted_ssh_output_is_no_go(self):
        for output in ('not-json',json.dumps({'state':'SNAPSHOT_CANDIDATE_FOUND','snapshots_checked':True,'candidate_copies':1,'roots_accessible':1,'roots_missing':0}),
                       json.dumps({'state':'FAKE','snapshots_checked':1,'candidate_copies':1,'roots_accessible':1,'roots_missing':0})):
            with self.subTest(output=output[:20]),patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=output)):
                self.assertEqual(m.query_history('albandrieu@172.17.0.24','backup.age')['state'],'SSH_HISTORY_UNAVAILABLE')

    def test_failure_no_retry(self):
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=255,stdout='')) as ssh:
            self.assertEqual(m.query_history('albandrieu@172.17.0.24','backup.age')['state'],'SSH_HISTORY_UNAVAILABLE')
        self.assertEqual(ssh.call_count,1)

    def test_probe_preflight_denies_wrong_mount(self):
        base=SimpleNamespace(check_mount=lambda:'UNEXPECTED_NFS_EXPORT',
               local_expected_filename=lambda path:('SOURCE_UNIQUE_AGE_FOUND','private.age'), LOCAL_SOURCE=Path('/a'))
        with patch.object(m,'load_base',return_value=base),patch.object(m,'query_history') as query,redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--probe','--acknowledge',m.ACK]),3)
        query.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['archive_opened'])

    def test_probe_result_does_not_overclaim_recovery(self):
        base=SimpleNamespace(check_mount=lambda:'EXPECTED_NFS_EXPORT_MOUNTED',
               local_expected_filename=lambda path:('SOURCE_UNIQUE_AGE_FOUND','private.age'),LOCAL_SOURCE=Path('/a'))
        result={'state':'SNAPSHOT_CANDIDATE_FOUND','snapshots_checked':2,'candidate_copies':1,'roots_accessible':1,'roots_missing':2,
               'page':0,'next_page':None,'more_pages':False,'inventory_truncated':False}
        with patch.object(m,'load_base',return_value=base),patch.object(m,'query_history',return_value=result),redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--probe','--acknowledge',m.ACK]),0)
        obj=json.loads(out.getvalue())
        self.assertEqual(obj['status'],'NO-GO')
        self.assertFalse(obj['restore_verified'])
        self.assertFalse(obj['archive_opened'])
        self.assertFalse(obj['hardware_mutation_authorized'])
        self.assertFalse(obj['paths_disclosed'])

    def test_real_remote_snippet_on_synthetic_snapshots(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            snap_root=root/'snapshots';snap_root.mkdir()
            snapshot=snap_root/'mock-snap';(snapshot/'secret').mkdir(parents=True)
            # Replace all 3 probe roots with synthetic directories using no real filesystem
            modified=m.REMOTE_HISTORY.replace("'/mnt/cpool/backup/lab/.zfs/snapshot'",repr(str(snap_root)))
            modified=modified.replace("'/mnt/cpool/backup/.zfs/snapshot'",repr(str(root/'noneA')))
            modified=modified.replace("'/mnt/cpool/.zfs/snapshot'",repr(str(root/'noneB')))
            code='EXPECTED_NAME = "escrow.age"\nPAGE = 0\n'+modified
            def run():
                proc=subprocess.run([sys.executable,'-'],input=code,text=True,capture_output=True,timeout=5)
                self.assertEqual(proc.returncode,0,proc.stderr)
                return json.loads(proc.stdout)
            data=run()
            self.assertEqual(data['state'],'NO_CANDIDATE_IN_CHECKED_SNAPSHOTS')
            (snapshot/'secret'/'escrow.age').write_bytes(b'synthetic ciphertext')
            data=run()
            self.assertEqual(data['state'],'SNAPSHOT_CANDIDATE_FOUND')
            self.assertEqual(data['candidate_copies'],1)
            self.assertEqual(data['snapshots_checked'],1)
            self.assertNotIn('mock-snap',json.dumps(data))

    def test_scan_refuses_symlinked_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);scan=root/'snapshots'; scan.mkdir()
            (root/'real'/'secret').mkdir(parents=True)
            (root/'real'/'secret'/'escrow.age').write_bytes(b'synthetic')
            (scan/'symlink-snap').symlink_to(root/'real',target_is_directory=True)
            code='EXPECTED_NAME = "escrow.age"\nPAGE = 0\n' + m.REMOTE_HISTORY.replace(
                "'/mnt/cpool/backup/lab/.zfs/snapshot'",repr(str(scan))).replace(
                "'/mnt/cpool/backup/.zfs/snapshot'",repr(str(root/'noneA'))).replace(
                "'/mnt/cpool/.zfs/snapshot'",repr(str(root/'noneB')))
            proc=subprocess.run([sys.executable,'-'],input=code,text=True,capture_output=True,timeout=5)
            self.assertEqual(proc.returncode,0,proc.stderr)
            data=json.loads(proc.stdout)
            self.assertEqual(data['candidate_copies'],0)
            self.assertEqual(data['snapshots_checked'],0)

    def test_pagination_detects_copy_beyond_first_32_without_false_absence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            snapshots=root/'snapshots'; snapshots.mkdir()
            for n in range(70):
                (snapshots/f'snapshot-{n:04d}'/'secret').mkdir(parents=True)
            # Reverse lexicographic order: snapshot-0025 occurs on page 1.
            (snapshots/'snapshot-0025'/'secret'/'escrow.age').write_bytes(b'ENCRYPTED')
            modified=m.REMOTE_HISTORY.replace(
                "'/mnt/cpool/backup/lab/.zfs/snapshot'",repr(str(snapshots))).replace(
                "'/mnt/cpool/backup/.zfs/snapshot'",repr(str(root/'missing2'))).replace(
                "'/mnt/cpool/.zfs/snapshot'",repr(str(root/'missing3')))
            def scan(page):
                code='EXPECTED_NAME = "escrow.age"\nPAGE = '+str(page)+'\n'+modified
                proc=subprocess.run([sys.executable,'-'],input=code,text=True,capture_output=True,timeout=5)
                self.assertEqual(proc.returncode,0,proc.stderr)
                return json.loads(proc.stdout)
            first=scan(0)
            self.assertEqual(first['state'],'SNAPSHOT_HISTORY_INCOMPLETE')
            self.assertEqual(first['snapshots_checked'],32)
            self.assertEqual(first['next_page'],1)
            self.assertTrue(first['more_pages'])
            second=scan(1)
            self.assertEqual(second['state'],'SNAPSHOT_CANDIDATE_FOUND')
            self.assertEqual(second['candidate_copies'],1)
            self.assertEqual(second['page'],1)
            third=scan(2)
            self.assertEqual(third['state'],'NO_CANDIDATE_IN_CHECKED_SNAPSHOTS')
            self.assertIsNone(third['next_page'])
            self.assertEqual(third['snapshots_checked'],6)
            for entry in (first,second,third):
                self.assertNotIn('snapshot-0025',json.dumps(entry))

    def test_page_bounds_and_check_mode_fail_before_ssh(self):
        with patch.object(m,'query_history') as remote,redirect_stderr(io.StringIO()):
            for args in (['--probe','--page','-1','--acknowledge',m.ACK],
                         ['--probe','--page','32','--acknowledge',m.ACK],
                         ['--check','--page','1']):
                with self.subTest(args=args),self.assertRaises(SystemExit) as err:
                    m.main(args)
                self.assertEqual(err.exception.code,2)
        remote.assert_not_called()

    def test_query_rejects_inconsistent_pagination_from_server(self):
        base={'state':'SNAPSHOT_HISTORY_INCOMPLETE','snapshots_checked':32,'candidate_copies':0,
              'roots_accessible':1,'roots_missing':2,'page':1,'next_page':2,
              'more_pages':True,'inventory_truncated':False}
        for updates in ({'page':0},{'more_pages':False},
                        {'next_page':25}, {'next_page':True},
                        {'inventory_truncated':3},
                        {'state':'NO_CANDIDATE_IN_CHECKED_SNAPSHOTS'}):
            content={**base,**updates}
            with self.subTest(changes=updates),patch.object(m.subprocess,'run',
                    return_value=SimpleNamespace(returncode=0,stdout=json.dumps(content))):
                self.assertEqual(m.query_history('albandrieu@172.17.0.24','backup.age',page=1)['state'],
                                 'SSH_HISTORY_UNAVAILABLE')

    def test_snapshot_directory_entry_cap_never_claims_complete_absence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);snapshots=root/'snapshots';snapshots.mkdir()
            for n in range(1025):
                (snapshots/f'snap-{n:05d}').mkdir()
            modified=m.REMOTE_HISTORY.replace(
                "'/mnt/cpool/backup/lab/.zfs/snapshot'",repr(str(snapshots))).replace(
                "'/mnt/cpool/backup/.zfs/snapshot'",repr(str(root/'missing2'))).replace(
                "'/mnt/cpool/.zfs/snapshot'",repr(str(root/'missing3')))
            code='EXPECTED_NAME = "escrow.age"\nPAGE = 31\n'+modified
            proc=subprocess.run([sys.executable,'-'],input=code,text=True,capture_output=True,timeout=5)
            self.assertEqual(proc.returncode,0,proc.stderr)
            parsed=json.loads(proc.stdout)
            self.assertEqual(parsed['state'],'SNAPSHOT_HISTORY_INCOMPLETE')
            self.assertTrue(parsed['inventory_truncated'])
            self.assertIsNone(parsed['next_page'])


if __name__ == '__main__': unittest.main()
