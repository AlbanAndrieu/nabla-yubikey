"""Pure/synthetic NFS escrow server metadata tests, no remote SSH used."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/workstation/inspect-yubikey-escrow-nfs-server.py'
spec = importlib.util.spec_from_file_location('escrow_nfs_server', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Contracts(unittest.TestCase):
    def test_local_finds_single_source_filename_without_contents(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'private.age').write_bytes(b'synthetic')
            self.assertEqual(m.local_expected_filename(p), ('SOURCE_UNIQUE_AGE_FOUND','private.age'))
            (p / 'another.age').touch()
            self.assertEqual(m.local_expected_filename(p), ('SOURCE_FILENAME_NOT_UNIQUE',None))

    def test_local_refuses_symlink_filename(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'target.age').write_bytes(b'synthetic')
            (p/'link.age').symlink_to(p/'target.age')
            self.assertEqual(m.local_expected_filename(p), ('SOURCE_UNIQUE_AGE_FOUND','target.age'))

    def test_local_rejects_unsafe_basename(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'file name.age').touch()
            self.assertEqual(m.local_expected_filename(p), ('SOURCE_FILENAME_UNSAFE',None))

    def test_mount_exact_export_only(self):
        for line, state in [
            ('/media/backup/lab nfs4 nabla:/mnt/cpool/backup/lab\n','EXPECTED_NFS_EXPORT_MOUNTED'),
            ('/media/backup/lab nfs4 other:/mnt/cpool/backup/lab\n','UNEXPECTED_NFS_EXPORT'),
            ('/ ext4 /dev/vda\n','UNEXPECTED_MOUNT'),
        ]:
            with self.subTest(line=line), patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=line)):
                self.assertEqual(m.check_mount(), state)

    def test_remote_python_snippet_checks_server_presence_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d) / 'secret'
            root.mkdir()
            program='EXPECTED_NAME = "backup.age"\n' + m.REMOTE_PROBE.replace(
                "Path('/mnt/cpool/backup/lab/secret')", f'Path({str(root)!r})')
            for exists, expected in [(False, 'SERVER_EXPECTED_COPY_MISSING'),
                                     (True, 'SERVER_EXPECTED_COPY_REGULAR_NONEMPTY')]:
                if exists:
                    (root/'backup.age').write_bytes(b'ENCRYPTED ONLY - fixture')
                result=subprocess.run([sys.executable,'-'],input=program,text=True,
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                obj=json.loads(result.stdout)
                self.assertEqual(obj['state'],expected)
                self.assertEqual(obj['age_files'],int(exists))

    def test_server_rejects_suspect_ssh_target(self):
        with patch.object(m.subprocess,'run') as run:
            self.assertEqual(m.query_server('-oProxyCommand=evil','secret.age'), ('INVALID_SSH_TARGET',None))
            run.assert_not_called()

    def test_server_query_only_receives_filename_on_stdin(self):
        raw=json.dumps({'state':'SERVER_EXPECTED_COPY_MISSING','age_files':0})
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0, stdout=raw)) as run:
            self.assertEqual(m.query_server('albandrieu@172.17.0.24','private.age'), ('SERVER_EXPECTED_COPY_MISSING',0))
        argv=run.call_args.args[0]
        self.assertNotIn('private.age',repr(argv))
        self.assertEqual(argv[-2:], ['python3','-'])
        self.assertIn('BatchMode=yes',argv)
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertIn('private.age',run.call_args.kwargs['input'])
        self.assertEqual(run.call_args.kwargs['stderr'],subprocess.DEVNULL)

    def test_server_does_not_trust_arbitrary_output(self):
        for output in ('secret/path', json.dumps({'state':'SERVER_EXPECTED_COPY_MISSING', 'age_files': True}),
                       json.dumps({'state':'SOMETHING_ELSE','age_files':3})):
            with self.subTest(output=output), patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0, stdout=output)):
                self.assertEqual(m.query_server('albandrieu@172.17.0.24','private.age'), ('SSH_READONLY_PROBE_UNVERIFIED',None))

    def test_check_no_ssh_or_file_read(self):
        with patch.object(m,'check_mount',return_value='EXPECTED_NFS_EXPORT_MOUNTED'), \
             patch.object(m,'local_expected_filename',return_value=('SOURCE_UNIQUE_AGE_FOUND','private.age')), \
             patch.object(m,'query_server') as remote, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--check']),0)
        remote.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['archive_opened'])

    def test_probe_explicit_approval_and_target_required(self):
        with patch.object(m,'query_server') as remote, redirect_stderr(io.StringIO()):
            for args in (['--probe'], ['--probe','--ssh-target','albandrieu@172.17.0.24'],
                         ['--probe','--ssh-target','albandrieu@172.17.0.24','--acknowledge','wrong']):
                with self.subTest(args=args), self.assertRaises(SystemExit) as ex:
                    m.main(args)
                self.assertEqual(ex.exception.code,2)
        remote.assert_not_called()

    def test_probe_missing_export_never_contacts_host(self):
        with patch.object(m,'check_mount',return_value='UNEXPECTED_NFS_EXPORT'), \
             patch.object(m,'local_expected_filename',return_value=('SOURCE_UNIQUE_AGE_FOUND','private.age')), \
             patch.object(m,'query_server') as server, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--probe','--ssh-target','albandrieu@172.17.0.24','--acknowledge',m.ACK]),3)
        server.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['restoration_verified'])

    def test_server_credential_failure_no_retry(self):
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=255,stdout='')) as run:
            self.assertEqual(m.query_server('albandrieu@172.17.0.24','private.age'),('SSH_READONLY_PROBE_UNAVAILABLE',None))
        self.assertEqual(run.call_count,1)

if __name__ == '__main__': unittest.main()
