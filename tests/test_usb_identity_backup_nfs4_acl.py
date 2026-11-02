"""Hermetic ACL inventory tests: synthetic directories and mocked midclt / SSH."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/workstation/inspect-usb-identity-backup-nfs4-acl.py'
spec = importlib.util.spec_from_file_location('usb_identity_acl', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    def setUp(self):
        self.name = 'usb-recovery-identity-20261028T000000Z-a1b2c3d4.age'
        self.pair = (Path('/fake/local') / self.name, Path('/fake/nfs') / self.name)
        self.backup = SimpleNamespace(encrypted_pair=lambda: ('BACKUP_RESTORATION_PREFLIGHT_READY', self.pair))

    def test_check_only_metadata_and_no_ssh(self):
        with patch.object(m, 'load_backup', return_value=self.backup), \
             patch.object(m, 'query_server') as probe, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--check']), 0)
        probe.assert_not_called()
        report = json.loads(out.getvalue())
        self.assertIsNone(report['levels'])
        self.assertFalse(report['effective_nfs4_authorization_verified'])
        self.assertFalse(report['archive_opened'])

    def test_check_refuses_missing_archive(self):
        absent = SimpleNamespace(encrypted_pair=lambda: ('BACKUPS_ABSENT_OR_AMBIGUOUS', None))
        with patch.object(m, 'load_backup', return_value=absent), \
             patch.object(m, 'query_server') as probe, redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(['--check']), 3)
        probe.assert_not_called()

    def test_interactive_ack_gate(self):
        with redirect_stderr(io.StringIO()), patch.object(m, 'query_server') as probe:
            for args in ([], ['--probe'], ['--probe', '--acknowledge', 'other'],
                         ['--check', '--acknowledge', m.ACK]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                    m.main(args)
                self.assertEqual(error.exception.code, 2)
        probe.assert_not_called()

    def test_ssh_uses_pinned_host_and_code_via_stdin(self):
        response = {'levels': [self.acl_record(i) for i in range(4)]}
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(response))) as ssh:
            self.assertEqual(m.query_server(self.name), response['levels'])
        argv = ssh.call_args.args[0]
        self.assertEqual(argv[-3:], [m.SSH_TARGET, 'python3', '-'])
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('BatchMode=yes', argv)
        self.assertNotIn(self.name, repr(argv))
        self.assertIn(self.name, ssh.call_args.kwargs['input'])
        self.assertEqual(ssh.call_args.kwargs['stderr'], subprocess.DEVNULL)

    @staticmethod
    def acl_record(i, *, state='NFS4_REVIEW_REQUIRED', nonowner=0):
        return {'level': i, 'state': state, 'acltype': 'NFS4',
                'trivial': False, 'ace_count': 1,
                'potential_nonowner_allow_count': nonowner}

    def test_malformed_or_private_server_output_rejected(self):
        invalid = [
            'secret/raw/path', '{}', json.dumps({'levels': []}),
            json.dumps({'levels': [self.acl_record(i) for i in range(3)]}),
            json.dumps({'levels': [{**self.acl_record(i), 'level': True} if i == 1
                                   else self.acl_record(i) for i in range(4)]}),
            json.dumps({'levels': [{**self.acl_record(i), 'trivial': 'False'} if i == 1
                                   else self.acl_record(i) for i in range(4)]}),
            json.dumps({'levels': [{**self.acl_record(i), 'extra': 'secret'} if i == 1
                                   else self.acl_record(i) for i in range(4)]}),
        ]
        for output in invalid:
            with self.subTest(output=output[:30]), patch.object(m.subprocess, 'run',
                return_value=SimpleNamespace(returncode=0, stdout=output)):
                self.assertIsNone(m.query_server(self.name))

    def test_invalid_filename_rejected_before_ssh(self):
        with patch.object(m.subprocess, 'run') as run:
            for name in ('../secret.age', 'fake.age', 'usb-recovery-identity-20261028T000000Z-X.age'):
                self.assertIsNone(m.query_server(name))
        run.assert_not_called()

    def test_failed_ssh_not_retried(self):
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(
                returncode=255, stdout='')) as run:
            self.assertIsNone(m.query_server(self.name))
        self.assertEqual(run.call_count, 1)

    def test_missing_archive_stops_remote_before_ssh(self):
        absent = SimpleNamespace(encrypted_pair=lambda: ('BACKUPS_ABSENT_OR_AMBIGUOUS', None))
        with patch.object(m, 'load_backup', return_value=absent), \
             patch.object(m, 'query_server') as remote, redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(['--probe', '--acknowledge', m.ACK]), 3)
        remote.assert_not_called()

    def test_potential_nonowner_acl_fails_closed(self):
        data = [self.acl_record(i) for i in range(4)]
        data[2] = self.acl_record(2, state='POTENTIAL_NONOWNER_ALLOW', nonowner=2)
        with patch.object(m, 'load_backup', return_value=self.backup), \
             patch.object(m, 'query_server', return_value=data), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--probe', '--acknowledge', m.ACK]), 3)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed['levels'][2]['level'], 'backup_directory')
        self.assertEqual(parsed['levels'][2]['potential_nonowner_allow_count'], 2)
        self.assertFalse(parsed['effective_nfs4_authorization_verified'])
        self.assertNotIn(self.name, out.getvalue())

    def test_all_nfs4_present_still_not_effective_authorization_proof(self):
        with patch.object(m, 'load_backup', return_value=self.backup), \
             patch.object(m, 'query_server', return_value=[self.acl_record(i) for i in range(4)]), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--probe', '--acknowledge', m.ACK]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertFalse(result['effective_nfs4_authorization_verified'])
        self.assertFalse(result['remote_write_performed'])

    def test_remote_code_with_synthetic_acl_documents(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            share = root/'lab'; share.mkdir()
            secret = share/'secret'; secret.mkdir()
            copies = secret/'usb-recovery-backups'; copies.mkdir()
            (copies/self.name).write_bytes(b'encrypted fixture')
            command = root/'bin'; command.mkdir()
            midclt = command/'midclt'
            midclt.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                'print(json.dumps({"path": sys.argv[3],"acltype":"NFS4","trivial":False,'
                '"acl":[{"tag":os.getenv("FIXTURE_TAG","owner@"),"type":"ALLOW",'
                '"perms":{"BASIC":os.getenv("FIXTURE_PERMS","FULL_CONTROL")},'
                '"flags":{}}]}))\n', encoding='utf-8')
            midclt.chmod(0o700)
            code = ('EXPECTED_NAME = ' + json.dumps(self.name) + '\n' +
                    m.REMOTE.replace('Path("/mnt/cpool/backup/lab")', f'Path({str(share)!r})'))
            env = {**os.environ, 'PATH': str(command) + os.pathsep + os.environ.get('PATH', '')}
            def execute(**extras):
                proc = subprocess.run([sys.executable, '-'], input=code, text=True,
                                      capture_output=True, env={**env, **extras}, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn(str(share), proc.stdout)
                self.assertNotIn(self.name, proc.stdout)
                return json.loads(proc.stdout)['levels']
            default = execute()
            self.assertEqual([r['state'] for r in default], ['NFS4_REVIEW_REQUIRED']*4)
            exposed = execute(FIXTURE_TAG='everyone@', FIXTURE_PERMS='READ')
            self.assertEqual([r['state'] for r in exposed], ['POTENTIAL_NONOWNER_ALLOW']*4)
            self.assertEqual(exposed[3]['potential_nonowner_allow_count'], 1)
            (copies/self.name).unlink()
            (copies/self.name).symlink_to(share/'secret')
            self.assertEqual(execute()[-1]['state'], 'UNTRUSTED_PATH')


if __name__ == '__main__':
    unittest.main()
