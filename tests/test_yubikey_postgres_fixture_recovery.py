"""Hermetic contracts for opt-in offline PostgreSQL fixture recovery."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/workstation/verify-postgres-fixture-recovery.sh'
FAKE_SHA = 'sha256:' + 'a' * 64

class Contracts(unittest.TestCase):
    def call(self, *args, image=FAKE_SHA, endpoint="unix:///var/run/docker.sock", docker_host=""):
        with tempfile.TemporaryDirectory() as temp:
            docker = Path(temp, 'docker')
            docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRACE"\nif [ "$1" = context ]; then printf "%s\\n" "$LOCAL_ENDPOINT"; fi\nif [ "$1" = image ] && [ "$2" = inspect ]; then printf "%s\\n" "$IMAGE_SHA"; fi\n')
            docker.chmod(0o700)
            trace = Path(temp, 'trace')
            env = {**os.environ, 'PATH': f'{temp}:' + os.environ['PATH'],
                   'TRACE': str(trace), 'IMAGE_SHA': FAKE_SHA, 'LOCAL_ENDPOINT': endpoint, 'DOCKER_HOST': docker_host,
                   'NABLA_POSTGRES_FIXTURE_IMAGE_SHA256': image}
            proc = subprocess.run(['bash', str(SOURCE), *args], env=env,
                                  capture_output=True, text=True, timeout=6)
            called = trace.read_text() if trace.exists() else ''
            return proc, called

    def test_check_never_starts_docker(self):
        proc, called = self.call('--check')
        self.assertEqual(proc.returncode, 0)
        self.assertIn('NOT_RUN', proc.stdout)
        self.assertIn('image inspect', called)
        self.assertNotIn('run', called)
        self.assertNotIn('exec', called)

    def test_tag_and_missing_image_rejected(self):
        for value in ('postgres:18', '', 'sha256:invalid', 'sha256:' + 'b'*64):
            proc, called = self.call('--check', image=value)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn(' run ', called)

    def test_remote_docker_endpoints_are_rejected_before_image_access(self):
        for opts in ({'endpoint': 'ssh://truenas'}, {'endpoint': 'tcp://172.17.0.24:2375'},
                     {'docker_host': 'ssh://truenas'}):
            proc, called = self.call('--check', **opts)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn('image inspect', called)
            self.assertNotIn(' run ', called)

    def test_run_requires_exact_acknowledgment(self):
        for args in (('--run',), ('--run', '--acknowledge', 'wrong'), ('--run', '--check'), ()):
            proc, called = self.call(*args)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(called, '')

    def test_isolated_runtime_contract(self):
        text = SOURCE.read_text()
        for clause in ('--pull=never', '--network none', '--read-only', '--tmpfs',
                       'trap cleanup EXIT', 'pg_dump', 'pg_restore',
                       'synthetic-fixture', 'POSTGRES_HOST_AUTH_METHOD=trust',
                       'docker rm -f'):
            self.assertIn(clause, text)
        for unsafe in ('-p 5432', '--network host', '--privileged', '--volume',
                       'pg_restore --clean', 'curl ', 'wget '):
            self.assertNotIn(unsafe, text)

if __name__ == '__main__':
    unittest.main()
