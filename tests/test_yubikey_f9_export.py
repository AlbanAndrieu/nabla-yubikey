"""Isolated --save-public-f9 F9 export tests; never invoke a real reader."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/workstation/inspect-age-yubikey-f9-chain.sh'


class F9PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.mock = self.directory / 'bin'
        self.mock.mkdir()
        self.out = self.directory / 'public-f9.pem'
        self.trace = self.directory / 'trace'
        ykman = self.mock / 'ykman'
        ykman.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$MOCK_TRACE"
case "$*" in
  'list --serials') echo "${MOCK_SERIALS:-11110002}" ;;
  '--device 11110002 info') echo 'Firmware version: 5.4.3' ;;
  '--device 11110002 piv certificates export --format PEM f9 -')
    printf '%s\\n' '-----BEGIN CERTIFICATE-----' 'MOCK' '-----END CERTIFICATE-----' ;;
  *) exit 97 ;;
esac
''')
        ykman.chmod(0o700)
        openssl = self.mock / 'openssl'
        openssl.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "openssl $*" >> "$MOCK_TRACE"
case "$*" in
 *'-noout -subject -issuer -dates') exit 0 ;;
 *'-noout -fingerprint -sha256') printf 'sha256 Fingerprint=01:23\n' ;;
 *) exit 98 ;;
esac
''')
        openssl.chmod(0o700)

    def execute(self, *args, **variables):
        env = dict(os.environ, PATH=str(self.mock) + os.pathsep + os.environ['PATH'],
                   MOCK_TRACE=str(self.trace))
        env.update(variables)
        return subprocess.run(['bash', str(SCRIPT), *args], env=env,
                              capture_output=True, text=True)

    def test_save_new_public_f9_file_mode_0600(self):
        r = self.execute('--serial', '11110002', '--save-public-f9', str(self.out))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('public certificate saved', r.stdout)
        self.assertIn('BEGIN CERTIFICATE', self.out.read_text())
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o600)

    def test_cannot_overwrite_existing_pem(self):
        self.out.write_text('keep this important evidence')
        r = self.execute('--serial', '11110002', '--save-public-f9', str(self.out))
        self.assertEqual(r.returncode, 3)
        self.assertEqual(self.out.read_text(), 'keep this important evidence')
        self.assertFalse(self.trace.exists())

    def test_cannot_follow_symlink(self):
        protected = self.directory / 'protected'
        protected.write_text('do not touch')
        self.out.symlink_to(protected)
        r = self.execute('--serial', '11110002', '--save-public-f9', str(self.out))
        self.assertEqual(r.returncode, 3)
        self.assertEqual(protected.read_text(), 'do not touch')

    def test_wrong_device_never_writes_file(self):
        r = self.execute('--serial', '11110002', '--save-public-f9', str(self.out),
                         MOCK_SERIALS='11110001')
        self.assertEqual(r.returncode, 3)
        self.assertFalse(self.out.exists())
        self.assertNotIn('certificates export', self.trace.read_text())

    def test_bad_usage_never_calls_ykman(self):
        r = self.execute('--serial', '11110002', '--save-public-f9')
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.trace.exists())


if __name__ == '__main__':
    unittest.main()
