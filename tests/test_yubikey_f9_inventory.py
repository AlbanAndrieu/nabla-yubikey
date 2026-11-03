"""Hermetic F9 read-only tests; executable shims prohibit actual device use."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/workstation/inspect-age-yubikey-f9-chain.sh'


class F9ReadOnlyContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.trace = self.root / 'trace'
        self.ykman = self.bin / 'ykman'
        self.ykman.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$MOCK_TRACE"
case "$*" in
  'list --serials') printf '%s\\n' "${MOCK_DEVICES:-11110002}" ;;
  '--device 11110002 info'|'--device 11110001 info')
    [[ "${MOCK_INFO_FAIL:-0}" == 0 ]] || exit 1
    printf 'Firmware version: %s\\n' "${MOCK_FIRMWARE:-5.7.4}" ;;
  '--device 11110002 piv certificates export --format PEM f9 -'|\
  '--device 11110001 piv certificates export --format PEM f9 -')
    [[ "${MOCK_F9_FAIL:-0}" == 0 ]] || exit 1
    printf '%s\\n' '-----BEGIN CERTIFICATE-----' 'SYNTHETIC' '-----END CERTIFICATE-----' ;;
  *) exit 88 ;;
esac
''')
        self.ykman.chmod(0o700)
        ossl = self.bin / 'openssl'
        ossl.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf 'openssl %s\\n' "$*" >> "$MOCK_TRACE"
case "$*" in
  *'-noout -subject -issuer -dates') exit 0 ;;
  *'-noout -fingerprint -sha256') printf 'sha256 Fingerprint=01:23\\n' ;;
  *) exit 89 ;;
esac
''')
        ossl.chmod(0o700)

    def run_check(self, *args, **overrides):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   MOCK_TRACE=str(self.trace))
        env.update({k: str(v) for k, v in overrides.items()})
        return subprocess.run(['bash', str(SCRIPT), *args], env=env,
                              capture_output=True, text=True)

    def test_valid_single_secondary_read_only(self):
        result = self.run_check('--serial', '11110002')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('NOT the Yubico root', result.stdout)
        self.assertIn('NO-GO', result.stdout)
        lines = self.trace.read_text().splitlines()
        self.assertEqual(len(lines), 5)
        self.assertTrue(all(any(t in line for t in ('list --serials', ' info',
                         'certificates export', 'openssl ')) for line in lines))
        self.assertFalse(any(t in '\n'.join(lines) for t in (' keys generate',
                         ' access ', 'piv reset', ' --pin ', ' attest ')))

    def test_multiple_devices_fail_before_export(self):
        result = self.run_check('--serial', '11110002', MOCK_DEVICES='11110002\n11110001')
        self.assertEqual(result.returncode, 3)
        self.assertNotIn('certificates export', self.trace.read_text())

    def test_wrong_device_fails(self):
        result = self.run_check('--serial', '11110002', MOCK_DEVICES='11110001')
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(' info', self.trace.read_text())

    def test_unknown_serial_fails_without_running_ykman(self):
        result = self.run_check('--serial', '01234567')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.trace.exists())

    def test_f9_missing_fails_closed(self):
        result = self.run_check('--serial', '11110002', MOCK_F9_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('cannot export', result.stderr)

    def test_unrecognized_firmware_fails_closed(self):
        result = self.run_check('--serial', '11110002', MOCK_FIRMWARE='unknown')
        self.assertEqual(result.returncode, 3)
        self.assertNotIn('certificates export', self.trace.read_text())

    def test_info_error_fails_closed(self):
        result = self.run_check('--serial', '11110002', MOCK_INFO_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertNotIn('certificates export', self.trace.read_text())

    def test_help_does_not_call_device(self):
        result = self.run_check('--help')
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.trace.exists())


if __name__ == '__main__':
    unittest.main()
