import importlib.util
import io
import subprocess
import unittest
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'scripts/workstation/probe-yubikey-backup-openpgp.py'
spec=importlib.util.spec_from_file_location('backup_openpgp',source)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class Contracts(unittest.TestCase):
    def test_passive_check_does_not_touch_card(self):
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod.subprocess,'run') as runner:
            self.assertEqual(mod.check(),'TOOLS_PRESENT_HARDWARE_NOT_CHECKED')
            runner.assert_not_called()

    def test_interactive_guard_before_ykman(self):
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod.subprocess,'run') as runner:
            self.assertEqual(mod.probe(False),'INTERACTIVE_TERMINAL_REQUIRED')
            runner.assert_not_called()

    def test_wrong_serial_blocks_gpg(self):
        bad=subprocess.CompletedProcess([],0,'11110001\n','')
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod.subprocess,'run',return_value=bad) as runner:
            self.assertEqual(mod.probe(True),'EXPECTED_ONE_BACKUP_YUBIKEY')
            self.assertEqual(runner.call_count,1)

    def test_gpg_probe_only_reads_public_status_and_masks_it(self):
        good=subprocess.CompletedProcess([],0,'11110002\n','')
        card=subprocess.CompletedProcess([],0,'Application ID ...: D2760001240103040006186980150000\n','')
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod.subprocess,'run',side_effect=[good,card]) as runner:
            self.assertEqual(mod.probe(True),'GPG_CARD_STATUS_RESPONDS_PUBLIC_ONLY_IDENTITY_UNVERIFIED')
            self.assertEqual(runner.call_args.args[0],['gpg','--batch','--no-tty','--card-status'])
            self.assertEqual(runner.call_args.kwargs['stdin'],subprocess.DEVNULL)
            self.assertEqual(runner.call_args.kwargs['timeout'],20)

    def test_gpg_failure_never_claims_transport(self):
        good=subprocess.CompletedProcess([],0,'11110002\n','')
        bad=subprocess.CompletedProcess([],2,'','No such device, secrets irrelevant')
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod.subprocess,'run',side_effect=[good,bad]):
            self.assertEqual(mod.probe(True),'OPENPGP_DEVICE_NOT_AVAILABLE')

    def test_no_success_for_empty_stdout_with_exit_zero(self):
        self.assertEqual(mod.classify_card_reply(0, '', ''),
                         'OPENPGP_CARD_STATUS_UNRECOGNIZED')

    def test_no_success_for_arbitrary_text_with_exit_zero(self):
        self.assertEqual(mod.classify_card_reply(0, 'private path not for logs', ''),
                         'OPENPGP_CARD_STATUS_UNRECOGNIZED')

    def test_no_success_for_gpg_warning_even_with_valid_application_id(self):
        aid = 'Application ID ...: D2760001240103040006186980150000\n'
        self.assertEqual(mod.classify_card_reply(0, aid, 'gpg: warning: unexpected'),
                         'OPENPGP_TRANSPORT_NOT_CONFIRMED')

    def test_no_success_if_valid_app_id_and_exit_nonzero(self):
        aid = 'Application ID ...: D2760001240103040006186980150000\n'
        self.assertEqual(mod.classify_card_reply(2, aid, 'gpg: failed'),
                         'OPENPGP_TRANSPORT_NOT_CONFIRMED')

    def test_common_gpg_errors_are_classified_without_details(self):
        errors = [
            ('gpg: selecting openpgp failed: No such device', 'OPENPGP_DEVICE_NOT_AVAILABLE'),
            ('gpg: OpenPGP card not available: Card error', 'OPENPGP_CARD_OR_READER_ERROR'),
            ('scdaemon: failed to connect to agent', 'OPENPGP_SCDAEMON_OR_AGENT_UNAVAILABLE'),
            ('PCSC resource busy', 'OPENPGP_READER_BUSY_UNVERIFIED'),
            ('gpg: another obscure /home/secret/private/path', 'OPENPGP_TRANSPORT_NOT_CONFIRMED'),
        ]
        for diagnostic, expected in errors:
            with self.subTest(diagnostic=expected):
                actual = mod.classify_card_reply(2, '', diagnostic)
                self.assertEqual(actual, expected)
                self.assertNotIn('/home/', actual)
                self.assertNotIn('secret', actual)

    def test_output_size_or_nul_is_rejected(self):
        for text in ('secret\x00', 'a' * 32769):
            with self.subTest(length=len(text)):
                self.assertEqual(mod.classify_card_reply(0, text, ''),
                                 'OPENPGP_PROBE_UNCLASSIFIED')

    def test_probe_timeout_is_categorized_not_retried(self):
        good = subprocess.CompletedProcess([], 0, '11110002\n', '')
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'), \
             patch.object(mod.subprocess, 'run',
                          side_effect=[good, subprocess.TimeoutExpired(['gpg'], 20)]) as runner:
            self.assertEqual(mod.probe(True), 'OPENPGP_PROBE_TIMEOUT')
            self.assertEqual(runner.call_count, 2)

    def test_probe_reports_busy_reader_without_logging_sensitive_error(self):
        good = subprocess.CompletedProcess([], 0, '11110002\n', '')
        failure = subprocess.CompletedProcess([], 2, '',
                    'gpg: resource busy: /private/reader/internal-id')
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'), \
             patch.object(mod.subprocess, 'run', side_effect=[good, failure]):
            self.assertEqual(mod.probe(True), 'OPENPGP_READER_BUSY_UNVERIFIED')

    def test_unsupported_options_rejected(self):
        with redirect_stderr(io.StringIO()), patch.object(mod,'probe') as runner:
            for args in (['--probe'],['--probe','--acknowledge','wrong'],['--check','--acknowledge','x'],['--sign']):
                with self.assertRaises(SystemExit) as e: mod.main(args)
                self.assertEqual(e.exception.code,2)
            runner.assert_not_called()

    def test_cli_masks_raw_card_output(self):
        with patch.object(mod,'probe',return_value='OPENPGP_TRANSPORT_NOT_CONFIRMED'), patch.object(mod.sys.stdin,'isatty',return_value=True),patch.object(mod.sys.stdout,'isatty',return_value=True):
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(mod.main(['--probe','--acknowledge',mod.ACK]),3)
            self.assertIn('NO-GO',output.getvalue())
            self.assertNotIn('No such device',output.getvalue())

if __name__=='__main__':unittest.main()
