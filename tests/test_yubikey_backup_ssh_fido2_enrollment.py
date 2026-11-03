"""Hermetic tests: no physical token, no actual FIDO key created."""
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/workstation/enroll-yubikey-backup-ssh-fido2.py"
spec = importlib.util.spec_from_file_location("yubikey_backup_ssh_enrollment", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / '.ssh').mkdir(mode=0o700)

    def test_check_requires_no_token_and_does_not_create_key(self):
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'), patch.object(mod, 'exact_card_present') as card:
            self.assertEqual(mod.assess(self.home), 'READY_FOR_INTERACTIVE_ENROLLMENT')
            card.assert_not_called()
        self.assertFalse((self.home / '.ssh' / mod.DIRECTORY).exists())

    def test_refuses_untrusted_ssh_dir(self):
        (self.home / '.ssh').chmod(0o755)
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'):
            self.assertEqual(mod.assess(self.home), 'SSH_DIRECTORY_UNTRUSTED')

    def test_existing_target_not_overwritten(self):
        path = self.home / '.ssh' / mod.DIRECTORY
        path.mkdir()
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'), patch.object(mod.subprocess, 'run') as runner:
            self.assertEqual(mod.enroll(self.home, tty=True), 'TARGET_EXISTS_NO_OVERWRITE')
            runner.assert_not_called()

    def test_no_tty_never_contacts_card(self):
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'), patch.object(mod, 'exact_card_present') as card:
            self.assertEqual(mod.enroll(self.home, tty=False), 'INTERACTIVE_TERMINAL_REQUIRED')
            card.assert_not_called()

    def test_wrong_serial_never_creates_output(self):
        with patch.object(mod.shutil, 'which', return_value='/usr/bin/fake'), patch.object(mod, 'exact_card_present', return_value=False):
            self.assertEqual(mod.enroll(self.home, tty=True), 'EXPECTED_EXACTLY_ONE_BACKUP_YUBIKEY')
        self.assertFalse((self.home / '.ssh' / mod.DIRECTORY).exists())

    def test_exact_card_query_stdin_closed_and_no_secret_output(self):
        good = subprocess.CompletedProcess([], 0, mod.SERIAL+'\n', '')
        with patch.object(mod.subprocess, 'run', return_value=good) as run:
            self.assertTrue(mod.exact_card_present())
        self.assertEqual(run.call_args.args[0], ['ykman','list','--serials'])
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['timeout'], 10)
        for output in (mod.SERIAL+'\n11110001\n', '11110001\n', ''):
            with patch.object(mod.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,output,'')):
                self.assertFalse(mod.exact_card_present())

    def test_enroll_creates_only_new_handle_and_never_changes_ssh_config(self):
        def fake_run(args, **kw):
            self.assertEqual(args[:3], ['ssh-keygen', '-t', 'ed25519-sk'])
            base = Path(args[args.index('-f')+1]); base.write_text('fake handle')
            base.chmod(0o600)
            (Path(str(base)+'.pub')).write_text('fake public handle')
            return SimpleNamespace(returncode=0)
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod, 'exact_card_present',return_value=True), patch.object(mod.subprocess,'run',side_effect=fake_run):
            state=mod.enroll(self.home,tty=True)
        self.assertEqual(state,'LOCAL_FIDO2_KEY_HANDLE_CREATED_REMOTE_LOGIN_NOT_VERIFIED')
        self.assertEqual(stat.S_IMODE((self.home/'.ssh'/mod.DIRECTORY).stat().st_mode),0o700)
        self.assertFalse((self.home/'.ssh'/'config').exists())
        self.assertFalse((self.home/'.ssh'/'authorized_keys').exists())

    def test_failed_enroll_is_not_retried_and_keeps_partial_directory(self):
        with patch.object(mod.shutil,'which',return_value='/usr/bin/fake'), patch.object(mod,'exact_card_present',return_value=True), patch.object(mod.subprocess,'run',return_value=SimpleNamespace(returncode=1)):
            self.assertEqual(mod.enroll(self.home,tty=True),'ENROLLMENT_FAILED_INSPECT_TARGET')
            self.assertEqual(mod.enroll(self.home,tty=True),'TARGET_EXISTS_NO_OVERWRITE')

    def test_unapproved_arguments_rejected_before_writing(self):
        with patch.object(mod,'enroll') as enroll, patch.object(mod,'assess') as assess, redirect_stderr(io.StringIO()):
            for args in (['--enroll'],['--enroll','--acknowledge','wrong'],['--check','--acknowledge','x'],['--reset']):
                with self.assertRaises(SystemExit) as e: mod.main(args)
                self.assertEqual(e.exception.code,2)
            enroll.assert_not_called(); assess.assert_not_called()

    def test_check_cli_redacted_json_and_no_mutation(self):
        with patch.dict(os.environ,{'HOME':str(self.home)}), patch.object(mod.shutil,'which',return_value='/usr/bin/fake'):
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(mod.main(['--check']),0)
        self.assertIn('READY_FOR_INTERACTIVE_ENROLLMENT',output.getvalue())
        self.assertNotIn(str(self.home),output.getvalue())
        self.assertFalse((self.home/'.ssh'/mod.DIRECTORY).exists())

if __name__=='__main__': unittest.main()
