"""No real backup files or YubiKeys are required for these tests."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/workstation/compare-yubikey-escrow-pair-readonly.py'
spec = importlib.util.spec_from_file_location('escrow_compare', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a, self.b = (Path(self.tmp.name) / x for x in ('a.age','b.age'))
        self.a.write_bytes(b'ENCRYPTED only sample')
        self.b.write_bytes(b'ENCRYPTED only sample')
        self.a.chmod(0o600)
        self.b.chmod(0o600)

    def cross_fs(self):
        # Fixture paths live on one filesystem. Only simulated metadata
        # differs for this mock: never fake actual physical independence.
        first = self.a.stat()
        second = self.b.stat()
        from types import SimpleNamespace
        def record(st, dev):
            return SimpleNamespace(st_dev=dev, st_ino=st.st_ino, st_size=st.st_size,
                st_mtime_ns=st.st_mtime_ns, st_ctime_ns=st.st_ctime_ns,
                st_nlink=st.st_nlink, st_mode=st.st_mode, st_uid=st.st_uid)
        return (record(first,100), record(second,200))

    def test_check_no_io_or_discovery(self):
        with patch.object(module, 'discover') as discover, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(['--check']),0)
        discover.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['encrypted_content_read_attempted'])

    def test_compare_requires_exact_acknowledgement(self):
        with patch.object(module, 'discover') as discover, redirect_stderr(io.StringIO()):
            for args in ([],['--compare'],['--compare','--acknowledge','no'],
                         ['--check','--acknowledge',module.ACK],['--decrypt']):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    module.main(args)
        discover.assert_not_called()

    def test_discovery_failure_never_opens(self):
        with patch.object(module,'discover',return_value=('DISCOVERY_MULTIPLE_MATCHING_PAIRS',None)), \
             patch.object(module,'compare_ciphertexts') as comparator, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(['--compare','--acknowledge',module.ACK]),3)
        comparator.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['restoration_verified'])

    def test_reject_symlink_and_hardlink(self):
        self.a.unlink()
        self.a.symlink_to(self.b)
        self.assertEqual(module.compare_ciphertexts(self.a,self.b),'ENCRYPTED_COPY_UNVERIFIED')
        self.a.unlink()
        os.link(self.b,self.a)
        self.assertEqual(module.compare_ciphertexts(self.a,self.b),'ENCRYPTED_COPY_UNVERIFIED')

    def test_wrong_owner_or_oversized_rejected_before_open(self):
        class Fake:
            st_mode=0o100600; st_nlink=1; st_uid=os.getuid()+1000; st_size=50
        with patch.object(Path,'lstat',return_value=Fake()), patch.object(module.os,'open') as opener:
            self.assertEqual(module.compare_ciphertexts(self.a,self.b),'ENCRYPTED_COPY_UNVERIFIED')
            opener.assert_not_called()

    def test_group_or_world_readable_escrow_rejected_before_open(self):
        self.a.chmod(0o644)
        with patch.object(module.os, 'open') as opener:
            self.assertEqual(
                module.compare_ciphertexts(self.a, self.b),
                'ENCRYPTED_COPY_UNVERIFIED',
            )
            opener.assert_not_called()

    def test_parent_directory_symlink_is_rejected(self):
        alias = Path(self.tmp.name) / "alias"
        alias.symlink_to(Path(self.tmp.name), target_is_directory=True)
        with patch.object(module.os, 'open') as opener:
            self.assertEqual(
                module.compare_ciphertexts(alias / "a.age", self.b),
                'ENCRYPTED_COPY_UNVERIFIED',
            )
            opener.assert_not_called()

    def test_same_filesystem_is_not_independent(self):
        self.assertEqual(module.compare_ciphertexts(self.a,self.b),'COPIES_NOT_ON_DISTINCT_FILESYSTEMS')

    def test_open_read_flags_are_nofollow_and_nonblock(self):
        with patch.object(module.os, 'open', wraps=os.open) as opener:
            fd, _ = module.secure_open(self.a)
            os.close(fd)
        flags=opener.call_args.args[1]
        self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertTrue(flags & os.O_NONBLOCK)
        self.assertTrue(flags & os.O_CLOEXEC)

    def test_identical_ciphertexts_return_only_boolean_evidence(self):
        first,second = self.cross_fs()
        original=module.secure_open
        def fake_secure(path):
            fd, real=original(path)
            return fd, first if path==self.a else second
        with patch.object(module,'secure_open',side_effect=fake_secure), patch.object(module,'unchanged',return_value=True):
            self.assertEqual(module.compare_ciphertexts(self.a,self.b),
                             'ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED')

    def test_modified_ciphertexts_do_not_pass(self):
        self.b.write_bytes(b'ENCRYPTED only wrong!')
        first,second = self.cross_fs()
        original=module.secure_open
        def fake_secure(path):
            fd,_=original(path)
            return fd,first if path==self.a else second
        with patch.object(module,'secure_open',side_effect=fake_secure), patch.object(module,'unchanged',return_value=True):
            self.assertEqual(module.compare_ciphertexts(self.a,self.b),'ENCRYPTED_COPIES_DIFFER')

    def test_changed_metadata_blocks_success(self):
        first,second=self.cross_fs()
        original=module.secure_open
        def fake_secure(path):
            fd,_=original(path)
            return fd,first if path==self.a else second
        with patch.object(module,'secure_open',side_effect=fake_secure), patch.object(module,'unchanged',return_value=False):
            self.assertEqual(module.compare_ciphertexts(self.a,self.b),'ENCRYPTED_COPY_CHANGED_DURING_READ')

    def test_paths_never_appear_in_output_and_restore_false(self):
        with patch.object(module,'discover',return_value=('TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED',(self.a,self.b))), \
             patch.object(module,'compare_ciphertexts',return_value='ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED'), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(['--compare','--acknowledge',module.ACK]),0)
        self.assertNotIn(str(self.a),out.getvalue())
        self.assertNotIn(str(self.b),out.getvalue())
        self.assertIn('"status": "NO-GO"',out.getvalue())
        self.assertFalse(json.loads(out.getvalue())['restoration_verified'])


    def test_manual_without_tty_never_prompts_or_opens(self):
        with patch.object(module.getpass,"getpass") as prompt, \
             patch.object(module,"load_locator") as loader:
            self.assertEqual(module.select_manual_pair(tty=False),
                             ("INTERACTIVE_TERMINAL_REQUIRED",None))
            prompt.assert_not_called()
            loader.assert_not_called()

    def test_manual_pair_can_verify_metadata_without_auto_discovery(self):
        user_input=iter(("/home/user/private/source.age","/media/backup/secret/copy.age"))
        from types import SimpleNamespace
        fake=SimpleNamespace(classify_inputs=lambda a,b:"TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED")
        with patch.object(module,"load_locator",return_value=fake), \
             patch.object(module, "discover") as discover:
            state,paths=module.select_manual_pair(tty=True,reader=lambda prompt:next(user_input))
        self.assertEqual(state,"TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED")
        self.assertEqual(paths[0],Path("/home/user/private/source.age"))
        self.assertEqual(paths[1],Path("/media/backup/secret/copy.age"))
        discover.assert_not_called()

    def test_manual_same_file_denied_before_content_read(self):
        from types import SimpleNamespace
        fake=SimpleNamespace(classify_inputs=lambda a,b:"SAME_FILE")
        with patch.object(module,"load_locator",return_value=fake):
            state,paths=module.select_manual_pair(tty=True,reader=lambda prompt:"/home/user/one.age")
        self.assertEqual(state,"SAME_FILE")
        self.assertIsNone(paths)

    def test_manual_input_interrupted_returns_only_bounded_state(self):
        with patch.object(module.getpass, "getpass", side_effect=EOFError()):
            self.assertEqual(module.select_manual_pair(tty=True),
                             ("MANUAL_ESCROW_INPUT_UNAVAILABLE",None))

    def test_manual_mode_explicit_ack_required(self):
        with patch.object(module,"select_manual_pair") as reader, redirect_stderr(io.StringIO()):
            for args in (["--compare-manual"],
                         ["--compare-manual","--acknowledge","wrong"]):
                with self.assertRaises(SystemExit) as exc:
                    module.main(args)
                self.assertEqual(exc.exception.code,2)
            reader.assert_not_called()

    def test_manual_compare_does_not_print_paths_or_modify_originals(self):
        with patch.object(module, "select_manual_pair",
                return_value=("TWO_FILES_DIFFERENT_FILESYSTEMS_UNVERIFIED",(self.a,self.b))), \
             patch.object(module.os,"isatty",return_value=True), \
             patch.object(module, "compare_ciphertexts",
                return_value="ENCRYPTED_COPIES_IDENTICAL_RESTORE_UNVERIFIED") as compare, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(["--compare-manual","--acknowledge",module.ACK]),0)
        self.assertEqual(compare.call_args.args,(self.a,self.b))
        report=json.loads(out.getvalue())
        self.assertTrue(report["encrypted_content_read_attempted"])
        self.assertFalse(report["restoration_verified"])
        self.assertNotIn(str(self.a),out.getvalue())
        self.assertNotIn(str(self.b),out.getvalue())

    def test_manual_missing_tty_keeps_no_go_and_no_read(self):
        with patch.object(module.os,"isatty",return_value=False), \
             patch.object(module,"compare_ciphertexts") as cmp, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(module.main(["--compare-manual","--acknowledge",module.ACK]),3)
        cmp.assert_not_called()
        report=json.loads(out.getvalue())
        self.assertEqual(report["state"],"INTERACTIVE_TERMINAL_REQUIRED")
        self.assertFalse(report["encrypted_content_read_attempted"])


if __name__ == '__main__': unittest.main()
