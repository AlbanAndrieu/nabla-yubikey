"""Hermetic one-command PR-274 operator verification contract. No real network or YubiKey."""
from pathlib import Path
import os
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/workstation/run-age-yubikey-pr274-readonly.sh'
BRANCH = 'fix/homelab-operator-diagnostics-followup-20261024'


def git(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), *args], capture_output=True,
                          text=True, check=True).stdout.strip()


class IsolatedPRRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nabla-pr274-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / 'home'
        self.home.mkdir(mode=0o700)
        self.source = self.base / 'source'
        self.source.mkdir()
        git(self.source, 'init', '-q')
        git(self.source, 'config', 'user.name', 'Operator Fixture')
        git(self.source, 'config', 'user.email', 'operator@example.invalid')
        git(self.source, 'config', 'commit.gpgsign', 'false')
        self.gate = self.source / 'scripts/workstation/verify-age-yubikey-offline.sh'
        self.gate.parent.mkdir(parents=True)
        self.gate.write_text('#!/usr/bin/env bash\n'
                             '[[ "${TEST_GATE_FAIL:-0}" == 0 ]] || exit 57\n'
                             'echo "PASS: mock offline gate"\n')
        self.verify = self.source / 'scripts/workstation/verify-age-yubikey-f9-root-offline.py'
        self.verify.write_text('''#!/usr/bin/env python3
import os
import pathlib
import sys
if os.getenv('TEST_VERIFIER_FAIL') == '1':
    sys.exit(44)
assert '--expected-f9-sha256' in sys.argv
assert pathlib.Path(sys.argv[sys.argv.index('--f9') + 1]).is_file()
assert pathlib.Path(sys.argv[sys.argv.index('--root') + 1]).is_file()
pathlib.Path(os.environ['TEST_VERIFIER_TRACE']).write_text('executed')
print('PASS: synthetic offline F9 verifier invoked')
''')
        self.inspect = self.source / 'scripts/workstation/inspect-age-yubikey-f9-chain.sh'
        self.inspect.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "${TEST_F9_EXPORT_FAIL:-0}" == 0 ]] || exit 55
[[ "$1" == '--serial' && "$2" == 11110002 && "$3" == '--save-public-f9' ]]
printf 'MOCK PUBLIC CERTIFICATE\\n' > "$4"
printf 'PASS: simulated read-only public export\\n'
''')
        self.readiness = self.source / 'scripts/workstation/report-age-yubikey-piv82-readiness.py'
        self.readiness.write_text('''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
if os.getenv("TEST_READINESS_FAIL") == "1":
    sys.exit(46)
assert "--f9" in sys.argv and "--root" in sys.argv and "--json" in sys.argv
assert Path(sys.argv[sys.argv.index("--f9") + 1]).is_file()
Path(os.environ["TEST_READINESS_TRACE"]).write_text("NO-GO")
print(json.dumps({"status": "NO-GO", "hardware_mutation_authorized": False}))
''')
        self.readiness_trace = self.base / 'readiness-trace'
        self.inventory = self.source / 'scripts/workstation/inspect-age-yubikey-piv82-secondary.py'
        self.inventory.write_text('''#!/usr/bin/env python3
import json
import os
import sys
assert sys.argv[1:] == ["--serial", "11110002", "--json"]
from pathlib import Path
Path(os.environ["TEST_INVENTORY_TRACE"]).write_text("inspected public metadata")
state = "OCCUPIED" if os.getenv("TEST_INVENTORY_OCCUPIED") == "1" else "EMPTY_CONFIRMED"
print(json.dumps({"slot82": state, "status": "NO-GO", "hardware_mutation_authorized": False}))
if state == "OCCUPIED":
    sys.exit(4)
''')
        self.inventory_trace = self.base / 'inventory-trace'
        self.recovery = self.source / 'scripts/workstation/inspect-yubikey-recovery-readonly.py'
        self.recovery.write_text('''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
if os.getenv("TEST_RECOVERY_FAIL") == "1":
    sys.exit(3)
args = sys.argv[1:]
assert "--otp2-secondary" in args or ("--escrow-a" in args and "--escrow-b" in args)
Path(os.environ["TEST_RECOVERY_TRACE"]).write_text("read-only recovery")
print(json.dumps({"status": "NO-GO", "hardware_mutation_authorized": False}))
''')
        self.recovery_trace = self.base / 'recovery-trace'
        git(self.source, 'add', '.')
        git(self.source, 'commit', '-qm', 'initial fixture')
        self.original = git(self.source, 'rev-parse', 'HEAD')
        self.remote = self.base / 'remote.git'
        git(self.source, 'init', '--bare', '-q', str(self.remote))
        git(self.source, 'branch', BRANCH)
        git(self.source, 'push', '-q', str(self.remote), f'{BRANCH}:{BRANCH}')
        git(self.source, 'switch', '-q', '--detach', self.original)
        self.evidence = self.base / 'evidence'
        self.evidence.mkdir()
        (self.evidence / 'f9-11110002.pem').write_text('PUBLIC MOCK\n')
        (self.evidence / 'yubico-piv-ca-1.pem').write_text('PUBLIC MOCK ROOT\n')
        self.trace = self.base / 'trace'
        self.env = dict(os.environ, HOME=str(self.home), NABLA_YUBIKEY_TEST_MODE='1',
                        NABLA_YUBIKEY_TEST_REMOTE=str(self.remote),
                        NABLA_YUBIKEY_TEST_PYTHON=sys.executable,
                        TEST_VERIFIER_TRACE=str(self.trace),
                        TEST_READINESS_TRACE=str(self.readiness_trace),
                        TEST_INVENTORY_TRACE=str(self.inventory_trace),
                        TEST_RECOVERY_TRACE=str(self.recovery_trace))

    def run_script(self, *args, **env):
        e = dict(self.env, **{k: str(v) for k, v in env.items()})
        return subprocess.run(['bash', str(SCRIPT), '--repo', str(self.source),
                               '--evidence-dir', str(self.evidence), *args],
                              env=e, capture_output=True, text=True, timeout=20,
                              cwd=str(self.base))

    def assert_untouched(self):
        self.assertEqual(git(self.source, 'rev-parse', 'HEAD'), self.original)
        worktrees = git(self.source, 'worktree', 'list', '--porcelain')
        self.assertEqual(worktrees.count('worktree '), 1, worktrees)

    def test_one_call_from_arbitrary_directory_keeps_source_detached(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS: snapshot', result.stdout)
        self.assertIn('git pull skipped', result.stdout)
        self.assertTrue(self.trace.exists())
        self.assertTrue(self.readiness_trace.exists())
        self.assert_untouched()

    def test_preexisting_uncommitted_file_is_preserved(self):
        extra = self.source / 'user-local-note.txt'
        extra.write_text('must remain')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(extra.read_text(), 'must remain')
        self.assertIn('original checkout has changes', result.stdout)
        self.assert_untouched()

    def test_failed_gate_blocks_verifier_and_preserves_original(self):
        result = self.run_script(TEST_GATE_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('Offline gate failed', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_untouched()

    def test_invalid_remote_does_not_switch_checkout(self):
        result = self.run_script(NABLA_YUBIKEY_TEST_REMOTE=str(self.base / 'absent'))
        self.assertEqual(result.returncode, 3)
        self.assertIn('Remote branch lookup failed', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_untouched()

    def test_missing_public_f9_uses_only_public_export(self):
        (self.evidence / 'f9-11110002.pem').unlink()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('read-only export', result.stdout)
        self.assertTrue((self.evidence / 'f9-11110002.pem').exists())
        self.assert_untouched()

    def test_failed_public_export_stops_without_verifier(self):
        (self.evidence / 'f9-11110002.pem').unlink()
        result = self.run_script(TEST_F9_EXPORT_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('Read-only F9 export failed', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_untouched()

    def test_verification_failure_returns_no_go(self):
        result = self.run_script(TEST_VERIFIER_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('F9 certificate failed', result.stderr)
        self.assert_untouched()

    def test_missing_source_checkout_recovers_from_bare_cache(self):
        # Reboot can remove /tmp; the Git remote fixture remains available.
        invalid = self.base / 'unknown'
        result = self.run_script('--repo', str(invalid))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('absent after reboot', result.stdout)
        cache = self.home / '.local/share/nabla/git/nabla-compose.git'
        self.assertTrue((cache / 'HEAD').exists())
        self.assert_untouched()

    def test_repeated_run_uses_same_durable_bare_cache(self):
        self.assertEqual(self.run_script().returncode, 0)
        second = self.run_script()
        self.assertEqual(second.returncode, 0, second.stderr)
        cache = self.home / '.local/share/nabla/git/nabla-compose.git'
        registered = git(cache, 'worktree', 'list', '--porcelain')
        self.assertEqual(registered.count('worktree '), 1, registered)
        self.assert_untouched()

    def test_parallel_agents_have_separate_worktree_paths(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.run_script(), range(2)))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        snapshots = {
            line.rsplit(' at ', 1)[-1]
            for result in results
            for line in result.stdout.splitlines()
            if 'isolated PR snapshot' in line
        }
        self.assertEqual(len(snapshots), 2)
        self.assert_untouched()

    def test_readiness_failure_stops_after_valid_f9(self):
        result = self.run_script(TEST_READINESS_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('readiness report failed closed', result.stderr)
        self.assertTrue(self.trace.exists())
        self.assertFalse(self.readiness_trace.exists())
        self.assert_untouched()

    def test_default_never_uses_piv82_hardware(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.inventory_trace.exists())
        self.assert_untouched()

    def test_explicit_inventory_reads_public_metadata_only(self):
        result = self.run_script('--inventory-secondary')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"slot82": "EMPTY_CONFIRMED"', result.stdout)
        self.assertTrue(self.inventory_trace.exists())
        self.assert_untouched()

    def test_explicit_inventory_occupied_stops_fail_closed(self):
        result = self.run_script('--inventory-secondary', TEST_INVENTORY_OCCUPIED='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('"slot82": "OCCUPIED"', result.stdout)
        self.assertIn('NO-GO for provisioning', result.stderr)
        self.assert_untouched()

    def test_bootstrap_pinned_sha_skips_remote_lookup_and_fetch(self):
        # A verified caller can pass the exact commit without fetching twice.
        original = self.env["NABLA_YUBIKEY_TEST_REMOTE"]
        pinned = self.original
        result = self.run_script("--pinned-sha", pinned,
                                 NABLA_YUBIKEY_TEST_REMOTE=str(self.base / 'nonexistent'))
        self.assertEqual(result.returncode, 3)
        self.assertIn('Pinned commit missing in persistent cache', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_untouched()

    def test_pinned_sha_uses_existing_cache_offline(self):
        # Prime the isolated bare Git cache, then remove the remote.
        self.assertEqual(self.run_script().returncode, 0)
        result = self.run_script("--pinned-sha", self.original,
                                 NABLA_YUBIKEY_TEST_REMOTE=str(self.base / 'nonexistent'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The remote is deliberately unavailable: a successful run proves
        # that --pinned-sha reuses cached objects without a second lookup.
        self.assertIn('PASS: snapshot', result.stdout)
        self.assertTrue(self.trace.exists())
        self.assert_untouched()

    def test_invalid_pinned_sha_never_uses_network_or_hardware(self):
        result = self.run_script("--pinned-sha", "not-a-commit",
                                 NABLA_YUBIKEY_TEST_REMOTE=str(self.base / 'nonexistent'))
        self.assertEqual(result.returncode, 3)
        self.assertIn('must be a full 40-hex SHA', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_untouched()

    def test_runner_single_execution_path_and_syntax(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        body = SCRIPT.read_text()
        for fragment in (
            'parent="$(mktemp -d',
            'git --git-dir="$cache" worktree add --detach',
            "printf 'PASS: snapshot",
            "read -r sha ref_name <<<",
        ):
            self.assertEqual(body.count(fragment), 1, fragment)
        self.assertNotIn("IFS=\n", body)

    def test_runner_refuses_source_but_keeps_parent_alive(self):
        result = subprocess.run(
            ["bash", "-c", 'source "$1" || :; echo PARENT_ALIVE',
             "test", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PARENT_ALIVE", result.stdout)
        self.assertIn("never source", result.stderr.lower())

    def test_runner_stages_are_fail_closed_and_ordered(self):
        body = SCRIPT.read_text()
        stages = (
            'git --git-dir="$cache" cat-file -e "$sha^{commit}"',
            "worktree add --detach",
            "Offline gate failed; F9 validation not attempted",
            "Public F9 certificate failed pinned legacy-root validation",
            "Public F9 readiness report failed closed",
            "printf 'PASS: snapshot",
        )
        indexes = [body.index(fragment) for fragment in stages]
        self.assertEqual(indexes, sorted(indexes))
        self.assertIn("hardware_mutation_authorized", self.readiness.read_text())

    def test_recovery_mode_is_opt_in(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.recovery_trace.exists())
        self.assert_untouched()

    def test_otp2_mode_produces_no_go_report(self):
        result = self.run_script('--otp2-secondary')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.recovery_trace.exists())
        self.assertIn('"status": "NO-GO"', result.stdout)
        self.assert_untouched()

    def test_single_escrow_path_is_rejected_before_git_or_hardware(self):
        result = self.run_script('--escrow-a', '/tmp/one.age')
        self.assertEqual(result.returncode, 2)
        self.assertIn('escrow requires BOTH', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.recovery_trace.exists())
        self.assert_untouched()

    def test_failed_recovery_diagnostic_stops_chain(self):
        result = self.run_script('--otp2-secondary', TEST_RECOVERY_FAIL='1')
        self.assertEqual(result.returncode, 3)
        self.assertIn('recovery evidence incomplete', result.stderr)
        self.assertNotIn('PASS: snapshot', result.stdout)
        self.assert_untouched()

    def test_explicit_pr280_branch_uses_requested_ref(self):
        target = 'feat/apisix-standalone-poc-20261025'
        git(self.source, 'push', '-q', str(self.remote),
            f'{self.original}:refs/heads/{target}')
        result = self.run_script('--branch', target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS: snapshot', result.stdout)
        self.assert_untouched()

    def test_invalid_branch_fails_before_network_or_hardware(self):
        result = self.run_script('--branch', '../invalid')
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid branch name', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.recovery_trace.exists())
        self.assert_untouched()

    def test_explicit_branch_ref_missing_fails_closed(self):
        result = self.run_script('--branch', 'feat/not-created-20261025')
        self.assertEqual(result.returncode, 3)
        self.assertIn('Remote branch lookup failed', result.stderr)
        self.assertFalse(self.trace.exists())
        self.assert_untouched()

    def test_help_does_not_contact_git_or_hardware(self):
        result = subprocess.run(['bash', str(SCRIPT), '--help'], cwd=str(self.base),
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        # Help describes the supported interface, not a deprecated /tmp checkout.
        self.assertIn('--pinned-sha SHA', result.stdout)
        self.assertIn('--branch NAME', result.stdout)
        self.assertIn('--inventory-secondary', result.stdout)
        self.assertNotIn('/tmp/nabla-yubikey-pr259', result.stdout)
        self.assertFalse(self.trace.exists())


if __name__ == '__main__':
    unittest.main()
