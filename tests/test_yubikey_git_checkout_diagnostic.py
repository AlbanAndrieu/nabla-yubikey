"""Hermetic Git-fixture tests for the offline YubiKey checkout diagnostic."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/workstation/diagnose-age-yubikey-git-checkout.sh"
FILE = "scripts/workstation/test-age-yubikey-piv82-attestation-offline.py"


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


class YubiKeyGitCheckoutDiagnostic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nabla-yubikey-git-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Synthetic Test")
        git(self.repo, "config", "user.email", "noreply@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / FILE).parent.mkdir(parents=True)
        (self.repo / FILE).write_text("# first\n")
        git(self.repo, "add", FILE)
        git(self.repo, "commit", "-qm", "synthetic first")
        self.first = git(self.repo, "rev-parse", "HEAD")
        (self.repo / FILE).write_text("# second\n")
        git(self.repo, "add", FILE)
        git(self.repo, "commit", "-qm", "synthetic second")
        self.second = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "update-ref", "refs/remotes/origin/master", self.second)

    def check(self, *args):
        return subprocess.run(["bash", str(SCRIPT), "--repo", str(self.repo), *args],
                              capture_output=True, text=True)

    def test_detached_matching_cached_ref_is_allowed_but_not_freshness_proof(self):
        git(self.repo, "switch", "--detach", "-q", self.second)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("detached HEAD", result.stdout)
        self.assertIn("remote freshness UNKNOWN", result.stdout)
        self.assertIn("git fetch --no-tags https://", result.stdout)

    def test_stale_detached_checkout_is_rejected(self):
        git(self.repo, "switch", "--detach", "-q", self.first)
        result = self.check()
        self.assertEqual(result.returncode, 3)
        self.assertIn("behind cached origin/master", result.stderr)
        self.assertIn("git pull cannot infer branch", result.stdout)

    def test_dirty_worktree_is_rejected(self):
        (self.repo / "new-untracked.txt").write_text("synthetic only")
        result = self.check()
        self.assertEqual(result.returncode, 3)
        self.assertIn("untracked changes", result.stderr)

    def test_missing_attestation_file_is_rejected(self):
        (self.repo / FILE).unlink()
        result = self.check()
        self.assertEqual(result.returncode, 3)
        self.assertIn("attestation test missing", result.stderr)

    def test_missing_tracking_ref_is_rejected_without_network(self):
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/master")
        result = self.check()
        self.assertEqual(result.returncode, 3)
        self.assertIn("tracking ref origin/master is missing", result.stderr)

    def test_untrusted_ref_option_is_rejected(self):
        result = self.check("--ref", "--help")
        self.assertEqual(result.returncode, 2)
        self.assertIn("only an origin/* tracking ref", result.stderr)

    def test_help_is_hardware_and_network_free(self):
        result = subprocess.run(["bash", str(SCRIPT), "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("never fetches", result.stdout)


if __name__ == "__main__":
    unittest.main()
