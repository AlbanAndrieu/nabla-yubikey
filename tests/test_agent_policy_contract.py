"""Read-only checks for YubiKey agent policy; hardware-independent."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AgentPolicyContract(unittest.TestCase):
    def test_hardware_and_secret_guards(self):
        doc = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for marker in ("PIN/PUK/PIV", "authorized_keys", "BW_SESSION",
                       "AGENT_EXECUTION_MODE=offline",
                       "AGENT_EXECUTION_MODE=workstation",
                       "NOT_RUN", "nabla-compose", "ansible-workstation"):
            with self.subTest(marker=marker):
                self.assertIn(marker, doc)

    def test_pr_reuse_and_batch(self):
        doc = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
        for marker in ("open prs", "reuse the compatible pr",
                       "before editing", "coherent tested batch",
                       "cross-service migration", "never commit directly"):
            with self.subTest(marker=marker):
                self.assertIn(marker, doc)

    def test_small_claude_adapter(self):
        doc = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn("@AGENTS.md", doc)
        self.assertLessEqual(len(doc.splitlines()), 16)
        self.assertTrue((ROOT / "docs/agent-pr-workflow.md").is_file())


if __name__ == "__main__":
    unittest.main()
