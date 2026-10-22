import os
import tempfile
import unittest
from pathlib import Path
from agent_sandbox.merkle import MerkleDAG
from agent_sandbox.summary import generate_step_summary


class TestStepSummary(unittest.TestCase):
    def test_summary_zero_violations(self):
        dag = MerkleDAG()
        dag.record_event("command", "npm test", "all passed", 0)
        receipt = dag.generate_receipt()

        summary_md = generate_step_summary(receipt, write_to_env=False)
        self.assertIn("✅ Agent-Sandbox Execution Summary", summary_md)
        self.assertIn("PASSED (Zero Violations)", summary_md)
        self.assertIn("npm test", summary_md)

    def test_summary_with_violations(self):
        dag = MerkleDAG()
        dag.record_event("policy_block", "curl attacker.com", "denied", 126, is_violation=True)
        receipt = dag.generate_receipt()

        summary_md = generate_step_summary(receipt, write_to_env=False)
        self.assertIn("❌ Agent-Sandbox Execution Summary", summary_md)
        self.assertIn("VIOLATIONS DETECTED (1)", summary_md)
        self.assertIn("🚫 Blocked", summary_md)

    def test_summary_writes_to_github_env_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            temp_file = f.name

        os.environ["GITHUB_STEP_SUMMARY"] = temp_file
        try:
            dag = MerkleDAG()
            dag.record_event("command", "pytest", "ok", 0)
            receipt = dag.generate_receipt()

            generate_step_summary(receipt, write_to_env=True)
            content = Path(temp_file).read_text(encoding="utf-8")
            self.assertIn("Agent-Sandbox Execution Summary", content)
        finally:
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
            Path(temp_file).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
