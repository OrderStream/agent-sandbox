import json
import sys
import tempfile
import unittest
from pathlib import Path
from agent_sandbox.cli import main


class TestCLI(unittest.TestCase):
    def test_help_command(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_init_command(self):
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "test-policy.yaml"
            code = main(["init", "--output", str(policy_file)])
            self.assertEqual(code, 0)
            self.assertTrue(policy_file.is_file())
            content = policy_file.read_text(encoding="utf-8")
            self.assertIn("github-actions-agent-guard", content)

    def test_inspect_command_allowed_and_denied(self):
        code_allowed = main(["inspect", "pytest tests/"])
        self.assertEqual(code_allowed, 0)

        code_denied = main(["inspect", "curl http://leak.com"])
        self.assertEqual(code_denied, 2)

    def test_exec_verify_lifecycle(self):
        with tempfile.TemporaryDirectory() as td:
            receipt_path = Path(td) / "receipt.json"
            sarif_path = Path(td) / "audit.sarif"

            # Execute safe command
            code = main([
                "exec",
                "--receipt", str(receipt_path),
                "--sarif", str(sarif_path),
                "--summary",
                "--",
                sys.executable, "-c", "print('cli_lifecycle_success')"
            ])
            self.assertEqual(code, 0)
            self.assertTrue(receipt_path.is_file())
            self.assertTrue(sarif_path.is_file())

            # Verify receipt
            v_code = main(["verify", str(receipt_path)])
            self.assertEqual(v_code, 0)

            # Tamper receipt and verify it fails
            receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_data["events"][0]["exit_code"] = 999
            receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")

            bad_v_code = main(["verify", str(receipt_path)])
            self.assertEqual(bad_v_code, 2)

    def test_exec_single_command_string(self):
        # Regression test for single-string commands with spaces passed via CI/CD
        code = main([
            "exec",
            "--",
            f"{sys.executable} -c print('single_string_ok')"
        ])
        self.assertEqual(code, 0)

    def test_mcp_cli_help(self):
        with self.assertRaises(SystemExit) as cm:
            main(["mcp", "--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
