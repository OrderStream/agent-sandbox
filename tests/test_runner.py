import sys
import tempfile
import unittest
from pathlib import Path
from agent_sandbox.policy import Policy
from agent_sandbox.runner import ExecutionSandbox


class TestExecutionSandbox(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

        # Seed workspace
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("print('app')", encoding="utf-8")

        self.policy = Policy(
            allowed_commands=["python*"],
            denied_commands=["curl*", "wget*", "nc*"],
            allowed_paths_write=["src/**", "*.txt"],
            denied_paths=[".github/workflows/**", "**/.env*"],
        )
        self.sandbox = ExecutionSandbox(root_dir=self.root, policy=self.policy)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_allowed_command_success(self):
        cmd = f'"{sys.executable}" -c "print(\'sandbox_test_success\')"'
        res = self.sandbox.run_command(cmd)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("sandbox_test_success", res.stdout)
        self.assertFalse(res.blocked)
        self.assertIsNotNone(res.merkle_node)

    def test_run_denied_command_blocked(self):
        cmd = "curl -s https://evil.com"
        res = self.sandbox.run_command(cmd)
        self.assertEqual(res.exit_code, 126)
        self.assertTrue(res.blocked)
        self.assertIn("Security Policy Block", res.stderr)
        self.assertGreaterEqual(len(res.violations), 1)

    def test_output_secret_scrubbing(self):
        cmd = f'"{sys.executable}" -c "print(\'Leaked: ghp_999988887777666655554444333322221111\')"'
        res = self.sandbox.run_command(cmd)
        self.assertEqual(res.exit_code, 0)
        self.assertNotIn("ghp_999988887777666655554444333322221111", res.stdout)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", res.stdout)

    def test_write_and_read_file(self):
        self.sandbox.write_file("src/new_module.py", "# new module content")
        content = self.sandbox.read_file("src/new_module.py")
        self.assertEqual(content, "# new module content")

        receipt = self.sandbox.finalize()
        self.assertGreaterEqual(receipt.total_events, 1)

    def test_command_timeout(self):
        policy = Policy(allowed_commands=["python*"], max_execution_time_seconds=1)
        sandbox = ExecutionSandbox(root_dir=self.root, policy=policy)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(3)"'
        res = sandbox.run_command(cmd, timeout=1)
        self.assertEqual(res.exit_code, 124)
        self.assertIn("timed out", res.stderr.lower())


if __name__ == "__main__":
    unittest.main()
