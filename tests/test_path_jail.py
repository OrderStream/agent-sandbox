import tempfile
import unittest
from pathlib import Path
from agent_sandbox.path_jail import PathJail, PathViolation
from agent_sandbox.policy import Policy


class TestPathJail(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        
        # Create dummy structure
        (self.root / "src").mkdir()
        (self.root / "src" / "main.py").write_text("print('hello')", encoding="utf-8")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_main.py").write_text("assert True", encoding="utf-8")
        (self.root / ".github" / "workflows").mkdir(parents=True)
        (self.root / ".github" / "workflows" / "ci.yml").write_text("name: CI", encoding="utf-8")
        (self.root / ".env").write_text("SECRET=12345", encoding="utf-8")

        self.policy = Policy(
            allowed_paths_read=["**"],
            allowed_paths_write=["src/**", "tests/**", "*.txt"],
            denied_paths=[".github/workflows/**", "**/.env*", "/etc/**"]
        )
        self.jail = PathJail(self.root, self.policy)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_allowed_read(self):
        # Reading src/main.py is permitted
        self.jail.inspect_read("src/main.py")

    def test_denied_read_sensitive_file(self):
        with self.assertRaises(PathViolation) as cm:
            self.jail.inspect_read(".env")
        self.assertIn("Matches forbidden path pattern", str(cm.exception))

    def test_allowed_write(self):
        self.jail.inspect_write("src/utils.py")
        self.jail.inspect_write("tests/test_utils.py")
        self.jail.inspect_write("notes.txt")

    def test_denied_write_workflow_tampering(self):
        with self.assertRaises(PathViolation) as cm:
            self.jail.inspect_write(".github/workflows/ci.yml")
        self.assertIn(".github/workflows/**", str(cm.exception))

    def test_denied_write_outside_whitelist(self):
        with self.assertRaises(PathViolation) as cm:
            self.jail.inspect_write("dangerous_script.sh")
        self.assertIn("not in allowed_paths_write", str(cm.exception).lower())

    def test_directory_traversal_escape(self):
        with self.assertRaises(PathViolation) as cm:
            self.jail.inspect_read("../../etc/passwd")
        self.assertIn("outside root directory", str(cm.exception))

    def test_workspace_snapshot_and_diff(self):
        pre_snap = self.jail.snapshot_workspace()
        self.assertIn("src/main.py", pre_snap)

        # Modify a file and add a file
        (self.root / "src" / "main.py").write_text("print('updated')", encoding="utf-8")
        (self.root / "src" / "helper.py").write_text("# new helper", encoding="utf-8")

        diff = self.jail.diff_workspace(pre_snap)
        self.assertEqual(diff.modified, ["src/main.py"])
        self.assertEqual(diff.added, ["src/helper.py"])
        self.assertEqual(diff.deleted, [])
        self.assertTrue(diff.has_changes)

        # Verification of legitimate changes passes
        violations = self.jail.verify_diff(diff)
        self.assertEqual(len(violations), 0)

    def test_workspace_diff_catches_unauthorized_write(self):
        pre_snap = self.jail.snapshot_workspace()

        # Add unauthorized file
        (self.root / "unauthorized.bin").write_text("malware", encoding="utf-8")
        diff = self.jail.diff_workspace(pre_snap)

        violations = self.jail.verify_diff(diff)
        self.assertEqual(len(violations), 1)
        self.assertIn("unauthorized.bin", violations[0])

    def test_workspace_diff_catches_denied_path_tampering(self):
        pre_snap = self.jail.snapshot_workspace()
        self.assertIn(".github/workflows/ci.yml", pre_snap)

        # Malicious workflow tampering
        (self.root / ".github" / "workflows" / "ci.yml").write_text("name: Backdoor", encoding="utf-8")
        diff = self.jail.diff_workspace(pre_snap)
        self.assertIn(".github/workflows/ci.yml", diff.modified)

        violations = self.jail.verify_diff(diff)
        self.assertGreaterEqual(len(violations), 1)
        self.assertTrue(any(".github/workflows/**" in v for v in violations))

    def test_explicit_paths_diff(self):
        target = self.root / "src" / "explicit.py"
        pre_snap = self.jail.snapshot_workspace(explicit_paths=[target])
        self.assertEqual(len(pre_snap), 0)

        target.write_text("x = 1", encoding="utf-8")
        post_snap = self.jail.snapshot_workspace(explicit_paths=[target])
        self.assertIn("src/explicit.py", post_snap)

        diff = self.jail.diff_workspace(pre_snap, post_snapshot=post_snap)
        self.assertEqual(diff.added, ["src/explicit.py"])
        self.assertEqual(len(self.jail.verify_diff(diff)), 0)

    def test_read_only_policy_snapshot(self):
        ro_policy = Policy(allowed_paths_read=["**"], allowed_paths_write=[])
        ro_jail = PathJail(self.root, ro_policy)
        snap = ro_jail.snapshot_workspace()
        # Should not walk internal directories, only root files or denied files
        self.assertNotIn("src/main.py", snap)


if __name__ == "__main__":
    unittest.main()

