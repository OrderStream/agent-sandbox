import json
import unittest
from pathlib import Path
import tempfile
from agent_sandbox.policy import Policy, PolicyViolation, load_policy


class TestPolicy(unittest.TestCase):
    def test_default_policy(self):
        policy = Policy()
        self.assertEqual(policy.name, "default-agent-policy")
        self.assertTrue(policy.is_enforcing())
        self.assertTrue(policy.redact_secrets)
        self.assertIn("curl*", policy.denied_commands)
        self.assertIn(".github/workflows/**", policy.denied_paths)

    def test_policy_to_dict_and_from_dict(self):
        policy = Policy(name="custom-guard", mode="audit", allow_network=True)
        d = policy.to_dict()
        self.assertEqual(d["name"], "custom-guard")
        self.assertEqual(d["mode"], "audit")
        self.assertTrue(d["allow_network"])

        reloaded = Policy.from_dict(d)
        self.assertEqual(reloaded.name, "custom-guard")
        self.assertFalse(reloaded.is_enforcing())

    def test_load_policy_from_json_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            data = {"name": "json-policy", "mode": "enforce", "allowed_commands": ["python*"]}
            json.dump(data, f)
            temp_path = f.name

        try:
            policy = load_policy(temp_path)
            self.assertEqual(policy.name, "json-policy")
            self.assertEqual(policy.allowed_commands, ["python*"])
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_load_policy_from_yaml_string(self):
        import textwrap
        yaml_content = textwrap.dedent("""
        name: test-yaml
        mode: enforce
        allow_network: false
        allowed_commands:
          - "git status"
          - "pytest"
        """)
        policy = load_policy(yaml_content)
        self.assertEqual(policy.name, "test-yaml")
        self.assertIn("pytest", policy.allowed_commands)
        self.assertFalse(policy.allow_network)

    def test_policy_violation_exception(self):
        exc = PolicyViolation("test_rule", "unauthorized action", severity="critical")
        d = exc.to_dict()
        self.assertEqual(d["rule"], "test_rule")
        self.assertEqual(d["severity"], "critical")
        self.assertIn("unauthorized action", str(exc))


if __name__ == "__main__":
    unittest.main()
