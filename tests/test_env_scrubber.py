import os
import unittest
from agent_sandbox.env_scrubber import EnvironmentScrubber
from agent_sandbox.policy import Policy


class TestEnvironmentScrubber(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(
            strip_env_vars=["GITHUB_TOKEN", "AWS_SECRET_KEY", "OPENAI_API_KEY"],
            custom_redact_patterns=[r"\bCONFIDENTIAL_[A-Z0-9]+\b"]
        )
        self.scrubber = EnvironmentScrubber(self.policy)

    def test_prepare_environment_strips_secrets(self):
        mock_env = {
            "PATH": "/usr/bin",
            "HOME": "/home/user",
            "GITHUB_TOKEN": "ghp_123456789012345678901234567890123456",
            "AWS_SECRET_KEY": "supersecretkey",
            "PUBLIC_VAR": "visible"
        }
        cleaned = self.scrubber.prepare_environment(mock_env)
        self.assertIn("PATH", cleaned)
        self.assertIn("HOME", cleaned)
        self.assertIn("PUBLIC_VAR", cleaned)
        self.assertNotIn("GITHUB_TOKEN", cleaned)
        self.assertNotIn("AWS_SECRET_KEY", cleaned)
        self.assertEqual(cleaned["AGENT_SANDBOX_ACTIVE"], "1")

    def test_prepare_environment_whitelist_mode(self):
        policy = Policy(allowed_env_vars=["PATH", "CUSTOM_ALLOWED"])
        scrubber = EnvironmentScrubber(policy)
        mock_env = {
            "PATH": "/usr/bin",
            "CUSTOM_ALLOWED": "permitted",
            "RANDOM_SECRET": "strip_me"
        }
        cleaned = scrubber.prepare_environment(mock_env)
        self.assertIn("PATH", cleaned)
        self.assertIn("CUSTOM_ALLOWED", cleaned)
        self.assertNotIn("RANDOM_SECRET", cleaned)

    def test_scrub_github_tokens(self):
        raw = "Output containing ghp_111122223333444455556666777788889999 and more"
        scrubbed = self.scrubber.scrub(raw)
        self.assertNotIn("ghp_111122223333444455556666777788889999", scrubbed)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", scrubbed)

    def test_scrub_aws_keys(self):
        raw = "Connecting with key AKIAIOSFODNN7EXAMPLE to S3"
        scrubbed = self.scrubber.scrub(raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertIn("[REDACTED_AWS_KEY]", scrubbed)

    def test_scrub_ai_api_keys(self):
        raw = "Using key sk-1234567890abcdef1234567890abcdef for inference"
        scrubbed = self.scrubber.scrub(raw)
        self.assertNotIn("sk-1234567890abcdef1234567890abcdef", scrubbed)
        self.assertIn("[REDACTED_AI_API_KEY]", scrubbed)

    def test_scrub_custom_pattern(self):
        raw = "Internal id is CONFIDENTIAL_X9928"
        scrubbed = self.scrubber.scrub(raw)
        self.assertNotIn("CONFIDENTIAL_X9928", scrubbed)
        self.assertIn("[REDACTED_CUSTOM]", scrubbed)


if __name__ == "__main__":
    unittest.main()
