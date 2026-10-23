import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from agent_sandbox.cli import main
from agent_sandbox.license import generate_license_key, verify_license_key, LicenseInfo
from agent_sandbox.cloud_sync import push_receipt_to_cloud, notify_security_webhook
from agent_sandbox.merkle import MerkleReceipt


class TestCommercialLicenseAndCloud(unittest.TestCase):
    def test_license_generation_and_verification(self):
        secret = "super-secret-company-key"
        key = generate_license_key(
            customer_id="acme_corp_123",
            tier="enterprise",
            seats=50,
            expires_in_days=30,
            org_domain="acme.org",
            signing_secret=secret,
        )
        self.assertTrue(key.startswith("ASL1."))

        valid, info, msg = verify_license_key(key, signing_secret=secret)
        self.assertTrue(valid)
        self.assertIsNotNone(info)
        self.assertEqual(info.customer_id, "acme_corp_123")
        self.assertEqual(info.tier, "enterprise")
        self.assertEqual(info.seats, 50)
        self.assertTrue(info.is_enterprise)
        self.assertFalse(info.is_expired)

    def test_license_tampering_fails(self):
        secret = "super-secret-company-key"
        key = generate_license_key(
            customer_id="hacker_attempt",
            tier="starter",
            seats=1,
            expires_in_days=10,
            org_domain="target.com",
            signing_secret=secret,
        )
        parts = key.split(".")
        # Tamper payload
        tampered_key = f"{parts[0]}.{parts[1]}xyz.{parts[2]}"
        valid, info, msg = verify_license_key(tampered_key, signing_secret=secret)
        self.assertFalse(valid)
        self.assertIn("signature mismatch", msg.lower())

    def test_license_cli_subcommand(self):
        secret = "test-secret"
        key = generate_license_key(
            customer_id="dev_team",
            tier="pro",
            seats=20,
            expires_in_days=15,
            org_domain="example.io",
            signing_secret=secret,
        )
        os.environ["AGENT_SANDBOX_LICENSE_SECRET"] = secret
        try:
            exit_code = main(["license", key])
            self.assertEqual(exit_code, 0)

            # Test invalid key
            bad_exit = main(["license", "invalid.key.value"])
            self.assertEqual(bad_exit, 2)
        finally:
            os.environ.pop("AGENT_SANDBOX_LICENSE_SECRET", None)

    def test_cloud_sync_telemetry_missing_endpoint(self):
        receipt = MerkleReceipt(
            version="1.0",
            policy_name="test",
            policy_hash="abc",
            merkle_root="def",
            total_events=5,
            violations_count=0,
            started_at="2026-10-23T00:00:00Z",
            completed_at="2026-10-23T00:00:01Z",
        )
        # Without endpoint configured, should return failure gracefully without crashing
        ok, msg = push_receipt_to_cloud(receipt, endpoint="")
        self.assertFalse(ok)
        self.assertIn("No cloud endpoint specified", msg)


    def test_default_salt_license_generation_and_features(self):
        # Generate with default secret
        key = generate_license_key(
            customer_id="default_corp",
            tier="enterprise",
            seats=10,
            expires_in_days=30,
            org_domain="default.com",
            features=["custom_feature_1", "merkle_365d"],
        )
        valid, info, msg = verify_license_key(key)
        self.assertTrue(valid)
        self.assertIsNotNone(info)
        self.assertTrue(info.has_feature("custom_feature_1"))
        self.assertFalse(info.has_feature("non_existent_feature"))

    def test_expired_license_key(self):
        # Expired license (-1 days)
        key = generate_license_key(
            customer_id="expired_corp",
            tier="starter",
            seats=1,
            expires_in_days=-1,
            org_domain="expired.com",
        )
        valid, info, msg = verify_license_key(key)
        self.assertFalse(valid)
        self.assertTrue(info.is_expired)
        self.assertIn("expired", msg.lower())

    def test_dual_authorization_human_approval_gate(self):
        from agent_sandbox.policy import Policy
        from agent_sandbox.runner import ExecutionSandbox

        # Policy with require_human_approval = True
        policy = Policy(
            name="approval-test",
            require_human_approval=True,
            mode="enforce",
        )
        sandbox = ExecutionSandbox(policy=policy)

        # 1. Without approval token, execution must be blocked with exit code 126
        os.environ.pop("AGENT_SANDBOX_APPROVAL_TOKEN", None)
        result = sandbox.run_command("git status")
        self.assertTrue(result.blocked)
        self.assertEqual(result.exit_code, 126)
        self.assertTrue(any("Dual-authorization required" in v for v in result.violations))

        # 2. With approval token set, execution proceeds
        os.environ["AGENT_SANDBOX_APPROVAL_TOKEN"] = "token-admin-12345"
        try:
            result_approved = sandbox.run_command("git status")
            self.assertFalse(result_approved.blocked)
            self.assertEqual(result_approved.exit_code, 0)
        finally:
            os.environ.pop("AGENT_SANDBOX_APPROVAL_TOKEN", None)

    def test_cli_exec_license_verification_enforcement(self):
        # Invalid license passed to CLI exec must halt execution with 126
        exit_code = main(["exec", "--license-key", "invalid.license.signature", "--", "git", "status"])
        self.assertEqual(exit_code, 126)

        # Valid license passes
        valid_key = generate_license_key(
            customer_id="valid_cli",
            tier="pro",
            seats=5,
            expires_in_days=30,
            org_domain="valid.io",
        )
        exit_ok = main(["exec", "--license-key", valid_key, "--", "git", "status"])
        self.assertEqual(exit_ok, 0)

    def test_cloud_server_query_routing_and_auth(self):
        from agent_sandbox.cloud_server import CloudDashboardHandler, GLOBAL_STORE
        import io

        class DummyWFile:
            def __init__(self):
                self.data = bytearray()
            def write(self, b):
                self.data.extend(b)

        # Verify that URL routing works even with query string
        handler = CloudDashboardHandler.__new__(CloudDashboardHandler)
        handler.headers = {}
        handler.wfile = DummyWFile()
        handler.send_response = lambda code: None
        handler.send_header = lambda k, v: None
        handler.end_headers = lambda: None

        # Test query parameter on /api/v1/telemetry
        handler.path = "/api/v1/telemetry?filter=all&limit=10"
        handler.do_GET()
        res_json = json.loads(handler.wfile.data.decode("utf-8"))
        self.assertEqual(res_json.get("status"), "healthy")

        # Test API key authentication in do_POST
        os.environ["AGENT_SANDBOX_CLOUD_API_KEY"] = "secret-dashboard-key"
        try:
            post_handler = CloudDashboardHandler.__new__(CloudDashboardHandler)
            post_handler.path = "/api/v1/telemetry"
            post_handler.headers = {"Authorization": "Bearer wrong-key", "Content-Length": "2"}
            post_handler.wfile = DummyWFile()
            post_handler.rfile = io.BytesIO(b"{}")
            post_handler.send_response = lambda code: setattr(post_handler, "last_code", code)
            post_handler.send_header = lambda k, v: None
            post_handler.end_headers = lambda: None

            post_handler.do_POST()
            self.assertEqual(getattr(post_handler, "last_code", None), 401)
        finally:
            os.environ.pop("AGENT_SANDBOX_CLOUD_API_KEY", None)


if __name__ == "__main__":
    unittest.main()
