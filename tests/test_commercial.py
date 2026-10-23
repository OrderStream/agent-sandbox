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


if __name__ == "__main__":
    unittest.main()
