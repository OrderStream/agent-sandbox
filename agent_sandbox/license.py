"""
Commercial Open-Core License Verification Engine for agent-sandbox Enterprise.
Validates HMAC-SHA256 signed license keys without requiring external network calls.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


ENTERPRISE_SECRET_ENV_VAR = "AGENT_SANDBOX_LICENSE_SECRET"
DEFAULT_PUBLIC_SALT = "agent-sandbox-core-ent-v1"


@dataclass
class LicenseInfo:
    customer_id: str
    tier: str  # "starter", "pro", "enterprise"
    seats: int
    expires_at: int  # Unix timestamp
    org_domain: str
    features: list[str]

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_enterprise(self) -> bool:
        return self.tier.lower() in ("pro", "enterprise")


def generate_license_key(
    customer_id: str,
    tier: str,
    seats: int,
    expires_in_days: int,
    org_domain: str,
    signing_secret: str,
    features: Optional[list[str]] = None,
) -> str:
    """
    Generates an enterprise license key signed with HMAC-SHA256.
    Format: ASL1.<payload_b64>.<signature_hex>
    """
    if features is None:
        features = ["merkle_retention_365d", "multi_repo_sync", "sso_auth_gate", "slack_alerts"]
    
    expires_at = int(time.time()) + (expires_in_days * 86400)
    payload_dict = {
        "cid": customer_id,
        "tier": tier,
        "seats": seats,
        "exp": expires_at,
        "org": org_domain,
        "feat": features,
    }
    payload_json = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")

    sig = hmac.new(
        signing_secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"ASL1.{payload_b64}.{sig}"


def verify_license_key(
    license_key: str,
    signing_secret: Optional[str] = None,
) -> Tuple[bool, Optional[LicenseInfo], str]:
    """
    Verifies a commercial license key.
    Returns (is_valid, license_info, error_message).
    """
    if not license_key or not isinstance(license_key, str):
        return False, None, "License key is missing or empty"

    parts = license_key.strip().split(".")
    if len(parts) != 3 or parts[0] != "ASL1":
        return False, None, "Invalid license key format (must start with ASL1.<payload>.<signature>)"

    _, payload_b64, signature = parts

    secret = signing_secret or os.environ.get(ENTERPRISE_SECRET_ENV_VAR, DEFAULT_PUBLIC_SALT)
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return False, None, "License signature mismatch or corrupted key"

    try:
        # urlsafe_b64decode requires padding
        padding = 4 - (len(payload_b64) % 4)
        if padding < 4:
            payload_b64 += "=" * padding
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)
    except Exception as exc:
        return False, None, f"Failed to decode license payload: {exc}"

    info = LicenseInfo(
        customer_id=payload.get("cid", "unknown"),
        tier=payload.get("tier", "starter"),
        seats=int(payload.get("seats", 1)),
        expires_at=int(payload.get("exp", 0)),
        org_domain=payload.get("org", "example.com"),
        features=payload.get("feat", []),
    )

    if info.is_expired:
        return False, info, f"License expired on {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(info.expires_at))}"

    return True, info, "License is active and valid"
