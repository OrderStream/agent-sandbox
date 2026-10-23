"""
Cloud Telemetry and Webhook Synchronization for agent-sandbox Enterprise.
Streams cryptographic Merkle audit receipts to centralized SaaS dashboards and security webhooks (Slack/Discord/SIEM).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple
from agent_sandbox.merkle import MerkleReceipt


CLOUD_ENDPOINT_ENV_VAR = "AGENT_SANDBOX_CLOUD_ENDPOINT"
CLOUD_API_KEY_ENV_VAR = "AGENT_SANDBOX_CLOUD_API_KEY"
WEBHOOK_URL_ENV_VAR = "AGENT_SANDBOX_SECURITY_WEBHOOK"


def push_receipt_to_cloud(
    receipt: MerkleReceipt,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
    org_id: Optional[str] = None,
    repo_name: Optional[str] = None,
    timeout_seconds: int = 10,
) -> Tuple[bool, str]:
    """
    Synchronizes a finalized Merkle receipt to the centralized SaaS dashboard.
    """
    cloud_url = endpoint or os.environ.get(CLOUD_ENDPOINT_ENV_VAR)
    key = api_key or os.environ.get(CLOUD_API_KEY_ENV_VAR)

    if not cloud_url:
        return False, "No cloud endpoint specified (set AGENT_SANDBOX_CLOUD_ENDPOINT or pass --cloud-endpoint)"

    payload = {
        "org_id": org_id or os.environ.get("GITHUB_REPOSITORY_OWNER", "unknown-org"),
        "repo": repo_name or os.environ.get("GITHUB_REPOSITORY", "unknown-repo"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local-run"),
        "receipt": receipt.to_dict(),
    }

    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "agent-sandbox-cloud-sync/1.0",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"

    req = urllib.request.Request(cloud_url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
            if 200 <= status < 300:
                return True, f"Successfully dispatched telemetry to cloud (HTTP {status}): {body[:100]}"
            return False, f"Cloud telemetry rejected with HTTP {status}: {body[:200]}"
    except urllib.error.HTTPError as exc:
        err_msg = exc.read().decode("utf-8", errors="replace")
        return False, f"Cloud sync HTTP {exc.code} error: {err_msg[:200]}"
    except Exception as exc:
        return False, f"Failed to push telemetry to cloud: {exc}"


def notify_security_webhook(
    receipt: MerkleReceipt,
    webhook_url: Optional[str] = None,
    timeout_seconds: int = 5,
) -> Tuple[bool, str]:
    """
    Dispatches a real-time security alert to Slack, Discord, or generic Webhook
    if policy violations occurred during the agent execution.
    """
    url = webhook_url or os.environ.get(WEBHOOK_URL_ENV_VAR)
    if not url:
        return False, "No webhook URL configured (set AGENT_SANDBOX_SECURITY_WEBHOOK or pass --webhook)"

    repo = os.environ.get("GITHUB_REPOSITORY", "Local Workspace")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")

    color = 15158332 if receipt.violations_count > 0 else 3066993  # Red or Green for Discord
    emoji = "🚨" if receipt.violations_count > 0 else "✅"

    slack_blocks = {
        "text": f"{emoji} agent-sandbox audit alert for {repo}: {receipt.violations_count} violation(s)",
        "attachments": [
            {
                "color": "#e74c3c" if receipt.violations_count > 0 else "#2ecc71",
                "fields": [
                    {"title": "Repository", "value": repo, "short": True},
                    {"title": "Run ID", "value": run_id, "short": True},
                    {"title": "Merkle Root", "value": f"`{receipt.merkle_root[:16]}...`", "short": True},
                    {"title": "Total Events", "value": str(receipt.total_events), "short": True},
                    {"title": "Violations", "value": str(receipt.violations_count), "short": True},
                    {"title": "Policy", "value": receipt.policy_name, "short": True},
                ],
            }
        ],
    }

    data = json.dumps(slack_blocks).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "agent-sandbox-webhook/1.0"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            return True, f"Security alert sent successfully (HTTP {response.status})"
    except Exception as exc:
        return False, f"Failed to send security webhook: {exc}"
