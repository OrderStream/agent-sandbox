"""
SARIF 2.1.0 (Static Analysis Results Interchange Format) generator for agent-sandbox.
Enables native integration with GitHub Code Scanning & Security alerts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from agent_sandbox.merkle import MerkleReceipt


RULES_CATALOG = {
    "AS001": {
        "id": "AS001",
        "name": "DisallowedCommandExecuted",
        "shortDescription": {"text": "Autonomous agent attempted execution of a blocked or unapproved command"},
        "fullDescription": {"text": "Agent command did not match whitelist or matched explicit security blacklist patterns."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/OrderStream/agent-sandbox#command-firewall"
    },
    "AS002": {
        "id": "AS002",
        "name": "PathJailEscapeAttempt",
        "shortDescription": {"text": "Agent attempted filesystem access outside designated directory boundary"},
        "fullDescription": {"text": "Path traversal or unauthorized write to forbidden directories (e.g., .github/workflows or system roots) was detected."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/OrderStream/agent-sandbox#path-jail"
    },
    "AS003": {
        "id": "AS003",
        "name": "WorkflowTamperingDetected",
        "shortDescription": {"text": "Agent attempted to modify CI/CD workflows or git hooks"},
        "fullDescription": {"text": "Direct tampering with GitHub Actions workflows or git hooks is strictly prohibited to prevent pipeline hijacking."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/OrderStream/agent-sandbox#threat-model"
    },
    "AS004": {
        "id": "AS004",
        "name": "SecretExfiltrationPayload",
        "shortDescription": {"text": "Potential data exfiltration or reverse shell pattern detected"},
        "fullDescription": {"text": "Command or script matched patterns for network sockets, base64 data exfiltration, or curl secret uploads."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://github.com/OrderStream/agent-sandbox#threat-model"
    }
}


def generate_sarif_report(receipt: MerkleReceipt | Dict[str, Any], output_path: str | Path | None = None) -> Dict[str, Any]:
    """
    Transform receipt violation events into a compliant SARIF 2.1.0 log document.
    """
    data = receipt.to_dict() if isinstance(receipt, MerkleReceipt) else receipt
    events = data.get("events", [])

    sarif_results: List[Dict[str, Any]] = []

    for ev in events:
        exit_code = ev.get("exit_code")
        action = ev.get("action_type")
        target = ev.get("target", "")
        is_violation = ev.get("is_violation", False)

        if is_violation or action == "policy_block" or exit_code == 126:
            # Map to rule
            rule_id = "AS001"
            if ".github" in target or ".git" in target:
                rule_id = "AS003"
            elif any(k in target.lower() for k in ["curl", "dev/tcp", "base64", "exfil"]):
                rule_id = "AS004"
            elif any(k in target.lower() for k in ["../", "/etc", "/root"]):
                rule_id = "AS002"

            result_entry = {
                "ruleId": rule_id,
                "ruleIndex": list(RULES_CATALOG.keys()).index(rule_id),
                "level": "error",
                "message": {
                    "text": f"Agent security violation detected during '{action}' on target: {target}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target if not target.startswith(" ") else "workspace"
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "timestamp": ev.get("timestamp"),
                    "leafHash": ev.get("leaf_hash")
                }
            }
            sarif_results.append(result_entry)

    from agent_sandbox import __version__
    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-sandbox",
                        "informationUri": "https://github.com/OrderStream/agent-sandbox",
                        "semanticVersion": __version__,
                        "rules": list(RULES_CATALOG.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc
