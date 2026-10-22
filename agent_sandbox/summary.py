"""
GitHub Actions Step Summary ($GITHUB_STEP_SUMMARY) generator for agent-sandbox.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List
from agent_sandbox.merkle import MerkleReceipt


def generate_step_summary(
    receipt: MerkleReceipt | Dict[str, Any],
    write_to_env: bool = True
) -> str:
    """
    Format execution results into GitHub Actions Markdown step summary.
    """
    data = receipt.to_dict() if isinstance(receipt, MerkleReceipt) else receipt
    events: List[Dict[str, Any]] = data.get("events", [])
    violations = data.get("violations_count", 0)
    merkle_root = data.get("merkle_root", "")
    policy_name = data.get("policy_name", "default")
    
    status_icon = "✅" if violations == 0 else "❌"
    status_text = "PASSED (Zero Violations)" if violations == 0 else f"VIOLATIONS DETECTED ({violations})"

    md_lines = [
        f"## {status_icon} Agent-Sandbox Execution Summary",
        "",
        f"- **Security Status**: `{status_text}`",
        f"- **Active Policy**: `{policy_name}`",
        f"- **Cryptographic Merkle Root**: `{merkle_root}`",
        f"- **Total Action Events**: `{len(events)}`",
        f"- **Start Time**: `{data.get('started_at', 'N/A')}`",
        f"- **End Time**: `{data.get('completed_at', 'N/A')}`",
        "",
        "### 📜 Action Audit Trail",
        "",
        "| # | Type | Target / Command | Exit Code | Leaf Hash | Status |",
        "|---|------|------------------|-----------|-----------|--------|"
    ]

    for ev in events:
        idx = ev.get("index", 0)
        atype = ev.get("action_type", "")
        target = ev.get("target", "").replace("|", "\\|")
        if len(target) > 50:
            target = target[:47] + "..."
        exit_code = ev.get("exit_code")
        leaf = ev.get("leaf_hash", "")[:12] + "..."
        
        is_violation = ev.get("is_violation", False)
        if atype == "policy_block" or exit_code == 126 or is_violation:
            item_status = "🚫 Blocked" if (atype == "policy_block" or exit_code == 126) else "⚠️ Violation"
        elif exit_code == 0:
            item_status = "🟢 Allowed"
        else:
            item_status = f"🟡 Code {exit_code}"

        md_lines.append(f"| {idx} | `{atype}` | `{target}` | `{exit_code}` | `{leaf}` | {item_status} |")

    md_lines.append("")
    if violations > 0:
        md_lines.extend([
            "> [!CAUTION]",
            f"> **{violations} Policy Violations were intercepted!**",
            "> Check the detailed SARIF log or workflow logs for blocked parameters."
        ])
    else:
        md_lines.extend([
            "> [!NOTE]",
            "> All autonomous agent tool calls executed within verified security boundaries."
        ])

    summary_md = "\n".join(md_lines) + "\n"

    # Write to GITHUB_STEP_SUMMARY environment file if running in GitHub Actions
    if write_to_env:
        step_summary_file = os.getenv("GITHUB_STEP_SUMMARY")
        if step_summary_file:
            try:
                with open(step_summary_file, "a", encoding="utf-8") as f:
                    f.write(summary_md)
            except Exception:
                pass

    return summary_md
