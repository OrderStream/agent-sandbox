"""
agent-sandbox: Deterministic Zero-Trust Security Sandbox & Cryptographic Audit DAG
for Autonomous AI Agents in GitHub Actions, CI/CD, and Local Runtimes.
"""

__version__ = "0.1.0"
__author__ = "OrderStream"
__license__ = "MIT"

from agent_sandbox.policy import Policy, PolicyViolation, load_policy
from agent_sandbox.firewall import CommandFirewall, FirewallDecision
from agent_sandbox.path_jail import PathJail, PathViolation
from agent_sandbox.env_scrubber import EnvironmentScrubber
from agent_sandbox.merkle import MerkleDAG, MerkleNode, MerkleReceipt, verify_receipt
from agent_sandbox.runner import ExecutionSandbox, ExecutionResult
from agent_sandbox.mcp_proxy import MCPProxyFilter, run_mcp_stdio_proxy
from agent_sandbox.sarif import generate_sarif_report
from agent_sandbox.summary import generate_step_summary

__all__ = [
    "__version__",
    "Policy",
    "PolicyViolation",
    "load_policy",
    "CommandFirewall",
    "FirewallDecision",
    "PathJail",
    "PathViolation",
    "EnvironmentScrubber",
    "MerkleDAG",
    "MerkleNode",
    "MerkleReceipt",
    "verify_receipt",
    "ExecutionSandbox",
    "ExecutionResult",
    "MCPProxyFilter",
    "run_mcp_stdio_proxy",
    "generate_sarif_report",
    "generate_step_summary",
]
