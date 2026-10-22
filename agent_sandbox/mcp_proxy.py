"""
Model Context Protocol (MCP) Security Filter:
Intercepts JSON-RPC 2.0 tool calls in-flight, evaluating parameters against
security policy before execution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from agent_sandbox.firewall import CommandFirewall
from agent_sandbox.merkle import MerkleDAG
from agent_sandbox.path_jail import PathJail, PathViolation
from agent_sandbox.policy import Policy, PolicyViolation


@dataclass
class FilterResult:
    allowed: bool
    response_override: Optional[Dict[str, Any]] = None
    reason: str = ""


class MCPProxyFilter:
    """
    Middleware filter for Model Context Protocol (MCP) JSON-RPC tool requests.
    """

    KNOWN_EXEC_TOOLS = {"execute_command", "run_command", "bash", "shell", "terminal", "exec"}
    KNOWN_WRITE_TOOLS = {"write_file", "edit_file", "create_file", "modify_file", "save_file", "append_file"}
    KNOWN_READ_TOOLS = {"read_file", "view_file", "cat_file", "get_file", "fetch_file"}

    def __init__(self, sandbox_root: str = ".", policy: Optional[Policy] = None, dag: Optional[MerkleDAG] = None):
        self.policy = policy or Policy()
        self.firewall = CommandFirewall(self.policy)
        self.path_jail = PathJail(sandbox_root, self.policy)
        self.dag = dag

    def filter_message(self, message: Dict[str, Any] | str) -> FilterResult:
        """
        Inspect an incoming JSON-RPC message.
        If compliant, returns FilterResult(allowed=True).
        If non-compliant, returns FilterResult(allowed=False, response_override={...}).
        """
        if isinstance(message, str):
            try:
                data = json.loads(message)
            except Exception:
                return FilterResult(allowed=True)
        else:
            data = message

        # Only filter tools/call methods
        method = data.get("method")
        msg_id = data.get("id")

        if method != "tools/call":
            return FilterResult(allowed=True)

        params = data.get("params", {})
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        # 1. Command Execution Tools
        if tool_name in self.KNOWN_EXEC_TOOLS:
            cmd = args.get("command") or args.get("cmd") or args.get("script") or ""
            decision = self.firewall.inspect(str(cmd))
            if not decision.allowed:
                reason = f"MCP tool call '{tool_name}' blocked: {'; '.join(decision.reasons)}"
                if self.dag:
                    self.dag.record_event(
                        action_type="mcp_call",
                        target=f"{tool_name}: {cmd}",
                        stdout_content=reason,
                        exit_code=126,
                        is_violation=True,
                    )
                return FilterResult(
                    allowed=False,
                    reason=reason,
                    response_override=self._make_error_response(msg_id, -32001, reason),
                )

        # 2. File Write Tools
        elif tool_name in self.KNOWN_WRITE_TOOLS:
            file_path = args.get("path") or args.get("file_path") or args.get("target") or ""
            try:
                self.path_jail.inspect_write(str(file_path))
            except PathViolation as e:
                reason = f"MCP tool call '{tool_name}' blocked: {str(e)}"
                if self.dag:
                    self.dag.record_event(
                        action_type="mcp_call",
                        target=f"{tool_name}: {file_path}",
                        stdout_content=reason,
                        exit_code=126,
                        is_violation=True,
                    )
                return FilterResult(
                    allowed=False,
                    reason=reason,
                    response_override=self._make_error_response(msg_id, -32002, reason),
                )

        # 3. File Read Tools
        elif tool_name in self.KNOWN_READ_TOOLS:
            file_path = args.get("path") or args.get("file_path") or args.get("target") or ""
            try:
                self.path_jail.inspect_read(str(file_path))
            except PathViolation as e:
                reason = f"MCP tool call '{tool_name}' blocked: {str(e)}"
                if self.dag:
                    self.dag.record_event(
                        action_type="mcp_call",
                        target=f"{tool_name}: {file_path}",
                        stdout_content=reason,
                        exit_code=126,
                        is_violation=True,
                    )
                return FilterResult(
                    allowed=False,
                    reason=reason,
                    response_override=self._make_error_response(msg_id, -32003, reason),
                )

        # Record compliant event
        if self.dag:
            self.dag.record_event(
                action_type="mcp_call",
                target=f"{tool_name}",
                stdout_content=json.dumps(args),
                exit_code=0,
                is_violation=False,
            )

        return FilterResult(allowed=True)

    @staticmethod
    def _make_error_response(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message,
                "data": {"blocked_by": "agent-sandbox", "type": "PolicyViolation"}
            }
        }
