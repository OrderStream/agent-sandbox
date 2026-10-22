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

    # Comprehensive tool registries covering Cursor, Claude Code, OpenAI, LangChain, SWE-agent
    KNOWN_EXEC_TOOLS = {
        "execute_command", "run_command", "bash", "shell", "terminal", "exec",
        "run_terminal_command", "bash_command", "terminal_exec", "run_shell_command",
        "run_script", "subprocess_exec", "cmd", "powershell", "sh", "run"
    }
    KNOWN_WRITE_TOOLS = {
        "write_file", "edit_file", "create_file", "modify_file", "save_file",
        "append_file", "write_to_file", "replace_file_content", "patch_file", "write"
    }
    KNOWN_READ_TOOLS = {
        "read_file", "view_file", "cat_file", "get_file", "fetch_file",
        "open_file", "read", "read_file_content"
    }

    def __init__(self, sandbox_root: str = ".", policy: Optional[Policy] = None, dag: Optional[MerkleDAG] = None):
        self.policy = policy or Policy()
        self.firewall = CommandFirewall(self.policy)
        self.path_jail = PathJail(sandbox_root, self.policy)
        self.dag = dag

    @staticmethod
    def _extract_arg_value(args: Dict[str, Any], candidates: List[str]) -> str:
        """Case-insensitive candidate search in arguments dictionary."""
        lower_map = {k.lower(): v for k, v in args.items()}
        for cand in candidates:
            cand_l = cand.lower()
            if cand_l in lower_map and lower_map[cand_l]:
                val = lower_map[cand_l]
                if isinstance(val, str):
                    return val
                return str(val)
        return ""

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
        tool_name = str(params.get("name", "")).strip().lower()
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            args = {}

        # 1. Command Execution Tools
        if tool_name in self.KNOWN_EXEC_TOOLS or "command" in tool_name or "terminal" in tool_name or "exec" in tool_name:
            cmd = self._extract_arg_value(args, ["command", "commandline", "cmd", "script", "code", "input", "query"])
            decision = self.firewall.inspect(cmd)
            if not decision.allowed:
                reason = f"MCP tool call '{params.get('name')}' blocked: {'; '.join(decision.reasons)}"
                if self.dag:
                    self.dag.record_event(
                        action_type="mcp_call",
                        target=f"{params.get('name')}: {cmd}",
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
        elif tool_name in self.KNOWN_WRITE_TOOLS or "write" in tool_name or "edit" in tool_name:
            file_path = self._extract_arg_value(args, ["path", "filepath", "target", "targetfile", "file", "filename", "destination"])
            try:
                self.path_jail.inspect_write(file_path)
            except PathViolation as e:
                reason = f"MCP tool call '{params.get('name')}' blocked: {str(e)}"
                if self.dag:
                    self.dag.record_event(
                        action_type="mcp_call",
                        target=f"{params.get('name')}: {file_path}",
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
        elif tool_name in self.KNOWN_READ_TOOLS or "read" in tool_name or "view" in tool_name or "cat" in tool_name:
            file_path = self._extract_arg_value(args, ["path", "filepath", "target", "targetfile", "absolutepath", "file", "filename", "source", "uri"])
            try:
                self.path_jail.inspect_read(file_path)
            except PathViolation as e:
                reason = f"MCP tool call '{params.get('name')}' blocked: {str(e)}"
                if self.dag:
                    self.dag.record_event(
                        action_type="mcp_call",
                        target=f"{params.get('name')}: {file_path}",
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
                target=f"{params.get('name', tool_name)}",
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


def run_mcp_stdio_proxy(
    filter_instance: MCPProxyFilter,
    upstream_cmd: Optional[str | List[str]] = None,
    stdin_stream: Optional[Any] = None,
    stdout_stream: Optional[Any] = None,
) -> int:
    """
    Run the MCP proxy filter in real-time stdio mode.
    If upstream_cmd is provided, spawns the upstream MCP server as a subprocess,
    intercepts tool calls from stdin, blocks malicious calls with JSON-RPC error responses,
    and forwards compliant calls to the upstream MCP process, streaming responses back.
    If upstream_cmd is None, acts as a standalone line-by-line JSON-RPC policy validator.
    """
    import subprocess
    import sys
    from agent_sandbox.env_scrubber import EnvironmentScrubber

    in_f = stdin_stream or sys.stdin
    out_f = stdout_stream or sys.stdout
    scrubber = EnvironmentScrubber(filter_instance.policy)

    child_proc = None
    if upstream_cmd:
        clean_env = scrubber.prepare_environment()
        cmd_args = upstream_cmd if isinstance(upstream_cmd, list) else upstream_cmd.split()
        child_proc = subprocess.Popen(
            cmd_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=clean_env,
            bufsize=1,
        )

    try:
        for line in in_f:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception:
                # Forward verbatim if not valid JSON
                if child_proc and child_proc.stdin:
                    child_proc.stdin.write(line_str + "\n")
                    child_proc.stdin.flush()
                continue

            decision = filter_instance.filter_message(msg)
            if not decision.allowed:
                # Emit policy violation response immediately to client
                resp = decision.response_override or filter_instance._make_error_response(
                    msg.get("id"), -32000, decision.reason
                )
                out_f.write(json.dumps(resp) + "\n")
                out_f.flush()
            else:
                if child_proc and child_proc.stdin and child_proc.stdout:
                    # Forward compliant message to upstream server
                    child_proc.stdin.write(line_str + "\n")
                    child_proc.stdin.flush()
                    # Read response line from child
                    child_resp = child_proc.stdout.readline()
                    if child_resp:
                        scrubbed = scrubber.scrub(child_resp)
                        out_f.write(scrubbed)
                        out_f.flush()
                else:
                    # Standalone validator mode: emit OK confirmation
                    if msg.get("method") == "tools/call":
                        ok_resp = {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "result": {"status": "allowed", "agent_sandbox": "ok"}
                        }
                        out_f.write(json.dumps(ok_resp) + "\n")
                        out_f.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        if child_proc:
            try:
                child_proc.terminate()
                child_proc.wait(timeout=2)
            except Exception:
                child_proc.kill()

    return 0
