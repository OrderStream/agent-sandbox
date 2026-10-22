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


if __name__ == "__main__":
    unittest.main()
