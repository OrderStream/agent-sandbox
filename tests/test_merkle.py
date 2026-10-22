import json
import tempfile
import unittest
from pathlib import Path
from agent_sandbox.merkle import MerkleDAG, MerkleReceipt, sha256_hex, verify_receipt


class TestMerkleDAG(unittest.TestCase):
    def test_empty_dag_genesis(self):
        dag = MerkleDAG()
        self.assertEqual(dag.last_hash, MerkleDAG.GENESIS_HASH)
        self.assertEqual(dag.compute_root(), MerkleDAG.GENESIS_HASH)

    def test_single_event_root(self):
        dag = MerkleDAG()
        node = dag.record_event(
            action_type="command",
            target="pytest tests/",
            stdout_content="5 passed",
            exit_code=0
        )
        self.assertEqual(node.index, 0)
        self.assertEqual(node.prev_node_hash, MerkleDAG.GENESIS_HASH)
        self.assertEqual(dag.compute_root(), node.leaf_hash)

    def test_multi_event_merkle_tree(self):
        dag = MerkleDAG(policy_name="test-policy")
        dag.record_event("command", "git status", "clean", 0)
        dag.record_event("file_write", "src/code.py", "bytes=42", 0)
        dag.record_event("command", "python -m unittest", "OK", 0)

        self.assertEqual(len(dag.nodes), 3)
        root = dag.compute_root()
        self.assertNotEqual(root, MerkleDAG.GENESIS_HASH)
        self.assertEqual(len(root), 64)

    def test_receipt_generation_and_verification(self):
        dag = MerkleDAG(policy_name="strict-policy", policy_dict={"mode": "enforce"})
        dag.record_event("command", "python test.py", "OK", 0)
        dag.record_event("file_write", "output.txt", "done", 0)

        receipt = dag.generate_receipt()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            receipt.save(f.name)
            temp_path = f.name

        try:
            valid, msg = verify_receipt(temp_path)
            self.assertTrue(valid)
            self.assertIn("cryptographically valid", msg)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_receipt_tamper_detection(self):
        dag = MerkleDAG()
        dag.record_event("command", "pytest", "passed", 0)
        receipt = dag.generate_receipt()
        d = receipt.to_dict()

        # Tamper with an event target
        d["events"][0]["target"] = "curl evil.com"

        valid, msg = verify_receipt(d)
        self.assertFalse(valid)
        self.assertIn("Tampered leaf", msg)

    def test_receipt_root_tamper_detection(self):
        dag = MerkleDAG()
        dag.record_event("command", "echo test", "test", 0)
        receipt = dag.generate_receipt()
        d = receipt.to_dict()

        # Alter root
        d["merkle_root"] = "0" * 64

        valid, msg = verify_receipt(d)
        self.assertFalse(valid)
        self.assertIn("Merkle root mismatch", msg)


if __name__ == "__main__":
    unittest.main()
