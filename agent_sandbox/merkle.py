"""
Deterministic Merkle DAG: Cryptographic append-only execution log,
Merkle tree proofs, and tamper-evident audit receipts for AI agent runs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass
class MerkleNode:
    index: int
    timestamp: str
    action_type: str  # 'command', 'file_write', 'mcp_call', 'policy_block'
    target: str
    exit_code: Optional[int]
    stdout_hash: str
    pre_state_hash: str
    post_state_hash: str
    prev_node_hash: str
    is_violation: bool = False
    leaf_hash: str = ""

    def compute_leaf_hash(self) -> str:
        payload = (
            f"{self.index}:{self.timestamp}:{self.action_type}:{self.target}:"
            f"{self.exit_code}:{self.stdout_hash}:{self.pre_state_hash}:"
            f"{self.post_state_hash}:{self.prev_node_hash}:{1 if self.is_violation else 0}"
        )
        return sha256_hex(payload)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class MerkleReceipt:
    version: str
    policy_name: str
    policy_hash: str
    merkle_root: str
    total_events: int
    violations_count: int
    started_at: str
    completed_at: str
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, file_path: str | Path) -> None:
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


class MerkleDAG:
    """
    Maintains an append-only cryptographic directed acyclic graph of agent operations.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, policy_name: str = "default", policy_dict: Optional[Dict[str, Any]] = None):
        self.policy_name = policy_name
        self.policy_hash = sha256_hex(json.dumps(policy_dict or {}, sort_keys=True))
        self.nodes: List[MerkleNode] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.violations_count = 0

    @property
    def last_hash(self) -> str:
        if not self.nodes:
            return self.GENESIS_HASH
        return self.nodes[-1].leaf_hash

    def record_event(
        self,
        action_type: str,
        target: str,
        stdout_content: str = "",
        exit_code: Optional[int] = 0,
        pre_state_hash: str = "",
        post_state_hash: str = "",
        is_violation: bool = False,
    ) -> MerkleNode:
        """
        Append a deterministic event node to the audit chain.
        """
        if is_violation:
            self.violations_count += 1

        idx = len(self.nodes)
        ts = datetime.now(timezone.utc).isoformat()
        std_hash = sha256_hex(stdout_content)

        node = MerkleNode(
            index=idx,
            timestamp=ts,
            action_type=action_type,
            target=target,
            exit_code=exit_code,
            stdout_hash=std_hash,
            pre_state_hash=pre_state_hash or self.GENESIS_HASH,
            post_state_hash=post_state_hash or self.GENESIS_HASH,
            prev_node_hash=self.last_hash,
            is_violation=is_violation,
        )
        node.leaf_hash = node.compute_leaf_hash()
        self.nodes.append(node)
        return node

    def compute_root(self) -> str:
        """
        Compute the binary Merkle root across all recorded event leaf hashes.
        """
        if not self.nodes:
            return self.GENESIS_HASH

        leaves = [n.leaf_hash for n in self.nodes]
        return self._build_tree_root(leaves)

    @classmethod
    def _build_tree_root(cls, hashes: List[str]) -> str:
        if not hashes:
            return cls.GENESIS_HASH
        if len(hashes) == 1:
            return hashes[0]

        current = list(hashes)
        while len(current) > 1:
            if len(current) % 2 != 0:
                current.append(current[-1])  # Duplicate last element for balanced tree

            next_level: List[str] = []
            for i in range(0, len(current), 2):
                combined = current[i] + current[i + 1]
                next_level.append(sha256_hex(combined))
            current = next_level

        return current[0]

    def generate_receipt(self) -> MerkleReceipt:
        """
        Produce a finalized tamper-evident receipt.
        """
        return MerkleReceipt(
            version="1.0",
            policy_name=self.policy_name,
            policy_hash=self.policy_hash,
            merkle_root=self.compute_root(),
            total_events=len(self.nodes),
            violations_count=self.violations_count,
            started_at=self.started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            events=[n.to_dict() for n in self.nodes],
        )


def verify_receipt(receipt_data: str | Path | Dict[str, Any]) -> Tuple[bool, str]:
    """
    Cryptographically verify an execution receipt:
    1. Validates hash chain continuity.
    2. Recalculates leaf hashes.
    3. Reconstructs Merkle tree and matches root.
    """
    if isinstance(receipt_data, (str, Path)):
        p = Path(receipt_data)
        if not p.is_file():
            return False, f"Receipt file not found: {receipt_data}"
        data = json.loads(p.read_text(encoding="utf-8"))
    else:
        data = receipt_data

    events = data.get("events", [])
    expected_root = data.get("merkle_root", "")

    if not events:
        if expected_root == MerkleDAG.GENESIS_HASH:
            return True, "Valid empty receipt"
        return False, "Empty event list but non-genesis root"

    recomputed_leaves: List[str] = []
    prev_hash = MerkleDAG.GENESIS_HASH

    for i, ev in enumerate(events):
        node = MerkleNode(
            index=ev["index"],
            timestamp=ev["timestamp"],
            action_type=ev["action_type"],
            target=ev["target"],
            exit_code=ev.get("exit_code"),
            stdout_hash=ev["stdout_hash"],
            pre_state_hash=ev["pre_state_hash"],
            post_state_hash=ev["post_state_hash"],
            prev_node_hash=ev["prev_node_hash"],
            is_violation=ev.get("is_violation", False),
        )
        calculated_leaf = node.compute_leaf_hash()
        
        # Verify internal claim
        if calculated_leaf != ev["leaf_hash"]:
            return False, f"Tampered leaf at index {i}: claimed {ev['leaf_hash']} != calculated {calculated_leaf}"

        # Verify chain continuity
        if ev["prev_node_hash"] != prev_hash:
            return False, f"Broken chain link at index {i}: expected prev {prev_hash}, got {ev['prev_node_hash']}"

        recomputed_leaves.append(calculated_leaf)
        prev_hash = calculated_leaf

    computed_root = MerkleDAG._build_tree_root(recomputed_leaves)
    if computed_root != expected_root:
        return False, f"Merkle root mismatch! Expected {expected_root}, computed {computed_root}"

    return True, f"Receipt cryptographically valid ({len(events)} events, root: {computed_root[:16]}...)"
