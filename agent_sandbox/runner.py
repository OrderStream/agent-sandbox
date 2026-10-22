"""
Execution Sandbox: Orchestrates command firewalling, path containment,
environment scrubbing, process confinement, and Merkle audit logging.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from agent_sandbox.env_scrubber import EnvironmentScrubber
from agent_sandbox.firewall import CommandFirewall, FirewallDecision
from agent_sandbox.merkle import MerkleDAG, MerkleNode, MerkleReceipt, sha256_hex
from agent_sandbox.path_jail import FileDiff, PathJail, PathViolation
from agent_sandbox.policy import Policy, PolicyViolation


@dataclass
class ExecutionResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    diff: FileDiff = field(default_factory=FileDiff)
    violations: List[str] = field(default_factory=list)
    merkle_node: Optional[MerkleNode] = None
    blocked: bool = False

    @property
    def is_success(self) -> bool:
        return self.exit_code == 0 and not self.blocked and len(self.violations) == 0


class ExecutionSandbox:
    """
    Zero-trust execution sandbox confining autonomous agent tool calls and commands.
    """

    def __init__(self, root_dir: str | Path = ".", policy: Optional[Policy] = None):
        self.root_dir = Path(root_dir).resolve()
        self.policy = policy or Policy()
        
        self.firewall = CommandFirewall(self.policy)
        self.path_jail = PathJail(self.root_dir, self.policy)
        self.scrubber = EnvironmentScrubber(self.policy)
        self.dag = MerkleDAG(policy_name=self.policy.name, policy_dict=self.policy.to_dict())

    def run_command(self, command: str, timeout: Optional[int] = None) -> ExecutionResult:
        """
        Execute a command within sandbox constraints, capturing output and state transitions.
        """
        start_time = time.perf_counter()
        t_limit = timeout or self.policy.max_execution_time_seconds
        violations: List[str] = []

        # 1. Static AST Firewall Inspection
        decision: FirewallDecision = self.firewall.inspect(command)
        if not decision.allowed:
            violations.extend(decision.reasons)
            if self.policy.is_enforcing():
                # Block immediately
                node = self.dag.record_event(
                    action_type="policy_block",
                    target=command,
                    stdout_content="; ".join(decision.reasons),
                    exit_code=126,
                    is_violation=True,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000
                return ExecutionResult(
                    command=command,
                    exit_code=126,
                    stdout="",
                    stderr=f"Security Policy Block: {'; '.join(decision.reasons)}",
                    duration_ms=duration_ms,
                    violations=violations,
                    merkle_node=node,
                    blocked=True,
                )

        # 2. Workspace Pre-execution Snapshot
        pre_snapshot = self.path_jail.snapshot_workspace()
        pre_hash = sha256_hex(json.dumps(pre_snapshot, sort_keys=True))

        # 3. Environment Sanitization
        clean_env = self.scrubber.prepare_environment()

        # 4. Process Execution
        stdout_raw = ""
        stderr_raw = ""
        exit_code = 0

        try:
            # We execute commands through shell so aliases, pipes, and scripts run as expected,
            # but only after AST-level inspection and environment isolation.
            proc = subprocess.run(
                command,
                cwd=str(self.root_dir),
                shell=True,
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=t_limit,
                errors="replace",
            )
            stdout_raw = proc.stdout
            stderr_raw = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
            stderr_raw = f"Command timed out after {t_limit} seconds."
            violations.append(f"Execution timeout ({t_limit}s exceeded)")
        except Exception as e:
            exit_code = 1
            stderr_raw = f"Sandbox execution error: {str(e)}"
            violations.append(f"Subprocess spawn failure: {str(e)}")

        duration_ms = (time.perf_counter() - start_time) * 1000

        # 5. Output Truncation & Secret Scrubbing
        max_bytes = self.policy.max_output_bytes
        if len(stdout_raw.encode("utf-8", errors="replace")) > max_bytes:
            stdout_raw = stdout_raw[:max_bytes] + "\n...[OUTPUT TRUNCATED BY AGENT-SANDBOX]"
        if len(stderr_raw.encode("utf-8", errors="replace")) > max_bytes:
            stderr_raw = stderr_raw[:max_bytes] + "\n...[STDERR TRUNCATED BY AGENT-SANDBOX]"

        clean_stdout = self.scrubber.scrub(stdout_raw)
        clean_stderr = self.scrubber.scrub(stderr_raw)

        # 6. Post-execution Filesystem Diff & Verification
        diff = self.path_jail.diff_workspace(pre_snapshot)
        post_snapshot = self.path_jail.snapshot_workspace()
        post_hash = sha256_hex(json.dumps(post_snapshot, sort_keys=True))

        diff_violations = self.path_jail.verify_diff(diff)
        if diff_violations:
            violations.extend(diff_violations)

        # 7. Merkle DAG Cryptographic Recording
        is_violation = bool(violations)
        node = self.dag.record_event(
            action_type="command",
            target=command,
            stdout_content=clean_stdout + clean_stderr,
            exit_code=exit_code,
            pre_state_hash=pre_hash,
            post_state_hash=post_hash,
            is_violation=is_violation,
        )

        # 8. If diff violations occurred in enforcing mode, flag failure
        if diff_violations and self.policy.is_enforcing():
            exit_code = 126
            clean_stderr += f"\nSandbox Security Violation: {'; '.join(diff_violations)}"

        return ExecutionResult(
            command=command,
            exit_code=exit_code,
            stdout=clean_stdout,
            stderr=clean_stderr,
            duration_ms=duration_ms,
            diff=diff,
            violations=violations,
            merkle_node=node,
            blocked=is_violation and self.policy.is_enforcing(),
        )

    def write_file(self, file_path: str | Path, content: str | bytes) -> None:
        """
        Safely write a file through the sandbox jail and record in Merkle DAG.
        """
        self.path_jail.inspect_write(file_path)

        target = Path(file_path)
        full_path = target if target.is_absolute() else (self.root_dir / target).resolve()
        
        pre_snapshot = self.path_jail.snapshot_workspace()
        pre_hash = sha256_hex(json.dumps(pre_snapshot, sort_keys=True))

        full_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            full_path.write_text(content, encoding="utf-8")
        else:
            full_path.write_bytes(content)

        post_snapshot = self.path_jail.snapshot_workspace()
        post_hash = sha256_hex(json.dumps(post_snapshot, sort_keys=True))

        rel_name = full_path.relative_to(self.root_dir).as_posix()
        self.dag.record_event(
            action_type="file_write",
            target=rel_name,
            stdout_content=f"bytes_written={len(content)}",
            exit_code=0,
            pre_state_hash=pre_hash,
            post_state_hash=post_hash,
        )

    def read_file(self, file_path: str | Path) -> str:
        """
        Safely read a file through the sandbox jail.
        """
        self.path_jail.inspect_read(file_path)
        target = Path(file_path)
        full_path = target if target.is_absolute() else (self.root_dir / target).resolve()
        return full_path.read_text(encoding="utf-8", errors="replace")

    def finalize(self) -> MerkleReceipt:
        """Finalize execution and return tamper-evident receipt."""
        return self.dag.generate_receipt()
