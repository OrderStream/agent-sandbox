"""
Deterministic Path Jail: Directory boundary enforcement, symlink resolution,
and post-execution file modification verification for agent workspaces.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from agent_sandbox.policy import Policy, PolicyViolation


class PathViolation(PolicyViolation):
    """Raised when an agent attempts unauthorized read/write access to a path."""
    def __init__(self, operation: str, path: str, reason: str):
        super().__init__(
            rule=f"path_jail_{operation}",
            detail=f"Unauthorized {operation} attempt on '{path}': {reason}",
            severity="critical"
        )
        self.operation = operation
        self.path = path


@dataclass
class FileDiff:
    added: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    @property
    def all_written(self) -> List[str]:
        return self.added + self.modified


class PathJail:
    """
    Enforces strict filesystem jail boundaries on autonomous agent file operations.
    """

    def __init__(self, root_dir: str | Path, policy: Optional[Policy] = None):
        self.root_dir = Path(root_dir).resolve()
        self.policy = policy or Policy()

    def inspect_read(self, target_path: str | Path) -> None:
        """Verify whether an agent is permitted to read target_path."""
        self._check_access(target_path, operation="read")

    def inspect_write(self, target_path: str | Path) -> None:
        """Verify whether an agent is permitted to write to target_path."""
        self._check_access(target_path, operation="write")

    def _check_access(self, target_path: str | Path, operation: str) -> None:
        raw_str = str(target_path)
        
        # Check traversal markers
        if ".." in raw_str:
            resolved = (self.root_dir / target_path).resolve()
        else:
            resolved = Path(target_path).resolve() if Path(target_path).is_absolute() else (self.root_dir / target_path).resolve()

        # Check if resolved path escapes sandbox root
        try:
            rel_path = resolved.relative_to(self.root_dir).as_posix()
        except ValueError:
            # Escaped the root directory entirely
            raise PathViolation(
                operation,
                raw_str,
                f"Path resolves outside root directory '{self.root_dir}' -> '{resolved}'"
            )

        # Check against denied patterns
        for denied in self.policy.denied_paths:
            if self._match_path(rel_path, denied) or self._match_path(resolved.as_posix(), denied):
                raise PathViolation(
                    operation,
                    rel_path,
                    f"Matches forbidden path pattern '{denied}'"
                )

        # For write operations, verify against write allowlist
        if operation == "write" and self.policy.allowed_paths_write:
            allowed = any(self._match_path(rel_path, pattern) for pattern in self.policy.allowed_paths_write)
            if not allowed:
                raise PathViolation(
                    operation,
                    rel_path,
                    f"Not in allowed_paths_write allowlist ({len(self.policy.allowed_paths_write)} rules)"
                )

        # For read operations, verify against read allowlist
        if operation == "read" and self.policy.allowed_paths_read:
            allowed = any(self._match_path(rel_path, pattern) for pattern in self.policy.allowed_paths_read)
            if not allowed:
                raise PathViolation(
                    operation,
                    rel_path,
                    f"Not in allowed_paths_read allowlist"
                )

    def _match_path(self, path_str: str, pattern: str) -> bool:
        """Support glob matching including recursive **."""
        clean_path = path_str.replace("\\", "/").strip("/")
        clean_pat = pattern.replace("\\", "/").strip("/")
        
        # Exact match or wildcard
        if clean_pat == "**" or clean_pat == "*":
            return True

        if fnmatch.fnmatch(clean_path, clean_pat):
            return True

        # Handle directory prefix patterns like 'src/**'
        if clean_pat.endswith("/**"):
            dir_prefix = clean_pat[:-3]
            if clean_path == dir_prefix or clean_path.startswith(dir_prefix + "/"):
                return True

        # Suffix matching like '*.py'
        if clean_pat.startswith("*."):
            if fnmatch.fnmatch(os.path.basename(clean_path), clean_pat):
                return True

        return False

    def snapshot_workspace(
        self,
        target_patterns: Optional[List[str]] = None,
        explicit_paths: Optional[List[str | Path]] = None,
        max_files: int = 5000,
    ) -> Dict[str, str]:
        """
        Capture a deterministic SHA-256 hash map using targeted allowlist diffing.
        Instead of walking up to 5,000 files across the entire workspace twice per command,
        only snapshots and hashes paths matching the policy's allowed write patterns,
        files explicitly touched, or candidate paths.
        """
        snapshot: Dict[str, str] = {}

        if explicit_paths:
            for p in explicit_paths:
                full_path = Path(p) if Path(p).is_absolute() else (self.root_dir / p).resolve()
                if full_path.is_file():
                    try:
                        rel_path = full_path.relative_to(self.root_dir).as_posix()
                        snapshot[rel_path] = self._hash_file(full_path)
                    except (OSError, PermissionError, RuntimeError, ValueError):
                        continue
            return snapshot

        patterns = target_patterns if target_patterns is not None else self.policy.allowed_paths_write

        if not patterns or any(p.strip("/") in {"**", "*"} for p in patterns):
            count = 0
            for current_root, dirs, files in os.walk(self.root_dir):
                if count >= max_files:
                    dirs[:] = []
                    break
                dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules"}]
                for file_name in files:
                    count += 1
                    if count > max_files:
                        dirs[:] = []
                        break
                    full_path = Path(current_root) / file_name
                    try:
                        rel_path = full_path.relative_to(self.root_dir).as_posix()
                        file_hash = self._hash_file(full_path)
                        snapshot[rel_path] = file_hash
                    except (OSError, PermissionError, RuntimeError):
                        continue
            return snapshot

        candidate_paths: Set[Path] = set()

        # Workspace root entries to catch any unauthorized additions at root level
        try:
            for entry in os.scandir(self.root_dir):
                if entry.name not in {".git", ".venv", "venv", "__pycache__", "node_modules"} and entry.is_file():
                    candidate_paths.add(Path(entry.path))
        except (OSError, PermissionError):
            pass

        # Targeted allowlist scanning
        for pattern in patterns:
            clean_pat = pattern.replace("\\", "/").strip("/")
            if "/**" in clean_pat:
                dir_part = clean_pat.split("/**")[0]
                target_dir = (self.root_dir / dir_part).resolve()
                if target_dir.is_dir():
                    count = 0
                    for c_root, dirs, files in os.walk(target_dir):
                        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules"}]
                        for f in files:
                            count += 1
                            if count > max_files:
                                break
                            candidate_paths.add(Path(c_root) / f)
            elif "*" in clean_pat:
                try:
                    for matched in self.root_dir.glob(clean_pat):
                        if matched.is_file():
                            candidate_paths.add(matched)
                except Exception:
                    pass
            else:
                target = (self.root_dir / clean_pat).resolve()
                if target.is_file():
                    candidate_paths.add(target)
                elif target.is_dir():
                    count = 0
                    for c_root, dirs, files in os.walk(target):
                        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules"}]
                        for f in files:
                            count += 1
                            if count > max_files:
                                break
                            candidate_paths.add(Path(c_root) / f)

        for full_path in candidate_paths:
            try:
                rel_path = full_path.relative_to(self.root_dir).as_posix()
                snapshot[rel_path] = self._hash_file(full_path)
            except (OSError, PermissionError, RuntimeError, ValueError):
                continue

        return snapshot

    def diff_workspace(
        self,
        pre_snapshot: Dict[str, str],
        post_snapshot: Optional[Dict[str, str]] = None,
        target_patterns: Optional[List[str]] = None,
        explicit_paths: Optional[List[str | Path]] = None,
    ) -> FileDiff:
        """
        Compare current filesystem state against a prior snapshot.
        If post_snapshot is provided, reuses it to eliminate redundant filesystem hashing.
        """
        if post_snapshot is None:
            post_snapshot = self.snapshot_workspace(
                target_patterns=target_patterns,
                explicit_paths=explicit_paths,
            )
        
        added: List[str] = []
        modified: List[str] = []
        deleted: List[str] = []

        pre_keys: Set[str] = set(pre_snapshot.keys())
        post_keys: Set[str] = set(post_snapshot.keys())

        for p in post_keys - pre_keys:
            added.append(p)

        for p in pre_keys - post_keys:
            deleted.append(p)

        for p in pre_keys & post_keys:
            if pre_snapshot[p] != post_snapshot[p]:
                modified.append(p)

        return FileDiff(
            added=sorted(added),
            modified=sorted(modified),
            deleted=sorted(deleted),
        )

    def verify_diff(self, diff: FileDiff) -> List[str]:
        """
        Verify that all created/modified/deleted files comply with policy write rules.
        Returns list of violation messages if any.
        """
        violations: List[str] = []
        for path in diff.all_written:
            try:
                self.inspect_write(path)
            except PathViolation as e:
                violations.append(str(e))

        for path in diff.deleted:
            # Treat file deletions as write operations requiring permission
            try:
                self.inspect_write(path)
            except PathViolation as e:
                violations.append(f"Unauthorized deletion: {e}")

        return violations

    @staticmethod
    def _hash_file(path: Path) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
