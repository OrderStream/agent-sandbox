"""
Security policy schema, loader, and validator for agent-sandbox.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class PolicyViolation(Exception):
    """Raised when an action violates the security policy in enforce mode."""

    def __init__(self, rule: str, detail: str, severity: str = "error"):
        super().__init__(f"[{severity.upper()}] Policy violation on rule '{rule}': {detail}")
        self.rule = rule
        self.detail = detail
        self.severity = severity

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule": self.rule,
            "detail": self.detail,
            "severity": self.severity,
        }


@dataclass
class Policy:
    name: str = "default-agent-policy"
    mode: str = "enforce"  # 'enforce' or 'audit'
    version: str = "1.0"
    
    # Execution & Command Rules
    allowed_commands: List[str] = field(default_factory=lambda: [
        "python*", "pytest*", "node*", "npm test*", "git status*", "git diff*", "cargo test*"
    ])
    denied_commands: List[str] = field(default_factory=lambda: [
        "curl*", "wget*", "nc*", "netcat*", "ssh*", "sudo*", "su*", "chmod *777*", "chown*",
        "rm -rf /*", "rm -rf ./*", "dd*", "mkfs*", ":(){ :|:& };:"
    ])
    
    # Path & Filesystem Rules
    allowed_paths_read: List[str] = field(default_factory=lambda: ["**"])
    allowed_paths_write: List[str] = field(default_factory=lambda: [
        "src/**", "tests/**", "lib/**", "*.py", "*.ts", "*.js", "*.json", "*.md", "*.txt"
    ])
    denied_paths: List[str] = field(default_factory=lambda: [
        ".github/workflows/**", ".git/hooks/**", ".git/config", "**/.env*", "**/*.pem",
        "**/*id_rsa*", "**/*id_ed25519*", "/etc/**", "/root/**", "C:\\Windows\\System32/**"
    ])
    
    # Network & Secret Rules
    allow_network: bool = False
    allowed_hosts: List[str] = field(default_factory=list)
    redact_secrets: bool = True
    custom_redact_patterns: List[str] = field(default_factory=list)
    
    # Environment Sanitization
    strip_env_vars: List[str] = field(default_factory=lambda: [
        "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "NPM_TOKEN", "PYPI_TOKEN",
        "SLACK_BOT_TOKEN", "DISCORD_TOKEN", "PRIVATE_KEY", "SECRET_KEY"
    ])
    allowed_env_vars: Optional[List[str]] = None  # If set, whitelist mode
    
    # Execution Guardrails
    max_execution_time_seconds: int = 120
    max_output_bytes: int = 2 * 1024 * 1024  # 2MB
    isolate_working_dir: bool = False

    def is_enforcing(self) -> bool:
        return self.mode.lower() == "enforce"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "version": self.version,
            "allowed_commands": list(self.allowed_commands),
            "denied_commands": list(self.denied_commands),
            "allowed_paths_read": list(self.allowed_paths_read),
            "allowed_paths_write": list(self.allowed_paths_write),
            "denied_paths": list(self.denied_paths),
            "allow_network": self.allow_network,
            "allowed_hosts": list(self.allowed_hosts),
            "redact_secrets": self.redact_secrets,
            "custom_redact_patterns": list(self.custom_redact_patterns),
            "strip_env_vars": list(self.strip_env_vars),
            "allowed_env_vars": list(self.allowed_env_vars) if self.allowed_env_vars else None,
            "max_execution_time_seconds": self.max_execution_time_seconds,
            "max_output_bytes": self.max_output_bytes,
            "isolate_working_dir": self.isolate_working_dir,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Policy:
        # Filter keys to match dataclass fields
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """
    Zero-dependency robust parser for simple YAML configurations.
    Falls back to JSON or line-by-line parsing if pyyaml is not installed.
    """
    import textwrap
    clean_text = textwrap.dedent(text).strip()

    try:
        import yaml  # type: ignore
        return yaml.safe_load(clean_text) or {}
    except ImportError:
        pass

    # Fallback YAML parser for standard key: value and list structures
    data: Dict[str, Any] = {}
    current_list_key: Optional[str] = None

    for raw_line in clean_text.splitlines():
        line = raw_line.split("#")[0].strip()
        if not line:
            continue

        if line.startswith("- "):
            item = line[2:].strip().strip("\"'")
            if current_list_key:
                if current_list_key not in data or not isinstance(data[current_list_key], list):
                    data[current_list_key] = []
                data[current_list_key].append(item)
            continue

        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            if not val:
                current_list_key = key
                data[key] = []
            else:
                current_list_key = None
                # Parse scalar types
                if val.lower() == "true":
                    data[key] = True
                elif val.lower() == "false":
                    data[key] = False
                elif val.isdigit():
                    data[key] = int(val)
                elif (val.startswith("[") and val.endswith("]")):
                    # Inline JSON array
                    try:
                        data[key] = json.loads(val)
                    except Exception:
                        items = [s.strip().strip("\"'") for s in val[1:-1].split(",") if s.strip()]
                        data[key] = items
                else:
                    data[key] = val.strip("\"'")

    return data


def load_policy(source: str | Path | Dict[str, Any] | None) -> Policy:
    """Load policy from file path, JSON/YAML string, or dictionary."""
    if source is None:
        return Policy()

    if isinstance(source, Policy):
        return source

    if isinstance(source, dict):
        return Policy.from_dict(source)

    path = Path(source)
    if path.is_file():
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            return Policy.from_dict(json.loads(content))
        return Policy.from_dict(_parse_simple_yaml(content))

    # Assume raw string content
    raw_str = str(source).strip()
    if raw_str.startswith("{"):
        return Policy.from_dict(json.loads(raw_str))
    return Policy.from_dict(_parse_simple_yaml(raw_str))
