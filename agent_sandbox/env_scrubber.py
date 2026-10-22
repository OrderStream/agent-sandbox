"""
Environment Scrubber: Variable sanitization, token stripping, and real-time
stream redaction for LLM agent outputs and execution traces.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Set
from agent_sandbox.policy import Policy


class EnvironmentScrubber:
    """
    Sanitizes process environments and scrubs secret tokens from agent output streams.
    """

    SAFE_ENV_DEFAULTS = {
        "PATH", "HOME", "USER", "USERNAME", "SHELL", "LANG", "LC_ALL",
        "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "COMSPEC",
        "PATHEXT", "PYTHONPATH", "NODE_PATH"
    }

    BUILTIN_PATTERNS = [
        # GitHub Tokens
        (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}\b"), "[REDACTED_GITHUB_PAT]"),
        # AWS Keys
        (re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
        # OpenAI / Anthropic Keys
        (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "[REDACTED_AI_API_KEY]"),
        (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"), "[REDACTED_ANTHROPIC_KEY]"),
        # Slack Tokens
        (re.compile(r"\bxox[baprs]-[A-Za-z0-9_\-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
        # Private Keys
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
         "[REDACTED_PRIVATE_KEY]"),
        # Generic Bearer Tokens
        (re.compile(r"\bBearer\s+[A-Za-z0-9\-_=]{32,}\b", re.IGNORECASE), "Bearer [REDACTED_BEARER_TOKEN]"),
    ]

    def __init__(self, policy: Optional[Policy] = None):
        self.policy = policy or Policy()
        self.exact_secrets: Set[str] = set()
        self._harvest_environment_secrets()

    def _harvest_environment_secrets(self) -> None:
        """
        Record sensitive variable values from the host environment to ensure
        they are redacted even if they don't match standard regex shapes.
        """
        sensitive_keys = {
            "TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH", "CREDENTIAL", "PASSPHRASE"
        }
        for k, v in os.environ.items():
            k_upper = k.upper()
            if any(s in k_upper for s in sensitive_keys):
                val = v.strip()
                if len(val) >= 8:  # avoid redacting trivial words
                    self.exact_secrets.add(val)

    def prepare_environment(self, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Generate a clean, sanitized environment dictionary for child process execution.
        """
        source = dict(base_env or os.environ)
        cleaned: Dict[str, str] = {}

        if self.policy.allowed_env_vars is not None:
            # Whitelist mode: only keep explicitly permitted keys
            allowed_set = set(self.policy.allowed_env_vars) | self.SAFE_ENV_DEFAULTS
            for k, v in source.items():
                if k in allowed_set or k.upper() in allowed_set:
                    cleaned[k] = v
        else:
            # Blacklist mode: remove configured strip keys
            strip_set = {k.upper() for k in self.policy.strip_env_vars}
            for k, v in source.items():
                if k.upper() not in strip_set:
                    cleaned[k] = v

        # Inject sandbox indicator
        cleaned["AGENT_SANDBOX_ACTIVE"] = "1"
        cleaned["AGENT_SANDBOX_POLICY"] = self.policy.name

        return cleaned

    def scrub(self, text: str) -> str:
        """
        Scrub sensitive tokens, credentials, and known secrets from text output.
        """
        if not text or not self.policy.redact_secrets:
            return text

        result = text

        # 1. Exact secrets harvested from environment
        for secret in self.exact_secrets:
            if secret in result:
                result = result.replace(secret, "[REDACTED_ENV_SECRET]")

        # 2. Builtin regex patterns
        for pattern, replacement in self.BUILTIN_PATTERNS:
            result = pattern.sub(replacement, result)

        # 3. Custom regex patterns from policy
        for custom_pat in self.policy.custom_redact_patterns:
            try:
                rx = re.compile(custom_pat)
                result = rx.sub("[REDACTED_CUSTOM]", result)
            except re.error:
                continue

        return result
