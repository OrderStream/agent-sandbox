"""
AST Command Firewall: In-flight inspection, decomposition, and threat detection
for AI agent shell commands and tool executions.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from agent_sandbox.policy import Policy, PolicyViolation


@dataclass
class FirewallDecision:
    allowed: bool
    command: str
    reasons: List[str] = field(default_factory=list)
    atoms: List[str] = field(default_factory=list)
    severity: str = "info"  # 'info', 'warning', 'critical'

    def raise_if_denied(self, is_enforcing: bool = True) -> None:
        if not self.allowed and is_enforcing:
            reason_str = "; ".join(self.reasons)
            raise PolicyViolation("command_firewall", reason_str, severity=self.severity)


class CommandFirewall:
    """
    Analyzes shell command pipelines to block malicious tool calls,
    prompt injection exploits, reverse shells, and unauthorized utilities.
    """

    # High-risk patterns indicating reverse shells, evasion, or destructive intent
    CRITICAL_PATTERNS = [
        (re.compile(r"/dev/(?:tcp|udp)/\S+"), "Direct socket reverse shell syntax (/dev/tcp or /dev/udp)"),
        (re.compile(r"(?:\bexec\s+\d+<>/dev/tcp)"), "Interactive bash socket redirect"),
        (re.compile(r"\b(?:nc|netcat|ncat|socat)\b.*-(?:e|c)\b"), "Netcat executable spawn flag (-e / -c)"),
        (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+/(?:\s|$|\*)"), "Root filesystem deletion (rm -rf /)"),
        (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "Forkbomb pattern detected"),
        (re.compile(r">\s*(\.github/workflows/|\.git/hooks/)"), "CI/CD workflow or Git hook overwrite attempt via redirect"),
        (re.compile(r"\b(?:sudo|su|doas)\b"), "Unauthorized privilege escalation"),
        (re.compile(r"\bcurl\b.*(?:@\.env|@id_rsa|@/etc/)"), "Direct secret file exfiltration via curl"),
        (re.compile(r"\bbase64\b.*\|\s*(?:curl|wget|nc)"), "Base64 encoded data exfiltration pipeline"),
    ]

    def __init__(self, policy: Optional[Policy] = None):
        self.policy = policy or Policy()

    def inspect(self, command: str) -> FirewallDecision:
        """
        Inspect a shell command string against the security policy and critical threat heuristics.
        """
        raw_cmd = command.strip()
        if not raw_cmd:
            return FirewallDecision(allowed=True, command=command, atoms=[])

        reasons: List[str] = []
        severity = "info"

        # 1. Critical pattern scanning across whole command line
        for pattern, desc in self.CRITICAL_PATTERNS:
            if pattern.search(raw_cmd):
                reasons.append(desc)
                severity = "critical"

        # 2. Decompose command line into atomic sub-commands
        atoms = self._extract_atomic_commands(raw_cmd)

        # 3. Check each atomic command against policy
        for atom in atoms:
            atom_clean = self._normalize_command_atom(atom)
            if not atom_clean:
                continue

            # Check explicit denied commands
            for denied_pattern in self.policy.denied_commands:
                if self._matches_pattern(atom_clean, denied_pattern):
                    reasons.append(f"Command '{atom_clean}' matches denied pattern '{denied_pattern}'")
                    severity = "critical"

            # Check allowed commands (if allowlist specified)
            if self.policy.allowed_commands:
                is_allowed = any(
                    self._matches_pattern(atom_clean, allowed_pattern)
                    for allowed_pattern in self.policy.allowed_commands
                )
                if not is_allowed:
                    reasons.append(
                        f"Command '{atom_clean}' is not in allowed_commands whitelist "
                        f"({len(self.policy.allowed_commands)} rules)"
                    )
                    if severity != "critical":
                        severity = "warning"

        allowed = len(reasons) == 0
        return FirewallDecision(
            allowed=allowed,
            command=command,
            reasons=reasons,
            atoms=atoms,
            severity=severity,
        )

    def _extract_atomic_commands(self, cmd: str) -> List[str]:
        """
        Split compound commands (piped, chained, subshells, process substitutions)
        into discrete executable tokens, respecting backslash escapes, nested parentheses,
        and quotation marks so that malicious commands cannot be hidden in subexpressions.
        """
        atoms: List[str] = []
        current: List[str] = []
        in_single = False
        in_double = False
        i = 0
        n = len(cmd)

        while i < n:
            ch = cmd[i]

            # Backslash escape handling: outside single quotes, \ escapes the next character
            if ch == "\\" and not in_single and i + 1 < n:
                current.append(ch)
                current.append(cmd[i + 1])
                i += 2
                continue

            # Toggle quote states
            if ch == "'" and not in_double:
                in_single = not in_single
                current.append(ch)
                i += 1
                continue
            elif ch == '"' and not in_single:
                in_double = not in_double
                current.append(ch)
                i += 1
                continue

            # If not in quotes, check for chaining delimiters
            if not in_single and not in_double:
                # Check 2-char delimiters: &&, ||
                if i + 1 < n and cmd[i:i+2] in ("&&", "||"):
                    atom_str = "".join(current).strip()
                    if atom_str:
                        atoms.append(atom_str)
                    current = []
                    i += 2
                    continue
                # Check 1-char delimiters: ;, |, &, \n, \r
                elif ch in (";", "|", "&", "\n", "\r"):
                    atom_str = "".join(current).strip()
                    if atom_str:
                        atoms.append(atom_str)
                    current = []
                    i += 1
                    continue

            current.append(ch)
            i += 1

        last_atom = "".join(current).strip()
        if last_atom:
            atoms.append(last_atom)

        # Now extract subshells, process substitutions, backticks, and eval/bash -c executions
        expanded_atoms: List[str] = []
        for atom in atoms:
            sub_exprs = self._extract_subshell_expressions(atom)
            for sub in sub_exprs:
                expanded_atoms.extend(self._extract_atomic_commands(sub))

            # Check nested sh/bash/zsh -c "..."
            nested_matches = re.findall(r"""(?:sh|bash|zsh|dash)\s+-c\s+["']([^"']+)["']""", atom)
            for nested in nested_matches:
                if nested.strip():
                    expanded_atoms.extend(self._extract_atomic_commands(nested))

            # Check eval "..." or eval '...'
            eval_matches = re.findall(r"""\beval\s+["']([^"']+)["']""", atom)
            for ev_cmd in eval_matches:
                if ev_cmd.strip():
                    expanded_atoms.extend(self._extract_atomic_commands(ev_cmd))

            expanded_atoms.append(atom)

        return expanded_atoms

    def _extract_subshell_expressions(self, text: str) -> List[str]:
        """
        Extract nested subshell expressions: $(...), <(...), >(...), and `...`
        handling arbitrary nested parentheses and quotes safely.
        """
        extracted: List[str] = []
        i = 0
        n = len(text)

        while i < n:
            # Check for $(...), <(...), >(...)
            if i + 1 < n and (text[i:i+2] in ("$(", "<(", ">(")):
                start = i + 2
                depth = 1
                j = start
                in_s = False
                in_d = False
                while j < n and depth > 0:
                    c = text[j]
                    if c == "\\" and not in_s and j + 1 < n:
                        j += 2
                        continue
                    if c == "'" and not in_d:
                        in_s = not in_s
                    elif c == '"' and not in_s:
                        in_d = not in_d
                    elif not in_s and not in_d:
                        if c == "(":
                            depth += 1
                        elif c == ")":
                            depth -= 1
                            if depth == 0:
                                inner = text[start:j].strip()
                                if inner:
                                    extracted.append(inner)
                                i = j + 1
                                break
                    j += 1
                else:
                    i = j
                continue

            # Check for backticks `...`
            elif text[i] == "`":
                j = i + 1
                while j < n:
                    if text[j] == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if text[j] == "`":
                        inner = text[i+1:j].strip()
                        if inner:
                            extracted.append(inner)
                        i = j + 1
                        break
                    j += 1
                else:
                    i = n
                continue

            i += 1

        return extracted

    def _normalize_command_atom(self, atom: str) -> str:
        """
        De-obfuscate executable name: remove escaping quotes, strip path prefixes,
        strip leading environment variable assignments (FOO=bar cmd), remove Windows cmd caret escapes.
        e.g., 'c""url -s http://...' -> 'curl -s http://...'
              '/usr/bin/git status' -> 'git status'
              'FOO=bar curl http://...' -> 'curl http://...'
        """
        trimmed = atom.strip()
        # Strip subshell grouping parentheses / braces
        trimmed = re.sub(r"^[({!\s]+", "", trimmed)
        trimmed = re.sub(r"[)};\s]+$", "", trimmed)

        # Remove file redirects before parsing command head, but preserve process substitutions
        # only match redirects not followed by paren
        cmd_no_redirect = re.split(r"(?:>>|>(?!\()|<(?!\())", trimmed)[0].strip()
        if not cmd_no_redirect:
            return ""

        try:
            tokens = shlex.split(cmd_no_redirect, posix=(os.name != "nt"))
        except ValueError:
            tokens = cmd_no_redirect.split()

        if not tokens:
            return ""

        # Skip leading environment variable assignments (e.g., FOO=bar cmd)
        idx = 0
        while idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", tokens[idx]):
            idx += 1
        if idx >= len(tokens):
            return ""
        tokens = tokens[idx:]

        # Normalize executable token across Windows and Unix paths
        raw_exe = tokens[0].strip("\"'()`;{}")
        # Strip Windows cmd caret escape characters (e.g. c^u^r^l -> curl)
        raw_exe = raw_exe.replace("^", "")
        # Convert all backslashes to forward slashes first to preserve path separation
        path_normalized = raw_exe.replace("\\", "/")
        base_exe = os.path.basename(path_normalized)
        # Strip internal escaping quotes
        base_exe_clean = base_exe.replace("'", "").replace('"', "")
        # Remove .exe extension if present for cross-platform matching
        if base_exe_clean.lower().endswith(".exe"):
            base_exe_clean = base_exe_clean[:-4]

        tokens[0] = base_exe_clean
        return " ".join(tokens)

    def _matches_pattern(self, cmd: str, pattern: str) -> bool:
        """
        Match command against pattern with support for wildcards.
        Supports both full command matching ('curl *') and prefix/executable matching ('curl*').
        """
        cmd_lower = cmd.lower()
        pat_lower = pattern.lower()

        # Wildcard match
        if fnmatch.fnmatch(cmd_lower, pat_lower):
            return True

        # First token match
        cmd_first_token = cmd_lower.split()[0] if cmd_lower.split() else ""
        pat_first_token = pat_lower.split()[0] if pat_lower.split() else ""

        if fnmatch.fnmatch(cmd_first_token, pat_first_token):
            return True

        return False
