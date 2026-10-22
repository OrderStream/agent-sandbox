"""
CLI interface for agent-sandbox: Command execution, cryptographic receipt verification,
policy initialization, and inspection.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from agent_sandbox import __version__
from agent_sandbox.firewall import CommandFirewall
from agent_sandbox.merkle import verify_receipt
from agent_sandbox.policy import Policy, load_policy
from agent_sandbox.runner import ExecutionSandbox
from agent_sandbox.sarif import generate_sarif_report
from agent_sandbox.summary import generate_step_summary


DEFAULT_STARTER_POLICY = """# agent-sandbox policy specification
name: github-actions-agent-guard
version: "1.0"
mode: enforce

# Permitted commands (wildcards supported)
allowed_commands:
  - "python*"
  - "pytest*"
  - "node*"
  - "npm test*"
  - "git status*"
  - "git diff*"
  - "cargo test*"

# Explicitly denied commands & exploit signatures
denied_commands:
  - "curl*"
  - "wget*"
  - "nc*"
  - "netcat*"
  - "ssh*"
  - "sudo*"
  - "su*"
  - "chmod *777*"
  - "chown*"
  - "rm -rf /*"
  - "rm -rf ./*"

# Filesystem read boundaries
allowed_paths_read:
  - "**"

# Filesystem write boundaries
allowed_paths_write:
  - "src/**"
  - "tests/**"
  - "lib/**"
  - "*.py"
  - "*.ts"
  - "*.js"
  - "*.json"
  - "*.md"
  - "*.txt"

# Forbidden paths (strictly blocked for read & write)
denied_paths:
  - ".github/workflows/**"
  - ".git/hooks/**"
  - ".git/config"
  - "**/.env*"
  - "**/*.pem"
  - "**/*id_rsa*"
  - "/etc/**"
  - "/root/**"

# Network & exfiltration controls
allow_network: false
redact_secrets: true

# Execution timeouts
max_execution_time_seconds: 120
max_output_bytes: 2097152
"""


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.output)
    if target.exists() and not args.force:
        print(f"[!] File '{target}' already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    target.write_text(DEFAULT_STARTER_POLICY, encoding="utf-8")
    print(f"[+] Initialized starter security policy at '{target}'")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else Policy()
    firewall = CommandFirewall(policy)
    decision = firewall.inspect(args.command)

    print(f"Command: {decision.command}")
    print(f"Allowed: {'YES' if decision.allowed else 'NO'}")
    print(f"Severity: {decision.severity}")
    if decision.atoms:
        print(f"Atomic Sub-commands: {decision.atoms}")
    if decision.reasons:
        print("Reasons / Violations:")
        for r in decision.reasons:
            print(f"  - {r}")

    return 0 if decision.allowed else 2


def cmd_verify(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        print(f"[!] Error: Receipt file '{receipt_path}' not found.", file=sys.stderr)
        return 1

    valid, msg = verify_receipt(receipt_path)
    if valid:
        print(f"[+] VERIFICATION SUCCESS: {msg}")
        return 0
    else:
        print(f"[-] VERIFICATION FAILED: {msg}", file=sys.stderr)
        return 2


def cmd_exec(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else Policy()
    sandbox = ExecutionSandbox(root_dir=args.workdir, policy=policy)

    command_str = " ".join(args.command) if isinstance(args.command, list) else str(args.command)
    if not command_str.strip():
        print("[!] Error: No command provided to execute.", file=sys.stderr)
        return 1

    result = sandbox.run_command(command_str, timeout=args.timeout)

    # Print stdout / stderr
    if result.stdout:
        sys.stdout.write(result.stdout)
        if not result.stdout.endswith("\n"):
            sys.stdout.write("\n")
    if result.stderr:
        sys.stderr.write(result.stderr)
        if not result.stderr.endswith("\n"):
            sys.stderr.write("\n")

    # Generate receipt
    receipt = sandbox.finalize()
    if args.receipt:
        receipt.save(args.receipt)
        print(f"[+] Saved cryptographic audit receipt to '{args.receipt}'", file=sys.stderr)

    # Generate SARIF report if requested
    if args.sarif:
        generate_sarif_report(receipt, args.sarif)
        print(f"[+] Saved SARIF security report to '{args.sarif}'", file=sys.stderr)

    # Generate Step Summary
    if args.summary:
        generate_step_summary(receipt, write_to_env=True)

    if result.blocked:
        print(f"[!] Command execution blocked by agent-sandbox policy: {result.violations}", file=sys.stderr)
        return result.exit_code or 126

    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Deterministic Zero-Trust Security Sandbox & Cryptographic Audit DAG for Autonomous AI Agents."
    )
    parser.add_argument("--version", action="version", version=f"agent-sandbox {__version__}")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # exec subcommand
    exec_p = subparsers.add_parser("exec", help="Execute command inside the sandbox")
    exec_p.add_argument("--policy", "-p", help="Path to policy YAML or JSON file")
    exec_p.add_argument("--workdir", "-w", default=".", help="Root directory boundary (default: current dir)")
    exec_p.add_argument("--receipt", "-r", help="Path to write cryptographic execution receipt JSON")
    exec_p.add_argument("--sarif", "-s", help="Path to write SARIF 2.1.0 security report")
    exec_p.add_argument("--summary", action="store_true", help="Generate GitHub Actions step summary")
    exec_p.add_argument("--timeout", "-t", type=int, help="Override command timeout in seconds")
    exec_p.add_argument("command", nargs=argparse.REMAINDER, help="Command and arguments to execute")

    # verify subcommand
    ver_p = subparsers.add_parser("verify", help="Verify cryptographic receipt Merkle root")
    ver_p.add_argument("receipt", help="Path to receipt.json to verify")

    # init subcommand
    init_p = subparsers.add_parser("init", help="Initialize a starter security policy")
    init_p.add_argument("--output", "-o", default="agent-policy.yaml", help="Output file path")
    init_p.add_argument("--force", "-f", action="store_true", help="Overwrite existing policy file")

    # inspect subcommand
    ins_p = subparsers.add_parser("inspect", help="Inspect a command string without executing")
    ins_p.add_argument("--policy", "-p", help="Path to policy YAML or JSON file")
    ins_p.add_argument("command", help="Command string to analyze")

    args = parser.parse_args(argv)

    if args.subcommand == "exec":
        # Remove leading '--' if passed
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        return cmd_exec(args)
    elif args.subcommand == "verify":
        return cmd_verify(args)
    elif args.subcommand == "init":
        return cmd_init(args)
    elif args.subcommand == "inspect":
        return cmd_inspect(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
