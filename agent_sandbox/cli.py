"""
CLI interface for agent-sandbox: Command execution, cryptographic receipt verification,
policy initialization, and inspection.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
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

    # Enterprise License configuration & validation
    cli_license = getattr(args, "license_key", None) or os.environ.get("AGENT_SANDBOX_LICENSE_KEY")
    if cli_license:
        policy.enterprise_license = cli_license

    if policy.enterprise_license:
        from agent_sandbox.license import verify_license_key
        valid, info, lic_msg = verify_license_key(policy.enterprise_license)
        if not valid:
            print(f"[!] Enterprise License Warning: {lic_msg}", file=sys.stderr)
            if policy.is_enforcing():
                print("[-] Execution halted: Valid enterprise license required by policy.", file=sys.stderr)
                return 126
        elif info:
            print(f"[+] Enterprise License Active: Tier '{info.tier}' ({info.seats} seats)", file=sys.stderr)

    # Enterprise Dual-Authorization Approval Token
    if getattr(args, "approval_token", None):
        os.environ["AGENT_SANDBOX_APPROVAL_TOKEN"] = args.approval_token

    sandbox = ExecutionSandbox(root_dir=args.workdir, policy=policy)

    if isinstance(args.command, list):
        if len(args.command) == 1:
            command_str = args.command[0]
        elif os.name == "nt":
            command_str = subprocess.list2cmdline(args.command)
        else:
            import shlex
            command_str = shlex.join(args.command)
    else:
        command_str = str(args.command)

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

    # Enterprise Tier: Cloud Synchronization
    cloud_ep = args.cloud_endpoint or policy.cloud_sync_endpoint or os.environ.get("AGENT_SANDBOX_CLOUD_ENDPOINT")
    if cloud_ep:
        from agent_sandbox.cloud_sync import push_receipt_to_cloud
        cloud_key = args.cloud_api_key or policy.cloud_api_key or os.environ.get("AGENT_SANDBOX_CLOUD_API_KEY")
        ok, msg = push_receipt_to_cloud(receipt, endpoint=cloud_ep, api_key=cloud_key)
        if ok:
            print(f"[+] Cloud Telemetry: {msg}", file=sys.stderr)
        else:
            print(f"[!] Cloud Telemetry Warning: {msg}", file=sys.stderr)

    # Enterprise Tier: Security Webhook Alerts (Slack/Discord/SIEM)
    webhook_url = args.webhook or policy.security_webhook or os.environ.get("AGENT_SANDBOX_SECURITY_WEBHOOK")
    if webhook_url:
        from agent_sandbox.cloud_sync import notify_security_webhook
        ok, msg = notify_security_webhook(receipt, webhook_url=webhook_url)
        if ok:
            print(f"[+] Security Alert: {msg}", file=sys.stderr)
        else:
            print(f"[!] Security Alert Warning: {msg}", file=sys.stderr)

    if result.blocked:
        print(f"[!] Command execution blocked by agent-sandbox policy: {result.violations}", file=sys.stderr)
        return result.exit_code or 126

    return result.exit_code


def cmd_license_verify(args: argparse.Namespace) -> int:
    from agent_sandbox.license import verify_license_key
    key = args.license_key or os.environ.get("AGENT_SANDBOX_LICENSE_KEY")
    if not key:
        print("[!] Error: No license key provided. Specify via argument or AGENT_SANDBOX_LICENSE_KEY.", file=sys.stderr)
        return 1
    
    valid, info, msg = verify_license_key(key)
    if valid and info:
        print(f"[+] Enterprise License VALID: Tier '{info.tier}', Seats: {info.seats}, Org: {info.org_domain}")
        print(f"    Features: {', '.join(info.features)}")
        return 0
    else:
        print(f"[-] Enterprise License INVALID: {msg}", file=sys.stderr)
        return 2


def cmd_server(args: argparse.Namespace) -> int:
    from agent_sandbox.cloud_server import run_cloud_server
    run_cloud_server(port=args.port, host=args.host, api_key=args.api_key)
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from agent_sandbox.mcp_proxy import MCPProxyFilter, run_mcp_stdio_proxy
    policy = load_policy(args.policy) if args.policy else Policy()
    mcp_filter = MCPProxyFilter(sandbox_root=args.workdir, policy=policy)
    return run_mcp_stdio_proxy(mcp_filter, upstream_cmd=args.server)


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
    # Enterprise Cloud & License flags
    exec_p.add_argument("--license-key", help="Commercial enterprise license key")
    exec_p.add_argument("--approval-token", help="Human approval authorization token for dual-authorization gates")
    exec_p.add_argument("--cloud-endpoint", help="Agent-Sandbox Cloud SaaS ingestion endpoint URL")
    exec_p.add_argument("--cloud-api-key", help="API key for Agent-Sandbox Cloud")
    exec_p.add_argument("--webhook", help="Security webhook URL (Slack / Discord / SIEM) for real-time violation alerts")
    exec_p.add_argument("command", nargs=argparse.REMAINDER, help="Command and arguments to execute")

    # verify subcommand
    ver_p = subparsers.add_parser("verify", help="Verify cryptographic receipt Merkle root")
    ver_p.add_argument("receipt", help="Path to receipt.json to verify")

    # license subcommand
    lic_p = subparsers.add_parser("license", help="Verify enterprise license key")
    lic_p.add_argument("license_key", nargs="?", help="License key to validate (or reads AGENT_SANDBOX_LICENSE_KEY)")

    # init subcommand
    init_p = subparsers.add_parser("init", help="Initialize a starter security policy")
    init_p.add_argument("--output", "-o", default="agent-policy.yaml", help="Output file path")
    init_p.add_argument("--force", "-f", action="store_true", help="Overwrite existing policy file")

    # inspect subcommand
    ins_p = subparsers.add_parser("inspect", help="Inspect a command string without executing")
    ins_p.add_argument("--policy", "-p", help="Path to policy YAML or JSON file")
    ins_p.add_argument("command", help="Command string to analyze")

    # mcp subcommand
    mcp_p = subparsers.add_parser("mcp", help="Run Model Context Protocol (MCP) stdio firewall proxy")
    mcp_p.add_argument("--policy", "-p", help="Path to policy YAML or JSON file")
    mcp_p.add_argument("--workdir", "-w", default=".", help="Root directory boundary (default: current dir)")
    mcp_p.add_argument("--server", "-s", help="Upstream MCP server command to wrap (e.g. 'npx -y @modelcontextprotocol/server-filesystem .')")

    # server subcommand
    server_p = subparsers.add_parser("server", help="Run lightweight Agent-Sandbox Cloud telemetry and security dashboard")
    server_p.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    server_p.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    server_p.add_argument("--api-key", help="Require Bearer API token for telemetry ingestion")

    args = parser.parse_args(argv)

    if args.subcommand == "exec":
        # Remove leading '--' if passed
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        return cmd_exec(args)
    elif args.subcommand == "verify":
        return cmd_verify(args)
    elif args.subcommand == "license":
        return cmd_license_verify(args)
    elif args.subcommand == "server":
        return cmd_server(args)
    elif args.subcommand == "init":
        return cmd_init(args)
    elif args.subcommand == "inspect":
        return cmd_inspect(args)
    elif args.subcommand == "mcp":
        return cmd_mcp(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
