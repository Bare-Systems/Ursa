#!/usr/bin/env python3
"""Ursa Minor CLI — entry point for the recon toolkit."""

import getpass
import json

import click


@click.group()
def main():
    """Ursa Minor — Recon & Scanning Toolkit."""
    pass


@main.group()
def mcp():
    """MCP server commands."""
    pass


@mcp.command()
def serve():
    """Start the Ursa Minor MCP server."""
    from ursa_minor.server import mcp_server
    mcp_server.run()


@main.group()
def approval():
    """Manage signed approvals for high-risk MCP tools."""
    pass


@approval.command("init")
@click.option("--force", is_flag=True, help="Replace an existing approval key.")
def approval_init(force: bool):
    """Initialize the owner-only local approval-signing key."""
    from ursa_minor.approval import initialize_approval_key

    try:
        path = initialize_approval_key(force=force)
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Initialized Ursa Minor approval key: {path}")


@approval.command("issue")
@click.option("--tool", "tool_name", required=True, help="Exact MCP tool name.")
@click.option("--target", required=True, help="Exact target passed to the tool.")
@click.option("--actor", required=True, help="Exact policy_actor requesting execution.")
@click.option("--reason", required=True, help="Exact policy_reason for the operation.")
@click.option(
    "--args-json",
    default="{}",
    show_default=True,
    help="Tool arguments used for argument-sensitive risk classification.",
)
@click.option("--ttl", "ttl_seconds", type=click.IntRange(1, 3600), default=300)
def approval_issue(
    tool_name: str,
    target: str,
    actor: str,
    reason: str,
    args_json: str,
    ttl_seconds: int,
):
    """Issue a short-lived, single-use approval token bound to an operation."""
    from ursa_minor.approval import issue_approval
    from ursa_minor.policy import classify_tool_policy, policy_requires_gate

    try:
        args = json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid --args-json: {exc}") from exc
    if not isinstance(args, dict):
        raise click.ClickException("--args-json must decode to an object")

    policy = classify_tool_policy(tool_name, args)
    if not policy_requires_gate(policy):
        raise click.ClickException(
            f"{tool_name} is {policy.risk_level} risk for those arguments and does not need approval"
        )
    try:
        token = issue_approval(
            tool_name=tool_name,
            target=target,
            actor=actor,
            reason=reason,
            risk_level=policy.risk_level,
            ttl_seconds=ttl_seconds,
            approved_by=getpass.getuser(),
        )
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(token)


if __name__ == "__main__":
    main()
