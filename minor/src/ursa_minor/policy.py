"""Ursa Minor local policy gates and audit records.

This module is intentionally self-contained. Ursa Minor can run without Ursa
Major's database, so high-risk MCP tool execution gets local machine-readable
metadata, approval evaluation, and JSONL audit records.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_AUDIT_DIR = Path.home() / ".ursa" / "audit"

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
APPROVAL_RISKS = {"high", "critical"}
SENSITIVE_ARG_KEYS = {
    "auth_header",
    "cookies",
    "password",
    "community",
    "policy_approval_id",
}


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    tool_name: str
    risk_level: str
    category: str
    description: str
    approval_required: bool = False
    destructive: bool = False
    sensitive_result: bool = False
    target_arg: str = "target"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolPolicyDecision:
    tool_name: str
    allowed: bool
    requires_approval: bool
    risk_level: str
    policy_result: str
    reason: str
    actor: str
    target: str
    justification: str
    approval_id: str
    policy: dict[str, Any]
    args: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


TOOL_POLICIES: dict[str, ToolPolicy] = {
    "discover_network": ToolPolicy(
        "discover_network", "medium", "network", "ARP network discovery."
    ),
    "scan_ports": ToolPolicy(
        "scan_ports", "medium", "network", "TCP connect port scan."
    ),
    "sniff_packets": ToolPolicy(
        "sniff_packets",
        "high",
        "network",
        "Live packet capture can collect third-party traffic.",
        approval_required=True,
        sensitive_result=True,
        target_arg="interface",
    ),
    "full_recon": ToolPolicy(
        "full_recon",
        "high",
        "network",
        "Network discovery plus per-host port scanning.",
        approval_required=True,
        target_arg="target_range",
    ),
    "dirbust": ToolPolicy(
        "dirbust", "medium", "web", "Directory and file discovery.", target_arg="url"
    ),
    "vuln_scan": ToolPolicy(
        "vuln_scan", "low", "web", "Header-only audit unless active tests are selected.", target_arg="url"
    ),
    "api_scan": ToolPolicy(
        "api_scan",
        "high",
        "web",
        "Schema-driven API probing, auth checks, injection canaries, and IDOR candidates.",
        approval_required=True,
        target_arg="url",
    ),
    "ursa_run_checks": ToolPolicy(
        "ursa_run_checks", "medium", "web", "Declarative HTTP checks.", target_arg="target"
    ),
    "credential_spray": ToolPolicy(
        "credential_spray",
        "critical",
        "credentials",
        "Credential spraying can trigger lockouts and authentication alerts.",
        approval_required=True,
        destructive=True,
        sensitive_result=True,
    ),
    "crack_hash": ToolPolicy(
        "crack_hash",
        "medium",
        "credentials",
        "Offline hash cracking against provided material.",
        sensitive_result=True,
        target_arg="target_hash",
    ),
    "generate_reverse_shell": ToolPolicy(
        "generate_reverse_shell",
        "high",
        "payload",
        "Payload generation for reverse shells.",
        approval_required=True,
        sensitive_result=True,
        target_arg="lport",
    ),
    "snmp_scan": ToolPolicy(
        "snmp_scan", "medium", "network", "SNMP enumeration.", target_arg="target"
    ),
    "arp_spoof": ToolPolicy(
        "arp_spoof",
        "critical",
        "network",
        "ARP spoofing can intercept or disrupt traffic.",
        approval_required=True,
        destructive=True,
        target_arg="target_ip",
    ),
}


def _get_audit_dir() -> Path:
    DEFAULT_AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_AUDIT_DIR


def _scrub_args(args: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in args.items():
        if key in SENSITIVE_ARG_KEYS:
            scrubbed[key] = "<redacted>" if value else value
        else:
            scrubbed[key] = value
    return scrubbed


def _active_engagement() -> dict | None:
    try:
        from ursa_minor.engagement import get_active

        return get_active()
    except Exception:
        return None


def _scope_check(target: str) -> dict | None:
    if not target or "://" not in target:
        return None
    try:
        from ursa_minor.engagement import check

        return check(target)
    except Exception:
        return None


def _selected_vuln_tests(args: dict[str, Any]) -> set[str]:
    raw = str(args.get("tests", "all") or "all")
    selected = {item.strip().lower() for item in raw.split(",") if item.strip()}
    if not selected or "all" in selected:
        selected = {"sqli", "xss", "cmdi", "lfi", "headers"}
    return selected


def _url_has_query_params(value: str) -> bool:
    try:
        return bool(urllib.parse.urlparse(value).query)
    except Exception:
        return False


def classify_tool_policy(tool_name: str, args: dict[str, Any] | None = None) -> ToolPolicy:
    """Return static or argument-sensitive policy metadata for a tool run."""
    args = args or {}
    base = TOOL_POLICIES.get(
        tool_name,
        ToolPolicy(tool_name, "low", "utility", "No explicit policy metadata."),
    )

    if tool_name == "scan_ports" and bool(args.get("scan_all")):
        return replace(
            base,
            risk_level="high",
            approval_required=True,
            description="Full TCP port sweep across 1-65535.",
        )

    if tool_name == "dirbust" and (args.get("auth_header") or args.get("cookies")):
        return replace(
            base,
            risk_level="high",
            approval_required=True,
            sensitive_result=True,
            description="Authenticated directory discovery.",
        )

    if tool_name == "snmp_scan" and (args.get("brute_force") or args.get("walk")):
        return replace(
            base,
            risk_level="high",
            approval_required=True,
            sensitive_result=True,
            description="SNMP brute force or walk may expose sensitive device data.",
        )

    if tool_name == "vuln_scan":
        selected = _selected_vuln_tests(args)
        target = str(args.get("url") or "")
        if selected <= {"headers"} or not _url_has_query_params(target):
            return replace(
                base,
                risk_level="low",
                approval_required=False,
                destructive=False,
                description="Passive security-header audit.",
            )
        if selected & {"sqli", "cmdi", "lfi"}:
            return replace(
                base,
                risk_level="critical",
                approval_required=True,
                destructive=True,
                description="Active injection probes against URL parameters.",
            )
        if "xss" in selected:
            return replace(
                base,
                risk_level="high",
                approval_required=True,
                description="Active reflected-input probe against URL parameters.",
            )

    return base


def policy_requires_gate(policy: ToolPolicy) -> bool:
    """Return True when a server tool should invoke policy enforcement."""
    return (
        policy.approval_required
        or policy.destructive
        or policy.risk_level in APPROVAL_RISKS
    )


def list_tool_policies(risk_level: str = "") -> list[dict[str, Any]]:
    """Return machine-readable tool policy metadata, optionally filtered by risk."""
    risk = risk_level.strip().lower()
    policies = []
    for policy in TOOL_POLICIES.values():
        if risk and policy.risk_level != risk:
            continue
        policies.append(policy.to_dict())
    return sorted(policies, key=lambda item: (RISK_ORDER.get(item["risk_level"], 9), item["tool_name"]))


def _target_from_args(policy: ToolPolicy, args: dict[str, Any], target: str) -> str:
    if target:
        return str(target)
    value = args.get(policy.target_arg, "")
    return str(value) if value is not None else ""


def evaluate_tool_policy(
    tool_name: str,
    *,
    args: dict[str, Any] | None = None,
    target: str = "",
    actor: str = "operator",
    reason: str = "",
    approval_id: str = "",
) -> ToolPolicyDecision:
    """Evaluate one Ursa Minor tool run against local policy."""
    raw_args = args or {}
    policy = classify_tool_policy(tool_name, raw_args)
    actor = actor.strip() or "operator"
    reason = reason.strip()
    approval_id = approval_id.strip()
    target = _target_from_args(policy, raw_args, target)

    allowed = True
    requires_approval = False
    policy_result = "allow"
    decision_reason = f"Allowed by Ursa Minor local policy ({policy.risk_level} risk)."

    scope = _scope_check(target)
    if scope is not None and not scope.get("in_scope", True):
        allowed = False
        policy_result = "deny"
        decision_reason = f"Target is out of scope: {scope.get('reason', 'scope check failed')}"
    else:
        active = _active_engagement()
        if policy.destructive and active and not active.get("allow_destructive", False):
            allowed = False
            policy_result = "deny"
            decision_reason = "Active engagement does not approve destructive Ursa Minor tools."
        elif policy_requires_gate(policy):
            if not approval_id:
                allowed = False
                requires_approval = True
                policy_result = "approval_required"
                decision_reason = (
                    f"Approval is required for {policy.risk_level}-risk Ursa Minor tool "
                    f"{tool_name}."
                )
            elif not reason:
                allowed = False
                policy_result = "deny"
                decision_reason = "Approved high-risk Ursa Minor tools require a justification reason."
            else:
                decision_reason = (
                    f"Allowed by approval {approval_id} for {policy.risk_level}-risk "
                    f"Ursa Minor tool {tool_name}."
                )

    return ToolPolicyDecision(
        tool_name=tool_name,
        allowed=allowed,
        requires_approval=requires_approval,
        risk_level=policy.risk_level,
        policy_result=policy_result,
        reason=decision_reason,
        actor=actor,
        target=target,
        justification=reason,
        approval_id=approval_id,
        policy=policy.to_dict(),
        args=_scrub_args(raw_args),
    )


def record_policy_audit(decision: ToolPolicyDecision) -> Path:
    """Append one local JSONL audit record for a policy decision."""
    record = {
        "timestamp": time.time(),
        "timestamp_str": datetime.now().isoformat(),
        **decision.to_dict(),
    }
    path = _get_audit_dir() / "minor_policy.jsonl"
    with open(path, "a") as fh:
        fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    return path


def enforce_tool_policy(
    tool_name: str,
    *,
    args: dict[str, Any] | None = None,
    target: str = "",
    actor: str = "operator",
    reason: str = "",
    approval_id: str = "",
) -> ToolPolicyDecision:
    """Evaluate and audit one tool policy decision."""
    decision = evaluate_tool_policy(
        tool_name,
        args=args,
        target=target,
        actor=actor,
        reason=reason,
        approval_id=approval_id,
    )
    record_policy_audit(decision)
    return decision


def format_policy_block(decision: ToolPolicyDecision) -> str:
    """Render an operator-facing policy refusal or approval-required message."""
    status = decision.policy_result.replace("_", " ").upper()
    lines = [
        f"POLICY {status}: {decision.tool_name}",
        f"Risk: {decision.risk_level}",
        f"Target: {decision.target or '(none)'}",
        f"Actor: {decision.actor}",
        f"Decision: {decision.reason}",
    ]
    if decision.requires_approval:
        lines.append("")
        lines.append("Provide policy_approval_id and policy_reason to proceed.")
    return "\n".join(lines)
