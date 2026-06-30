"""Ursa Major governance and policy enforcement helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

from major.config import get_config
from major.db import (
    append_immutable_audit_event,
    create_approval_request,
    create_task,
    evaluate_campaign_policy_alerts,
    get_approval_request,
    list_approval_requests,
    resolve_approval_request,
)

RISK_MATRIX: dict[str, str] = {
    "sysinfo": "low",
    "pwd": "low",
    "whoami": "low",
    "env": "low",
    "ls": "medium",
    "ps": "medium",
    "cd": "medium",
    "download": "high",
    "upload": "high",
    "sleep": "medium",
    "shell": "high",
    "kill": "critical",
    "arp_spoof": "critical",
    "arp_spoof_stop": "low",
}

SHELL_HIGH_RISK_TOKENS = {
    "rm -rf",
    "chmod 777",
    "chown ",
    "net user",
    "reg add",
    "powershell -enc",
    "nc -e",
    "curl ",
    "wget ",
}

SHELL_CRITICAL_TOKENS = {
    "vssadmin delete shadows",
    "bcdedit ",
    "diskpart",
    "cipher /w",
}


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    risk_level: str
    policy_result: str
    reason: str
    policy_path: str = "bearclaw/local"


def _classify_shell_risk(command: str) -> str:
    cmd = command.lower().strip()
    if any(token in cmd for token in SHELL_CRITICAL_TOKENS):
        return "critical"
    if any(token in cmd for token in SHELL_HIGH_RISK_TOKENS):
        return "high"
    if len(cmd) > 140:
        return "high"
    return "medium"


def classify_task_risk(task_type: str, args: dict[str, Any] | None = None) -> str:
    task = (task_type or "").strip().lower()
    args = args or {}
    if task == "shell":
        return _classify_shell_risk(str(args.get("command", "")))
    return RISK_MATRIX.get(task, "high")


def enforce_bearclaw_policy(
    *,
    action: str,
    task_type: str,
    args: dict[str, Any] | None,
    actor: str,
    approval_id: str | None = None,
) -> PolicyDecision:
    """Policy decision point aligned to the BearClaw path."""
    cfg = get_config()
    governance = cfg.get("major.governance", {}) or {}
    risk_level = classify_task_risk(task_type, args)
    step_up_enabled = bool(governance.get("require_step_up_approval", False))
    step_up_risks = set(governance.get("step_up_risks", ["high", "critical"]))
    mode = governance.get("bearclaw_mode", "local")

    if mode == "disabled":
        return PolicyDecision(
            allowed=True,
            requires_approval=False,
            risk_level=risk_level,
            policy_result="allow",
            reason="BearClaw governance disabled by configuration.",
            policy_path="bearclaw/disabled",
        )

    if step_up_enabled and risk_level in step_up_risks and not approval_id:
        return PolicyDecision(
            allowed=False,
            requires_approval=True,
            risk_level=risk_level,
            policy_result="step_up_required",
            reason=f"Step-up approval is required for {risk_level}-risk action.",
        )

    if step_up_enabled and risk_level in step_up_risks and approval_id:
        approval = get_approval_request(approval_id)
        if not approval:
            return PolicyDecision(
                allowed=False,
                requires_approval=False,
                risk_level=risk_level,
                policy_result="deny",
                reason=f"Approval {approval_id} was not found.",
            )
        if approval.get("status") != "approved":
            return PolicyDecision(
                allowed=False,
                requires_approval=False,
                risk_level=risk_level,
                policy_result="deny",
                reason=f"Approval {approval_id} is not approved.",
            )
        if approval.get("task_type") and approval.get("task_type") != task_type:
            return PolicyDecision(
                allowed=False,
                requires_approval=False,
                risk_level=risk_level,
                policy_result="deny",
                reason=f"Approval {approval_id} does not match task type {task_type}.",
            )

    return PolicyDecision(
        allowed=True,
        requires_approval=False,
        risk_level=risk_level,
        policy_result="allow",
        reason=f"Allowed by BearClaw local policy ({risk_level} risk).",
    )


def queue_task_with_policy(
    *,
    session_id: str,
    task_type: str,
    args: dict[str, Any] | None = None,
    actor: str = "operator",
    approval_id: str | None = None,
) -> dict[str, Any]:
    """Enqueue a task through governance controls and immutable auditing."""
    task_args = args or {}
    decision = enforce_bearclaw_policy(
        action="queue_task",
        task_type=task_type,
        args=task_args,
        actor=actor,
        approval_id=approval_id,
    )

    audit_details = {
        "task_type": task_type,
        "args": task_args,
        "reason": decision.reason,
        "policy_path": decision.policy_path,
    }

    if decision.requires_approval:
        approval_id = create_approval_request(
            action="queue_task",
            risk_level=decision.risk_level,
            session_id=session_id,
            task_type=task_type,
            args=task_args,
            requested_by=actor,
            reason=decision.reason,
        )
        append_immutable_audit_event(
            actor=actor,
            action="queue_task",
            session_id=session_id,
            approval_id=approval_id,
            risk_level=decision.risk_level,
            policy_result=decision.policy_result,
            details={
                **audit_details,
                "approval_id": approval_id,
                "status": "awaiting_approval",
            },
        )
        return {
            "status": "approval_required",
            "approval_id": approval_id,
            "risk_level": decision.risk_level,
            "message": decision.reason,
        }

    if not decision.allowed:
        append_immutable_audit_event(
            actor=actor,
            action="queue_task",
            session_id=session_id,
            approval_id=approval_id,
            risk_level=decision.risk_level,
            policy_result=decision.policy_result,
            details={**audit_details, "status": "denied"},
        )
        return {
            "status": "denied",
            "risk_level": decision.risk_level,
            "message": decision.reason,
        }

    task_id = create_task(session_id, task_type, task_args)
    append_immutable_audit_event(
        actor=actor,
        action="queue_task",
        session_id=session_id,
        task_id=task_id,
        approval_id=approval_id,
        risk_level=decision.risk_level,
        policy_result=decision.policy_result,
        details={**audit_details, "task_id": task_id},
    )
    return {
        "status": "queued",
        "task_id": task_id,
        "risk_level": decision.risk_level,
        "message": decision.reason,
    }


def format_risk_matrix() -> str:
    """Text table of policy risk mapping for operator visibility."""
    rows = ["TASK TYPE      RISK", "-------------------"]
    for task_type in sorted(RISK_MATRIX):
        rows.append(f"{task_type:<13} {RISK_MATRIX[task_type]}")
    rows.append("shell         command-dependent (medium/high/critical)")
    return "\n".join(rows)


def normalize_args_string(args: str) -> dict[str, Any]:
    """Parse JSON args string from MCP tools."""
    try:
        parsed = json.loads(args) if isinstance(args, str) else args
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON args: {args}") from exc
    return parsed if isinstance(parsed, dict) else {}


def _sign_approval_decision(approval_id: str, actor: str, approved: bool, note: str, signed_at: float) -> str:
    """Create an HMAC signature for approval decisions."""
    secret = str(get_config().get("major.governance.approval_signing_key", "")).encode("utf-8")
    payload = f"{approval_id}|{actor}|{1 if approved else 0}|{note}|{int(signed_at)}".encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def process_approval_decision(
    *,
    approval_id: str,
    approved: bool,
    actor: str,
    note: str = "",
) -> dict[str, Any]:
    """Resolve one approval and emit immutable audit entries."""
    req = get_approval_request(approval_id)
    if not req:
        return {"status": "not_found", "approval_id": approval_id}
    if req.get("status") != "pending":
        return {
            "status": "already_resolved",
            "approval_id": approval_id,
            "current_status": req.get("status"),
        }

    changed = resolve_approval_request(
        approval_id,
        approved=approved,
        decided_by=actor,
        note=note,
    )
    if not changed:
        return {"status": "error", "approval_id": approval_id}

    signed_at = time.time()
    approval_signature = _sign_approval_decision(approval_id, actor, approved, note, signed_at)

    if approved:
        task_args = json.loads(req.get("args") or "{}")
        queue_decision = queue_task_with_policy(
            session_id=req["session_id"],
            task_type=req.get("task_type") or "shell",
            args=task_args,
            actor=actor,
            approval_id=approval_id,
        )
        append_immutable_audit_event(
            actor=actor,
            action="approval_decision",
            session_id=req.get("session_id"),
            approval_id=approval_id,
            risk_level=req.get("risk_level", "unknown"),
            policy_result="approved",
            details={
                "note": note,
                "queue_result": queue_decision["status"],
                "approval_signature": approval_signature,
                "signed_at": signed_at,
            },
        )
        return {
            "status": "approved",
            "approval_id": approval_id,
            "queue_result": queue_decision["status"],
            "task_id": queue_decision.get("task_id"),
            "approval_signature": approval_signature,
            "signed_at": signed_at,
        }

    append_immutable_audit_event(
        actor=actor,
        action="approval_decision",
        session_id=req.get("session_id"),
        approval_id=approval_id,
        risk_level=req.get("risk_level", "unknown"),
        policy_result="rejected",
        details={
            "note": note,
            "approval_signature": approval_signature,
            "signed_at": signed_at,
        },
    )
    return {
        "status": "rejected",
        "approval_id": approval_id,
        "approval_signature": approval_signature,
        "signed_at": signed_at,
    }


def process_bulk_approval_decisions(
    *,
    approved: bool,
    actor: str,
    note: str = "",
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Resolve pending approvals filtered by campaign/tag."""
    pending = list_approval_requests(
        status="pending",
        campaign=campaign,
        tag=tag,
        risk_level=risk_level,
        limit=limit,
    )
    results = [
        process_approval_decision(
            approval_id=row["id"],
            approved=approved,
            actor=actor,
            note=note,
        )
        for row in pending
    ]
    summary = {
        "matched": len(pending),
        "processed": len(results),
        "approved": sum(1 for r in results if r["status"] == "approved"),
        "rejected": sum(1 for r in results if r["status"] == "rejected"),
        "failed": sum(1 for r in results if r["status"] in {"error", "not_found"}),
        "already_resolved": sum(1 for r in results if r["status"] == "already_resolved"),
        "results": results,
    }
    return summary


def build_policy_remediation_recommendations(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Build operator-safe remediation suggestions from policy alerts."""
    recommendations: list[dict[str, str]] = []
    for alert in alerts:
        campaign = str(alert.get("campaign", "unassigned"))
        metric = str(alert.get("metric", "total"))
        severity = str(alert.get("severity", "warning"))
        risk = "critical" if metric == "critical" else ("high" if metric == "high" else "")
        if metric == "critical":
            action = "Prioritize critical approvals. If malicious/noisy, bulk reject critical queue."
        elif metric == "high":
            action = "Drain high-risk queue by explicit approve/reject decisions."
        else:
            action = "Reduce total pending queue by triaging oldest requests first."

        approve_cmd = (
            f"ursa_approve_campaign(campaign='{campaign}', risk_level='{risk}')"
            if risk
            else f"ursa_approve_campaign(campaign='{campaign}')"
        )
        reject_cmd = (
            f"ursa_reject_campaign(campaign='{campaign}', risk_level='{risk}')"
            if risk
            else f"ursa_reject_campaign(campaign='{campaign}')"
        )
        recommendations.append(
            {
                "campaign": campaign,
                "metric": metric,
                "severity": severity,
                "action": action,
                "approve_cmd": approve_cmd,
                "reject_cmd": reject_cmd,
            }
        )
    return recommendations


def get_policy_remediation_plan(campaign: str | None = None) -> list[dict[str, str]]:
    """Fetch current alerts and produce remediation guidance."""
    alerts = evaluate_campaign_policy_alerts(campaign=campaign)
    return build_policy_remediation_recommendations(alerts)
