"""Governance routes — approvals, risk matrix, and immutable audit."""

import csv
import io
import json
import time
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import Response

from major.db import (
    add_campaign_checklist_item,
    delete_campaign_policy,
    evaluate_campaign_policy_alerts,
    get_immutable_audit,
    list_approval_requests,
    list_campaign_checklist,
    list_campaign_policies,
    upsert_campaign_policy,
    verify_immutable_audit_chain,
)
from major.governance import (
    format_risk_matrix,
    get_policy_remediation_plan,
    process_approval_decision,
    process_bulk_approval_decisions,
)
from major.web.app import templates
from major.web.auth import actor_for, require_role

router = APIRouter(prefix="/governance")


@router.get("/")
async def governance_home(
    request: Request,
    status: str = "pending",
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
):
    approvals = list_approval_requests(
        status=status,
        campaign=campaign,
        tag=tag,
        risk_level=risk_level,
        limit=100,
    )
    audit_check = verify_immutable_audit_chain()
    audit_events = get_immutable_audit(limit=50)
    policies = list_campaign_policies()
    policy_alerts = evaluate_campaign_policy_alerts(campaign=campaign)
    query = urlencode(
        {
            k: v
            for k, v in {
                "status": status,
                "campaign": campaign,
                "tag": tag,
                "risk_level": risk_level,
            }.items()
            if v
        }
    )

    return templates.TemplateResponse(
        request,
        "governance.html",
        {
            "active_page": "governance",
            "approvals": approvals,
            "current_status": status,
            "current_campaign": campaign,
            "current_tag": tag,
            "current_risk_level": risk_level,
            "query_string": query,
            "audit_check": audit_check,
            "audit_events": audit_events,
            "risk_matrix": format_risk_matrix(),
            "policies": policies,
            "policy_alerts": policy_alerts,
        },
    )


@router.post("/approvals/{approval_id}/approve")
async def approve_request(
    request: Request,
    approval_id: str,
    note: str = Form(default=""),
):
    _ = require_role(request, "reviewer")
    result = process_approval_decision(
        approval_id=approval_id,
        approved=True,
        actor=actor_for(request, "governance/approve"),
        note=note,
    )
    if result["status"] == "not_found":
        raise HTTPException(404, "Approval not found")
    if result["status"] == "already_resolved":
        raise HTTPException(409, "Approval is already resolved")
    if result["status"] == "error":
        raise HTTPException(500, "Could not update approval")

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response


@router.post("/approvals/{approval_id}/reject")
async def reject_request(
    request: Request,
    approval_id: str,
    note: str = Form(default=""),
):
    _ = require_role(request, "reviewer")
    result = process_approval_decision(
        approval_id=approval_id,
        approved=False,
        actor=actor_for(request, "governance/reject"),
        note=note,
    )
    if result["status"] == "not_found":
        raise HTTPException(404, "Approval not found")
    if result["status"] == "already_resolved":
        raise HTTPException(409, "Approval is already resolved")
    if result["status"] == "error":
        raise HTTPException(500, "Could not update approval")

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response


@router.post("/approvals/bulk")
async def bulk_approval_decisions(
    request: Request,
    campaign: str = Form(default=""),
    tag: str = Form(default=""),
    risk_level: str = Form(default=""),
    decision: str = Form(default="approve"),
    note: str = Form(default=""),
):
    _ = require_role(request, "reviewer")
    campaign_value = campaign.strip() or None
    tag_value = tag.strip() or None
    approved = decision.strip().lower() == "approve"
    _ = process_bulk_approval_decisions(
        approved=approved,
        actor=actor_for(request, "governance/bulk-approve" if approved else "governance/bulk-reject"),
        note=note,
        campaign=campaign_value,
        tag=tag_value,
        risk_level=risk_level.strip() or None,
        limit=500,
    )

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response


@router.post("/policy")
async def upsert_policy(
    request: Request,
    campaign: str = Form(...),
    max_pending_total: int = Form(default=20),
    max_pending_high: int = Form(default=10),
    max_pending_critical: int = Form(default=2),
    max_oldest_pending_minutes: int = Form(default=60),
    note: str = Form(default=""),
):
    _ = require_role(request, "admin")
    name = campaign.strip()
    if not name:
        raise HTTPException(400, "Campaign is required")
    upsert_campaign_policy(
        campaign=name,
        max_pending_total=max_pending_total,
        max_pending_high=max_pending_high,
        max_pending_critical=max_pending_critical,
        max_oldest_pending_minutes=max_oldest_pending_minutes,
        updated_by=actor_for(request, "governance/policy"),
        note=note,
    )
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/governance/?status=pending&campaign={name}"
    return response


@router.post("/policy/delete")
async def delete_policy(request: Request, campaign: str = Form(...)):
    _ = require_role(request, "admin")
    name = campaign.strip()
    if not name:
        raise HTTPException(400, "Campaign is required")
    _ = delete_campaign_policy(name)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/?status=pending"
    return response


@router.post("/remediation/apply")
async def apply_remediation(
    request: Request,
    campaign: str = Form(...),
    strategy: str = Form(default="reduce-critical"),
    note: str = Form(default=""),
):
    _ = require_role(request, "reviewer")
    name = campaign.strip()
    if not name:
        raise HTTPException(400, "Campaign is required")

    strategy_key = strategy.strip().lower()
    if strategy_key == "reduce-critical":
        risk_level = "critical"
    elif strategy_key == "reduce-high":
        risk_level = "high"
    elif strategy_key == "clear-backlog":
        risk_level = None
    else:
        raise HTTPException(400, "Invalid strategy")

    process_bulk_approval_decisions(
        approved=False,
        actor=actor_for(request, "governance/remediation"),
        note=note or f"Web remediation strategy={strategy_key}",
        campaign=name,
        risk_level=risk_level,
        limit=500,
    )
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/governance/?status=pending&campaign={name}"
    return response


@router.post("/remediation/checklist")
async def create_remediation_checklist(
    request: Request,
    campaign: str = Form(...),
    owner: str = Form(default=""),
    due_in_hours: int = Form(default=24),
):
    user = require_role(request, "reviewer")
    name = campaign.strip()
    if not name:
        raise HTTPException(400, "Campaign is required")
    plan = get_policy_remediation_plan(campaign=name)
    if not plan:
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = f"/governance/?status=pending&campaign={name}"
        return response

    existing_titles = {
        (row.get("title") or "").strip().lower() for row in list_campaign_checklist(campaign=name, limit=5000)
    }
    due_at = None
    if due_in_hours > 0:
        due_at = time.time() + min(due_in_hours, 24 * 14) * 3600
    for item in plan:
        title = f"Policy remediation: {item['metric']} ({item['severity']})"
        if title.lower() in existing_titles:
            continue
        details = (
            f"{item['action']}\n"
            f"Approve path: {item['approve_cmd']}\n"
            f"Reject path: {item['reject_cmd']}"
        )
        add_campaign_checklist_item(
            campaign=name,
            title=title,
            details=details,
            owner=owner.strip() or user.get("username", ""),
            due_at=due_at,
            actor=actor_for(request, "governance/remediation-checklist"),
        )
        existing_titles.add(title.lower())
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/governance/?status=pending&campaign={name}"
    return response


@router.post("/remediation/preview")
async def preview_remediation(
    request: Request,
    campaign: str = Form(...),
    strategy: str = Form(default="reduce-critical"),
):
    name = campaign.strip()
    if not name:
        raise HTTPException(400, "Campaign is required")

    strategy_key = strategy.strip().lower()
    if strategy_key == "reduce-critical":
        risk_level = "critical"
    elif strategy_key == "reduce-high":
        risk_level = "high"
    elif strategy_key == "clear-backlog":
        risk_level = None
    else:
        raise HTTPException(400, "Invalid strategy")

    rows = list_approval_requests(
        status="pending",
        campaign=name,
        risk_level=risk_level,
        limit=5000,
    )
    return templates.TemplateResponse(
        request,
        "partials/remediation_preview.html",
        {
            "campaign": name,
            "strategy": strategy_key,
            "count": len(rows),
        },
    )


@router.get("/report")
async def governance_report(format: str = "json"):
    fmt = format.strip().lower()
    if fmt not in {"json", "csv"}:
        raise HTTPException(400, "format must be json or csv")

    policies = list_campaign_policies()
    alerts = evaluate_campaign_policy_alerts()
    approvals = list_approval_requests(status="pending", limit=5000)

    if fmt == "json":
        payload = {
            "counts": {
                "policies": len(policies),
                "alerts": len(alerts),
                "pending_approvals": len(approvals),
            },
            "policies": policies,
            "alerts": alerts,
            "pending_approvals": approvals,
        }
        body = json.dumps(payload, indent=2)
        filename = "governance_report.json"
        content_type = "application/json"
    else:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["section", "campaign", "metric", "value", "extra"])
        for p in policies:
            writer.writerow(
                [
                    "policy",
                    p["campaign"],
                    "thresholds",
                    (
                        f"total={p['max_pending_total']} high={p['max_pending_high']} "
                        f"critical={p['max_pending_critical']} oldest_min={p['max_oldest_pending_minutes']}"
                    ),
                    p.get("note", ""),
                ]
            )
        for a in alerts:
            writer.writerow(
                [
                    "alert",
                    a["campaign"],
                    a["metric"],
                    a["value"],
                    f"threshold={a['threshold']} severity={a['severity']}",
                ]
            )
        for ap in approvals:
            writer.writerow(
                [
                    "pending_approval",
                    ap.get("campaign") or "unassigned",
                    ap.get("risk_level", ""),
                    ap.get("id", ""),
                    ap.get("reason", ""),
                ]
            )
        body = buffer.getvalue()
        filename = "governance_report.csv"
        content_type = "text/csv"

    response = Response(content=body, media_type=content_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
