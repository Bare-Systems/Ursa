"""Dashboard route — overview of C2 status."""

import time

from fastapi import APIRouter, Request

from major.db import (
    evaluate_campaign_policy_alerts,
    get_events,
    list_approval_requests,
    list_campaign_checklist,
    list_sessions,
    list_tasks,
)
from major.governance import build_policy_remediation_recommendations
from major.web.app import templates

router = APIRouter()


@router.get("/")
async def dashboard(request: Request):
    sessions = list_sessions()
    active = [s for s in sessions if s["status"] == "active"]
    stale = [s for s in sessions if s["status"] == "stale"]
    dead = [s for s in sessions if s["status"] == "dead"]
    pending_approvals = list_approval_requests(status="pending", limit=500)
    policy_alerts = evaluate_campaign_policy_alerts()
    policy_recommendations = build_policy_remediation_recommendations(policy_alerts)
    recent_tasks = list_tasks(limit=200)
    recent_events = get_events(limit=200)
    checklist_items = list_campaign_checklist(limit=5000)
    now = time.time()
    overdue_items = []
    due_soon_items = []
    for item in checklist_items:
        if item.get("status") == "done":
            continue
        due_at = item.get("due_at")
        if not due_at:
            continue
        if due_at < now:
            overdue_items.append(item)
        elif due_at <= now + 24 * 3600:
            due_soon_items.append(item)

    checklist_by_campaign: dict[str, dict[str, int]] = {}
    for item in checklist_items:
        campaign = (item.get("campaign") or "unassigned").strip() or "unassigned"
        bucket = checklist_by_campaign.setdefault(campaign, {"open": 0, "overdue": 0, "due_soon": 0})
        if item.get("status") != "done":
            bucket["open"] += 1
        due_at = item.get("due_at")
        if item.get("status") != "done" and due_at:
            if due_at < now:
                bucket["overdue"] += 1
            elif due_at <= now + 24 * 3600:
                bucket["due_soon"] += 1
    top_checklist_campaigns = sorted(
        checklist_by_campaign.items(),
        key=lambda item: (item[1]["overdue"], item[1]["due_soon"], item[1]["open"]),
        reverse=True,
    )[:8]

    campaigns: dict[str, dict[str, int]] = {}
    for s in sessions:
        name = (s.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["sessions"] += 1
    for t in recent_tasks:
        name = (t.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["tasks"] += 1
    for e in recent_events:
        name = (e.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["events"] += 1
    top_campaigns = sorted(
        campaigns.items(),
        key=lambda item: item[1]["sessions"] + item[1]["tasks"] + item[1]["events"],
        reverse=True,
    )[:6]
    pending_by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pending_by_campaign: dict[str, int] = {}
    for approval in pending_approvals:
        risk = (approval.get("risk_level") or "").lower()
        if risk in pending_by_risk:
            pending_by_risk[risk] += 1
        campaign = (approval.get("campaign") or "unassigned").strip() or "unassigned"
        pending_by_campaign[campaign] = pending_by_campaign.get(campaign, 0) + 1
    top_pending_campaigns = sorted(
        pending_by_campaign.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:6]

    return templates.TemplateResponse(request, "dashboard.html", {
        "active_page": "dashboard",
        "active_count": len(active),
        "stale_count": len(stale),
        "dead_count": len(dead),
        "total_sessions": len(sessions),
        "pending_approvals": len(pending_approvals),
        "policy_alert_count": len(policy_alerts),
        "checklist_overdue_count": len(overdue_items),
        "checklist_due_soon_count": len(due_soon_items),
        "policy_alerts": policy_alerts[:6],
        "policy_recommendations": policy_recommendations[:6],
        "recent_events": recent_events[:15],
        "recent_tasks": recent_tasks[:10],
        "active_sessions": active[:5],
        "top_campaigns": top_campaigns,
        "pending_by_risk": pending_by_risk,
        "top_pending_campaigns": top_pending_campaigns,
        "top_checklist_campaigns": top_checklist_campaigns,
        "overdue_checklist_items": sorted(overdue_items, key=lambda row: row.get("due_at") or 0)[:12],
        "due_soon_checklist_items": sorted(due_soon_items, key=lambda row: row.get("due_at") or 0)[:12],
    })
