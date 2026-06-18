"""Bearer-authenticated JSON API for the BearClaw Rails port."""

import json
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from major.db import (
    add_campaign_checklist_item,
    add_campaign_note,
    apply_campaign_playbook,
    create_user,
    delete_campaign_checklist_item,
    delete_campaign_note,
    delete_campaign_playbook,
    delete_campaign_policy,
    evaluate_campaign_policy_alerts,
    get_campaign_playbook,
    get_campaign_policy,
    get_campaign_timeline,
    get_events,
    get_file,
    get_immutable_audit,
    get_session,
    get_task,
    get_user_by_id,
    kill_session,
    list_approval_requests,
    list_campaign_checklist,
    list_campaign_checklist_history,
    list_campaign_notes,
    list_campaign_playbooks,
    list_campaign_policies,
    list_files,
    list_sessions,
    list_tasks,
    list_users,
    set_user_password,
    snapshot_campaign_checklist_to_playbook,
    update_campaign_checklist_item,
    update_session_info,
    update_user_role_status,
    upsert_campaign_playbook,
    upsert_campaign_policy,
    verify_immutable_audit_chain,
)
from major.governance import (
    build_policy_remediation_recommendations,
    format_risk_matrix,
    get_policy_remediation_plan,
    process_approval_decision,
    process_bulk_approval_decisions,
    queue_task_with_policy,
)
from major.netinsight import (
    device_count,
    list_devices,
    list_scans,
    new_devices,
    record_scan,
    set_baseline,
    set_device_trust,
)
from major.pihole import (
    dns_overview,
)
from major.pihole import (
    top_domains as dns_top_domains,
)
from major.pihole import (
    top_talkers as dns_top_talkers,
)
from major.web.auth import api_actor_for, require_api_role

router = APIRouter(prefix="/api/v1")
REQUIRE_API_ROLE = Depends(require_api_role)

CHECKLIST_STATUSES = {"pending", "in_progress", "blocked", "done"}
CHECKLIST_SORT_OPTIONS = {"created_desc", "created_asc", "updated_desc", "updated_asc", "due_asc", "due_desc"}


def _parse_due_at(value):
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).strip()).timestamp()
    except ValueError:
        raise HTTPException(400, "Invalid due_at") from None


def _json_args(args_value):
    if isinstance(args_value, dict):
        return args_value
    if not args_value:
        return {}
    try:
        return json.loads(args_value)
    except (TypeError, json.JSONDecodeError):
        return {}


def _campaign_detail_payload(campaign_name: str, *, status_filter: str = "", owner_filter: str = "", text_filter: str = "", sort: str = "created_desc") -> dict:
    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=150)
    events = get_events(campaign=campaign_name, limit=150)
    pending_approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=150)
    policy = get_campaign_policy(campaign_name)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign_name)
    recommendations = get_policy_remediation_plan(campaign=campaign_name)
    timeline = get_campaign_timeline(campaign_name, limit=200)
    notes = list_campaign_notes(campaign=campaign_name, limit=200)
    checklist_items = list_campaign_checklist(
        campaign=campaign_name,
        status=status_filter or None,
        owner=owner_filter or None,
        text=text_filter or None,
        sort=sort,
        limit=300,
    )
    checklist_all = list_campaign_checklist(campaign=campaign_name, limit=1000)
    checklist_history = list_campaign_checklist_history(campaign=campaign_name, limit=120)
    playbooks = list_campaign_playbooks(limit=100)

    checklist_counts = {"pending": 0, "in_progress": 0, "blocked": 0, "done": 0}
    for item in checklist_all:
        status = (item.get("status") or "pending").strip().lower()
        if status not in checklist_counts:
            status = "pending"
        checklist_counts[status] += 1

    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for session in sessions:
        status = session.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    for task in tasks:
        task_type = task.get("task_type", "unknown")
        by_task_type[task_type] = by_task_type.get(task_type, 0) + 1
    for approval in pending_approvals:
        risk = (approval.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1

    return {
        "campaign_name": campaign_name,
        "sessions": sessions,
        "tasks": tasks,
        "events": events,
        "pending_approvals": pending_approvals,
        "policy": policy,
        "alerts": alerts,
        "recommendations": recommendations,
        "timeline": timeline,
        "notes": notes,
        "checklist_items": checklist_items,
        "checklist_counts": checklist_counts,
        "checklist_history": checklist_history,
        "playbooks": playbooks,
        "checklist_filters": {
            "status": status_filter,
            "owner": owner_filter,
            "q": text_filter,
            "sort": sort,
        },
        "by_status": by_status,
        "by_task_type": sorted(by_task_type.items(), key=lambda item: item[1], reverse=True)[:8],
        "by_risk": by_risk,
    }


@router.get("/overview")
async def overview(_: dict = REQUIRE_API_ROLE):
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

    campaigns: dict[str, dict[str, int]] = {}
    for session in sessions:
        name = (session.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["sessions"] += 1
    for task in recent_tasks:
        name = (task.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["tasks"] += 1
    for event in recent_events:
        name = (event.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["events"] += 1

    pending_by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pending_by_campaign: dict[str, int] = {}
    for approval in pending_approvals:
        risk = (approval.get("risk_level") or "").lower()
        if risk in pending_by_risk:
            pending_by_risk[risk] += 1
        campaign = (approval.get("campaign") or "unassigned").strip() or "unassigned"
        pending_by_campaign[campaign] = pending_by_campaign.get(campaign, 0) + 1

    return {
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
        "top_campaigns": sorted(
            campaigns.items(),
            key=lambda item: item[1]["sessions"] + item[1]["tasks"] + item[1]["events"],
            reverse=True,
        )[:6],
        "pending_by_risk": pending_by_risk,
        "top_pending_campaigns": sorted(pending_by_campaign.items(), key=lambda item: item[1], reverse=True)[:6],
        "top_checklist_campaigns": sorted(
            checklist_by_campaign.items(),
            key=lambda item: (item[1]["overdue"], item[1]["due_soon"], item[1]["open"]),
            reverse=True,
        )[:8],
        "overdue_checklist_items": sorted(overdue_items, key=lambda row: row.get("due_at") or 0)[:12],
        "due_soon_checklist_items": sorted(due_soon_items, key=lambda row: row.get("due_at") or 0)[:12],
    }


@router.get("/sessions")
async def sessions_index(status: str | None = None, campaign: str | None = None, tag: str | None = None, _: dict = REQUIRE_API_ROLE):
    return {"sessions": list_sessions(status=status, campaign=campaign, tag=tag)}


@router.get("/sessions/{session_id}")
async def sessions_show(session_id: str, _: dict = REQUIRE_API_ROLE):
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return {
        "session": session,
        "tasks": list_tasks(session_id=session_id, limit=50),
        "files": list_files(session_id=session_id),
        "events": get_events(session_id=session_id, limit=20),
    }


@router.patch("/sessions/{session_id}/context")
async def sessions_context(session_id: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    update_session_info(
        session_id,
        campaign=str(payload.get("campaign", "")).strip(),
        tags=str(payload.get("tags", "")).strip(),
    )
    return {"ok": True, "actor": api_actor_for(user, "sessions/context")}


@router.post("/sessions/{session_id}/kill")
async def sessions_kill(session_id: str, user: dict = REQUIRE_API_ROLE):
    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="kill",
        args={},
        actor=api_actor_for(user, "sessions/kill"),
    )
    if decision["status"] != "queued":
        raise HTTPException(403, decision["message"])
    kill_session(session_id)
    return decision


@router.post("/sessions/{session_id}/tasks")
async def sessions_task(session_id: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    task_type = str(payload.get("task_type", "shell")).strip() or "shell"
    command = str(payload.get("command", "")).strip()
    args = {"command": command} if task_type == "shell" and command else dict(payload.get("args") or {})
    decision = queue_task_with_policy(
        session_id=session_id,
        task_type=task_type,
        args=args,
        actor=api_actor_for(user, "sessions/task"),
    )
    if decision["status"] != "queued":
        raise HTTPException(403, decision["message"])
    return {"decision": decision, "task": get_task(decision["task_id"])}


@router.get("/tasks")
async def tasks_index(
    session_id: str | None = None,
    status: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
    _: dict = REQUIRE_API_ROLE,
):
    return {"tasks": list_tasks(session_id=session_id, status=status, campaign=campaign, tag=tag, limit=100)}


@router.get("/tasks/{task_id}")
async def tasks_show(task_id: str, _: dict = REQUIRE_API_ROLE):
    task = get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    task["parsed_args"] = _json_args(task.get("args"))
    return {"task": task}


@router.get("/files")
async def files_index(session_id: str | None = None, _: dict = REQUIRE_API_ROLE):
    return {"files": list_files(session_id=session_id)}


@router.get("/files/{file_id}/download")
async def files_download(file_id: str, _: dict = REQUIRE_API_ROLE):
    file_row = get_file(file_id)
    if not file_row:
        raise HTTPException(404, "File not found")
    response = Response(content=file_row["data"], media_type="application/octet-stream")
    response.headers["Content-Disposition"] = f'attachment; filename="{file_row["filename"]}"'
    return response


@router.get("/events")
async def events_index(
    level: str | None = None,
    session_id: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
    _: dict = REQUIRE_API_ROLE,
):
    return {"events": get_events(limit=200, level=level, session_id=session_id, campaign=campaign, tag=tag)}


@router.get("/campaigns")
async def campaigns_index(_: dict = REQUIRE_API_ROLE):
    sessions = list_sessions()
    tasks = list_tasks(limit=2000)
    events = get_events(limit=2000)
    approvals = list_approval_requests(status="pending", limit=2000)
    campaigns: dict[str, dict[str, int]] = {}
    for rows, key in ((sessions, "sessions"), (tasks, "tasks"), (events, "events"), (approvals, "approvals")):
        for row in rows:
            name = (row.get("campaign") or "unassigned").strip() or "unassigned"
            campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
            campaigns[name][key] += 1
    return {
        "campaigns": sorted(
            campaigns.items(),
            key=lambda item: item[1]["sessions"] + item[1]["tasks"] + item[1]["events"] + item[1]["approvals"],
            reverse=True,
        )
    }


@router.get("/campaigns/playbooks")
async def campaigns_playbooks(_: dict = REQUIRE_API_ROLE):
    return {"playbooks": list_campaign_playbooks(limit=300)}


@router.post("/campaigns/playbooks")
async def campaigns_playbooks_save(payload: dict, _: dict = REQUIRE_API_ROLE):
    playbook = upsert_campaign_playbook(
        str(payload.get("name", "")).strip(),
        payload.get("items") or [],
        description=str(payload.get("description", "")).strip(),
    )
    return {"playbook": playbook}


@router.delete("/campaigns/playbooks/{name}")
async def campaigns_playbooks_delete(name: str, _: dict = REQUIRE_API_ROLE):
    return {"ok": delete_campaign_playbook(name.strip())}


@router.get("/campaigns/playbooks/{name}")
async def campaigns_playbook_show(name: str, _: dict = REQUIRE_API_ROLE):
    playbook = get_campaign_playbook(name.strip())
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    return {"playbook": playbook}


@router.get("/campaigns/{campaign_name}")
async def campaigns_show(
    campaign_name: str,
    status: str = "",
    owner: str = "",
    q: str = "",
    sort: str = "created_desc",
    _: dict = REQUIRE_API_ROLE,
):
    if status and status not in CHECKLIST_STATUSES:
        status = ""
    if sort not in CHECKLIST_SORT_OPTIONS:
        sort = "created_desc"
    return _campaign_detail_payload(campaign_name, status_filter=status, owner_filter=owner, text_filter=q, sort=sort)


@router.post("/campaigns/{campaign_name}/notes")
async def campaigns_add_note(campaign_name: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    note = str(payload.get("note", "")).strip()
    if note:
        add_campaign_note(campaign_name, note, author=api_actor_for(user, "campaigns/note"))
    return {"ok": True}


@router.delete("/campaigns/{campaign_name}/notes/{note_id}")
async def campaigns_delete_note(campaign_name: str, note_id: int, _: dict = REQUIRE_API_ROLE):
    return {"ok": delete_campaign_note(note_id), "campaign_name": campaign_name}


@router.post("/campaigns/{campaign_name}/checklist")
async def campaigns_add_checklist(campaign_name: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    add_campaign_checklist_item(
        campaign=campaign_name,
        title=str(payload.get("title", "")).strip(),
        details=str(payload.get("details", "")).strip(),
        owner=str(payload.get("owner", "")).strip(),
        due_at=_parse_due_at(payload.get("due_at")),
        actor=api_actor_for(user, "campaigns/checklist-add"),
    )
    return {"ok": True}


@router.patch("/campaigns/{campaign_name}/checklist/{item_id}")
async def campaigns_update_checklist(campaign_name: str, item_id: int, payload: dict, user: dict = REQUIRE_API_ROLE):
    updates = {}
    for key in ("title", "details", "status", "owner"):
        if key in payload:
            value = payload.get(key)
            if value is not None:
                updates[key] = str(value).strip()
    if "due_at" in payload:
        updates["due_at"] = _parse_due_at(payload.get("due_at"))
    if "status" in updates and updates["status"] not in CHECKLIST_STATUSES:
        raise HTTPException(400, "Invalid checklist status")
    return {"ok": update_campaign_checklist_item(item_id, actor=api_actor_for(user, "campaigns/checklist-update"), **updates), "campaign_name": campaign_name}


@router.delete("/campaigns/{campaign_name}/checklist/{item_id}")
async def campaigns_delete_checklist(campaign_name: str, item_id: int, user: dict = REQUIRE_API_ROLE):
    return {"ok": delete_campaign_checklist_item(item_id, actor=api_actor_for(user, "campaigns/checklist-delete")), "campaign_name": campaign_name}


@router.patch("/campaigns/{campaign_name}/checklist")
async def campaigns_bulk_checklist(campaign_name: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    action_status = str(payload.get("action_status", "")).strip().lower()
    if action_status not in CHECKLIST_STATUSES:
        raise HTTPException(400, "Invalid checklist status")
    rows = list_campaign_checklist(
        campaign=campaign_name,
        status=str(payload.get("status_filter", "")).strip().lower() or None,
        owner=str(payload.get("owner_filter", "")).strip() or None,
        text=str(payload.get("q_filter", "")).strip() or None,
        sort=str(payload.get("sort_filter", "created_desc")).strip().lower(),
        limit=1000,
    )
    updated = 0
    for row in rows:
        if update_campaign_checklist_item(int(row["id"]), status=action_status, actor=api_actor_for(user, "campaigns/checklist-bulk")):
            updated += 1
    return {"ok": True, "updated": updated}


@router.post("/campaigns/{campaign_name}/playbook/apply")
async def campaigns_apply_playbook(campaign_name: str, payload: dict, _: dict = REQUIRE_API_ROLE):
    return apply_campaign_playbook(
        campaign=campaign_name,
        playbook_name=str(payload.get("playbook", "")).strip(),
        default_owner=str(payload.get("owner", "")).strip(),
        skip_existing=True,
    )


@router.post("/campaigns/{campaign_name}/playbook/snapshot")
async def campaigns_snapshot_playbook(campaign_name: str, payload: dict, _: dict = REQUIRE_API_ROLE):
    return snapshot_campaign_checklist_to_playbook(
        campaign=campaign_name,
        playbook_name=str(payload.get("playbook_name", "")).strip(),
        description=str(payload.get("description", "")).strip(),
        only_open=bool(payload.get("only_open", True)),
    )


@router.get("/campaigns/{campaign_name}/handoff")
async def campaigns_handoff(campaign_name: str, _: dict = REQUIRE_API_ROLE):
    return _campaign_detail_payload(campaign_name)


@router.get("/governance")
async def governance_index(
    status: str = "pending",
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
    _: dict = REQUIRE_API_ROLE,
):
    policy_alerts = evaluate_campaign_policy_alerts(campaign=campaign)
    return {
        "approvals": list_approval_requests(status=status, campaign=campaign, tag=tag, risk_level=risk_level, limit=100),
        "audit_check": verify_immutable_audit_chain(),
        "audit_events": get_immutable_audit(limit=50),
        "risk_matrix": format_risk_matrix(),
        "policies": list_campaign_policies(),
        "policy_alerts": policy_alerts,
        "recommendations": build_policy_remediation_recommendations(policy_alerts),
        "current_status": status,
        "current_campaign": campaign,
        "current_tag": tag,
        "current_risk_level": risk_level,
    }


@router.post("/governance/approvals/{approval_id}/approve")
async def governance_approve(approval_id: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    return process_approval_decision(
        approval_id=approval_id,
        approved=True,
        actor=api_actor_for(user, "governance/approve"),
        note=str(payload.get("note", "")).strip(),
    )


@router.post("/governance/approvals/{approval_id}/reject")
async def governance_reject(approval_id: str, payload: dict, user: dict = REQUIRE_API_ROLE):
    return process_approval_decision(
        approval_id=approval_id,
        approved=False,
        actor=api_actor_for(user, "governance/reject"),
        note=str(payload.get("note", "")).strip(),
    )


@router.post("/governance/approvals/bulk")
async def governance_bulk(payload: dict, user: dict = REQUIRE_API_ROLE):
    return process_bulk_approval_decisions(
        approved=str(payload.get("decision", "approve")).strip().lower() == "approve",
        actor=api_actor_for(user, "governance/bulk"),
        note=str(payload.get("note", "")).strip(),
        campaign=str(payload.get("campaign", "")).strip() or None,
        tag=str(payload.get("tag", "")).strip() or None,
        risk_level=str(payload.get("risk_level", "")).strip() or None,
        limit=500,
    )


@router.post("/governance/policy")
async def governance_policy(payload: dict, user: dict = REQUIRE_API_ROLE):
    campaign = str(payload.get("campaign", "")).strip()
    if not campaign:
        raise HTTPException(400, "Campaign is required")
    return {
        "policy": upsert_campaign_policy(
            campaign=campaign,
            max_pending_total=int(payload.get("max_pending_total", 20)),
            max_pending_high=int(payload.get("max_pending_high", 10)),
            max_pending_critical=int(payload.get("max_pending_critical", 2)),
            max_oldest_pending_minutes=int(payload.get("max_oldest_pending_minutes", 60)),
            updated_by=api_actor_for(user, "governance/policy"),
            note=str(payload.get("note", "")).strip(),
        )
    }


@router.delete("/governance/policy/{campaign}")
async def governance_delete_policy(campaign: str, _: dict = REQUIRE_API_ROLE):
    return {"ok": delete_campaign_policy(campaign.strip())}


@router.post("/governance/remediation/apply")
async def governance_apply_remediation(payload: dict, user: dict = REQUIRE_API_ROLE):
    strategy = str(payload.get("strategy", "reduce-critical")).strip().lower()
    if strategy == "reduce-critical":
        risk_level = "critical"
    elif strategy == "reduce-high":
        risk_level = "high"
    elif strategy == "clear-backlog":
        risk_level = None
    else:
        raise HTTPException(400, "Invalid strategy")
    return process_bulk_approval_decisions(
        approved=False,
        actor=api_actor_for(user, "governance/remediation"),
        note=str(payload.get("note", "")).strip() or f"API remediation strategy={strategy}",
        campaign=str(payload.get("campaign", "")).strip() or None,
        risk_level=risk_level,
        limit=500,
    )


@router.post("/governance/remediation/checklist")
async def governance_remediation_checklist(payload: dict, user: dict = REQUIRE_API_ROLE):
    campaign = str(payload.get("campaign", "")).strip()
    if not campaign:
        raise HTTPException(400, "Campaign is required")
    owner = str(payload.get("owner", "")).strip() or user.get("username", "")
    due_in_hours = min(max(int(payload.get("due_in_hours", 24)), 0), 24 * 14)
    due_at = time.time() + due_in_hours * 3600 if due_in_hours > 0 else None
    existing_titles = {(row.get("title") or "").strip().lower() for row in list_campaign_checklist(campaign=campaign, limit=5000)}
    created = 0
    for item in get_policy_remediation_plan(campaign=campaign):
        title = f"Policy remediation: {item['metric']} ({item['severity']})"
        if title.lower() in existing_titles:
            continue
        add_campaign_checklist_item(
            campaign=campaign,
            title=title,
            details=f"{item['action']}\nApprove path: {item['approve_cmd']}\nReject path: {item['reject_cmd']}",
            owner=owner,
            due_at=due_at,
            actor=api_actor_for(user, "governance/remediation-checklist"),
        )
        existing_titles.add(title.lower())
        created += 1
    return {"ok": True, "created": created}


@router.get("/governance/report")
async def governance_report(_: dict = REQUIRE_API_ROLE):
    return {
        "counts": {
            "policies": len(list_campaign_policies()),
            "alerts": len(evaluate_campaign_policy_alerts()),
            "pending_approvals": len(list_approval_requests(status="pending", limit=5000)),
        },
        "policies": list_campaign_policies(),
        "alerts": evaluate_campaign_policy_alerts(),
        "pending_approvals": list_approval_requests(status="pending", limit=5000),
    }


@router.get("/users")
async def users_index(_: dict = REQUIRE_API_ROLE):
    return {"users": list_users(limit=500)}


@router.post("/users")
async def users_create(payload: dict, _: dict = REQUIRE_API_ROLE):
    return {
        "user": create_user(
            str(payload.get("username", "")).strip(),
            str(payload.get("password", "")),
            role=str(payload.get("role", "operator")).strip().lower() or "operator",
            is_active=bool(payload.get("is_active", True)),
        )
    }


@router.patch("/users/{user_id}")
async def users_update(user_id: int, payload: dict, _: dict = REQUIRE_API_ROLE):
    ok = update_user_role_status(user_id, role=payload.get("role"), is_active=payload.get("is_active"))
    user = get_user_by_id(user_id)
    return {"ok": ok, "user": user}


@router.post("/users/{user_id}/password")
async def users_password(user_id: int, payload: dict, _: dict = REQUIRE_API_ROLE):
    return {"ok": set_user_password(user_id, str(payload.get("password", "")))}


# ── Network Insight ──


@router.post("/network/scan")
async def network_ingest_scan(payload: dict, user: dict = REQUIRE_API_ROLE):
    """Ingest a device list from a network scan run by the host collector."""
    devices = payload.get("devices")
    if not isinstance(devices, list):
        raise HTTPException(400, "Expected 'devices' to be a list")
    summary = record_scan(
        devices,
        source=str(payload.get("source", "") or api_actor_for(user, "network/scan")),
        target_range=str(payload.get("target_range", "") or ""),
    )
    return {"ok": True, **summary}


@router.get("/network/devices")
async def network_devices(only_untrusted: bool = False, _: dict = REQUIRE_API_ROLE):
    return {"counts": device_count(), "devices": list_devices(only_untrusted=only_untrusted)}


@router.get("/network/devices/new")
async def network_new_devices(_: dict = REQUIRE_API_ROLE):
    """Unknown/unbaselined devices — the 'new device joined' security signal."""
    return {"counts": device_count(), "devices": new_devices()}


@router.post("/network/baseline")
async def network_set_baseline(_: dict = REQUIRE_API_ROLE):
    return {"ok": True, "trusted": set_baseline()}


@router.patch("/network/devices/{mac}")
async def network_set_trust(mac: str, payload: dict, _: dict = REQUIRE_API_ROLE):
    label = payload.get("label")
    ok = set_device_trust(
        mac,
        trusted=bool(payload.get("trusted", True)),
        label=None if label is None else str(label),
    )
    if not ok:
        raise HTTPException(404, "Unknown device")
    return {"ok": True}


@router.get("/network/scans")
async def network_scans(limit: int = 50, _: dict = REQUIRE_API_ROLE):
    return {"scans": list_scans(limit=limit)}


# ── DNS Insight (Pi-hole) ──


@router.get("/dns/overview")
async def dns_insight_overview(since_hours: float = 24, _: dict = REQUIRE_API_ROLE):
    """Total/blocked/allowed query counts and block ratio over a time window."""
    return dns_overview(since_hours=since_hours)


@router.get("/dns/talkers")
async def dns_insight_talkers(
    since_hours: float = 24, limit: int = 10, _: dict = REQUIRE_API_ROLE
):
    """Top clients by query volume, with per-client blocked/allowed split."""
    return {
        "overview": dns_overview(since_hours=since_hours),
        "talkers": dns_top_talkers(since_hours=since_hours, limit=limit),
    }


@router.get("/dns/domains")
async def dns_insight_domains(
    since_hours: float = 24,
    limit: int = 10,
    client: str | None = None,
    only_blocked: bool = False,
    _: dict = REQUIRE_API_ROLE,
):
    """Most-queried domains overall, for one client, or only blocked ones."""
    return {
        "domains": dns_top_domains(
            since_hours=since_hours, limit=limit, client=client, only_blocked=only_blocked
        )
    }
