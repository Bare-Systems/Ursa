"""Campaign routes — campaign-centric operational view."""

import json
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import Response

from major.db import (
    add_campaign_checklist_item,
    add_campaign_note,
    apply_campaign_playbook,
    delete_campaign_checklist_item,
    delete_campaign_note,
    delete_campaign_playbook,
    evaluate_campaign_policy_alerts,
    get_campaign_playbook,
    get_campaign_policy,
    get_campaign_timeline,
    get_events,
    list_approval_requests,
    list_campaign_checklist,
    list_campaign_checklist_history,
    list_campaign_notes,
    list_campaign_playbooks,
    list_sessions,
    list_tasks,
    snapshot_campaign_checklist_to_playbook,
    update_campaign_checklist_item,
    upsert_campaign_playbook,
)
from major.governance import get_policy_remediation_plan
from major.web.app import templates
from major.web.auth import actor_for, require_role

router = APIRouter(prefix="/campaigns")
CHECKLIST_STATUSES = {"pending", "in_progress", "blocked", "done"}
CHECKLIST_SORT_OPTIONS = {"created_desc", "created_asc", "updated_desc", "updated_asc", "due_asc", "due_desc"}


def _parse_due_at(value: str) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _campaign_redirect(campaign_name: str, status: str = "", owner: str = "", q: str = "", sort: str = "") -> str:
    params: dict[str, str] = {}
    if status:
        params["status"] = status
    if owner:
        params["owner"] = owner
    if q:
        params["q"] = q
    if sort:
        params["sort"] = sort
    if params:
        return f"/campaigns/{campaign_name}?" + urlencode(params)
    return f"/campaigns/{campaign_name}"


def _parse_playbook_items(raw: str) -> list[dict]:
    text = (raw or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    # Fallback mini-format: `title | details | owner | due_offset_days`
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        items.append(
            {
                "title": parts[0] if len(parts) >= 1 else "",
                "details": parts[1] if len(parts) >= 2 else "",
                "owner": parts[2] if len(parts) >= 3 else "",
                "due_offset_days": parts[3] if len(parts) >= 4 and parts[3] else None,
            }
        )
    return items


@router.get("/")
async def campaign_list(request: Request):
    sessions = list_sessions()
    tasks = list_tasks(limit=2000)
    events = get_events(limit=2000)
    approvals = list_approval_requests(status="pending", limit=2000)

    campaigns: dict[str, dict[str, int]] = {}
    for s in sessions:
        name = (s.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["sessions"] += 1
    for t in tasks:
        name = (t.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["tasks"] += 1
    for e in events:
        name = (e.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["events"] += 1
    for a in approvals:
        name = (a.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["approvals"] += 1

    rows = sorted(
        campaigns.items(),
        key=lambda item: (
            item[1]["sessions"] + item[1]["tasks"] + item[1]["events"] + item[1]["approvals"]
        ),
        reverse=True,
    )
    return templates.TemplateResponse(
        request,
        "campaigns.html",
        {
            "active_page": "campaigns",
            "campaigns": rows,
        },
    )


@router.get("/playbooks")
async def campaign_playbooks_page(request: Request):
    _ = require_role(request, "admin")
    playbooks = list_campaign_playbooks(limit=300)
    return templates.TemplateResponse(
        request,
        "campaign_playbooks.html",
        {
            "active_page": "campaigns",
            "playbooks": playbooks,
        },
    )


@router.post("/playbooks/save")
async def campaign_playbooks_save(request: Request):
    _ = require_role(request, "admin")
    form = await request.form()
    name = str(form.get("name", "")).strip()
    description = str(form.get("description", "")).strip()
    items_raw = str(form.get("items", "")).strip()
    items = _parse_playbook_items(items_raw)
    if name and items:
        upsert_campaign_playbook(name, items=items, description=description)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/campaigns/playbooks"
    return response


@router.post("/playbooks/{name}/delete")
async def campaign_playbooks_delete(request: Request, name: str):
    _ = require_role(request, "admin")
    _ = delete_campaign_playbook(name.strip())
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/campaigns/playbooks"
    return response


@router.get("/playbooks/{name}/export")
async def campaign_playbook_export(request: Request, name: str):
    _ = require_role(request, "admin")
    playbook = get_campaign_playbook(name.strip())
    if not playbook:
        return Response(content="playbook not found", status_code=404)
    body = json.dumps(playbook, indent=2)
    response = Response(content=body, media_type="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="campaign_playbook_{name}.json"'
    return response


@router.get("/{campaign_name}")
async def campaign_detail(request: Request, campaign_name: str):
    status_filter = str(request.query_params.get("status", "")).strip().lower()
    owner_filter = str(request.query_params.get("owner", "")).strip()
    text_filter = str(request.query_params.get("q", "")).strip()
    sort = str(request.query_params.get("sort", "created_desc")).strip().lower()
    if status_filter and status_filter not in CHECKLIST_STATUSES:
        status_filter = ""
    if sort not in CHECKLIST_SORT_OPTIONS:
        sort = "created_desc"

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
        st = (item.get("status") or "pending").strip().lower()
        if st not in checklist_counts:
            st = "pending"
        checklist_counts[st] += 1

    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in sessions:
        status = s.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    for t in tasks:
        task_type = t.get("task_type", "unknown")
        by_task_type[task_type] = by_task_type.get(task_type, 0) + 1
    for a in pending_approvals:
        risk = (a.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1

    return templates.TemplateResponse(
        request,
        "campaign_detail.html",
        {
            "active_page": "campaigns",
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
        },
    )


@router.post("/{campaign_name}/notes")
async def campaign_add_note(request: Request, campaign_name: str):
    user = require_role(request, "operator")
    form = await request.form()
    note = str(form.get("note", "")).strip()
    if note:
        add_campaign_note(campaign_name, note, author=f"web:{user['username']}")
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/campaigns/{campaign_name}"
    return response


@router.post("/{campaign_name}/notes/{note_id}/delete")
async def campaign_delete_note(request: Request, campaign_name: str, note_id: int):
    _ = require_role(request, "operator")
    _ = delete_campaign_note(note_id)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/campaigns/{campaign_name}"
    return response


@router.post("/{campaign_name}/checklist")
async def campaign_add_checklist_item(request: Request, campaign_name: str):
    _ = require_role(request, "operator")
    form = await request.form()
    title = str(form.get("title", "")).strip()
    details = str(form.get("details", "")).strip()
    owner = str(form.get("owner", "")).strip()
    due_at = _parse_due_at(str(form.get("due_at", "")))
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort = str(form.get("sort_filter", "created_desc")).strip().lower()
    if title:
        add_campaign_checklist_item(
            campaign=campaign_name,
            title=title,
            details=details,
            owner=owner,
            due_at=due_at,
            actor=actor_for(request, "campaigns/checklist-add"),
        )
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort,
    )
    return response


@router.post("/{campaign_name}/checklist/{item_id}/update")
async def campaign_update_checklist_item(request: Request, campaign_name: str, item_id: int):
    _ = require_role(request, "operator")
    form = await request.form()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    status = str(form.get("status", "")).strip().lower()
    updates: dict[str, Any] = {}
    if status in CHECKLIST_STATUSES:
        updates["status"] = status
    title = str(form.get("title", "")).strip()
    if title:
        updates["title"] = title
    details = str(form.get("details", "")).strip()
    if details:
        updates["details"] = details
    owner = str(form.get("owner", "")).strip()
    if owner:
        updates["owner"] = owner
    if "due_at" in form:
        updates["due_at"] = _parse_due_at(str(form.get("due_at", "")))
    if updates:
        update_campaign_checklist_item(item_id, actor=actor_for(request, "campaigns/checklist-update"), **updates)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.post("/{campaign_name}/checklist/{item_id}/delete")
async def campaign_delete_checklist_item(request: Request, campaign_name: str, item_id: int):
    _ = require_role(request, "operator")
    form = await request.form()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    _ = delete_campaign_checklist_item(item_id, actor=actor_for(request, "campaigns/checklist-delete"))
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.post("/{campaign_name}/checklist/bulk")
async def campaign_bulk_update_checklist(request: Request, campaign_name: str):
    _ = require_role(request, "operator")
    form = await request.form()
    action_status = str(form.get("action_status", "")).strip().lower()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    if action_status in CHECKLIST_STATUSES:
        rows = list_campaign_checklist(
            campaign=campaign_name,
            status=status_filter or None,
            owner=owner_filter or None,
            text=text_filter or None,
            sort=sort_filter,
            limit=1000,
        )
        for row in rows:
            update_campaign_checklist_item(
                int(row["id"]),
                status=action_status,
                actor=actor_for(request, "campaigns/checklist-bulk"),
            )
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.post("/{campaign_name}/playbook/apply")
async def campaign_apply_playbook(request: Request, campaign_name: str):
    _ = require_role(request, "operator")
    form = await request.form()
    playbook_name = str(form.get("playbook", "")).strip()
    owner = str(form.get("owner", "")).strip()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    if playbook_name:
        apply_campaign_playbook(
            campaign=campaign_name,
            playbook_name=playbook_name,
            default_owner=owner,
            skip_existing=True,
        )
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.post("/{campaign_name}/playbook/snapshot")
async def campaign_snapshot_playbook(request: Request, campaign_name: str):
    _ = require_role(request, "operator")
    form = await request.form()
    playbook_name = str(form.get("playbook_name", "")).strip()
    description = str(form.get("description", "")).strip()
    only_open = str(form.get("only_open", "1")).strip() in {"1", "true", "on", "yes"}
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    if playbook_name:
        try:
            snapshot_campaign_checklist_to_playbook(
                campaign=campaign_name,
                playbook_name=playbook_name,
                description=description,
                only_open=only_open,
            )
        except ValueError:
            pass
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.get("/{campaign_name}/handoff")
async def campaign_handoff_report(campaign_name: str, format: str = "md"):
    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=300)
    events = get_events(campaign=campaign_name, limit=300)
    approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=300)
    notes = list_campaign_notes(campaign=campaign_name, limit=100)
    checklist = list_campaign_checklist(campaign=campaign_name, limit=400)
    checklist_history = list_campaign_checklist_history(campaign=campaign_name, limit=100)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign_name)
    checklist_open = [c for c in checklist if c.get("status") != "done"]

    by_status: dict[str, int] = {}
    for s in sessions:
        status = s.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1

    payload = {
        "campaign": campaign_name,
        "counts": {
            "sessions": len(sessions),
            "tasks": len(tasks),
            "events": len(events),
            "pending_approvals": len(approvals),
            "policy_alerts": len(alerts),
            "notes": len(notes),
            "checklist_items": len(checklist),
            "checklist_open": len(checklist_open),
            "checklist_changes": len(checklist_history),
        },
        "session_status": by_status,
        "pending_approvals": approvals[:10],
        "alerts": alerts[:10],
        "notes": notes[:20],
        "checklist": checklist[:30],
        "checklist_history": checklist_history[:20],
    }

    fmt = format.strip().lower()
    if fmt == "json":
        body = json.dumps(payload, indent=2)
        filename = f"campaign_handoff_{campaign_name}.json"
        content_type = "application/json"
    elif fmt == "md":
        lines = [
            f"# Campaign Handoff: {campaign_name}",
            "",
            "## Summary",
            f"- Sessions: {payload['counts']['sessions']}",
            f"- Tasks (recent): {payload['counts']['tasks']}",
            f"- Events (recent): {payload['counts']['events']}",
            f"- Pending approvals: {payload['counts']['pending_approvals']}",
            f"- Policy alerts: {payload['counts']['policy_alerts']}",
            f"- Notes: {payload['counts']['notes']}",
            f"- Checklist items: {payload['counts']['checklist_items']}",
            f"- Open checklist: {payload['counts']['checklist_open']}",
            f"- Checklist changes: {payload['counts']['checklist_changes']}",
            "",
            "## Session Status",
        ]
        for key, count in sorted(by_status.items()):
            lines.append(f"- {key}: {count}")
        lines.extend(["", "## Pending Approvals"])
        for a in approvals[:10]:
            lines.append(
                f"- `{a['id']}` risk={a['risk_level']} action={a['action']} session={a.get('session_id') or '-'}"
            )
        lines.extend(["", "## Active Alerts"])
        for a in alerts[:10]:
            lines.append(f"- {a['metric']}: {a['value']} > {a['threshold']} ({a['severity']})")
        lines.extend(["", "## Notes"])
        for n in notes[:20]:
            lines.append(
                f"- [{datetime.fromtimestamp(n['created_at']).strftime('%Y-%m-%d %H:%M:%S')}] "
                f"**{n['author']}**: {n['note']}"
            )
        lines.extend(["", "## Checklist"])
        if checklist:
            for item in checklist[:30]:
                due = "-"
                if item.get("due_at"):
                    due = datetime.fromtimestamp(item["due_at"]).strftime("%Y-%m-%d %H:%M:%S")
                lines.append(
                    f"- `{item['id']}` [{item['status']}] {item['title']} "
                    f"(owner={item.get('owner') or '-'}, due={due})"
                )
        else:
            lines.append("- None")
        lines.extend(["", "## Checklist History"])
        if checklist_history:
            for item in checklist_history[:20]:
                lines.append(
                    f"- [{datetime.fromtimestamp(item['created_at']).strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"item={item['item_id']} action={item['action']} status={item.get('new_status') or '-'} "
                    f"title={item.get('title') or '-'}"
                )
        else:
            lines.append("- None")
        lines.append("")
        body = "\n".join(lines)
        filename = f"campaign_handoff_{campaign_name}.md"
        content_type = "text/markdown"
    else:
        return Response(content="format must be md or json", status_code=400)

    response = Response(content=body, media_type=content_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
