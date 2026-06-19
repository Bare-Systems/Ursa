"""Task routes — global task list and detail."""

from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request

from major.db import get_task, list_tasks
from major.web.app import templates

router = APIRouter(prefix="/tasks")


@router.get("/")
async def task_list(
    request: Request,
    session_id: str | None = None,
    status: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
):
    tasks = list_tasks(
        session_id=session_id,
        status=status,
        campaign=campaign,
        tag=tag,
        limit=100,
    )
    query = urlencode(
        {
            k: v
            for k, v in {
                "session_id": session_id,
                "status": status,
                "campaign": campaign,
                "tag": tag,
            }.items()
            if v
        }
    )

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "partials/task_table.html", {
            "tasks": tasks,
        })

    return templates.TemplateResponse(request, "tasks.html", {
        "active_page": "tasks",
        "tasks": tasks,
        "current_session": session_id,
        "current_status": status,
        "current_campaign": campaign,
        "current_tag": tag,
        "query_string": query,
    })


@router.get("/{task_id}")
async def task_detail(request: Request, task_id: str):
    task = get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")

    return templates.TemplateResponse(request, "partials/shell_output.html", {
        "task": task,
    })
