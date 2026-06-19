"""Event log route."""

from urllib.parse import urlencode

from fastapi import APIRouter, Request

from major.db import get_events
from major.web.app import templates

router = APIRouter(prefix="/events")


@router.get("/")
async def event_list(
    request: Request,
    level: str | None = None,
    session_id: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
):
    events = get_events(
        limit=200,
        level=level,
        session_id=session_id,
        campaign=campaign,
        tag=tag,
    )
    query = urlencode(
        {
            k: v
            for k, v in {
                "level": level,
                "session_id": session_id,
                "campaign": campaign,
                "tag": tag,
            }.items()
            if v
        }
    )

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "partials/event_list.html", {
            "events": events,
        })

    return templates.TemplateResponse(request, "events.html", {
        "active_page": "events",
        "events": events,
        "current_level": level,
        "current_campaign": campaign,
        "current_tag": tag,
        "query_string": query,
    })
