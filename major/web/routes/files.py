"""File routes — browse and download exfiltrated files."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from major.db import get_file, list_files
from major.web.app import templates

router = APIRouter(prefix="/files")


@router.get("/")
async def file_list(request: Request, session_id: str | None = None):
    files = list_files(session_id=session_id)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "partials/file_table.html", {
            "files": files,
        })

    return templates.TemplateResponse(request, "files.html", {
        "active_page": "files",
        "files": files,
    })


@router.get("/{file_id}/download")
async def download_file(file_id: str):
    f = get_file(file_id)
    if not f:
        raise HTTPException(404, "File not found")

    return Response(
        content=f["data"],
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{f["filename"]}"'},
    )
