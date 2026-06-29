"""Ursa Major — control-plane service for BearClaw and MCP operators."""

import json
import re
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.types import Receive, Scope, Send

from major.config import get_config
from major.web.auth import authenticate_api_request

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

WEB_DIR = Path(__file__).parent

app = FastAPI(title="Ursa Major Control Plane", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

session_secret = str(get_config().get("major.web.auth.session_secret", "ursa-dev-session-secret"))
_raw_base_path = str(get_config().get("major.web.base_path", ""))

templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

_HTML_PATH_ATTR_RE = re.compile(
    r'(?P<prefix>(?:href|src|action|hx-get|hx-post|hx-push-url)=["\'])/(?P<rest>[^"\']*)'
)


def normalize_base_path(path: str) -> str:
    """Normalise base-path config into '' or '/prefix'."""
    value = (path or "").strip()
    if not value or value == "/":
        return ""
    value = "/" + value.strip("/")
    return value.rstrip("/")


WEB_BASE_PATH = normalize_base_path(_raw_base_path)


def web_path(path: str = "/") -> str:
    """Prefix an app-local path with the configured base path."""
    if not path:
        return WEB_BASE_PATH or "/"
    if not path.startswith("/") or path.startswith("//"):
        return path
    if not WEB_BASE_PATH:
        return path
    if path == WEB_BASE_PATH or path.startswith(WEB_BASE_PATH + "/"):
        return path
    if path == "/":
        return WEB_BASE_PATH + "/"
    return WEB_BASE_PATH + path


def _rewrite_html_paths(body: bytes) -> bytes:
    """Rewrite absolute HTML paths so the UI can live behind a reverse-proxy subpath."""
    if not WEB_BASE_PATH or not body:
        return body
    text = body.decode("utf-8")
    rewritten = _HTML_PATH_ATTR_RE.sub(
        lambda m: f"{m.group('prefix')}{WEB_BASE_PATH}/{m.group('rest')}",
        text,
    )
    return rewritten.encode("utf-8")


async def _apply_base_path(response: Response) -> Response:
    """Prefix redirect headers and HTML paths with the configured base path."""
    if not WEB_BASE_PATH:
        return response

    for header in ("location", "HX-Redirect"):
        value = response.headers.get(header)
        if value:
            response.headers[header] = web_path(value)

    content_type = response.headers.get("content-type", "").lower()
    if "text/html" not in content_type:
        return response

    body = b""
    async for chunk in response.body_iterator:  # type: ignore[attr-defined]
        body += chunk
    body = _rewrite_html_paths(body)

    headers = dict(response.headers)
    headers["content-length"] = str(len(body))
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
        background=response.background,
    )


# -- Template Filters --

def format_timestamp(ts):
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def time_ago(ts):
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        return f"{int(diff // 60)}m ago"
    elif diff < 86400:
        return f"{int(diff // 3600)}h ago"
    else:
        return f"{int(diff // 86400)}d ago"


def status_color(status):
    return {
        "active": "status-active",
        "stale": "status-stale",
        "dead": "status-dead",
        "pending": "status-pending",
        "in_progress": "status-in_progress",
        "completed": "status-completed",
        "error": "status-error",
    }.get(status, "")


def parse_json(val):
    if not val:
        return {}
    if isinstance(val, dict):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return {}


def filesizeformat(size):
    if not size:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


templates.env.filters["format_ts"] = format_timestamp
templates.env.filters["time_ago"] = time_ago
templates.env.filters["status_color"] = status_color
templates.env.filters["parse_json"] = parse_json
templates.env.filters["filesizeformat"] = filesizeformat
templates.env.globals["web_path"] = web_path


# -- Register Routers --

from major.web.routes import api  # noqa: E402
from server import mcp_server as operator_mcp_server  # noqa: E402


class ControlPlaneMCPProxy:
    """Forward `/mcp` requests to the current FastMCP ASGI app."""

    def __init__(self, parent_app: FastAPI):
        self.parent_app = parent_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        mcp_app = getattr(self.parent_app.state, "control_plane_mcp_app", None)
        if mcp_app is None:
            response = JSONResponse(
                {"detail": "MCP control plane is starting"},
                status_code=503,
            )
            await response(scope, receive, send)
            return
        await mcp_app(scope, receive, send)


CONTROL_PLANE_MCP_APP = ControlPlaneMCPProxy(app)


@asynccontextmanager
async def control_plane_lifespan(_app):
    # FastMCP's session manager is single-use, so the embedded control plane
    # rebuilds a fresh ASGI app for each startup/lifespan cycle.
    operator_mcp_server.settings.streamable_http_path = "/mcp"
    operator_mcp_server.settings.transport_security = None
    operator_mcp_server._session_manager = None
    _app.state.control_plane_mcp_app = operator_mcp_server.streamable_http_app()
    async with operator_mcp_server.session_manager.run():
        yield
    _app.state.control_plane_mcp_app = None


app.router.lifespan_context = control_plane_lifespan


@app.middleware("http")
async def auth_middleware(request, call_next):
    path = request.url.path
    request.state.user = None
    request.state.web_base_path = WEB_BASE_PATH
    request.state.web_path = web_path
    public_paths = {"/healthz"}
    if path.startswith("/mcp"):
        try:
            request.state.user = authenticate_api_request(
                authorization=request.headers.get("authorization"),
                x_bearclaw_actor=request.headers.get("x-bearclaw-actor"),
                x_bearclaw_role=request.headers.get("x-bearclaw-role"),
                role="admin",
                scope="admin",
                allow_missing_token=True,
            )
        except HTTPException as exc:
            return await _apply_base_path(
                JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
            )
        response = await call_next(request)
        return await _apply_base_path(response)

    if path.startswith("/api/") or path in public_paths:
        response = await call_next(request)
        return await _apply_base_path(response)

    body = (
        "Direct Ursa web UI routes are disabled. "
        "Use BearClawWeb for operator workflows."
    )
    return await _apply_base_path(Response(content=body, status_code=410, media_type="text/plain"))



@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "ursa-major-control-plane"}

app.include_router(api.router)
app.mount("/", CONTROL_PLANE_MCP_APP)
