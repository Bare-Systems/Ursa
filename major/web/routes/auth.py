"""Authentication and user administration routes."""

from urllib.parse import unquote

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from major.db import (
    authenticate_user,
    create_user,
    list_users,
    set_user_password,
    touch_user_login,
    update_user_role_status,
)
from major.web.app import templates
from major.web.auth import require_role

router = APIRouter(prefix="/auth")


def _safe_next_url(value: str) -> str:
    path = unquote((value or "").strip())
    if not path.startswith("/"):
        return "/"
    if path.startswith("//"):
        return "/"
    return path


@router.get("/login")
async def login_page(request: Request, next: str = "/"):
    user = getattr(request.state, "user", None)
    if user:
        return RedirectResponse(url=_safe_next_url(next), status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "next_url": _safe_next_url(next),
            "error": "",
        },
    )


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    next_url = _safe_next_url(str(form.get("next", "/")))
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next_url": next_url,
                "error": "Invalid username or password.",
            },
            status_code=401,
        )
    request.session["user_id"] = int(user["id"])
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    touch_user_login(int(user["id"]))
    return RedirectResponse(url=next_url, status_code=303)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/auth/login", status_code=303)


@router.get("/users")
async def users_page(request: Request):
    _ = require_role(request, "admin")
    users = list_users(limit=500)
    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "active_page": "users",
            "users": users,
        },
    )


@router.post("/users/create")
async def users_create(request: Request):
    _ = require_role(request, "admin")
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    role = str(form.get("role", "operator")).strip().lower()
    is_active = str(form.get("is_active", "1")).strip() in {"1", "true", "on", "yes"}
    try:
        if username and password:
            create_user(username, password, role=role, is_active=is_active)
    except ValueError:
        pass
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/auth/users"
    return response


@router.post("/users/{user_id}/update")
async def users_update(request: Request, user_id: int):
    _ = require_role(request, "admin")
    form = await request.form()
    role = str(form.get("role", "")).strip().lower()
    is_active = str(form.get("is_active", "")).strip() in {"1", "true", "on", "yes"}
    try:
        update_user_role_status(user_id, role=role, is_active=is_active)
    except ValueError:
        pass
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/auth/users"
    return response


@router.post("/users/{user_id}/password")
async def users_password(request: Request, user_id: int):
    _ = require_role(request, "admin")
    form = await request.form()
    password = str(form.get("password", ""))
    if password:
        set_user_password(user_id, password)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/auth/users"
    return response
