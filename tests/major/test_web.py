"""Tests for the Ursa Major Web UI (major/web/).

Covers:
- Template filter utility functions
- RBAC helper functions (role_allows, require_role, actor_for)
- Open-redirect protection (_safe_next_url)
- Auth middleware (redirect logic, HTMX redirect, static bypass)
- Login / logout flow
- Dashboard, sessions, tasks, files, events routes
- Campaign management routes
- Governance (approvals, policy) routes
- User administration routes (admin-only)
"""

import time

import pytest
from fastapi.testclient import TestClient

# auth_middleware now returns HTTP 410 for all non-API/MCP paths.
# Tests that exercise disabled web UI routes are marked skip so CI is clean.
_WEB_UI_DISABLED = pytest.mark.skip(
    reason=(
        "Web UI routes disabled; auth_middleware returns 410 for non-API/MCP paths. "
        "Use BearClawWeb for operator workflows."
    )
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def web_client(tmp_db):
    """Return a TestClient backed by a fresh isolated SQLite database."""
    from major.web.app import app

    # TestClient maintains a cookie jar across calls, enabling session auth.
    with TestClient(
        app,
        raise_server_exceptions=True,
        base_url="http://127.0.0.1:6707",
    ) as client:
        yield client


def _login(client: TestClient, username: str, password: str, *, follow: bool = True) -> None:
    """POST /auth/login and assert success (redirect to /)."""
    resp = client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=follow,
    )
    # Success redirects to "/"
    return resp


def _make_user(username: str, password: str, role: str = "operator"):
    """Create a user directly in the (already-patched) database."""
    from major.db import create_user
    return create_user(username, password, role=role)


@pytest.fixture()
def admin_client(web_client, tmp_db):
    """TestClient authenticated as an admin user."""
    _make_user("admin_test", "passw0rd!", "admin")
    _login(web_client, "admin_test", "passw0rd!")
    return web_client


@pytest.fixture()
def operator_client(web_client, tmp_db):
    """TestClient authenticated as an operator user."""
    _make_user("op_test", "passw0rd!", "operator")
    _login(web_client, "op_test", "passw0rd!")
    return web_client


@pytest.fixture()
def reviewer_client(web_client, tmp_db):
    """TestClient authenticated as a reviewer user."""
    _make_user("rev_test", "passw0rd!", "reviewer")
    _login(web_client, "rev_test", "passw0rd!")
    return web_client


@pytest.fixture()
def sample_session_id(tmp_db):
    """Return a session ID created directly in the database."""
    from major.db import create_session
    return create_session(
        remote_ip="10.1.2.3",
        hostname="WEBTEST",
        username="victim",
        os_info="Linux 6.1",
        arch="x86_64",
        pid=99,
        process_name="bash",
        encryption_key="ab" * 32,
        beacon_interval=5,
        jitter=0.1,
    )


# ---------------------------------------------------------------------------
# Template filter unit tests (pure Python, no HTTP)
# ---------------------------------------------------------------------------

class TestTemplateFilters:

    def test_format_timestamp_valid(self):
        from major.web.app import format_timestamp
        result = format_timestamp(1_700_000_000)
        assert "-" in result and ":" in result   # formatted as date/time string

    def test_format_timestamp_none_returns_never(self):
        from major.web.app import format_timestamp
        assert format_timestamp(None) == "never"

    def test_format_timestamp_zero_treated_as_never(self):
        from major.web.app import format_timestamp
        # 0 is falsy, so the guard returns "never"
        assert format_timestamp(0) == "never"

    def test_time_ago_seconds(self):
        from major.web.app import time_ago
        result = time_ago(time.time() - 30)
        assert "s ago" in result

    def test_time_ago_minutes(self):
        from major.web.app import time_ago
        result = time_ago(time.time() - 300)
        assert "m ago" in result

    def test_time_ago_hours(self):
        from major.web.app import time_ago
        result = time_ago(time.time() - 7200)
        assert "h ago" in result

    def test_time_ago_days(self):
        from major.web.app import time_ago
        result = time_ago(time.time() - 172800)
        assert "d ago" in result

    def test_time_ago_none_returns_never(self):
        from major.web.app import time_ago
        assert time_ago(None) == "never"

    def test_status_color_active(self):
        from major.web.app import status_color
        assert status_color("active") == "status-active"

    def test_status_color_all_known(self):
        from major.web.app import status_color
        for s in ("active", "stale", "dead", "pending", "in_progress", "completed", "error"):
            assert status_color(s).startswith("status-")

    def test_status_color_unknown_returns_empty(self):
        from major.web.app import status_color
        assert status_color("mystery") == ""

    def test_parse_json_string(self):
        from major.web.app import parse_json
        result = parse_json('{"key": "val"}')
        assert result == {"key": "val"}

    def test_parse_json_dict_passthrough(self):
        from major.web.app import parse_json
        d = {"a": 1}
        assert parse_json(d) is d

    def test_parse_json_invalid_returns_empty(self):
        from major.web.app import parse_json
        assert parse_json("not-json!!!") == {}

    def test_parse_json_none_returns_empty(self):
        from major.web.app import parse_json
        assert parse_json(None) == {}

    def test_filesizeformat_bytes(self):
        from major.web.app import filesizeformat
        assert filesizeformat(512) == "512 B"

    def test_filesizeformat_kilobytes(self):
        from major.web.app import filesizeformat
        result = filesizeformat(2048)
        assert "KB" in result

    def test_filesizeformat_megabytes(self):
        from major.web.app import filesizeformat
        result = filesizeformat(3 * 1024 * 1024)
        assert "MB" in result

    def test_filesizeformat_zero(self):
        from major.web.app import filesizeformat
        assert filesizeformat(0) == "0 B"

    def test_filesizeformat_none(self):
        from major.web.app import filesizeformat
        assert filesizeformat(None) == "0 B"


# ---------------------------------------------------------------------------
# RBAC helper unit tests (pure Python, no HTTP)
# ---------------------------------------------------------------------------

class TestRoleHelpers:

    def test_role_allows_exact_match(self):
        from major.web.auth import role_allows
        assert role_allows("admin", "admin") is True
        assert role_allows("operator", "operator") is True

    def test_higher_role_satisfies_lower_requirement(self):
        from major.web.auth import role_allows
        assert role_allows("admin", "reviewer") is True
        assert role_allows("admin", "operator") is True
        assert role_allows("reviewer", "operator") is True

    def test_lower_role_fails_higher_requirement(self):
        from major.web.auth import role_allows
        assert role_allows("operator", "reviewer") is False
        assert role_allows("operator", "admin") is False
        assert role_allows("reviewer", "admin") is False

    def test_unknown_role_fails_any_requirement(self):
        from major.web.auth import role_allows
        assert role_allows("superuser", "operator") is False
        assert role_allows("", "operator") is False

    def test_role_allows_case_insensitive(self):
        from major.web.auth import role_allows
        assert role_allows("ADMIN", "admin") is True
        assert role_allows("Admin", "Reviewer") is True

    def test_current_user_raises_401_without_user(self):
        from fastapi import HTTPException, Request

        from major.web.auth import current_user

        # Build a minimal mock request with no state.user
        scope = {"type": "http", "method": "GET", "path": "/"}
        request = Request(scope)
        request.state.user = None

        with pytest.raises(HTTPException) as exc_info:
            current_user(request)
        assert exc_info.value.status_code == 401

    def test_require_role_raises_403_if_insufficient(self):
        from fastapi import HTTPException, Request

        from major.web.auth import require_role

        scope = {"type": "http", "method": "GET", "path": "/"}
        request = Request(scope)
        request.state.user = {"id": 1, "username": "op", "role": "operator", "is_active": True}

        with pytest.raises(HTTPException) as exc_info:
            require_role(request, "admin")
        assert exc_info.value.status_code == 403

    def test_require_role_returns_user_if_sufficient(self):
        from fastapi import Request

        from major.web.auth import require_role

        scope = {"type": "http", "method": "GET", "path": "/"}
        request = Request(scope)
        request.state.user = {"id": 1, "username": "boss", "role": "admin", "is_active": True}

        user = require_role(request, "reviewer")
        assert user["username"] == "boss"

    def test_actor_for_generates_audit_string(self):
        from fastapi import Request

        from major.web.auth import actor_for

        scope = {"type": "http", "method": "GET", "path": "/"}
        request = Request(scope)
        request.state.user = {"id": 7, "username": "alice", "role": "admin"}

        result = actor_for(request, "approve")
        assert result == "web:alice:approve"

    def test_require_api_role_accepts_valid_bearer(self, monkeypatch):
        from major.web.auth import require_api_role

        class DummyConfig:
            @staticmethod
            def get(path, default=None):
                if path == "major.web.auth.api_token":
                    return "shared-token"
                return default

        monkeypatch.setattr("major.web.auth.get_config", lambda: DummyConfig())

        user = require_api_role(
            authorization="Bearer shared-token",
            x_bearclaw_actor="joe@example.com",
            x_bearclaw_role="admin",
        )
        assert user["username"] == "joe@example.com"
        assert user["role"] == "admin"

    def test_require_api_role_rejects_invalid_token(self, monkeypatch):
        from fastapi import HTTPException

        from major.web.auth import require_api_role

        class DummyConfig:
            @staticmethod
            def get(path, default=None):
                if path == "major.web.auth.api_token":
                    return "shared-token"
                return default

        monkeypatch.setattr("major.web.auth.get_config", lambda: DummyConfig())

        with pytest.raises(HTTPException) as exc_info:
            require_api_role(
                authorization="Bearer wrong-token",
                x_bearclaw_actor="joe@example.com",
                x_bearclaw_role="admin",
            )
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# _safe_next_url tests (open-redirect protection)
# ---------------------------------------------------------------------------

class TestSafeNextUrl:
    """Tests for the login route's open-redirect sanitizer."""

    def _fn(self, value):
        from major.web.routes.auth import _safe_next_url
        return _safe_next_url(value)

    def test_relative_path_passed_through(self):
        assert self._fn("/sessions/") == "/sessions/"

    def test_empty_returns_root(self):
        assert self._fn("") == "/"

    def test_none_like_empty_returns_root(self):
        assert self._fn(None) == "/"

    def test_double_slash_blocked(self):
        assert self._fn("//evil.com") == "/"

    def test_absolute_url_blocked(self):
        assert self._fn("https://evil.com/steal") == "/"

    def test_url_encoded_relative_passthrough(self):
        result = self._fn("%2Fsessions%2F")
        assert result.startswith("/")


# ---------------------------------------------------------------------------
# Base-path support for reverse-proxy subpath mounts
# ---------------------------------------------------------------------------

class TestWebBasePath:

    def test_normalize_base_path(self):
        from major.web.app import normalize_base_path

        assert normalize_base_path("") == ""
        assert normalize_base_path("/") == ""
        assert normalize_base_path("ursa") == "/ursa"
        assert normalize_base_path("/ursa/") == "/ursa"

    @_WEB_UI_DISABLED
    def test_redirects_are_prefixed(self, web_client, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        resp = web_client.get("/sessions/", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/ursa/auth/login")

    @_WEB_UI_DISABLED
    def test_htmx_redirect_header_is_prefixed(self, web_client, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        resp = web_client.get(
            "/sessions/",
            headers={"HX-Request": "true"},
            follow_redirects=False,
        )

        assert resp.status_code == 401
        assert resp.headers["HX-Redirect"].startswith("/ursa/auth/login")

    @_WEB_UI_DISABLED
    def test_login_page_rewrites_absolute_paths(self, web_client, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        resp = web_client.get("/auth/login")

        assert resp.status_code == 200
        assert 'href="/ursa/static/style.css"' in resp.text
        assert 'src="/ursa/static/htmx.min.js"' in resp.text
        assert 'action="/ursa/auth/login"' in resp.text

    @_WEB_UI_DISABLED
    def test_authenticated_pages_rewrite_links(self, web_client, tmp_db, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        _make_user("prefixed", "s3cret!", "operator")
        _login(web_client, "prefixed", "s3cret!")

        resp = web_client.get("/")

        assert resp.status_code == 200
        assert 'href="/ursa/"' in resp.text
        assert 'href="/ursa/sessions/"' in resp.text
        assert 'href="/ursa/governance/' in resp.text

    @_WEB_UI_DISABLED
    def test_login_success_redirect_uses_base_path(self, web_client, tmp_db, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        _make_user("alice_base", "s3cret!", "operator")
        resp = web_client.post(
            "/auth/login",
            data={"username": "alice_base", "password": "s3cret!"},
            follow_redirects=False,
        )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/ursa/"

    @_WEB_UI_DISABLED
    def test_login_next_redirect_uses_base_path(self, web_client, tmp_db, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        _make_user("alice_next", "s3cret!", "operator")
        resp = web_client.post(
            "/auth/login",
            data={"username": "alice_next", "password": "s3cret!", "next": "/sessions/"},
            follow_redirects=False,
        )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/ursa/sessions/"

    @_WEB_UI_DISABLED
    def test_existing_prefixed_redirect_is_not_double_prefixed(self, web_client, tmp_db, monkeypatch):
        import major.web.app as web_app

        monkeypatch.setattr(web_app, "WEB_BASE_PATH", "/ursa")
        _make_user("alice_prefixed", "s3cret!", "operator")
        resp = web_client.post(
            "/auth/login",
            data={"username": "alice_prefixed", "password": "s3cret!", "next": "/ursa/sessions/"},
            follow_redirects=False,
        )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/ursa/sessions/"


# ---------------------------------------------------------------------------
# Auth middleware (redirect / bypass behaviour)
# ---------------------------------------------------------------------------

class TestAuthMiddleware:

    @_WEB_UI_DISABLED
    def test_unauthenticated_root_redirects_to_login(self, web_client):
        resp = web_client.get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert "/auth/login" in resp.headers["location"]

    @_WEB_UI_DISABLED
    def test_unauthenticated_sessions_redirects_to_login(self, web_client):
        resp = web_client.get("/sessions/", follow_redirects=False)
        assert resp.status_code == 303
        assert "/auth/login" in resp.headers["location"]

    @_WEB_UI_DISABLED
    def test_login_page_is_public(self, web_client):
        resp = web_client.get("/auth/login", follow_redirects=False)
        assert resp.status_code == 200

    @_WEB_UI_DISABLED
    def test_htmx_unauthenticated_returns_401_with_redirect_header(self, web_client):
        resp = web_client.get(
            "/sessions/",
            headers={"HX-Request": "true"},
            follow_redirects=False,
        )
        assert resp.status_code == 401
        assert "HX-Redirect" in resp.headers
        assert "/auth/login" in resp.headers["HX-Redirect"]

    def test_static_path_bypasses_auth(self, web_client):
        # Static file may not exist, but should NOT be a 303 auth redirect
        resp = web_client.get("/static/nonexistent.css", follow_redirects=False)
        assert resp.status_code != 303

    def test_mcp_route_reaches_control_plane_without_token_when_unconfigured(self, web_client):
        resp = web_client.get(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            follow_redirects=False,
        )
        assert resp.status_code in {400, 406}
        assert "mcp-session-id" in resp.headers

    def test_mcp_route_requires_token_when_configured(self, web_client, monkeypatch):
        class DummyConfig:
            @staticmethod
            def get(path, default=None):
                if path == "major.web.auth.api_token":
                    return "shared-token"
                return default

        monkeypatch.setattr("major.web.auth.get_config", lambda: DummyConfig())

        resp = web_client.get(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    def test_mcp_route_accepts_valid_token_when_configured(self, web_client, monkeypatch):
        class DummyConfig:
            @staticmethod
            def get(path, default=None):
                if path == "major.web.auth.api_token":
                    return "shared-token"
                return default

        monkeypatch.setattr("major.web.auth.get_config", lambda: DummyConfig())

        resp = web_client.get(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer shared-token",
            },
            follow_redirects=False,
        )
        assert resp.status_code in {400, 406}
        assert "mcp-session-id" in resp.headers


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestLoginLogout:

    def test_login_page_renders(self, web_client):
        resp = web_client.get("/auth/login")
        assert resp.status_code == 200
        assert b"login" in resp.content.lower()

    def test_login_success_redirects_to_root(self, web_client, tmp_db):
        _make_user("alice", "s3cret!", "operator")
        resp = web_client.post(
            "/auth/login",
            data={"username": "alice", "password": "s3cret!"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"

    def test_login_with_next_param_redirects_to_next(self, web_client, tmp_db):
        _make_user("alice2", "s3cret!", "operator")
        resp = web_client.post(
            "/auth/login",
            data={"username": "alice2", "password": "s3cret!", "next": "/sessions/"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/sessions/"

    def test_login_wrong_password_returns_401(self, web_client, tmp_db):
        _make_user("bob", "correct!", "operator")
        resp = web_client.post(
            "/auth/login",
            data={"username": "bob", "password": "wrong!"},
            follow_redirects=False,
        )
        assert resp.status_code == 401
        assert b"Invalid" in resp.content

    def test_login_unknown_user_returns_401(self, web_client):
        resp = web_client.post(
            "/auth/login",
            data={"username": "nobody", "password": "anything"},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    def test_logout_clears_session(self, admin_client):
        # Confirm we're logged in
        assert admin_client.get("/", follow_redirects=False).status_code == 200
        # Logout
        admin_client.post("/auth/logout", follow_redirects=True)
        # Now unauthenticated
        resp = admin_client.get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert "/auth/login" in resp.headers["location"]

    def test_already_logged_in_login_page_still_renders(self, admin_client):
        # auth_middleware sets request.state.user = None before early-returning
        # for public paths, so the login handler always renders (never auto-redirects).
        resp = admin_client.get("/auth/login", follow_redirects=False)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestDashboard:

    def test_dashboard_authenticated_returns_200(self, operator_client):
        resp = operator_client.get("/")
        assert resp.status_code == 200

    def test_dashboard_unauthenticated_redirects(self, web_client):
        resp = web_client.get("/", follow_redirects=False)
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# Session routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestSessionRoutes:

    def test_sessions_list_empty(self, operator_client):
        resp = operator_client.get("/sessions/")
        assert resp.status_code == 200

    def test_sessions_list_with_session(self, operator_client, sample_session_id):
        resp = operator_client.get("/sessions/")
        assert resp.status_code == 200
        assert sample_session_id.encode() in resp.content or b"WEBTEST" in resp.content

    def test_session_detail_returns_200(self, operator_client, sample_session_id):
        resp = operator_client.get(f"/sessions/{sample_session_id}")
        assert resp.status_code == 200

    def test_session_detail_not_found_returns_404(self, operator_client):
        resp = operator_client.get("/sessions/deadbeef-nope")
        assert resp.status_code == 404

    def test_session_queue_task(self, operator_client, sample_session_id):
        resp = operator_client.post(
            f"/sessions/{sample_session_id}/task",
            data={"task_type": "whoami"},
            follow_redirects=False,
        )
        # Either redirect (task queued) or 200 (policy pending approval)
        assert resp.status_code in (200, 303)

    def test_session_kill(self, operator_client, sample_session_id):
        resp = operator_client.post(
            f"/sessions/{sample_session_id}/kill",
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_session_context_update(self, operator_client, sample_session_id):
        resp = operator_client.post(
            f"/sessions/{sample_session_id}/context",
            data={"campaign": "op-alpha", "tags": "linux,root"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_session_filter_by_status(self, operator_client, sample_session_id):
        resp = operator_client.get("/sessions/?status=active")
        assert resp.status_code == 200

    def test_sessions_require_auth(self, web_client):
        resp = web_client.get("/sessions/", follow_redirects=False)
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# Task routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestTaskRoutes:

    def test_tasks_list_empty(self, operator_client):
        resp = operator_client.get("/tasks/")
        assert resp.status_code == 200

    def test_tasks_list_with_task(self, operator_client, sample_session_id, tmp_db):
        from major.db import create_task

        create_task(sample_session_id, "shell", {"command": "id"})
        resp = operator_client.get("/tasks/")
        assert resp.status_code == 200

    def test_task_detail(self, operator_client, sample_session_id, tmp_db):
        from major.db import create_task
        task_id = create_task(sample_session_id, "shell", {"command": "id"})
        resp = operator_client.get(f"/tasks/{task_id}")
        assert resp.status_code == 200

    def test_task_detail_not_found_returns_404(self, operator_client):
        resp = operator_client.get("/tasks/nonexistent-task-id")
        assert resp.status_code == 404

    def test_tasks_filter_by_session(self, operator_client, sample_session_id, tmp_db):
        from major.db import create_task
        create_task(sample_session_id, "whoami")
        resp = operator_client.get(f"/tasks/?session_id={sample_session_id}")
        assert resp.status_code == 200

    def test_tasks_require_auth(self, web_client):
        resp = web_client.get("/tasks/", follow_redirects=False)
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# File routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestFileRoutes:

    def test_files_list_empty(self, operator_client):
        resp = operator_client.get("/files/")
        assert resp.status_code == 200

    def test_files_list_with_file(self, operator_client, sample_session_id, tmp_db):
        from major.db import store_file
        store_file(sample_session_id, "loot.txt", b"secret data", direction="upload")
        resp = operator_client.get("/files/")
        assert resp.status_code == 200
        assert b"loot.txt" in resp.content

    def test_file_download(self, operator_client, sample_session_id, tmp_db):
        from major.db import store_file
        file_id = store_file(sample_session_id, "evidence.bin", b"\xde\xad\xbe\xef", direction="upload")
        resp = operator_client.get(f"/files/{file_id}/download")
        assert resp.status_code == 200
        assert resp.content == b"\xde\xad\xbe\xef"

    def test_file_download_not_found_returns_404(self, operator_client):
        resp = operator_client.get("/files/doesnotexist/download")
        assert resp.status_code == 404

    def test_files_require_auth(self, web_client):
        resp = web_client.get("/files/", follow_redirects=False)
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# Event routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestEventRoutes:

    def test_events_list_empty(self, operator_client):
        resp = operator_client.get("/events/")
        assert resp.status_code == 200

    def test_events_list_with_event(self, operator_client, tmp_db):
        from major.db import log_event
        log_event("info", "test_source", "Web UI test event")
        resp = operator_client.get("/events/")
        assert resp.status_code == 200

    def test_events_filter_by_level(self, operator_client, tmp_db):
        from major.db import log_event
        log_event("warning", "scanner", "Port scan complete")
        resp = operator_client.get("/events/?level=warning")
        assert resp.status_code == 200

    def test_events_filter_by_session(self, operator_client, sample_session_id, tmp_db):
        from major.db import log_event
        log_event("info", "session", "check-in", session_id=sample_session_id)
        resp = operator_client.get(f"/events/?session_id={sample_session_id}")
        assert resp.status_code == 200

    def test_events_require_auth(self, web_client):
        resp = web_client.get("/events/", follow_redirects=False)
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# Campaign routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestCampaignRoutes:

    def test_campaigns_list_empty(self, operator_client):
        resp = operator_client.get("/campaigns/")
        assert resp.status_code == 200

    def test_campaign_detail_for_named_campaign(self, operator_client, sample_session_id, tmp_db):
        # Tag session to a campaign
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-delta")
        resp = operator_client.get("/campaigns/op-delta")
        assert resp.status_code == 200

    def test_campaign_add_note(self, operator_client, sample_session_id, tmp_db):
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-echo")
        resp = operator_client.post(
            "/campaigns/op-echo/notes",
            data={"note": "Initial recon complete"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_campaign_delete_note(self, operator_client, sample_session_id, tmp_db):
        from major.db import add_campaign_note, list_campaign_notes, update_session_info
        update_session_info(sample_session_id, campaign="op-foxtrot")
        add_campaign_note("op-foxtrot", "A note to delete")
        notes = list_campaign_notes("op-foxtrot")
        note_id = notes[0]["id"]
        resp = operator_client.post(
            f"/campaigns/op-foxtrot/notes/{note_id}/delete",
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_campaign_add_checklist_item(self, operator_client, sample_session_id, tmp_db):
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-golf")
        resp = operator_client.post(
            "/campaigns/op-golf/checklist",
            data={"title": "Run nmap scan", "details": "", "owner": "alice", "due_at": ""},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_campaign_update_checklist_item(self, operator_client, sample_session_id, tmp_db):
        from major.db import (
            add_campaign_checklist_item,
            list_campaign_checklist,
            update_session_info,
        )
        update_session_info(sample_session_id, campaign="op-hotel")
        add_campaign_checklist_item("op-hotel", "Old title")
        items = list_campaign_checklist("op-hotel")
        item_id = items[0]["id"]
        resp = operator_client.post(
            f"/campaigns/op-hotel/checklist/{item_id}/update",
            data={"title": "New title", "status": "in_progress", "owner": "", "due_at": ""},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_campaign_delete_checklist_item(self, operator_client, sample_session_id, tmp_db):
        from major.db import (
            add_campaign_checklist_item,
            list_campaign_checklist,
            update_session_info,
        )
        update_session_info(sample_session_id, campaign="op-india")
        add_campaign_checklist_item("op-india", "Delete me")
        items = list_campaign_checklist("op-india")
        item_id = items[0]["id"]
        resp = operator_client.post(
            f"/campaigns/op-india/checklist/{item_id}/delete",
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_campaign_handoff_get(self, operator_client, sample_session_id, tmp_db):
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-juliet")
        resp = operator_client.get("/campaigns/op-juliet/handoff")
        assert resp.status_code == 200

    def test_campaigns_require_auth(self, web_client):
        resp = web_client.get("/campaigns/", follow_redirects=False)
        assert resp.status_code == 303

    def test_campaign_bulk_checklist_update(self, operator_client, sample_session_id, tmp_db):
        from major.db import add_campaign_checklist_item, update_session_info
        update_session_info(sample_session_id, campaign="op-kilo")
        add_campaign_checklist_item("op-kilo", "Item 1")
        add_campaign_checklist_item("op-kilo", "Item 2")
        resp = operator_client.post(
            "/campaigns/op-kilo/checklist/bulk",
            data={"status": "done"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_playbooks_list_admin_only(self, admin_client):
        resp = admin_client.get("/campaigns/playbooks")
        assert resp.status_code == 200

    def test_playbooks_list_operator_forbidden(self, operator_client):
        resp = operator_client.get("/campaigns/playbooks")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Governance routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestGovernanceRoutes:

    def test_governance_dashboard_renders(self, reviewer_client):
        resp = reviewer_client.get("/governance/")
        assert resp.status_code == 200

    def test_governance_requires_auth(self, web_client):
        resp = web_client.get("/governance/", follow_redirects=False)
        assert resp.status_code == 303

    def test_set_campaign_policy(self, admin_client, sample_session_id, tmp_db):
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-lima")
        resp = admin_client.post(
            "/governance/policy",
            data={
                "campaign": "op-lima",
                "max_pending_total": "20",
                "max_pending_high": "10",
                "max_pending_critical": "2",
                "max_oldest_pending_minutes": "60",
                "note": "Test policy",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_delete_campaign_policy(self, admin_client, tmp_db):
        from major.db import upsert_campaign_policy
        upsert_campaign_policy("op-mike", max_pending_total=5)
        resp = admin_client.post(
            "/governance/policy/delete",
            data={"campaign": "op-mike"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_governance_report_json(self, reviewer_client):
        resp = reviewer_client.get("/governance/report?format=json")
        assert resp.status_code == 200

    def test_governance_report_csv(self, reviewer_client):
        resp = reviewer_client.get("/governance/report?format=csv")
        assert resp.status_code == 200

    def test_set_policy_operator_forbidden(self, operator_client):
        resp = operator_client.post(
            "/governance/policy",
            data={"campaign": "op-x"},
        )
        assert resp.status_code == 403

    def test_remediation_preview(self, reviewer_client, sample_session_id, tmp_db):
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-november")
        resp = reviewer_client.post(
            "/governance/remediation/preview",
            data={"campaign": "op-november", "strategy": "reduce-critical"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)


# ---------------------------------------------------------------------------
# Approval workflow
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestApprovalWorkflow:

    def _create_pending_approval(self, session_id: str) -> str:
        from major.db import create_approval_request
        return create_approval_request(
            action="shell",
            risk_level="high",
            session_id=session_id,
            task_type="shell",
            args={"command": "cat /etc/shadow"},
            reason="High-risk shell command",
            requested_by="web:op_test:shell",
        )

    def test_approve_request(self, reviewer_client, sample_session_id, tmp_db):
        approval_id = self._create_pending_approval(sample_session_id)
        resp = reviewer_client.post(
            f"/governance/approvals/{approval_id}/approve",
            data={"note": "Looks good"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_reject_request(self, reviewer_client, sample_session_id, tmp_db):
        approval_id = self._create_pending_approval(sample_session_id)
        resp = reviewer_client.post(
            f"/governance/approvals/{approval_id}/reject",
            data={"note": "Out of scope"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_approve_requires_reviewer(self, operator_client, sample_session_id, tmp_db):
        approval_id = self._create_pending_approval(sample_session_id)
        resp = operator_client.post(
            f"/governance/approvals/{approval_id}/approve",
            data={"note": ""},
        )
        assert resp.status_code == 403

    def test_reject_requires_reviewer(self, operator_client, sample_session_id, tmp_db):
        approval_id = self._create_pending_approval(sample_session_id)
        resp = operator_client.post(
            f"/governance/approvals/{approval_id}/reject",
            data={"note": ""},
        )
        assert resp.status_code == 403

    def test_bulk_approve_campaign(self, reviewer_client, sample_session_id, tmp_db):
        from major.db import update_session_info
        update_session_info(sample_session_id, campaign="op-bulk")
        self._create_pending_approval(sample_session_id)
        resp = reviewer_client.post(
            "/governance/approvals/bulk",
            data={"campaign": "op-bulk", "action": "approve", "note": "Bulk approved"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)


# ---------------------------------------------------------------------------
# User administration routes
# ---------------------------------------------------------------------------

@_WEB_UI_DISABLED
class TestUserAdminRoutes:

    def test_users_page_admin_can_access(self, admin_client):
        resp = admin_client.get("/auth/users")
        assert resp.status_code == 200

    def test_users_page_operator_forbidden(self, operator_client):
        resp = operator_client.get("/auth/users")
        assert resp.status_code == 403

    def test_users_page_reviewer_forbidden(self, reviewer_client):
        resp = reviewer_client.get("/auth/users")
        assert resp.status_code == 403

    def test_create_user_as_admin(self, admin_client):
        resp = admin_client.post(
            "/auth/users/create",
            data={"username": "newop", "password": "secure123", "role": "operator", "is_active": "1"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)

    def test_create_user_operator_forbidden(self, operator_client):
        resp = operator_client.post(
            "/auth/users/create",
            data={"username": "hack", "password": "pw", "role": "admin"},
        )
        assert resp.status_code == 403

    def test_update_user_role(self, admin_client, tmp_db):
        from major.db import create_user, get_user_by_id
        user = create_user("promote_me", "pw", role="operator")
        user_id = user["id"]
        resp = admin_client.post(
            f"/auth/users/{user_id}/update",
            data={"role": "reviewer", "is_active": "1"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        updated = get_user_by_id(user_id)
        assert updated["role"] == "reviewer"

    def test_change_user_password(self, admin_client, tmp_db):
        from major.db import create_user
        user = create_user("changepw_user", "oldpassword", role="operator")
        user_id = user["id"]
        resp = admin_client.post(
            f"/auth/users/{user_id}/password",
            data={"password": "newpassword99"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        # Verify new password authenticates
        from major.db import authenticate_user
        assert authenticate_user("changepw_user", "newpassword99") is not None
        assert authenticate_user("changepw_user", "oldpassword") is None

    def test_change_password_operator_forbidden(self, operator_client, tmp_db):
        from major.db import create_user
        user = create_user("victim_user", "pw", role="operator")
        resp = operator_client.post(
            f"/auth/users/{user['id']}/password",
            data={"password": "hacked"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# SSE endpoint
# ---------------------------------------------------------------------------

class TestSSEEndpoint:

    @pytest.mark.skip(
        reason=(
            "SSE generator has an infinite while-True/asyncio.sleep(2) loop "
            "that blocks the synchronous TestClient. Route is registered and "
            "auth-guarded; integration verified manually with a live server."
        )
    )
    def test_sse_route_is_registered(self, operator_client):
        resp = operator_client.get("/sse/events")
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

    @_WEB_UI_DISABLED
    def test_sse_unauthenticated_redirects(self, web_client):
        # Middleware redirects before the SSE generator runs, so no hang.
        resp = web_client.get("/sse/events", follow_redirects=False)
        assert resp.status_code == 303
