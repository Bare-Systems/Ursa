"""Integration tests for Ursa Major — C2 server and Control Plane.

Test IDs:
  TC-URSA-001  CP /healthz responds 200
  TC-URSA-002  CP /api/v1/users requires auth (401)
  TC-URSA-003  CP web-UI paths return 410 Gone (UI disabled, use BearClaw)
  TC-URSA-004  C2 /health responds 200 with healthy status
  TC-URSA-005  C2 /register creates a session
  TC-URSA-006  C2 rejects unauthenticated beacon (no session)

All tests use in-process clients/servers — no live homelab service required.
Run against a live instance with: URSA_PORT=6708 pytest tests/test_ursa.py -v
"""

import json
import urllib.error
import urllib.request

from tests.conftest import TEST_API_TOKEN


# ── TC-URSA-001 / TC-URSA-002 / TC-URSA-003 — Control Plane ─────────────────


class TestCPHealthz:
    """TC-URSA-001: /healthz must be publicly reachable without credentials."""

    def test_healthz(self, cp_test_client):
        resp = cp_test_client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["service"] == "ursa-major-control-plane"

    def test_healthz_no_auth_header_needed(self, cp_test_client):
        resp = cp_test_client.get("/healthz", headers={})
        assert resp.status_code == 200


class TestCPUsersRequireAuth:
    """TC-URSA-002: /api/v1/users must reject unauthenticated requests."""

    def test_users_require_auth(self, cp_test_client):
        resp = cp_test_client.get("/api/v1/users")
        assert resp.status_code == 401

    def test_users_wrong_token_rejected(self, cp_test_client):
        resp = cp_test_client.get(
            "/api/v1/users",
            headers={"Authorization": "Bearer totally-wrong-token"},
        )
        assert resp.status_code == 401

    def test_api_overview_requires_auth(self, cp_test_client):
        resp = cp_test_client.get("/api/v1/overview")
        assert resp.status_code == 401

    def test_valid_token_accepted(self, cp_test_client):
        resp = cp_test_client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
        )
        assert resp.status_code == 200


class TestLoginRejectsBadCredentials:
    """TC-URSA-003: Web UI paths return 410 Gone.

    The direct web UI (/auth/login, /auth/users, /sessions/, /tasks/) was
    removed. auth_middleware returns HTTP 410 for all non-API/non-health paths
    so operators are directed to BearClawWeb instead.
    """

    def test_login_rejects_bad_credentials(self, cp_test_client):
        resp = cp_test_client.post(
            "/auth/login",
            data={"username": "admin", "password": "wrong_password"},
            follow_redirects=False,
        )
        assert resp.status_code == 410

    def test_users_page_gone(self, cp_test_client):
        resp = cp_test_client.get("/auth/users", follow_redirects=False)
        assert resp.status_code == 410

    def test_sessions_page_gone(self, cp_test_client):
        resp = cp_test_client.get("/sessions/", follow_redirects=False)
        assert resp.status_code == 410

    def test_tasks_page_gone(self, cp_test_client):
        resp = cp_test_client.get("/tasks/", follow_redirects=False)
        assert resp.status_code == 410


# ── TC-URSA-004 / TC-URSA-005 / TC-URSA-006 — C2 Server ─────────────────────


def _c2_get(host, port, path):
    url = f"http://{host}:{port}{path}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _c2_post(host, port, path, data):
    url = f"http://{host}:{port}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read()) if e.fp else {}
        return e.code, body


class TestC2Health:
    """TC-URSA-004: C2 /health must respond 200 with healthy status."""

    def test_healthz(self, c2_test_server):
        host, port = c2_test_server
        status, body = _c2_get(host, port, "/health")
        data = json.loads(body)
        assert status == 200
        assert data["status"] == "healthy"

    def test_root_responds(self, c2_test_server):
        host, port = c2_test_server
        status, body = _c2_get(host, port, "/")
        assert status == 200
        data = json.loads(body)
        assert data["status"] == "ok"


class TestC2Register:
    """TC-URSA-005: /register creates a session and returns a session key."""

    def test_register_returns_session_id_and_key(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _c2_post(host, port, "/register", {
            "hostname": "TESTBOX",
            "username": "operator",
            "os": "Linux 6.1",
            "arch": "x64",
            "pid": 1337,
            "process": "python3",
        })
        assert status == 200
        assert "session_id" in resp
        assert "key" in resp
        assert len(resp["key"]) == 64

    def test_register_missing_fields_still_creates_session(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _c2_post(host, port, "/register", {})
        assert status == 200
        assert "session_id" in resp


class TestC2Beacon:
    """TC-URSA-006: /beacon rejects unknown session IDs."""

    def test_beacon_unknown_session_rejected(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _c2_post(host, port, "/beacon", {
            "session_id": "00000000-0000-0000-0000-000000000000",
            "data": "",
        })
        assert status == 404
