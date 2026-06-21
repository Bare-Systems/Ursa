"""Shared fixtures for the Ursa test suite."""

import os
import sys
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

# Port the live Ursa Major C2 service listens on (was 18443, now 6708).
# Override via URSA_PORT env-var when running integration tests against a
# live homelab instance: URSA_PORT=6708 pytest tests/test_ursa.py
URSA_C2_PORT: int = int(os.environ.get("URSA_PORT", 6708))
URSA_CP_PORT: int = 6707

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "minor" / "src"))


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Provide a fresh, isolated SQLite database for each test.

    Patches major.db._db_path so all db functions use a temp file.
    """
    import major.db as db_mod

    db_file = tmp_path / "test_ursa.db"
    monkeypatch.setattr(db_mod, "_db_path", lambda: db_file)
    db_mod.init_db()
    return db_file


@pytest.fixture
def crypto_instance():
    """Return a UrsaCrypto instance with a known test key."""
    from major.crypto import UrsaCrypto

    return UrsaCrypto(b"test-key-for-ursa-crypto-suite!!")


@pytest.fixture
def c2_test_server(tmp_db):
    """Start a real C2 HTTP server on an ephemeral port.

    Yields (host, port). Server runs in a daemon thread and is
    torn down after the test.
    """
    from major.server import UrsaC2Handler

    server = HTTPServer(("127.0.0.1", 0), UrsaC2Handler)
    host, port = server.server_address

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield host, port

    server.shutdown()


@pytest.fixture
def sample_session(tmp_db):
    """Create and return a sample session ID for tests that need one."""
    from major.db import create_session

    return create_session(
        remote_ip="10.0.0.42",
        hostname="TESTBOX",
        username="testuser",
        os_info="Linux 5.15",
        arch="x86_64",
        pid=1234,
        process_name="python3",
        encryption_key="deadbeef" * 8,
        beacon_interval=10,
        jitter=0.2,
    )


TEST_API_TOKEN = "ursa-test-api-token"


@pytest.fixture
def cp_test_client(tmp_db, monkeypatch):
    """Return a FastAPI TestClient backed by a fresh isolated database.

    Configures a test API token so /api/v1/* endpoints return 401 (not 503)
    for unauthenticated requests. Mirrors the homelab CP base_url.
    """
    import major.config as _cfg_mod
    import major.web.auth as _auth_mod

    cfg = _cfg_mod.get_config()
    original_get = cfg.get

    def _patched_get(path, default=None):
        if path == "major.web.auth.api_token":
            return TEST_API_TOKEN
        return original_get(path, default)

    monkeypatch.setattr(cfg, "get", _patched_get)

    from fastapi.testclient import TestClient
    from major.web.app import app

    with TestClient(app, raise_server_exceptions=True, base_url=f"http://127.0.0.1:{URSA_CP_PORT}") as client:
        yield client
