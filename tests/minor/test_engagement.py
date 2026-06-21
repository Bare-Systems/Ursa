"""Tests for ursa_minor.engagement — scope management and JSON persistence.

All tests are pure local: engagement files go to a tmp_path fixture and the
module-level globals (_ENG_DIR, _ACTIVE_FILE) are monkeypatched so nothing
touches the real ~/.ursa directory.
"""

import json

import pytest

import ursa_minor.engagement as eng


@pytest.fixture(autouse=True)
def isolated_eng_dir(tmp_path, monkeypatch):
    """Redirect all engagement I/O to a throwaway temp directory."""
    eng_dir = tmp_path / "engagements"
    eng_dir.mkdir()
    active_file = eng_dir / ".active"

    monkeypatch.setattr(eng, "_ENG_DIR", eng_dir)
    monkeypatch.setattr(eng, "_ACTIVE_FILE", active_file)

    yield eng_dir


# ── _ip_in_scope (pure function) ──────────────────────────────────────────────


class TestIpInScope:

    def test_exact_ip_match(self):
        assert eng._ip_in_scope("192.168.1.1", ["192.168.1.1"])

    def test_exact_ip_no_match(self):
        assert not eng._ip_in_scope("192.168.1.2", ["192.168.1.1"])

    def test_cidr_match(self):
        assert eng._ip_in_scope("10.0.0.55", ["10.0.0.0/24"])

    def test_cidr_excludes_out_of_range(self):
        assert not eng._ip_in_scope("10.0.1.1", ["10.0.0.0/24"])

    def test_cidr_slash_32_exact(self):
        assert eng._ip_in_scope("172.16.0.1", ["172.16.0.1/32"])
        assert not eng._ip_in_scope("172.16.0.2", ["172.16.0.1/32"])

    def test_wildcard_domain_match(self):
        assert eng._ip_in_scope("sub.example.com", ["*.example.com"])

    def test_wildcard_domain_matches_base_too(self):
        assert eng._ip_in_scope("example.com", ["*.example.com"])

    def test_wildcard_domain_no_match_sibling(self):
        assert not eng._ip_in_scope("other.com", ["*.example.com"])

    def test_multiple_entries_any_match(self):
        scope = ["10.0.0.1", "192.168.0.0/16", "*.internal.test"]
        assert eng._ip_in_scope("10.0.0.1", scope)
        assert eng._ip_in_scope("192.168.99.1", scope)
        assert eng._ip_in_scope("api.internal.test", scope)

    def test_empty_scope_never_matches(self):
        assert not eng._ip_in_scope("10.0.0.1", [])

    def test_blank_entries_ignored(self):
        assert eng._ip_in_scope("10.0.0.1", ["", "10.0.0.1", "  "])


# ── create ────────────────────────────────────────────────────────────────────


class TestCreate:

    def test_returns_record_with_expected_fields(self):
        record = eng.create("Test Engagement", scope_hosts="192.168.1.0/24")
        assert record["name"] == "Test Engagement"
        assert record["status"] == "active"
        assert "192.168.1.0/24" in record["scope"]["hosts"]
        assert record["allow_destructive"] is False

    def test_creates_json_file_on_disk(self, isolated_eng_dir):
        record = eng.create("Disk test", scope_hosts="10.0.0.1")
        eng_id = record["id"]
        json_path = isolated_eng_dir / f"{eng_id}.json"
        assert json_path.exists()
        on_disk = json.loads(json_path.read_text())
        assert on_disk["id"] == eng_id

    def test_writes_active_file(self, isolated_eng_dir):
        record = eng.create("Active test", scope_hosts="10.0.0.1")
        active_file = isolated_eng_dir / ".active"
        assert active_file.read_text().strip() == record["id"]

    def test_scope_paths_parsed_correctly(self):
        record = eng.create("Paths test", scope_hosts="10.0.0.1", scope_paths="/api,/health")
        assert "/api" in record["scope"]["paths"]
        assert "/health" in record["scope"]["paths"]

    def test_default_scope_path_is_root(self):
        record = eng.create("Default path", scope_hosts="10.0.0.1")
        assert "/" in record["scope"]["paths"]

    def test_allow_destructive_flag(self):
        record = eng.create("Destructive", scope_hosts="10.0.0.1", allow_destructive=True)
        assert record["allow_destructive"] is True

    def test_rate_limit_rps_stored(self):
        record = eng.create("Rate limited", scope_hosts="10.0.0.1", rate_limit_rps=5)
        assert record["rate_limit_rps"] == 5

    def test_notes_stored(self):
        record = eng.create("With notes", scope_hosts="10.0.0.1", notes="pentest of homelab")
        assert record["notes"] == "pentest of homelab"


# ── check ─────────────────────────────────────────────────────────────────────


class TestCheck:

    def test_no_active_engagement_always_in_scope(self):
        result = eng.check("http://anything.example.com/any/path")
        assert result["in_scope"] is True
        assert result["engagement_id"] is None
        assert result["allow_destructive"] is True

    def test_url_in_scope(self):
        eng.create("My eng", scope_hosts="192.168.1.1", scope_paths="/api")
        result = eng.check("http://192.168.1.1/api/v1/users")
        assert result["in_scope"] is True
        assert result["allow_destructive"] is False

    def test_host_not_in_scope(self):
        eng.create("My eng", scope_hosts="192.168.1.1")
        result = eng.check("http://10.0.0.99/")
        assert result["in_scope"] is False
        assert "not in scope" in result["reason"]

    def test_path_not_in_scope(self):
        eng.create("My eng", scope_hosts="192.168.1.1", scope_paths="/api")
        result = eng.check("http://192.168.1.1/admin")
        assert result["in_scope"] is False
        assert "not in scope" in result["reason"]

    def test_cidr_host_in_scope(self):
        eng.create("CIDR eng", scope_hosts="10.0.0.0/24")
        assert eng.check("http://10.0.0.50/")["in_scope"] is True
        assert eng.check("http://10.0.1.50/")["in_scope"] is False

    def test_wildcard_domain_in_scope(self):
        eng.create("Wildcard eng", scope_hosts="*.lab.local", scope_paths="/")
        assert eng.check("http://api.lab.local/")["in_scope"] is True
        assert eng.check("http://evil.com/")["in_scope"] is False

    def test_destructive_flag_propagates(self):
        eng.create("Destructive eng", scope_hosts="10.0.0.1", allow_destructive=True)
        result = eng.check("http://10.0.0.1/")
        assert result["allow_destructive"] is True

    def test_returns_engagement_id(self):
        record = eng.create("ID test", scope_hosts="10.0.0.1")
        result = eng.check("http://10.0.0.1/")
        assert result["engagement_id"] == record["id"]


# ── get_active ────────────────────────────────────────────────────────────────


class TestGetActive:

    def test_returns_none_when_no_active(self):
        assert eng.get_active() is None

    def test_returns_record_when_active(self):
        created = eng.create("Active eng", scope_hosts="10.0.0.1")
        loaded = eng.get_active()
        assert loaded is not None
        assert loaded["id"] == created["id"]
        assert loaded["name"] == "Active eng"

    def test_returns_none_after_close(self):
        eng.create("Will close", scope_hosts="10.0.0.1")
        eng.close()
        assert eng.get_active() is None


# ── close ─────────────────────────────────────────────────────────────────────


class TestClose:

    def test_close_returns_closed_record(self):
        eng.create("Closeable", scope_hosts="10.0.0.1")
        closed = eng.close()
        assert closed is not None
        assert closed["status"] == "closed"
        assert closed["closed_at"] is not None

    def test_close_when_no_active_returns_none(self):
        assert eng.close() is None

    def test_scope_checks_after_close_are_open(self):
        eng.create("Temp eng", scope_hosts="10.0.0.1")
        eng.close()
        result = eng.check("http://completely-different.com/")
        assert result["in_scope"] is True
        assert result["engagement_id"] is None


# ── list_all ──────────────────────────────────────────────────────────────────


class TestListAll:

    def test_empty_when_no_engagements(self):
        assert eng.list_all() == []

    def test_lists_created_engagements(self, isolated_eng_dir):
        # Write two engagement files directly (IDs are second-resolution timestamps,
        # so rapid successive creates within the same second would collide).
        for eng_id, name in [("eng_20260101_120000", "Eng A"), ("eng_20260101_120001", "Eng B")]:
            record = {"id": eng_id, "name": name, "status": "active",
                      "created_at": "2026-01-01T12:00:00", "scope": {"hosts": ["10.0.0.1"], "paths": ["/"]},
                      "allow_destructive": False}
            (isolated_eng_dir / f"{eng_id}.json").write_text(json.dumps(record))
        summaries = eng.list_all()
        names = {s["name"] for s in summaries}
        assert "Eng A" in names
        assert "Eng B" in names

    def test_summary_shape(self):
        eng.create("Shape test", scope_hosts="10.0.0.1")
        s = eng.list_all()[0]
        assert {"id", "name", "status", "created_at", "scope_hosts", "allow_destructive"} <= s.keys()

    def test_closed_engagement_appears_in_list(self):
        eng.create("To close", scope_hosts="10.0.0.1")
        eng.close()
        summaries = eng.list_all()
        assert any(s["status"] == "closed" for s in summaries)


# ── active_engagement_id public accessor ─────────────────────────────────────


class TestActiveEngagementId:

    def test_returns_none_when_nothing_active(self):
        assert eng.active_engagement_id() is None

    def test_returns_id_when_active(self):
        record = eng.create("ID accessor test", scope_hosts="10.0.0.1")
        assert eng.active_engagement_id() == record["id"]
