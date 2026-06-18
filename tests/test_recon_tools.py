"""Tests for ursa_session_recon, ursa_sitrep, and related helpers.

These tools are pure Python functions that read from the DB, so tests
use the tmp_db fixture for isolation without needing a live C2 server.
"""

from __future__ import annotations

import json

from major.db import complete_task, create_session, create_task, set_setting

# ── helpers ───────────────────────────────────────────────────────────────────

def _make_session(tmp_db, hostname="HOST1", username="op", os_info="Linux"):
    return create_session(
        remote_ip="10.0.0.1",
        hostname=hostname,
        username=username,
        os_info=os_info,
        arch="x86_64",
        pid=1234,
        process_name="python3",
    )


def _make_post_task(session_id, module="enum/loot", status="completed", findings=None):
    """Create and optionally complete a post task with synthetic findings."""
    task_id = create_task(
        session_id=session_id,
        task_type="post",
        args={"code": "stub", "module": module, "args": {}},
    )
    if status in ("completed", "error"):
        if findings is not None:
            data = {"findings": findings, "finding_counts": {}}
            result_str = f"Module output\n\n--- data ---\n{json.dumps(data)}"
        else:
            result_str = "Module output — no findings"
        error = "exec failed" if status == "error" else ""
        complete_task(task_id, result=result_str if status == "completed" else "", error=error)
    return task_id


def _make_findings(severities=("CRITICAL", "HIGH", "MEDIUM")):
    return [
        {"severity": sev, "category": "test", "title": f"{sev} finding", "detail": f"detail for {sev}"}
        for sev in severities
    ]


# ── _parse_post_result ────────────────────────────────────────────────────────

class TestParsePostResult:

    def test_plain_text_returns_empty_data(self):
        from server import _parse_post_result
        out, data = _parse_post_result("plain output")
        assert out == "plain output"
        assert data == {}

    def test_splits_on_sentinel(self):
        from server import _parse_post_result
        payload = '{"findings": []}'
        result_str = f"output text\n\n--- data ---\n{payload}"
        out, data = _parse_post_result(result_str)
        assert out == "output text"
        assert data == {"findings": []}

    def test_invalid_json_after_sentinel_returns_empty_data(self):
        from server import _parse_post_result
        result_str = "output\n\n--- data ---\n{not valid json"
        out, data = _parse_post_result(result_str)
        assert out == "output"
        assert data == {}

    def test_error_string_no_sentinel(self):
        from server import _parse_post_result
        out, data = _parse_post_result("[ERROR] exec failed: something")
        assert "[ERROR]" in out
        assert data == {}


# ── _collect_findings ─────────────────────────────────────────────────────────

class TestCollectFindings:

    def test_empty_task_list_returns_empty(self):
        from server import _collect_findings
        assert _collect_findings([]) == []

    def test_ignores_non_post_tasks(self):
        from server import _collect_findings
        shell_task = {
            "task_type": "shell", "status": "completed",
            "args": json.dumps({"module": "enum/loot"}),
            "result": f"out\n\n--- data ---\n{json.dumps({'findings': [{'severity':'CRITICAL','title':'x','category':'c','detail':'d'}]})}",
        }
        assert _collect_findings([shell_task]) == []

    def test_ignores_pending_tasks(self):
        from server import _collect_findings
        t = {
            "task_type": "post", "status": "pending",
            "args": json.dumps({"module": "enum/loot"}),
            "result": "",
        }
        assert _collect_findings([t]) == []

    def test_ignores_non_loot_modules(self):
        from server import _collect_findings
        t = {
            "task_type": "post", "status": "completed",
            "args": json.dumps({"module": "enum/sysinfo"}),
            "result": f"out\n\n--- data ---\n{json.dumps({'findings': [{'severity':'HIGH','title':'x','category':'c','detail':'d'}]})}",
            "id": "t1",
        }
        assert _collect_findings([t]) == []

    def test_collects_from_enum_loot(self):
        from server import _collect_findings
        findings = [{"severity": "CRITICAL", "title": "uid=0", "category": "privesc", "detail": "root"}]
        t = {
            "task_type": "post", "status": "completed",
            "args": json.dumps({"module": "enum/loot"}),
            "result": f"out\n\n--- data ---\n{json.dumps({'findings': findings})}",
            "id": "t1",
        }
        result = _collect_findings([t])
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["title"] == "uid=0"

    def test_collects_from_cred_loot(self):
        from server import _collect_findings
        findings = [{"severity": "HIGH", "title": "browser creds", "category": "cred", "detail": "x"}]
        t = {
            "task_type": "post", "status": "completed",
            "args": json.dumps({"module": "cred/loot"}),
            "result": f"out\n\n--- data ---\n{json.dumps({'findings': findings})}",
            "id": "t2",
        }
        result = _collect_findings([t])
        assert len(result) == 1

    def test_sorted_by_severity(self):
        from server import _collect_findings
        findings = [
            {"severity": "LOW",      "title": "low",  "category": "c", "detail": ""},
            {"severity": "CRITICAL", "title": "crit", "category": "c", "detail": ""},
            {"severity": "HIGH",     "title": "high", "category": "c", "detail": ""},
        ]
        t = {
            "task_type": "post", "status": "completed",
            "args": json.dumps({"module": "enum/loot"}),
            "result": f"out\n\n--- data ---\n{json.dumps({'findings': findings})}",
            "id": "t1",
        }
        result = _collect_findings([t])
        assert [f["severity"] for f in result] == ["CRITICAL", "HIGH", "LOW"]

    def test_tagged_with_module_and_task_id(self):
        from server import _collect_findings
        findings = [{"severity": "HIGH", "title": "x", "category": "c", "detail": ""}]
        t = {
            "task_type": "post", "status": "completed",
            "args": json.dumps({"module": "enum/loot"}),
            "result": f"out\n\n--- data ---\n{json.dumps({'findings': findings})}",
            "id": "myid",
        }
        result = _collect_findings([t])
        assert result[0]["_module"]  == "enum/loot"
        assert result[0]["_task_id"] == "myid"


# ── ursa_session_recon ────────────────────────────────────────────────────────

class TestSessionRecon:

    def test_unknown_session_returns_error(self, tmp_db):
        from server import ursa_session_recon
        out = ursa_session_recon("BADID99")
        assert "not found" in out.lower()

    def test_no_tasks_shows_no_loot_message(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        out = ursa_session_recon(sid)
        assert "no loot modules" in out.lower()

    def test_shows_session_header(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db, hostname="VICTIM1", username="jdoe")
        out = ursa_session_recon(sid)
        assert "VICTIM1" in out
        assert "jdoe" in out
        assert sid in out

    def test_shows_pending_module_status(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        create_task(sid, "post", {"code": "stub", "module": "enum/sysinfo", "args": {}})
        out = ursa_session_recon(sid)
        assert "enum/sysinfo" in out
        assert "pending" in out

    def test_shows_completed_module_status(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/sysinfo", status="completed")
        out = ursa_session_recon(sid)
        assert "enum/sysinfo" in out
        assert "completed" in out

    def test_shows_error_module_status(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/privesc", status="error")
        out = ursa_session_recon(sid)
        assert "enum/privesc" in out
        assert "error" in out

    def test_shows_critical_findings(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/loot", findings=_make_findings(["CRITICAL"]))
        out = ursa_session_recon(sid)
        assert "CRITICAL" in out
        assert "CRITICAL finding" in out

    def test_shows_all_severity_levels(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/loot",
                        findings=_make_findings(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
        out = ursa_session_recon(sid)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in out

    def test_shows_findings_from_cred_loot(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="cred/loot",
                        findings=[{"severity": "CRITICAL", "title": "Chrome passwords",
                                   "category": "cred", "detail": "14 saved"}])
        out = ursa_session_recon(sid)
        assert "Chrome passwords" in out

    def test_loot_still_pending_note(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        # Queue loot but leave it pending
        create_task(sid, "post", {"code": "stub", "module": "enum/loot", "args": {}})
        out = ursa_session_recon(sid)
        assert "still running" in out.lower() or "pending" in out.lower()

    def test_task_count_in_output(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/sysinfo", status="completed")
        _make_post_task(sid, module="enum/network", status="completed")
        out = ursa_session_recon(sid)
        assert "2" in out

    def test_findings_summary_counts(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/loot",
                        findings=_make_findings(["CRITICAL", "HIGH", "HIGH", "MEDIUM"]))
        out = ursa_session_recon(sid)
        assert "CRITICAL:1" in out
        assert "HIGH:2" in out

    def test_mixed_modules_only_loot_contributes_findings(self, tmp_db):
        from server import ursa_session_recon
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/sysinfo", status="completed")
        _make_post_task(sid, module="enum/loot",
                        findings=_make_findings(["HIGH"]))
        out = ursa_session_recon(sid)
        assert "HIGH" in out
        assert "HIGH finding" in out


# ── ursa_sitrep ───────────────────────────────────────────────────────────────

class TestSitrep:

    def test_returns_string(self, tmp_db):
        from server import ursa_sitrep
        out = ursa_sitrep()
        assert isinstance(out, str)

    def test_contains_header(self, tmp_db):
        from server import ursa_sitrep
        out = ursa_sitrep()
        assert "Sitrep" in out

    def test_empty_db_no_crash(self, tmp_db):
        from server import ursa_sitrep
        out = ursa_sitrep()
        # Should show 0 active sessions and not crash
        assert "0 active" in out

    def test_shows_active_session(self, tmp_db):
        from server import ursa_sitrep
        _make_session(tmp_db, hostname="ACTIVE1", username="root")
        out = ursa_sitrep()
        assert "1 active" in out
        assert "ACTIVE1" in out

    def test_shows_session_user_at_host(self, tmp_db):
        from server import ursa_sitrep
        _make_session(tmp_db, hostname="WIN1", username="admin")
        out = ursa_sitrep()
        assert "admin@WIN1" in out

    def test_shows_multiple_active_sessions(self, tmp_db):
        from server import ursa_sitrep
        _make_session(tmp_db, hostname="H1")
        _make_session(tmp_db, hostname="H2")
        _make_session(tmp_db, hostname="H3")
        out = ursa_sitrep()
        assert "3 active" in out

    def test_shows_task_counts(self, tmp_db):
        from server import ursa_sitrep
        sid = _make_session(tmp_db)
        create_task(sid, "shell", {"command": "whoami"})
        out = ursa_sitrep()
        assert "pending" in out

    def test_auto_recon_disabled_shown(self, tmp_db):
        from server import ursa_sitrep
        set_setting("auto_recon.enabled", False)
        out = ursa_sitrep()
        assert "DISABLED" in out

    def test_auto_recon_enabled_shown(self, tmp_db):
        from server import ursa_sitrep
        set_setting("auto_recon.enabled", True)
        out = ursa_sitrep()
        assert "ENABLED" in out

    def test_auto_recon_modules_listed_when_enabled(self, tmp_db):
        from server import ursa_sitrep
        set_setting("auto_recon.enabled", True)
        out = ursa_sitrep()
        assert "enum/sysinfo" in out

    def test_critical_findings_surfaced(self, tmp_db):
        from server import ursa_sitrep
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/loot",
                        findings=[{"severity": "CRITICAL", "title": "Root process",
                                   "category": "privesc", "detail": "uid=0"}])
        out = ursa_sitrep()
        assert "Root process" in out

    def test_high_findings_surfaced(self, tmp_db):
        from server import ursa_sitrep
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="cred/loot",
                        findings=[{"severity": "HIGH", "title": "Browser creds",
                                   "category": "cred", "detail": "14 saved"}])
        out = ursa_sitrep()
        assert "Browser creds" in out

    def test_medium_findings_not_in_sitrep(self, tmp_db):
        """sitrep only surfaces CRITICAL/HIGH — MEDIUM stays in session recon."""
        from server import ursa_sitrep
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/loot",
                        findings=[{"severity": "MEDIUM", "title": "MEDIUM detail",
                                   "category": "misc", "detail": "x"}])
        out = ursa_sitrep()
        assert "MEDIUM detail" not in out

    def test_no_sessions_no_critical_findings(self, tmp_db):
        from server import ursa_sitrep
        out = ursa_sitrep()
        assert "No critical/high findings" in out

    def test_shows_recon_progress_per_session(self, tmp_db):
        from server import ursa_sitrep
        sid = _make_session(tmp_db)
        _make_post_task(sid, module="enum/sysinfo", status="completed")
        _make_post_task(sid, module="enum/users",   status="pending")
        out = ursa_sitrep()
        # Should show recon:1/2
        assert "recon:1/2" in out

    def test_timestamp_in_header(self, tmp_db):
        import datetime

        from server import ursa_sitrep
        out = ursa_sitrep()
        year = str(datetime.datetime.now().year)
        assert year in out
