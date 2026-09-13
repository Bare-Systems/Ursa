"""Tests for governance policy, approvals, and immutable audit events."""

from major.db import (
    create_session,
    get_approval_request,
    get_immutable_audit,
    list_approval_requests,
    resolve_approval_request,
    verify_immutable_audit_chain,
)
from major.governance import (
    build_policy_remediation_recommendations,
    classify_task_risk,
    get_policy_remediation_plan,
    process_approval_decision,
    process_bulk_approval_decisions,
    queue_task_with_policy,
)


class _Cfg:
    def __init__(self, values):
        self._values = values

    def get(self, path, default=None):
        return self._values.get(path, default)


def test_queue_task_without_step_up(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": False,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )

    result = queue_task_with_policy(
        session_id=sample_session,
        task_type="whoami",
        args={},
        actor="test",
    )
    assert result["status"] == "queued"
    assert result["task_id"]

    audit_rows = get_immutable_audit(limit=10)
    assert audit_rows
    assert audit_rows[0]["policy_result"] == "allow"
    assert verify_immutable_audit_chain()["ok"] is True


def test_high_risk_requires_approval_when_enabled(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )

    result = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/etc/shadow"},
        actor="test",
    )
    assert result["status"] == "approval_required"
    assert result["approval_id"]

    approvals = list_approval_requests(status="pending", limit=10)
    assert any(r["id"] == result["approval_id"] for r in approvals)
    assert verify_immutable_audit_chain()["ok"] is True


def test_approved_request_can_queue_task(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )
    pending = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
    )
    assert pending["status"] == "approval_required"
    approval_id = pending["approval_id"]

    assert resolve_approval_request(approval_id, approved=True, decided_by="test") is True
    assert get_approval_request(approval_id)["status"] == "approved"

    queued = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
        approval_id=approval_id,
    )
    assert queued["status"] == "queued"
    assert queued["task_id"]


def test_invalid_approval_id_is_denied(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )
    result = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
        approval_id="NOPE1234",
    )
    assert result["status"] == "denied"
    assert "not found" in result["message"]


def test_approval_is_bound_to_session_and_arguments(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )
    pending = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/approved.txt"},
        actor="test",
    )
    assert resolve_approval_request(
        pending["approval_id"], approved=True, decided_by="reviewer"
    )

    wrong_args = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/etc/shadow"},
        actor="test",
        approval_id=pending["approval_id"],
    )
    other_session = create_session("10.0.0.99")
    wrong_session = queue_task_with_policy(
        session_id=other_session,
        task_type="download",
        args={"path": "/tmp/approved.txt"},
        actor="test",
        approval_id=pending["approval_id"],
    )

    assert wrong_args["status"] == "denied"
    assert "arguments" in wrong_args["message"]
    assert wrong_session["status"] == "denied"
    assert "session" in wrong_session["message"]


def test_approval_is_consumed_after_one_task(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )
    pending = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/approved.txt"},
        actor="test",
    )
    assert resolve_approval_request(
        pending["approval_id"], approved=True, decided_by="reviewer"
    )

    first = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/approved.txt"},
        actor="test",
        approval_id=pending["approval_id"],
    )
    replay = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/approved.txt"},
        actor="test",
        approval_id=pending["approval_id"],
    )

    assert first["status"] == "queued"
    assert replay["status"] == "denied"
    assert "not approved" in replay["message"]


def test_process_approval_decision_approve_queues_task(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )
    pending = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
    )
    result = process_approval_decision(
        approval_id=pending["approval_id"],
        approved=True,
        actor="test-bulk",
        note="ok",
    )
    assert result["status"] == "approved"
    assert result["queue_result"] == "queued"
    assert result["task_id"]
    assert result["approval_signature"]
    assert result["signed_at"]


def test_process_bulk_approvals_campaign_filter(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )
    sid_campaign = create_session("10.0.0.99", campaign="ALPHA", tags="prod")
    sid_other = create_session("10.0.0.100", campaign="BETA", tags="lab")

    a1 = queue_task_with_policy(
        session_id=sid_campaign,
        task_type="download",
        args={"path": "/tmp/a.txt"},
        actor="test",
    )
    a2 = queue_task_with_policy(
        session_id=sid_other,
        task_type="download",
        args={"path": "/tmp/b.txt"},
        actor="test",
    )
    assert a1["status"] == "approval_required"
    assert a2["status"] == "approval_required"

    summary = process_bulk_approval_decisions(
        approved=False,
        actor="test-bulk",
        campaign="ALPHA",
        tag=None,
        note="campaign reject",
    )
    assert summary["matched"] == 1
    assert summary["rejected"] == 1


def test_build_policy_remediation_recommendations():
    recs = build_policy_remediation_recommendations(
        [
            {
                "campaign": "ALPHA",
                "metric": "critical",
                "severity": "critical",
                "value": 3,
                "threshold": 1,
            }
        ]
    )
    assert len(recs) == 1
    assert recs[0]["campaign"] == "ALPHA"
    assert "critical" in recs[0]["approve_cmd"]


def test_arp_spoof_classified_as_critical():
    assert classify_task_risk("arp_spoof") == "critical"


def test_arp_spoof_stop_classified_as_low():
    assert classify_task_risk("arp_spoof_stop") == "low"


def test_shell_commands_fail_high_unless_explicitly_read_only():
    assert classify_task_risk("shell", {"command": "whoami"}) == "medium"
    assert classify_task_risk("shell", {"command": "echo hello"}) == "high"
    assert classify_task_risk("shell", {"command": "whoami; curl attacker"}) == "high"


def test_post_module_risk_depends_on_category():
    assert classify_task_risk("post", {"module": "enum/sysinfo"}) == "medium"
    assert classify_task_risk("post", {"module": "cred/browser"}) == "high"
    assert classify_task_risk("post", {"module": "persist/cron"}) == "critical"
    assert classify_task_risk("post", {"module": "enum/../../persist/cron"}) == "high"


def test_auto_recon_skips_invalid_module_paths(tmp_db, sample_session, monkeypatch):
    from major.server import _queue_auto_recon

    monkeypatch.setattr(
        "major.server._auto_recon_modules",
        lambda: ["enum/../../persist/cron"],
    )

    assert _queue_auto_recon(sample_session) == []


def test_get_policy_remediation_plan_from_alerts(tmp_db):
    from major import db

    sid = db.create_session("10.0.0.1", campaign="ALPHA")
    db.upsert_campaign_policy(
        campaign="ALPHA",
        max_pending_total=0,
        max_pending_high=0,
        max_pending_critical=0,
        updated_by="test",
    )
    db.create_approval_request("queue_task", "critical", session_id=sid, task_type="kill")
    plan = get_policy_remediation_plan(campaign="ALPHA")
    assert len(plan) >= 1
    assert plan[0]["campaign"] == "ALPHA"
