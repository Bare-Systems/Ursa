"""Tests for Ursa Minor local policy gates and audit records."""

import json

import pytest

import ursa_minor.policy as policy_mod


@pytest.fixture(autouse=True)
def audit_dir(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    monkeypatch.setattr(policy_mod, "DEFAULT_AUDIT_DIR", audit_dir)
    monkeypatch.setattr(policy_mod, "_active_engagement", lambda: None)
    monkeypatch.setattr(policy_mod, "_scope_check", lambda _target: None)
    return audit_dir


def _audit_records(audit_dir):
    path = audit_dir / "minor_policy.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_high_risk_tools_have_machine_readable_metadata():
    policies = {item["tool_name"]: item for item in policy_mod.list_tool_policies()}

    revshell = policies["generate_reverse_shell"]
    assert revshell["risk_level"] == "high"
    assert revshell["approval_required"] is True
    assert revshell["category"] == "payload"

    spray = policies["credential_spray"]
    assert spray["risk_level"] == "critical"
    assert spray["destructive"] is True


def test_allowed_policy_decision_is_audited(audit_dir):
    decision = policy_mod.enforce_tool_policy(
        "scan_ports",
        args={"target": "10.0.0.5", "scan_all": False},
        target="10.0.0.5",
        actor="alice",
        reason="quick service check",
    )

    assert decision.allowed is True
    records = _audit_records(audit_dir)
    assert len(records) == 1
    assert records[0]["actor"] == "alice"
    assert records[0]["target"] == "10.0.0.5"
    assert records[0]["justification"] == "quick service check"
    assert records[0]["policy_result"] == "allow"


def test_high_risk_tool_requires_approval(audit_dir):
    decision = policy_mod.enforce_tool_policy(
        "generate_reverse_shell",
        args={"payload_type": "bash", "lport": 4444},
        target="listener:4444",
        actor="alice",
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
    assert decision.policy_result == "approval_required"
    records = _audit_records(audit_dir)
    assert records[0]["tool_name"] == "generate_reverse_shell"
    assert records[0]["policy_result"] == "approval_required"


def test_high_risk_tool_with_approval_and_reason_is_allowed():
    decision = policy_mod.enforce_tool_policy(
        "generate_reverse_shell",
        args={"payload_type": "bash", "lport": 4444},
        target="listener:4444",
        actor="alice",
        approval_id="APP-123",
        reason="authorized payload lab",
    )

    assert decision.allowed is True
    assert decision.policy_result == "allow"
    assert "APP-123" in decision.reason


def test_approved_high_risk_tool_without_reason_is_denied(audit_dir):
    decision = policy_mod.enforce_tool_policy(
        "api_scan",
        args={"url": "https://api.example.test"},
        target="https://api.example.test",
        actor="alice",
        approval_id="APP-123",
    )

    assert decision.allowed is False
    assert decision.requires_approval is False
    assert decision.policy_result == "deny"
    records = _audit_records(audit_dir)
    assert records[0]["reason"].lower().startswith("approved high-risk")


def test_active_engagement_can_deny_destructive_tool(monkeypatch):
    monkeypatch.setattr(policy_mod, "_active_engagement", lambda: {"allow_destructive": False})

    decision = policy_mod.enforce_tool_policy(
        "credential_spray",
        args={"service": "ssh", "target": "10.0.0.5", "password": "secret"},
        target="10.0.0.5",
        actor="alice",
        approval_id="APP-123",
        reason="approved credential test",
    )

    assert decision.allowed is False
    assert decision.policy_result == "deny"
    assert "does not approve destructive" in decision.reason
    assert decision.args["password"] == "<redacted>"


def test_vuln_scan_header_only_is_low_risk_but_param_injection_requires_approval():
    headers = policy_mod.classify_tool_policy(
        "vuln_scan",
        {"url": "https://app.example.test/health", "tests": "headers"},
    )
    active = policy_mod.classify_tool_policy(
        "vuln_scan",
        {"url": "https://app.example.test/search?q=abc", "tests": "all"},
    )

    assert headers.risk_level == "low"
    assert policy_mod.policy_requires_gate(headers) is False
    assert active.risk_level == "critical"
    assert active.approval_required is True
    assert active.destructive is True


def test_server_blocks_reverse_shell_without_approval():
    from ursa_minor.server import generate_reverse_shell

    result = generate_reverse_shell(payload_type="bash", lport=4444, policy_actor="alice")

    assert "POLICY APPROVAL REQUIRED" in result
    assert "generate_reverse_shell" in result


def test_server_lists_policy_metadata():
    from ursa_minor.server import ursa_tool_policies

    output = ursa_tool_policies(risk_level="critical")

    assert "credential_spray" in output
    assert "arp_spoof" in output
