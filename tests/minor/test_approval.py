import os

import pytest
from click.testing import CliRunner

import ursa_minor.approval as approval
from ursa_minor.cli import main


@pytest.fixture(autouse=True)
def approval_store(tmp_path, monkeypatch):
    approval_dir = tmp_path / "approvals"
    monkeypatch.setattr(approval, "APPROVAL_DIR", approval_dir)
    monkeypatch.setattr(approval, "APPROVAL_KEY_FILE", approval_dir / "minor.key")
    monkeypatch.setattr(approval, "APPROVAL_USE_FILE", approval_dir / "used.jsonl")
    monkeypatch.delenv("URSA_MINOR_APPROVAL_KEY", raising=False)
    approval.initialize_approval_key()


def _issue(now=1_000):
    return approval.issue_approval(
        tool_name="full_recon",
        target="10.0.0.0/24",
        actor="alice",
        reason="authorized lab recon",
        risk_level="high",
        ttl_seconds=60,
        approved_by="bob",
        now=now,
    )


def _verify(token, **overrides):
    values = {
        "tool_name": "full_recon",
        "target": "10.0.0.0/24",
        "actor": "alice",
        "reason": "authorized lab recon",
        "risk_level": "high",
        "now": 1_010,
    }
    values.update(overrides)
    return approval.verify_approval(token, **values)


def test_key_and_use_store_are_owner_only():
    assert approval.APPROVAL_KEY_FILE.stat().st_mode & 0o777 == 0o600

    claims, error = _verify(_issue())

    assert error == ""
    assert claims["approved_by"] == "bob"
    assert approval.APPROVAL_USE_FILE.stat().st_mode & 0o777 == 0o600


def test_approval_is_single_use():
    token = _issue()
    assert _verify(token)[0] is not None

    claims, error = _verify(token)

    assert claims is None
    assert "already been used" in error


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool_name", "credential_spray"),
        ("target", "10.0.1.0/24"),
        ("actor", "mallory"),
        ("reason", "different operation"),
        ("risk_level", "critical"),
    ],
)
def test_approval_is_bound_to_operation(field, value):
    claims, error = _verify(_issue(), consume=False, **{field: value})

    assert claims is None
    assert error


def test_expired_and_tampered_tokens_are_rejected():
    token = _issue()
    assert _verify(token, now=1_061, consume=False)[0] is None

    claims, error = _verify(token + "x", consume=False)

    assert claims is None
    assert "signature" in error.lower()


def test_environment_key_must_be_strong(monkeypatch):
    monkeypatch.setenv("URSA_MINOR_APPROVAL_KEY", "short")

    with pytest.raises(ValueError, match="at least 32 bytes"):
        approval.issue_approval(
            tool_name="full_recon",
            target="10.0.0.0/24",
            actor="alice",
            reason="authorized lab recon",
            risk_level="high",
        )

    assert os.environ["URSA_MINOR_APPROVAL_KEY"] == "short"


def test_key_file_must_be_owner_only():
    token = _issue()
    approval.APPROVAL_KEY_FILE.chmod(0o644)

    claims, error = _verify(token, consume=False)

    assert claims is None
    assert "owner-only" in error


def test_cli_issues_verifiable_operation_token():
    result = CliRunner().invoke(
        main,
        [
            "approval",
            "issue",
            "--tool",
            "full_recon",
            "--target",
            "10.0.0.0/24",
            "--actor",
            "alice",
            "--reason",
            "authorized lab recon",
        ],
    )

    assert result.exit_code == 0
    claims, error = approval.verify_approval(
        result.output.strip(),
        tool_name="full_recon",
        target="10.0.0.0/24",
        actor="alice",
        reason="authorized lab recon",
        risk_level="high",
        consume=False,
    )
    assert error == ""
    assert claims is not None
