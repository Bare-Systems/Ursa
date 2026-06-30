from pathlib import Path

import pytest

from major.config import ConfigValidationError, is_production_mode, load_config


def _write_config(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_dev_defaults_are_allowed_without_production_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("URSA_ENV", raising=False)
    monkeypatch.delenv("URSA_MODE", raising=False)
    monkeypatch.delenv("URSA_PRODUCTION", raising=False)

    cfg = load_config(path=_write_config(tmp_path / "ursa.yaml", "{}"))

    assert is_production_mode(cfg) is False
    assert cfg.get("major.web.auth.bootstrap_password") == "change-me-now"


def test_production_mode_rejects_default_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("URSA_ENV", "production")

    with pytest.raises(ConfigValidationError) as exc_info:
        load_config(path=_write_config(tmp_path / "ursa.yaml", "{}"))

    message = str(exc_info.value)
    assert "major.web.auth.session_secret" in message
    assert "major.web.auth.bootstrap_password" in message
    assert "major.governance.approval_signing_key" in message
    assert "api_signing_keys or api_token" in message


def test_configured_production_mode_rejects_placeholder_api_signing_key(tmp_path, monkeypatch):
    monkeypatch.delenv("URSA_ENV", raising=False)
    monkeypatch.delenv("URSA_MODE", raising=False)
    monkeypatch.delenv("URSA_PRODUCTION", raising=False)

    with pytest.raises(ConfigValidationError) as exc_info:
        load_config(
            path=_write_config(
                tmp_path / "ursa.yaml",
                """
environment: production
major:
  web:
    auth:
      session_secret: "ssssssssssssssssssssssssssssssss"
      bootstrap_password: "not-default-anymore"
      api_signing_keys:
        - "rotate-this-32-byte-signing-secret"
  governance:
    approval_signing_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
            )
        )

    assert "major.web.auth.api_signing_keys[0]" in str(exc_info.value)


def test_production_mode_accepts_generated_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("URSA_PRODUCTION", "1")

    cfg = load_config(
        path=_write_config(
            tmp_path / "ursa.yaml",
            """
major:
  web:
    auth:
      session_secret: "ssssssssssssssssssssssssssssssss"
      bootstrap_password: "not-default-anymore"
      api_signing_keys:
        - "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
  governance:
    approval_signing_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
        )
    )

    assert is_production_mode(cfg) is True
    assert cfg.get("major.web.auth.api_signing_keys") == ["kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"]


def test_production_mode_validates_static_api_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("URSA_ENV", "field")

    with pytest.raises(ConfigValidationError) as exc_info:
        load_config(
            path=_write_config(
                tmp_path / "ursa.yaml",
                """
major:
  web:
    auth:
      session_secret: "ssssssssssssssssssssssssssssssss"
      bootstrap_password: "not-default-anymore"
      api_token: "your-shared-bearclaw-token"
  governance:
    approval_signing_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
            )
        )

    assert "major.web.auth.api_token" in str(exc_info.value)
