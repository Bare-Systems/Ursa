"""Signed, short-lived, one-use approvals for Ursa Minor high-risk tools."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any

APPROVAL_DIR = Path.home() / ".ursa" / "approvals"
APPROVAL_KEY_FILE = APPROVAL_DIR / "minor.key"
APPROVAL_USE_FILE = APPROVAL_DIR / "minor-used.jsonl"
TOKEN_PREFIX = "ursa-minor.v1"
MAX_TTL_SECONDS = 3600


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _ensure_approval_dir() -> None:
    APPROVAL_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    APPROVAL_DIR.chmod(0o700)


def initialize_approval_key(*, force: bool = False) -> Path:
    """Create the local approval-signing key with owner-only permissions."""
    _ensure_approval_dir()
    if APPROVAL_KEY_FILE.exists() and not force:
        raise FileExistsError(f"Approval key already exists: {APPROVAL_KEY_FILE}")
    APPROVAL_KEY_FILE.write_bytes(secrets.token_bytes(32))
    APPROVAL_KEY_FILE.chmod(0o600)
    return APPROVAL_KEY_FILE


def _load_key() -> bytes:
    configured = os.environ.get("URSA_MINOR_APPROVAL_KEY", "").encode()
    if configured:
        if len(configured) < 32:
            raise ValueError("URSA_MINOR_APPROVAL_KEY must be at least 32 bytes")
        return configured
    if not APPROVAL_KEY_FILE.exists():
        raise FileNotFoundError(
            f"Approval key not initialized; run `ursa approval init` ({APPROVAL_KEY_FILE})"
        )
    key_stat = APPROVAL_KEY_FILE.stat()
    if stat.S_IMODE(key_stat.st_mode) & 0o077:
        raise PermissionError(f"Approval key must be owner-only (0600): {APPROVAL_KEY_FILE}")
    key = APPROVAL_KEY_FILE.read_bytes()
    if len(key) < 32:
        raise ValueError(f"Approval key is too short: {APPROVAL_KEY_FILE}")
    return key


def issue_approval(
    *,
    tool_name: str,
    target: str,
    actor: str,
    reason: str,
    risk_level: str,
    ttl_seconds: int = 300,
    approved_by: str = "operator",
    now: int | None = None,
) -> str:
    """Issue an HMAC-signed approval bound to an operation and requester."""
    if not all(value.strip() for value in (tool_name, target, actor, reason, risk_level)):
        raise ValueError("tool, target, actor, reason, and risk level are required")
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}")

    issued_at = int(time.time() if now is None else now)
    claims = {
        "actor": actor.strip(),
        "approved_by": approved_by.strip() or "operator",
        "exp": issued_at + ttl_seconds,
        "iat": issued_at,
        "jti": secrets.token_urlsafe(12),
        "reason": reason.strip(),
        "risk": risk_level.strip().lower(),
        "target": target.strip(),
        "tool": tool_name.strip(),
        "v": 1,
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(_load_key(), payload, hashlib.sha256).digest()
    return f"{TOKEN_PREFIX}.{_b64encode(payload)}.{_b64encode(signature)}"


def _consume_once(jti: str, expires_at: int, current_time: int) -> bool:
    """Atomically record a token identifier; return False when already used."""
    _ensure_approval_dir()
    fd = os.open(APPROVAL_USE_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as handle:
        os.chmod(APPROVAL_USE_FILE, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        active_records = []
        for line in handle:
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if int(record.get("exp", 0)) >= current_time:
                active_records.append(record)
        if any(str(record.get("jti", "")) == jti for record in active_records):
            return False
        active_records.append({"jti": jti, "exp": expires_at})
        handle.seek(0)
        handle.truncate()
        for record in active_records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return True


def verify_approval(
    token: str,
    *,
    tool_name: str,
    target: str,
    actor: str,
    reason: str,
    risk_level: str,
    consume: bool = True,
    now: int | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Verify binding, expiry, risk ceiling, signature, and one-use semantics."""
    # TOKEN_PREFIX itself contains a dot, so parse from the right.
    try:
        token_prefix, version, payload_text, signature_text = token.split(".", 3)
    except ValueError:
        return None, "Approval token format is invalid."
    if f"{token_prefix}.{version}" != TOKEN_PREFIX:
        return None, "Approval token version is unsupported."

    try:
        payload = _b64decode(payload_text)
        supplied_signature = _b64decode(signature_text)
        expected_signature = hmac.new(_load_key(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None, "Approval token signature is invalid."
        claims = json.loads(payload)
        if not isinstance(claims, dict):
            return None, "Approval token claims must be an object."
    except (
        binascii.Error,
        FileNotFoundError,
        PermissionError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        return None, str(exc)

    current_time = int(time.time() if now is None else now)
    if int(claims.get("exp", 0)) <= current_time:
        return None, "Approval token has expired."
    if int(claims.get("iat", 0)) > current_time + 30:
        return None, "Approval token was issued in the future."
    expected = {
        "tool": tool_name.strip(),
        "target": target.strip(),
        "actor": actor.strip(),
        "reason": reason.strip(),
    }
    for claim, value in expected.items():
        if not hmac.compare_digest(str(claims.get(claim, "")), value):
            return None, f"Approval token {claim} does not match this operation."

    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    approved_risk = str(claims.get("risk", "")).lower()
    if risk_order.get(risk_level, 99) > risk_order.get(approved_risk, -1):
        return None, "Approval token does not authorize this risk level."

    jti = str(claims.get("jti", ""))
    if not jti:
        return None, "Approval token identifier is missing."
    if consume and not _consume_once(jti, int(claims["exp"]), current_time):
        return None, "Approval token has already been used."
    return claims, ""
