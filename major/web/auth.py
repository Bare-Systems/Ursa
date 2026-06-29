"""Control-plane auth / RBAC helpers."""

import base64
import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Callable
from typing import Any, NoReturn

from fastapi import Header, HTTPException, Request

from major.config import get_config

ROLE_LEVELS = {
    "operator": 1,
    "reviewer": 2,
    "admin": 3,
}

TOKEN_PREFIX = "ursa.v1"
DEFAULT_API_AUDIENCE = "ursa-control-plane"
SCOPE_IMPLICATIONS = {
    "*": {"*", "admin", "review", "write", "read"},
    "admin": {"admin", "review", "write", "read"},
    "review": {"review", "read"},
    "write": {"write", "read"},
    "read": {"read"},
}
_SEEN_SIGNED_JTIS: dict[str, float] = {}


def role_allows(user_role: str, required_role: str) -> bool:
    """Whether role meets or exceeds required role."""
    return ROLE_LEVELS.get((user_role or "").strip().lower(), 0) >= ROLE_LEVELS.get(
        (required_role or "").strip().lower(),
        99,
    )


def current_user(request: Request) -> dict:
    """Current authenticated user from request state."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Authentication required")
    return user


def require_role(request: Request, role: str) -> dict:
    """Require minimum role for a route/action."""
    user = current_user(request)
    if not role_allows(user.get("role", ""), role):
        raise HTTPException(403, "Insufficient permissions")
    return user


def actor_for(request: Request, action: str) -> str:
    """Stable actor string for audit records."""
    user = current_user(request)
    return f"web:{user.get('username', 'unknown')}:{action}"


def api_actor_for(user: dict, action: str) -> str:
    """Stable actor string for API-originated audit records."""
    return f"api:{user.get('username', 'unknown')}:{action}"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _normalise_scopes(value: Any, *, default: list[str] | None = None) -> list[str]:
    if value in (None, ""):
        return list(default or [])
    if isinstance(value, str):
        raw = value.replace(",", " ").split()
    elif isinstance(value, (list, tuple, set)):
        raw = [str(item) for item in value]
    else:
        raw = [str(value)]
    scopes = [item.strip().lower() for item in raw if item and item.strip()]
    return scopes or list(default or [])


def scope_allows(user_scopes: Any, required_scope: str) -> bool:
    """Whether granted scopes include a required API capability."""
    required = (required_scope or "").strip().lower()
    if not required:
        return True
    expanded: set[str] = set()
    for scope in _normalise_scopes(user_scopes):
        expanded.update(SCOPE_IMPLICATIONS.get(scope, {scope}))
    return "*" in expanded or required in expanded


def _api_audience() -> str:
    return str(
        get_config().get("major.web.auth.api_audience", DEFAULT_API_AUDIENCE)
    ).strip() or DEFAULT_API_AUDIENCE


def _api_signing_keys() -> list[str]:
    cfg = get_config()
    configured = cfg.get("major.web.auth.api_signing_keys", [])
    if not configured:
        configured = cfg.get("major.web.auth.api_signing_key", "")
    if isinstance(configured, str):
        values = [configured]
    else:
        values = [str(item) for item in configured or []]
    return [item.strip() for item in values if item and item.strip()]


def _legacy_token_records() -> list[dict[str, Any]]:
    cfg = get_config()
    records: list[dict[str, Any]] = []
    configured = cfg.get("major.web.auth.api_tokens", [])
    if isinstance(configured, dict):
        entries: list[Any] = []
        for token_key, entry in configured.items():
            if isinstance(entry, dict):
                token_record = dict(entry)
                token_record.setdefault("token", token_key)
                entries.append(token_record)
            elif entry:
                entries.append(entry)
            else:
                entries.append(token_key)
        configured = entries
    if isinstance(configured, str):
        configured = [configured]

    for entry in configured or []:
        if isinstance(entry, str):
            token = entry.strip()
            record: dict[str, Any] = {}
        elif isinstance(entry, dict):
            token = str(entry.get("token", "")).strip()
            record = dict(entry)
        else:
            continue
        if token:
            records.append({
                "token": token,
                "actor": str(record.get("actor", "bearclaw-web")).strip() or "bearclaw-web",
                "role": str(record.get("role", "admin")).strip().lower() or "admin",
                "scopes": _normalise_scopes(record.get("scopes"), default=["*"]),
                "audience": str(record.get("audience", _api_audience())).strip() or _api_audience(),
                "expires_at": record.get("expires_at"),
            })

    token = str(cfg.get("major.web.auth.api_token", "")).strip()
    if token:
        records.append({
            "token": token,
            "actor": str(
                cfg.get("major.web.auth.api_token_actor", "bearclaw-web")
            ).strip() or "bearclaw-web",
            "role": str(cfg.get("major.web.auth.api_token_role", "admin")).strip().lower() or "admin",
            "scopes": _normalise_scopes(
                cfg.get("major.web.auth.api_token_scopes", ["*"]),
                default=["*"],
            ),
            "audience": str(
                cfg.get("major.web.auth.api_token_audience", _api_audience())
            ).strip() or _api_audience(),
            "expires_at": cfg.get("major.web.auth.api_token_expires_at", None),
        })
    return records


def _legacy_auth_configured() -> bool:
    return bool(_legacy_token_records())


def _signed_auth_configured() -> bool:
    return bool(_api_signing_keys())


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        return ""
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return value.strip()


def _coerce_timestamp(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _audit_authz_failure(reason: str, *, actor: str = "unknown") -> None:
    try:
        from major.db import log_event

        log_event("warning", "auth", f"API auth denied for {actor}: {reason}")
    except Exception:
        pass


def _deny(status_code: int, detail: str, *, actor: str = "unknown") -> NoReturn:
    _audit_authz_failure(detail, actor=actor)
    raise HTTPException(status_code, detail)


def _user_from_legacy_token(token: str, *, now: float) -> dict[str, Any] | None:
    for record in _legacy_token_records():
        if not hmac.compare_digest(token, str(record["token"])):
            continue
        expires_at = _coerce_timestamp(record.get("expires_at"))
        if expires_at is not None and now >= expires_at:
            _deny(401, "API token expired", actor=str(record.get("actor", "unknown")))
        return {
            "username": record["actor"],
            "role": record["role"],
            "scopes": record["scopes"],
            "audience": record["audience"],
            "is_active": True,
            "auth_type": "static-token",
        }
    return None


def _token_signature(message: str, signing_key: str) -> str:
    return _b64url_encode(
        hmac.new(signing_key.encode(), message.encode("ascii"), hashlib.sha256).digest()
    )


def _prune_replay_cache(now: float) -> None:
    expired = [jti for jti, expires_at in _SEEN_SIGNED_JTIS.items() if expires_at <= now]
    for jti in expired:
        _SEEN_SIGNED_JTIS.pop(jti, None)


def _user_from_signed_token(token: str, *, now: float) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 4 or ".".join(parts[:2]) != TOKEN_PREFIX:
        _deny(401, "Invalid signed API token")

    payload_b64 = parts[2]
    signature = parts[3]
    message = f"{TOKEN_PREFIX}.{payload_b64}"
    keys = _api_signing_keys()
    if not keys:
        raise HTTPException(503, "API signing key is not configured")
    if not any(hmac.compare_digest(signature, _token_signature(message, key)) for key in keys):
        _deny(401, "Invalid signed API token")

    try:
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        _deny(401, "Invalid signed API token")

    actor = str(claims.get("sub") or claims.get("actor") or "").strip()
    if not actor:
        _deny(401, "Signed API token missing subject")
    role = str(claims.get("role", "")).strip().lower()
    if role not in ROLE_LEVELS:
        _deny(403, "Signed API token has invalid role", actor=actor)
    audience = str(claims.get("aud", "")).strip()
    if audience != _api_audience():
        _deny(401, "Signed API token has wrong audience", actor=actor)
    exp = _coerce_timestamp(claims.get("exp"))
    if exp is None or now >= exp:
        _deny(401, "Signed API token expired", actor=actor)
    nbf = _coerce_timestamp(claims.get("nbf"))
    if nbf is not None and now < nbf:
        _deny(401, "Signed API token is not yet valid", actor=actor)

    jti = str(claims.get("jti", "")).strip()
    if not jti:
        _deny(401, "Signed API token missing jti", actor=actor)
    _prune_replay_cache(now)
    if jti in _SEEN_SIGNED_JTIS:
        _deny(401, "Signed API token replay detected", actor=actor)
    replay_ttl = float(get_config().get("major.web.auth.api_replay_ttl_seconds", 300))
    _SEEN_SIGNED_JTIS[jti] = min(float(exp), now + max(replay_ttl, 1.0))

    return {
        "username": actor,
        "role": role,
        "scopes": _normalise_scopes(claims.get("scopes"), default=[]),
        "audience": audience,
        "is_active": True,
        "auth_type": "signed-token",
        "jti": jti,
    }


def mint_api_token(
    actor: str,
    *,
    role: str = "admin",
    scopes: list[str] | tuple[str, ...] | str | None = None,
    audience: str | None = None,
    expires_in: int = 300,
    signing_key: str | None = None,
    jti: str | None = None,
    now: float | None = None,
) -> str:
    """Create a signed `ursa.v1` API token for service-to-service clients."""
    issued_at = int(now if now is not None else time.time())
    key = signing_key or (_api_signing_keys()[0] if _api_signing_keys() else "")
    if not key:
        raise ValueError("API signing key is not configured")
    payload = {
        "sub": actor,
        "role": role.strip().lower(),
        "scopes": _normalise_scopes(scopes, default=["read"]),
        "aud": audience or _api_audience(),
        "iat": issued_at,
        "nbf": issued_at - 5,
        "exp": issued_at + int(expires_in),
        "jti": jti or uuid.uuid4().hex,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload_b64 = _b64url_encode(payload_json)
    message = f"{TOKEN_PREFIX}.{payload_b64}"
    return f"{message}.{_token_signature(message, key)}"


def clear_api_replay_cache() -> None:
    """Clear signed-token replay state. Intended for tests."""
    _SEEN_SIGNED_JTIS.clear()


def authenticate_api_request(
    authorization: str | None = None,
    x_bearclaw_actor: str | None = None,
    x_bearclaw_role: str | None = None,
    role: str = "admin",
    scope: str = "admin",
    *,
    allow_missing_token: bool = False,
) -> dict:
    """Authenticate a control-plane request and require server-side permissions.

    `x_bearclaw_actor` and `x_bearclaw_role` are accepted for wire
    compatibility with older clients but are not authoritative.
    """
    _ = (x_bearclaw_actor, x_bearclaw_role)
    now = time.time()
    token = _extract_bearer_token(authorization)
    auth_configured = _legacy_auth_configured() or _signed_auth_configured()

    if not token:
        if allow_missing_token and not auth_configured:
            return {
                "username": "dev-mcp",
                "role": "admin",
                "scopes": ["*"],
                "is_active": True,
                "auth_type": "dev-mcp",
            }
        _deny(401, "Missing API token")

    user: dict[str, Any]
    if token.startswith(f"{TOKEN_PREFIX}."):
        user = _user_from_signed_token(token, now=now)
    else:
        legacy_user = _user_from_legacy_token(token, now=now)
        if legacy_user is None:
            if not auth_configured:
                raise HTTPException(503, "API token is not configured")
            _deny(401, "Invalid API token")
        user = legacy_user

    actor = str(user.get("username", "unknown"))
    if not role_allows(str(user.get("role", "")), role):
        _deny(403, "Insufficient role", actor=actor)
    if not scope_allows(user.get("scopes", []), scope):
        _deny(403, "Insufficient scope", actor=actor)
    return user


def require_api_role(
    authorization: str | None = Header(default=None),
    x_bearclaw_actor: str | None = Header(default=None),
    x_bearclaw_role: str | None = Header(default=None),
    role: str = "admin",
    scope: str = "admin",
) -> dict:
    """Authenticate a bearer-token API request and require minimum role."""
    return authenticate_api_request(
        authorization=authorization,
        x_bearclaw_actor=x_bearclaw_actor,
        x_bearclaw_role=x_bearclaw_role,
        role=role,
        scope=scope,
    )


def api_role_dependency(role: str = "admin", scope: str = "admin") -> Callable[..., dict]:
    """Build a FastAPI dependency for an API role/scope pair."""

    def _dependency(
        authorization: str | None = Header(default=None),
        x_bearclaw_actor: str | None = Header(default=None),
        x_bearclaw_role: str | None = Header(default=None),
    ) -> dict:
        return authenticate_api_request(
            authorization=authorization,
            x_bearclaw_actor=x_bearclaw_actor,
            x_bearclaw_role=x_bearclaw_role,
            role=role,
            scope=scope,
        )

    return _dependency
