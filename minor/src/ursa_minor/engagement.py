"""
Ursa Minor — Engagement / Scope Manifest
=========================================
Lightweight scope-management layer for penetration test sessions.

An engagement tracks:
  - Which hosts/CIDRs/URL prefixes are in scope
  - Rate limits and concurrency caps
  - Whether destructive tests (sqli, cmdi, etc.) are approved
  - Free-form operator notes

Engagements are stored as JSON files in ~/.ursa/engagements/.
Only one engagement is "active" at a time; the active engagement ID
is written to ~/.ursa/engagements/.active.

Usage (via MCP tools):
  create_engagement(name="Tardigrade local", scope_hosts="127.0.0.1",
                    scope_paths="/,/health,/api", allow_destructive=False)
  check_scope("http://127.0.0.1:18069/health")   # → True
  check_scope("http://evil.example.com/")          # → False (out of scope)
  get_engagement()                                  # → summary of active
  close_engagement()                                # → deactivates
"""

import ipaddress
import json
import time
from datetime import datetime
from pathlib import Path


_ENG_DIR = Path.home() / ".ursa" / "engagements"
_ACTIVE_FILE = _ENG_DIR / ".active"


# ── internal helpers ──────────────────────────────────────────────────────────


def _eng_dir() -> Path:
    _ENG_DIR.mkdir(parents=True, exist_ok=True)
    return _ENG_DIR


def _active_id() -> str | None:
    p = _ACTIVE_FILE
    if p.exists():
        v = p.read_text().strip()
        return v if v else None
    return None


def active_engagement_id() -> str | None:
    """Public accessor for the active engagement id (or None).

    Used by the asset graph to scope collected facts to the current engagement.
    """
    return _active_id()


def _load(eng_id: str) -> dict | None:
    f = _eng_dir() / f"{eng_id}.json"
    if not f.exists():
        return None
    with open(f) as fh:
        return json.load(fh)


def _save(eng_id: str, record: dict) -> None:
    f = _eng_dir() / f"{eng_id}.json"
    with open(f, "w") as fh:
        json.dump(record, fh, indent=2, default=str)


def _ip_in_scope(host: str, scope_hosts: list[str]) -> bool:
    """Return True if host matches any scope entry (exact, CIDR, or wildcard domain)."""
    try:
        host_addr = ipaddress.ip_address(host)
    except ValueError:
        host_addr = None

    for entry in scope_hosts:
        entry = entry.strip()
        if not entry:
            continue
        # CIDR
        if "/" in entry:
            try:
                if host_addr and host_addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
            continue
        # Wildcard domain prefix (e.g. *.example.com)
        if entry.startswith("*."):
            suffix = entry[1:]  # ".example.com"
            if host.endswith(suffix) or host == entry[2:]:
                return True
            continue
        # Exact match
        if host == entry:
            return True

    return False


# ── public API (called by MCP tools in server.py) ────────────────────────────


def create(
    name: str,
    scope_hosts: str,
    scope_paths: str = "/",
    allow_destructive: bool = False,
    rate_limit_rps: int = 10,
    notes: str = "",
) -> dict:
    """Create a new engagement and make it active.

    Args:
        name: Human-readable engagement name.
        scope_hosts: Comma-separated list of in-scope targets. Accepts IP
                     addresses, CIDR ranges (192.168.1.0/24), and hostnames
                     or wildcard domains (*.example.com).
        scope_paths: Comma-separated URL path prefixes considered in scope
                     (default: "/"). Only paths that start with one of these
                     prefixes are allowed.
        allow_destructive: Whether injection/exploit tests (SQLi, CMDi, LFI)
                           are approved for this engagement.
        rate_limit_rps: Suggested requests-per-second cap (informational;
                        tools that respect it will throttle themselves).
        notes: Free-form operator notes attached to the engagement record.

    Returns:
        Engagement record dict.
    """
    eng_id = f"eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    hosts = [h.strip() for h in scope_hosts.split(",") if h.strip()]
    paths = [p.strip() for p in scope_paths.split(",") if p.strip()] or ["/"]

    record = {
        "id": eng_id,
        "name": name,
        "created_at": datetime.now().isoformat(),
        "status": "active",
        "scope": {
            "hosts": hosts,
            "paths": paths,
        },
        "allow_destructive": allow_destructive,
        "rate_limit_rps": rate_limit_rps,
        "notes": notes,
        "closed_at": None,
    }
    _save(eng_id, record)
    _ACTIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _ACTIVE_FILE.write_text(eng_id)
    return record


def check(url: str) -> dict:
    """Check whether a URL is in scope for the active engagement.

    Returns a dict with keys:
      in_scope (bool), reason (str), engagement_id (str | None),
      allow_destructive (bool)
    """
    import urllib.parse

    eng_id = _active_id()
    if eng_id is None:
        return {
            "in_scope": True,
            "reason": "No active engagement — scope checks disabled",
            "engagement_id": None,
            "allow_destructive": True,
        }

    record = _load(eng_id)
    if record is None:
        return {
            "in_scope": False,
            "reason": f"Active engagement {eng_id} not found on disk",
            "engagement_id": eng_id,
            "allow_destructive": False,
        }

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"

    scope = record.get("scope", {})
    scope_hosts = scope.get("hosts", [])
    scope_paths = scope.get("paths", ["/"])

    if not _ip_in_scope(host, scope_hosts):
        return {
            "in_scope": False,
            "reason": f"Host '{host}' not in scope {scope_hosts}",
            "engagement_id": eng_id,
            "allow_destructive": False,
        }

    if not any(path.startswith(p) for p in scope_paths):
        return {
            "in_scope": False,
            "reason": f"Path '{path}' not in scope paths {scope_paths}",
            "engagement_id": eng_id,
            "allow_destructive": False,
        }

    return {
        "in_scope": True,
        "reason": "URL matches scope",
        "engagement_id": eng_id,
        "allow_destructive": record.get("allow_destructive", False),
    }


def get_active() -> dict | None:
    """Return the active engagement record, or None."""
    eng_id = _active_id()
    if eng_id is None:
        return None
    return _load(eng_id)


def close() -> dict | None:
    """Close the active engagement. Returns the closed record, or None."""
    eng_id = _active_id()
    if eng_id is None:
        return None

    record = _load(eng_id)
    if record is None:
        _ACTIVE_FILE.write_text("")
        return None

    record["status"] = "closed"
    record["closed_at"] = datetime.now().isoformat()
    _save(eng_id, record)
    _ACTIVE_FILE.write_text("")
    return record


def list_all(limit: int = 20) -> list[dict]:
    """Return summary of all engagements (newest first)."""
    d = _eng_dir()
    files = sorted(d.glob("eng_*.json"), reverse=True)[:limit]
    summaries = []
    for f in files:
        try:
            with open(f) as fh:
                r = json.load(fh)
            summaries.append({
                "id": r.get("id"),
                "name": r.get("name"),
                "status": r.get("status"),
                "created_at": r.get("created_at"),
                "scope_hosts": r.get("scope", {}).get("hosts", []),
                "allow_destructive": r.get("allow_destructive", False),
            })
        except Exception:
            continue
    return summaries
