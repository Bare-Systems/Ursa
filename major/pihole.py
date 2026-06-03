#!/usr/bin/env python3
"""
Ursa Major — Pi-hole DNS Insight
================================
Read-only aggregation over Pi-hole's FTL long-term query database
(``pihole-FTL.db``) for per-client "what is it talking to" telemetry
(ROADMAP Phase 5B).

The DNS log already exists — Pi-hole records every query for the whole LAN.
This module opens that DB **read-only** and answers operator questions:
top talkers by query volume, top domains (overall or per client), and the
blocked-vs-allowed ratio. Nothing here writes to Pi-hole.

The privileged scan/inventory side lives in netinsight.py; this is the
DNS-destination side of the same home-security picture.

Schema support: works against both FTL layouts.
  * **v5** — flat ``queries`` table with ``domain``/``client`` as TEXT.
  * **v6** — normalized ``queries`` where ``domain``/``client`` are integer ids
    into ``domain_by_id`` / ``client_by_id`` lookup tables.
The layout is detected at query time (presence of ``domain_by_id``), so the
caller never has to know which Pi-hole version is running.

If the DB is missing or unreadable, every function degrades gracefully
(empty results / ``available: False``) so the widget shows an "unavailable"
state instead of erroring.
"""

import sqlite3
import time
from contextlib import contextmanager

from major.config import get_config

# Pi-hole FTL query status codes that count as *blocked*. Everything else
# (forwarded, cached, retried, stale, unknown) is treated as allowed.
# Ref: Pi-hole FTL query status definitions.
BLOCKED_STATUSES = (1, 4, 5, 6, 7, 8, 9, 10, 11, 16)

# Inlined into SQL — every element is a literal int, so this is injection-safe.
_BLOCKED_SQL = "(" + ",".join(str(s) for s in BLOCKED_STATUSES) + ")"


class PiholeUnavailable(Exception):
    """Raised internally when the FTL DB cannot be opened/queried."""


def _db_path(db_path: str | None = None) -> str:
    return db_path or str(get_config().get("major.pihole.db_path", ""))


@contextmanager
def _open(db_path: str | None = None):
    """Open the FTL DB read-only and yield ``(connection, schema)``.

    Schema detection happens once here, at the connection layer, so each query
    function gets the resolved column expressions without re-detecting. Raises
    PiholeUnavailable if the DB can't be opened or queried.
    """
    path = _db_path(db_path)
    if not path:
        raise PiholeUnavailable("Pi-hole FTL DB path is not configured")
    try:
        # Read-only URI so we can never mutate Pi-hole's database.
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        schema = _schema(conn)
    except sqlite3.Error as exc:
        raise PiholeUnavailable(f"cannot open FTL DB at {path}: {exc}") from exc
    try:
        yield conn, schema
    except sqlite3.Error as exc:
        raise PiholeUnavailable(f"FTL DB query failed: {exc}") from exc
    finally:
        conn.close()


def _since_ts(since_hours: float) -> int:
    return int(time.time() - since_hours * 3600)


def _schema(conn) -> dict:
    """Resolve column expressions for the FTL schema in use.

    The ``queries`` table is always aliased ``q``. On v6 the domain/client are
    integer ids, so we LEFT JOIN the lookup tables and read their text columns;
    on v5 they are TEXT columns on ``queries`` directly.
    """
    normalized = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='domain_by_id'"
    ).fetchone()
    if normalized:
        return {
            "domain": "d.domain",
            "client": "c.ip",
            "joins": (
                " LEFT JOIN domain_by_id d ON q.domain = d.id"
                " LEFT JOIN client_by_id c ON q.client = c.id"
            ),
        }
    return {"domain": "q.domain", "client": "q.client", "joins": ""}


def dns_overview(since_hours: float = 24, db_path: str | None = None) -> dict:
    """Total / blocked / allowed counts and block ratio over a time window.

    Returns ``available: False`` (with zeroed counts) if the DB is unreadable.
    """
    since = _since_ts(since_hours)
    try:
        with _open(db_path) as (conn, _):
            row = conn.execute(
                f"""
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN status IN {_BLOCKED_SQL} THEN 1 ELSE 0 END), 0) AS blocked
                FROM queries
                WHERE timestamp >= ?
                """,
                (since,),
            ).fetchone()
            clients = conn.execute(
                "SELECT COUNT(DISTINCT client) AS c FROM queries WHERE timestamp >= ?",
                (since,),
            ).fetchone()["c"]
    except PiholeUnavailable:
        return {
            "available": False,
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "block_ratio": 0.0,
            "clients": 0,
            "since_hours": since_hours,
        }

    total = row["total"] or 0
    blocked = row["blocked"] or 0
    allowed = total - blocked
    return {
        "available": True,
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "block_ratio": round(blocked / total, 4) if total else 0.0,
        "clients": clients or 0,
        "since_hours": since_hours,
    }


def top_talkers(since_hours: float = 24, limit: int = 10, db_path: str | None = None) -> list[dict]:
    """Clients ranked by query volume, with per-client blocked/allowed split."""
    since = _since_ts(since_hours)
    try:
        with _open(db_path) as (conn, s):
            rows = conn.execute(
                f"""
                SELECT {s['client']} AS client,
                       COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN q.status IN {_BLOCKED_SQL} THEN 1 ELSE 0 END), 0) AS blocked
                FROM queries q{s['joins']}
                WHERE q.timestamp >= ?
                GROUP BY {s['client']}
                ORDER BY total DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
    except PiholeUnavailable:
        return []

    talkers = []
    for r in rows:
        total = r["total"] or 0
        blocked = r["blocked"] or 0
        talkers.append({
            "client": r["client"],
            "total": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "block_ratio": round(blocked / total, 4) if total else 0.0,
        })
    return talkers


def top_domains(
    since_hours: float = 24,
    limit: int = 10,
    client: str | None = None,
    only_blocked: bool = False,
    db_path: str | None = None,
) -> list[dict]:
    """Most-queried domains overall, or for a single client.

    Args:
        client: restrict to one client IP/name (top domains per client).
        only_blocked: count only blocked queries (what is being blocked most).
    """
    since = _since_ts(since_hours)
    try:
        with _open(db_path) as (conn, s):
            where = ["q.timestamp >= ?"]
            params: list = [since]
            if client:
                where.append(f"{s['client']} = ?")
                params.append(client)
            if only_blocked:
                where.append(f"q.status IN {_BLOCKED_SQL}")
            params.append(limit)

            rows = conn.execute(
                f"""
                SELECT {s['domain']} AS domain, COUNT(*) AS count
                FROM queries q{s['joins']}
                WHERE {' AND '.join(where)}
                GROUP BY {s['domain']}
                ORDER BY count DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
    except PiholeUnavailable:
        return []

    return [{"domain": r["domain"], "count": r["count"]} for r in rows]
