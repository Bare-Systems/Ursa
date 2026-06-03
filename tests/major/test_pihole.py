"""Tests for Ursa Major Pi-hole DNS insight (ROADMAP Phase 5B).

Builds a synthetic pihole-FTL.db with the FTL v5 long-term `queries` schema,
so the aggregation logic is exercised without a real Pi-hole install.
"""

import sqlite3
import time

import pytest

from major import pihole


def _make_ftl_v5_db(path, rows):
    """FTL v5 flat schema: domain/client stored as TEXT on `queries`."""
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            type INTEGER NOT NULL,
            status INTEGER NOT NULL,
            domain TEXT NOT NULL,
            client TEXT NOT NULL,
            forward TEXT,
            additional_info TEXT
        )
        """
    )
    conn.executemany(
        "INSERT INTO queries (timestamp, type, status, domain, client) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


def _make_ftl_v6_db(path, rows):
    """FTL v6 normalized schema: domain/client are ids into lookup tables."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT)")
    conn.execute("CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT, name TEXT)")
    conn.execute(
        """
        CREATE TABLE queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            type INTEGER NOT NULL,
            status INTEGER NOT NULL,
            domain INTEGER NOT NULL,
            client INTEGER NOT NULL,
            forward INTEGER,
            additional_info TEXT
        )
        """
    )
    domain_ids, client_ids = {}, {}
    for _ts, _type, _status, domain, client in rows:
        domain_ids.setdefault(domain, len(domain_ids) + 1)
        client_ids.setdefault(client, len(client_ids) + 1)
    for domain, did in domain_ids.items():
        conn.execute("INSERT INTO domain_by_id (id, domain) VALUES (?, ?)", (did, domain))
    for client, cid in client_ids.items():
        conn.execute("INSERT INTO client_by_id (id, ip, name) VALUES (?, ?, ?)", (cid, client, None))
    conn.executemany(
        "INSERT INTO queries (timestamp, type, status, domain, client) VALUES (?, ?, ?, ?, ?)",
        [(ts, t, st, domain_ids[dom], client_ids[cl]) for (ts, t, st, dom, cl) in rows],
    )
    conn.commit()
    conn.close()


# Run every test against both FTL layouts so the schema adapter is covered.
@pytest.fixture(params=["v5", "v6"])
def ftl_db(request, tmp_path):
    """A fixture FTL DB: 2 clients, mix of allowed (2/3) and blocked (1/4/5) queries."""
    now = int(time.time())
    rows = [
        # client A — 4 queries, 2 blocked
        (now - 60, 1, 2, "github.com", "192.168.86.20"),       # allowed (forwarded)
        (now - 50, 1, 3, "github.com", "192.168.86.20"),       # allowed (cache)
        (now - 40, 1, 1, "ads.example.com", "192.168.86.20"),  # blocked (gravity)
        (now - 30, 1, 5, "tracker.example.com", "192.168.86.20"),  # blocked (blacklist)
        # client B — 2 queries, 1 blocked
        (now - 20, 1, 2, "apple.com", "192.168.86.30"),        # allowed
        (now - 10, 1, 4, "ads.example.com", "192.168.86.30"),  # blocked (regex)
        # an old query outside the default 24h window
        (now - 60 * 60 * 48, 1, 2, "old.example.com", "192.168.86.99"),
    ]
    db_file = tmp_path / "pihole-FTL.db"
    builder = _make_ftl_v5_db if request.param == "v5" else _make_ftl_v6_db
    builder(db_file, rows)
    return str(db_file)


def test_overview_counts_and_block_ratio(ftl_db):
    ov = pihole.dns_overview(since_hours=24, db_path=ftl_db)
    assert ov["available"] is True
    assert ov["total"] == 6          # the 48h-old query is excluded
    assert ov["blocked"] == 3        # statuses 1, 5, 4
    assert ov["allowed"] == 3
    assert ov["block_ratio"] == 0.5
    assert ov["clients"] == 2


def test_top_talkers_ranked_with_split(ftl_db):
    talkers = pihole.top_talkers(since_hours=24, limit=10, db_path=ftl_db)
    assert [t["client"] for t in talkers] == ["192.168.86.20", "192.168.86.30"]
    a = talkers[0]
    assert a["total"] == 4
    assert a["blocked"] == 2
    assert a["allowed"] == 2
    assert a["block_ratio"] == 0.5


def test_top_domains_overall(ftl_db):
    domains = pihole.top_domains(since_hours=24, limit=10, db_path=ftl_db)
    by_name = {d["domain"]: d["count"] for d in domains}
    assert by_name["ads.example.com"] == 2  # queried by both clients
    assert by_name["github.com"] == 2


def test_top_domains_for_one_client(ftl_db):
    domains = pihole.top_domains(since_hours=24, client="192.168.86.30", db_path=ftl_db)
    names = {d["domain"] for d in domains}
    assert names == {"apple.com", "ads.example.com"}


def test_top_domains_only_blocked(ftl_db):
    domains = pihole.top_domains(since_hours=24, only_blocked=True, db_path=ftl_db)
    names = {d["domain"] for d in domains}
    assert "ads.example.com" in names
    assert "github.com" not in names      # github was allowed
    assert "apple.com" not in names


def test_missing_db_degrades_gracefully(tmp_path):
    missing = str(tmp_path / "does-not-exist.db")
    ov = pihole.dns_overview(db_path=missing)
    assert ov["available"] is False
    assert ov["total"] == 0
    assert pihole.top_talkers(db_path=missing) == []
    assert pihole.top_domains(db_path=missing) == []


def test_unconfigured_db_path_degrades_gracefully():
    ov = pihole.dns_overview(db_path="")  # empty path, no config fallback in test
    # Falls through to config; if config has the default path it won't exist in CI,
    # so availability must be False either way.
    assert ov["available"] is False
