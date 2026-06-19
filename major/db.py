#!/usr/bin/env python3
"""
Ursa Major — Database Layer
============================
SQLite-backed storage for sessions, tasks, and results.
"""

import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from major.config import get_config


def _db_path() -> Path:
    """Resolve the active database path from the current config."""
    return Path(get_config().get("major.db_path"))


def get_db():
    """Get a database connection with WAL mode for concurrent access."""
    db = sqlite3.connect(str(_db_path()), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db():
    """Create all tables if they don't exist."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            remote_ip TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            username TEXT DEFAULT '',
            os TEXT DEFAULT '',
            arch TEXT DEFAULT '',
            pid INTEGER DEFAULT 0,
            process_name TEXT DEFAULT '',
            campaign TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            beacon_interval INTEGER DEFAULT 5,
            jitter REAL DEFAULT 0.1,
            status TEXT DEFAULT 'active',
            encryption_key TEXT DEFAULT '',
            metadata TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            args TEXT DEFAULT '{}',
            status TEXT DEFAULT 'pending',
            created_at REAL NOT NULL,
            picked_up_at REAL,
            completed_at REAL,
            result TEXT DEFAULT '',
            error TEXT DEFAULT '',
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            direction TEXT NOT NULL,
            size INTEGER DEFAULT 0,
            data BLOB,
            created_at REAL NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS listeners (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            bind_host TEXT DEFAULT '0.0.0.0',
            bind_port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'http',
            status TEXT DEFAULT 'stopped',
            created_at REAL NOT NULL,
            config TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            level TEXT DEFAULT 'info',
            source TEXT DEFAULT '',
            message TEXT NOT NULL,
            session_id TEXT,
            details TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS approval_requests (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            session_id TEXT,
            task_type TEXT DEFAULT '',
            args TEXT DEFAULT '{}',
            requested_by TEXT NOT NULL,
            reason TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            created_at REAL NOT NULL,
            decided_at REAL,
            decided_by TEXT,
            decision_note TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS immutable_audit (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            session_id TEXT,
            task_id TEXT,
            approval_id TEXT,
            risk_level TEXT DEFAULT 'unknown',
            policy_result TEXT DEFAULT 'unknown',
            details TEXT DEFAULT '{}',
            prev_hash TEXT DEFAULT '',
            event_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS campaign_policies (
            campaign TEXT PRIMARY KEY,
            max_pending_total INTEGER DEFAULT 20,
            max_pending_high INTEGER DEFAULT 10,
            max_pending_critical INTEGER DEFAULT 2,
            max_oldest_pending_minutes INTEGER DEFAULT 60,
            updated_at REAL NOT NULL,
            updated_by TEXT DEFAULT 'operator',
            note TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS campaign_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign TEXT NOT NULL,
            created_at REAL NOT NULL,
            author TEXT DEFAULT 'operator',
            note TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS campaign_checklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            title TEXT NOT NULL,
            details TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            owner TEXT DEFAULT '',
            due_at REAL
        );

        CREATE TABLE IF NOT EXISTS campaign_checklist_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            campaign TEXT NOT NULL,
            created_at REAL NOT NULL,
            actor TEXT DEFAULT 'system',
            action TEXT NOT NULL,
            title TEXT DEFAULT '',
            prev_status TEXT DEFAULT '',
            new_status TEXT DEFAULT '',
            details TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS campaign_playbooks (
            name TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            description TEXT DEFAULT '',
            items_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operator',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            last_login_at REAL
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
        CREATE INDEX IF NOT EXISTS idx_events_session ON event_log(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON event_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
        CREATE INDEX IF NOT EXISTS idx_approvals_created_at ON approval_requests(created_at);
        CREATE INDEX IF NOT EXISTS idx_immutable_timestamp ON immutable_audit(timestamp);
        CREATE INDEX IF NOT EXISTS idx_policy_updated_at ON campaign_policies(updated_at);
        CREATE INDEX IF NOT EXISTS idx_campaign_notes_campaign ON campaign_notes(campaign);
        CREATE INDEX IF NOT EXISTS idx_campaign_notes_created_at ON campaign_notes(created_at);
        CREATE INDEX IF NOT EXISTS idx_campaign_checklist_campaign ON campaign_checklist(campaign);
        CREATE INDEX IF NOT EXISTS idx_campaign_checklist_status ON campaign_checklist(status);
        CREATE INDEX IF NOT EXISTS idx_campaign_checklist_history_campaign
            ON campaign_checklist_history(campaign);
        CREATE INDEX IF NOT EXISTS idx_campaign_checklist_history_created_at
            ON campaign_checklist_history(created_at);
        CREATE INDEX IF NOT EXISTS idx_campaign_playbooks_updated_at
            ON campaign_playbooks(updated_at);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_devices (
            mac TEXT PRIMARY KEY,
            ip TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            label TEXT DEFAULT '',
            trusted INTEGER NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS network_scans (
            id TEXT PRIMARY KEY,
            started_at REAL NOT NULL,
            source TEXT DEFAULT '',
            target_range TEXT DEFAULT '',
            device_count INTEGER NOT NULL DEFAULT 0,
            new_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_network_devices_trusted ON network_devices(trusted);
        CREATE INDEX IF NOT EXISTS idx_network_devices_last_seen ON network_devices(last_seen);
        CREATE INDEX IF NOT EXISTS idx_network_scans_started_at ON network_scans(started_at);
    """)
    _ensure_sessions_columns(db)
    _ensure_campaign_policy_columns(db)
    _ensure_default_campaign_playbooks(db)
    _ensure_users_columns(db)
    _ensure_default_admin_user(db)
    db.commit()
    db.close()


# ── Session Operations ──


def create_session(remote_ip, hostname="", username="", os_info="",
                   arch="", pid=0, process_name="", encryption_key="",
                   beacon_interval=5, jitter=0.1, campaign="", tags=""):
    """Register a new implant session."""
    db = get_db()
    session_id = str(uuid.uuid4())[:8]
    now = time.time()
    db.execute("""
        INSERT INTO sessions (id, remote_ip, hostname, username, os, arch,
                             pid, process_name, campaign, tags, first_seen, last_seen,
                             beacon_interval, jitter, encryption_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, remote_ip, hostname, username, os_info, arch,
          pid, process_name, campaign, tags, now, now, beacon_interval, jitter, encryption_key))
    db.commit()
    db.close()
    log_event("info", "session", f"New session {session_id} from {remote_ip} ({username}@{hostname})",
              session_id=session_id)
    return session_id


def update_session_checkin(session_id, remote_ip=None):
    """Update last_seen timestamp for a session heartbeat."""
    db = get_db()
    if remote_ip:
        db.execute("UPDATE sessions SET last_seen=?, remote_ip=? WHERE id=?",
                   (time.time(), remote_ip, session_id))
    else:
        db.execute("UPDATE sessions SET last_seen=? WHERE id=?",
                   (time.time(), session_id))
    db.commit()
    db.close()


def get_session(session_id):
    """Get a single session by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_sessions(status=None, campaign=None, tag=None):
    """List all sessions, optionally filtered by status/campaign/tag."""
    db = get_db()
    query = "SELECT * FROM sessions WHERE 1=1"
    params = []
    if status:
        query += " AND status=?"
        params.append(status)
    if campaign:
        query += " AND campaign=?"
        params.append(campaign)
    if tag:
        query += " AND tags LIKE ?"
        params.append(f"%{tag}%")
    query += " ORDER BY last_seen DESC"
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


def kill_session(session_id):
    """Mark a session as dead."""
    db = get_db()
    db.execute("UPDATE sessions SET status='dead' WHERE id=?", (session_id,))
    db.commit()
    db.close()
    log_event("info", "session", f"Session {session_id} marked as dead",
              session_id=session_id)


def update_session_info(session_id, **kwargs):
    """Update session metadata fields."""
    db = get_db()
    allowed = {"hostname", "username", "os", "arch", "pid", "process_name",
               "campaign", "tags", "beacon_interval", "jitter", "status", "metadata"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [session_id]
        db.execute(f"UPDATE sessions SET {set_clause} WHERE id=?", values)
        db.commit()
    db.close()


# ── Task Operations ──


def create_task(session_id, task_type, args=None):
    """Queue a new task for a session."""
    db = get_db()
    task_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO tasks (id, session_id, task_type, args, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
    """, (task_id, session_id, task_type, json.dumps(args or {}), time.time()))
    db.commit()
    db.close()
    log_event("info", "task", f"Task {task_id} ({task_type}) queued for session {session_id}",
              session_id=session_id)
    return task_id


def get_pending_tasks(session_id):
    """Get all pending tasks for a session and mark them as picked up."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM tasks WHERE session_id=? AND status='pending'
        ORDER BY created_at ASC
    """, (session_id,)).fetchall()

    task_ids = [r["id"] for r in rows]
    if task_ids:
        placeholders = ",".join("?" * len(task_ids))
        db.execute(f"""
            UPDATE tasks SET status='in_progress', picked_up_at=?
            WHERE id IN ({placeholders})
        """, [time.time()] + task_ids)
        db.commit()

    db.close()
    return [dict(r) for r in rows]


def complete_task(task_id, result="", error=""):
    """Mark a task as completed with results."""
    db = get_db()
    status = "error" if error else "completed"
    db.execute("""
        UPDATE tasks SET status=?, completed_at=?, result=?, error=?
        WHERE id=?
    """, (status, time.time(), result, error, task_id))
    db.commit()
    db.close()


def get_task(task_id):
    """Get a single task by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_tasks(session_id=None, status=None, campaign=None, tag=None, limit=50):
    """List tasks, optionally filtered by session/status/campaign/tag."""
    db = get_db()
    query = """
        SELECT t.*, s.campaign AS campaign, s.tags AS session_tags
        FROM tasks t
        LEFT JOIN sessions s ON s.id = t.session_id
        WHERE 1=1
    """
    params = []
    if session_id:
        query += " AND t.session_id=?"
        params.append(session_id)
    if status:
        query += " AND t.status=?"
        params.append(status)
    if campaign:
        query += " AND s.campaign=?"
        params.append(campaign)
    if tag:
        query += " AND s.tags LIKE ?"
        params.append(f"%{tag}%")
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ── File Operations ──


def store_file(session_id, filename, data, direction="download"):
    """Store a file transferred to/from an implant."""
    db = get_db()
    file_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO files (id, session_id, filename, direction, size, data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (file_id, session_id, filename, direction, len(data), data, time.time()))
    db.commit()
    db.close()
    log_event("info", "file", f"File {filename} ({len(data)}B) {direction} via session {session_id}",
              session_id=session_id)
    return file_id


def get_file(file_id):
    """Retrieve a stored file."""
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_files(session_id=None):
    """List stored files."""
    db = get_db()
    if session_id:
        rows = db.execute("SELECT id, session_id, filename, direction, size, created_at FROM files WHERE session_id=? ORDER BY created_at DESC",
                         (session_id,)).fetchall()
    else:
        rows = db.execute("SELECT id, session_id, filename, direction, size, created_at FROM files ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


# ── Listener Operations ──


def create_listener(name, bind_port, bind_host="0.0.0.0", protocol="http", config=None):
    """Register a new listener."""
    db = get_db()
    listener_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO listeners (id, name, bind_host, bind_port, protocol, status, created_at, config)
        VALUES (?, ?, ?, ?, ?, 'stopped', ?, ?)
    """, (listener_id, name, bind_host, bind_port, protocol, time.time(),
          json.dumps(config or {})))
    db.commit()
    db.close()
    return listener_id


def update_listener_status(listener_id, status):
    """Update listener status."""
    db = get_db()
    db.execute("UPDATE listeners SET status=? WHERE id=?", (status, listener_id))
    db.commit()
    db.close()


def list_listeners():
    """List all listeners."""
    db = get_db()
    rows = db.execute("SELECT * FROM listeners ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_listener(listener_id=None, name=None):
    """Get a listener by ID or name."""
    db = get_db()
    if listener_id:
        row = db.execute("SELECT * FROM listeners WHERE id=?", (listener_id,)).fetchone()
    elif name:
        row = db.execute("SELECT * FROM listeners WHERE name=?", (name,)).fetchone()
    else:
        row = None
    db.close()
    return dict(row) if row else None


# ── Event Log ──


def log_event(level, source, message, session_id=None, details=None):
    """Log an event to the event log."""
    db = get_db()
    db.execute("""
        INSERT INTO event_log (timestamp, level, source, message, session_id, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (time.time(), level, source, message, session_id, json.dumps(details or {})))
    db.commit()
    db.close()


def get_events(limit=100, level=None, session_id=None, campaign=None, tag=None):
    """Retrieve recent events, optionally filtered by campaign/tag."""
    db = get_db()
    query = """
        SELECT e.*, s.campaign AS campaign, s.tags AS session_tags
        FROM event_log e
        LEFT JOIN sessions s ON s.id = e.session_id
        WHERE 1=1
    """
    params = []
    if level:
        query += " AND e.level=?"
        params.append(level)
    if session_id:
        query += " AND e.session_id=?"
        params.append(session_id)
    if campaign:
        query += " AND s.campaign=?"
        params.append(campaign)
    if tag:
        query += " AND s.tags LIKE ?"
        params.append(f"%{tag}%")
    query += " ORDER BY e.timestamp DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ── Governance ──


def create_approval_request(
    action,
    risk_level,
    session_id=None,
    task_type="",
    args=None,
    requested_by="operator",
    reason="",
):
    """Create a pending step-up approval request."""
    db = get_db()
    approval_id = str(uuid.uuid4())[:8]
    db.execute("""
        INSERT INTO approval_requests (
            id, action, risk_level, session_id, task_type, args,
            requested_by, reason, status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
    """, (
        approval_id,
        action,
        risk_level,
        session_id,
        task_type,
        json.dumps(args or {}),
        requested_by,
        reason,
        time.time(),
    ))
    db.commit()
    db.close()
    log_event(
        "warning",
        "governance",
        f"Approval request {approval_id} created for {action} ({risk_level})",
        session_id=session_id,
        details={"approval_id": approval_id, "task_type": task_type, "risk_level": risk_level},
    )
    return approval_id


def get_approval_request(approval_id):
    """Get one approval request by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM approval_requests WHERE id=?", (approval_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_approval_requests(status=None, campaign=None, tag=None, risk_level=None, limit=50):
    """List approval requests, optionally filtered by status/campaign/tag/risk."""
    db = get_db()
    query = """
        SELECT a.*, s.campaign AS campaign, s.tags AS session_tags
        FROM approval_requests a
        LEFT JOIN sessions s ON s.id = a.session_id
        WHERE 1=1
    """
    params = []
    if status:
        query += " AND a.status=?"
        params.append(status)
    if campaign:
        query += " AND s.campaign=?"
        params.append(campaign)
    if tag:
        query += " AND s.tags LIKE ?"
        params.append(f"%{tag}%")
    if risk_level:
        query += " AND a.risk_level=?"
        params.append(risk_level)
    query += " ORDER BY a.created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


def resolve_approval_request(approval_id, approved, decided_by="operator", note=""):
    """Approve or reject an approval request."""
    status = "approved" if approved else "rejected"
    db = get_db()
    db.execute("""
        UPDATE approval_requests
        SET status=?, decided_at=?, decided_by=?, decision_note=?
        WHERE id=? AND status='pending'
    """, (status, time.time(), decided_by, note, approval_id))
    changed = db.total_changes
    db.commit()
    db.close()
    if changed:
        req = get_approval_request(approval_id)
        if req:
            log_event(
                "info",
                "governance",
                f"Approval {approval_id} {status} by {decided_by}",
                session_id=req.get("session_id"),
                details={"approval_id": approval_id, "status": status, "note": note},
            )
        return True
    return False


def _compute_event_hash(prev_hash, payload):
    raw = f"{prev_hash}|{json.dumps(payload, sort_keys=True, separators=(',', ':'))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _ensure_sessions_columns(db):
    """Best-effort migration for sessions table additive columns."""
    columns = {r[1] for r in db.execute("PRAGMA table_info(sessions)").fetchall()}
    if "campaign" not in columns:
        db.execute("ALTER TABLE sessions ADD COLUMN campaign TEXT DEFAULT ''")
    if "tags" not in columns:
        db.execute("ALTER TABLE sessions ADD COLUMN tags TEXT DEFAULT ''")


def _ensure_campaign_policy_columns(db):
    """Best-effort migration for campaign policy additive columns."""
    columns = {r[1] for r in db.execute("PRAGMA table_info(campaign_policies)").fetchall()}
    if "max_oldest_pending_minutes" not in columns:
        db.execute(
            "ALTER TABLE campaign_policies ADD COLUMN max_oldest_pending_minutes INTEGER DEFAULT 60"
        )


def _ensure_users_columns(db):
    """Best-effort migration for users table additive columns."""
    columns = {r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'operator'")
    if "is_active" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    if "last_login_at" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN last_login_at REAL")


def _ensure_default_campaign_playbooks(db):
    """Seed baseline playbooks when none are configured."""
    existing = db.execute("SELECT COUNT(*) AS n FROM campaign_playbooks").fetchone()
    if existing and int(existing["n"]) > 0:
        return
    now = time.time()
    defaults = [
        (
            "initial-access",
            "Baseline foothold and validation sequence.",
            [
                {"title": "Validate beacon stability", "details": "Confirm consistent check-ins", "due_offset_days": 0},
                {"title": "Collect host baseline", "details": "Hostname, user, domain, AV posture", "due_offset_days": 0},
                {"title": "Establish operator notes", "details": "Capture mission context and goals", "due_offset_days": 0},
            ],
        ),
        (
            "lateral-movement",
            "Prepare for lateral movement execution.",
            [
                {"title": "Enumerate reachable hosts", "details": "SMB/RDP/WinRM pathways", "due_offset_days": 1},
                {"title": "Map credential options", "details": "Token, hash, and delegated auth paths", "due_offset_days": 1},
                {"title": "Define rollback trigger", "details": "Conditions to halt movement safely", "due_offset_days": 2},
            ],
        ),
        (
            "cleanup-handoff",
            "End-of-operation cleanup and handoff.",
            [
                {"title": "Purge temporary artifacts", "details": "Remove dropped binaries/scripts", "due_offset_days": 0},
                {"title": "Archive campaign evidence", "details": "Export handoff + governance reports", "due_offset_days": 0},
                {"title": "Write final handoff note", "details": "Known risks, gaps, and next actions", "due_offset_days": 0},
            ],
        ),
    ]
    for name, description, items in defaults:
        db.execute(
            """
            INSERT OR IGNORE INTO campaign_playbooks (name, created_at, updated_at, description, items_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, now, now, description, json.dumps(items)),
        )


def _ensure_default_admin_user(db):
    """Create one bootstrap admin user if no users exist."""
    existing = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    if existing and int(existing["n"]) > 0:
        return
    cfg = get_config()
    username = str(cfg.get("major.web.auth.bootstrap_username", "admin")).strip() or "admin"
    password = str(cfg.get("major.web.auth.bootstrap_password", "change-me-now"))
    role = str(cfg.get("major.web.auth.bootstrap_role", "admin")).strip().lower() or "admin"
    now = time.time()
    db.execute(
        """
        INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, 1, ?, ?)
        """,
        (username, hash_password(password), role, now, now),
    )


def append_immutable_audit_event(
    *,
    actor,
    action,
    session_id=None,
    task_id=None,
    approval_id=None,
    risk_level="unknown",
    policy_result="unknown",
    details=None,
):
    """Append an immutable, hash-chained audit event."""
    db = get_db()
    event_id = str(uuid.uuid4())[:12]
    ts = time.time()

    prev = db.execute("""
        SELECT event_hash FROM immutable_audit
        ORDER BY timestamp DESC, id DESC
        LIMIT 1
    """).fetchone()
    prev_hash = prev["event_hash"] if prev else ""

    payload = {
        "id": event_id,
        "timestamp": ts,
        "actor": actor,
        "action": action,
        "session_id": session_id,
        "task_id": task_id,
        "approval_id": approval_id,
        "risk_level": risk_level,
        "policy_result": policy_result,
        "details": details or {},
    }
    event_hash = _compute_event_hash(prev_hash, payload)

    db.execute("""
        INSERT INTO immutable_audit (
            id, timestamp, actor, action, session_id, task_id, approval_id,
            risk_level, policy_result, details, prev_hash, event_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_id,
        ts,
        actor,
        action,
        session_id,
        task_id,
        approval_id,
        risk_level,
        policy_result,
        json.dumps(details or {}),
        prev_hash,
        event_hash,
    ))
    db.commit()
    db.close()
    return event_id


def get_immutable_audit(limit=200):
    """Retrieve immutable audit events in reverse chronological order."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM immutable_audit
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


def verify_immutable_audit_chain():
    """Verify hash integrity of all immutable audit events."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM immutable_audit
        ORDER BY timestamp ASC, id ASC
    """).fetchall()
    db.close()

    prev_hash = ""
    checked = 0
    for row in rows:
        payload = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "actor": row["actor"],
            "action": row["action"],
            "session_id": row["session_id"],
            "task_id": row["task_id"],
            "approval_id": row["approval_id"],
            "risk_level": row["risk_level"],
            "policy_result": row["policy_result"],
            "details": json.loads(row["details"] or "{}"),
        }
        expected_hash = _compute_event_hash(prev_hash, payload)
        if row["prev_hash"] != prev_hash or row["event_hash"] != expected_hash:
            return {"ok": False, "checked": checked, "failed_event": row["id"]}
        prev_hash = row["event_hash"]
        checked += 1
    return {"ok": True, "checked": checked}


def upsert_campaign_policy(
    campaign,
    max_pending_total=20,
    max_pending_high=10,
    max_pending_critical=2,
    max_oldest_pending_minutes=60,
    updated_by="operator",
    note="",
):
    """Create or update a campaign governance policy threshold set."""
    db = get_db()
    db.execute(
        """
        INSERT INTO campaign_policies (
            campaign, max_pending_total, max_pending_high, max_pending_critical, max_oldest_pending_minutes,
            updated_at, updated_by, note
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(campaign) DO UPDATE SET
            max_pending_total=excluded.max_pending_total,
            max_pending_high=excluded.max_pending_high,
            max_pending_critical=excluded.max_pending_critical,
            max_oldest_pending_minutes=excluded.max_oldest_pending_minutes,
            updated_at=excluded.updated_at,
            updated_by=excluded.updated_by,
            note=excluded.note
        """,
        (
            campaign,
            max_pending_total,
            max_pending_high,
            max_pending_critical,
            max_oldest_pending_minutes,
            time.time(),
            updated_by,
            note,
        ),
    )
    db.commit()
    db.close()
    return get_campaign_policy(campaign)


def get_campaign_policy(campaign):
    """Fetch one campaign policy."""
    db = get_db()
    row = db.execute("SELECT * FROM campaign_policies WHERE campaign=?", (campaign,)).fetchone()
    db.close()
    return dict(row) if row else None


def list_campaign_policies():
    """List all campaign policies."""
    db = get_db()
    rows = db.execute("SELECT * FROM campaign_policies ORDER BY campaign ASC").fetchall()
    db.close()
    return [dict(r) for r in rows]


def delete_campaign_policy(campaign):
    """Delete a campaign policy by campaign name."""
    db = get_db()
    db.execute("DELETE FROM campaign_policies WHERE campaign=?", (campaign,))
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def evaluate_campaign_policy_alerts(campaign=None):
    """Evaluate policy threshold breaches for pending approvals."""
    policies = list_campaign_policies()
    if campaign:
        policies = [p for p in policies if p["campaign"] == campaign]
    if not policies:
        return []

    pending = list_approval_requests(status="pending", limit=10000)
    counts: dict[str, dict[str, float]] = {}
    now = time.time()
    for row in pending:
        name = (row.get("campaign") or "unassigned").strip() or "unassigned"
        info = counts.setdefault(name, {"total": 0, "high": 0, "critical": 0, "oldest_age_minutes": 0.0})
        info["total"] += 1
        risk = (row.get("risk_level") or "").lower()
        if risk == "high":
            info["high"] += 1
        elif risk == "critical":
            info["critical"] += 1
        age_minutes = max(0.0, (now - float(row.get("created_at") or now)) / 60.0)
        if age_minutes > info["oldest_age_minutes"]:
            info["oldest_age_minutes"] = age_minutes

    alerts = []
    for policy in policies:
        name = policy["campaign"]
        c = counts.get(name, {"total": 0, "high": 0, "critical": 0, "oldest_age_minutes": 0.0})
        checks = [
            ("total", c["total"], int(policy["max_pending_total"]), "warning"),
            ("high", c["high"], int(policy["max_pending_high"]), "warning"),
            ("critical", c["critical"], int(policy["max_pending_critical"]), "critical"),
            (
                "oldest_age_minutes",
                int(c["oldest_age_minutes"]),
                int(policy["max_oldest_pending_minutes"]),
                "warning",
            ),
        ]
        for metric, value, threshold, severity in checks:
            if value > threshold:
                alerts.append(
                    {
                        "campaign": name,
                        "metric": metric,
                        "value": value,
                        "threshold": threshold,
                        "severity": severity,
                    }
                )
    return alerts


def get_campaign_timeline(campaign, limit=200):
    """Unified timeline for a campaign across events, tasks, and approvals."""
    db = get_db()
    rows = db.execute(
        """
        SELECT * FROM (
            SELECT
                e.timestamp AS ts,
                'event' AS kind,
                CAST(e.id AS TEXT) AS ref_id,
                e.session_id AS session_id,
                e.level AS severity,
                e.source || ': ' || e.message AS summary
            FROM event_log e
            LEFT JOIN sessions s ON s.id = e.session_id
            WHERE s.campaign=?

            UNION ALL

            SELECT
                t.created_at AS ts,
                'task' AS kind,
                t.id AS ref_id,
                t.session_id AS session_id,
                t.status AS severity,
                t.task_type AS summary
            FROM tasks t
            LEFT JOIN sessions s ON s.id = t.session_id
            WHERE s.campaign=?

            UNION ALL

            SELECT
                a.created_at AS ts,
                'approval' AS kind,
                a.id AS ref_id,
                a.session_id AS session_id,
                a.risk_level AS severity,
                a.action AS summary
            FROM approval_requests a
            LEFT JOIN sessions s ON s.id = a.session_id
            WHERE s.campaign=?

            UNION ALL

            SELECT
                n.created_at AS ts,
                'note' AS kind,
                CAST(n.id AS TEXT) AS ref_id,
                NULL AS session_id,
                n.author AS severity,
                n.note AS summary
            FROM campaign_notes n
            WHERE n.campaign=?

            UNION ALL

            SELECT
                h.created_at AS ts,
                'checklist' AS kind,
                CAST(h.item_id AS TEXT) AS ref_id,
                NULL AS session_id,
                COALESCE(NULLIF(h.new_status, ''), h.action) AS severity,
                h.action || ': ' || h.title AS summary
            FROM campaign_checklist_history h
            WHERE h.campaign=?
        )
        ORDER BY ts DESC
        LIMIT ?
        """,
        (campaign, campaign, campaign, campaign, campaign, limit),
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def add_campaign_note(campaign, note, author="operator"):
    """Append an operator note to a campaign timeline."""
    db = get_db()
    db.execute(
        """
        INSERT INTO campaign_notes (campaign, created_at, author, note)
        VALUES (?, ?, ?, ?)
        """,
        (campaign, time.time(), author, note),
    )
    db.commit()
    db.close()


def list_campaign_notes(campaign=None, limit=100):
    """List campaign notes, optionally filtered by campaign."""
    db = get_db()
    if campaign:
        rows = db.execute(
            """
            SELECT * FROM campaign_notes
            WHERE campaign=?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (campaign, limit),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT * FROM campaign_notes
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def delete_campaign_note(note_id):
    """Delete one campaign note by ID."""
    db = get_db()
    db.execute("DELETE FROM campaign_notes WHERE id=?", (note_id,))
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def add_campaign_checklist_item(
    campaign,
    title,
    details="",
    owner="",
    due_at=None,
    actor="system",
):
    """Create checklist item for a campaign."""
    db = get_db()
    now = time.time()
    db.execute(
        """
        INSERT INTO campaign_checklist (campaign, created_at, updated_at, title, details, status, owner, due_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (campaign, now, now, title, details, owner, due_at),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    _record_campaign_checklist_history(
        db,
        item_id=item_id,
        campaign=campaign,
        actor=actor,
        action="created",
        title=title,
        new_status="pending",
        details={"owner": owner, "due_at": due_at, "details": details},
    )
    db.commit()
    db.close()
    return int(item_id)


def list_campaign_checklist(campaign=None, status=None, owner=None, text=None, sort="created_desc", limit=200):
    """List checklist items with optional campaign/status/owner/text filters."""
    db = get_db()
    sql = "SELECT * FROM campaign_checklist WHERE 1=1"
    params = []
    if campaign:
        sql += " AND campaign=?"
        params.append(campaign)
    if status:
        sql += " AND status=?"
        params.append(status)
    if owner:
        sql += " AND owner LIKE ?"
        params.append(f"%{owner}%")
    if text:
        sql += " AND (title LIKE ? OR details LIKE ?)"
        pattern = f"%{text}%"
        params.extend([pattern, pattern])

    order_by = {
        "created_desc": "created_at DESC",
        "created_asc": "created_at ASC",
        "updated_desc": "updated_at DESC",
        "updated_asc": "updated_at ASC",
        "due_asc": "CASE WHEN due_at IS NULL THEN 1 ELSE 0 END, due_at ASC, created_at DESC",
        "due_desc": "CASE WHEN due_at IS NULL THEN 1 ELSE 0 END, due_at DESC, created_at DESC",
    }.get(sort, "created_at DESC")

    sql += f" ORDER BY {order_by} LIMIT ?"
    params.append(limit)
    rows = db.execute(sql, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


def update_campaign_checklist_item(item_id, actor="system", **kwargs):
    """Update checklist item fields."""
    allowed = {"title", "details", "status", "owner", "due_at"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return False
    updates["updated_at"] = time.time()

    db = get_db()
    row = db.execute("SELECT * FROM campaign_checklist WHERE id=?", (item_id,)).fetchone()
    if not row:
        db.close()
        return False
    before = dict(row)
    set_clause = ", ".join(f"{k}=?" for k in updates)
    params = list(updates.values()) + [item_id]
    db.execute(f"UPDATE campaign_checklist SET {set_clause} WHERE id=?", params)
    changed = db.total_changes
    if changed > 0:
        after = {**before, **updates}
        changed_fields = [key for key in ("title", "details", "status", "owner", "due_at") if key in updates]
        action = "updated"
        if "status" in updates and updates["status"] != before.get("status"):
            action = "status_changed"
        _record_campaign_checklist_history(
            db,
            item_id=item_id,
            campaign=before["campaign"],
            actor=actor,
            action=action,
            title=str(after.get("title") or ""),
            prev_status=str(before.get("status") or ""),
            new_status=str(after.get("status") or ""),
            details={"changed_fields": changed_fields},
        )
    db.commit()
    db.close()
    return changed > 0


def delete_campaign_checklist_item(item_id, actor="system"):
    """Delete checklist item."""
    db = get_db()
    row = db.execute("SELECT * FROM campaign_checklist WHERE id=?", (item_id,)).fetchone()
    if not row:
        db.close()
        return False
    item = dict(row)
    _record_campaign_checklist_history(
        db,
        item_id=item_id,
        campaign=item["campaign"],
        actor=actor,
        action="deleted",
        title=str(item.get("title") or ""),
        prev_status=str(item.get("status") or ""),
        details={"owner": item.get("owner") or ""},
    )
    db.execute("DELETE FROM campaign_checklist WHERE id=?", (item_id,))
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def list_campaign_checklist_history(campaign, action=None, item_id=None, limit=200):
    """List checklist history events for a campaign."""
    db = get_db()
    query = """
        SELECT * FROM campaign_checklist_history
        WHERE campaign=?
    """
    params = [campaign]
    if action:
        query += " AND action=?"
        params.append(action)
    if item_id is not None:
        query += " AND item_id=?"
        params.append(item_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(
        query,
        params,
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def upsert_campaign_playbook(name, items, description=""):
    """Create or update a reusable checklist playbook."""
    playbook = name.strip()
    if not playbook:
        raise ValueError("Playbook name is required")
    if not isinstance(items, list) or not items:
        raise ValueError("Playbook items must be a non-empty list")

    normalized = []
    for item in items:
        if isinstance(item, str):
            title = item.strip()
            if not title:
                continue
            normalized.append({"title": title, "details": "", "owner": "", "due_offset_days": None})
            continue
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        due_offset = item.get("due_offset_days")
        try:
            due_offset = int(due_offset) if due_offset is not None else None
        except (TypeError, ValueError):
            due_offset = None
        normalized.append(
            {
                "title": title,
                "details": str(item.get("details", "")).strip(),
                "owner": str(item.get("owner", "")).strip(),
                "due_offset_days": due_offset,  # type: ignore[dict-item]
            }
        )
    if not normalized:
        raise ValueError("Playbook items must include at least one valid title")

    now = time.time()
    db = get_db()
    db.execute(
        """
        INSERT INTO campaign_playbooks (name, created_at, updated_at, description, items_json)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            updated_at=excluded.updated_at,
            description=excluded.description,
            items_json=excluded.items_json
        """,
        (playbook, now, now, description.strip(), json.dumps(normalized)),
    )
    db.commit()
    db.close()
    return get_campaign_playbook(playbook)


def get_campaign_playbook(name):
    """Fetch one playbook by name."""
    db = get_db()
    row = db.execute("SELECT * FROM campaign_playbooks WHERE name=?", (name,)).fetchone()
    db.close()
    if not row:
        return None
    payload = dict(row)
    try:
        payload["items"] = json.loads(payload.pop("items_json") or "[]")
    except json.JSONDecodeError:
        payload["items"] = []
    return payload


def list_campaign_playbooks(limit=100):
    """List all campaign playbooks."""
    db = get_db()
    rows = db.execute(
        """
        SELECT * FROM campaign_playbooks
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    db.close()
    items = []
    for row in rows:
        payload = dict(row)
        try:
            parsed = json.loads(payload.pop("items_json") or "[]")
        except json.JSONDecodeError:
            parsed = []
        payload["items"] = parsed
        items.append(payload)
    return items


def delete_campaign_playbook(name):
    """Delete a campaign playbook by name."""
    db = get_db()
    db.execute("DELETE FROM campaign_playbooks WHERE name=?", (name,))
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def apply_campaign_playbook(campaign, playbook_name, default_owner="", due_base=None, skip_existing=True):
    """Apply a playbook to a campaign by creating checklist items."""
    book = get_campaign_playbook(playbook_name)
    if not book:
        return {"created": 0, "skipped": 0, "total": 0, "missing": True}

    due_anchor = float(due_base) if due_base is not None else time.time()
    existing = set()
    if skip_existing:
        for row in list_campaign_checklist(campaign=campaign, limit=5000):
            existing.add((row.get("title") or "").strip().lower())

    created = 0
    skipped = 0
    for item in book["items"]:
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        key = title.lower()
        if skip_existing and key in existing:
            skipped += 1
            continue
        owner = str(item.get("owner", "")).strip() or default_owner.strip()
        due_at = None
        offset = item.get("due_offset_days")
        if offset is not None:
            try:
                due_at = due_anchor + int(offset) * 86400
            except (TypeError, ValueError):
                due_at = None
        add_campaign_checklist_item(
            campaign=campaign,
            title=title,
            details=str(item.get("details", "")).strip(),
            owner=owner,
            due_at=due_at,
        )
        created += 1
        existing.add(key)
    return {"created": created, "skipped": skipped, "total": len(book["items"]), "missing": False}


def snapshot_campaign_checklist_to_playbook(
    campaign,
    playbook_name,
    description="",
    only_open=True,
):
    """Create/update a playbook from the campaign's current checklist."""
    rows = list_campaign_checklist(campaign=campaign, limit=5000)
    if only_open:
        rows = [row for row in rows if row.get("status") != "done"]
    items = []
    for row in rows:
        items.append(
            {
                "title": str(row.get("title") or "").strip(),
                "details": str(row.get("details") or "").strip(),
                "owner": str(row.get("owner") or "").strip(),
                "due_offset_days": None,
            }
        )
    if not items:
        raise ValueError("No checklist items available to snapshot")
    return upsert_campaign_playbook(
        playbook_name,
        items=items,
        description=description.strip() or f"Snapshot from campaign {campaign}",
    )


def _record_campaign_checklist_history(
    db,
    item_id,
    campaign,
    action,
    title="",
    prev_status="",
    new_status="",
    details=None,
    actor="system",
):
    db.execute(
        """
        INSERT INTO campaign_checklist_history
            (item_id, campaign, created_at, actor, action, title, prev_status, new_status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item_id,
            campaign,
            time.time(),
            actor,
            action,
            title,
            prev_status,
            new_status,
            json.dumps(details or {}),
        ),
    )


PASSWORD_ALGO = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 210_000
VALID_ROLES = {"operator", "reviewer", "admin"}


def hash_password(password, *, salt_hex=None, iterations=PASSWORD_ITERATIONS):
    """Hash a password for storage."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password is required")
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        int(iterations),
    ).hex()
    return f"{PASSWORD_ALGO}${int(iterations)}${salt.hex()}${digest}"


def verify_password(password, password_hash):
    """Verify plaintext password against stored hash."""
    try:
        algo, iterations, salt_hex, digest = str(password_hash).split("$", 3)
    except ValueError:
        return False
    if algo != PASSWORD_ALGO:
        return False
    check = hash_password(password, salt_hex=salt_hex, iterations=int(iterations))
    return check == password_hash


def get_user_by_username(username, include_password=False):
    """Fetch a user by username."""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    if not row:
        return None
    user = dict(row)
    user["is_active"] = bool(user.get("is_active"))
    if not include_password:
        user.pop("password_hash", None)
    return user


def get_user_by_id(user_id, include_password=False):
    """Fetch a user by id."""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    if not row:
        return None
    user = dict(row)
    user["is_active"] = bool(user.get("is_active"))
    if not include_password:
        user.pop("password_hash", None)
    return user


def list_users(limit=200):
    """List users for administration."""
    db = get_db()
    rows = db.execute(
        """
        SELECT id, username, role, is_active, created_at, updated_at, last_login_at
        FROM users
        ORDER BY username ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    db.close()
    users = [dict(r) for r in rows]
    for user in users:
        user["is_active"] = bool(user.get("is_active"))
    return users


def create_user(username, password, role="operator", is_active=True):
    """Create a user account."""
    name = (username or "").strip()
    chosen_role = (role or "operator").strip().lower()
    if not name:
        raise ValueError("Username is required")
    if chosen_role not in VALID_ROLES:
        raise ValueError("Invalid role")
    now = time.time()
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                hash_password(password),
                chosen_role,
                1 if is_active else 0,
                now,
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        db.close()
        raise ValueError("Username already exists") from exc
    db.commit()
    db.close()
    return get_user_by_username(name)


def set_user_password(user_id, password):
    """Set a new password for a user."""
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
        (hash_password(password), time.time(), user_id),
    )
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def update_user_role_status(user_id, role=None, is_active=None):
    """Update user role and/or active status."""
    updates: dict[str, Any] = {}
    if role is not None:
        chosen_role = str(role).strip().lower()
        if chosen_role not in VALID_ROLES:
            raise ValueError("Invalid role")
        updates["role"] = chosen_role
    if is_active is not None:
        updates["is_active"] = 1 if bool(is_active) else 0
    if not updates:
        return False
    updates["updated_at"] = time.time()
    db = get_db()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    params = list(updates.values()) + [user_id]
    db.execute(f"UPDATE users SET {set_clause} WHERE id=?", params)
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def touch_user_login(user_id):
    """Update last login timestamp."""
    db = get_db()
    db.execute(
        "UPDATE users SET last_login_at=?, updated_at=? WHERE id=?",
        (time.time(), time.time(), user_id),
    )
    changed = db.total_changes
    db.commit()
    db.close()
    return changed > 0


def get_setting(key: str, default=None):
    """Get a runtime setting by key. Returns parsed JSON value or default."""
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close()
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        return row["value"]


def set_setting(key: str, value) -> None:
    """Persist a runtime setting. Value is JSON-serialised."""
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value), time.time()),
    )
    db.commit()
    db.close()


def authenticate_user(username, password):
    """Authenticate username/password and return user if valid."""
    user = get_user_by_username((username or "").strip(), include_password=True)
    if not user or not user.get("is_active"):
        return None
    stored_hash = user.get("password_hash") or ""
    if not verify_password(password, stored_hash):
        return None
    user.pop("password_hash", None)
    return user
