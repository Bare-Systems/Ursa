"""Ursa Minor defensive host triage helpers."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable


DEFAULT_BASELINE_DIR = Path.home() / ".ursa" / "baselines"

_SUSPICIOUS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "remote fetch": ("http://", "https://", "curl ", "wget ", "invoke-webrequest"),
    "encoded execution": ("base64", "-enc", "frombase64string", "decode("),
    "script interpreter": ("powershell", "cmd.exe", "bash -c", "bash -lc", "sh -c", "python -c"),
    "launch control": ("launchctl", "osascript", "schtasks", "reg add"),
    "socket utility": ("nc ", "netcat", "/dev/tcp/"),
}

_PERSISTENCE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "darwin": [
        ("launch_agent", "Users/*/Library/LaunchAgents/*.plist"),
        ("launch_agent", "Library/LaunchAgents/*.plist"),
        ("launch_daemon", "Library/LaunchDaemons/*.plist"),
        ("login_item", "Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"),
    ],
    "linux": [
        ("cron", "etc/cron.d/*"),
        ("cron", "etc/cron.daily/*"),
        ("cron", "etc/cron.hourly/*"),
        ("cron", "etc/cron.weekly/*"),
        ("cron", "var/spool/cron/*"),
        ("systemd", "etc/systemd/system/*.service"),
        ("systemd", "etc/systemd/system/*.timer"),
        ("systemd", "home/*/.config/systemd/user/*.service"),
        ("systemd", "home/*/.config/systemd/user/*.timer"),
        ("shell_profile", "home/*/.profile"),
        ("shell_profile", "home/*/.bash_profile"),
        ("shell_profile", "home/*/.bashrc"),
    ],
    "windows": [
        ("startup_folder", "ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/*"),
        ("startup_folder", "Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*"),
        ("scheduled_task", "Windows/System32/Tasks/**/*"),
    ],
}


def _get_baseline_dir() -> Path:
    """Get the baseline directory, creating it if needed."""
    try:
        from major.config import get_config

        cfg = get_config()
        baseline_dir = Path(cfg.get("minor.baselines_dir", str(DEFAULT_BASELINE_DIR)))
    except ImportError:
        baseline_dir = DEFAULT_BASELINE_DIR

    baseline_dir = baseline_dir.expanduser()
    baseline_dir.mkdir(parents=True, exist_ok=True)
    return baseline_dir


def _normalize_system(system: str | None = None) -> str:
    if system:
        return system.lower()
    return platform.system().lower()


def _normalize_root(root_path: str | None = None) -> Path:
    if not root_path:
        return Path("/")
    return Path(root_path).expanduser().resolve()


def _iso_timestamp(ts: float | int | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), tz=UTC).isoformat()


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip())
    return cleaned or "default"


def _file_sha256(path: Path, max_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            remaining = max_bytes
            while remaining > 0:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _read_text_preview(path: Path, max_bytes: int = 4096) -> str:
    try:
        return path.read_text(errors="ignore")[:max_bytes]
    except OSError:
        return ""


def _looks_hidden(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts if part not in (".", ".."))


def _looks_user_writable_staging(path: Path) -> bool:
    lowered = str(path).lower()
    markers = ("/tmp/", "/temp/", "/downloads/", "\\temp\\", "\\downloads\\", "/appdata/local/temp/")
    return any(marker in lowered for marker in markers)


def _evaluate_entry_risk(path: Path, preview: str) -> tuple[str, list[str]]:
    preview_lower = preview.lower()
    reasons: list[str] = []

    for label, needles in _SUSPICIOUS_KEYWORDS.items():
        if any(needle in preview_lower for needle in needles):
            reasons.append(label)

    if _looks_hidden(path):
        reasons.append("hidden path")
    if _looks_user_writable_staging(path):
        reasons.append("user-writable staging path")

    if "remote fetch" in reasons and ("encoded execution" in reasons or "script interpreter" in reasons):
        severity = "high"
    elif reasons:
        severity = "medium"
    else:
        severity = "low"

    return severity, reasons


def _resolve_persistence_paths(root: Path, system: str) -> list[tuple[str, Path]]:
    patterns = _PERSISTENCE_PATTERNS.get(system, [])
    paths: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for category, pattern in patterns:
        for path in root.glob(pattern):
            if path.is_dir():
                continue
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            paths.append((category, path))

    return sorted(paths, key=lambda item: str(item[1]))


def collect_persistence_entries(
    root_path: str | None = None,
    system: str | None = None,
) -> list[dict]:
    """Scan common persistence locations and return structured findings."""
    normalized_system = _normalize_system(system)
    root = _normalize_root(root_path)
    entries: list[dict] = []

    for category, path in _resolve_persistence_paths(root, normalized_system):
        try:
            stat = path.stat()
        except OSError:
            continue
        preview = _read_text_preview(path)
        severity, reasons = _evaluate_entry_risk(path, preview)
        entries.append({
            "category": category,
            "path": str(path),
            "filename": path.name,
            "severity": severity,
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "mtime_str": _iso_timestamp(stat.st_mtime),
            "sha256": _file_sha256(path),
            "reasons": reasons,
            "detail": ", ".join(reasons) if reasons else "No obvious suspicious markers.",
        })

    return entries


def _unix_passwd_users(root: Path) -> list[dict]:
    passwd_path = root / "etc" / "passwd"
    if not passwd_path.exists():
        return []

    users: list[dict] = []
    try:
        for line in passwd_path.read_text(errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, _, uid, gid, gecos, home, shell = parts[:7]
            users.append({
                "username": username,
                "uid": int(uid) if uid.isdigit() else uid,
                "gid": int(gid) if gid.isdigit() else gid,
                "gecos": gecos,
                "home": home,
                "shell": shell,
            })
    except OSError:
        return []

    return users


def _run_command(args: list[str]) -> str:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0 and not result.stdout:
        return ""
    return result.stdout


def _split_host_port(value: str) -> tuple[str, int | str]:
    cleaned = value.strip()
    if cleaned.startswith("[") and "]:" in cleaned:
        host, port = cleaned[1:].rsplit("]:", 1)
        return host, int(port) if port.isdigit() else port
    if cleaned.count(":") >= 1:
        host, port = cleaned.rsplit(":", 1)
        return host or "*", int(port) if port.isdigit() else port
    return cleaned or "*", ""


def parse_ss_output(output: str) -> list[dict]:
    ports: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("state"):
            continue
        parts = re.split(r"\s+", line, maxsplit=5)
        if len(parts) < 5:
            continue
        host, port = _split_host_port(parts[3])
        ports.append({
            "protocol": parts[0].lower(),
            "address": host,
            "port": port,
            "process": parts[5] if len(parts) > 5 else "",
        })
    return ports


def parse_lsof_output(output: str) -> list[dict]:
    ports: list[dict] = []
    pattern = re.compile(r"(?P<address>\*|[0-9A-Fa-f\.:]+):(?P<port>\d+)\s+\(LISTEN\)")
    for line in output.splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        match = pattern.search(line)
        if not match:
            continue
        process = line.split(None, 1)[0]
        ports.append({
            "protocol": "tcp",
            "address": match.group("address"),
            "port": int(match.group("port")),
            "process": process,
        })
    return ports


def parse_netstat_output(output: str) -> list[dict]:
    ports: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.lower().startswith("tcp"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 4:
            continue
        state = parts[3].upper() if len(parts) > 3 else ""
        if "LISTEN" not in state:
            continue
        host, port = _split_host_port(parts[1])
        process = parts[4] if len(parts) > 4 else ""
        ports.append({
            "protocol": parts[0].lower(),
            "address": host,
            "port": port,
            "process": process,
        })
    return ports


def collect_listening_ports(system: str | None = None) -> list[dict]:
    """Collect current listening TCP ports using platform-native tools."""
    normalized_system = _normalize_system(system)

    commands: list[tuple[list[str], Callable[[str], list[dict]]]] = []
    if normalized_system == "linux":
        commands = [
            (["ss", "-lntp"], parse_ss_output),
            (["netstat", "-lnt"], parse_netstat_output),
        ]
    elif normalized_system == "darwin":
        commands = [
            (["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], parse_lsof_output),
            (["netstat", "-an", "-p", "tcp"], parse_netstat_output),
        ]
    elif normalized_system == "windows":
        commands = [(["netstat", "-ano", "-p", "tcp"], parse_netstat_output)]

    for cmd, parser in commands:
        if shutil.which(cmd[0]) is None:
            continue
        try:
            output = _run_command(cmd)
        except (OSError, subprocess.SubprocessError):
            continue
        if not output:
            continue
        parsed = parser(output)
        if parsed:
            return parsed

    return []


def collect_host_snapshot(
    root_path: str | None = None,
    system: str | None = None,
) -> dict:
    """Collect a lightweight defensive snapshot of the host."""
    normalized_system = _normalize_system(system)
    root = _normalize_root(root_path)
    snapshot = {
        "platform": normalized_system,
        "root_path": str(root),
        "collected_at": time.time(),
        "collected_at_str": datetime.now(tz=UTC).isoformat(),
        "persistence": collect_persistence_entries(root_path=str(root), system=normalized_system),
        "users": _unix_passwd_users(root) if normalized_system in {"linux", "darwin"} else [],
        "listening_ports": [] if root_path else collect_listening_ports(system=normalized_system),
    }
    return snapshot


def save_baseline(name: str, snapshot: dict) -> Path:
    """Persist a host snapshot to disk as a named baseline."""
    baseline_dir = _get_baseline_dir()
    path = baseline_dir / f"{_safe_name(name)}.json"
    with path.open("w") as handle:
        json.dump(snapshot, handle, indent=2, default=str)
    return path


def load_baseline(name: str) -> dict | None:
    """Load a previously saved baseline by name."""
    path = _get_baseline_dir() / f"{_safe_name(name)}.json"
    if not path.exists():
        return None
    with path.open() as handle:
        return json.load(handle)


def _findings_from_diff(diff: dict) -> list[dict]:
    findings: list[dict] = []
    severity_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}

    for entry in diff["new_persistence"]:
        findings.append({
            "severity": entry.get("severity", "medium"),
            "title": "New persistence artifact",
            "category": entry.get("category", "persistence"),
            "detail": entry.get("path", ""),
            "evidence": entry,
        })
    for entry in diff["changed_persistence"]:
        old_severity = entry.get("old", {}).get("severity", "medium")
        new_severity = entry.get("new", {}).get("severity", "medium")
        findings.append({
            "severity": old_severity if severity_rank.get(old_severity, 0) >= severity_rank.get(new_severity, 0) else new_severity,
            "title": "Persistence artifact changed",
            "category": entry.get("new", {}).get("category", "persistence"),
            "detail": entry.get("path", ""),
            "evidence": entry,
        })
    for entry in diff["new_listening_ports"]:
        findings.append({
            "severity": "medium",
            "title": "New listening port",
            "category": "network",
            "detail": f"{entry.get('address')}:{entry.get('port')}",
            "evidence": entry,
        })
    for entry in diff["new_users"]:
        findings.append({
            "severity": "medium",
            "title": "New local user",
            "category": "identity",
            "detail": entry.get("username", ""),
            "evidence": entry,
        })

    findings.sort(key=lambda item: severity_rank.get(item["severity"], 0), reverse=True)
    return findings


def diff_snapshots(baseline: dict, current: dict) -> dict:
    """Compare two host snapshots and return a structured drift report."""
    baseline_persistence = {entry["path"]: entry for entry in baseline.get("persistence", [])}
    current_persistence = {entry["path"]: entry for entry in current.get("persistence", [])}

    new_persistence = [
        current_persistence[path]
        for path in sorted(set(current_persistence) - set(baseline_persistence))
    ]
    removed_persistence = [
        baseline_persistence[path]
        for path in sorted(set(baseline_persistence) - set(current_persistence))
    ]
    changed_persistence = []
    for path in sorted(set(baseline_persistence) & set(current_persistence)):
        before = baseline_persistence[path]
        after = current_persistence[path]
        if before.get("sha256") != after.get("sha256") or before.get("size") != after.get("size"):
            changed_persistence.append({"path": path, "old": before, "new": after})

    baseline_ports = {
        f"{entry.get('protocol')}|{entry.get('address')}|{entry.get('port')}": entry
        for entry in baseline.get("listening_ports", [])
    }
    current_ports = {
        f"{entry.get('protocol')}|{entry.get('address')}|{entry.get('port')}": entry
        for entry in current.get("listening_ports", [])
    }
    new_listening_ports = [
        current_ports[key]
        for key in sorted(set(current_ports) - set(baseline_ports))
    ]
    removed_listening_ports = [
        baseline_ports[key]
        for key in sorted(set(baseline_ports) - set(current_ports))
    ]

    baseline_users = {entry["username"]: entry for entry in baseline.get("users", []) if entry.get("username")}
    current_users = {entry["username"]: entry for entry in current.get("users", []) if entry.get("username")}
    new_users = [current_users[key] for key in sorted(set(current_users) - set(baseline_users))]
    removed_users = [baseline_users[key] for key in sorted(set(baseline_users) - set(current_users))]

    diff = {
        "baseline_collected_at": baseline.get("collected_at_str", ""),
        "current_collected_at": current.get("collected_at_str", ""),
        "new_persistence": new_persistence,
        "removed_persistence": removed_persistence,
        "changed_persistence": changed_persistence,
        "new_listening_ports": new_listening_ports,
        "removed_listening_ports": removed_listening_ports,
        "new_users": new_users,
        "removed_users": removed_users,
    }
    diff["findings"] = _findings_from_diff(diff)
    diff["summary"] = {
        "new_persistence": len(new_persistence),
        "changed_persistence": len(changed_persistence),
        "removed_persistence": len(removed_persistence),
        "new_listening_ports": len(new_listening_ports),
        "removed_listening_ports": len(removed_listening_ports),
        "new_users": len(new_users),
        "removed_users": len(removed_users),
        "finding_count": len(diff["findings"]),
    }
    return diff


def render_persistence_report(entries: list[dict]) -> str:
    """Render persistence entries as human-readable text."""
    if not entries:
        return "No persistence artifacts found in the scanned locations."

    severity_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for entry in entries:
        severity = entry.get("severity", "low")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    lines = [
        f"Persistence Scan Results ({len(entries)} artifacts)",
        (
            f"  High: {severity_counts.get('high', 0)}"
            f"  Medium: {severity_counts.get('medium', 0)}"
            f"  Low: {severity_counts.get('low', 0)}"
        ),
        "",
    ]
    for entry in entries:
        reason = entry.get("detail") or "No obvious suspicious markers."
        lines.append(
            f"[{entry.get('severity', 'low').upper()}] {entry.get('category')} -> "
            f"{entry.get('path')} ({reason})"
        )
    return "\n".join(lines)


def render_diff_report(name: str, diff: dict) -> str:
    """Render a baseline drift report as text."""
    summary = diff.get("summary", {})
    lines = [
        f"Baseline Drift Report: {name}",
        f"  Baseline collected: {diff.get('baseline_collected_at', 'unknown')}",
        f"  Current collected:  {diff.get('current_collected_at', 'unknown')}",
        (
            f"  New persistence: {summary.get('new_persistence', 0)}"
            f"  Changed persistence: {summary.get('changed_persistence', 0)}"
            f"  New ports: {summary.get('new_listening_ports', 0)}"
            f"  New users: {summary.get('new_users', 0)}"
        ),
        "",
    ]

    findings = diff.get("findings", [])
    if not findings:
        lines.append("No material drift detected.")
        return "\n".join(lines)

    for finding in findings:
        lines.append(
            f"[{finding['severity'].upper()}] {finding['title']}: {finding['detail']}"
        )
    return "\n".join(lines)


def render_triage_report(
    snapshot: dict,
    persistence_entries: list[dict],
    diff: dict | None = None,
    baseline_name: str | None = None,
) -> str:
    """Render a host triage summary."""
    lines = [
        "Host Triage Summary",
        f"  Platform: {snapshot.get('platform', 'unknown')}",
        f"  Persistence artifacts: {len(persistence_entries)}",
        f"  Local users: {len(snapshot.get('users', []))}",
        f"  Listening ports: {len(snapshot.get('listening_ports', []))}",
        "",
    ]

    high_findings = [entry for entry in persistence_entries if entry.get("severity") == "high"]
    medium_findings = [entry for entry in persistence_entries if entry.get("severity") == "medium"]
    if high_findings or medium_findings:
        lines.append(
            f"Persistence heuristics flagged {len(high_findings)} high and {len(medium_findings)} medium artifacts."
        )
    else:
        lines.append("No suspicious persistence markers were flagged by heuristic scanning.")

    if diff and baseline_name:
        lines.append("")
        lines.append(f"Baseline drift vs {baseline_name}:")
        summary = diff.get("summary", {})
        lines.append(
            f"  Findings: {summary.get('finding_count', 0)}"
            f"  New persistence: {summary.get('new_persistence', 0)}"
            f"  Changed persistence: {summary.get('changed_persistence', 0)}"
            f"  New ports: {summary.get('new_listening_ports', 0)}"
        )
        for finding in diff.get("findings", [])[:10]:
            lines.append(f"  [{finding['severity'].upper()}] {finding['title']}: {finding['detail']}")

    return "\n".join(lines)
