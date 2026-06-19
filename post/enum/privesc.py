"""Privilege escalation checker — read-only enumeration.

Scans for common misconfigurations and privilege escalation vectors.
Nothing here exploits anything; it only checks whether conditions
that enable known techniques are present.

Checks performed
----------------
SUID/SGID binaries    — world-executable files with the setuid/setgid bit.
                        Cross-reference with GTFOBins to identify exploitable ones.
Sudo rules            — output of `sudo -l`; ANY entry may be exploitable.
Writable PATH dirs    — directories in $PATH writable by the current user allow
                        PATH hijacking when a SUID binary calls an unqualified cmd.
Writable cron files   — writable cron scripts execute as root on a schedule.
Docker socket         — /var/run/docker.sock grants root-equivalent access.
Capabilities          — file capabilities can grant elevated privileges without SUID.
/etc/shadow readable  — if readable without root, password hashes are exposed.
/etc/passwd writable  — if writable, add a root-equivalent account directly.
NFS exports           — no_root_squash exports can be mounted and exploit SUID.
Interesting env vars  — LD_PRELOAD, PYTHONPATH etc. can hijack library loading.

Platform: Linux, macOS (darwin).
"""

from __future__ import annotations

import os
import stat
import subprocess

from post.base import ModuleResult, PostModule
from post.loader import register

# GTFOBins SUID binaries known to allow privilege escalation.
# Full list: https://gtfobins.github.io/#+suid
_GTFOBINS_SUID = {
    "bash", "sh", "dash", "zsh", "ksh", "fish",
    "python", "python2", "python3", "perl", "ruby", "lua",
    "awk", "gawk", "nawk", "mawk",
    "find", "xargs",
    "vim", "vi", "nano", "less", "more",
    "cp", "mv", "install",
    "tee", "dd",
    "nmap", "netcat", "nc", "curl", "wget",
    "tar", "zip", "unzip", "gzip",
    "openssl",
    "git", "make",
    "env", "nice", "timeout",
    "strace", "ltrace",
    "node", "php",
    "socat", "screen", "tmux",
    "ssh", "scp", "sftp", "rsync",
    "mount", "umount",
    "pkexec",           # CVE-2021-4034
    "sudo",             # always interesting
}


def _run(cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (r.stdout + r.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return f"[error: {exc}]"


def _check_suid_sgid() -> dict:
    """Find SUID and SGID binaries on the filesystem."""
    suid_raw = _run("find / -perm -4000 -type f 2>/dev/null")
    sgid_raw = _run("find / -perm -2000 -type f 2>/dev/null")

    suid_bins = [p for p in suid_raw.splitlines() if p and not p.startswith("[error")]
    sgid_bins = [p for p in sgid_raw.splitlines() if p and not p.startswith("[error")]

    # Cross-reference with known GTFOBins list
    gtfo_hits = [
        b for b in suid_bins
        if any(b.endswith("/" + name) or b == name for name in _GTFOBINS_SUID)
    ]

    return {
        "suid_binaries": suid_bins,
        "sgid_binaries": sgid_bins,
        "gtfobins_hits": gtfo_hits,
        "count": len(suid_bins) + len(sgid_bins),
    }


def _check_sudo() -> dict:
    """Read sudo rules for the current user."""
    output = _run("sudo -l 2>/dev/null")
    # Highlight NOPASSWD entries — these are immediately exploitable
    nopasswd = [
        line.strip()
        for line in output.splitlines()
        if "NOPASSWD" in line or "nopasswd" in line
    ]
    return {
        "raw": output,
        "nopasswd_entries": nopasswd,
        "has_nopasswd": bool(nopasswd),
    }


def _check_writable_path_dirs() -> dict:
    """Check if any directory in $PATH is writable by the current user."""
    path_dirs = os.environ.get("PATH", "").split(":")
    writable = []
    for d in path_dirs:
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            writable.append(d)
    return {"path_dirs": path_dirs, "writable": writable}


def _check_writable_cron() -> dict:
    """Find world-writable or user-writable cron files."""
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ]
    writable = []
    for p in cron_paths:
        if os.path.exists(p) and os.access(p, os.W_OK):
            writable.append(p)
        elif os.path.isdir(p):
            try:
                entries = list(os.scandir(p))
            except PermissionError:
                continue
            for entry in entries:
                if os.access(entry.path, os.W_OK):
                    writable.append(entry.path)
    return {"writable_cron_paths": writable}


def _check_docker_socket() -> dict:
    """Check for an accessible Docker socket (root-equivalent)."""
    sock = "/var/run/docker.sock"
    exists = os.path.exists(sock)
    readable = exists and os.access(sock, os.R_OK)
    writable = exists and os.access(sock, os.W_OK)
    return {
        "docker_socket_exists": exists,
        "readable": readable,
        "writable": writable,
        "exploitable": writable,
        "note": (
            "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
            if writable else ""
        ),
    }


def _check_capabilities() -> dict:
    """Find files with Linux capabilities set."""
    output = _run("getcap -r / 2>/dev/null")
    lines = [l for l in output.splitlines() if l and not l.startswith("[error")]
    # Interesting caps that allow privilege escalation
    interesting_caps = {"cap_setuid", "cap_setgid", "cap_net_raw", "cap_dac_override",
                        "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace"}
    hits = [l for l in lines if any(c in l.lower() for c in interesting_caps)]
    return {"all_caps": lines, "interesting": hits}


def _check_shadow_passwd() -> dict:
    """Check readability of /etc/shadow and writability of /etc/passwd."""
    shadow_readable = os.access("/etc/shadow", os.R_OK)
    passwd_writable = os.access("/etc/passwd", os.W_OK)
    return {
        "shadow_readable": shadow_readable,
        "passwd_writable": passwd_writable,
        "note_shadow": "Hashes exposed — crack offline with hashcat/john" if shadow_readable else "",
        "note_passwd": "Can add root-equivalent account: echo 'r00t::0:0::/root:/bin/bash' >> /etc/passwd" if passwd_writable else "",
    }


def _check_nfs_exports() -> dict:
    """Check /etc/exports for no_root_squash (NFS privilege escalation)."""
    exports_raw = _run("cat /etc/exports 2>/dev/null")
    no_root_squash = [
        l for l in exports_raw.splitlines()
        if "no_root_squash" in l and not l.strip().startswith("#")
    ]
    return {
        "exports_raw": exports_raw,
        "no_root_squash_entries": no_root_squash,
    }


def _check_interesting_env() -> dict:
    """Check environment variables that can lead to privilege escalation."""
    dangerous = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "RUBYLIB",
                 "PERL5LIB", "NODE_PATH", "DYLD_INSERT_LIBRARIES"]
    found = {k: os.environ[k] for k in dangerous if k in os.environ}
    return {"dangerous_env": found}


@register
class PrivescModule(PostModule):
    NAME = "enum/privesc"
    DESCRIPTION = "Read-only privilege escalation checker: SUID, sudo, caps, docker, cron, writable files"
    PLATFORM = ["linux", "darwin"]

    def run(self, args: dict | None = None) -> ModuleResult:  # noqa: ARG002
        findings: dict = {}
        alerts: list[str] = []

        findings["suid_sgid"] = _check_suid_sgid()
        if findings["suid_sgid"]["gtfobins_hits"]:
            alerts.append(
                f"[!] SUID GTFOBins: {findings['suid_sgid']['gtfobins_hits']}"
            )

        findings["sudo"] = _check_sudo()
        if findings["sudo"]["has_nopasswd"]:
            alerts.append(f"[!] Sudo NOPASSWD: {findings['sudo']['nopasswd_entries']}")

        findings["writable_path"] = _check_writable_path_dirs()
        if findings["writable_path"]["writable"]:
            alerts.append(
                f"[!] Writable PATH dirs: {findings['writable_path']['writable']}"
            )

        findings["writable_cron"] = _check_writable_cron()
        if findings["writable_cron"]["writable_cron_paths"]:
            alerts.append(
                f"[!] Writable cron paths: {findings['writable_cron']['writable_cron_paths']}"
            )

        findings["docker"] = _check_docker_socket()
        if findings["docker"]["exploitable"]:
            alerts.append("[!] Docker socket writable — root via container mount")

        findings["capabilities"] = _check_capabilities()
        if findings["capabilities"]["interesting"]:
            alerts.append(
                f"[!] Interesting capabilities: {findings['capabilities']['interesting']}"
            )

        findings["shadow_passwd"] = _check_shadow_passwd()
        if findings["shadow_passwd"]["shadow_readable"]:
            alerts.append("[!] /etc/shadow is readable")
        if findings["shadow_passwd"]["passwd_writable"]:
            alerts.append("[!] /etc/passwd is writable")

        findings["nfs"] = _check_nfs_exports()
        if findings["nfs"]["no_root_squash_entries"]:
            alerts.append(
                f"[!] NFS no_root_squash: {findings['nfs']['no_root_squash_entries']}"
            )

        findings["env"] = _check_interesting_env()
        if findings["env"]["dangerous_env"]:
            alerts.append(
                f"[!] Dangerous env vars: {list(findings['env']['dangerous_env'].keys())}"
            )

        summary = "\n".join(alerts) if alerts else "No obvious privesc vectors found."
        return ModuleResult(ok=True, output=summary, data=findings)
