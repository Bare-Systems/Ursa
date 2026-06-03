#!/usr/bin/env python3
"""
Ursa Major — Network Insight
============================
Persistence and logic for home-network device inventory and baseline drift.

The privileged ARP scan runs in Ursa Minor (raw sockets, sudo, on the LAN).
This module only stores the resulting device list, maintains a trusted
baseline, and answers "how many devices / which are new/unknown" — so the
Docker control plane never needs raw network access itself.

A device's identity is its MAC address; IP/vendor/hostname are mutable
attributes refreshed on each sighting.
"""

import re
import time
import uuid

from major.db import get_db, log_event

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower()


def _clean_device(raw: dict) -> dict | None:
    """Validate and normalise one scan entry into {mac, ip, vendor, hostname}."""
    if not isinstance(raw, dict):
        return None
    mac = _normalize_mac(raw.get("mac", ""))
    if not _MAC_RE.match(mac):
        return None
    return {
        "mac": mac,
        "ip": str(raw.get("ip", "") or "").strip(),
        "vendor": str(raw.get("vendor", "") or "").strip(),
        "hostname": str(raw.get("hostname", "") or "").strip(),
    }


def record_scan(devices, source: str = "", target_range: str = "") -> dict:
    """Persist a network scan result.

    Upserts each device (insert new, refresh attributes + last_seen/times_seen
    for known ones), records a scan-history row, and returns a summary
    including the MACs that were seen for the first time.

    Args:
        devices: iterable of {ip, mac, vendor[, hostname]} dicts.
        source: free-text origin of the scan (e.g. "host-collector").
        target_range: CIDR that was scanned, for the history row.
    """
    cleaned: dict[str, dict] = {}
    for raw in devices or []:
        dev = _clean_device(raw)
        if dev:
            cleaned[dev["mac"]] = dev  # dedupe by MAC; last entry wins

    now = time.time()
    db = get_db()
    new_macs: list[str] = []
    try:
        known = {
            row["mac"]
            for row in db.execute("SELECT mac FROM network_devices").fetchall()
        }
        for mac, dev in cleaned.items():
            if mac in known:
                db.execute(
                    """
                    UPDATE network_devices
                    SET ip=?, vendor=?, hostname=COALESCE(NULLIF(?, ''), hostname),
                        last_seen=?, times_seen=times_seen + 1
                    WHERE mac=?
                    """,
                    (dev["ip"], dev["vendor"], dev["hostname"], now, mac),
                )
            else:
                new_macs.append(mac)
                db.execute(
                    """
                    INSERT INTO network_devices
                        (mac, ip, vendor, hostname, label, trusted,
                         first_seen, last_seen, times_seen)
                    VALUES (?, ?, ?, ?, '', 0, ?, ?, 1)
                    """,
                    (mac, dev["ip"], dev["vendor"], dev["hostname"], now, now),
                )

        scan_id = str(uuid.uuid4())[:8]
        db.execute(
            """
            INSERT INTO network_scans
                (id, started_at, source, target_range, device_count, new_count)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, now, source, target_range, len(cleaned), len(new_macs)),
        )
        db.commit()
    finally:
        db.close()

    if new_macs:
        log_event(
            "warning",
            "network",
            f"{len(new_macs)} new device(s) joined the network: {', '.join(new_macs)}",
            details={"scan_id": scan_id, "new_macs": new_macs, "source": source},
        )

    return {
        "scan_id": scan_id,
        "device_count": len(cleaned),
        "new_count": len(new_macs),
        "new_macs": new_macs,
    }


def list_devices(only_untrusted: bool = False) -> list[dict]:
    """Return the current device inventory, newest sighting first."""
    db = get_db()
    query = "SELECT * FROM network_devices"
    if only_untrusted:
        query += " WHERE trusted=0"
    query += " ORDER BY last_seen DESC"
    rows = db.execute(query).fetchall()
    db.close()
    return [dict(r) for r in rows]


def new_devices() -> list[dict]:
    """Devices not yet marked trusted — i.e. unknown/unbaselined."""
    return list_devices(only_untrusted=True)


def device_count() -> dict:
    """Counts for widgets: total devices and how many are untrusted."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM network_devices").fetchone()[0]
    untrusted = db.execute(
        "SELECT COUNT(*) FROM network_devices WHERE trusted=0"
    ).fetchone()[0]
    db.close()
    return {"total": total, "trusted": total - untrusted, "untrusted": untrusted}


def set_baseline() -> int:
    """Mark every currently-known device as trusted.

    Establishes "this is normal" — afterward, any device with a new MAC shows
    up as untrusted/new. Returns the number of devices marked trusted.
    """
    db = get_db()
    cur = db.execute("UPDATE network_devices SET trusted=1 WHERE trusted=0")
    count = cur.rowcount
    db.commit()
    db.close()
    log_event("info", "network", f"Network baseline set: {count} device(s) trusted")
    return count


def set_device_trust(mac: str, trusted: bool, label: str | None = None) -> bool:
    """Set trust (and optionally a friendly label) for one device.

    Returns False if the MAC is unknown.
    """
    mac = _normalize_mac(mac)
    db = get_db()
    try:
        exists = db.execute(
            "SELECT 1 FROM network_devices WHERE mac=?", (mac,)
        ).fetchone()
        if not exists:
            return False
        if label is None:
            db.execute(
                "UPDATE network_devices SET trusted=? WHERE mac=?",
                (1 if trusted else 0, mac),
            )
        else:
            db.execute(
                "UPDATE network_devices SET trusted=?, label=? WHERE mac=?",
                (1 if trusted else 0, label.strip(), mac),
            )
        db.commit()
    finally:
        db.close()
    return True


def list_scans(limit: int = 50) -> list[dict]:
    """Recent scan history, newest first."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM network_scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]
