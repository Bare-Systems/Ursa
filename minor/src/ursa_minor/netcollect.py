#!/usr/bin/env python3
"""
Ursa Minor — Network Inventory Collector
========================================
The privileged half of ROADMAP Phase 5A.

A sudo-capable host job runs an ARP sweep of the local network and POSTs the
discovered ``[{ip, mac, vendor}]`` list to Ursa Major's control-plane ingest
endpoint (``POST /api/v1/network/scan``). The Docker control plane never needs
raw-socket/L2 access itself — it only persists what this collector reports.

Run it on a host with LAN reachability (the Beelink), on a timer:

    sudo URSA_CP_URL=http://127.0.0.1:8080 \\
         URSA_API_TOKEN=... \\
         python -m ursa_minor.netcollect

Or as the installed console script:

    sudo ursa-netcollect --range 192.168.86.0/24

Configuration (env, so no token ever lands in argv/process list or a manifest):
    URSA_CP_URL / URSA_URL   Control-plane base URL (default http://127.0.0.1:8080)
    URSA_API_TOKEN           Bearer token for the admin API (required if Major has one)
    URSA_SCAN_RANGE          CIDR to scan (default: auto-detect local /24)
    URSA_COLLECTOR_ACTOR     Audit actor string (default "host-collector")

This is a defensive home-network inventory tool for a network you own.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
INGEST_PATH = "/api/v1/network/scan"
DEFAULT_ACTOR = "host-collector"


def resolve_target(explicit: str | None = None, env_value: str | None = None) -> str:
    """Pick the CIDR to scan: explicit arg > env > auto-detected local network.

    The auto-detect branch is the only one that needs scapy/root, so it is
    imported lazily — the env/explicit paths stay dependency-free and testable.
    """
    if explicit:
        return explicit
    if env_value:
        return env_value
    from ursa_minor.server import _get_network_range  # lazy: pulls scapy

    target_range, _local_ip = _get_network_range()
    return target_range


def scan_devices(target_range: str, timeout: int = 3) -> list[dict]:
    """ARP-sweep ``target_range`` and return ``[{ip, mac, vendor}]``.

    Isolated here so the rest of the module imports without scapy/root.
    """
    from scapy.all import ARP, Ether, srp, conf  # type: ignore[attr-defined]  # lazy: pulls scapy
    from ursa_minor.server import _lookup_vendor

    conf.verb = 0
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_range),
        timeout=timeout,
        retry=1,
    )
    devices = [
        {"ip": received.psrc, "mac": received.hwsrc, "vendor": _lookup_vendor(received.hwsrc)}
        for _sent, received in answered
    ]
    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")] if d["ip"] else [])
    return devices


def build_payload(devices: list[dict], target_range: str, source: str) -> dict:
    """Assemble the JSON body the ingest endpoint expects."""
    return {"devices": devices, "target_range": target_range, "source": source}


def post_scan(
    base_url: str,
    token: str | None,
    payload: dict,
    *,
    actor: str = DEFAULT_ACTOR,
    role: str = "admin",
    timeout: int = 10,
    opener=urllib.request.urlopen,
) -> dict:
    """POST a scan payload to the control-plane ingest endpoint.

    ``opener`` is injectable so tests can capture the request without a socket.
    Returns the parsed JSON summary from Ursa Major.
    """
    url = base_url.rstrip("/") + INGEST_PATH
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("X-BearClaw-Actor", actor)
    request.add_header("X-BearClaw-Role", role)
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    with opener(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def run_collector(
    *,
    base_url: str,
    token: str | None,
    target: str | None,
    actor: str,
    timeout: int,
    scanner=scan_devices,
    poster=post_scan,
) -> dict:
    """Resolve target, scan, and ingest. Returns the ingest summary."""
    target_range = resolve_target(explicit=target, env_value=os.environ.get("URSA_SCAN_RANGE"))
    devices = scanner(target_range, timeout=timeout)
    payload = build_payload(devices, target_range, source=actor)
    summary = poster(base_url, token, payload, actor=actor, timeout=timeout)
    return {"target_range": target_range, "scanned": len(devices), **(summary or {})}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ursa network inventory collector")
    parser.add_argument("--range", dest="target", default=None, help="CIDR to scan (default: auto-detect / $URSA_SCAN_RANGE)")
    parser.add_argument("--url", dest="base_url", default=None, help="Control-plane base URL (default: $URSA_CP_URL / $URSA_URL)")
    parser.add_argument("--actor", dest="actor", default=None, help='Audit actor (default: $URSA_COLLECTOR_ACTOR or "host-collector")')
    parser.add_argument("--timeout", dest="timeout", type=int, default=3, help="ARP response timeout in seconds")
    args = parser.parse_args(argv)

    base_url = args.base_url or os.environ.get("URSA_CP_URL") or os.environ.get("URSA_URL") or DEFAULT_BASE_URL
    token = os.environ.get("URSA_API_TOKEN") or ""
    actor = args.actor or os.environ.get("URSA_COLLECTOR_ACTOR") or DEFAULT_ACTOR

    try:
        summary = run_collector(
            base_url=base_url,
            token=token,
            target=args.target,
            actor=actor,
            timeout=args.timeout,
        )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore") if hasattr(exc, "read") else ""
        print(f"[netcollect] ingest failed: HTTP {exc.code} {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"[netcollect] control plane unreachable at {base_url}: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — host job: report and exit non-zero
        print(f"[netcollect] error: {exc}", file=sys.stderr)
        return 1

    print(
        f"[netcollect] {summary['target_range']}: scanned {summary['scanned']} device(s), "
        f"{summary.get('new_count', 0)} new (scan {summary.get('scan_id', '?')})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
