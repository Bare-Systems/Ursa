"""Tests for the Ursa Minor network inventory collector (ROADMAP Phase 5A).

The privileged ARP scan and the HTTP POST are both injectable, so these tests
exercise target resolution, payload assembly, and the request the collector
sends to the control plane without touching scapy, sudo, or a socket.
"""

import json

from ursa_minor import netcollect


class _FakeResponse:
    """Minimal context-manager stand-in for urlopen's return value."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def test_resolve_target_prefers_explicit():
    assert netcollect.resolve_target("10.0.0.0/24", "192.168.1.0/24") == "10.0.0.0/24"


def test_resolve_target_falls_back_to_env():
    assert netcollect.resolve_target(None, "192.168.86.0/24") == "192.168.86.0/24"


def test_build_payload_shape():
    devices = [{"ip": "192.168.86.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Apple"}]
    payload = netcollect.build_payload(devices, "192.168.86.0/24", "host-collector")
    assert payload == {
        "devices": devices,
        "target_range": "192.168.86.0/24",
        "source": "host-collector",
    }


def test_post_scan_builds_authenticated_request():
    captured = {}

    def fake_opener(request, timeout=None):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["data"] = json.loads(request.data.decode("utf-8"))
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        return _FakeResponse(json.dumps({"ok": True, "scan_id": "abc123", "new_count": 2}).encode())

    payload = netcollect.build_payload(
        [{"ip": "192.168.86.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Apple"}],
        "192.168.86.0/24",
        "host-collector",
    )
    summary = netcollect.post_scan(
        "http://127.0.0.1:8080/", "secret-token", payload, actor="host-collector", opener=fake_opener
    )

    assert captured["url"] == "http://127.0.0.1:8080/api/v1/network/scan"
    assert captured["method"] == "POST"
    assert captured["data"]["target_range"] == "192.168.86.0/24"
    assert captured["headers"]["authorization"] == "Bearer secret-token"
    assert captured["headers"]["x-bearclaw-actor"] == "host-collector"
    assert captured["headers"]["x-bearclaw-role"] == "admin"
    assert summary["scan_id"] == "abc123"


def test_post_scan_omits_authorization_when_no_token():
    captured = {}

    def fake_opener(request, timeout=None):
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        return _FakeResponse(b"{}")

    netcollect.post_scan("http://127.0.0.1:8080", "", {"devices": []}, opener=fake_opener)
    assert "authorization" not in captured["headers"]


def test_run_collector_wires_scan_into_post():
    posted = {}

    def fake_scanner(target_range, timeout=3):
        assert target_range == "192.168.86.0/24"
        return [
            {"ip": "192.168.86.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Apple"},
            {"ip": "192.168.86.9", "mac": "11:22:33:44:55:66", "vendor": "Unknown"},
        ]

    def fake_poster(base_url, token, payload, *, actor="host-collector", timeout=10):
        posted["payload"] = payload
        posted["token"] = token
        return {"ok": True, "scan_id": "deadbeef", "new_count": 1, "device_count": 2}

    summary = netcollect.run_collector(
        base_url="http://127.0.0.1:8080",
        token="tok",
        target="192.168.86.0/24",
        actor="host-collector",
        timeout=3,
        scanner=fake_scanner,
        poster=fake_poster,
    )

    assert summary["scanned"] == 2
    assert summary["scan_id"] == "deadbeef"
    assert posted["token"] == "tok"
    assert len(posted["payload"]["devices"]) == 2
    assert posted["payload"]["source"] == "host-collector"
