"""Tests for Ursa Major network-insight inventory + baseline drift."""

from major import netinsight


SCAN_A = [
    {"ip": "192.168.86.1", "mac": "AA:BB:CC:00:00:01", "vendor": "Google"},
    {"ip": "192.168.86.53", "mac": "aa:bb:cc:00:00:02", "vendor": "Beelink"},
]


def test_record_scan_inserts_devices_and_history(tmp_db):
    summary = netinsight.record_scan(SCAN_A, source="test", target_range="192.168.86.0/24")

    assert summary["device_count"] == 2
    assert summary["new_count"] == 2
    assert netinsight.device_count() == {"total": 2, "trusted": 0, "untrusted": 2}

    scans = netinsight.list_scans()
    assert len(scans) == 1
    assert scans[0]["target_range"] == "192.168.86.0/24"
    assert scans[0]["new_count"] == 2


def test_mac_is_normalised_and_deduped(tmp_db):
    # Same MAC in mixed case + duplicate => one device.
    netinsight.record_scan([
        {"ip": "192.168.86.10", "mac": "DE:AD:BE:EF:00:01", "vendor": "x"},
        {"ip": "192.168.86.10", "mac": "de:ad:be:ef:00:01", "vendor": "x"},
    ])
    devices = netinsight.list_devices()
    assert len(devices) == 1
    assert devices[0]["mac"] == "de:ad:be:ef:00:01"


def test_invalid_macs_are_skipped(tmp_db):
    summary = netinsight.record_scan([
        {"ip": "192.168.86.10", "mac": "not-a-mac", "vendor": "x"},
        {"ip": "192.168.86.11", "mac": "", "vendor": "x"},
        {"ip": "192.168.86.12", "mac": "AA:BB:CC:00:00:09", "vendor": "ok"},
    ])
    assert summary["device_count"] == 1


def test_rescan_refreshes_without_new_flag(tmp_db):
    netinsight.record_scan(SCAN_A)
    summary = netinsight.record_scan([
        {"ip": "192.168.86.99", "mac": "AA:BB:CC:00:00:01", "vendor": "Google"},
    ])
    # Known MAC, just a new IP — not a new device.
    assert summary["new_count"] == 0
    dev = next(d for d in netinsight.list_devices() if d["mac"] == "aa:bb:cc:00:00:01")
    assert dev["ip"] == "192.168.86.99"
    assert dev["times_seen"] == 2


def test_baseline_then_new_device_is_flagged(tmp_db):
    netinsight.record_scan(SCAN_A)
    trusted = netinsight.set_baseline()
    assert trusted == 2
    assert netinsight.new_devices() == []

    # An unexpected device shows up after baseline.
    summary = netinsight.record_scan(SCAN_A + [
        {"ip": "192.168.86.200", "mac": "FF:FF:FF:00:00:42", "vendor": "Unknown"},
    ])
    assert summary["new_count"] == 1
    new = netinsight.new_devices()
    assert len(new) == 1
    assert new[0]["mac"] == "ff:ff:ff:00:00:42"
    assert new[0]["trusted"] == 0


def test_set_device_trust_and_label(tmp_db):
    netinsight.record_scan(SCAN_A)
    assert netinsight.set_device_trust("aa:bb:cc:00:00:02", trusted=True, label="Beelink") is True
    dev = next(d for d in netinsight.list_devices() if d["mac"] == "aa:bb:cc:00:00:02")
    assert dev["trusted"] == 1
    assert dev["label"] == "Beelink"

    assert netinsight.set_device_trust("00:00:00:00:00:00", trusted=True) is False


def test_new_device_logs_security_event(tmp_db):
    from major.db import get_events

    netinsight.record_scan(SCAN_A)
    netinsight.set_baseline()
    netinsight.record_scan([{"ip": "192.168.86.201", "mac": "FF:FF:FF:00:00:43", "vendor": "?"}])

    events = get_events(level="warning")
    assert any("new device" in e["message"].lower() for e in events)
