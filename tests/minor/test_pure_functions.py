"""Tests for Ursa Minor pure utility functions (no network I/O)."""

import pytest

import ursa_minor.policy as policy_mod
from ursa_minor.server import (
    _calculate_cidr,
    _lookup_vendor,
    generate_reverse_shell,
    identify_hash,
    lookup_service,
)


@pytest.fixture(autouse=True)
def policy_audit_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_mod, "DEFAULT_AUDIT_DIR", tmp_path / "audit")
    monkeypatch.setattr(policy_mod, "_active_engagement", lambda: None)


class TestCalculateCidr:

    def test_class_c_network(self):
        assert _calculate_cidr("192.168.1.100", "255.255.255.0") == "192.168.1.0/24"

    def test_class_b_network(self):
        assert _calculate_cidr("172.16.5.42", "255.255.0.0") == "172.16.0.0/16"

    def test_slash_25(self):
        assert _calculate_cidr("10.0.0.200", "255.255.255.128") == "10.0.0.128/25"

    def test_slash_32(self):
        assert _calculate_cidr("10.0.0.1", "255.255.255.255") == "10.0.0.1/32"


class TestLookupVendor:

    def test_known_vendor_raspberry_pi(self):
        assert _lookup_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi"

    def test_known_vendor_apple(self):
        assert _lookup_vendor("3c:22:fb:11:22:33") == "Apple"

    def test_unknown_vendor(self):
        assert _lookup_vendor("ff:ff:ff:aa:bb:cc") == "Unknown"


class TestLookupService:

    def test_ssh(self):
        result = lookup_service(22)
        assert "SSH" in result or "ssh" in result

    def test_http(self):
        result = lookup_service(80)
        assert "HTTP" in result or "http" in result

    def test_unknown_port(self):
        result = lookup_service(59999)
        assert result  # Should return something, not crash


class TestIdentifyHash:

    def test_md5(self):
        result = identify_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert "MD5" in result

    def test_sha1(self):
        result = identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert "SHA" in result

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = identify_hash(h)
        assert "SHA" in result and "256" in result

    def test_bcrypt(self):
        result = identify_hash("$2b$12$LJ3m4ys3YkUQ.vlMF1HXOeIBbPgsxMPE3FfE/bChGFk8eK1LqGSba")
        assert "bcrypt" in result.lower()

    def test_non_hex_string(self):
        result = identify_hash("not-a-hash-at-all")
        assert result  # Should return something, not crash


class TestGenerateReverseShell:
    _approval = {
        "policy_actor": "pytest",
        "policy_reason": "unit test approved payload generation",
        "policy_approval_id": "APP-test",
    }

    def test_bash_payload(self):
        result = generate_reverse_shell(payload_type="bash", lport=9999, **self._approval)
        assert "/dev/tcp/" in result
        assert "9999" in result

    def test_python_payload(self):
        result = generate_reverse_shell(payload_type="python", lport=5555, **self._approval)
        assert "socket" in result
        assert "5555" in result

    def test_all_payloads(self):
        result = generate_reverse_shell(payload_type="all", lport=4444, **self._approval)
        # Should contain multiple payload types
        assert "bash" in result.lower()
        assert "python" in result.lower()

    def test_unknown_type(self):
        result = generate_reverse_shell(payload_type="invalid_lang", lport=4444, **self._approval)
        assert result  # Should handle gracefully
