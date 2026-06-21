"""Regression tests for SSL two-pass fallback — issue #3.

vuln_scan and probe_http were emitting false-positive "Missing header"
findings when run against HTTPS targets with self-signed or private-CA
certificates.  The root cause: urllib raised SSLCertVerificationError on
first connect, which was caught and returned empty headers, causing every
security header check to fire as absent.

Fix: both tools now use a two-pass strategy — try verified first, fall
back to CERT_NONE on SSLCertVerificationError, and annotate the result
so operators know the cert is untrusted.

These tests verify:
  1. probe.py's _fetch_with_redirects falls back correctly.
  2. The security header audit reflects actual response headers, not the
     error-path empty dict.
  3. vuln_scan's internal _fetch closure exhibits the same behaviour.
  4. Non-SSL errors do NOT trigger the fallback (connection refused, etc.).
"""

import ssl
import urllib.error
from unittest.mock import MagicMock, patch

# Headers a self-signed-cert target serves (all present server-side).
_SELF_SIGNED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}


def _ssl_url_error() -> urllib.error.URLError:
    """Simulate the error urllib raises for a self-signed certificate."""
    reason = ssl.SSLCertVerificationError(
        "certificate verify failed: self-signed certificate in certificate chain"
    )
    return urllib.error.URLError(reason)


def _mock_resp(status: int = 200, headers: dict | None = None, body: bytes = b"") -> MagicMock:
    """Return a minimal mock HTTP response."""
    m = MagicMock()
    m.status = status
    m.headers = headers if headers is not None else {}
    m.read.return_value = body
    return m


# ── probe.py: _fetch_with_redirects ──────────────────────────────────────────


class TestFetchWithRedirectsSSLFallback:

    def _two_openers(self, resp_headers: dict):
        """Return (verified_opener, fallback_opener) pair."""
        verified = MagicMock()
        verified.open.side_effect = _ssl_url_error()

        fallback = MagicMock()
        fallback.open.return_value = _mock_resp(200, headers=resp_headers, body=b"<html/>")
        return verified, fallback

    def _opener_factory(self, verified, fallback):
        def _build(ssl_ctx=None):
            return verified if ssl_ctx is None else fallback
        return _build

    def test_ssl_error_triggers_cert_none_fallback(self):
        from ursa_minor.probe import _fetch_with_redirects

        v, fb = self._two_openers(_SELF_SIGNED_HEADERS)
        with patch("ursa_minor.probe._build_no_redirect_opener",
                   side_effect=self._opener_factory(v, fb)):
            status, _, _, _, _, tls_unverified = _fetch_with_redirects(
                "https://192.168.1.1/", timeout=5
            )

        assert status == 200
        assert tls_unverified is True

    def test_security_headers_captured_from_fallback_response(self):
        from ursa_minor.probe import _fetch_with_redirects

        v, fb = self._two_openers(_SELF_SIGNED_HEADERS)
        with patch("ursa_minor.probe._build_no_redirect_opener",
                   side_effect=self._opener_factory(v, fb)):
            _, headers, _, _, _, _ = _fetch_with_redirects("https://192.168.1.1/", timeout=5)

        lower_keys = {k.lower() for k in headers}
        assert "strict-transport-security" in lower_keys
        assert "x-frame-options" in lower_keys
        assert "x-content-type-options" in lower_keys
        assert "content-security-policy" in lower_keys

    def test_tls_unverified_false_when_cert_trusted(self):
        from ursa_minor.probe import _fetch_with_redirects

        opener = MagicMock()
        opener.open.return_value = _mock_resp(200, headers=_SELF_SIGNED_HEADERS, body=b"ok")
        with patch("ursa_minor.probe._build_no_redirect_opener", return_value=opener):
            _, _, _, _, _, tls_unverified = _fetch_with_redirects("https://example.com/", timeout=5)

        assert tls_unverified is False

    def test_non_ssl_connection_error_not_retried(self):
        """Connection refused (URLError without SSL cause) must not trigger the fallback."""
        from ursa_minor.probe import _fetch_with_redirects

        conn_refused = urllib.error.URLError("Connection refused")
        build_count = [0]

        def _build(ssl_ctx=None):
            build_count[0] += 1
            m = MagicMock()
            m.open.side_effect = conn_refused
            return m

        with patch("ursa_minor.probe._build_no_redirect_opener", side_effect=_build):
            status, headers, body, _, _, tls_unverified = _fetch_with_redirects(
                "https://192.168.1.1/", timeout=5
            )

        assert status == 0
        assert headers == {}
        assert tls_unverified is False
        assert build_count[0] == 1  # no second build for fallback

    def test_http_target_not_affected_by_ssl_logic(self):
        """Plain-HTTP targets work normally; no SSL fallback path is reached."""
        from ursa_minor.probe import _fetch_with_redirects

        opener = MagicMock()
        opener.open.return_value = _mock_resp(200, headers=_SELF_SIGNED_HEADERS, body=b"ok")
        with patch("ursa_minor.probe._build_no_redirect_opener", return_value=opener):
            status, headers, _, _, _, tls_unverified = _fetch_with_redirects(
                "http://192.168.1.1/", timeout=5
            )

        assert status == 200
        assert tls_unverified is False
        assert "Strict-Transport-Security" in headers


# ── probe.py: _sec_header_audit — no false positives after fallback ──────────


class TestSecHeaderAuditAfterSSLFallback:

    def test_present_headers_not_reported_as_missing(self):
        """Headers returned by the CERT_NONE fallback must appear as 'present'."""
        from ursa_minor.probe import _fetch_with_redirects, _sec_header_audit

        v, fb = (MagicMock(), MagicMock())
        v.open.side_effect = _ssl_url_error()
        fb.open.return_value = _mock_resp(200, headers=_SELF_SIGNED_HEADERS, body=b"")

        with patch("ursa_minor.probe._build_no_redirect_opener",
                   side_effect=lambda ssl_ctx=None: v if ssl_ctx is None else fb):
            _, headers, _, _, _, _ = _fetch_with_redirects("https://192.168.1.1/", timeout=5)

        audit = _sec_header_audit(headers, is_https=True)
        missing = {e["header"] for e in audit if not e["present"]}

        assert "Strict-Transport-Security" not in missing
        assert "X-Frame-Options" not in missing
        assert "X-Content-Type-Options" not in missing
        assert "Content-Security-Policy" not in missing

    def test_tls_unverified_note_in_format_report(self):
        """format_report() must mention the CERT_NONE fallback when tls_unverified."""
        from ursa_minor.probe import format_report, probe

        v, fb = (MagicMock(), MagicMock())
        v.open.side_effect = _ssl_url_error()
        fb.open.return_value = _mock_resp(200, headers=_SELF_SIGNED_HEADERS, body=b"")

        with patch("ursa_minor.probe._build_no_redirect_opener",
                   side_effect=lambda ssl_ctx=None: v if ssl_ctx is None else fb), \
             patch("ursa_minor.probe._tls_info", return_value={"error": "skipped in test"}), \
             patch("ursa_minor.probe._favicon_hash", return_value=None), \
             patch("ursa_minor.probe._allowed_methods", return_value=[]):
            data = probe("https://192.168.1.1/", check_favicon=False, check_methods=False)

        assert data["tls_unverified"] is True
        report = format_report(data)
        assert "TLS certificate not verified" in report or "CERT_NONE" in report


# ── vuln_scan: internal _fetch closure ───────────────────────────────────────


class TestVulnScanSSLFallback:

    def test_no_false_positives_on_self_signed_target(self):
        """Headers present in the self-signed-cert response must not be flagged absent."""
        fallback_opener = MagicMock()
        fallback_opener.open.return_value = _mock_resp(200, headers=_SELF_SIGNED_HEADERS, body=b"")

        from ursa_minor.server import vuln_scan

        with patch("urllib.request.urlopen", side_effect=_ssl_url_error()), \
             patch("urllib.request.build_opener", return_value=fallback_opener):
            result = vuln_scan("https://192.168.1.1/", tests="headers")

        assert "Missing Strict-Transport-Security" not in result
        assert "Missing X-Frame-Options" not in result
        assert "Missing X-Content-Type-Options" not in result
        assert "Missing Content-Security-Policy" not in result

    def test_empty_fallback_response_reports_headers_as_missing(self):
        """When the fallback also returns no headers, findings ARE emitted (correct behavior)."""
        fallback_opener = MagicMock()
        fallback_opener.open.return_value = _mock_resp(200, headers={}, body=b"")

        from ursa_minor.server import vuln_scan

        with patch("urllib.request.urlopen", side_effect=_ssl_url_error()), \
             patch("urllib.request.build_opener", return_value=fallback_opener):
            result = vuln_scan("https://192.168.1.1/", tests="headers")

        assert "Missing Strict-Transport-Security" in result
        assert "Missing X-Frame-Options" in result

    def test_non_ssl_failure_reports_headers_missing(self):
        """A plain connection failure (not SSL) correctly surfaces missing-header findings."""
        from ursa_minor.server import vuln_scan

        conn_err = urllib.error.URLError("Connection refused")
        with patch("urllib.request.urlopen", side_effect=conn_err):
            result = vuln_scan("https://192.168.1.1/", tests="headers")

        assert "Missing Strict-Transport-Security" in result
        assert "Missing X-Frame-Options" in result

    def test_plain_http_target_headers_detected_correctly(self):
        """Plain HTTP targets use the normal urlopen path; headers are detected without SSL logic."""
        from ursa_minor.server import vuln_scan

        with patch("urllib.request.urlopen",
                   return_value=_mock_resp(200, headers=_SELF_SIGNED_HEADERS, body=b"")):
            result = vuln_scan("http://192.168.1.1/", tests="headers")

        assert "Missing X-Frame-Options" not in result
        assert "Missing X-Content-Type-Options" not in result
