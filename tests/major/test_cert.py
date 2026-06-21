"""Tests for major.cert — self-signed TLS certificate generation.

Pure local: no network, no live sockets. generate_cert_pem() is exercised
in-memory. ensure_cert() writes to tmp_path so nothing touches major/tls/.
build_ssl_context() is verified to load a generated cert successfully.
"""

import ipaddress
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from major.cert import build_ssl_context, ensure_cert, generate_cert_pem

# ── generate_cert_pem ─────────────────────────────────────────────────────────


class TestGenerateCertPem:

    def test_returns_pem_bytes(self):
        cert_pem, key_pem = generate_cert_pem(hostname="c2.test")
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_cert_cn_matches_hostname(self):
        cert_pem, _ = generate_cert_pem(hostname="myhost.lab")
        cert = x509.load_pem_x509_certificate(cert_pem)
        cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        assert any(attr.value == "myhost.lab" for attr in cns)

    def test_cert_is_self_signed(self):
        cert_pem, _ = generate_cert_pem(hostname="test.local")
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.subject == cert.issuer

    def test_san_includes_primary_hostname(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "c2.example.com" in dns_names

    def test_san_includes_localhost_by_default(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "localhost" in dns_names

    def test_san_includes_loopback_ip(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("127.0.0.1") in ips

    def test_extra_sans_ip_added(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test", extra_sans=["192.168.1.50"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("192.168.1.50") in ips

    def test_extra_sans_hostname_added(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test", extra_sans=["alt.c2.test"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "alt.c2.test" in dns_names

    def test_validity_period(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test", days=90)
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 89 <= delta.days <= 91

    def test_organisation_name(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test", org="Red Team Ops")
        cert = x509.load_pem_x509_certificate(cert_pem)
        orgs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        assert any(attr.value == "Red Team Ops" for attr in orgs)

    def test_rsa_key_size(self):
        _, key_pem = generate_cert_pem(hostname="c2.test")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(key_pem, password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_key_usage_extension_present(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is True

    def test_extended_key_usage_server_auth(self):
        cert_pem, _ = generate_cert_pem(hostname="c2.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku.value


# ── ensure_cert ───────────────────────────────────────────────────────────────


class TestEnsureCert:

    def test_creates_cert_and_key_files(self, tmp_path):
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        assert cert_path.exists()
        assert key_path.exists()

    def test_returns_absolute_paths(self, tmp_path):
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        assert cert_path.is_absolute()
        assert key_path.is_absolute()

    def test_idempotent_does_not_regenerate(self, tmp_path):
        ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        first_mtime = (tmp_path / "cert.pem").stat().st_mtime

        ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        second_mtime = (tmp_path / "cert.pem").stat().st_mtime

        assert first_mtime == second_mtime

    def test_regenerate_flag_replaces_files(self, tmp_path):
        ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        first_content = (tmp_path / "cert.pem").read_bytes()

        ensure_cert(cert_dir=tmp_path, hostname="c2.test", regenerate=True)
        second_content = (tmp_path / "cert.pem").read_bytes()

        # Two freshly generated certs will have different serial numbers / keys
        assert first_content != second_content

    def test_creates_parent_directory(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "tls"
        ensure_cert(cert_dir=nested, hostname="c2.test")
        assert nested.is_dir()
        assert (nested / "cert.pem").exists()

    def test_cert_file_is_valid_pem(self, tmp_path):
        cert_path, _ = ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        data = cert_path.read_bytes()
        # Parseable as a real X.509 cert
        cert = x509.load_pem_x509_certificate(data)
        assert cert is not None

    def test_extra_sans_propagated(self, tmp_path):
        ensure_cert(cert_dir=tmp_path, hostname="c2.test", extra_sans=["10.0.0.5"])
        cert = x509.load_pem_x509_certificate((tmp_path / "cert.pem").read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("10.0.0.5") in ips


# ── build_ssl_context ─────────────────────────────────────────────────────────


class TestBuildSslContext:

    def test_returns_ssl_context(self, tmp_path):
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        ctx = build_ssl_context(cert_path, key_path)
        assert isinstance(ctx, ssl.SSLContext)

    def test_minimum_tls_version_is_1_2(self, tmp_path):
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        ctx = build_ssl_context(cert_path, key_path)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_accepts_string_paths(self, tmp_path):
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="c2.test")
        ctx = build_ssl_context(str(cert_path), str(key_path))
        assert isinstance(ctx, ssl.SSLContext)
