"""TLS certificate utilities for Ursa Major.

Generates self-signed X.509 certificates (with SAN) for the C2 HTTPS listener.
No CA or external tooling required — everything uses the `cryptography` package.

Usage
-----
    from major.cert import ensure_cert

    cert_path, key_path = ensure_cert()          # auto-managed in major/tls/
    cert_path, key_path = ensure_cert(           # custom location + identity
        cert_dir="/etc/ursa/tls",
        hostname="c2.example.com",
        extra_sans=["10.0.0.1"],
        days=365,
    )

    # Or generate and get PEM bytes directly (no files written):
    from major.cert import generate_cert_pem
    cert_pem, key_pem = generate_cert_pem(hostname="c2.example.com")

Wrapping an HTTPServer socket with TLS
--------------------------------------
    import ssl
    from major.cert import ensure_cert

    cert_path, key_path = ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
"""

from __future__ import annotations

import ipaddress
import os
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Default TLS directory (relative to the major/ package)
_TLS_DIR = Path(__file__).parent / "tls"

# Certificate validity
_DEFAULT_DAYS = 365

# RSA key size — 2048 is fine for internal C2; bump to 4096 for extra paranoia
_KEY_BITS = 2048


# ── Core generator ─────────────────────────────────────────────────────────────


def generate_cert_pem(
    hostname: str = "",
    extra_sans: list[str] | None = None,
    days: int = _DEFAULT_DAYS,
    org: str = "Ursa Ops",
) -> tuple[bytes, bytes]:
    """Generate a self-signed certificate and private key.

    Returns (cert_pem, key_pem) as bytes — nothing is written to disk.

    Args:
        hostname: Primary hostname for the cert CN and SAN.
                  Defaults to the machine's FQDN.
        extra_sans: Additional SANs — can be hostnames or IPv4/IPv6 addresses.
        days: Certificate validity period.
        org: Organisation name embedded in the subject DN.

    Returns:
        (cert_pem, key_pem) — PEM-encoded certificate and RSA private key.
    """
    if not hostname:
        hostname = socket.getfqdn()
    if extra_sans is None:
        extra_sans = []

    # ── Private key ──────────────────────────────────────────────────────────
    key = rsa.generate_private_key(public_exponent=65537, key_size=_KEY_BITS)

    # ── Subject / Issuer DN ──────────────────────────────────────────────────
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,            hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,      org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "C2"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,           "US"),
    ])

    # ── Subject Alternative Names ────────────────────────────────────────────
    san_entries: list[x509.GeneralName] = []

    # Always include the primary hostname as a DNS SAN
    san_entries.append(x509.DNSName(hostname))

    # Also add localhost and loopback for dev convenience
    for default_host in ("localhost",):
        if default_host != hostname:
            san_entries.append(x509.DNSName(default_host))
    for default_ip in ("127.0.0.1", "::1"):
        san_entries.append(x509.IPAddress(ipaddress.ip_address(default_ip)))

    # Process extra SANs — auto-detect IP vs DNS
    for san in extra_sans:
        san = san.strip()
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(san)))
        except ValueError:
            # Not an IP address — treat as DNS name
            san_entries.append(x509.DNSName(san))

    # ── Certificate builder ──────────────────────────────────────────────────
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)           # Self-signed → issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))   # Small backdate for clock skew
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    return cert_pem, key_pem


# ── File-backed helper ─────────────────────────────────────────────────────────


def ensure_cert(
    cert_dir: str | Path | None = None,
    hostname: str = "",
    extra_sans: list[str] | None = None,
    days: int = _DEFAULT_DAYS,
    org: str = "Ursa Ops",
    regenerate: bool = False,
) -> tuple[Path, Path]:
    """Ensure a self-signed TLS certificate exists on disk.

    If cert.pem / key.pem already exist in *cert_dir* and *regenerate* is
    False, the existing files are returned unchanged.  This means a single
    ``ensure_cert()`` call at server start is idempotent across restarts.

    Args:
        cert_dir: Directory for cert.pem / key.pem.  Defaults to major/tls/.
        hostname: Primary CN / DNS SAN.  Defaults to machine FQDN.
        extra_sans: Additional SANs (IPs or hostnames).
        days: Certificate validity.
        org: Organisation DN field.
        regenerate: Force regeneration even if files already exist.

    Returns:
        (cert_path, key_path) as absolute Path objects.
    """
    tls_dir = Path(cert_dir) if cert_dir else _TLS_DIR
    tls_dir.mkdir(parents=True, exist_ok=True)

    cert_path = tls_dir / "cert.pem"
    key_path  = tls_dir / "key.pem"

    if not regenerate and cert_path.exists() and key_path.exists():
        return cert_path, key_path

    cert_pem, key_pem = generate_cert_pem(
        hostname=hostname,
        extra_sans=extra_sans,
        days=days,
        org=org,
    )

    # Write key first with restricted permissions
    key_path.write_bytes(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # Windows — best effort

    cert_path.write_bytes(cert_pem)

    return cert_path, key_path


# ── Convenience: build an ssl.SSLContext ready to wrap ────────────────────────


def build_ssl_context(
    cert_path: str | Path,
    key_path: str | Path,
) -> ssl.SSLContext:  # type: ignore[name-defined]
    """Return a server-side ssl.SSLContext loaded with the given cert/key.

    Uses TLS 1.2+ only; disables SSLv2/SSLv3/TLS 1.0/1.1.

    Example::

        ctx = build_ssl_context(cert_path, key_path)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    """
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Only allow strong cipher suites
    ctx.set_ciphers(
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-CHACHA20-POLY1305"
    )

    return ctx
