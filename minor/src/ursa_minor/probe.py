"""
Ursa Minor — HTTP Probe Engine
================================
Rich single-request HTTP probe used by the `probe_http` MCP tool.

Collects in one round-trip:
  - Final status code and redirect chain
  - Response headers (Server, Content-Type, X-Powered-By, security headers)
  - Body metrics: size, sha256 of first 4 KB, page title
  - Response time
  - TLS certificate subject / expiry / issuer (HTTPS only, via ssl stdlib)
  - Allowed HTTP methods (OPTIONS probe, optional)
  - Favicon hash (sha256 of /favicon.ico, optional)

All network I/O uses stdlib only (urllib, ssl, http.client) to keep the
dependency footprint minimal.
"""

import hashlib
import http.client
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 ursa-minor/1"
)


# ── TLS helpers ───────────────────────────────────────────────────────────────


def _tls_info(host: str, port: int, timeout: float) -> dict:
    """Return TLS certificate details for host:port.

    Two-pass strategy: try with system CA store first (check_hostname=False
    but CERT_REQUIRED) so Python parses the full cert dict. If that fails
    due to an untrusted / self-signed cert, fall back to CERT_NONE to at
    least capture cipher and protocol.
    """
    cert: dict = {}
    cipher: tuple | None = None
    version: str | None = None
    untrusted_note: str = ""

    # Pass 1 — CA-verified (populates getpeercert() dict)
    ctx_verify = ssl.create_default_context()
    ctx_verify.check_hostname = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx_verify.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                cipher = tls.cipher()
                version = tls.version()
    except ssl.SSLCertVerificationError:
        # Pass 2 — CERT_NONE fallback for self-signed / private CA
        ctx_none = ssl.create_default_context()
        ctx_none.check_hostname = False
        ctx_none.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx_none.wrap_socket(raw, server_hostname=host) as tls:
                    cert = {}
                    cipher = tls.cipher()
                    version = tls.version()
            untrusted_note = "self-signed or private CA — cert fields unavailable"
        except Exception as exc:
            return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}

    if not cert and not untrusted_note:
        return {"error": "no certificate presented"}

    if untrusted_note:
        return {
            "subject_cn": "",
            "issuer_cn": "",
            "issuer_org": "",
            "not_after": "",
            "days_remaining": None,
            "san": [],
            "protocol": version or "",
            "cipher": cipher[0] if cipher else "",
            "self_signed": True,
            "note": untrusted_note,
        }

    subject = dict(x[0] for x in cert.get("subject", []))  # type: ignore[misc]
    issuer = dict(x[0] for x in cert.get("issuer", []))  # type: ignore[misc]
    not_after_str = cert.get("notAfter", "")
    san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]  # type: ignore[misc]

    expiry_dt = None
    days_remaining = None
    if not_after_str:
        try:
            expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")  # type: ignore[arg-type]
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            days_remaining = (expiry_dt - now).days
        except ValueError:
            pass

    return {
        "subject_cn": subject.get("commonName", ""),
        "issuer_cn": issuer.get("commonName", ""),
        "issuer_org": issuer.get("organizationName", ""),
        "not_after": not_after_str,
        "days_remaining": days_remaining,
        "san": san[:10],
        "protocol": version or "",
        "cipher": cipher[0] if cipher else "",
        "self_signed": subject == issuer,
    }


# ── redirect-following fetch ──────────────────────────────────────────────────


def _no_verify_ssl_ctx() -> ssl.SSLContext:
    """Return an SSL context that skips certificate verification.

    Used as a fallback for self-signed / private-CA targets so header audits
    work correctly even when the cert chain is untrusted.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_no_redirect_opener(
    ssl_ctx: ssl.SSLContext | None = None,
) -> urllib.request.OpenerDirector:
    """Build a urllib opener that does not auto-follow redirects.

    If ssl_ctx is provided it is passed to the HTTPS handler so the opener
    can reach self-signed / private-CA targets.
    """
    handlers: list = []
    if ssl_ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
    opener = urllib.request.build_opener(*handlers)
    opener.handlers = [  # type: ignore[attr-defined]
        h for h in opener.handlers  # type: ignore[attr-defined]
        if not isinstance(h, urllib.request.HTTPRedirectHandler)
    ]
    return opener


def _fetch_with_redirects(
    url: str, timeout: float, max_redirects: int = 10
) -> tuple[int, dict, bytes, list[str], float, bool]:
    """Fetch url, following redirects manually so we can capture the chain.

    For HTTPS targets, tries a verified connection first. If TLS verification
    fails (self-signed / private CA), retries with certificate verification
    disabled so security header audits remain accurate.

    Returns: (final_status, final_headers_dict, body_bytes, redirect_chain,
              elapsed_s, tls_unverified)

    tls_unverified is True when the CERT_NONE fallback was used.
    """
    chain: list[str] = [url]
    current = url
    elapsed = 0.0
    tls_unverified = False

    # First attempt uses the default opener (verified TLS).
    # If it raises SSLCertVerificationError we rebuild with CERT_NONE.
    opener = _build_no_redirect_opener()

    for _ in range(max_redirects + 1):
        req = urllib.request.Request(current, method="GET")
        req.add_header("User-Agent", _UA)

        t0 = time.perf_counter()
        try:
            resp = opener.open(req, timeout=timeout)
            elapsed += time.perf_counter() - t0
            status = resp.status
            headers = dict(resp.headers)
            body = resp.read(65536)
        except urllib.error.HTTPError as e:
            elapsed += time.perf_counter() - t0
            status = e.code
            headers = dict(e.headers) if e.headers else {}
            body = e.read(4096) if e.fp else b""
        except Exception as _outer_exc:
            # urllib wraps ssl.SSLCertVerificationError inside URLError.
            _is_ssl_err = (
                isinstance(_outer_exc, ssl.SSLCertVerificationError)
                or (
                    isinstance(_outer_exc, urllib.error.URLError)
                    and isinstance(getattr(_outer_exc, "reason", None), ssl.SSLCertVerificationError)
                )
            )
            if not _is_ssl_err:
                elapsed += time.perf_counter() - t0
                return 0, {}, b"", chain, elapsed, tls_unverified
            elapsed += time.perf_counter() - t0
            # Rebuild opener without TLS verification and retry this hop.
            tls_unverified = True
            opener = _build_no_redirect_opener(ssl_ctx=_no_verify_ssl_ctx())
            try:
                resp = opener.open(req, timeout=timeout)
                status = resp.status
                headers = dict(resp.headers)
                body = resp.read(65536)
            except urllib.error.HTTPError as e:
                status = e.code
                headers = dict(e.headers) if e.headers else {}
                body = e.read(4096) if e.fp else b""
            except Exception:
                return 0, {}, b"", chain, elapsed, tls_unverified

        if status in (301, 302, 303, 307, 308):
            loc = headers.get("Location", headers.get("location", ""))
            if loc:
                # Resolve relative redirects
                next_url = urllib.parse.urljoin(current, loc)
                chain.append(next_url)
                current = next_url
                continue

        return status, headers, body, chain, elapsed, tls_unverified

    # Exhausted max_redirects — return last state
    return status, headers, body, chain, elapsed, tls_unverified


# ── favicon ───────────────────────────────────────────────────────────────────


def _favicon_hash(base_url: str, timeout: float, ssl_ctx: ssl.SSLContext | None = None) -> str | None:
    fav_url = urllib.parse.urljoin(base_url, "/favicon.ico")
    try:
        req = urllib.request.Request(fav_url, method="GET")
        req.add_header("User-Agent", _UA)
        opener = _build_no_redirect_opener(ssl_ctx=ssl_ctx)
        with opener.open(req, timeout=timeout) as r:
            if r.status == 200:
                data = r.read(65536)
                if data:
                    return hashlib.sha256(data).hexdigest()
    except Exception:
        pass
    return None


# ── allowed methods ───────────────────────────────────────────────────────────


def _allowed_methods(url: str, timeout: float, ssl_ctx: ssl.SSLContext | None = None) -> list[str]:
    try:
        req = urllib.request.Request(url, method="OPTIONS")
        req.add_header("User-Agent", _UA)
        opener = _build_no_redirect_opener(ssl_ctx=ssl_ctx)
        with opener.open(req, timeout=timeout) as r:
            allow = r.headers.get("Allow", r.headers.get("allow", ""))
            if allow:
                return [m.strip() for m in allow.split(",") if m.strip()]
    except urllib.error.HTTPError as e:
        allow = e.headers.get("Allow", e.headers.get("allow", "")) if e.headers else ""
        if allow:
            return [m.strip() for m in allow.split(",") if m.strip()]
    except Exception:
        pass
    return []


# ── page title ────────────────────────────────────────────────────────────────


def _extract_title(body: bytes) -> str:
    try:
        text = body[:8192].decode("utf-8", errors="ignore")
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1).strip())[:200]
    except Exception:
        pass
    return ""


# ── security header audit ─────────────────────────────────────────────────────


_SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection",
]


def _sec_header_audit(headers: dict, is_https: bool) -> list[dict]:
    """Return list of {header, present, value, note} dicts."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    results = []
    for h in _SEC_HEADERS:
        present = h.lower() in lower_headers
        val = lower_headers.get(h.lower(), "")
        note = ""
        if h == "Strict-Transport-Security" and not is_https and not present:
            note = "N/A on plain HTTP"
        results.append({"header": h, "present": present, "value": val, "note": note})
    return results


# ── public API ────────────────────────────────────────────────────────────────


def probe(
    url: str,
    timeout: float = 10.0,
    check_favicon: bool = True,
    check_methods: bool = True,
) -> dict:
    """Perform a rich HTTP probe against url.

    Returns a structured dict with all collected data.
    Keys:
      url, final_url, status, redirect_chain, elapsed_ms,
      content_type, content_length, body_size, body_hash,
      title, server, x_powered_by,
      security_headers (list of audit dicts),
      tls (dict, HTTPS only), favicon_hash (str|None),
      allowed_methods (list|None), raw_headers (dict)
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    is_https = scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_https else 80)

    status, headers, body, chain, elapsed, tls_unverified = _fetch_with_redirects(url, timeout)

    lower_h = {k.lower(): v for k, v in headers.items()}

    body_preview = body[:4096]
    body_hash = hashlib.sha256(body_preview).hexdigest() if body_preview else ""
    title = _extract_title(body)

    # When TLS verification was skipped, reuse the CERT_NONE context for
    # favicon and methods probes so they don't fail on the same target.
    aux_ssl_ctx = _no_verify_ssl_ctx() if tls_unverified else None

    # TLS info (for HTTPS targets only — connect to original host, not redirected)
    tls = None
    if is_https:
        tls = _tls_info(host, port, timeout)
    elif len(chain) > 1:
        # If we were redirected to HTTPS, grab TLS info from final URL
        final_parsed = urllib.parse.urlparse(chain[-1])
        if final_parsed.scheme.lower() == "https":
            fhost = final_parsed.hostname or ""
            fport = final_parsed.port or 443
            tls = _tls_info(fhost, fport, timeout)

    fav = _favicon_hash(url, timeout, ssl_ctx=aux_ssl_ctx) if check_favicon else None
    methods = _allowed_methods(chain[-1] if chain else url, timeout, ssl_ctx=aux_ssl_ctx) if check_methods else None

    return {
        "url": url,
        "final_url": chain[-1] if chain else url,
        "status": status,
        "redirect_chain": chain,
        "elapsed_ms": round(elapsed * 1000),
        "content_type": lower_h.get("content-type", ""),
        "content_length": lower_h.get("content-length", ""),
        "body_size": len(body),
        "body_hash": body_hash,
        "title": title,
        "server": lower_h.get("server", ""),
        "x_powered_by": lower_h.get("x-powered-by", ""),
        "security_headers": _sec_header_audit(headers, is_https),
        "tls": tls,
        "tls_unverified": tls_unverified,
        "favicon_hash": fav,
        "allowed_methods": methods,
        "raw_headers": headers,
    }


def format_report(data: dict) -> str:
    """Format probe() output as a human-readable text report."""
    lines: list[str] = []
    a = lines.append

    a(f"HTTP Probe: {data['url']}")
    if data.get("tls_unverified"):
        a("  [MEDIUM] TLS certificate not verified — self-signed or untrusted CA [WSTG-CRYP-01][ASVS-9.2.1]")
        a("           (probe used CERT_NONE fallback; security header results are accurate)")
    a(f"  Status     : {data['status']}")
    if len(data.get("redirect_chain", [])) > 1:
        a(f"  Final URL  : {data['final_url']}")
        a(f"  Redirects  : {' → '.join(data['redirect_chain'])}")
    a(f"  Response   : {data['elapsed_ms']} ms")
    a(f"  Server     : {data.get('server') or '(not disclosed)'}")
    if data.get("x_powered_by"):
        a(f"  X-Powered-By: {data['x_powered_by']}")
    a(f"  Content-Type: {data.get('content_type') or '(none)'}")
    a(f"  Body size  : {data.get('body_size', 0)} bytes")
    a(f"  Body hash  : {data.get('body_hash') or '(empty)'}")
    if data.get("title"):
        a(f"  Page title : {data['title']}")
    if data.get("favicon_hash"):
        a(f"  Favicon SHA256: {data['favicon_hash']}")
    if data.get("allowed_methods"):
        a(f"  HTTP Methods  : {', '.join(data['allowed_methods'])}")

    # TLS
    tls = data.get("tls")
    if tls:
        a("")
        a("TLS Certificate:")
        if "error" in tls:
            a(f"  Error: {tls['error']}")
        else:
            a(f"  Subject CN   : {tls.get('subject_cn')}")
            a(f"  Issuer       : {tls.get('issuer_cn')} / {tls.get('issuer_org')}")
            a(f"  Expires      : {tls.get('not_after')} ({tls.get('days_remaining', '?')} days)")
            a(f"  Protocol     : {tls.get('protocol')}")
            a(f"  Cipher       : {tls.get('cipher')}")
            if tls.get("self_signed"):
                a(f"  [WARN] Self-signed certificate")
            if tls.get("days_remaining") is not None and tls["days_remaining"] < 30:
                a(f"  [WARN] Certificate expires in {tls['days_remaining']} days")
            if tls.get("san"):
                a(f"  SANs         : {', '.join(tls['san'])}")

    # Security headers
    sec = data.get("security_headers", [])
    if sec:
        a("")
        missing = [s for s in sec if not s["present"] and not s.get("note")]
        present = [s for s in sec if s["present"]]
        if missing:
            a("Missing security headers:")
            for s in missing:
                a(f"  ✗ {s['header']}")
        if present:
            a("Present security headers:")
            for s in present:
                a(f"  ✓ {s['header']}: {s['value'][:80]}")
        na = [s for s in sec if s.get("note")]
        if na:
            a("N/A headers:")
            for s in na:
                a(f"  ~ {s['header']} ({s['note']})")

    return "\n".join(lines)
