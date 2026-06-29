"""
Ursa — Configuration System
============================
Loads config from ursa.yaml with sensible defaults for everything.
Zero-config still works exactly as before.

Search order:
    1. Explicit path passed to load_config()
    2. ./ursa.yaml (project root)
    3. ~/.ursa/config.yaml

Profile support:
    profiles:
      field:
        major:
          port: 443

    Profile values override base config. CLI flags override profiles.
"""

from copy import deepcopy
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


# ── Defaults ──

PROJECT_ROOT = Path(__file__).parent.parent

DEFAULTS = {
    "major": {
        "host": "0.0.0.0",
        "port": 6708,
        "db_path": str(PROJECT_ROOT / "major" / "ursa.db"),
        "stale_threshold": 300,
        "reaper_interval": 30,
        "server_header": "nginx/1.24.0",
        "web": {
            "host": "0.0.0.0",
            "port": 8080,
            "base_path": "",
            "auth": {
                "session_secret": "ursa-dev-session-secret-change-me",
                "bootstrap_username": "admin",
                "bootstrap_password": "change-me-now",
                "bootstrap_role": "admin",
                # Migration static token. Role/scopes are server-side and
                # request headers are not authoritative.
                "api_token": "",
                "api_token_actor": "bearclaw-web",
                "api_token_role": "admin",
                "api_token_scopes": ["*"],
                "api_tokens": [],
                # Preferred service-token mode. Clients mint short-lived
                # ursa.v1 tokens signed by the first key; all keys verify.
                "api_signing_keys": [],
                "api_audience": "ursa-control-plane",
                "api_replay_ttl_seconds": 300,
            },
        },
        "implant_defaults": {
            "beacon_interval": 5,
            "jitter": 0.1,
        },
        # Traffic profile — controls URL paths and response headers
        # Options: default | jquery | office365 | github-api
        "traffic_profile": "default",
        # TLS / HTTPS configuration
        "tls": {
            "enabled": False,
            # Hostname for the self-signed cert SAN (defaults to machine FQDN)
            "hostname": "",
            # Additional SANs — list of hostnames or IPs
            "extra_sans": [],
            # Cert validity in days
            "cert_days": 365,
            # Explicit cert/key paths (leave empty to auto-generate in major/tls/)
            "cert_path": "",
            "key_path": "",
        },
        # HTTP redirector — transparent forwarding proxy for OPSEC
        "redirector": {
            "enabled": False,
            "listen_host": "0.0.0.0",
            "listen_port": 80,
            # Where to forward matched traffic (your actual C2)
            "upstream_url": "http://127.0.0.1:6708",
            # Only forward requests matching these path prefixes
            # Empty list = forward everything
            "allowed_paths": [],
            # Reject beacons that don't contain this UA fragment
            "user_agent_filter": "",
            # Set false for self-signed upstream certs (typical for C2 HTTPS)
            "verify_tls": False,
            "upstream_timeout": 10,
        },
        # Trusted redirector IPs — X-Forwarded-For from these IPs is trusted
        # to contain the real implant IP (set to your redirector IP)
        "trusted_redirectors": [],
        # Auto-recon — queue an initial recon sequence on first beacon check-in
        "auto_recon": {
            "enabled": False,
            "modules": [
                "enum/sysinfo",
                "enum/users",
                "enum/privesc",
                "enum/network",
                "enum/loot",
            ],
        },
        # Pi-hole DNS insight — read-only access to the FTL long-term query DB
        # for per-client "what is it talking to" telemetry (ROADMAP Phase 5B).
        "pihole": {
            # Path to pihole-FTL.db. On the homelab this is bind-mounted from the
            # Pi-hole container; default matches a standard Pi-hole install.
            "db_path": "/etc/pihole/pihole-FTL.db",
        },
        "governance": {
            # Route policy decisions through the BearClaw enforcement path.
            # "local" performs local policy checks compatible with BearClaw inputs.
            "bearclaw_mode": "local",
            # Enforce step-up approval for high-risk operations.
            "require_step_up_approval": False,
            # Risk tiers that require approval when step-up is enabled.
            "step_up_risks": ["high", "critical"],
            # HMAC key for signing approval decisions in immutable audit details.
            "approval_signing_key": "ursa-dev-approval-signing-key",
        },
    },
    "minor": {
        "default_timeout": 3,
        "scan_threads": 100,
        "dirbust_threads": 20,
        "credential_threads": 5,
        "subdomain_threads": 50,
        "arp_spoof_max_duration": 300,
        "results_dir": str(Path.home() / ".ursa" / "results"),
    },
    "profiles": {},
}


# ── Config Class ──

class UrsaConfig:
    """Nested config with dotted-path access."""

    def __init__(self, data: dict):
        self._data = data

    def get(self, path: str, default=None):
        """Get a value by dotted path: cfg.get('major.port', 6708)"""
        keys = path.split(".")
        current = self._data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    @property
    def raw(self) -> dict:
        return self._data


# ── Loader ──

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins on conflicts."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _find_config_file() -> Path | None:
    """Search for ursa.yaml in standard locations."""
    candidates = [
        PROJECT_ROOT / "ursa.yaml",
        Path.home() / ".ursa" / "config.yaml",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def load_config(path: str | Path | None = None, profile: str | None = None) -> UrsaConfig:
    """Load configuration from YAML file with defaults.

    Args:
        path: Explicit config file path. If None, searches standard locations.
        profile: Profile name to apply on top of base config.

    Returns:
        UrsaConfig instance with merged values.
    """
    config = deepcopy(DEFAULTS)

    # Find and load YAML
    config_path = Path(path) if path else _find_config_file()

    if config_path and config_path.exists():
        if yaml is None:
            import warnings
            warnings.warn(
                f"Found {config_path} but pyyaml is not installed. "
                "Using defaults. Install with: pip install pyyaml",
                stacklevel=2,
            )
        else:
            with open(config_path) as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)

    # Apply profile if specified
    if profile and profile in config.get("profiles", {}):
        profile_data = config["profiles"][profile]
        config = _deep_merge(config, profile_data)  # type: ignore[arg-type]

    # Resolve relative db_path to absolute
    db_path = Path(str(config["major"]["db_path"]))
    if not db_path.is_absolute():
        config["major"]["db_path"] = str(PROJECT_ROOT / db_path)

    return UrsaConfig(config)


# ── Module-level singleton ──
# Loaded once on import, can be reloaded with load_config()

_cfg = None


def get_config() -> UrsaConfig:
    """Get the global config singleton. Lazy-loaded on first call."""
    global _cfg
    if _cfg is None:
        _cfg = load_config()
    return _cfg


def reload_config(path: str | Path | None = None, profile: str | None = None) -> UrsaConfig:
    """Reload config (e.g. after CLI arg parsing)."""
    global _cfg
    _cfg = load_config(path=path, profile=profile)
    return _cfg
