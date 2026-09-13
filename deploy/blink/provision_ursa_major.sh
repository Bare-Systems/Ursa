#!/usr/bin/env bash
set -euo pipefail
umask 077

runtime_dir="{{runtime_dir}}"
config_dir="${runtime_dir}/config"
data_dir="${runtime_dir}/data"
staging_dir="${runtime_dir}/staging"
config_file="${config_dir}/ursa.yaml"
env_file="${runtime_dir}/.env"

mkdir -p "${config_dir}" "${data_dir}/tls" "${staging_dir}"

cat >"${env_file}" <<EOF
COMPOSE_PROJECT_NAME={{compose_project}}
URSA_RUNTIME_DIR={{runtime_dir}}
URSA_PUBLISH_HOST={{publish_host}}
URSA_C2_PORT={{c2_port}}
URSA_CP_PORT={{cp_port}}
URSA_IMAGE_NAME={{image_name}}
EOF

CONFIG_FILE="${config_file}" URSA_TOKEN="${URSA_TOKEN:-}" python3 - <<'PY'
import json
import os
import secrets
from pathlib import Path

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

config_path = Path(os.environ["CONFIG_FILE"])
data = {}

if config_path.exists():
    raw = config_path.read_text().strip()
    if raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            if yaml is not None:
                data = yaml.safe_load(raw) or {}

# Blink is a network-published deployment. Force production validation rather
# than relying on an operator to remember an environment variable.
data["environment"] = "production"

major = data.setdefault("major", {})
major["host"] = "0.0.0.0"
major["port"] = {{c2_port}}
major["db_path"] = "/data/ursa.db"
major.setdefault("traffic_profile", "default")

tls = major.setdefault("tls", {})
tls["enabled"] = True
tls["hostname"] = "{{publish_host}}"
tls["extra_sans"] = ["{{publish_host}}"]
tls["cert_path"] = "/data/tls/cert.pem"
tls["key_path"] = "/data/tls/key.pem"

web = major.setdefault("web", {})
web["host"] = "0.0.0.0"
web["port"] = {{cp_port}}
web["base_path"] = ""
auth = web.setdefault("auth", {})
known_defaults = {
    "ursa-dev-session-secret-change-me",
    "change-me-now",
    "your-shared-bearclaw-token",
    "rotate-this-32-byte-signing-secret",
    "ursa-dev-approval-signing-key",
}

if not auth.get("session_secret") or auth.get("session_secret") in known_defaults:
    auth["session_secret"] = secrets.token_urlsafe(32)
auth.setdefault("bootstrap_username", "admin")
if not auth.get("bootstrap_password") or auth.get("bootstrap_password") in known_defaults:
    auth["bootstrap_password"] = secrets.token_urlsafe(24)
auth.setdefault("bootstrap_role", "admin")
# Bearer token clients (BearClawWeb, the host collector) authenticate with. Seed
# once and preserve thereafter — like session_secret — so deploys never clobber a
# working token. Prefer an injected URSA_TOKEN (so a fresh deploy can match the
# clients' configured token); otherwise generate a strong one. Without this a
# clean deploy leaves api_token empty and the admin API returns 503.
if not auth.get("api_token") or auth.get("api_token") in known_defaults:
    auth["api_token"] = os.environ.get("URSA_TOKEN") or secrets.token_urlsafe(32)
auth.setdefault("api_token_actor", "bearclaw-web")
auth.setdefault("api_token_role", "admin")
auth.setdefault("api_token_scopes", ["*"])
auth.setdefault("api_audience", "ursa-control-plane")
signing_keys = auth.get("api_signing_keys") or []
if isinstance(signing_keys, str):
    signing_keys = [signing_keys]
auth["api_signing_keys"] = [
    secrets.token_urlsafe(32) if key in known_defaults else key
    for key in signing_keys
] or [secrets.token_urlsafe(32)]
auth.setdefault("api_replay_ttl_seconds", 300)

governance = major.setdefault("governance", {})
governance.setdefault("bearclaw_mode", "local")
# Network-published deployments must not silently disable the high-risk gate.
governance["require_step_up_approval"] = True
step_up_risks = governance.get("step_up_risks") or []
if isinstance(step_up_risks, str):
    step_up_risks = [step_up_risks]
governance["step_up_risks"] = sorted(set(step_up_risks) | {"high", "critical"})
if (
    not governance.get("approval_signing_key")
    or governance.get("approval_signing_key") in known_defaults
):
    governance["approval_signing_key"] = secrets.token_urlsafe(32)

config_path.write_text(json.dumps(data, indent=2) + "\n")
PY

chmod 600 "${config_file}" "${env_file}"
docker info >/dev/null
