import json
import os
import subprocess
from pathlib import Path

from major.config import load_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROVISIONER = PROJECT_ROOT / "deploy" / "blink" / "provision_ursa_major.sh"
COMPOSE_FILE = PROJECT_ROOT / "deploy" / "blink" / "ursa-major.compose.yaml"


def _render_provisioner(runtime_dir: Path) -> str:
    rendered = PROVISIONER.read_text(encoding="utf-8")
    replacements = {
        "{{runtime_dir}}": str(runtime_dir),
        "{{compose_project}}": "ursa-test",
        "{{publish_host}}": "127.0.0.1",
        "{{c2_port}}": "6708",
        "{{cp_port}}": "6707",
        "{{image_name}}": "ursa-major:test",
    }
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    return rendered.replace("docker info >/dev/null", "true")


def test_blink_provisioner_replaces_defaults_and_enables_governance(tmp_path):
    runtime_dir = tmp_path / "runtime"
    config_dir = runtime_dir / "config"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "ursa.yaml"
    config_file.write_text(
        json.dumps(
            {
                "major": {
                    "web": {
                        "auth": {
                            "session_secret": "ursa-dev-session-secret-change-me",
                            "bootstrap_password": "change-me-now",
                            "api_signing_keys": ["rotate-this-32-byte-signing-secret"],
                        }
                    },
                    "governance": {
                        "require_step_up_approval": False,
                        "step_up_risks": ["high"],
                        "approval_signing_key": "ursa-dev-approval-signing-key",
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["URSA_TOKEN"] = "t" * 32
    subprocess.run(
        ["bash"],
        input=_render_provisioner(runtime_dir),
        text=True,
        env=env,
        check=True,
    )

    provisioned = json.loads(config_file.read_text(encoding="utf-8"))
    auth = provisioned["major"]["web"]["auth"]
    governance = provisioned["major"]["governance"]

    assert provisioned["environment"] == "production"
    assert auth["session_secret"] != "ursa-dev-session-secret-change-me"
    assert auth["bootstrap_password"] != "change-me-now"
    assert auth["api_token"] == "t" * 32
    assert auth["api_signing_keys"] != ["rotate-this-32-byte-signing-secret"]
    assert governance["require_step_up_approval"] is True
    assert set(governance["step_up_risks"]) >= {"high", "critical"}
    assert governance["approval_signing_key"] != "ursa-dev-approval-signing-key"
    assert config_file.stat().st_mode & 0o777 == 0o600
    assert (runtime_dir / ".env").stat().st_mode & 0o777 == 0o600
    assert load_config(path=config_file).get("environment") == "production"


def test_blink_compose_builds_from_repository_root():
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    assert compose.count("context: ../..") == 2
