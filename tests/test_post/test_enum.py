"""Tests for implemented post-exploitation enumeration modules."""

import platform
from functools import cache

import pytest

from post.base import ModuleResult
from post.enum.network import NetworkModule
from post.enum.privesc import PrivescModule
from post.enum.sysinfo import SysinfoModule
from post.enum.users import UsersModule

# All enum modules are Linux/macOS only
pytestmark = pytest.mark.skipif(
    platform.system().lower() == "windows",
    reason="Enum modules not supported on Windows",
)


# ── Helpers ───────────────────────────────────────────────────────────────────


@cache
def _run(module_class):
    """Instantiate and run a module; return the ModuleResult."""
    result = module_class().run({})
    assert isinstance(result, ModuleResult), "run() must return a ModuleResult"
    return result


# ── SysinfoModule ─────────────────────────────────────────────────────────────


class TestSysinfo:
    def test_run_returns_module_result(self):
        _run(SysinfoModule)

    def test_ok_true(self):
        assert _run(SysinfoModule).ok is True

    def test_output_is_string(self):
        assert isinstance(_run(SysinfoModule).output, str)

    def test_output_has_hostname(self):
        assert "Hostname" in _run(SysinfoModule).output

    def test_data_has_required_keys(self):
        data = _run(SysinfoModule).data
        for key in ("hostname", "os", "os_release", "machine"):
            assert key in data, f"Missing key: {key}"

    def test_hostname_is_string(self):
        assert isinstance(_run(SysinfoModule).data["hostname"], str)

    def test_env_dict_present(self):
        data = _run(SysinfoModule).data
        assert "env" in data
        assert isinstance(data["env"], dict)

    def test_container_hints_is_list(self):
        data = _run(SysinfoModule).data
        assert "container_vm_hints" in data
        assert isinstance(data["container_vm_hints"], list)


# ── PrivescModule ─────────────────────────────────────────────────────────────


@pytest.mark.slow  # find / scan can take several minutes on large filesystems
class TestPrivesc:
    def test_run_returns_module_result(self):
        _run(PrivescModule)

    def test_ok_true(self):
        assert _run(PrivescModule).ok is True

    def test_output_is_string(self):
        result = _run(PrivescModule)
        assert isinstance(result.output, str)
        assert len(result.output) > 0

    def test_data_has_all_check_keys(self):
        data = _run(PrivescModule).data
        for key in ("suid_sgid", "sudo", "writable_path", "writable_cron",
                    "docker", "capabilities", "shadow_passwd", "nfs", "env"):
            assert key in data, f"Missing check key: {key}"

    def test_suid_sgid_has_expected_shape(self):
        d = _run(PrivescModule).data["suid_sgid"]
        assert "suid_binaries" in d
        assert "gtfobins_hits" in d
        assert isinstance(d["suid_binaries"], list)
        assert isinstance(d["gtfobins_hits"], list)

    def test_sudo_has_expected_shape(self):
        d = _run(PrivescModule).data["sudo"]
        assert "has_nopasswd" in d
        assert "nopasswd_entries" in d
        assert isinstance(d["has_nopasswd"], bool)

    def test_docker_has_expected_shape(self):
        d = _run(PrivescModule).data["docker"]
        assert "docker_socket_exists" in d
        assert "exploitable" in d

    def test_shadow_has_expected_shape(self):
        d = _run(PrivescModule).data["shadow_passwd"]
        assert "shadow_readable" in d
        assert "passwd_writable" in d
        assert isinstance(d["shadow_readable"], bool)

    def test_writable_path_has_expected_shape(self):
        d = _run(PrivescModule).data["writable_path"]
        assert "path_dirs" in d
        assert "writable" in d
        assert isinstance(d["writable"], list)


# ── UsersModule ───────────────────────────────────────────────────────────────


class TestUsers:
    def test_run_returns_module_result(self):
        _run(UsersModule)

    def test_ok_true(self):
        assert _run(UsersModule).ok is True

    def test_output_has_current_user(self):
        assert "Current user" in _run(UsersModule).output

    def test_current_user_has_required_fields(self):
        u = _run(UsersModule).data["current_user"]
        for field in ("uid", "gid", "username", "groups", "is_root"):
            assert field in u, f"Missing field: {field}"

    def test_uid_is_int(self):
        assert isinstance(_run(UsersModule).data["current_user"]["uid"], int)

    def test_groups_is_list(self):
        assert isinstance(_run(UsersModule).data["current_user"]["groups"], list)

    def test_all_users_is_list(self):
        assert isinstance(_run(UsersModule).data["all_users"], list)

    def test_all_users_not_empty(self):
        # At least one account (current user) must exist
        assert len(_run(UsersModule).data["all_users"]) > 0

    def test_ssh_keys_is_list(self):
        assert isinstance(_run(UsersModule).data["ssh_keys"], list)

    def test_sudo_groups_is_dict(self):
        assert isinstance(_run(UsersModule).data["sudo_groups"], dict)


# ── NetworkModule ─────────────────────────────────────────────────────────────


class TestNetwork:
    def test_run_returns_module_result(self):
        _run(NetworkModule)

    def test_ok_true(self):
        assert _run(NetworkModule).ok is True

    def test_data_has_required_keys(self):
        data = _run(NetworkModule).data
        for key in ("hostname", "interfaces", "routes", "arp_cache",
                    "listening_ports", "hosts_file"):
            assert key in data, f"Missing key: {key}"

    def test_interfaces_is_dict(self):
        assert isinstance(_run(NetworkModule).data["interfaces"], dict)

    def test_listening_ports_is_list(self):
        assert isinstance(_run(NetworkModule).data["listening_ports"], list)

    def test_internal_hosts_seen_is_list(self):
        assert isinstance(_run(NetworkModule).data["internal_hosts_seen"], list)

    def test_hostname_is_string(self):
        assert isinstance(_run(NetworkModule).data["hostname"], str)
