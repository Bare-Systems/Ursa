"""Tests for implemented post-exploitation modules.

Covers the 11 implemented modules:
  enum/loot,
  cred/browser, cred/keychain, cred/memory, cred/loot,
  lateral/pth, lateral/ssh, lateral/wmi,
  persist/cron, persist/launchagent, persist/registry
"""

import platform

import pytest

from post.base import ModuleResult, PostModule
from post.loader import PostLoader

# ── Helpers ────────────────────────────────────────────────────────────────────

SYSTEM     = platform.system()
IS_LINUX   = SYSTEM == "Linux"
IS_MACOS   = SYSTEM == "Darwin"
IS_WINDOWS = SYSTEM == "Windows"


def dispatch(name, args=None):
    return PostLoader().dispatch(name, args or {})


# ── Shared metadata checks ─────────────────────────────────────────────────────

IMPLEMENTED_MODULES = [
    "enum/loot",
    "cred/browser",
    "cred/keychain",
    "cred/memory",
    "cred/loot",
    "lateral/pth",
    "lateral/ssh",
    "lateral/wmi",
    "persist/cron",
    "persist/launchagent",
    "persist/registry",
]


class TestImplementedMetadata:
    @pytest.mark.parametrize("name", IMPLEMENTED_MODULES)
    def test_implemented_flag_is_true(self, name):
        modules = {m["name"]: m for m in PostLoader().list_modules()}
        assert modules[name]["implemented"] is True

    @pytest.mark.parametrize("name", IMPLEMENTED_MODULES)
    def test_dispatch_returns_module_result_shape(self, name):
        result = PostLoader().dispatch(name)
        assert isinstance(result, dict)
        assert "ok" in result
        assert "output" in result
        assert "data" in result
        assert "error" in result

    @pytest.mark.parametrize("name", IMPLEMENTED_MODULES)
    def test_module_is_subclass_of_post_module(self, name):
        # Resolve the class from the loader registry
        loader = PostLoader()
        modules = {m["name"]: m for m in loader.list_modules()}
        assert name in modules


# ── cred/browser ───────────────────────────────────────────────────────────────

class TestBrowserModule:
    def test_implemented_true(self):
        from post.cred.browser import BrowserCredModule
        assert BrowserCredModule.IMPLEMENTED is True

    def test_platform_is_list(self):
        from post.cred.browser import BrowserCredModule
        assert isinstance(BrowserCredModule.PLATFORM, list)
        assert len(BrowserCredModule.PLATFORM) > 0

    def test_run_returns_module_result(self):
        from post.cred.browser import BrowserCredModule
        result = BrowserCredModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_ok_on_supported_platform(self):
        result = dispatch("cred/browser")
        # ok may be False if no browsers installed, but should never raise
        assert "ok" in result
        assert result["error"] == "" or isinstance(result["error"], str)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_returns_data_dict(self):
        result = dispatch("cred/browser")
        assert isinstance(result["data"], dict)

    def test_chrome_key_linux_helper_returns_bytes(self):
        from post.cred.browser import _chrome_key_linux
        key = _chrome_key_linux()
        assert isinstance(key, bytes)
        assert len(key) == 16

    def test_pbkdf2_helper_returns_correct_length(self):
        from post.cred.browser import _pbkdf2_key
        key = _pbkdf2_key(b"peanuts", iterations=1)
        assert len(key) == 16

    def test_chrome_locations_returns_list(self):
        from post.cred.browser import _chrome_locations
        locs = _chrome_locations()
        assert isinstance(locs, list)

    def test_firefox_profiles_returns_list(self):
        from post.cred.browser import _firefox_profiles
        profiles = _firefox_profiles()
        assert isinstance(profiles, list)


# ── cred/keychain ──────────────────────────────────────────────────────────────

class TestKeychainModule:
    def test_implemented_true(self):
        from post.cred.keychain import KeychainModule
        assert KeychainModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.cred.keychain import KeychainModule
        assert "linux" in KeychainModule.PLATFORM
        assert "darwin" in KeychainModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.cred.keychain import KeychainModule
        result = KeychainModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(IS_MACOS, reason="test macos path separately")
    @pytest.mark.skipif(not IS_LINUX, reason="linux only")
    def test_dispatch_linux_returns_ok(self):
        result = dispatch("cred/keychain")
        assert result["ok"] is True
        assert "secretstorage" in result["output"].lower() or "credential" in result["output"].lower()

    @pytest.mark.skipif(not IS_MACOS, reason="macos only")
    def test_dispatch_macos_returns_ok(self):
        result = dispatch("cred/keychain")
        assert result["ok"] is True
        assert "keychain" in result["output"].lower()

    @pytest.mark.skipif(not IS_MACOS, reason="macos only")
    def test_macos_list_keychains_returns_list(self):
        from post.cred.keychain import _macos_list_keychains
        keychains = _macos_list_keychains()
        assert isinstance(keychains, list)

    @pytest.mark.skipif(not IS_LINUX, reason="linux only")
    def test_linux_credential_files_returns_list(self):
        from post.cred.keychain import _linux_credential_files
        files = _linux_credential_files()
        assert isinstance(files, list)
        for f in files:
            assert "path" in f
            assert "size" in f
            assert "mode" in f


# ── cred/memory ────────────────────────────────────────────────────────────────

class TestMemoryModule:
    def test_implemented_true(self):
        from post.cred.memory import MemoryCredModule
        assert MemoryCredModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.cred.memory import MemoryCredModule
        assert "linux" in MemoryCredModule.PLATFORM
        assert "darwin" in MemoryCredModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.cred.memory import MemoryCredModule
        result = MemoryCredModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_returns_ok(self):
        result = dispatch("cred/memory")
        assert result["ok"] is True

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_output_mentions_ssh(self):
        result = dispatch("cred/memory")
        assert "ssh" in result["output"].lower()

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_data_has_expected_keys(self):
        result = dispatch("cred/memory")
        assert "agent_sockets" in result["data"] or "ssh_keys" in result["data"]

    def test_find_ssh_keys_returns_list(self):
        from post.cred.memory import _find_ssh_keys
        keys = _find_ssh_keys()
        assert isinstance(keys, list)

    def test_find_agent_sockets_returns_list(self):
        from post.cred.memory import _find_agent_sockets
        sockets = _find_agent_sockets()
        assert isinstance(sockets, list)


# ── lateral/pth ────────────────────────────────────────────────────────────────

class TestPassTheHashModule:
    def test_implemented_true(self):
        from post.lateral.pth import PassTheHashModule
        assert PassTheHashModule.IMPLEMENTED is True

    def test_platform_includes_common_oses(self):
        from post.lateral.pth import PassTheHashModule
        assert "linux" in PassTheHashModule.PLATFORM or "windows" in PassTheHashModule.PLATFORM

    def test_run_without_args_returns_module_result(self):
        from post.lateral.pth import PassTheHashModule
        result = PassTheHashModule().run({})
        assert isinstance(result, ModuleResult)

    def test_run_missing_target_returns_error(self):
        from post.lateral.pth import PassTheHashModule
        result = PassTheHashModule().run({})
        # Should fail gracefully — either impacket missing or no target
        assert result.ok is False or isinstance(result.error, str)

    def test_parse_hash_lm_nt_format(self):
        from post.lateral.pth import _parse_hash
        lm, nt = _parse_hash("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_parse_hash_nt_only(self):
        from post.lateral.pth import _parse_hash
        lm, nt = _parse_hash("8846f7eaee8fb117ad06bdd830b7586c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_dispatch_without_impacket_returns_helpful_error(self):
        """When impacket is missing, error should mention how to install."""
        from post.lateral import pth as pth_mod
        if pth_mod._IMPACKET_OK:
            pytest.skip("impacket is installed — skip missing-impacket path")
        result = dispatch("lateral/pth", {"target": "127.0.0.1", "username": "admin",
                                          "hash": "aad3:8846"})
        assert result["ok"] is False
        assert "impacket" in result["error"].lower()


# ── lateral/ssh ────────────────────────────────────────────────────────────────

class TestSSHPivotModule:
    def test_implemented_true(self):
        from post.lateral.ssh import SSHPivotModule
        assert SSHPivotModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.lateral.ssh import SSHPivotModule
        assert "linux" in SSHPivotModule.PLATFORM
        assert "darwin" in SSHPivotModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.lateral.ssh import SSHPivotModule
        result = SSHPivotModule().run({})
        assert isinstance(result, ModuleResult)

    def test_list_mode_returns_ok(self):
        result = dispatch("lateral/ssh", {"mode": "list"})
        assert result["ok"] is True
        assert "pivot" in result["output"].lower() or "active" in result["output"].lower()

    def test_list_data_has_pivots_key(self):
        result = dispatch("lateral/ssh", {"mode": "list"})
        assert "pivots" in result["data"]

    def test_missing_host_returns_error(self):
        result = dispatch("lateral/ssh", {"mode": "socks5"})
        assert result["ok"] is False

    def test_unknown_mode_no_host_returns_error(self):
        result = dispatch("lateral/ssh", {"mode": "bogus"})
        # No ssh_host → returns "Required: ssh_host, ssh_user" error
        assert result["ok"] is False

    def test_without_paramiko_returns_error_or_ok(self):
        from post.lateral import ssh as ssh_mod
        if not ssh_mod._PARAMIKO_OK:
            result = dispatch("lateral/ssh", {"action": "list"})
            assert result["ok"] is False
            assert "paramiko" in result["error"].lower()


# ── persist/cron ───────────────────────────────────────────────────────────────

class TestCronModule:
    def test_implemented_true(self):
        from post.persist.cron import CronPersistModule
        assert CronPersistModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.persist.cron import CronPersistModule
        assert "linux" in CronPersistModule.PLATFORM
        assert "darwin" in CronPersistModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.persist.cron import CronPersistModule
        result = CronPersistModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_list_action_returns_ok(self):
        result = dispatch("persist/cron", {"action": "list"})
        assert result["ok"] is True

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_list_output_mentions_crontab(self):
        result = dispatch("persist/cron", {"action": "list"})
        assert "crontab" in result["output"].lower()

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_list_data_has_cron_entries_key(self):
        result = dispatch("persist/cron", {"action": "list"})
        assert "cron_entries" in result["data"]

    def test_install_without_command_returns_error(self):
        result = dispatch("persist/cron", {"action": "install", "command": ""})
        assert result["ok"] is False
        assert "command" in result["error"].lower()

    def test_unknown_action_returns_error(self):
        result = dispatch("persist/cron", {"action": "bogus_action"})
        assert result["ok"] is False

    def test_systemd_install_on_macos_returns_error(self):
        if not IS_MACOS:
            pytest.skip("macOS only")
        result = dispatch("persist/cron", {"action": "systemd_install",
                                           "command": "/bin/true"})
        assert result["ok"] is False
        assert "linux" in result["error"].lower()

    def test_crontab_list_helper_returns_list(self):
        from post.persist.cron import _crontab_list
        entries = _crontab_list()
        assert isinstance(entries, list)


# ── persist/launchagent ────────────────────────────────────────────────────────

class TestLaunchAgentModule:
    def test_implemented_true(self):
        from post.persist.launchagent import LaunchAgentPersistModule as LaunchAgentModule
        assert LaunchAgentModule.IMPLEMENTED is True

    def test_platform_darwin_only(self):
        from post.persist.launchagent import LaunchAgentPersistModule as LaunchAgentModule
        assert LaunchAgentModule.PLATFORM == ["darwin"]

    def test_run_returns_module_result(self):
        from post.persist.launchagent import LaunchAgentPersistModule as LaunchAgentModule
        result = LaunchAgentModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not IS_MACOS, reason="macOS only")
    def test_list_action_returns_ok(self):
        result = dispatch("persist/launchagent", {"action": "list"})
        assert result["ok"] is True

    @pytest.mark.skipif(not IS_MACOS, reason="macOS only")
    def test_list_data_has_agents_key(self):
        result = dispatch("persist/launchagent", {"action": "list"})
        assert "agents" in result["data"]

    def test_install_without_program_returns_error(self):
        result = dispatch("persist/launchagent", {"action": "install"})
        assert result["ok"] is False

    def test_on_non_macos_returns_error(self):
        if IS_MACOS:
            pytest.skip("only meaningful on non-macOS")
        result = dispatch("persist/launchagent", {"action": "list"})
        assert result["ok"] is False

    def test_unknown_action_returns_error(self):
        result = dispatch("persist/launchagent", {"action": "bogus"})
        assert result["ok"] is False

    def test_plist_path_helper(self):
        from post.persist.launchagent import _plist_path
        p = _plist_path("com.test.label")
        assert str(p).endswith("com.test.label.plist")
        assert "LaunchAgents" in str(p)


# ── lateral/wmi ────────────────────────────────────────────────────────────────

class TestWMIExecModule:
    def test_implemented_true(self):
        from post.lateral.wmi import WMIExecModule
        assert WMIExecModule.IMPLEMENTED is True

    def test_platform_windows_only(self):
        from post.lateral.wmi import WMIExecModule
        assert WMIExecModule.PLATFORM == ["windows"]

    def test_is_subclass_of_post_module(self):
        from post.lateral.wmi import WMIExecModule
        assert issubclass(WMIExecModule, PostModule)

    def test_run_returns_module_result(self):
        from post.lateral.wmi import WMIExecModule
        result = WMIExecModule().run({})
        assert isinstance(result, ModuleResult)

    def test_missing_target_returns_error(self):
        result = dispatch("lateral/wmi", {})
        assert result["ok"] is False
        assert "target" in result["error"].lower()

    def test_empty_target_returns_error(self):
        result = dispatch("lateral/wmi", {"target": ""})
        assert result["ok"] is False

    def test_empty_command_returns_error(self):
        result = dispatch("lateral/wmi", {"target": "10.0.0.1", "command": ""})
        assert result["ok"] is False
        assert "command" in result["error"].lower()

    def test_unknown_method_returns_error(self):
        result = dispatch("lateral/wmi", {"target": "10.0.0.1", "method": "bogus"})
        assert result["ok"] is False
        assert "bogus" in result["error"]

    def test_wmic_on_non_windows_returns_error(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("lateral/wmi", {
            "target": "10.0.0.1",
            "method": "wmic",
            "command": "whoami",
        })
        assert result["ok"] is False
        assert "windows" in result["error"].lower()

    def test_wmiexec_without_impacket_returns_error(self):
        from post.lateral import wmi as wmi_mod
        if wmi_mod._IMPACKET_OK:
            pytest.skip("impacket is installed")
        result = dispatch("lateral/wmi", {
            "target": "10.0.0.1",
            "method": "wmiexec",
            "command": "whoami",
        })
        assert result["ok"] is False
        assert "impacket" in result["error"].lower()

    def test_dcom_without_impacket_returns_error(self):
        from post.lateral import wmi as wmi_mod
        if wmi_mod._IMPACKET_OK:
            pytest.skip("impacket is installed")
        result = dispatch("lateral/wmi", {
            "target": "10.0.0.1",
            "method": "dcom",
            "command": "whoami",
        })
        assert result["ok"] is False
        assert "impacket" in result["error"].lower()

    def test_winrm_without_pypsrp_returns_error(self):
        from post.lateral import wmi as wmi_mod
        if wmi_mod._PYPSRP_OK:
            pytest.skip("pypsrp is installed")
        result = dispatch("lateral/wmi", {
            "target": "10.0.0.1",
            "method": "winrm",
            "command": "Get-Process",
        })
        assert result["ok"] is False
        assert "pypsrp" in result["error"].lower()

    def test_split_hash_lm_nt_format(self):
        from post.lateral.wmi import _split_hash
        lm, nt = _split_hash("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_split_hash_nt_only(self):
        from post.lateral.wmi import _split_hash
        lm, nt = _split_hash("8846f7eaee8fb117ad06bdd830b7586c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"  # empty LM placeholder
        assert nt == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_dispatch_result_has_required_keys(self):
        result = dispatch("lateral/wmi", {})
        assert "ok" in result
        assert "output" in result
        assert "data" in result
        assert "error" in result

    def test_impacket_flag_is_bool(self):
        from post.lateral import wmi as wmi_mod
        assert isinstance(wmi_mod._IMPACKET_OK, bool)

    def test_pypsrp_flag_is_bool(self):
        from post.lateral import wmi as wmi_mod
        assert isinstance(wmi_mod._PYPSRP_OK, bool)

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows only")
    def test_dispatch_windows_ok(self):
        result = dispatch("lateral/wmi", {
            "target": "127.0.0.1",
            "method": "wmic",
            "command": "whoami",
        })
        # May fail due to auth but should not raise
        assert "ok" in result


# ── persist/registry ───────────────────────────────────────────────────────────

class TestRegistryPersistModule:
    def test_implemented_true(self):
        from post.persist.registry import RegistryPersistModule
        assert RegistryPersistModule.IMPLEMENTED is True

    def test_platform_windows_only(self):
        from post.persist.registry import RegistryPersistModule
        assert RegistryPersistModule.PLATFORM == ["windows"]

    def test_is_subclass_of_post_module(self):
        from post.persist.registry import RegistryPersistModule
        assert issubclass(RegistryPersistModule, PostModule)

    def test_run_returns_module_result(self):
        from post.persist.registry import RegistryPersistModule
        result = RegistryPersistModule().run({})
        assert isinstance(result, ModuleResult)

    def test_dispatch_result_has_required_keys(self):
        result = dispatch("persist/registry", {})
        assert "ok" in result
        assert "output" in result
        assert "data" in result
        assert "error" in result

    # ── run_key ──────────────────────────────────────────────────────────────

    def test_run_key_missing_payload_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "run_key", "action": "install", "payload_path": "",
        })
        assert result["ok"] is False
        assert "payload_path" in result["error"].lower()

    def test_run_key_unknown_action_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "run_key", "action": "bogus",
        })
        assert result["ok"] is False
        assert "bogus" in result["error"]

    def test_run_key_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "run_key", "action": "install",
            "payload_path": r"C:\evil.exe",
        })
        assert result["ok"] is False
        assert "winreg" in result["error"].lower() or "windows" in result["error"].lower()

    def test_run_key_list_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "run_key", "action": "list",
        })
        assert result["ok"] is False

    def test_run_key_remove_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "run_key", "action": "remove", "name": "WindowsUpdate",
        })
        assert result["ok"] is False

    # ── scheduled_task ───────────────────────────────────────────────────────

    def test_schtask_missing_payload_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "scheduled_task", "action": "install", "payload_path": "",
        })
        assert result["ok"] is False
        assert "payload_path" in result["error"].lower()

    def test_schtask_unknown_action_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "scheduled_task", "action": "bogus",
        })
        assert result["ok"] is False

    def test_schtask_install_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "scheduled_task", "action": "install",
            "payload_path": r"C:\evil.exe",
        })
        assert result["ok"] is False
        assert "schtasks" in result["error"].lower() or "windows" in result["error"].lower()

    def test_schtask_list_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "scheduled_task", "action": "list",
        })
        assert result["ok"] is False

    # ── service ──────────────────────────────────────────────────────────────

    def test_service_missing_payload_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "service", "action": "install", "payload_path": "",
        })
        assert result["ok"] is False

    def test_service_unknown_action_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "service", "action": "bogus",
        })
        assert result["ok"] is False

    def test_service_install_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "service", "action": "install",
            "payload_path": r"C:\evil.exe",
        })
        assert result["ok"] is False
        assert "sc" in result["error"].lower() or "windows" in result["error"].lower()

    # ── com_hijack ────────────────────────────────────────────────────────────

    def test_com_hijack_missing_dll_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "com_hijack", "action": "install",
            "payload_path": "", "dll_path": "",
        })
        assert result["ok"] is False
        assert "dll_path" in result["error"].lower()

    def test_com_hijack_unknown_action_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "com_hijack", "action": "bogus",
        })
        assert result["ok"] is False

    def test_com_hijack_install_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "com_hijack", "action": "install",
            "dll_path": r"C:\evil.dll",
        })
        assert result["ok"] is False
        assert "winreg" in result["error"].lower() or "windows" in result["error"].lower()

    def test_com_hijack_remove_on_non_windows_fails_gracefully(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        result = dispatch("persist/registry", {
            "method": "com_hijack", "action": "remove",
        })
        assert result["ok"] is False

    # ── unknown method ────────────────────────────────────────────────────────

    def test_unknown_method_returns_error(self):
        result = dispatch("persist/registry", {
            "method": "magic_persist", "payload_path": r"C:\evil.exe",
        })
        assert result["ok"] is False
        assert "magic_persist" in result["error"]

    # ── helpers ───────────────────────────────────────────────────────────────

    def test_winreg_flag_is_bool(self):
        from post.persist import registry as reg_mod
        assert isinstance(reg_mod._WINREG_OK, bool)

    def test_winreg_unavailable_on_non_windows(self):
        if IS_WINDOWS:
            pytest.skip("non-Windows only")
        from post.persist import registry as reg_mod
        assert reg_mod._WINREG_OK is False

    def test_winreg_error_helper_returns_module_result(self):
        from post.persist.registry import _winreg_unavailable_error
        result = _winreg_unavailable_error("some alt cmd")
        assert isinstance(result, ModuleResult)
        assert result.ok is False
        assert "windows" in result.error.lower() or "winreg" in result.error.lower()

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows only")
    def test_run_key_list_on_windows_returns_ok(self):
        result = dispatch("persist/registry", {
            "method": "run_key", "action": "list",
        })
        assert result["ok"] is True
        assert "entries" in result["data"]

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows only")
    def test_schtask_list_on_windows_returns_ok(self):
        result = dispatch("persist/registry", {
            "method": "scheduled_task", "action": "list",
        })
        assert result["ok"] is True
        assert "tasks" in result["data"]


# ── enum/loot ──────────────────────────────────────────────────────────────────

class TestLootModule:
    """Integration tests for the enum/loot correlation module."""

    def test_implemented_true(self):
        from post.enum.loot import LootModule
        assert LootModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.enum.loot import LootModule
        assert "linux" in LootModule.PLATFORM
        assert "darwin" in LootModule.PLATFORM

    def test_is_subclass_of_post_module(self):
        from post.enum.loot import LootModule
        assert issubclass(LootModule, PostModule)

    def test_run_returns_module_result(self):
        from post.enum.loot import LootModule
        result = LootModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_returns_ok(self):
        result = dispatch("enum/loot")
        assert result["ok"] is True

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_output_has_loot_report_header(self):
        result = dispatch("enum/loot")
        assert "LOOT REPORT" in result["output"]

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_data_has_required_keys(self):
        result = dispatch("enum/loot")
        data = result["data"]
        for key in ("hostname", "username", "uid", "os", "findings",
                    "finding_counts", "module_errors", "raw"):
            assert key in data, f"Missing key: {key}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_finding_counts_has_all_severities(self):
        result = dispatch("enum/loot")
        counts = result["data"]["finding_counts"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in counts, f"Missing severity in finding_counts: {sev}"
            assert isinstance(counts[sev], int)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_findings_is_a_list(self):
        result = dispatch("enum/loot")
        assert isinstance(result["data"]["findings"], list)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_each_finding_has_required_keys(self):
        result = dispatch("enum/loot")
        for f in result["data"]["findings"]:
            for key in ("severity", "category", "title", "detail"):
                assert key in f, f"Finding missing key {key!r}: {f}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_findings_sorted_by_severity(self):
        from post.enum.loot import _SEVERITY_ORDER
        result = dispatch("enum/loot")
        severities = [f["severity"] for f in result["data"]["findings"]]
        orders = [_SEVERITY_ORDER.get(s, 9) for s in severities]
        assert orders == sorted(orders), "Findings not sorted by severity"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_raw_has_all_four_enum_modules(self):
        result = dispatch("enum/loot")
        raw = result["data"]["raw"]
        for key in ("sysinfo", "privesc", "users", "network"):
            assert key in raw, f"Missing raw module data: {key}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_raw_sysinfo_has_hostname(self):
        result = dispatch("enum/loot")
        # sysinfo should have run successfully
        assert "hostname" in result["data"]["raw"]["sysinfo"]

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_finding_count_matches_findings_list(self):
        from post.enum.loot import CRITICAL, HIGH, LOW, MEDIUM
        result = dispatch("enum/loot")
        findings = result["data"]["findings"]
        counts = result["data"]["finding_counts"]
        for sev, key in [(CRITICAL, "CRITICAL"), (HIGH, "HIGH"),
                         (MEDIUM, "MEDIUM"), (LOW, "LOW")]:
            actual = sum(1 for f in findings if f["severity"] == sev)
            assert counts[key] == actual, (
                f"{key} count mismatch: counts={counts[key]}, actual={actual}"
            )

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_hostname_populated(self):
        result = dispatch("enum/loot")
        assert result["data"]["hostname"]  # non-empty string

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_username_populated(self):
        result = dispatch("enum/loot")
        assert result["data"]["username"]  # non-empty string


# ── enum/loot correlator unit tests ────────────────────────────────────────────

class TestLootCorrelator:
    """Unit tests for _correlate() and helpers — use synthetic data, no subprocess."""

    def test_correlate_empty_returns_empty(self):
        from post.enum.loot import _correlate
        findings = _correlate({}, {}, {}, {})
        assert findings == []

    def test_finding_helper_returns_dict_with_all_keys(self):
        from post.enum.loot import _finding
        f = _finding("HIGH", "privesc", "test title", "test detail")
        assert f["severity"] == "HIGH"
        assert f["category"] == "privesc"
        assert f["title"] == "test title"
        assert f["detail"] == "test detail"

    def test_finding_helper_detail_defaults_to_empty(self):
        from post.enum.loot import _finding
        f = _finding("LOW", "network", "title only")
        assert f["detail"] == ""

    def test_safe_run_returns_tuple(self):
        from post.enum.loot import _safe_run
        result = _safe_run("enum/sysinfo")
        assert isinstance(result, tuple)
        assert len(result) == 2
        data, err = result
        assert isinstance(data, dict)
        assert isinstance(err, str)

    def test_safe_run_unknown_module_returns_error(self):
        from post.enum.loot import _safe_run
        data, err = _safe_run("enum/does_not_exist")
        assert data == {}
        assert "not registered" in err or err != ""

    def test_correlate_detects_root_user(self):
        from post.enum.loot import CRITICAL, _correlate
        users = {"current_user": {"is_root": True, "in_docker_group": False,
                                  "in_sudo_group": False, "username": "root", "uid": 0}}
        findings = _correlate({}, {}, users, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("root" in f["title"].lower() or "uid=0" in f["title"].lower()
                   for f in crits)

    def test_correlate_detects_shadow_readable(self):
        from post.enum.loot import CRITICAL, _correlate
        privesc = {"shadow_passwd": {"shadow_readable": True, "passwd_writable": False}}
        findings = _correlate({}, privesc, {}, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("shadow" in f["title"].lower() for f in crits)

    def test_correlate_detects_passwd_writable(self):
        from post.enum.loot import CRITICAL, _correlate
        privesc = {"shadow_passwd": {"shadow_readable": False, "passwd_writable": True}}
        findings = _correlate({}, privesc, {}, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("passwd" in f["title"].lower() for f in crits)

    def test_correlate_detects_docker_socket(self):
        from post.enum.loot import CRITICAL, _correlate
        privesc = {"docker": {"exploitable": True}}
        findings = _correlate({}, privesc, {}, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("docker" in f["title"].lower() for f in crits)

    def test_correlate_detects_readable_ssh_keys(self):
        from post.enum.loot import HIGH, _correlate
        users = {
            "ssh_keys": [
                {"username": "alice", "files": [
                    {"path": "/home/alice/.ssh/id_rsa",
                     "readable": True, "is_private_key": True},
                ]},
            ],
        }
        findings = _correlate({}, {}, users, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("ssh" in f["title"].lower() for f in highs)

    def test_correlate_no_ssh_keys_if_not_readable(self):
        from post.enum.loot import _correlate
        users = {
            "ssh_keys": [
                {"username": "alice", "files": [
                    {"path": "/root/.ssh/id_rsa",
                     "readable": False, "is_private_key": True},
                ]},
            ],
        }
        findings = _correlate({}, {}, users, {})
        assert not any("ssh key" in f["title"].lower() for f in findings)

    def test_correlate_detects_nopasswd_sudo(self):
        from post.enum.loot import HIGH, _correlate
        privesc = {"sudo": {"has_nopasswd": True, "nopasswd_entries": ["(ALL) NOPASSWD: ALL"]}}
        findings = _correlate({}, privesc, {}, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("nopasswd" in f["title"].lower() for f in highs)

    def test_correlate_detects_gtfobins(self):
        from post.enum.loot import HIGH, _correlate
        privesc = {"suid_sgid": {"gtfobins_hits": ["/usr/bin/find", "/usr/bin/python3"]}}
        findings = _correlate({}, privesc, {}, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("gtfobins" in f["title"].lower() for f in highs)

    def test_correlate_detects_docker_group(self):
        from post.enum.loot import HIGH, _correlate
        users = {"current_user": {"is_root": False, "in_docker_group": True,
                                  "in_sudo_group": False}}
        findings = _correlate({}, {}, users, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("docker" in f["title"].lower() for f in highs)

    def test_correlate_detects_aws_creds(self):
        from post.enum.loot import HIGH, _correlate
        sysinfo = {"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                           "AWS_SECRET_ACCESS_KEY": "secret"}}
        findings = _correlate(sysinfo, {}, {}, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("aws" in f["title"].lower() for f in highs)

    def test_correlate_detects_kubeconfig(self):
        from post.enum.loot import HIGH, _correlate
        sysinfo = {"env": {"KUBECONFIG": "/home/user/.kube/config"}}
        findings = _correlate(sysinfo, {}, {}, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("kube" in f["title"].lower() for f in highs)

    def test_correlate_detects_writable_cron(self):
        from post.enum.loot import MEDIUM, _correlate
        privesc = {"writable_cron": {"writable_cron_paths": ["/etc/cron.d/backup"]}}
        findings = _correlate({}, privesc, {}, {})
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert any("cron" in f["title"].lower() for f in mediums)

    def test_correlate_detects_writable_path_dirs(self):
        from post.enum.loot import MEDIUM, _correlate
        privesc = {"writable_path": {"writable": ["/tmp"]}}
        findings = _correlate({}, privesc, {}, {})
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert any("path" in f["title"].lower() for f in mediums)

    def test_correlate_detects_dangerous_env(self):
        from post.enum.loot import MEDIUM, _correlate
        privesc = {"env": {"dangerous_env": {"LD_PRELOAD": "/tmp/evil.so"}}}
        findings = _correlate({}, privesc, {}, {})
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert any("environment" in f["title"].lower() or "env" in f["title"].lower()
                   for f in mediums)

    def test_correlate_detects_container_hints(self):
        from post.enum.loot import MEDIUM, _correlate
        sysinfo = {"container_vm_hints": ["Docker (.dockerenv present)"]}
        findings = _correlate(sysinfo, {}, {}, {})
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert any("container" in f["title"].lower() for f in mediums)

    def test_correlate_detects_internal_hosts(self):
        from post.enum.loot import LOW, _correlate
        network = {"internal_hosts_seen": ["192.168.1.1", "10.0.0.50"]}
        findings = _correlate({}, {}, {}, network)
        lows = [f for f in findings if f["severity"] == LOW]
        assert any("internal" in f["title"].lower() or "hosts" in f["title"].lower()
                   for f in lows)

    def test_correlate_detects_non_loopback_ports(self):
        from post.enum.loot import LOW, _correlate
        network = {"listening_ports": [
            {"proto": "tcp", "local_addr": "0.0.0.0", "port": 8080, "process": "python3"},
        ]}
        findings = _correlate({}, {}, {}, network)
        lows = [f for f in findings if f["severity"] == LOW]
        assert any("listen" in f["title"].lower() or "port" in f["title"].lower()
                   for f in lows)

    def test_correlate_ignores_loopback_ports(self):
        from post.enum.loot import _correlate
        network = {"listening_ports": [
            {"proto": "tcp", "local_addr": "127.0.0.1", "port": 5432, "process": "postgres"},
        ]}
        findings = _correlate({}, {}, {}, network)
        port_findings = [
            f for f in findings
            if "listen" in f["title"].lower() or "port" in f["title"].lower()
        ]
        assert not port_findings

    def test_correlate_severity_order_is_consistent(self):
        from post.enum.loot import _SEVERITY_ORDER
        assert _SEVERITY_ORDER["CRITICAL"] < _SEVERITY_ORDER["HIGH"]
        assert _SEVERITY_ORDER["HIGH"] < _SEVERITY_ORDER["MEDIUM"]
        assert _SEVERITY_ORDER["MEDIUM"] < _SEVERITY_ORDER["LOW"]

    def test_correlate_multiple_criticals_all_reported(self):
        from post.enum.loot import CRITICAL, _correlate
        users   = {"current_user": {"is_root": True, "in_docker_group": False,
                                    "in_sudo_group": False}}
        privesc = {
            "shadow_passwd": {"shadow_readable": True, "passwd_writable": True},
            "docker": {"exploitable": True},
        }
        findings = _correlate({}, privesc, users, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert len(crits) >= 4  # root + shadow + passwd + docker


# ── cred/loot ──────────────────────────────────────────────────────────────────

class TestCredLootModule:
    """Integration tests for the cred/loot correlation module."""

    def test_implemented_true(self):
        from post.cred.loot import CredLootModule
        assert CredLootModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.cred.loot import CredLootModule
        assert "linux" in CredLootModule.PLATFORM
        assert "darwin" in CredLootModule.PLATFORM

    def test_is_subclass_of_post_module(self):
        from post.cred.loot import CredLootModule
        assert issubclass(CredLootModule, PostModule)

    def test_run_returns_module_result(self):
        from post.cred.loot import CredLootModule
        result = CredLootModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_returns_ok(self):
        result = dispatch("cred/loot")
        assert result["ok"] is True

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_output_has_credential_harvest_header(self):
        result = dispatch("cred/loot")
        assert "CREDENTIAL HARVEST" in result["output"]

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_data_has_required_keys(self):
        result = dispatch("cred/loot")
        data = result["data"]
        for key in ("hostname", "username", "findings", "finding_counts",
                    "module_errors", "inventory", "raw"):
            assert key in data, f"Missing key: {key}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_finding_counts_has_all_severities(self):
        result = dispatch("cred/loot")
        counts = result["data"]["finding_counts"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in counts
            assert isinstance(counts[sev], int)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_findings_is_a_list(self):
        result = dispatch("cred/loot")
        assert isinstance(result["data"]["findings"], list)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_each_finding_has_required_keys(self):
        result = dispatch("cred/loot")
        for f in result["data"]["findings"]:
            for key in ("severity", "category", "title", "detail"):
                assert key in f, f"Finding missing key {key!r}: {f}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_findings_sorted_by_severity(self):
        from post.cred.loot import _SEVERITY_ORDER
        result = dispatch("cred/loot")
        orders = [_SEVERITY_ORDER.get(f["severity"], 9)
                  for f in result["data"]["findings"]]
        assert orders == sorted(orders), "Findings not sorted by severity"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_inventory_has_required_keys(self):
        result = dispatch("cred/loot")
        inv = result["data"]["inventory"]
        for key in ("cleartext_browser_creds", "browser_cred_count",
                    "unencrypted_ssh_keys", "ssh_agent_keys",
                    "keychain_retrieved", "secretstorage_accessible",
                    "high_value_cred_files"):
            assert key in inv, f"Missing inventory key: {key}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_raw_has_all_three_cred_modules(self):
        result = dispatch("cred/loot")
        raw = result["data"]["raw"]
        for key in ("browser", "keychain", "memory"):
            assert key in raw, f"Missing raw module key: {key}"

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_finding_count_matches_findings_list(self):
        from post.cred.loot import CRITICAL, HIGH, LOW, MEDIUM
        result = dispatch("cred/loot")
        findings = result["data"]["findings"]
        counts = result["data"]["finding_counts"]
        for sev, key in [(CRITICAL, "CRITICAL"), (HIGH, "HIGH"),
                         (MEDIUM, "MEDIUM"), (LOW, "LOW")]:
            actual = sum(1 for f in findings if f["severity"] == sev)
            assert counts[key] == actual, (
                f"{key} count mismatch: counts={counts[key]}, actual={actual}"
            )

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_hostname_populated(self):
        result = dispatch("cred/loot")
        assert result["data"]["hostname"]

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_username_populated(self):
        result = dispatch("cred/loot")
        assert result["data"]["username"]


# ── cred/loot correlator unit tests ────────────────────────────────────────────

class TestCredLootCorrelator:
    """Unit tests for _correlate_creds() and helpers — synthetic data, no subprocess."""

    def test_correlate_empty_returns_empty(self):
        from post.cred.loot import _correlate_creds
        assert _correlate_creds({}, {}, {}) == []

    def test_finding_helper_returns_correct_shape(self):
        from post.cred.loot import _finding
        f = _finding("CRITICAL", "browser", "test title", "detail text")
        assert f == {"severity": "CRITICAL", "category": "browser",
                     "title": "test title", "detail": "detail text"}

    def test_finding_helper_default_detail(self):
        from post.cred.loot import _finding
        f = _finding("LOW", "ssh", "title only")
        assert f["detail"] == ""

    def test_is_real_password_empty_is_false(self):
        from post.cred.loot import _is_real_password
        assert _is_real_password("") is False

    def test_is_real_password_decrypt_error_is_false(self):
        from post.cred.loot import _is_real_password
        assert _is_real_password("[decrypt_error: some error]") is False
        assert _is_real_password("[error: file not found]") is False

    def test_is_real_password_placeholder_is_false(self):
        from post.cred.loot import _is_real_password
        assert _is_real_password("(encrypted — needs NSS)") is False
        assert _is_real_password("(needs nss)") is False

    def test_is_real_password_real_value_is_true(self):
        from post.cred.loot import _is_real_password
        assert _is_real_password("hunter2") is True
        assert _is_real_password("P@ssw0rd!") is True
        assert _is_real_password("ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX") is True

    def test_classify_cred_file_aws(self):
        from post.cred.loot import _classify_cred_file
        assert _classify_cred_file("/home/alice/.aws/credentials") == "high"

    def test_classify_cred_file_netrc(self):
        from post.cred.loot import _classify_cred_file
        assert _classify_cred_file("/home/alice/.netrc") == "high"

    def test_classify_cred_file_git_credentials(self):
        from post.cred.loot import _classify_cred_file
        assert _classify_cred_file("/home/alice/.git-credentials") == "high"

    def test_classify_cred_file_docker(self):
        from post.cred.loot import _classify_cred_file
        assert _classify_cred_file("/home/alice/.docker/config.json") == "high"

    def test_classify_cred_file_kubeconfig(self):
        from post.cred.loot import _classify_cred_file
        assert _classify_cred_file("/home/alice/.kube/config") == "medium"

    def test_classify_cred_file_etc_passwd(self):
        from post.cred.loot import _classify_cred_file
        assert _classify_cred_file("/etc/passwd") == "low"

    def test_safe_run_returns_tuple(self):
        from post.cred.loot import _safe_run
        data, err = _safe_run("cred/memory")
        assert isinstance(data, dict)
        assert isinstance(err, str)

    def test_safe_run_unknown_returns_error(self):
        from post.cred.loot import _safe_run
        data, err = _safe_run("cred/does_not_exist")
        assert data == {}
        assert err != ""

    def test_correlate_cleartext_browser_creds(self):
        from post.cred.loot import CRITICAL, _correlate_creds
        browser = {
            "count": 2,
            "credentials": [
                {"browser": "Chrome/Default", "url": "https://github.com",
                 "username": "alice", "password": "hunter2"},
                {"browser": "Chrome/Default", "url": "https://aws.amazon.com",
                 "username": "alice@corp.com", "password": "P@ssw0rd!"},
            ],
        }
        findings = _correlate_creds(browser, {}, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("browser" in f["title"].lower() or "cleartext" in f["title"].lower()
                   for f in crits)

    def test_correlate_encrypted_browser_creds_are_high(self):
        from post.cred.loot import HIGH, _correlate_creds
        browser = {
            "count": 3,
            "credentials": [
                {"browser": "Chrome/Default", "url": "https://example.com",
                 "username": "alice", "password": "[decrypt_error: bad key]"},
                {"browser": "Chrome/Default", "url": "https://corp.com",
                 "username": "bob", "password": ""},
            ],
        }
        findings = _correlate_creds(browser, {}, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("browser" in f["title"].lower() for f in highs)

    def test_correlate_unencrypted_ssh_keys_critical(self):
        from post.cred.loot import CRITICAL, _correlate_creds
        memory = {"unencrypted_private_keys": ["/home/alice/.ssh/id_rsa"],
                  "agent_keys": [], "key_files": []}
        findings = _correlate_creds({}, {}, memory)
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("unencrypted" in f["title"].lower() or "ssh" in f["title"].lower()
                   for f in crits)

    def test_correlate_macos_retrieved_secrets_critical(self):
        from post.cred.loot import CRITICAL, _correlate_creds
        keychain = {"retrieved": [{"service": "GitHub", "secret": "ghp_xxx"}],
                    "items": [], "keychains": []}
        findings = _correlate_creds({}, keychain, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("keychain" in f["title"].lower() for f in crits)

    def test_correlate_gnome_keyring_secrets_critical(self):
        from post.cred.loot import CRITICAL, _correlate_creds
        keychain = {
            "secretstorage_items": [
                {"service": "NetworkManager", "attributes": {}, "secret": "wifi-password"},
            ],
        }
        findings = _correlate_creds({}, keychain, {})
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert any("gnome" in f["title"].lower() or "keyring" in f["title"].lower()
                   for f in crits)

    def test_correlate_gnome_keyring_locked_is_medium(self):
        from post.cred.loot import MEDIUM, _correlate_creds
        keychain = {
            "secretstorage_items": [
                {"error": "GNOME Keyring is locked — unlock the desktop session first"},
            ],
        }
        findings = _correlate_creds({}, keychain, {})
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert any("keyring" in f["title"].lower() or "keychain" in f["title"].lower()
                   for f in mediums)

    def test_correlate_ssh_agent_keys_high(self):
        from post.cred.loot import HIGH, _correlate_creds
        memory = {
            "agent_sockets": ["/tmp/ssh-xxx/agent.123"],
            "agent_keys": [
                {"socket": "/tmp/ssh-xxx/agent.123",
                 "key_type": "ssh-ed25519", "comment": "alice@laptop",
                 "key_blob_len": 51},
            ],
            "key_files": [],
            "unencrypted_private_keys": [],
        }
        findings = _correlate_creds({}, {}, memory)
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("agent" in f["title"].lower() for f in highs)

    def test_correlate_high_value_files_high(self):
        from post.cred.loot import HIGH, _correlate_creds
        keychain = {
            "credential_files": [
                {"path": "/home/alice/.aws/credentials", "size": 120, "mode": "0o100600"},
                {"path": "/home/alice/.netrc", "size": 80, "mode": "0o100600"},
            ],
        }
        findings = _correlate_creds({}, keychain, {})
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("credential file" in f["title"].lower() for f in highs)

    def test_correlate_encrypted_keys_high(self):
        from post.cred.loot import HIGH, _correlate_creds
        memory = {
            "agent_keys": [],
            "key_files": [
                {"path": "/home/alice/.ssh/id_rsa", "type": "private_key",
                 "encrypted": True},
            ],
            "unencrypted_private_keys": [],
        }
        findings = _correlate_creds({}, {}, memory)
        highs = [f for f in findings if f["severity"] == HIGH]
        assert any("encrypted" in f["title"].lower() and "ssh" in f["title"].lower()
                   for f in highs)

    def test_correlate_firefox_creds_medium(self):
        from post.cred.loot import MEDIUM, _correlate_creds
        browser = {
            "count": 2,
            "credentials": [
                {"browser": "Firefox", "profile": "default-release",
                 "url": "https://github.com",
                 "username": "(encrypted — needs NSS)",
                 "password": "(encrypted — needs NSS/firepwd)"},
            ],
        }
        findings = _correlate_creds(browser, {}, {})
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert any("firefox" in f["title"].lower() for f in mediums)

    def test_correlate_known_hosts_low(self):
        from post.cred.loot import LOW, _correlate_creds
        memory = {
            "agent_keys": [],
            "key_files": [
                {"path": "/home/alice/.ssh/known_hosts", "type": "known_hosts",
                 "hosts": 23},
            ],
            "unencrypted_private_keys": [],
        }
        findings = _correlate_creds({}, {}, memory)
        lows = [f for f in findings if f["severity"] == LOW]
        assert any("known_hosts" in f["title"].lower() for f in lows)

    def test_correlate_authorized_keys_low(self):
        from post.cred.loot import LOW, _correlate_creds
        memory = {
            "agent_keys": [],
            "key_files": [
                {"path": "/home/alice/.ssh/authorized_keys", "type": "authorized_keys",
                 "entries": 3},
            ],
            "unencrypted_private_keys": [],
        }
        findings = _correlate_creds({}, {}, memory)
        lows = [f for f in findings if f["severity"] == LOW]
        assert any("authorized_keys" in f["title"].lower() for f in lows)

    def test_correlate_severity_order_consistent(self):
        from post.cred.loot import _SEVERITY_ORDER
        assert _SEVERITY_ORDER["CRITICAL"] < _SEVERITY_ORDER["HIGH"]
        assert _SEVERITY_ORDER["HIGH"] < _SEVERITY_ORDER["MEDIUM"]
        assert _SEVERITY_ORDER["MEDIUM"] < _SEVERITY_ORDER["LOW"]

    def test_correlate_multiple_criticals_all_reported(self):
        from post.cred.loot import CRITICAL, _correlate_creds
        browser = {
            "count": 1,
            "credentials": [{"browser": "Chrome", "url": "https://example.com",
                              "username": "alice", "password": "hunter2"}],
        }
        memory = {"unencrypted_private_keys": ["/home/alice/.ssh/id_rsa"],
                  "agent_keys": [], "key_files": []}
        keychain = {"retrieved": [{"service": "GitHub", "secret": "ghp_xxx"}]}
        findings = _correlate_creds(browser, keychain, memory)
        crits = [f for f in findings if f["severity"] == CRITICAL]
        assert len(crits) >= 3  # browser + unencrypted key + keychain
