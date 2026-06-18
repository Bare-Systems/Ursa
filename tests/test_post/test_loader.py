"""Tests for the PostLoader module registry and dispatcher."""

from post.loader import PostLoader


class TestPostLoaderList:
    def test_list_returns_list(self):
        loader = PostLoader()
        modules = loader.list_modules()
        assert isinstance(modules, list)

    def test_list_contains_dicts(self):
        loader = PostLoader()
        for m in loader.list_modules():
            assert "name" in m
            assert "description" in m
            assert "platform" in m
            assert "implemented" in m

    def test_list_contains_known_modules(self):
        loader = PostLoader()
        names = [m["name"] for m in loader.list_modules()]
        for expected in (
            "enum/sysinfo", "enum/privesc", "enum/users", "enum/network", "enum/loot",
            "cred/browser", "cred/keychain", "cred/memory", "cred/loot",
            "lateral/pth", "lateral/ssh", "lateral/wmi",
            "persist/cron", "persist/registry", "persist/launchagent",
        ):
            assert expected in names, f"Missing module: {expected}"

    def test_list_sorted_alphabetically(self):
        loader = PostLoader()
        names = [m["name"] for m in loader.list_modules()]
        assert names == sorted(names)

    def test_implemented_flags_correct(self):
        loader = PostLoader()
        modules = {m["name"]: m for m in loader.list_modules()}
        # Enum modules are implemented
        assert modules["enum/sysinfo"]["implemented"] is True
        assert modules["enum/privesc"]["implemented"] is True
        assert modules["enum/users"]["implemented"] is True
        assert modules["enum/network"]["implemented"] is True
        assert modules["enum/loot"]["implemented"] is True
        # Post-exploitation modules are now implemented
        assert modules["cred/browser"]["implemented"] is True
        assert modules["cred/keychain"]["implemented"] is True
        assert modules["cred/memory"]["implemented"] is True
        assert modules["cred/loot"]["implemented"] is True
        assert modules["lateral/pth"]["implemented"] is True
        assert modules["lateral/ssh"]["implemented"] is True
        assert modules["persist/cron"]["implemented"] is True
        assert modules["persist/launchagent"]["implemented"] is True
        # Windows-only modules are now implemented
        assert modules["lateral/wmi"]["implemented"] is True
        assert modules["persist/registry"]["implemented"] is True


class TestPostLoaderDispatch:
    def test_dispatch_unknown_module_returns_error(self):
        result = PostLoader().dispatch("nonexistent/module")
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_dispatch_windows_modules_without_args_return_ok_false(self):
        # These modules require args (target, payload_path, etc.) and return
        # ok=False when called without them, even though they are implemented.
        for name in ("lateral/wmi", "persist/registry"):
            result = PostLoader().dispatch(name)
            assert result["ok"] is False, f"{name} should return ok=False without required args"

    def test_dispatch_returns_dict(self):
        result = PostLoader().dispatch("nonexistent")
        assert isinstance(result, dict)
        assert set(result.keys()) >= {"ok", "output", "data", "error"}

    def test_dispatch_sysinfo_returns_ok(self):
        result = PostLoader().dispatch("enum/sysinfo")
        assert result["ok"] is True
        assert result["output"] != ""
        assert "hostname" in result["data"]
