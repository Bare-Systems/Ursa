"""Tests for major.profiles — malleable C2 traffic profiles.

Pure local: no network, no I/O. Covers TrafficProfile methods (builder_tokens,
reverse_map, download_prefix) and the module-level helpers (get_profile,
list_profiles), including the fallback behaviour for unknown profile names.
"""

import warnings

import pytest

from major.profiles import PROFILES, TrafficProfile, get_profile, list_profiles

# ── TrafficProfile.builder_tokens ─────────────────────────────────────────────


class TestBuilderTokens:

    def test_default_profile_contains_all_keys(self):
        tokens = PROFILES["default"].builder_tokens()
        expected = {
            "URSA_REGISTER_PATH",
            "URSA_BEACON_PATH",
            "URSA_RESULT_PATH",
            "URSA_UPLOAD_PATH",
            "URSA_DOWNLOAD_PATH",
            "URSA_STAGE_PATH",
        }
        assert expected <= tokens.keys()

    def test_download_path_strips_id_placeholder(self):
        tokens = PROFILES["jquery"].builder_tokens()
        assert "{id}" not in tokens["URSA_DOWNLOAD_PATH"]

    def test_download_path_retains_prefix(self):
        tokens = PROFILES["jquery"].builder_tokens()
        assert tokens["URSA_DOWNLOAD_PATH"] == "/ajax/libs/jquery/3.5.1"

    def test_office365_tokens_map_to_graph_paths(self):
        tokens = PROFILES["office365"].builder_tokens()
        assert tokens["URSA_BEACON_PATH"] == "/api/v1.0/me/mailFolders/inbox/messages"
        assert tokens["URSA_REGISTER_PATH"] == "/api/v1.0/auth/token"

    def test_github_api_tokens(self):
        tokens = PROFILES["github-api"].builder_tokens()
        assert tokens["URSA_BEACON_PATH"] == "/api/v3/notifications"
        assert "{id}" not in tokens["URSA_DOWNLOAD_PATH"]

    def test_custom_profile_builder_tokens(self):
        profile = TrafficProfile(
            name="test",
            description="Test profile",
            server_header="Test/1.0",
            urls={
                "register": "/api/auth",
                "beacon":   "/api/poll",
                "result":   "/api/result",
                "upload":   "/api/upload",
                "download": "/api/files/{id}",
                "stage":    "/api/stage",
            },
        )
        tokens = profile.builder_tokens()
        assert tokens["URSA_REGISTER_PATH"] == "/api/auth"
        assert tokens["URSA_DOWNLOAD_PATH"] == "/api/files"

    def test_missing_url_keys_fall_back_to_defaults(self):
        profile = TrafficProfile(
            name="minimal",
            description="Minimal",
            server_header="X/1",
            urls={"beacon": "/poll"},
        )
        tokens = profile.builder_tokens()
        assert tokens["URSA_BEACON_PATH"] == "/poll"
        assert tokens["URSA_REGISTER_PATH"] == "/register"
        assert tokens["URSA_STAGE_PATH"] == "/stage"


# ── TrafficProfile.reverse_map ────────────────────────────────────────────────


class TestReverseMap:

    def test_paths_map_to_logical_names(self):
        rev = PROFILES["default"].reverse_map()
        assert rev["/beacon"] == "beacon"
        assert rev["/register"] == "register"
        assert rev["/result"] == "result"

    def test_download_path_strips_id_suffix(self):
        rev = PROFILES["default"].reverse_map()
        assert "/download" in rev
        assert rev["/download"] == "download"

    def test_jquery_paths_present(self):
        rev = PROFILES["jquery"].reverse_map()
        assert "/ajax/libs/jquery/3.6.4/jquery.js" in rev
        assert rev["/ajax/libs/jquery/3.6.4/jquery.js"] == "beacon"

    def test_all_url_keys_appear_in_reverse_map(self):
        for name, profile in PROFILES.items():
            rev = profile.reverse_map()
            for logical in profile.urls:
                path = profile.urls[logical]
                clean = path.split("{id}")[0].rstrip("/") if "{id}" in path else path
                assert clean in rev, f"{name}: missing {logical!r} → {clean!r}"


# ── TrafficProfile.download_prefix ────────────────────────────────────────────


class TestDownloadPrefix:

    def test_default_prefix(self):
        assert PROFILES["default"].download_prefix() == "/download"

    def test_github_api_prefix(self):
        assert PROFILES["github-api"].download_prefix() == "/api/v3/repos/org/repo/releases/assets"

    def test_office365_prefix(self):
        assert PROFILES["office365"].download_prefix() == "/api/v1.0/me/drive/items"

    def test_no_placeholder_returns_path_unchanged(self):
        profile = TrafficProfile(
            name="t", description="t", server_header="t/1",
            urls={"download": "/static/files"},
        )
        assert profile.download_prefix() == "/static/files"


# ── get_profile ───────────────────────────────────────────────────────────────


class TestGetProfile:

    def test_known_profile_returned(self):
        p = get_profile("jquery")
        assert p.name == "jquery"
        assert "jQuery" in p.description

    def test_default_profile_returned(self):
        p = get_profile("default")
        assert p.name == "default"

    def test_unknown_name_returns_default_with_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            p = get_profile("nonexistent-profile")
        assert p.name == "default"
        assert len(caught) == 1
        assert "nonexistent-profile" in str(caught[0].message)

    @pytest.mark.parametrize("name", ["default", "jquery", "office365", "github-api"])
    def test_all_builtin_profiles_retrievable(self, name):
        p = get_profile(name)
        assert p.name == name


# ── list_profiles ─────────────────────────────────────────────────────────────


class TestListProfiles:

    def test_returns_all_builtin_profiles(self):
        listed = list_profiles()
        names = {p["name"] for p in listed}
        assert {"default", "jquery", "office365", "github-api"} <= names

    def test_each_entry_has_expected_keys(self):
        for entry in list_profiles():
            assert {"name", "description", "server_header", "endpoints"} <= entry.keys()

    def test_endpoints_count_matches_urls(self):
        for entry in list_profiles():
            profile = PROFILES[entry["name"]]
            assert entry["endpoints"] == len(profile.urls)


# ── built-in profile completeness ─────────────────────────────────────────────


class TestBuiltinProfileCompleteness:

    REQUIRED_KEYS = {"register", "beacon", "result", "upload", "download", "stage"}

    @pytest.mark.parametrize("name", ["default", "jquery", "office365", "github-api"])
    def test_all_url_keys_present(self, name):
        missing = self.REQUIRED_KEYS - PROFILES[name].urls.keys()
        assert not missing, f"Profile '{name}' missing URL keys: {missing}"

    @pytest.mark.parametrize("name", ["default", "jquery", "office365", "github-api"])
    def test_server_header_non_empty(self, name):
        assert PROFILES[name].server_header

    @pytest.mark.parametrize("name", ["jquery", "office365", "github-api"])
    def test_camouflage_profiles_have_response_headers(self, name):
        assert PROFILES[name].response_headers
