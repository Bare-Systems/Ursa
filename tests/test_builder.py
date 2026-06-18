"""Tests for the Ursa payload builder (implants/builder.py)."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from implants.builder import Builder, PayloadConfig, auto_c2_url, detect_local_ip

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_templates(tmp_path: Path) -> Path:
    """A temporary templates directory with one test template."""
    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "basic.py").write_text(
        'C2 = "URSA_C2_URL"\n'
        'INTERVAL = int("URSA_INTERVAL")\n'
        'JITTER = float("URSA_JITTER")\n'
    )
    return tdir


@pytest.fixture()
def tmp_templates_multi(tmp_path: Path) -> Path:
    """Templates directory with multiple extensions."""
    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "http_py.py").write_text('C2 = "URSA_C2_URL"\n')
    (tdir / "http_zig.zig").write_text(
        'const C2_URL: []const u8 = "URSA_C2_URL";\n'
        "const INTERVAL: u64 = URSA_INTERVAL;\n"
        "const JITTER: f64 = URSA_JITTER;\n"
    )
    (tdir / "http_go.go").write_text('var c2 = "URSA_C2_URL"\n')
    return tdir


@pytest.fixture()
def builder(tmp_templates: Path) -> Builder:
    return Builder(templates_dir=tmp_templates)


@pytest.fixture()
def config() -> PayloadConfig:
    return PayloadConfig(
        c2_url="http://10.0.0.1:6708",
        interval=10,
        jitter=0.2,
        template="basic",
    )


# ── PayloadConfig ─────────────────────────────────────────────────────────────


class TestPayloadConfig:
    def test_tokens_defaults(self):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708")
        tokens = cfg.tokens()
        assert tokens["URSA_C2_URL"] == "http://1.2.3.4:6708"
        assert tokens["URSA_INTERVAL"] == "5"
        assert tokens["URSA_JITTER"] == "0.3"

    def test_tokens_custom_values(self, config: PayloadConfig):
        tokens = config.tokens()
        assert tokens["URSA_C2_URL"] == "http://10.0.0.1:6708"
        assert tokens["URSA_INTERVAL"] == "10"
        assert tokens["URSA_JITTER"] == "0.2"

    def test_extra_tokens_included(self):
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            extra_tokens={"URSA_CUSTOM": "hello"},
        )
        assert cfg.tokens()["URSA_CUSTOM"] == "hello"


# ── Builder.list_templates ────────────────────────────────────────────────────


class TestListTemplates:
    def test_lists_available_templates(self, builder: Builder, tmp_templates: Path):
        (tmp_templates / "second.py").write_text("")
        names = builder.list_templates()
        assert "basic" in names
        assert "second" in names

    def test_returns_stems_not_filenames(self, builder: Builder):
        names = builder.list_templates()
        assert all(not n.endswith(".py") for n in names)

    def test_sorted_alphabetically(self, builder: Builder, tmp_templates: Path):
        (tmp_templates / "aaa.py").write_text("")
        (tmp_templates / "zzz.py").write_text("")
        names = builder.list_templates()
        assert names == sorted(names)

    def test_empty_directory(self, tmp_path: Path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        assert Builder(templates_dir=empty_dir).list_templates() == []

    def test_missing_directory(self, tmp_path: Path):
        missing = tmp_path / "nonexistent"
        assert Builder(templates_dir=missing).list_templates() == []


# ── Builder.build ─────────────────────────────────────────────────────────────


class TestBuild:
    def test_substitutes_c2_url(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        assert "http://10.0.0.1:6708" in source
        assert "URSA_C2_URL" not in source

    def test_substitutes_interval(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        assert '"10"' in source or "int(\"10\")" in source or "10" in source
        assert "URSA_INTERVAL" not in source

    def test_substitutes_jitter(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        assert "URSA_JITTER" not in source

    def test_all_tokens_replaced(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        for token in ("URSA_C2_URL", "URSA_INTERVAL", "URSA_JITTER"):
            assert token not in source

    def test_missing_template_raises(self, builder: Builder):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708", template="doesnotexist")
        with pytest.raises(FileNotFoundError, match="doesnotexist"):
            builder.build(cfg)

    def test_extra_tokens_substituted(self, tmp_templates: Path):
        (tmp_templates / "custom.py").write_text("KEY = 'URSA_MYKEY'\n")
        b = Builder(templates_dir=tmp_templates)
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            template="custom",
            extra_tokens={"URSA_MYKEY": "secret123"},
        )
        assert "secret123" in b.build(cfg)
        assert "URSA_MYKEY" not in b.build(cfg)

    def test_returns_string(self, builder: Builder, config: PayloadConfig):
        assert isinstance(builder.build(config), str)


# ── Builder.build_stager ──────────────────────────────────────────────────────


class TestBuildStager:
    def test_substitutes_c2_url(self, tmp_path: Path):
        stager = tmp_path / "stager.py"
        stager.write_text('C2 = "URSA_C2_URL"\n')

        import implants.builder as bmod
        orig = bmod.STAGER_PATH
        bmod.STAGER_PATH = stager
        try:
            source = Builder().build_stager("http://10.0.0.1:6708")
        finally:
            bmod.STAGER_PATH = orig

        assert "http://10.0.0.1:6708" in source
        assert "URSA_C2_URL" not in source

    def test_missing_stager_raises(self, tmp_path: Path):
        import implants.builder as bmod
        orig = bmod.STAGER_PATH
        bmod.STAGER_PATH = tmp_path / "nonexistent.py"
        try:
            with pytest.raises(FileNotFoundError):
                Builder().build_stager("http://1.2.3.4:6708")
        finally:
            bmod.STAGER_PATH = orig


# ── Builder.write / build_to_file ─────────────────────────────────────────────


class TestWrite:
    def test_writes_file(self, tmp_path: Path):
        out = tmp_path / "payload.py"
        Builder().write("# hello\n", out)
        assert out.read_text() == "# hello\n"

    def test_creates_parent_dirs(self, tmp_path: Path):
        out = tmp_path / "deep" / "nested" / "payload.py"
        Builder().write("x", out)
        assert out.exists()

    def test_build_to_file(self, builder: Builder, config: PayloadConfig, tmp_path: Path):
        out = tmp_path / "out.py"
        result = builder.build_to_file(config, out)
        assert result == out
        assert "http://10.0.0.1:6708" in out.read_text()


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_auto_c2_url_format(self):
        url = auto_c2_url(port=9000)
        assert url.startswith("http://")
        assert ":9000" in url

    def test_detect_local_ip_returns_string(self):
        ip = detect_local_ip()
        assert isinstance(ip, str)
        assert "." in ip  # IPv4 dotted notation

    def test_auto_c2_url_default_port(self):
        url = auto_c2_url()
        assert ":6708" in url


# ── real http_python template ─────────────────────────────────────────────────


class TestRealTemplate:
    """Smoke-test the actual http_python template that ships with the project."""

    def test_http_python_builds(self):
        b = Builder()  # uses default templates dir
        if "http_python" not in b.list_templates():
            pytest.skip("http_python template not present")
        cfg = PayloadConfig(c2_url="http://192.168.1.1:6708", template="http_python")
        source = b.build(cfg)
        assert "192.168.1.1" in source
        assert "URSA_C2_URL" not in source
        assert "URSA_INTERVAL" not in source
        assert "URSA_JITTER" not in source


# ── Multi-extension template discovery ───────────────────────────────────────


class TestMultiExtension:
    def test_lists_zig_template(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        names = b.list_templates()
        assert "http_zig" in names

    def test_lists_go_template(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        assert "http_go" in b.list_templates()

    def test_all_three_present(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        names = b.list_templates()
        assert set(names) == {"http_go", "http_py", "http_zig"}

    def test_sorted_alphabetically(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        names = b.list_templates()
        assert names == sorted(names)

    def test_no_duplicates_on_stem_conflict(self, tmp_templates_multi: Path):
        # If two files share a stem, only one entry should appear.
        (tmp_templates_multi / "http_zig.py").write_text("# duplicate stem\n")
        b = Builder(templates_dir=tmp_templates_multi)
        assert b.list_templates().count("http_zig") == 1

    def test_builds_zig_template(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        cfg = PayloadConfig(c2_url="http://10.0.0.1:6708", template="http_zig")
        source = b.build(cfg)
        assert "http://10.0.0.1:6708" in source
        assert "URSA_C2_URL" not in source
        assert "URSA_INTERVAL" not in source
        assert "URSA_JITTER" not in source

    def test_finds_zig_by_stem(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        p = b.template_path("http_zig")
        assert p.suffix == ".zig"


# ── PayloadConfig.post_build ──────────────────────────────────────────────────


class TestPostBuild:
    def test_default_is_empty(self):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708")
        assert cfg.post_build == ""

    def test_custom_post_build_stored(self):
        cmd = "zig build-exe {output} -femit-bin={binary}"
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708", post_build=cmd)
        assert cfg.post_build == cmd

    def test_post_build_not_in_tokens(self):
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            post_build="zig build-exe {output}",
        )
        assert "post_build" not in cfg.tokens()


# ── Builder.compile ───────────────────────────────────────────────────────────


class TestCompile:
    def test_returns_none_when_no_post_build(self, tmp_path: Path):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708")
        result = Builder().compile(cfg, tmp_path / "agent.zig")
        assert result is None

    def test_returns_binary_path_on_success(self, tmp_path: Path):
        src = tmp_path / "agent.zig"
        src.write_text("// stub\n")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            post_build="echo {output}",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            result = Builder().compile(cfg, src)
        assert result == tmp_path / "agent"  # extension stripped

    def test_raises_on_nonzero_exit(self, tmp_path: Path):
        src = tmp_path / "agent.zig"
        src.write_text("// stub\n")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            post_build="false",  # always exits 1
        )
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, ["false"])
            with pytest.raises(subprocess.CalledProcessError):
                Builder().compile(cfg, src)

    def test_substitutes_output_placeholder(self, tmp_path: Path):
        src = tmp_path / "payload.zig"
        src.write_text("// stub\n")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            post_build="mycc {output} -o {binary}",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            Builder().compile(cfg, src)
        call_args = mock_run.call_args[0][0]  # first positional arg = cmd list
        assert str(src) in call_args
        assert str(tmp_path / "payload") in call_args


# ── Builder.build_and_compile ─────────────────────────────────────────────────


class TestBuildAndCompile:
    def test_returns_source_path(self, tmp_templates: Path, tmp_path: Path):
        out = tmp_path / "payload.py"
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708", template="basic")
        src, _bin = Builder(templates_dir=tmp_templates).build_and_compile(cfg, out)
        assert src == out
        assert out.exists()

    def test_binary_none_when_no_post_build(self, tmp_templates: Path, tmp_path: Path):
        out = tmp_path / "payload.py"
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708", template="basic")
        _src, binary = Builder(templates_dir=tmp_templates).build_and_compile(cfg, out)
        assert binary is None

    def test_binary_returned_when_post_build_set(
        self, tmp_templates: Path, tmp_path: Path
    ):
        out = tmp_path / "agent.zig"
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708",
            template="basic",
            post_build="echo {output}",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            _src, binary = Builder(templates_dir=tmp_templates).build_and_compile(
                cfg, out
            )
        assert binary == tmp_path / "agent"


# ── Real http_zig template ────────────────────────────────────────────────────


class TestRealZigTemplate:
    """Smoke-test the http_zig.zig template that ships with the project."""

    def test_http_zig_builds(self):
        b = Builder()
        if "http_zig" not in b.list_templates():
            pytest.skip("http_zig template not present")
        cfg = PayloadConfig(c2_url="http://192.168.1.1:6708", template="http_zig")
        source = b.build(cfg)
        assert "192.168.1.1" in source
        assert "URSA_C2_URL" not in source
        assert "URSA_INTERVAL" not in source
        assert "URSA_JITTER" not in source

    def test_http_zig_numeric_interval(self):
        b = Builder()
        if "http_zig" not in b.list_templates():
            pytest.skip("http_zig template not present")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:6708", template="http_zig", interval=15
        )
        source = b.build(cfg)
        assert "15" in source
        assert "URSA_INTERVAL" not in source

    def test_http_zig_template_has_zig_extension(self):
        b = Builder()
        if "http_zig" not in b.list_templates():
            pytest.skip("http_zig template not present")
        assert b.template_path("http_zig").suffix == ".zig"


# ── Obfuscation ───────────────────────────────────────────────────────────────


class TestObfuscation:
    """Tests for Builder._obfuscate() and PayloadConfig.obfuscate flag."""

    def test_obfuscate_flag_default_false(self):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708")
        assert cfg.obfuscate is False

    def test_obfuscate_flag_can_be_set(self):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:6708", obfuscate=True)
        assert cfg.obfuscate is True

    def test_obfuscate_output_is_string(self):
        source = 'print("hello world")\n'
        result = Builder._obfuscate(source)
        assert isinstance(result, str)

    def test_obfuscate_output_differs_from_input(self):
        source = 'C2 = "http://10.0.0.1:6708"\n'
        result = Builder._obfuscate(source)
        assert result != source

    def test_obfuscate_hides_c2_url(self):
        source = 'C2_URL = "http://10.0.0.1:6708"\n'
        result = Builder._obfuscate(source)
        assert "http://10.0.0.1:6708" not in result

    def test_obfuscate_output_is_valid_python(self):
        source = 'x = 1 + 1\n'
        stub = Builder._obfuscate(source)
        # Should compile without errors
        compile(stub, "<obfuscated>", "exec")

    def test_obfuscate_exec_produces_correct_result(self):
        source = 'result = 2 + 2\n'
        stub = Builder._obfuscate(source)
        ns: dict = {}
        exec(stub, ns)
        assert ns["result"] == 4

    def test_obfuscate_randomized_key_each_call(self):
        source = 'x = 42\n'
        stub1 = Builder._obfuscate(source)
        stub2 = Builder._obfuscate(source)
        # Different keys → different encoded output (with overwhelming probability)
        assert stub1 != stub2

    def test_build_without_obfuscate_contains_c2_url(self, tmp_templates, builder):
        cfg = PayloadConfig(c2_url="http://10.0.0.1:6708", template="basic", obfuscate=False)
        source = builder.build(cfg)
        assert "http://10.0.0.1:6708" in source

    def test_build_with_obfuscate_hides_c2_url(self, tmp_templates, builder):
        cfg = PayloadConfig(c2_url="http://10.0.0.1:6708", template="basic", obfuscate=True)
        source = builder.build(cfg)
        assert "http://10.0.0.1:6708" not in source

    def test_build_with_obfuscate_exec_works(self, tmp_templates, builder):
        cfg = PayloadConfig(c2_url="http://10.0.0.1:6708", template="basic", obfuscate=True)
        stub = builder.build(cfg)
        # The template sets C2 = "http://10.0.0.1:6708" — exec and verify
        ns: dict = {}
        exec(stub, ns)
        assert ns.get("C2") == "http://10.0.0.1:6708"


# ── Beacon UA rotation ─────────────────────────────────────────────────────────


class TestBeaconUARotation:
    def test_user_agent_pool_is_non_empty(self):
        from implants.beacon import _USER_AGENTS
        assert len(_USER_AGENTS) >= 4

    def test_user_agent_pool_values_are_strings(self):
        from implants.beacon import _USER_AGENTS
        for ua in _USER_AGENTS:
            assert isinstance(ua, str)
            assert len(ua) > 20

    def test_beacon_picks_ua_from_pool(self):
        from implants.beacon import _USER_AGENTS, UrsaBeacon
        b = UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False)
        assert b.user_agent in _USER_AGENTS

    def test_different_instances_may_pick_different_uas(self):
        from implants.beacon import _USER_AGENTS, UrsaBeacon
        # With 7 choices, chance all 10 picks are the same is (1/7)^9 ≈ negligible
        if len(_USER_AGENTS) < 2:
            pytest.skip("Only one UA in pool")
        uas = {UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False).user_agent
               for _ in range(20)}
        assert len(uas) > 1


# ── Beacon jitter ─────────────────────────────────────────────────────────────


class TestBeaconJitter:
    def test_jitter_clamped_to_valid_range(self):
        from implants.beacon import UrsaBeacon
        b = UrsaBeacon("http://127.0.0.1:6708", jitter=5.0, sandbox_check=False)
        assert 0.0 <= b.jitter <= 1.0

    def test_jitter_negative_clamped_to_zero(self):
        from implants.beacon import UrsaBeacon
        b = UrsaBeacon("http://127.0.0.1:6708", jitter=-1.0, sandbox_check=False)
        assert b.jitter == 0.0

    def test_default_jitter_is_0_3(self):
        from implants.beacon import UrsaBeacon
        b = UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False)
        assert b.jitter == 0.3

    def test_jitter_sleep_stays_above_minimum(self):
        """_jitter_sleep must never pass less than 1 second to _obfuscated_sleep."""
        import unittest.mock as mock

        from implants import beacon as beacon_mod
        from implants.beacon import UrsaBeacon
        b = UrsaBeacon("http://127.0.0.1:6708", interval=1, jitter=0.9,
                        sandbox_check=False, amsi_bypass=False)
        sleep_calls = []
        with mock.patch.object(beacon_mod, "_obfuscated_sleep",
                               side_effect=lambda t: sleep_calls.append(t)):
            b._jitter_sleep()
        assert sleep_calls, "_obfuscated_sleep was not called"
        assert sleep_calls[0] >= 1


# ── Process name spoofing ─────────────────────────────────────────────────────


class TestBeaconProcessName:
    def test_no_process_name_no_crash(self):
        """Default (empty) process_name should not call spoof."""
        from implants.beacon import UrsaBeacon
        b = UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False)
        # Just checking it constructs cleanly
        assert b is not None

    def test_process_name_changes_argv0(self):
        """Passing process_name should mutate sys.argv[0]."""
        import sys

        from implants.beacon import UrsaBeacon
        original = sys.argv[0]
        UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False,
                   process_name="fake-process")
        assert sys.argv[0] == "fake-process"
        sys.argv[0] = original  # restore

    def test_process_name_empty_string_no_change(self):
        """Empty string process_name leaves argv[0] unchanged."""
        import sys

        from implants.beacon import UrsaBeacon
        original = sys.argv[0]
        UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False, process_name="")
        assert sys.argv[0] == original


# ── Go template ───────────────────────────────────────────────────────────────


class TestGoTemplate:
    """Tests for the http_go.go template."""

    def test_go_template_listed(self):
        from implants.builder import Builder
        templates = Builder().list_templates()
        assert "http_go" in templates

    def test_go_template_has_go_extension(self):
        from implants.builder import Builder
        path = Builder().template_path("http_go")
        assert path.suffix == ".go"

    def test_go_template_builds(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src = Builder().build(cfg)
        assert isinstance(src, str)
        assert len(src) > 100

    def test_go_template_substitutes_c2_url(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://10.1.2.3:9999", template="http_go")
        src = Builder().build(cfg)
        assert "http://10.1.2.3:9999" in src
        assert "URSA_C2_URL" not in src

    def test_go_template_substitutes_interval(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", interval=30,
                            template="http_go")
        src = Builder().build(cfg)
        assert "URSA_INTERVAL" not in src
        assert "30" in src

    def test_go_template_substitutes_jitter(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", jitter=0.5,
                            template="http_go")
        src = Builder().build(cfg)
        assert "URSA_JITTER" not in src
        assert "0.5" in src

    def test_go_template_is_valid_go_package(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src = Builder().build(cfg)
        assert "package main" in src
        assert "func main()" in src

    def test_go_template_has_all_task_types(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src = Builder().build(cfg)
        for task in ("shell", "sysinfo", "ps", "whoami", "pwd", "cd",
                     "ls", "env", "download", "upload", "sleep", "kill"):
            assert f'case "{task}"' in src, f"Missing task type: {task}"

    def test_go_template_has_ua_pool(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src = Builder().build(cfg)
        assert "Mozilla" in src
        assert "userAgents" in src

    def test_go_template_has_jitter_sleep(self):
        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src = Builder().build(cfg)
        assert "jitterSleep" in src

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed"
    )
    def test_go_template_compiles(self, tmp_path):
        """Build the template and compile it with 'go build'."""
        import subprocess

        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(
            c2_url="http://127.0.0.1:6708",
            template="http_go",
            post_build="go build -o {binary} {output}",
        )
        src_path = tmp_path / "agent.go"
        Builder().build_to_file(cfg, src_path)
        # Run go build directly (post_build via Builder.compile would work too)
        result = subprocess.run(
            ["go", "build", "-o", str(tmp_path / "agent"), str(src_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"go build failed:\n{result.stdout}\n{result.stderr}"
        )
        assert (tmp_path / "agent").exists()

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed"
    )
    def test_go_template_cross_compiles_linux(self, tmp_path):
        """Cross-compile for Linux/amd64 from any host."""
        import subprocess

        from implants.builder import Builder, PayloadConfig
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src_path = Builder().build_to_file(cfg, tmp_path / "agent.go")
        env = {**__import__("os").environ, "GOOS": "linux", "GOARCH": "amd64"}
        result = subprocess.run(
            ["go", "build", "-o", str(tmp_path / "agent-linux"), str(src_path)],
            capture_output=True, text=True, env=env,
        )
        assert result.returncode == 0, (
            f"cross-compile failed:\n{result.stdout}\n{result.stderr}"
        )
        assert (tmp_path / "agent-linux").exists()


# ── Go cross-compile — additional targets ─────────────────────────────────────


class TestGoTemplateCrossCompile:
    """Additional cross-compilation targets for the http_go.go template."""

    @pytest.fixture(autouse=True)
    def skip_if_missing(self):
        if "http_go" not in Builder().list_templates():
            pytest.skip("http_go template not present")

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed",
    )
    def test_cross_compiles_windows_amd64(self, tmp_path):
        """Cross-compile for Windows/amd64."""
        import os
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src_path = Builder().build_to_file(cfg, tmp_path / "agent.go")
        env = {**os.environ, "GOOS": "windows", "GOARCH": "amd64"}
        result = subprocess.run(
            ["go", "build", "-o", str(tmp_path / "agent.exe"), str(src_path)],
            capture_output=True, text=True, env=env,
        )
        assert result.returncode == 0, (
            f"Windows/amd64 cross-compile failed:\n{result.stdout}\n{result.stderr}"
        )
        assert (tmp_path / "agent.exe").exists()

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed",
    )
    def test_cross_compiles_darwin_arm64(self, tmp_path):
        """Cross-compile for macOS/arm64."""
        import os
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_go")
        src_path = Builder().build_to_file(cfg, tmp_path / "agent.go")
        env = {**os.environ, "GOOS": "darwin", "GOARCH": "arm64"}
        result = subprocess.run(
            ["go", "build", "-o", str(tmp_path / "agent-darwin"), str(src_path)],
            capture_output=True, text=True, env=env,
        )
        assert result.returncode == 0, (
            f"darwin/arm64 cross-compile failed:\n{result.stdout}\n{result.stderr}"
        )
        assert (tmp_path / "agent-darwin").exists()

    @pytest.mark.skipif(
        __import__("shutil").which("go") is None,
        reason="Go compiler not installed",
    )
    def test_build_and_compile_via_builder_api(self, tmp_path):
        """Use Builder.build_and_compile() end-to-end with go build."""
        cfg = PayloadConfig(
            c2_url="http://127.0.0.1:6708",
            template="http_go",
            post_build="go build -o {binary} {output}",
        )
        src_path, binary_path = Builder().build_and_compile(cfg, tmp_path / "agent.go")
        assert src_path.exists()
        assert binary_path is not None
        assert binary_path.exists()


# ── template_path edge cases ──────────────────────────────────────────────────


class TestTemplatePath:

    def test_returns_matching_path(self, tmp_templates):
        b = Builder(templates_dir=tmp_templates)
        p = b.template_path("basic")
        assert p.name == "basic.py"

    def test_error_message_includes_stem(self, tmp_templates):
        b = Builder(templates_dir=tmp_templates)
        with pytest.raises(FileNotFoundError, match="ghost"):
            b.template_path("ghost")

    def test_error_message_lists_available(self, tmp_templates):
        """The error for a missing template names the available ones."""
        b = Builder(templates_dir=tmp_templates)
        with pytest.raises(FileNotFoundError, match="basic"):
            b.template_path("nonexistent")

    def test_missing_templates_dir_raises(self, tmp_path):
        b = Builder(templates_dir=tmp_path / "missing")
        with pytest.raises(FileNotFoundError, match="Templates directory"):
            b.template_path("anything")

    def test_stem_conflict_returns_first_by_extension(self, tmp_path):
        """When two files share a stem, the one first alphabetically by ext wins."""
        tdir = tmp_path / "templates"
        tdir.mkdir()
        (tdir / "agent.go").write_text("// go\n")   # .go < .zig
        (tdir / "agent.zig").write_text("// zig\n")
        b = Builder(templates_dir=tdir)
        assert b.template_path("agent").suffix == ".go"


# ── list_templates edge cases ─────────────────────────────────────────────────


class TestListTemplatesEdgeCases:

    def test_ignores_files_without_extensions(self, tmp_templates):
        (tmp_templates / "README").write_text("no extension")
        b = Builder(templates_dir=tmp_templates)
        assert "README" not in b.list_templates()

    def test_ignores_hidden_dotfiles(self, tmp_templates):
        (tmp_templates / ".gitkeep").write_text("")
        names = Builder(templates_dir=tmp_templates).list_templates()
        assert ".gitkeep" not in names
        assert "" not in names

    def test_deduplicates_stem_conflict(self, tmp_templates):
        (tmp_templates / "basic.zig").write_text("// zig duplicate\n")
        names = Builder(templates_dir=tmp_templates).list_templates()
        assert names.count("basic") == 1


# ── detect_local_ip fallback ──────────────────────────────────────────────────


class TestDetectLocalIPFallback:

    def test_returns_loopback_when_socket_constructor_fails(self):
        with patch("implants.builder.socket.socket") as mock_cls:
            mock_cls.side_effect = OSError("no network")
            assert detect_local_ip() == "127.0.0.1"

    def test_returns_loopback_when_connect_fails(self):
        with patch("implants.builder.socket.socket") as mock_cls:
            mock_inst = mock_cls.return_value
            mock_inst.connect.side_effect = OSError("unreachable")
            assert detect_local_ip() == "127.0.0.1"


# ── Builder.write edge cases ──────────────────────────────────────────────────


class TestWriteEdgeCases:

    def test_overwrites_existing_file(self, tmp_path):
        out = tmp_path / "payload.py"
        out.write_text("old content\n")
        Builder().write("new content\n", out)
        assert out.read_text() == "new content\n"


# ── Zig template structural content ──────────────────────────────────────────


class TestRealZigTemplateStructure:
    """Structural / content checks for the http_zig.zig template."""

    @pytest.fixture(autouse=True)
    def skip_if_missing(self):
        if "http_zig" not in Builder().list_templates():
            pytest.skip("http_zig template not present")

    def _src(self, **kw) -> str:
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_zig", **kw)
        return Builder().build(cfg)

    def test_imports_std(self):
        assert 'const std = @import("std")' in self._src()

    def test_has_main_function(self):
        assert "pub fn main()" in self._src()

    def test_has_task_struct(self):
        assert "const Task = struct {" in self._src()

    def test_has_implant_struct(self):
        assert "const Implant = struct {" in self._src()

    def test_has_run_method(self):
        assert "pub fn run(" in self._src()

    def test_url_type_is_zig_slice(self):
        """The C2 URL constant uses a Zig []const u8 type annotation."""
        assert "[]const u8" in self._src()

    def test_beacon_interval_substituted(self):
        src = self._src(interval=20)
        assert "BEACON_INTERVAL" in src
        assert "20" in src

    def test_beacon_jitter_substituted(self):
        src = self._src(jitter=0.25)
        assert "BEACON_JITTER" in src
        assert "0.25" in src

    def test_task_types_documented_in_template(self):
        """Core task types are at least referenced (in comments or doc)."""
        src = self._src()
        for task in ("shell", "sysinfo", "whoami", "sleep", "kill"):
            assert task in src, f"Task type '{task}' not mentioned in Zig template"

    def test_uses_general_purpose_allocator(self):
        assert "GeneralPurposeAllocator" in self._src()

    @pytest.mark.skipif(
        __import__("shutil").which("zig") is None,
        reason="Zig compiler not installed",
    )
    def test_compiles_with_zig(self, tmp_path):
        """Template compiles cleanly; @panic stubs are valid Zig (runtime, not compile-time)."""
        cfg = PayloadConfig(c2_url="http://127.0.0.1:6708", template="http_zig")
        src_path = Builder().build_to_file(cfg, tmp_path / "agent.zig")
        result = subprocess.run(
            ["zig", "build-exe", str(src_path), f"-femit-bin={tmp_path / 'agent'}"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"zig build-exe failed:\n{result.stdout}\n{result.stderr}"
        )


# ── CLI (main()) ──────────────────────────────────────────────────────────────


class TestCLI:
    """Tests for the implants.builder command-line interface."""

    # -- list subcommand --

    def test_list_prints_template_names(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        from implants.builder import main
        main(["list"])
        assert "basic" in capsys.readouterr().out

    def test_list_shows_file_extension(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        from implants.builder import main
        main(["list"])
        assert ".py" in capsys.readouterr().out

    def test_list_empty_dir_prints_no_templates(self, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", empty)
        from implants.builder import main
        main(["list"])
        assert "No templates" in capsys.readouterr().out

    # -- build subcommand (stdout) --

    def test_build_stdout_contains_c2_url(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        from implants.builder import main
        main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic"])
        assert "http://1.2.3.4:6708" in capsys.readouterr().out

    def test_build_stdout_no_tokens_remain(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        from implants.builder import main
        main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic"])
        out = capsys.readouterr().out
        for tok in ("URSA_C2_URL", "URSA_INTERVAL", "URSA_JITTER"):
            assert tok not in out

    def test_build_uses_custom_interval(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        from implants.builder import main
        main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic",
              "--interval", "42"])
        assert "42" in capsys.readouterr().out

    def test_build_uses_custom_jitter(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        from implants.builder import main
        main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic",
              "--jitter", "0.7"])
        assert "0.7" in capsys.readouterr().out

    def test_build_auto_detects_c2_url_when_omitted(self, tmp_templates, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        monkeypatch.setattr(bmod, "auto_c2_url", lambda: "http://AUTO:6708")
        from implants.builder import main
        main(["build", "--template", "basic"])
        assert "http://AUTO:6708" in capsys.readouterr().out

    def test_build_missing_template_exits_1(self, capsys):
        from implants.builder import main
        with pytest.raises(SystemExit) as exc:
            main(["build", "--c2", "http://1.2.3.4:6708", "--template", "GHOST"])
        assert exc.value.code == 1

    # -- build subcommand (--output) --

    def test_build_writes_source_to_file(self, tmp_templates, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        out_file = tmp_path / "payload.py"
        from implants.builder import main
        main(["build", "--c2", "http://5.6.7.8:6708", "--template", "basic",
              "--output", str(out_file)])
        assert out_file.exists()
        assert "http://5.6.7.8:6708" in out_file.read_text()

    def test_build_to_file_prints_source_path(self, tmp_templates, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        out_file = tmp_path / "payload.py"
        from implants.builder import main
        main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic",
              "--output", str(out_file)])
        assert "Source written to" in capsys.readouterr().out

    def test_build_with_post_build_invokes_compile(
        self, tmp_templates, tmp_path, monkeypatch, capsys
    ):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        out_file = tmp_path / "payload.py"
        from implants.builder import main
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic",
                  "--output", str(out_file), "--post-build", "echo {output}"])
        assert mock_run.called
        assert "Binary:" in capsys.readouterr().out

    def test_build_compile_failure_exits_1(
        self, tmp_templates, tmp_path, monkeypatch, capsys
    ):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "TEMPLATES_DIR", tmp_templates)
        out_file = tmp_path / "payload.py"
        from implants.builder import main
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, ["false"])
            with pytest.raises(SystemExit) as exc:
                main(["build", "--c2", "http://1.2.3.4:6708", "--template", "basic",
                      "--output", str(out_file), "--post-build", "false"])
        assert exc.value.code == 1

    # -- stager subcommand --

    def test_stager_prints_to_stdout(self, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        stager = tmp_path / "stager.py"
        stager.write_text('C2 = "URSA_C2_URL"\n')
        monkeypatch.setattr(bmod, "STAGER_PATH", stager)
        from implants.builder import main
        main(["stager", "--c2", "http://9.9.9.9:6708"])
        assert "http://9.9.9.9:6708" in capsys.readouterr().out

    def test_stager_writes_to_file(self, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        stager = tmp_path / "stager.py"
        stager.write_text('C2 = "URSA_C2_URL"\n')
        monkeypatch.setattr(bmod, "STAGER_PATH", stager)
        out_file = tmp_path / "out_stager.py"
        from implants.builder import main
        main(["stager", "--c2", "http://9.9.9.9:6708", "--output", str(out_file)])
        assert "http://9.9.9.9:6708" in out_file.read_text()

    def test_stager_missing_exits_1(self, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        monkeypatch.setattr(bmod, "STAGER_PATH", tmp_path / "no_such.py")
        from implants.builder import main
        with pytest.raises(SystemExit) as exc:
            main(["stager", "--c2", "http://1.2.3.4:6708"])
        assert exc.value.code == 1

    def test_stager_auto_detects_c2_url_when_omitted(self, tmp_path, monkeypatch, capsys):
        import implants.builder as bmod
        stager = tmp_path / "stager.py"
        stager.write_text('C2 = "URSA_C2_URL"\n')
        monkeypatch.setattr(bmod, "STAGER_PATH", stager)
        monkeypatch.setattr(bmod, "auto_c2_url", lambda: "http://STAGER_AUTO:6708")
        from implants.builder import main
        main(["stager"])
        assert "http://STAGER_AUTO:6708" in capsys.readouterr().out
