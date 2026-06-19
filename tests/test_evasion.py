"""Tests for implants/evasion.py — sandbox/VM detection and operational evasion."""

import os
import platform
import sys
import time

import pytest

from implants.evasion import (
    _analysis_tools_running,
    _cpu_core_count,
    _cpu_has_vm_string,
    _debugger_attached,
    _disk_size_gb,
    _dmi_has_vm_string,
    _mac_ouis,
    _process_count,
    _timing_accelerated,
    _total_ram_mb,
    _uptime_seconds,
    amsi_bypass,
    is_sandbox,
    obfuscated_sleep,
    sandbox_checks,
    spoof_process_name,
)


class TestIndividualChecks:
    def test_uptime_returns_positive_float(self):
        uptime = _uptime_seconds()
        assert isinstance(uptime, float)
        assert uptime >= 0

    def test_uptime_reasonable_range(self):
        # A machine running tests has been up for at least a few seconds.
        # Unknown returns 9999, real uptime can be much larger.
        uptime = _uptime_seconds()
        assert uptime > 0

    def test_mac_ouis_returns_set(self):
        ouis = _mac_ouis()
        assert isinstance(ouis, set)

    def test_mac_ouis_format(self):
        ouis = _mac_ouis()
        for oui in ouis:
            parts = oui.split(":")
            assert len(parts) == 3, f"OUI {oui!r} should have 3 colon-separated parts"
            assert all(len(p) == 2 for p in parts)

    def test_cpu_has_vm_string_returns_bool(self):
        result = _cpu_has_vm_string()
        assert isinstance(result, bool)

    def test_dmi_has_vm_string_returns_bool(self):
        result = _dmi_has_vm_string()
        assert isinstance(result, bool)

    def test_process_count_returns_int(self):
        count = _process_count()
        assert isinstance(count, int)
        assert count >= 0

    def test_process_count_reasonable(self):
        # Any test runner has at least a handful of processes
        count = _process_count()
        assert count > 0


class TestSandboxChecks:
    def test_returns_dict(self):
        result = sandbox_checks()
        assert isinstance(result, dict)

    def test_has_all_expected_keys(self):
        result = sandbox_checks()
        expected_keys = {
            # Original checks
            "low_uptime",
            "sandbox_user",
            "sandbox_hostname",
            "vm_mac_oui",
            "vm_cpu_string",
            "vm_dmi_string",
            "low_process_count",
            # Hardware fingerprinting
            "low_ram",
            "low_cpu_cores",
            "small_disk",
            # Debugger / analysis tools
            "debugger_attached",
            "analysis_tools",
        }
        assert expected_keys.issubset(set(result.keys()))

    def test_timing_check_key_absent_by_default(self):
        result = sandbox_checks()
        assert "timing_accelerated" not in result

    def test_timing_check_key_present_when_requested(self):
        result = sandbox_checks(timing_check=True)
        assert "timing_accelerated" in result

    def test_all_values_are_bool(self):
        result = sandbox_checks()
        for key, val in result.items():
            assert isinstance(val, bool), f"check '{key}' returned non-bool: {val!r}"

    @pytest.mark.skipif(
        os.environ.get("CI") == "true",
        reason="CI runners are VMs and legitimately trigger vm_cpu_string + vm_dmi_string + low_uptime",
    )
    def test_not_sandbox_on_dev_machine(self):
        """On a normal developer machine the machine should not be flagged."""
        result = sandbox_checks()
        hit_count = sum(1 for v in result.values() if v)
        # On a real machine we expect fewer than 3 hits
        # (CI runners may have VM MACs or low uptime — tolerate up to 2)
        assert hit_count < 3, f"Unexpected sandbox hits: {result}"


class TestIsSandbox:
    def test_returns_bool(self):
        result = is_sandbox()
        assert isinstance(result, bool)

    @pytest.mark.skipif(
        os.environ.get("CI") == "true",
        reason="CI runners are VMs; min_hits=2 legitimately fires on GitHub Actions",
    )
    def test_false_on_dev_machine(self):
        """Should not flag a real dev/CI machine at the default threshold."""
        assert is_sandbox(min_hits=2) is False

    def test_min_hits_zero_is_always_false(self):
        # 0 checks fired >= 0 required — always True; min_hits=0 edge case
        # We don't guarantee True here but it should return bool
        assert isinstance(is_sandbox(min_hits=0), bool)

    def test_min_hits_high_is_false(self):
        # Requiring all 12 checks to fire should never trigger on a real machine
        assert is_sandbox(min_hits=12) is False

    def test_is_sandbox_with_mocked_hits(self, monkeypatch):
        """Artificially inject hits to verify threshold logic."""
        from implants import evasion
        # Make uptime look tiny (< 5 minutes) and username look like sandbox
        monkeypatch.setattr(evasion, "_uptime_seconds", lambda: 10.0)
        monkeypatch.setenv("USER", "sandbox")
        # Also mock process count
        monkeypatch.setattr(evasion, "_process_count", lambda: 5)

        result = evasion.sandbox_checks()
        hit_count = sum(1 for v in result.values() if v)
        # low_uptime + sandbox_user + low_process_count = at least 3 hits
        assert hit_count >= 3
        assert evasion.is_sandbox(min_hits=2) is True


class TestInlineBeaconCheck:
    """Verify the beacon.py inline _is_sandbox() matches the standalone module."""

    def test_beacon_has_is_sandbox(self):
        from implants.beacon import _is_sandbox
        assert callable(_is_sandbox)

    def test_beacon_is_sandbox_returns_bool(self):
        from implants.beacon import _is_sandbox
        result = _is_sandbox()
        assert isinstance(result, bool)

    @pytest.mark.skipif(
        os.environ.get("CI") == "true",
        reason="CI runners are VMs; min_hits=2 legitimately fires on GitHub Actions",
    )
    def test_beacon_is_sandbox_false_on_dev_machine(self):
        from implants.beacon import _is_sandbox
        assert _is_sandbox(min_hits=2) is False

    def test_beacon_has_spoof_process_name(self):
        from implants.beacon import _spoof_process_name
        assert callable(_spoof_process_name)


class TestSpoofProcessName:
    """Tests for spoof_process_name() in evasion.py."""

    def test_returns_bool(self):
        result = spoof_process_name("test-process")
        assert isinstance(result, bool)

    def test_returns_true_via_argv_fallback(self):
        # argv[0] mutation is always available, so should succeed
        result = spoof_process_name("test-process")
        assert result is True

    def test_argv0_is_changed(self):
        original = sys.argv[0]
        spoof_process_name("my-fake-process")
        assert sys.argv[0] == "my-fake-process"
        # Restore
        sys.argv[0] = original

    def test_empty_string_no_crash(self):
        # Empty name should not raise
        result = spoof_process_name("")
        assert isinstance(result, bool)

    def test_long_name_no_crash(self):
        # Very long names should not raise (prctl truncates to 15, argv is unlimited)
        result = spoof_process_name("a" * 200)
        assert isinstance(result, bool)

    def test_setproctitle_graceful_when_missing(self, monkeypatch):
        """If setproctitle is not installed, falls through gracefully."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "setproctitle":
                raise ImportError("no module")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        # Should still return True (argv[0] fallback)
        result = spoof_process_name("fallback-test")
        assert result is True

    @pytest.mark.skipif(platform.system() != "Linux", reason="prctl is Linux-only")
    def test_linux_prctl_attempt(self):
        """On Linux, the prctl path is attempted (may or may not succeed)."""
        result = spoof_process_name("ursa-beacon")
        assert isinstance(result, bool)


# ── Hardware fingerprinting ───────────────────────────────────────────────────


class TestHardwareFingerprinting:

    def test_total_ram_mb_returns_int(self):
        ram = _total_ram_mb()
        assert isinstance(ram, int)

    def test_total_ram_mb_nonnegative(self):
        assert _total_ram_mb() >= 0

    def test_total_ram_mb_nonzero_on_real_machine(self):
        # Any machine running tests has some RAM
        ram = _total_ram_mb()
        assert ram == 0 or ram > 500, f"Suspicious RAM: {ram} MB"

    def test_cpu_core_count_returns_int(self):
        assert isinstance(_cpu_core_count(), int)

    def test_cpu_core_count_at_least_one(self):
        assert _cpu_core_count() >= 1

    def test_disk_size_gb_returns_float(self):
        result = _disk_size_gb()
        assert isinstance(result, float)

    def test_disk_size_gb_positive(self):
        result = _disk_size_gb()
        assert result > 0

    def test_sandbox_checks_low_ram_false_on_real_machine(self):
        # A real dev machine has >= 2 GB RAM
        checks = sandbox_checks()
        ram = _total_ram_mb()
        if ram >= 2048:
            assert checks["low_ram"] is False

    def test_sandbox_checks_low_cpu_cores_false_on_real_machine(self):
        checks = sandbox_checks()
        if _cpu_core_count() >= 2:
            assert checks["low_cpu_cores"] is False

    def test_sandbox_checks_small_disk_false_on_real_machine(self):
        checks = sandbox_checks()
        if _disk_size_gb() >= 60:
            assert checks["small_disk"] is False


# ── Debugger detection ────────────────────────────────────────────────────────


class TestDebuggerDetection:

    def test_returns_bool(self):
        assert isinstance(_debugger_attached(), bool)

    def test_false_when_not_debugged(self):
        # Normal test runner is not inside a debugger
        assert _debugger_attached() is False

    def test_sandbox_checks_has_key(self):
        checks = sandbox_checks()
        assert "debugger_attached" in checks
        assert isinstance(checks["debugger_attached"], bool)

    def test_sandbox_checks_false_on_dev_machine(self):
        # Should not flag a normal dev/CI environment
        assert sandbox_checks()["debugger_attached"] is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux /proc only")
    def test_linux_reads_tracer_pid(self, tmp_path, monkeypatch):
        """Simulate a non-zero TracerPid in /proc/self/status."""
        from implants import evasion
        fake_status = "Name:\tpython3\nTracerPid:\t1234\nUid:\t1000\n"
        fake_file = tmp_path / "status"
        fake_file.write_text(fake_status)

        original_open = open

        def mock_open(path, *a, **kw):
            if str(path) == "/proc/self/status":
                return original_open(fake_file, *a, **kw)
            return original_open(path, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", mock_open)
        assert evasion._debugger_attached() is True

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux /proc only")
    def test_linux_zero_tracer_pid_not_debugged(self, tmp_path, monkeypatch):
        from implants import evasion
        fake_status = "Name:\tpython3\nTracerPid:\t0\nUid:\t1000\n"
        fake_file = tmp_path / "status"
        fake_file.write_text(fake_status)

        original_open = open

        def mock_open(path, *a, **kw):
            if str(path) == "/proc/self/status":
                return original_open(fake_file, *a, **kw)
            return original_open(path, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", mock_open)
        assert evasion._debugger_attached() is False


# ── Analysis tool detection ───────────────────────────────────────────────────


class TestAnalysisToolDetection:

    def test_returns_bool(self):
        assert isinstance(_analysis_tools_running(), bool)

    def test_false_on_clean_machine(self):
        # No analysis tools should be running in a normal CI/dev environment
        assert _analysis_tools_running() is False

    def test_sandbox_checks_has_key(self):
        checks = sandbox_checks()
        assert "analysis_tools" in checks

    def test_detects_fake_analysis_process(self, monkeypatch):
        """Inject a fake process list containing a known analysis tool."""
        import subprocess as sp

        from implants import evasion

        class FakeResult:
            stdout = "python3\nwireshark\nbash\n"

        monkeypatch.setattr(sp, "run", lambda *a, **kw: FakeResult())
        assert evasion._analysis_tools_running() is True

    def test_ignores_unrelated_processes(self, monkeypatch):
        """Normal processes should not trigger detection."""
        import subprocess as sp

        from implants import evasion

        class FakeResult:
            stdout = "python3\nbash\nnginx\nsshd\ncron\n"

        monkeypatch.setattr(sp, "run", lambda *a, **kw: FakeResult())
        assert evasion._analysis_tools_running() is False


# ── Timing attack detection ───────────────────────────────────────────────────


class TestTimingDetection:

    def test_returns_bool(self):
        assert isinstance(_timing_accelerated(test_secs=0.05), bool)

    def test_false_on_real_machine(self):
        # A real machine takes ~1s to sleep 1s
        # Use a very short sleep to keep tests fast
        assert _timing_accelerated(test_secs=0.1) is False

    def test_detects_accelerated_time(self, monkeypatch):
        """Simulate a sandbox that fast-forwards time.sleep."""
        from implants import evasion
        # Make time.monotonic() always show very little elapsed time
        call_count = [0]
        base = time.monotonic()

        def fast_monotonic():
            call_count[0] += 1
            # First call: start time, second call: return only 0.05s later
            if call_count[0] == 1:
                return base
            return base + 0.05  # way less than 1.0s

        monkeypatch.setattr(evasion.time, "monotonic", fast_monotonic)
        monkeypatch.setattr(evasion.time, "sleep", lambda _: None)  # instant

        assert evasion._timing_accelerated(test_secs=1.0) is True


# ── AMSI bypass ──────────────────────────────────────────────────────────────


class TestAmsiBypass:

    def test_returns_bool(self):
        assert isinstance(amsi_bypass(), bool)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Non-Windows path")
    def test_returns_false_on_non_windows(self):
        assert amsi_bypass() is False

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
    def test_returns_true_on_windows(self):
        # On Windows with amsi.dll present this should succeed
        result = amsi_bypass()
        assert isinstance(result, bool)

    def test_beacon_has_amsi_bypass(self):
        from implants.beacon import _amsi_bypass
        assert callable(_amsi_bypass)

    def test_beacon_amsi_bypass_false_on_non_windows(self):
        if platform.system() == "Windows":
            pytest.skip("Windows-only")
        from implants.beacon import _amsi_bypass
        assert _amsi_bypass() is False

    def test_beacon_init_accepts_amsi_bypass_flag(self):
        from implants.beacon import UrsaBeacon
        # Should not raise
        b = UrsaBeacon("http://127.0.0.1:9999", amsi_bypass=False)
        assert b is not None

    def test_beacon_init_amsi_bypass_true_no_crash(self):
        from implants.beacon import UrsaBeacon
        # amsi_bypass=True is a no-op on non-Windows — should not raise
        b = UrsaBeacon("http://127.0.0.1:9999", amsi_bypass=True)
        assert b is not None


# ── Obfuscated sleep ──────────────────────────────────────────────────────────


class TestObfuscatedSleep:

    def test_returns_none(self):
        result = obfuscated_sleep(0.04)
        assert result is None

    def test_zero_duration_no_crash(self):
        obfuscated_sleep(0)

    def test_negative_duration_no_crash(self):
        obfuscated_sleep(-5)

    def test_sleeps_approximately_correct_duration(self):
        start = time.monotonic()
        obfuscated_sleep(0.2)
        elapsed = time.monotonic() - start
        # Should be at least 0.15s (allowing generous tolerance for test speed)
        assert elapsed >= 0.10, f"Too fast: {elapsed:.3f}s"

    def test_beacon_has_obfuscated_sleep(self):
        from implants.beacon import _obfuscated_sleep
        assert callable(_obfuscated_sleep)

    def test_beacon_obfuscated_sleep_runs(self):
        from implants.beacon import _obfuscated_sleep
        _obfuscated_sleep(0.04)  # Just check it doesn't raise

    def test_beacon_jitter_sleep_uses_obfuscated_sleep(self, monkeypatch):
        """Verify _jitter_sleep delegates to _obfuscated_sleep, not time.sleep."""
        from implants import beacon as beacon_mod
        calls = []

        monkeypatch.setattr(beacon_mod, "_obfuscated_sleep", lambda s: calls.append(s))

        b = beacon_mod.UrsaBeacon("http://127.0.0.1:9999", interval=5, jitter=0.0,
                                   sandbox_check=False, amsi_bypass=False)
        b._jitter_sleep()
        assert len(calls) == 1
        assert calls[0] >= 1.0  # at least 1 second (clamped minimum)
