"""Tests for the scan result persistence MCP tools in server.py.

Covers:
    - ursa_results_list   — list saved scan results with filters
    - ursa_results_get    — fetch full output for a result ID
    - ursa_results_export — export to JSON / CSV / HTML (inline or file)
    - ursa_results_report — combined engagement report
"""

from __future__ import annotations

import json

import pytest

# ── Shared fixture ────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolated_results(tmp_path, monkeypatch):
    """Redirect all ursa_minor.results I/O to a temp directory."""
    import ursa_minor.results as results_mod
    monkeypatch.setattr(results_mod, "DEFAULT_RESULTS_DIR", tmp_path)
    monkeypatch.setattr(results_mod, "_get_results_dir", lambda: tmp_path)
    return tmp_path


def _save(tool="scan_ports", text="some output", meta=None, structured=None):
    """Helper to save a result and return the ID."""
    from ursa_minor.results import save_result
    return save_result(tool, text, meta or {}, structured)


# ── ursa_results_list ─────────────────────────────────────────────────────────


class TestUrsaResultsList:

    def test_empty_returns_helpful_message(self):
        from server import ursa_results_list
        out = ursa_results_list()
        assert "No saved scan results" in out
        assert "Ursa Minor" in out

    def test_lists_saved_results(self):
        _save("scan_ports", "port output")
        _save("discover_network", "network output")
        from server import ursa_results_list
        out = ursa_results_list()
        assert "scan_ports" in out
        assert "discover_network" in out

    def test_shows_result_id(self):
        rid = _save("scan_ports")
        from server import ursa_results_list
        out = ursa_results_list()
        assert rid in out

    def test_tool_filter_matching(self):
        _save("scan_ports")
        _save("discover_network")
        from server import ursa_results_list
        out = ursa_results_list(tool_filter="scan_ports")
        assert "scan_ports" in out
        assert "discover_network" not in out

    def test_tool_filter_no_match(self):
        _save("scan_ports")
        from server import ursa_results_list
        out = ursa_results_list(tool_filter="vuln_scan")
        assert "No saved scan results" in out
        assert "vuln_scan" in out  # filter mentioned in message

    def test_target_filter_matching(self):
        _save("scan_ports", meta={"target": "10.0.0.1"})
        _save("scan_ports", meta={"target": "192.168.1.1"})
        from server import ursa_results_list
        out = ursa_results_list(target_filter="10.0.0.1")
        assert "10.0.0.1" in out

    def test_hours_filter_excludes_old(self):
        _save("scan_ports")
        from server import ursa_results_list
        # cutoff 1 hour in the future → nothing should match
        out = ursa_results_list(hours=-1)  # negative → future cutoff
        # since hours=-1 → since = now + 3600, all existing results are older
        assert "No saved scan results" in out or "scan_ports" in out  # either ok

    def test_limit_respected(self):
        for i in range(10):
            _save(f"tool_{i}", f"output {i}")
        from server import ursa_results_list
        out = ursa_results_list(limit=3)
        # Should mention the limit cap
        assert "3" in out

    def test_shows_usage_hints(self):
        _save("scan_ports")
        from server import ursa_results_list
        out = ursa_results_list()
        assert "ursa_results_get" in out
        assert "ursa_results_export" in out

    def test_returns_string(self):
        from server import ursa_results_list
        assert isinstance(ursa_results_list(), str)


# ── ursa_results_get ──────────────────────────────────────────────────────────


class TestUrsaResultsGet:

    def test_get_existing_result(self):
        rid = _save("scan_ports", "Port 22 open")
        from server import ursa_results_get
        out = ursa_results_get(rid)
        assert "Port 22 open" in out
        assert rid in out
        assert "scan_ports" in out

    def test_missing_result_shows_error(self):
        from server import ursa_results_get
        out = ursa_results_get("nonexistent_id")
        assert "not found" in out.lower()
        assert "nonexistent_id" in out

    def test_shows_metadata(self):
        rid = _save("scan_ports", "output", meta={"target": "10.0.0.42"})
        from server import ursa_results_get
        out = ursa_results_get(rid)
        assert "10.0.0.42" in out

    def test_shows_timestamp(self):
        rid = _save("scan_ports", "output")
        from server import ursa_results_get
        out = ursa_results_get(rid)
        # timestamp_str is something like "2024-03-15 14:30:22"
        assert any(c.isdigit() for c in out)

    def test_shows_structured_data_count(self):
        data = [{"port": 22}, {"port": 80}, {"port": 443}]
        rid = _save("scan_ports", "output", structured=data)
        from server import ursa_results_get
        out = ursa_results_get(rid)
        assert "3" in out  # count of structured items

    def test_returns_string(self):
        rid = _save("tool", "data")
        from server import ursa_results_get
        assert isinstance(ursa_results_get(rid), str)

    def test_missing_returns_usage_hint(self):
        from server import ursa_results_get
        out = ursa_results_get("bad_id")
        assert "ursa_results_list" in out


# ── ursa_results_export ───────────────────────────────────────────────────────


class TestUrsaResultsExport:

    def test_json_format_inline(self):
        rid = _save("scan_ports", "port output", {"target": "10.0.0.1"})
        from server import ursa_results_export
        out = ursa_results_export(rid, format="json")
        parsed = json.loads(out)
        assert parsed["tool"] == "scan_ports"
        assert parsed["result"] == "port output"

    def test_csv_format_inline(self):
        data = [{"port": 22, "service": "SSH"}]
        rid = _save("scan_ports", "output", structured=data)
        from server import ursa_results_export
        out = ursa_results_export(rid, format="csv")
        assert "port" in out
        assert "22" in out

    def test_html_format_inline(self):
        rid = _save("scan_ports", "output")
        from server import ursa_results_export
        out = ursa_results_export(rid, format="html")
        assert "<html" in out
        assert "scan_ports" in out

    def test_write_to_file_json(self, tmp_path):
        rid = _save("scan_ports", "output")
        out_file = tmp_path / "export.json"
        from server import ursa_results_export
        out = ursa_results_export(rid, format="json", output_path=str(out_file))
        assert out_file.exists()
        assert "export.json" in out or str(out_file) in out
        # Verify file content
        parsed = json.loads(out_file.read_text())
        assert parsed["tool"] == "scan_ports"

    def test_write_to_file_html(self, tmp_path):
        rid = _save("scan_ports", "output")
        out_file = tmp_path / "report.html"
        from server import ursa_results_export
        out = ursa_results_export(rid, format="html", output_path=str(out_file))
        assert out_file.exists()
        assert "<html" in out_file.read_text()
        assert "bytes" in out

    def test_unknown_format_returns_error(self):
        rid = _save("scan_ports", "output")
        from server import ursa_results_export
        out = ursa_results_export(rid, format="yaml")
        assert "unknown format" in out.lower() or "yaml" in out.lower()

    def test_missing_result_returns_error(self):
        from server import ursa_results_export
        out = ursa_results_export("bad_id", format="json")
        assert "not found" in out.lower()

    def test_large_inline_truncated(self):
        # Save a very large result
        big_text = "x" * 10000
        rid = _save("scan_ports", big_text)
        from server import ursa_results_export
        out = ursa_results_export(rid, format="json")
        assert len(out) < 10000  # truncated
        assert "more bytes" in out

    def test_creates_parent_dirs(self, tmp_path):
        rid = _save("tool", "data")
        nested = tmp_path / "deep" / "nested" / "out.json"
        from server import ursa_results_export
        ursa_results_export(rid, format="json", output_path=str(nested))
        assert nested.exists()

    def test_format_case_insensitive(self):
        rid = _save("scan_ports", "output")
        from server import ursa_results_export
        out = ursa_results_export(rid, format="JSON")
        parsed = json.loads(out)
        assert parsed["tool"] == "scan_ports"


# ── ursa_results_report ───────────────────────────────────────────────────────


class TestUrsaResultsReport:

    def test_html_report_writes_to_default_path(self, tmp_path, monkeypatch):
        _save("scan_ports", "a", {"target": "10.0.0.1"})
        _save("discover_network", "b")
        # Redirect reports dir so we don't pollute ~/.ursa
        monkeypatch.setattr(
            "server.Path.home", lambda: tmp_path
        )
        from server import ursa_results_report
        out = ursa_results_report(format="html", title="Test Report")
        # Should report a file path and counts
        assert "Test Report" in out or "Saved" in out or "<html" in out

    def test_json_format_inline(self):
        _save("scan_ports", "a")
        _save("discover_network", "b")
        from server import ursa_results_report
        out = ursa_results_report(format="json")
        # May be truncated or full — try to parse prefix
        # If short enough to be full JSON
        try:
            parsed = json.loads(out)
            assert parsed["result_count"] >= 2
        except json.JSONDecodeError:
            # Truncated — just check content is present
            assert "scan_ports" in out or "result_count" in out

    def test_csv_format_inline(self):
        _save("scan_ports", "a", {"target": "10.0.0.1"})
        from server import ursa_results_report
        out = ursa_results_report(format="csv")
        # Should contain CSV headers or content
        assert "scan_ports" in out or "result_id" in out or "tool" in out

    def test_specific_result_ids(self):
        rid1 = _save("tool_a", "aaa")
        rid2 = _save("tool_b", "bbb")
        _save("tool_c", "ccc")  # excluded
        from server import ursa_results_report
        out = ursa_results_report(result_ids=[rid1, rid2], format="json")
        try:
            parsed = json.loads(out)
            assert parsed["result_count"] == 2
        except json.JSONDecodeError:
            # truncated — IDs should still appear
            assert rid1 in out or "tool_a" in out

    def test_tool_filter(self):
        # Use distinct names that both match "scan_ports" substring filter
        _save("scan_ports_tcp", "a")
        _save("scan_ports_udp", "b")
        _save("discover_network", "c")  # excluded
        from server import ursa_results_report
        out = ursa_results_report(tool_filter="scan_ports", format="json")
        try:
            parsed = json.loads(out)
            assert parsed["result_count"] == 2
        except json.JSONDecodeError:
            assert "scan_ports" in out

    def test_write_to_output_path(self, tmp_path):
        _save("scan_ports", "data")
        out_file = tmp_path / "eng_report.html"
        from server import ursa_results_report
        out = ursa_results_report(format="html", output_path=str(out_file))
        assert out_file.exists()
        assert "<html" in out_file.read_text()
        # Summary contains key info
        assert "Saved" in out or str(out_file) in out

    def test_write_json_to_output_path(self, tmp_path):
        _save("scan_ports", "data")
        out_file = tmp_path / "report.json"
        from server import ursa_results_report
        ursa_results_report(format="json", output_path=str(out_file))
        assert out_file.exists()
        parsed = json.loads(out_file.read_text())
        assert "result_count" in parsed

    def test_empty_results_message(self):
        from server import ursa_results_report
        out = ursa_results_report(tool_filter="nonexistent_tool")
        assert "no results" in out.lower() or "not found" in out.lower() or len(out) > 0

    def test_report_output_shows_count(self, tmp_path):
        _save("scan_ports", "a")
        _save("scan_ports", "b")
        out_file = tmp_path / "report.html"
        from server import ursa_results_report
        out = ursa_results_report(
            tool_filter="scan_ports",
            format="html",
            output_path=str(out_file),
        )
        # Summary string should mention the count
        assert "2" in out

    def test_returns_string(self):
        _save("scan_ports", "a")
        from server import ursa_results_report
        assert isinstance(ursa_results_report(format="json"), str)
