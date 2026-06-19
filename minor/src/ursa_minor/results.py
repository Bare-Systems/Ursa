"""
Ursa Minor — Scan Result Persistence & Export
==============================================
Auto-saves scan results as JSON. Exports to JSON, CSV, or HTML.

Results are stored in ~/.ursa/results/ (configurable via ursa.yaml).
"""

import csv
import html
import io
import json
import os
import time
from datetime import datetime
from pathlib import Path


DEFAULT_RESULTS_DIR = Path.home() / ".ursa" / "results"

# Tools whose results contain sensitive credential data. Excluded from
# unfiltered listings to prevent inadvertent exposure via list_scan_results.
# Retrievable directly by result ID or by passing tool_filter explicitly.
_SENSITIVE_TOOLS = {"crack_hash", "credential_spray"}


def _get_results_dir() -> Path:
    """Get results directory, creating it if needed."""
    try:
        from major.config import get_config
        cfg = get_config()
        results_dir = Path(cfg.get("minor.results_dir", str(DEFAULT_RESULTS_DIR)))
    except ImportError:
        results_dir = DEFAULT_RESULTS_DIR

    # Expand ~ in path
    results_dir = results_dir.expanduser()
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def save_result(
    tool_name: str,
    result_data: str,
    metadata: dict | None = None,
    structured_data: list | dict | None = None,
) -> str:
    """Save a scan result to disk.

    Args:
        tool_name: Name of the MCP tool (e.g. "scan_ports")
        result_data: The raw text output from the tool
        metadata: Optional dict with extra info (target, args, etc.)
        structured_data: Optional structured results (list of dicts, dict, etc.)

    Returns:
        Result ID (filename stem) for later retrieval.
    """
    results_dir = _get_results_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_id = f"{tool_name}_{ts}"
    filepath = results_dir / f"{result_id}.json"

    record = {
        "id": result_id,
        "tool": tool_name,
        "timestamp": time.time(),
        "timestamp_str": datetime.now().isoformat(),
        "metadata": metadata or {},
        "result": result_data,
    }

    if structured_data is not None:
        record["structured_data"] = structured_data

    with open(filepath, "w") as f:
        json.dump(record, f, indent=2, default=str)

    return result_id


def list_results(
    tool_filter: str | None = None,
    target_filter: str | None = None,
    since: float | None = None,
    limit: int = 50,
) -> list[dict]:
    """List saved scan results.

    Args:
        tool_filter: Filter by tool name (substring match).
        target_filter: Filter by target (substring match on metadata values).
        since: Only return results newer than this Unix timestamp.
        limit: Max results to return.

    Returns:
        List of result metadata dicts (without full result data).
    """
    results_dir = _get_results_dir()
    results = []

    json_files = sorted(results_dir.glob("*.json"), key=os.path.getmtime, reverse=True)

    for filepath in json_files[:limit * 3]:  # read extra in case of filters
        try:
            with open(filepath) as f:
                record = json.load(f)
            tool = record.get("tool", "")
            # Suppress sensitive credential results unless caller explicitly
            # asked for that tool by name.
            if tool in _SENSITIVE_TOOLS and (
                tool_filter is None or tool_filter.lower() not in tool.lower()
            ):
                continue
            if tool_filter and tool_filter.lower() not in tool.lower():
                continue
            if since and record.get("timestamp", 0) < since:
                continue
            if target_filter:
                meta = record.get("metadata", {})
                meta_values = " ".join(str(v) for v in meta.values()).lower()
                if target_filter.lower() not in meta_values:
                    continue
            results.append({
                "id": record.get("id", filepath.stem),
                "tool": record.get("tool", "unknown"),
                "timestamp": record.get("timestamp_str", ""),
                "metadata": record.get("metadata", {}),
            })
            if len(results) >= limit:
                break
        except (json.JSONDecodeError, KeyError):
            continue

    return results


def get_result(result_id: str) -> dict | None:
    """Retrieve a specific scan result by ID.

    Returns:
        Full result record including data, or None if not found.
    """
    results_dir = _get_results_dir()
    filepath = results_dir / f"{result_id}.json"

    if not filepath.exists():
        return None

    with open(filepath) as f:
        return json.load(f)


def delete_result(result_id: str) -> bool:
    """Delete a saved scan result.

    Returns:
        True if deleted, False if not found.
    """
    results_dir = _get_results_dir()
    filepath = results_dir / f"{result_id}.json"

    if not filepath.exists():
        return False

    filepath.unlink()
    return True


def export_json(result_id: str) -> str:
    """Export a result as formatted JSON."""
    record = get_result(result_id)
    if not record:
        return f"Result {result_id} not found."
    return json.dumps(record, indent=2, default=str)


def export_csv(result_id: str) -> str:
    """Export a result as CSV. Uses structured data when available."""
    record = get_result(result_id)
    if not record:
        return f"Result {result_id} not found."

    output = io.StringIO()

    # If structured data is a list of dicts, write proper tabular CSV
    structured = record.get("structured_data")
    if structured and isinstance(structured, list) and structured and isinstance(structured[0], dict):
        writer = csv.DictWriter(output, fieldnames=structured[0].keys())
        writer.writeheader()
        writer.writerows(structured)
        return output.getvalue()

    # Fallback: dump text lines
    plain_writer = csv.writer(output)
    plain_writer.writerow(["tool", "timestamp", "result_id"])
    plain_writer.writerow([record.get("tool", ""), record.get("timestamp_str", ""), result_id])
    plain_writer.writerow([])

    result_text = record.get("result", "")
    lines = result_text.strip().split("\n")
    for line in lines:
        plain_writer.writerow([line])

    return output.getvalue()


def _render_structured_html(tool: str, structured_data: list | dict) -> str:
    """Render structured data as HTML tables based on tool type."""
    if isinstance(structured_data, list) and structured_data and isinstance(structured_data[0], dict):
        # Generic table for list-of-dicts
        keys = list(structured_data[0].keys())
        header = "".join(f"<th>{html.escape(str(k))}</th>" for k in keys)
        rows = ""
        for item in structured_data:
            cells = ""
            for k in keys:
                val = str(item.get(k, ""))
                # Color severity values
                css = ""
                if k == "severity" or k == "risk_level":
                    level = val.lower()
                    if level == "critical":
                        css = ' style="color:var(--red);font-weight:bold"'
                    elif level == "high":
                        css = ' style="color:var(--yellow);font-weight:bold"'
                cells += f"<td{css}>{html.escape(val)}</td>"
            rows += f"<tr>{cells}</tr>\n"
        return f"<table><tr>{header}</tr>\n{rows}</table>"

    if isinstance(structured_data, dict):
        # Key-value table for dicts
        rows = ""
        for k, v in structured_data.items():
            if isinstance(v, (list, dict)):
                val = json.dumps(v, indent=2, default=str)
                rows += f"<tr><td>{html.escape(str(k))}</td><td><pre>{html.escape(val)}</pre></td></tr>\n"
            else:
                rows += f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>\n"
        return f"<table><tr><th>Key</th><th>Value</th></tr>\n{rows}</table>"

    return ""


_HTML_STYLE = """:root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    padding: 2rem; line-height: 1.5;
  }
  h1 { color: var(--accent); margin-bottom: 0.5rem; font-size: 1.5rem; }
  h2 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
  .meta { color: var(--text-muted); margin-bottom: 1.5rem; font-size: 0.9rem; }
  table {
    width: 100%; border-collapse: collapse; margin-bottom: 1.5rem;
    background: var(--surface); border-radius: 6px; overflow: hidden;
  }
  th, td {
    padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border);
  }
  th { background: var(--border); color: var(--text-muted); font-weight: 600; font-size: 0.85rem; }
  pre {
    background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
    padding: 1rem; overflow-x: auto; font-family: 'SF Mono', Monaco, monospace;
    font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;
  }
  .section { margin-bottom: 2rem; }
  .footer { color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; text-align: center; }"""


def export_html(result_id: str) -> str:
    """Export a result as a self-contained HTML report."""
    record = get_result(result_id)
    if not record:
        return f"Result {result_id} not found."

    tool = record.get("tool", "unknown")
    timestamp = record.get("timestamp_str", "")
    metadata = record.get("metadata", {})
    result_text = record.get("result", "")
    structured = record.get("structured_data")

    meta_rows = ""
    for k, v in metadata.items():
        meta_rows += f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>\n"

    meta_section = ""
    if meta_rows:
        meta_section = f"<h2>Scan Parameters</h2>\n<table><tr><th>Key</th><th>Value</th></tr>\n{meta_rows}</table>"

    # Render structured data as proper tables when available
    data_section = ""
    if structured:
        data_section = f"<h2>Results</h2>\n{_render_structured_html(tool, structured)}"

    output_section = f"<h2>Output</h2>\n<pre>{html.escape(result_text)}</pre>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Ursa Minor — {html.escape(tool)} Report</title>
<style>{_HTML_STYLE}</style>
</head>
<body>
  <h1>Ursa Minor — {html.escape(tool)}</h1>
  <p class="meta">Generated: {html.escape(timestamp)} | ID: {html.escape(result_id)}</p>

  {meta_section}
  {data_section}
  {output_section}

  <p class="footer">Ursa Minor Recon Toolkit — Bare Systems</p>
</body>
</html>"""


def diff_results(baseline_id: str, current_id: str) -> dict:
    """Diff two saved scan results and return a structured delta.

    Compares the ``structured_data`` findings lists of two results saved by
    the same tool.  Findings are normalised to strings for comparison —
    structured dicts are serialised as JSON lines.  Returns a dict with keys:

    - ``baseline_id``, ``current_id``: the two result IDs
    - ``baseline_tool``, ``current_tool``: tool names
    - ``new_findings``: items in current but not in baseline
    - ``fixed_findings``: items in baseline but not in current
    - ``unchanged_count``: count of items present in both
    - ``error``: non-empty string if either result is missing

    Args:
        baseline_id: Result ID of the earlier (reference) scan.
        current_id:  Result ID of the newer scan to compare against.
    """
    baseline_rec = get_result(baseline_id)
    current_rec = get_result(current_id)

    errors = []
    if not baseline_rec:
        errors.append(f"Baseline result '{baseline_id}' not found")
    if not current_rec:
        errors.append(f"Current result '{current_id}' not found")
    if errors:
        return {"error": "; ".join(errors), "baseline_id": baseline_id, "current_id": current_id}

    assert baseline_rec is not None
    assert current_rec is not None

    def _to_set(rec: dict) -> set[str]:
        sd = rec.get("structured_data")
        if sd is None:
            # Fall back to non-empty lines from raw text result
            return {line.strip() for line in rec.get("result", "").splitlines() if line.strip()}
        if isinstance(sd, list):
            return {json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item) for item in sd}
        if isinstance(sd, dict):
            return {json.dumps(sd, sort_keys=True)}
        return {str(sd)}

    baseline_set = _to_set(baseline_rec)
    current_set = _to_set(current_rec)

    new_findings = sorted(current_set - baseline_set)
    fixed_findings = sorted(baseline_set - current_set)
    unchanged_count = len(baseline_set & current_set)

    return {
        "baseline_id": baseline_id,
        "current_id": current_id,
        "baseline_tool": baseline_rec.get("tool", "unknown"),
        "current_tool": current_rec.get("tool", "unknown"),
        "baseline_timestamp": baseline_rec.get("timestamp_str", ""),
        "current_timestamp": current_rec.get("timestamp_str", ""),
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "unchanged_count": unchanged_count,
        "new_count": len(new_findings),
        "fixed_count": len(fixed_findings),
        "error": "",
    }


def export_engagement_report(
    result_ids: list[str] | None = None,
    tool_filter: str | None = None,
    title: str = "Engagement Report",
    format: str = "html",
) -> str:
    """Generate a combined report from multiple scan results.

    Args:
        result_ids: Specific result IDs to include. Uses all if None.
        tool_filter: Filter by tool name when result_ids is None.
        title: Report title.
        format: "html", "json", or "csv".

    Returns:
        Report content as a string.
    """
    # Gather records
    if result_ids:
        records = []
        for rid in result_ids:
            rec = get_result(rid)
            if rec:
                records.append(rec)
    else:
        listing = list_results(tool_filter=tool_filter, limit=200)
        records = []
        for item in listing:
            rec = get_result(item["id"])
            if rec:
                records.append(rec)

    if not records:
        return "No results found for engagement report."

    if format == "json":
        report = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "result_count": len(records),
            "results": records,
        }
        return json.dumps(report, indent=2, default=str)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["result_id", "tool", "timestamp", "target", "output"])
        for rec in records:
            target = rec.get("metadata", {}).get("target", rec.get("metadata", {}).get("target_range", ""))
            writer.writerow([
                rec.get("id", ""),
                rec.get("tool", ""),
                rec.get("timestamp_str", ""),
                target,
                rec.get("result", "")[:500],
            ])
        return output.getvalue()

    # HTML format
    sections = ""
    for rec in records:
        tool = rec.get("tool", "unknown")
        rid = rec.get("id", "unknown")
        ts = rec.get("timestamp_str", "")
        structured = rec.get("structured_data")
        result_text = rec.get("result", "")

        data_html = ""
        if structured:
            data_html = _render_structured_html(tool, structured)

        sections += f"""<div class="section">
  <h2>{html.escape(tool)} <span style="color:var(--text-muted);font-size:0.8rem">({html.escape(rid)})</span></h2>
  <p class="meta">{html.escape(ts)}</p>
  {data_html}
  <pre>{html.escape(result_text)}</pre>
</div>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Ursa Minor — {html.escape(title)}</title>
<style>{_HTML_STYLE}</style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <p class="meta">Generated: {html.escape(datetime.now().isoformat())} | Results: {len(records)}</p>

  {sections}

  <p class="footer">Ursa Minor Recon Toolkit — Bare Systems</p>
</body>
</html>"""
