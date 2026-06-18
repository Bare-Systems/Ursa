"""Tests for the Ursa Minor declarative check engine (ROADMAP Phase 6C).

Pure local: matcher logic is exercised directly, and request execution uses an
injectable fake opener returning canned responses — no network, no live targets.
"""


from ursa_minor import assetgraph as ag
from ursa_minor import checkengine as ce

# ── fake HTTP plumbing ──


class _FakeHeaders:
    def __init__(self, headers):
        self._h = headers

    def items(self):
        return self._h.items()


class _FakeResp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = _FakeHeaders(headers)
        self._body = body.encode() if isinstance(body, str) else body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def opener_for(routes):
    """Build a fake urlopen mapping URL-suffix → (status, headers, body)."""
    def _open(request, timeout=None):
        url = request.full_url
        for suffix, (status, headers, body) in routes.items():
            if url.endswith(suffix):
                return _FakeResp(status, headers, body)
        return _FakeResp(404, {}, "not found")
    return _open


# ── matcher unit logic ──


def test_status_matcher():
    m = ce.Matcher(type="status", values=[200, 301])
    assert m.evaluate({"status": 200})
    assert not m.evaluate({"status": 404})


def test_word_matcher_and_condition():
    m = ce.Matcher(type="word", part="body", values=["foo", "bar"], condition="and")
    assert m.evaluate({"body": "foo and bar"})
    assert not m.evaluate({"body": "only foo"})


def test_regex_matcher():
    m = ce.Matcher(type="regex", part="body", values=[r"(?m)^[A-Z0-9_]+="])
    assert m.evaluate({"body": "API_KEY=secret\n"})
    assert not m.evaluate({"body": "nothing here"})


def test_header_matcher_presence_and_negative():
    present = ce.Matcher(type="header", values=["server"])
    absent = ce.Matcher(type="header", values=["strict-transport-security"], negative=True)
    resp = {"headers": {"server": "nginx"}}
    assert present.evaluate(resp)
    assert absent.evaluate(resp)          # HSTS absent → negative matcher fires
    assert not absent.evaluate({"headers": {"strict-transport-security": "max-age=1"}})


# ── template loading ──


def test_load_template_from_dict_and_yaml():
    yaml_text = """
id: demo-check
info:
  name: Demo Check
  severity: medium
  wstg: WSTG-CONF-01
http:
  - method: GET
    path: /demo
    matchers-condition: and
    matchers:
      - type: status
        values: [200]
      - type: word
        values: ["hello"]
"""
    templates = ce.load_templates_from_yaml(yaml_text)
    assert len(templates) == 1
    t = templates[0]
    assert t.id == "demo-check" and t.severity == "medium" and t.wstg == "WSTG-CONF-01"
    assert t.requests[0].matchers_condition == "and"
    assert len(t.requests[0].matchers) == 2


def test_builtin_templates_parse():
    templates = ce.builtin_templates()
    ids = {t.id for t in templates}
    assert {"exposed-git-config", "exposed-dotenv", "missing-hsts"} <= ids


# ── execution + matching end to end ──


def test_run_template_matches_exposed_git():
    git = next(t for t in ce.builtin_templates() if t.id == "exposed-git-config")
    opener = opener_for({"/.git/config": (200, {"Content-Type": "text/plain"}, "[core]\n\trepositoryformatversion = 0")})
    findings = ce.run_template(git, "http://target.test", opener=opener)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["template_id"] == "exposed-git-config"
    assert f["request"].startswith("GET http://target.test/.git/config")
    assert "[core]" in f["response"]
    assert f["wstg"] == "WSTG-CONF-05"


def test_run_template_no_match_when_404():
    git = next(t for t in ce.builtin_templates() if t.id == "exposed-git-config")
    opener = opener_for({})  # everything 404s
    assert ce.run_template(git, "http://target.test", opener=opener) == []


def test_missing_hsts_fires_only_without_header():
    hsts = next(t for t in ce.builtin_templates() if t.id == "missing-hsts")
    no_header = opener_for({"/": (200, {"Content-Type": "text/html"}, "<html>")})
    with_header = opener_for({"/": (200, {"Strict-Transport-Security": "max-age=63072000"}, "<html>")})
    assert len(ce.run_template(hsts, "https://target.test", opener=no_header)) == 1
    assert ce.run_template(hsts, "https://target.test", opener=with_header) == []


def test_unreachable_host_yields_no_findings():
    import urllib.error

    def dead_opener(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    git = next(t for t in ce.builtin_templates() if t.id == "exposed-git-config")
    assert ce.run_template(git, "http://down.test", opener=dead_opener) == []


def test_http_error_status_is_matchable():
    # A template matching 403 should fire even though urllib raises HTTPError.
    import io
    import urllib.error

    tmpl = ce.load_template({
        "id": "forbidden-probe",
        "info": {"name": "403 probe", "severity": "info"},
        "http": [{"method": "GET", "path": "/admin", "matchers": [{"type": "status", "values": [403]}]}],
    })

    def forbidden_opener(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(b"nope"))

    findings = ce.run_template(tmpl, "http://target.test", opener=forbidden_opener)
    assert len(findings) == 1 and findings[0]["template_id"] == "forbidden-probe"


# ── asset graph integration ──


def test_findings_flow_into_graph_with_evidence():
    git = next(t for t in ce.builtin_templates() if t.id == "exposed-git-config")
    opener = opener_for({"/.git/config": (200, {}, "[core]\n")})
    findings = ce.run_template(git, "http://target.test", opener=opener)

    graph = ag.AssetGraph(engagement_id="test")
    ag.ingest(graph, "run_checks", findings, metadata={"target": "http://target.test"})

    assert len(graph.facts_of(ag.FINDING)) == 1
    evidence = graph.facts_of(ag.EVIDENCE)
    assert len(evidence) == 1
    assert "[core]" in evidence[0].attrs["response"]
    # finding → affects → route, and finding → has_evidence → evidence
    finding = graph.facts_of(ag.FINDING)[0]
    assert graph.neighbors(finding.id, "has_evidence") == evidence
    assert any(n.type == ag.ROUTE for n in graph.neighbors(finding.id, "affects"))
