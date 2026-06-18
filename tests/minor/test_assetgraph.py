"""Tests for the Ursa Minor normalized asset graph (ROADMAP Phase 6A).

Pure local + fixture-driven: no network, no sudo, no live targets. Exercises
the fact model (dedup/upsert, edges, queries), JSON round-tripping, and the
per-tool ingest adapters that turn structured_data blobs into facts.
"""

import pytest

from ursa_minor import assetgraph as ag


@pytest.fixture
def graph():
    return ag.AssetGraph(engagement_id="test")


# ── core fact model ──


def test_upsert_dedupes_by_identity_and_bumps_seen(graph):
    id1 = graph.upsert(ag.HOST, "192.168.86.20", {"vendor": "Apple"}, source="discover_network")
    id2 = graph.upsert(ag.HOST, "192.168.86.20", {"mac": "aa:bb:cc:dd:ee:ff"}, source="scan_ports")
    assert id1 == id2                       # same identity → same fact
    assert len(graph.facts_of(ag.HOST)) == 1
    fact = graph.get(id1)
    assert fact.times_seen == 2
    assert fact.attrs["vendor"] == "Apple"  # first attr preserved
    assert fact.attrs["mac"] == "aa:bb:cc:dd:ee:ff"  # second merged in
    assert fact.sources == ["discover_network", "scan_ports"]


def test_empty_values_never_clobber_known_attrs(graph):
    fid = graph.upsert(ag.HOST, "10.0.0.5", {"vendor": "Dell"}, source="x")
    graph.upsert(ag.HOST, "10.0.0.5", {"vendor": ""}, source="y")
    assert graph.get(fid).attrs["vendor"] == "Dell"


def test_deterministic_ids_are_stable_across_instances():
    a = ag.AssetGraph()
    b = ag.AssetGraph()
    assert a.upsert(ag.SERVICE, "h:443/tcp") == b.upsert(ag.SERVICE, "h:443/tcp")


def test_links_and_neighbors(graph):
    h = graph.upsert(ag.HOST, "10.0.0.5")
    s = graph.upsert(ag.SERVICE, "10.0.0.5:443/tcp")
    graph.link(h, "has_service", s)
    assert graph.neighbors(h, "has_service") == [graph.get(s)]
    assert graph.neighbors(s, "has_service", direction="in") == [graph.get(h)]
    assert graph.neighbors(s, "has_service", direction="out") == []


def test_summary_counts(graph):
    graph.upsert(ag.HOST, "10.0.0.1")
    graph.upsert(ag.HOST, "10.0.0.2")
    graph.upsert(ag.FINDING, "10.0.0.1|XSS")
    summary = graph.summary()
    assert summary["total_facts"] == 3
    assert summary["counts"]["host"] == 2
    assert summary["counts"]["finding"] == 1


def test_json_round_trip(graph):
    h = graph.upsert(ag.HOST, "10.0.0.5", {"vendor": "Dell"}, source="discover_network")
    s = graph.upsert(ag.SERVICE, "10.0.0.5:22/tcp", {"service": "ssh"}, source="scan_ports")
    graph.link(h, "has_service", s)

    restored = ag.AssetGraph.from_dict(graph.to_dict())
    assert restored.summary() == graph.summary()
    assert restored.get(h).attrs["vendor"] == "Dell"
    assert restored.neighbors(h, "has_service") == [restored.get(s)]


def test_save_and_load_graph(tmp_path):
    path = tmp_path / "eng.json"
    g = ag.AssetGraph(engagement_id="eng")
    g.upsert(ag.HOST, "10.0.0.9", {"vendor": "x"})
    g.save(path)

    loaded = ag.load_graph(engagement_id="eng", path=path)
    assert loaded.summary()["total_facts"] == 1
    assert loaded.facts_of(ag.HOST)[0].identity == "10.0.0.9"


def test_load_missing_graph_returns_empty(tmp_path):
    loaded = ag.load_graph(engagement_id="nope", path=tmp_path / "missing.json")
    assert loaded.summary()["total_facts"] == 0


# ── ingest adapters ──


def test_ingest_devices_creates_hosts(graph):
    ag.ingest(graph, "discover_network", [
        {"ip": "192.168.86.1", "mac": "AA:BB:CC:00:00:01", "vendor": "Google"},
        {"ip": "192.168.86.20", "mac": "de:ad:be:ef:00:02", "vendor": "Apple"},
    ])
    hosts = graph.facts_of(ag.HOST)
    assert len(hosts) == 2
    assert all(h.attrs.get("mac") for h in hosts)


def test_ingest_ports_links_services_to_host(graph):
    ag.ingest(
        graph, "scan_ports",
        [{"port": 22, "service": "ssh", "banner": "OpenSSH"}, {"port": 443, "service": "https", "banner": ""}],
        metadata={"target": "10.0.0.5"},
    )
    assert len(graph.facts_of(ag.SERVICE)) == 2
    host = graph.facts_of(ag.HOST)[0]
    services = graph.neighbors(host.id, "has_service")
    assert {s.attrs["port"] for s in services} == {22, 443}


def test_ingest_http_probe_creates_route_tech_and_cert(graph):
    ag.ingest(graph, "probe_http", {
        "url": "https://example.com/",
        "final_url": "https://example.com/home",
        "status": 200,
        "title": "Example",
        "server": "nginx",
        "x_powered_by": "PHP/8",
        "body_hash": "abc123",
        "favicon_hash": "def456",
        "tls": {"subject": "CN=example.com", "issuer": "CN=R3", "not_after": "2026-01-01", "fingerprint_sha256": "FP1"},
    })
    routes = graph.facts_of(ag.ROUTE)
    assert len(routes) == 1
    assert routes[0].identity == "https://example.com:443/home"
    assert len(graph.facts_of(ag.TECH_FINGERPRINT)) == 2   # nginx + PHP/8
    certs = graph.facts_of(ag.CERTIFICATE)
    assert len(certs) == 1 and certs[0].identity == "FP1"
    # route → presents_cert → certificate edge exists
    assert graph.neighbors(routes[0].id, "presents_cert") == certs


def test_ingest_findings_links_to_route(graph):
    ag.ingest(
        graph, "vuln_scan",
        [{"title": "Reflected XSS", "severity": "high", "category": "xss",
          "target": "https://example.com/search", "wstg": "WSTG-INPV-01"}],
        metadata={"target": "https://example.com/search"},
    )
    findings = graph.facts_of(ag.FINDING)
    assert len(findings) == 1
    assert findings[0].attrs["severity"] == "high"
    assert findings[0].attrs["wstg"] == "WSTG-INPV-01"
    # finding → affects → route
    routes = graph.neighbors(findings[0].id, "affects")
    assert routes and routes[0].type == ag.ROUTE


def test_ingest_dirbust_creates_routes_and_endpoints(graph):
    ag.ingest(
        graph, "dirbust",
        [{"path": "/admin", "status": 200, "size": 1024, "false_positive": False},
         {"path": "/backup", "status": 403, "size": 0, "false_positive": False},
         {"path": "/noise", "status": 200, "size": 5, "false_positive": True}],  # FP skipped
        metadata={"url": "http://10.0.0.5:8080/"},
    )
    routes = graph.facts_of(ag.ROUTE)
    assert {r.identity for r in routes} == {
        "http://10.0.0.5:8080/admin", "http://10.0.0.5:8080/backup",
    }
    # each route has a GET endpoint
    assert len(graph.facts_of(ag.ENDPOINT)) == 2
    admin = next(r for r in routes if r.identity.endswith("/admin"))
    eps = graph.neighbors(admin.id, "has_endpoint")
    assert eps and eps[0].attrs["method"] == "GET"
    # routes are served by the host
    host = graph.facts_of(ag.HOST)[0]
    assert len(graph.neighbors(host.id, "serves_route")) == 2


def test_ingest_tls_creates_certificate_and_service(graph):
    ag.ingest(graph, "tls_scan", {
        "host": "example.com", "port": 443, "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256", "self_signed": False,
        "subject": "CN=example.com", "issuer": "CN=R3", "not_after": "2026-01-01",
    })
    certs = graph.facts_of(ag.CERTIFICATE)
    assert len(certs) == 1
    assert certs[0].attrs["issuer"] == "CN=R3"
    svc = graph.facts_of(ag.SERVICE)[0]
    assert graph.neighbors(svc.id, "presents_cert") == certs


def test_ingest_os_fingerprint_picks_top_guess(graph):
    ag.ingest(
        graph, "os_fingerprint",
        [{"os": "Linux 5.x", "score": 80, "sources": ["ttl"]},
         {"os": "Windows", "score": 20, "sources": ["ttl"]}],
        metadata={"target": "10.0.0.5", "mode": "active"},
    )
    techs = graph.facts_of(ag.TECH_FINGERPRINT)
    assert len(techs) == 1
    assert techs[0].attrs["name"] == "Linux 5.x"
    assert techs[0].attrs["kind"] == "os"
    host = graph.facts_of(ag.HOST)[0]
    assert graph.neighbors(host.id, "runs") == techs


def test_finding_with_raw_exchange_attaches_evidence(graph):
    ag.ingest(
        graph, "vuln_scan",
        [{"title": "SQLi", "severity": "critical", "target": "https://x.com/item",
          "request": "GET /item?id=1' HTTP/1.1", "response": "SQL syntax error near ...",
          "matched_at": "id"}],
        metadata={},
    )
    findings = graph.facts_of(ag.FINDING)
    evidence = graph.facts_of(ag.EVIDENCE)
    assert len(findings) == 1 and len(evidence) == 1
    ev = evidence[0]
    assert ev.attrs["request"].startswith("GET /item")
    assert ev.attrs["response_sha256"]  # hashed for diffing
    # finding → has_evidence → evidence
    assert graph.neighbors(findings[0].id, "has_evidence") == [ev]


def test_add_evidence_truncates_large_body_but_hashes_full(graph):
    fid = graph.upsert(ag.FINDING, "t|big")
    big = "A" * (ag._EVIDENCE_BODY_CAP + 500)
    ev_id = ag.add_evidence(graph, fid, {"method": "get", "url": "https://x/y", "response": big}, source="check")
    ev = graph.get(ev_id)
    assert ev.attrs["response_truncated"] is True
    assert len(ev.attrs["response"]) == ag._EVIDENCE_BODY_CAP
    assert ev.attrs["method"] == "GET"  # normalized upper
    # hash is of the full body, not the truncated copy
    import hashlib
    assert ev.attrs["response_sha256"] == hashlib.sha256(big.encode()).hexdigest()


def test_unmapped_tool_is_a_noop(graph):
    ag.ingest(graph, "some_unknown_tool", [{"whatever": 1}])
    assert graph.summary()["total_facts"] == 0


def test_record_result_persists(tmp_path, monkeypatch):
    # Point the assets dir at a temp location so we don't touch ~/.ursa.
    monkeypatch.setattr(ag, "_ASSETS_DIR", tmp_path)
    summary = ag.record_result(
        "discover_network",
        [{"ip": "10.0.0.5", "mac": "aa:bb:cc:00:00:01", "vendor": "x"}],
        engagement_id="rr",
    )
    assert summary["counts"]["host"] == 1
    # The graph file was written and reloads with the host.
    reloaded = ag.load_graph(engagement_id="rr")
    assert reloaded.summary()["counts"]["host"] == 1


def test_record_result_none_data_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSETS_DIR", tmp_path)
    assert ag.record_result("scan_ports", None, engagement_id="rr") is None
