"""
Ursa Minor — Normalized Asset Graph + Evidence Schema
=====================================================
ROADMAP Phase 6, Stage 6A. The substrate the rest of the pentest-conductor
work builds on.

Today every tool emits its own freeform ``structured_data`` blob. This module
turns those blobs into *facts*: typed, de-duplicated objects that link into a
graph the model can reason over cheaply, instead of re-parsing terminal output.

Fact types (the doc's normalized object model):
    host · domain · service · certificate · route · endpoint ·
    parameter · auth_context · technology_fingerprint · finding

Each fact has a deterministic id derived from its identity, so re-ingesting the
same thing upserts (refreshes attrs, bumps ``times_seen``/``last_seen``) instead
of duplicating. Facts are linked with directed edges (e.g. host →has_service→
service, finding →affects→ route).

Storage mirrors the existing ``~/.ursa/`` JSON convention (see engagement.py /
results.py): one graph file per engagement at ``~/.ursa/assets/<engagement>.json``.
Ingestion is best-effort and must never break a scan — callers wrap it so a
graph write failure is swallowed.
"""

import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

# Fact type constants — the normalized object model.
HOST = "host"
DOMAIN = "domain"
SERVICE = "service"
CERTIFICATE = "certificate"
ROUTE = "route"
ENDPOINT = "endpoint"
PARAMETER = "parameter"
AUTH_CONTEXT = "auth_context"
TECH_FINGERPRINT = "technology_fingerprint"
FINDING = "finding"
# Supporting type: a replayable raw request/response exchange, attached to the
# finding or route it substantiates. First-class so it is queryable and diffable.
EVIDENCE = "evidence"

FACT_TYPES = (
    HOST, DOMAIN, SERVICE, CERTIFICATE, ROUTE, ENDPOINT,
    PARAMETER, AUTH_CONTEXT, TECH_FINGERPRINT, FINDING, EVIDENCE,
)

# Response bodies are truncated to this many chars in the stored evidence so a
# large page can't bloat the graph file; the full-body sha256 is kept for diffing.
_EVIDENCE_BODY_CAP = 8192

_ASSETS_DIR = Path.home() / ".ursa" / "assets"


def _fact_id(ftype: str, identity: str) -> str:
    """Deterministic, collision-resistant id for a fact's identity."""
    digest = hashlib.sha1(f"{ftype}|{identity}".encode()).hexdigest()[:12]
    return f"{ftype}:{digest}"


@dataclass
class Fact:
    type: str
    id: str
    identity: str
    attrs: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    times_seen: int = 0

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "id": self.id,
            "identity": self.identity,
            "attrs": self.attrs,
            "sources": self.sources,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "times_seen": self.times_seen,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Fact":
        return cls(
            type=d["type"],
            id=d["id"],
            identity=d.get("identity", ""),
            attrs=d.get("attrs", {}),
            sources=d.get("sources", []),
            first_seen=d.get("first_seen", 0.0),
            last_seen=d.get("last_seen", 0.0),
            times_seen=d.get("times_seen", 0),
        )


class AssetGraph:
    """An in-memory graph of facts + directed edges, persisted per engagement."""

    def __init__(self, engagement_id: str = "default"):
        self.engagement_id = engagement_id
        self.facts: dict[str, Fact] = {}
        # Edges as a set of (src_id, rel, dst_id) tuples; serialised as a list.
        self.edges: set[tuple[str, str, str]] = set()

    # ── mutation ──

    def upsert(self, ftype: str, identity: str, attrs: dict | None = None, source: str | None = None) -> str:
        """Insert or refresh a fact. Returns its id.

        On refresh: non-empty attr values overwrite/extend existing ones (empty
        values never clobber a known value), ``times_seen`` increments, and the
        source is recorded.
        """
        identity = (identity or "").strip()
        fid = _fact_id(ftype, identity)
        now = time.time()
        fact = self.facts.get(fid)
        if fact is None:
            fact = Fact(type=ftype, id=fid, identity=identity, first_seen=now)
            self.facts[fid] = fact
        for key, value in (attrs or {}).items():
            if value in (None, "", [], {}):
                continue
            fact.attrs[key] = value
        if source and source not in fact.sources:
            fact.sources.append(source)
        fact.last_seen = now
        fact.times_seen += 1
        return fid

    def link(self, src_id: str, rel: str, dst_id: str) -> None:
        if src_id and dst_id:
            self.edges.add((src_id, rel, dst_id))

    # ── queries ──

    def get(self, fid: str) -> Fact | None:
        return self.facts.get(fid)

    def facts_of(self, ftype: str) -> list[Fact]:
        return [f for f in self.facts.values() if f.type == ftype]

    def neighbors(self, fid: str, rel: str | None = None, direction: str = "out") -> list[Fact]:
        """Facts connected to ``fid``. direction: 'out' | 'in' | 'both'."""
        out = []
        for src, edge_rel, dst in self.edges:
            if rel is not None and edge_rel != rel:
                continue
            if direction in ("out", "both") and src == fid and dst in self.facts:
                out.append(self.facts[dst])
            if direction in ("in", "both") and dst == fid and src in self.facts:
                out.append(self.facts[src])
        return out

    def summary(self) -> dict:
        counts = {t: 0 for t in FACT_TYPES}
        for fact in self.facts.values():
            counts[fact.type] = counts.get(fact.type, 0) + 1
        return {
            "engagement_id": self.engagement_id,
            "total_facts": len(self.facts),
            "edges": len(self.edges),
            "counts": counts,
        }

    # ── persistence ──

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "facts": [f.to_dict() for f in self.facts.values()],
            "edges": [list(e) for e in sorted(self.edges)],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AssetGraph":
        graph = cls(engagement_id=d.get("engagement_id", "default"))
        for fd in d.get("facts", []):
            fact = Fact.from_dict(fd)
            graph.facts[fact.id] = fact
        for edge in d.get("edges", []):
            if len(edge) == 3:
                graph.edges.add(tuple(edge))
        return graph

    def save(self, path: Path | None = None) -> Path:
        path = path or _graph_path(self.engagement_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)
        return path


# ── module-level helpers ──


def _graph_path(engagement_id: str) -> Path:
    return _ASSETS_DIR / f"{engagement_id}.json"


def current_engagement_id() -> str:
    """Resolve the active engagement id, falling back to 'default'."""
    try:
        from ursa_minor.engagement import active_engagement_id
        return active_engagement_id() or "default"
    except Exception:
        return "default"


def load_graph(engagement_id: str | None = None, path: Path | None = None) -> AssetGraph:
    """Load the graph for an engagement (or a fresh empty one)."""
    engagement_id = engagement_id or current_engagement_id()
    path = path or _graph_path(engagement_id)
    if path.exists():
        try:
            with open(path) as fh:
                return AssetGraph.from_dict(json.load(fh))
        except (json.JSONDecodeError, KeyError, OSError):
            pass
    return AssetGraph(engagement_id=engagement_id)


# ── ingest adapters: tool structured_data → facts ──


def _norm_host(value: str) -> str:
    return (value or "").strip().lower()


def _route_identity(url: str) -> tuple[str, str]:
    """Return (normalized_route_url, host) for a URL."""
    p = urllib.parse.urlparse(url)
    host = (p.hostname or "").lower()
    scheme = (p.scheme or "http").lower()
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    return f"{scheme}://{host}:{port}{path}", host


def _ingest_devices(graph: AssetGraph, devices: list, source: str) -> None:
    """discover_network → host facts."""
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        ip = _norm_host(d.get("ip", ""))
        mac = (d.get("mac") or "").strip().lower()
        identity = ip or mac
        if not identity:
            continue
        graph.upsert(HOST, identity, {"ip": ip, "mac": mac, "vendor": d.get("vendor", "")}, source)


def _ingest_ports(graph: AssetGraph, ports: list, metadata: dict, source: str) -> None:
    """scan_ports → service facts linked to their host."""
    host = _norm_host((metadata or {}).get("target", ""))
    host_id = graph.upsert(HOST, host, {"ip": host}, source) if host else None
    for p in ports or []:
        if not isinstance(p, dict) or "port" not in p:
            continue
        port = p["port"]
        svc_id = graph.upsert(
            SERVICE,
            f"{host}:{port}/tcp",
            {"host": host, "port": port, "service": p.get("service", ""), "banner": p.get("banner", "")},
            source,
        )
        if host_id:
            graph.link(host_id, "has_service", svc_id)


def _ingest_http_probe(graph: AssetGraph, probe: dict, source: str) -> None:
    """probe_http → route (+ technology_fingerprint, certificate) facts."""
    if not isinstance(probe, dict):
        return
    url = probe.get("final_url") or probe.get("url") or ""
    if not url:
        return
    route_url, host = _route_identity(url)
    route_id = graph.upsert(
        ROUTE,
        route_url,
        {
            "url": route_url,
            "status": probe.get("status"),
            "title": probe.get("title", ""),
            "body_hash": probe.get("body_hash", ""),
            "favicon_hash": probe.get("favicon_hash"),
            "content_type": probe.get("content_type", ""),
        },
        source,
    )
    host_id = graph.upsert(HOST, host, {"ip": host}, source) if host else None
    if host_id:
        graph.link(host_id, "serves_route", route_id)

    for tech_key in ("server", "x_powered_by"):
        tech = probe.get(tech_key)
        if tech:
            tech_id = graph.upsert(TECH_FINGERPRINT, f"{route_url}|{tech}", {"name": tech, "via": tech_key}, source)
            graph.link(route_id, "runs", tech_id)

    tls = probe.get("tls")
    if isinstance(tls, dict) and not tls.get("error"):
        fingerprint = tls.get("fingerprint_sha256") or tls.get("serial") or f"{host}:cert"
        cert_id = graph.upsert(
            CERTIFICATE,
            str(fingerprint),
            {"subject": tls.get("subject", ""), "issuer": tls.get("issuer", ""),
             "not_after": tls.get("not_after", ""), "host": host},
            source,
        )
        graph.link(route_id, "presents_cert", cert_id)


def _ingest_subdomains(graph: AssetGraph, subs: list, source: str) -> None:
    """enumerate_subdomains → domain facts."""
    for s in subs or []:
        name = s.get("domain") or s.get("subdomain") or s.get("name") if isinstance(s, dict) else s
        name = _norm_host(str(name or ""))
        if name:
            ip = s.get("ip", "") if isinstance(s, dict) else ""
            graph.upsert(DOMAIN, name, {"name": name, "ip": ip}, source)


def _ingest_findings(graph: AssetGraph, findings: list, metadata: dict, source: str) -> None:
    """vuln_scan (and similar) → finding facts, linked to their target route."""
    default_target = (metadata or {}).get("target") or (metadata or {}).get("url") or ""
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        title = f.get("title") or f.get("name") or f.get("check") or "finding"
        target = f.get("target") or f.get("url") or default_target
        finding_id = graph.upsert(
            FINDING,
            f"{target}|{title}",
            {
                "title": title,
                "severity": f.get("severity", ""),
                "category": f.get("category", ""),
                "detail": f.get("detail", ""),
                "target": target,
                "wstg": f.get("wstg", ""),
                "asvs": f.get("asvs", ""),
            },
            source,
        )
        if target and (target.startswith("http://") or target.startswith("https://")):
            route_url, _ = _route_identity(target)
            route_id = graph.upsert(ROUTE, route_url, {"url": route_url}, source)
            graph.link(finding_id, "affects", route_id)

        # Attach replayable evidence when the finding carries a raw exchange.
        exchange = f.get("evidence") if isinstance(f.get("evidence"), dict) else None
        if exchange is None and (f.get("request") or f.get("response")):
            exchange = {"request": f.get("request", ""), "response": f.get("response", ""),
                        "url": target, "matched_at": f.get("matched_at", "")}
        if exchange:
            add_evidence(graph, finding_id, exchange, source)


def _ingest_dirbust(graph: AssetGraph, results: list, metadata: dict, source: str) -> None:
    """dirbust → route (+ GET endpoint) facts for each discovered path."""
    base = (metadata or {}).get("url") or (metadata or {}).get("target") or ""
    if not base:
        return
    _, host = _route_identity(base)
    host_id = graph.upsert(HOST, host, {"ip": host}, source) if host else None
    for r in results or []:
        if not isinstance(r, dict) or r.get("false_positive"):
            continue
        path = r.get("path", "")
        route_url, _ = _route_identity(urllib.parse.urljoin(base, path))
        route_id = graph.upsert(
            ROUTE, route_url,
            {"url": route_url, "status": r.get("status"), "size": r.get("size")},
            source,
        )
        if host_id:
            graph.link(host_id, "serves_route", route_id)
        ep_id = graph.upsert(ENDPOINT, f"GET {route_url}", {"method": "GET", "url": route_url}, source)
        graph.link(route_id, "has_endpoint", ep_id)


def _ingest_tls(graph: AssetGraph, structured: dict, source: str) -> None:
    """tls_scan → certificate (+ service) facts."""
    if not isinstance(structured, dict):
        return
    host = _norm_host(structured.get("host", ""))
    port = structured.get("port")
    if not host or not port:
        return
    host_id = graph.upsert(HOST, host, {"ip": host}, source)
    svc_id = graph.upsert(SERVICE, f"{host}:{port}/tcp",
                          {"host": host, "port": port, "service": "tls",
                           "protocol": structured.get("protocol", ""), "cipher": structured.get("cipher", "")},
                          source)
    graph.link(host_id, "has_service", svc_id)
    cert_id = graph.upsert(
        CERTIFICATE, f"{host}:{port}:cert",
        {"host": host, "port": port, "subject": structured.get("subject", ""),
         "issuer": structured.get("issuer", ""), "not_after": structured.get("not_after", ""),
         "self_signed": structured.get("self_signed")},
        source,
    )
    graph.link(svc_id, "presents_cert", cert_id)


def _ingest_os(graph: AssetGraph, guesses: list, metadata: dict, source: str) -> None:
    """os_fingerprint → technology_fingerprint fact (top guess) on the host."""
    host = _norm_host((metadata or {}).get("target", ""))
    if not host or not guesses:
        return
    top = max((g for g in guesses if isinstance(g, dict)), key=lambda g: g.get("score", 0), default=None)
    if not top:
        return
    host_id = graph.upsert(HOST, host, {"ip": host}, source)
    tech_id = graph.upsert(
        TECH_FINGERPRINT, f"{host}|OS:{top.get('os', '')}",
        {"name": top.get("os", ""), "kind": "os", "score": top.get("score"), "via": "os_fingerprint"},
        source,
    )
    graph.link(host_id, "runs", tech_id)


def add_evidence(graph: AssetGraph, owner_id: str, exchange: dict, source: str | None = None) -> str:
    """Attach a replayable request/response exchange to a finding or route.

    ``exchange`` keys (all optional): method, url, request/request_headers/
    request_body, status, response/response_headers/response_body, matched_at.
    The response body is truncated for storage; a full-body sha256 is retained
    for diffing. Linked to ``owner_id`` via a ``has_evidence`` edge. Returns the
    evidence fact id.
    """
    method = (exchange.get("method") or "GET").upper()
    url = exchange.get("url", "")
    response = exchange.get("response") or exchange.get("response_body") or ""
    resp_str = response if isinstance(response, str) else str(response)
    resp_hash = hashlib.sha256(resp_str.encode(errors="ignore")).hexdigest() if resp_str else ""
    truncated = len(resp_str) > _EVIDENCE_BODY_CAP

    request = exchange.get("request") or exchange.get("request_body") or ""
    identity = f"{method} {url}#{resp_hash or exchange.get('status', '')}|{exchange.get('matched_at', '')}"
    ev_id = graph.upsert(
        EVIDENCE, identity,
        {
            "method": method, "url": url,
            "request": request if isinstance(request, str) else str(request),
            "status": exchange.get("status"),
            "response": resp_str[:_EVIDENCE_BODY_CAP],
            "response_sha256": resp_hash,
            "response_truncated": truncated,
            "matched_at": exchange.get("matched_at", ""),
        },
        source,
    )
    graph.link(owner_id, "has_evidence", ev_id)
    return ev_id


# Map a tool name to its ingest adapter. Tools not listed are ignored (no-op),
# so adding the asset graph never destabilises an unmapped tool.
def ingest(graph: AssetGraph, tool: str, structured_data, metadata: dict | None = None) -> None:
    """Dispatch a tool's structured_data into the graph as facts."""
    metadata = metadata or {}
    source = tool
    if tool == "discover_network" and isinstance(structured_data, list):
        _ingest_devices(graph, structured_data, source)
    elif tool == "scan_ports" and isinstance(structured_data, list):
        _ingest_ports(graph, structured_data, metadata, source)
    elif tool == "probe_http" and isinstance(structured_data, dict):
        _ingest_http_probe(graph, structured_data, source)
    elif tool == "enumerate_subdomains" and isinstance(structured_data, list):
        _ingest_subdomains(graph, structured_data, source)
    elif tool in ("vuln_scan", "run_checks") and isinstance(structured_data, list):
        _ingest_findings(graph, structured_data, metadata, source)
    elif tool == "dirbust" and isinstance(structured_data, list):
        _ingest_dirbust(graph, structured_data, metadata, source)
    elif tool == "tls_scan" and isinstance(structured_data, dict):
        _ingest_tls(graph, structured_data, source)
    elif tool == "os_fingerprint" and isinstance(structured_data, list):
        _ingest_os(graph, structured_data, metadata, source)


def record_result(tool: str, structured_data, metadata: dict | None = None, engagement_id: str | None = None) -> dict | None:
    """Best-effort: load the graph, ingest a tool result, save, return summary.

    Returns None on any failure — graph ingestion must never break a scan.
    """
    if structured_data is None:
        return None
    try:
        graph = load_graph(engagement_id)
        ingest(graph, tool, structured_data, metadata)
        graph.save()
        return graph.summary()
    except Exception:
        return None
