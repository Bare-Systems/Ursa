"""
Ursa Minor — Declarative Check Engine
=====================================
ROADMAP Phase 6, Stage 6C. A Nuclei-inspired (not a Nuclei rewrite) template
engine so repeatable security knowledge lives in portable templates instead of
hardcoded Python. Codify a deterministic bug class once, re-run it forever.

A template declares:
  - info: id, name, severity, description, tags, category, wstg, asvs, confidence
  - http: one or more requests (method, path, headers, body) each with matchers
    (status / word / regex / header), and/or conditions, and negative matches

When a request's matchers fire, the engine emits a normalized *finding* dict
that carries the raw request/response — so it drops straight into the 6A asset
graph as a `finding` with attached replayable `evidence` (the engine routes
findings through `_auto_save` → `assetgraph.ingest("run_checks", ...)`).

HTTP is implemented fully (the doc calls it primary). DNS/TCP/TLS protocol
checks are a clean extension point on the same Template/Matcher model and are
tracked as a 6C follow-up. Request execution uses stdlib urllib (no `requests`
dependency) and is injectable so the engine unit-tests without a network.
"""

import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# Response bodies are capped in the stored evidence/finding so a large page
# can't bloat output; the asset graph keeps a full-body sha256 for diffing.
_RESP_CAP = 8192


@dataclass
class Matcher:
    type: str                       # "status" | "word" | "regex" | "header"
    part: str = "body"              # "body" | "header" | "status"
    values: list = field(default_factory=list)
    condition: str = "or"           # within a matcher's values: "or" | "and"
    negative: bool = False          # fire when the match is *absent*

    def evaluate(self, resp: dict) -> bool:
        hit = self._raw_match(resp)
        return (not hit) if self.negative else hit

    def _raw_match(self, resp: dict) -> bool:
        if self.type == "status":
            return resp.get("status") in {int(v) for v in self.values}

        if self.type == "header":
            headers = resp.get("headers", {})  # keys already lower-cased
            present = [v for v in self.values if v.lower() in headers]
            return (len(present) == len(self.values)) if self.condition == "and" else bool(present)

        haystack = _response_part(resp, self.part)

        if self.type == "word":
            results = [v in haystack for v in self.values]
        elif self.type == "regex":
            results = [re.search(v, haystack) is not None for v in self.values]
        else:
            return False

        return all(results) if self.condition == "and" else any(results)


@dataclass
class HttpRequest:
    method: str = "GET"
    path: str = "/"
    headers: dict = field(default_factory=dict)
    body: str | None = None
    matchers: list = field(default_factory=list)
    matchers_condition: str = "and"   # across matchers: "and" | "or"

    def matched(self, resp: dict) -> bool:
        if not self.matchers:
            return False
        results = [m.evaluate(resp) for m in self.matchers]
        return all(results) if self.matchers_condition == "and" else any(results)


@dataclass
class Template:
    id: str
    name: str = ""
    severity: str = "info"
    description: str = ""
    category: str = ""
    tags: list = field(default_factory=list)
    wstg: str = ""
    asvs: str = ""
    confidence: str = ""
    requests: list = field(default_factory=list)


def _response_part(resp: dict, part: str) -> str:
    if part == "status":
        return str(resp.get("status", ""))
    if part == "header":
        headers = resp.get("headers", {})
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    return resp.get("body", "") or ""


# ── template loading ──


def load_template(d: dict) -> Template:
    """Build a Template from a plain dict (the YAML/JSON shape)."""
    info = d.get("info", {})
    requests = []
    for req in d.get("http", d.get("requests", [])):
        matchers = [
            Matcher(
                type=m["type"],
                part=m.get("part", "body"),
                values=[m["values"]] if isinstance(m.get("values"), (str, int)) else list(m.get("values", [])),
                condition=m.get("condition", "or"),
                negative=bool(m.get("negative", False)),
            )
            for m in req.get("matchers", [])
        ]
        requests.append(HttpRequest(
            method=req.get("method", "GET").upper(),
            path=req.get("path", "/"),
            headers=req.get("headers", {}) or {},
            body=req.get("body"),
            matchers=matchers,
            matchers_condition=req.get("matchers-condition", req.get("matchers_condition", "and")),
        ))
    return Template(
        id=d.get("id", info.get("id", "unnamed")),
        name=info.get("name", d.get("id", "")),
        severity=info.get("severity", "info"),
        description=info.get("description", ""),
        category=info.get("category", ""),
        tags=list(info.get("tags", [])),
        wstg=info.get("wstg", ""),
        asvs=info.get("asvs", ""),
        confidence=info.get("confidence", ""),
        requests=requests,
    )


def load_templates_from_yaml(text: str) -> list[Template]:
    """Load one or more templates from a YAML document (supports `---` streams)."""
    import yaml
    return [load_template(doc) for doc in yaml.safe_load_all(text) if isinstance(doc, dict)]


def load_templates_from_dir(path) -> list[Template]:
    """Load every *.yaml / *.yml template under a directory."""
    from pathlib import Path
    templates = []
    base = Path(path)
    if not base.is_dir():
        return templates
    for f in sorted(base.glob("*.y*ml")):
        try:
            templates.extend(load_templates_from_yaml(f.read_text()))
        except Exception:
            continue
    return templates


# Portable, version-controlled starter templates. Operators add their own via
# a templates directory; these prove the engine end-to-end and seed the tests.
BUILTIN_TEMPLATES = [
    {
        "id": "exposed-git-config",
        "info": {
            "name": "Exposed .git/config", "severity": "high", "category": "exposure",
            "description": "A readable .git/config exposes repository metadata and often internal URLs.",
            "tags": ["exposure", "git"], "wstg": "WSTG-CONF-05", "asvs": "ASVS-14.3.2", "confidence": "high",
        },
        "http": [{
            "method": "GET", "path": "/.git/config",
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body", "values": ["[core]"]},
            ],
        }],
    },
    {
        "id": "exposed-dotenv",
        "info": {
            "name": "Exposed .env file", "severity": "critical", "category": "exposure",
            "description": "A readable .env file commonly leaks secrets, tokens, and DB credentials.",
            "tags": ["exposure", "secrets"], "wstg": "WSTG-CONF-05", "asvs": "ASVS-14.3.2", "confidence": "high",
        },
        "http": [{
            "method": "GET", "path": "/.env",
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex", "part": "body", "values": ["(?m)^[A-Z0-9_]+="]},
            ],
        }],
    },
    {
        "id": "missing-hsts",
        "info": {
            "name": "Missing Strict-Transport-Security header", "severity": "low", "category": "headers",
            "description": "HTTPS responses should set HSTS to prevent protocol downgrade.",
            "tags": ["headers", "tls"], "wstg": "WSTG-CONF-07", "asvs": "ASVS-9.2.1", "confidence": "high",
        },
        "http": [{
            "method": "GET", "path": "/",
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "header", "values": ["strict-transport-security"], "negative": True},
            ],
        }],
    },
]


def builtin_templates() -> list[Template]:
    return [load_template(d) for d in BUILTIN_TEMPLATES]


# ── execution ──


def execute_request(req: HttpRequest, base_url: str, timeout: float = 10.0,
                    opener=urllib.request.urlopen) -> dict | None:
    """Execute one template request against base_url. Returns a response dict
    {status, headers(lower-keyed), body, url, request_line} or None if the host
    is unreachable. ``opener`` is injectable so this unit-tests without a socket.
    """
    url = urllib.parse.urljoin(base_url if base_url.endswith("/") else base_url + "/", req.path.lstrip("/"))
    data = req.body.encode() if isinstance(req.body, str) else None
    request = urllib.request.Request(url, data=data, method=req.method)
    for k, v in (req.headers or {}).items():
        request.add_header(k, v)

    request_line = f"{req.method} {url}"
    try:
        resp = opener(request, timeout=timeout)
        status = getattr(resp, "status", None) or resp.getcode()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read()
    except urllib.error.HTTPError as e:
        # 4xx/5xx are still responses we want to match on.
        status = e.code
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        body = e.read() if hasattr(e, "read") else b""
    except (urllib.error.URLError, OSError):
        return None

    body_text = body.decode(errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body)
    return {"status": status, "headers": headers, "body": body_text, "url": url, "request_line": request_line}


def _finding_from(template: Template, resp: dict) -> dict:
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.get("headers", {}).items())
    response_text = f"HTTP {resp.get('status')}\n{header_blob}\n\n{resp.get('body', '')[:_RESP_CAP]}"
    return {
        "title": template.name or template.id,
        "severity": template.severity,
        "category": template.category or (template.tags[0] if template.tags else ""),
        "detail": template.description,
        "target": resp.get("url", ""),
        "wstg": template.wstg,
        "asvs": template.asvs,
        "template_id": template.id,
        "confidence": template.confidence,
        "request": resp.get("request_line", ""),
        "response": response_text,
        "matched_at": resp.get("url", ""),
    }


def run_template(template: Template, base_url: str, timeout: float = 10.0,
                 opener=urllib.request.urlopen) -> list[dict]:
    """Run a template against base_url; return a finding dict per matched request."""
    findings = []
    for req in template.requests:
        resp = execute_request(req, base_url, timeout=timeout, opener=opener)
        if resp is None:
            continue
        if req.matched(resp):
            findings.append(_finding_from(template, resp))
    return findings


def run_templates(templates: list[Template], base_url: str, timeout: float = 10.0,
                  opener=urllib.request.urlopen) -> list[dict]:
    """Run many templates against one target; return all findings."""
    findings = []
    for template in templates:
        findings.extend(run_template(template, base_url, timeout=timeout, opener=opener))
    return findings
