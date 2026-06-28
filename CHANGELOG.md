# Changelog

All notable changes to Ursa are documented here.

## [Unreleased]

### Changed

- Replaced the prototype C2 encrypted frame format with versioned AES-256-GCM envelopes for encrypted tasking, results, and beacon uploads; legacy encrypted frames now fail closed and must re-register under the AEAD protocol.

### Added

- CI: added `publish` job to `.github/workflows/ci.yml` that builds and pushes `ghcr.io/bare-systems/ursa` to GitHub Container Registry on every push to `main`; builds without pushing on PRs.

### Added

- **Declarative check engine (Ursa Minor)** — ROADMAP Phase 6C. New `ursa_minor.checkengine` is a Nuclei-inspired (not a rewrite) template engine so repeatable security knowledge lives in portable templates instead of hardcoded Python. Templates declare HTTP requests with matchers (status / word / regex / header), and/or conditions, and negative matches, plus severity/confidence and WSTG/ASVS mappings. A match emits a normalized finding carrying the raw request/response, which flows through `_auto_save → assetgraph.ingest("run_checks", …)` into the asset graph as a `finding` with attached replayable `evidence`. Ships YAML loading (directory + multi-doc streams) and a portable `BUILTIN_TEMPLATES` starter set (`exposed-git-config`, `exposed-dotenv`, `missing-hsts`). New `ursa_run_checks` MCP tool runs built-in + custom templates against a target, enforces the active engagement scope (refuses out-of-scope targets), and saves results for export/diff. HTTP is fully implemented; DNS/TCP/TLS are a tracked follow-up on the same model. Request execution uses stdlib urllib with an injectable opener (treats 4xx/5xx as matchable) and unit-tests without a network — `tests/minor/test_checkengine.py`, 12 tests.
- **Normalized asset graph + evidence schema (Ursa Minor)** — the substrate for ROADMAP Phase 6 (generic pentest conductor). New `ursa_minor.assetgraph` turns each tool's freeform `structured_data` into typed, de-duplicated *facts* — `host`, `domain`, `service`, `certificate`, `route`, `endpoint`, `parameter`, `auth_context`, `technology_fingerprint`, `finding` — linked by directed edges (host→has_service→service, route→presents_cert→certificate, finding→affects→route). Facts have deterministic identity-derived ids so re-ingesting upserts (refreshes attrs, bumps `times_seen`) instead of duplicating. Graphs are stored per engagement as JSON under `~/.ursa/assets/<engagement>.json` (mirroring the engagement/results convention) and scoped to the active engagement. `_auto_save` now feeds every scan into the graph best-effort (never breaks the scan), with ingest adapters for `discover_network`, `scan_ports`, `probe_http`, `enumerate_subdomains`, `vuln_scan`, `dirbust` (→route + GET endpoint), `tls_scan` (→certificate + service), and `os_fingerprint` (→technology fingerprint); unmapped tools are a no-op. Findings that carry a raw request/response auto-attach a replayable `evidence` fact (`add_evidence()` API; response truncated for storage with a full-body sha256 kept for diffing) — the substrate the 6C check engine writes through. New `ursa_asset_graph` MCP tool reports the world model (summary counts or facts of one type) so the model reasons over facts, not terminal output. Added `engagement.active_engagement_id()` public accessor. Tested in `tests/minor/test_assetgraph.py` (20 tests: fact model, dedup/upsert, edges/queries, JSON round-trip, all ingest adapters, evidence) — pure local, no network.
- **Pi-hole DNS insight (control plane)** — Ursa Major now answers "what is each device on my network actually talking to" by reading Pi-hole's FTL long-term query DB (`pihole-FTL.db`) **read-only** (`major/pihole.py`). Surfaces top talkers by query volume with a per-client blocked/allowed split, top domains (overall, per-client, or only-blocked), and an overall blocked-vs-allowed ratio over a configurable look-back window. Exposed via admin API under `/api/v1/dns/*` (`GET /overview`, `GET /talkers`, `GET /domains`) and the `ursa_dns_talkers` MCP tool. DB path is configurable (`major.pihole.db_path`, default `/etc/pihole/pihole-FTL.db`); a missing/unreadable DB degrades gracefully to an "unavailable" state rather than erroring. Works against **both** FTL schemas — v5 (flat `queries` with TEXT domain/client) and v6 (normalized `queries` with integer ids into `domain_by_id`/`client_by_id`) — detected automatically at query time, so it adapts to whichever Pi-hole version is running. ROADMAP Phase 5B. Tested in `tests/major/test_pihole.py` against synthetic v5 **and** v6 databases.
- **Network inventory collector (host collector)** — `ursa_minor.netcollect` (console script `ursa-netcollect`, also `python -m ursa_minor.netcollect`) is the privileged half of Phase 5A: a sudo-capable host job that ARP-sweeps the LAN (reusing Ursa Minor's scan + MAC-vendor lookup) and POSTs the discovered `[{ip,mac,vendor}]` list to Ursa Major's `POST /api/v1/network/scan` ingest endpoint with a bearer token plus `X-BearClaw-Actor`/`X-BearClaw-Role` headers. Target CIDR auto-detects (or `--range`/`$URSA_SCAN_RANGE`); base URL and token come from `$URSA_CP_URL`/`$URSA_URL` and `$URSA_API_TOKEN` (token never lands in argv or a manifest). scapy is imported lazily so the module loads — and unit-tests — without root or raw sockets. Intended to run on a timer on the LAN-reachable host (the Beelink); the Docker control plane stays free of raw network access. Tested in `tests/minor/test_netcollect.py` (target resolution, payload shape, authenticated request, scan→post wiring).
- **Network inventory + baseline drift (control plane)** — Ursa Major now persists home-network device inventory and surfaces "unknown device joined the network" as a security signal. New `network_devices` / `network_scans` tables (`major/db.py`) and `major/netinsight.py` logic: scans are ingested as `[{ip,mac,vendor}]`, devices are keyed/deduped by MAC, a trusted baseline can be set, and any post-baseline MAC is flagged untrusted (and logged as a `warning` event). Privileged ARP scanning stays in Ursa Minor / a host collector that POSTs results, so the Docker control plane needs no raw network access. Exposed via admin API under `/api/v1/network/*` (`POST /scan`, `GET /devices`, `GET /devices/new`, `POST /baseline`, `PATCH /devices/{mac}`, `GET /scans`) and the `ursa_network_inventory` MCP tool so BearClaw can answer "how many devices / any unknown ones". First slice of ROADMAP Phase 5 (Network Insight & Home Security Telemetry).

### Fixed

- Fixed 91 CI pytest failures: added `@_WEB_UI_DISABLED` skip marks to all web UI route tests (auth middleware returns HTTP 410 for non-API/MCP paths, routes moved to BearClawWeb); wrapped `os.scandir` in `_check_writable_cron()` with `try/except PermissionError` to fix 9 privesc test failures on CI; added `@pytest.mark.skipif(CI=true)` to 3 evasion sandbox-detection tests that legitimately fire on GitHub Actions VMs.
- Fixed 138 mypy errors across 20 files: `no_implicit_optional` fixes, variable shadowing renames to avoid `str-unpack`, `dict[str, Any]` annotations for mixed-type dicts, scapy `attr-defined` ignores, CSV writer type conflict rename, `Callable` import, and `TemplateResponse` API migration across all web route files.
- Resolved Ruff lint failures across Ursa Major and tests, including the API role dependency singleton, TLS context typing, and unused locals.
- Hardened the homelab provisioner (`deploy/blink/provision_ursa_major.sh`) to seed the control-plane `api_token`. It now sets `major.web.auth.api_token` via `setdefault(os.environ.get("URSA_TOKEN") or secrets.token_urlsafe(32))` — mirroring how `session_secret`/`approval_signing_key` are handled. An existing token is always preserved (deploys never clobber a working token), an injected `URSA_TOKEN` is honored so a fresh deploy can match clients, and otherwise a strong token is generated. Previously the script never set `api_token`, so a clean deploy left it empty and the admin API returned `503 "API token is not configured"`. Verified on the homelab: a redeploy preserved the existing token and the network admin API kept authenticating (`200`).
- Docker health checks for `ursa-major-c2` and `ursa-major-cp` were failing with `curl: not found` — replaced `curl` with Python `urllib` in both health check commands since the image doesn't include curl.

## [0.0.1] - 2026-05-11

### Added

- **ASVS v4 tagging on all findings** — Every `vuln_scan` finding now carries both a WSTG reference and an ASVS v4 control reference in brackets. Security header findings: `[ASVS-9.2.1]` (HSTS), `[ASVS-14.4.4]` (CSP), `[ASVS-14.4.3]` (X-Frame-Options), `[ASVS-14.4.1]` (X-Content-Type-Options), `[ASVS-14.3.3]` (Server/X-Powered-By disclosure). Injection findings: `[ASVS-5.3.4]` (SQLi), `[ASVS-5.3.3]` (XSS), `[ASVS-5.2.5]` (template injection), `[ASVS-5.2.2]` (CMDi), `[ASVS-12.3.1]` (LFI). TLS findings in `tls_scan`: `[ASVS-9.1.2]` (weak protocol), `[ASVS-9.1.3]` (weak cipher), `[ASVS-9.2.1]` (self-signed, expired, hostname mismatch, untrusted CA).
- **`diff_scan_results` tool** — Regression diff between any two saved scan results. Compares `structured_data` findings sets and reports: NEW findings (regressions or newly surfaced issues), FIXED findings (issues that disappeared after a change), and unchanged count. Supports `vuln_scan`, `dirbust`, `tls_scan`, `api_scan`, and any other tool that emits structured data. Result auto-saved as `diff_scan_results_<ts>` for inclusion in engagement reports. Enables the standard verify-fix-retest loop: run scan → apply fix → rerun scan → `diff_scan_results` to confirm the finding is gone.

- **`api_scan` tool** — OpenAPI/Swagger spec discovery and schema-driven endpoint
  testing. Auto-detects spec at common locations (`/openapi.json`, `/swagger.json`,
  `/api/docs`, etc.) or accepts an explicit `spec_path`. For each endpoint and
  parameter combination in the spec (up to 40 endpoints), generates targeted probes:
  unauthenticated access to auth-required endpoints (`WSTG-ATHN-01`), missing
  required parameters causing 500 responses (`WSTG-CONF-11`), SQL injection canary
  via quote in string parameters (`WSTG-INPV-05`), and IDOR candidates on integer
  path parameters (`WSTG-ATHZ-04`). Supports `auth_header` and `cookies` for
  authenticated scanning. Outputs a findings list and full endpoint inventory.
- **Authenticated scanning** — `vuln_scan` and `dirbust` now accept `auth_header`
  (e.g., `"Bearer eyJ..."`) and `cookies` (e.g., `"session=abc123"`) parameters.
  All requests — including the SPA baseline probe, robots.txt/sitemap crawl, and
  every wordlist check — carry the provided credentials, enabling testing of
  protected routes without manual session management.
- **Engagement-aware rate limiting in `dirbust`** — If an active engagement is set,
  `dirbust` reads `rate_limit_rps` from the engagement record and caps the thread
  count accordingly. The cap is reported in the output. This makes the engagement
  rate limit enforceable rather than advisory-only.
- **`probe_http` tool** — Rich single-URL HTTP fingerprint collected in one round-trip:
  final status, full redirect chain, response time, Server/X-Powered-By headers,
  Content-Type, body size, SHA-256 body hash, page title, security header audit
  (HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.), TLS certificate details
  (subject, issuer, expiry, protocol, cipher — HTTPS only), favicon SHA-256 hash,
  and allowed HTTP methods via OPTIONS probe. Implemented in `probe.py`; results
  auto-saved with `_auto_save()`.
- **`tls_scan` tool** — TLS certificate and cipher analysis using Python `ssl` stdlib
  (no external tools required). Reports protocol version, cipher suite, certificate
  subject/issuer/expiry/SANs, and flags weak protocols (TLSv1.0/1.1), short cipher
  key sizes, self-signed certs, expired or near-expiry certs, and hostname mismatches.
  All findings tagged with `WSTG-CRYP-01`.
- **`create_engagement` / `check_scope` / `get_engagement` / `close_engagement` tools** —
  Lightweight scope manifest for pentest sessions. An engagement records in-scope
  hosts (IP, CIDR, hostname, wildcard domain), allowed URL path prefixes, destructive-
  test approval gate, and a suggested rate-limit cap. `check_scope(url)` validates any
  target URL against the active engagement before scanning. Implemented in `engagement.py`;
  engagement records persisted as JSON in `~/.ursa/engagements/`.
- **`dirbust` discovery improvements** — Three new discovery sources extend the built-in
  wordlist automatically (controlled by new `crawl` parameter, default `True`):
  (1) `robots.txt` path harvesting — Disallow/Allow entries added to scan list;
  (2) `sitemap.xml` path harvesting — `<loc>` URL paths extracted;
  (3) shallow root-page crawl — `href`/`src`/`action` attribute values from the root
  HTML page extracted and added. New `wordlist_file` parameter accepts an external
  wordlist file (one path per line) merged with the built-in list. Discovery source
  counts reported in output.
- **WSTG tags on `vuln_scan` findings** — Every finding now includes an OWASP Web
  Security Testing Guide reference in brackets. Header findings: `[WSTG-CONF-10]`
  (HSTS), `[WSTG-CONF-12]` (CSP), `[WSTG-CLNT-09]` (X-Frame-Options),
  `[WSTG-CONF-07]` (X-Content-Type-Options), `[WSTG-INFO-02]` (Server header),
  `[WSTG-INFO-08]` (X-Powered-By). Injection findings: `[WSTG-INPV-05]` (SQLi),
  `[WSTG-CLNT-01]` (XSS), `[WSTG-INPV-18]` (template injection),
  `[WSTG-INPV-12]` (CMDi), `[WSTG-INPV-07]` (LFI).

### Fixed

- **`vuln_scan` / `probe_http` false positives on self-signed HTTPS targets** — Both tools
  returned empty headers (status 0) for HTTPS targets with self-signed or private-CA
  certificates, causing every security header to appear absent. Root cause: `urllib` raises
  `URLError(SSLCertVerificationError)` when TLS verification fails, and the exception was
  caught as a generic failure rather than an SSL-specific one. Fixed with a two-pass strategy
  matching `tls_scan`: first attempt uses the system CA store; on `SSLCertVerificationError`
  (detected by unwrapping the urllib `URLError.reason`), a second attempt uses `ssl.CERT_NONE`
  and adds a `[MEDIUM] TLS certificate not verified` finding to the output. All subsequent
  header audit results are accurate. Applied in `probe.py` (`_fetch_with_redirects`,
  `_favicon_hash`, `_allowed_methods`) and in the `_fetch()` closure in `vuln_scan`.
  Tracked as Ursa Minor issue #3.

- **`tls_scan` / `probe_http` TLS cert parsing** — Both tools used `ssl.CERT_NONE`
  which prevents Python from populating the `getpeercert()` dict, causing subject,
  issuer, expiry, and SAN fields to come back empty. Fixed with a two-pass strategy:
  first attempt uses `ssl.create_default_context()` (system CA store, `CERT_REQUIRED`)
  which fully parses the cert dict for CA-trusted targets. On `SSLCertVerificationError`
  (self-signed / private CA), a second attempt with `CERT_NONE` captures cipher and
  protocol and adds a `[MEDIUM]` finding noting the untrusted chain. All
  public-CA certs now show subject CN, issuer, expiry, days remaining, and SANs.

- **dirbust SPA false-positive detection** — Before scanning the wordlist,
  `dirbust` now probes a guaranteed-nonexistent path and SHA-256-hashes the
  response body (up to 4 KB). Any 200-status result whose body hash matches the
  probe baseline is tagged `[LIKELY_FP]` in output and `false_positive: true`
  in structured data. The CRITICAL FINDINGS block is suppressed for these paths.
  A summary line reports confirmed vs. likely-false-positive counts. This
  eliminates the false-positive storm produced by SPA `try_files` fallback
  routes (e.g., nginx `try_files $uri /index.html`).
- **crack_hash result leakage in list_scan_results** — Added `_SENSITIVE_TOOLS`
  constant (`{"crack_hash", "credential_spray"}`) in `results.py`. `list_results()`
  now skips records for these tools unless the caller passes an explicit
  `tool_filter` naming that tool. Previously, any unfiltered call to
  `list_scan_results` exposed cracked password attempts and credential spray
  results alongside routine recon data.
- **vuln_scan severity overstated for plain-HTTP targets** — Header checks now
  inspect the URL scheme before assigning severity. On `http://` targets, HSTS
  severity is downgraded from `HIGH` to `INFORMATIONAL` with an explanatory
  note ("not applicable on plain HTTP; expected on HTTPS terminator"), and CSP
  severity is downgraded from `HIGH` to `LOW`. HTTPS targets retain `HIGH` for
  both. This prevents severity inflation against local fixtures, dev targets,
  and intentional HTTP-only services.
- **vuln_scan result ID missing for no-parameter URLs** — The early-return code
  path for URLs with no query parameters (header-scan only) now calls
  `_auto_save()` and appends `[Saved as <id>]` to its output, matching the
  behaviour of `scan_ports` and `dirbust`. Previously this path returned without
  saving, causing `export_engagement_report` aggregation to silently omit
  `vuln_scan` results when the target had no injectable parameters.
- **Ursa Blink compose path drift** — Updated the `ursa-major` stop/start commands to use `deploy/blink/ursa-major.compose.yaml`, which matches the packaged deploy bundle. This fixes homelab deploy failures where the image pull succeeded but `docker compose` could not find the compose file on the target.
- **Slow builds on Apple Silicon** — Rewrote the Dockerfile as a two-stage build. Stage 1 runs natively on the build machine (`$BUILDPLATFORM`) and uses `pip download` to fetch pre-built `manylinux2014_x86_64` wheels without any QEMU emulation. Stage 2 installs from those local wheels — no compilation, no network — so even the first build is fast. Also added `dist/`, `deploy/`, and `*.tgz` to `.dockerignore` to eliminate deploy artifact bloat from the build context.
- **Missing rollback pipeline** — Added `rollback_pipeline = ["stop", "start", "health_check"]` to the `ursa-major` deploy config. Previously a failed deploy had no automated recovery path.
- **Dockerfile layer caching** — Rewrote the Dockerfile to separate dependency installation from source copying. `pyproject.toml` is copied first; stubs are used to install all deps into a cached layer; real source is copied second and installed with `--no-deps`. This eliminates the redundant apt-then-pip double-install pattern and ensures dep layers are only rebuilt when `pyproject.toml` changes, not on every code edit.

### Changed

- `blink.toml`: added `tls_insecure = true` to the `ursa-major.verify.tests.c2-health` inline HTTP test. Blink Sprint D flipped the HTTP adapter to TLS-verify-by-default; the C2 listener on `:6708` still uses a self-signed cert, so the test needs an explicit opt-in. The planner now surfaces this as a warning in `blink validate` / `blink plan`, keeping the insecure posture visible.
- Standardized the repository documentation contract and moved active planning to the workspace root `ROADMAP.md`.
- Merged the Ursa operator MCP surface into the `major.web` control plane at `/mcp`, renamed the operator-facing service concept to the control plane, and updated the published homelab ports to `6707` for control plane and `6708` for C2.
- Fixed the Ursa Major deploy/build pipeline so Blink pushes the same registry image name that the remote start step pulls, and updated the production image to install the Python package dependencies required by the embedded MCP control plane.
- Ignored the repository-root `blink.toml` and `BLINK.md` and stopped tracking them so homelab-specific Blink targets and operator notes stay local-only.
