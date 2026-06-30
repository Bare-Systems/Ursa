# Ursa

<div align="center">

**AI-native red team operations platform**

Command & control, autonomous recon, implant generation, governance, and operator UX — all designed for human + AI collaboration through MCP.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#quick-start)
[![License: Apache](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/protocol-MCP-7b61ff.svg)](https://modelcontextprotocol.io/)

</div>

---

## Table of Contents

- [Why Ursa](#why-ursa)
- [Platform Architecture](#platform-architecture)
- [Core Components](#core-components)
- [What You Can Do with Ursa](#what-you-can-do-with-ursa)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [MCP Setup (Claude Code / Desktop)](#mcp-setup-claude-code--desktop)
- [Ursa Major (C2)](#ursa-major-c2)
- [Ursa Minor (Recon)](#ursa-minor-recon)
- [Implants & Payloads](#implants--payloads)
- [Governance, Audit, and Campaign Ops](#governance-audit-and-campaign-ops)
- [Project Structure](#project-structure)
- [Roadmap and Planning](#roadmap-and-planning)
- [Security & Legal](#security--legal)
- [Contributing](#contributing)
- [License](#license)

---

## Why Ursa

Ursa is a modern red-team toolkit built for the way operators actually work today:

- **AI-operable by design** through MCP servers for both C2 and recon.
- **Operator-centric workflows** with campaign context, approvals, and shift handoff support.
- **Practical tradecraft coverage** across discovery, access support, execution, collection, and post-exploitation modules.
- **High leverage for small teams** by combining automation and human oversight.

If you want a single project that can be driven conversationally by an AI assistant *without* losing governance and operator control, this is what Ursa is for.

---

## Platform Architecture

```text
                        ┌─────────────────────────────┐
                        │         AI Agent             │
                        │  (Claude Code / Desktop)     │
                        └──────────┬──────────────────┘
                                   │ MCP Protocol
                        ┌──────────┴──────────────────┐
                        │                              │
                ┌───────▼───────┐            ┌─────────▼──────┐
                │  Ursa Major   │            │  Ursa Minor    │
                │  C2 Server    │            │  Recon Toolkit │
                │  (server.py)  │            │  (minor/)      │
                └───────┬───────┘            └────────┬───────┘
                        │                             │
                ┌───────▼───────┐            ┌────────▼───────┐
                │   Web UI      │            │    Targets     │
                │  (major/web)  │            │  (scan/enum)   │
                └───────────────┘            └────────────────┘
                        │ HTTP
                ┌───────▼───────┐
                │   Implants    │
                │  (beacons)    │
                └───────────────┘
```

---

## Core Components

| Component | Purpose | Docs |
|-----------|---------|------|
| **[Ursa Major](major/)** | Command and control: sessions, tasking, encrypted comms, control plane, governance, and campaign ops | [major/README.md](major/README.md) |
| **[Ursa Minor](minor/)** | Recon/scanning and host-triage suite with 20 tools (network, web, creds, SMB/SNMP, hash, defensive baselines) | [minor/README.md](minor/README.md) |
| **[Implants](implants/)** | Beacon templates (Python/Go/Zig), stager, evasion helpers, payload builder | [implants/README.md](implants/README.md) |
| **[Post modules](post/)** | Post-exploitation modules (enum, creds, lateral movement, persistence) | — |

---

## What You Can Do with Ursa

### Operate C2 with governance, not chaos
- Manage implant sessions, queue tasks, collect results, and move files.
- Enforce **step-up approvals** for risky actions.
- Preserve an **immutable audit chain** and signed approval decisions.

### Run autonomous and assisted reconnaissance
- Discover hosts, scan ports/services, fingerprint OS, test web exposures, and enumerate protocols/services.
- Use tooling from MCP, CLI, or standalone scripts.

### Generate and stage payloads quickly
- Build configured payloads for multiple implant templates.
- Use stagers and tokenized builder workflows for rapid iteration.

### Keep operations organized
- Group by campaigns/tags, maintain notes/checklists, and export handoff/report artifacts.

---

## Quick Start

### Prerequisites

- Python **3.11+**
- `sudo` access (required for several raw-socket recon operations in Ursa Minor)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or [Claude Desktop](https://claude.ai/download) for MCP integration

### Setup

```bash
git clone https://github.com/Bare-Systems/Ursa.git
cd Ursa

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional: install Ursa Minor as a package for CLI usage
pip install ./minor
```

### Start services

```bash
# Start C2 (default 0.0.0.0:6708)
python3 -m major.c2

# Start the Ursa control plane (REST on /api/v1/*, MCP on /mcp)
python3 -m major.cp
```

Development defaults are for local use only. Before any non-local deployment,
set `environment: production` in `ursa.yaml` or export `URSA_ENV=production`,
then configure generated secrets for the control plane and governance signing.
Production mode refuses to start with known development defaults.

## Blink Homelab Contract

On `blink`, Ursa has two distinct published surfaces:

- C2 listener: `https://192.168.86.53:6708`
- BearClaw-facing control plane (`major.web`): `http://192.168.86.53:6707`

BearClaw Security depends on `major.web`, not on the raw C2 listener. Do not
remove, retire, or stop deploying `major.web` while BearClaw Security pages
still exist. When BearClaw runs in Docker, it must call the host-published
control-plane address, not host loopback from inside the container.

---

## Configuration

Create a local config file at the project root:

```bash
cp ursa.yaml.example ursa.yaml
```

Example:

```yaml
environment: production
major:
  port: 6708
  traffic_profile: default        # default | jquery | office365 | github-api
  tls:
    enabled: false
  web:
    auth:
      session_secret: "<generated with: python -c 'import secrets; print(secrets.token_urlsafe(32))'>"
      bootstrap_username: "admin"
      bootstrap_password: "<generated password>"
      api_signing_keys:
        - "<generated with: python -c 'import secrets; print(secrets.token_urlsafe(32))'>"
  auto_recon:
    enabled: true
  governance:
    require_step_up_approval: true
    approval_signing_key: "<generated with: python -c 'import secrets; print(secrets.token_urlsafe(32))'>"
```

---

## MCP Setup (Codex / Claude Code / Desktop)

### Codex (`~/.codex/config.toml`)

Ursa Minor can run over stdio, while Ursa Major exposes MCP through the control
plane service.

1. Start the Ursa control plane locally:

```bash
/path/to/Ursa/.venv/bin/python3 -m major.cp \
  --host 127.0.0.1 \
  --port 6707
```

2. Add both servers to Codex:

```toml
[mcp_servers.ursa_major]
url = "http://127.0.0.1:6707/mcp"

[mcp_servers.ursa_minor]
command = "/path/to/Ursa/.venv/bin/python3"
args = ["/path/to/Ursa/minor/server.py"]
```

Restart Codex after updating the config so the new MCP entries are loaded.

Add both MCP servers to your Claude config.

### Claude Code (`~/.claude/settings.json` or project `.mcp.json`)

```json
{
  "mcpServers": {
    "Ursa-Major": {
      "command": "/path/to/Ursa/venv/bin/python3",
      "args": ["/path/to/Ursa/server.py"]
    },
    "Ursa-Minor": {
      "command": "sudo",
      "args": ["/path/to/Ursa/venv/bin/python3", "/path/to/Ursa/minor/server.py"]
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "Ursa-Major": {
      "command": "/path/to/Ursa/venv/bin/python3",
      "args": ["/path/to/Ursa/server.py"]
    },
    "Ursa-Minor": {
      "command": "sudo",
      "args": ["/path/to/Ursa/venv/bin/python3", "/path/to/Ursa/minor/server.py"]
    }
  }
}
```

> Replace `/path/to/Ursa` with your local clone path.

---

## Ursa Major (C2)

Ursa Major is an HTTP-based C2 server with:

- Session lifecycle tracking (active/stale/dead)
- 13 core task types (`shell`, `sysinfo`, `download`, `upload`, `sleep`, `kill`, `post`, etc.)
- Per-session encrypted tasking/result/upload envelopes (AES-256-GCM)
- Optional TLS and traffic profiles
- BearClaw-facing control-plane service with signed/scoped bearer auth plus bootstrap web auth config
- 60+ MCP tools for operations, governance, and campaign workflows

For full API/tooling details: **[major/README.md](major/README.md)**

---

## Ursa Minor (Recon)

Ursa Minor includes 20 reconnaissance, scanning, and lightweight host-triage tools, including:

- Network discovery and port/service scanning
- Packet capture and full recon orchestration
- Subdomain enumeration, directory busting, vulnerability scanning
- Credential spraying (SSH/FTP/HTTP Basic)
- OS fingerprinting, SMB enumeration, SNMP scanning
- Hash cracking/identification and reverse shell payload generation
- Defensive persistence scanning, host baselining, and drift triage

Use via MCP, package CLI, or standalone scripts.

For full details: **[minor/README.md](minor/README.md)**

---

## Implants & Payloads

The implants subsystem provides:

- **Python beacon** (full-featured)
- **Go beacon template** (cross-platform compilation support)
- **Zig beacon template** (skeleton)
- **Stager** for initial retrieval/exec flow
- **Builder** for tokenized payload generation and optional post-build steps
- **Evasion primitives** (sandbox/debugger checks, obfuscated sleep, process-name spoofing)

For implementation and usage details: **[implants/README.md](implants/README.md)**

---

## Governance, Audit, and Campaign Ops

Ursa goes beyond task execution by including operational safeguards:

- **Step-up approval workflow** for high-risk operations
- **Policy matrix and threshold alerts**
- **Cryptographically chained audit records**
- **Campaign-level grouping, notes, timelines, and handoff reports**

This makes Ursa suitable for structured team operations where traceability matters.

---

## Project Structure

```text
Ursa/
├── major/             # C2 server, governance, and BearClaw-facing control-plane logic
├── minor/             # Recon/scanning toolkit
├── implants/          # Beacon templates, stager, evasion, builder
├── post/              # Post-exploitation modules
├── tests/             # Test suite
├── server.py          # MCP server entry point (Ursa Major)
└── README.md
```

---

## Roadmap and Planning

- Active unfinished work for Ursa now lives in the workspace root `ROADMAP.md`.
- Repo-specific historical and shipped changes belong in `CHANGELOG.md`.

---

## Security & Legal

Ursa is intended for:

- Authorized security testing
- Red team engagements
- CTF competitions
- Security research

Do **not** use this project on systems you do not own or have explicit permission to test.

---

## Contributing

Contributions are welcome. Good starting points:

- Documentation polish and examples
- Tests and edge-case hardening
- Tool quality and false-positive reduction
- UX improvements for operator workflows and reporting

If you open a PR, include:
- Clear scope and rationale
- Reproduction/testing notes
- Any security implications

---

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
