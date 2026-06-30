# Ursa Minor

Recon, scanning, and lightweight host-defense toolkit — the reconnaissance component of [Ursa](../README.md).

Ursa Minor provides 20 tools across network reconnaissance, vulnerability scanning, and defensive host triage, available as an MCP server (for AI agents), a CLI, or standalone Python scripts.

## Tools

| Tool | Description |
|------|-------------|
| `discover_network` | ARP scan to find all live devices on the local network |
| `scan_ports` | TCP port scan with banner grabbing and service identification |
| `sniff_packets` | Live packet capture and protocol analysis |
| `full_recon` | Discover all hosts, then port scan each one |
| `lookup_service` | Identify what service runs on a given port |
| `get_my_network_info` | Get your local IP, gateway, and network range |
| `enumerate_subdomains` | Find subdomains via Certificate Transparency logs and DNS brute-force |
| `dirbust` | Brute-force hidden files and directories on web servers |
| `vuln_scan` | Scan web URLs for SQLi, XSS, command injection, LFI, and header issues |
| `credential_spray` | Brute-force or spray credentials against SSH, FTP, and HTTP Basic Auth |
| `os_fingerprint` | Identify remote OS via TCP/IP stack analysis and banner grabbing |
| `smb_enum` | Enumerate SMB shares, OS version, signing config, and known vulnerabilities |
| `snmp_scan` | Query devices via SNMP; brute-force community strings |
| `crack_hash` | Dictionary attack on MD5, SHA1, SHA256, and SHA512 hashes |
| `identify_hash` | Detect the type of a password hash |
| `generate_reverse_shell` | Generate reverse shell payloads for bash, python, nc, php, ruby, perl, powershell |
| `detect_persistence` | Scan common persistence locations and score suspicious artifacts |
| `create_baseline` | Save a defensive baseline snapshot of persistence, users, and listening ports |
| `baseline_diff` | Compare current host state against a saved baseline and report drift |
| `triage_host` | Run a lightweight host triage workflow with optional baseline comparison |
| `ursa_tool_policies` | Show tool risk levels, approval requirements, and policy metadata |

## Usage

### MCP Server (for Claude)

See the [main README](../README.md#mcp-configuration) for MCP setup instructions.

Once configured, Claude can use any tool conversationally:

> "Scan my network for devices"
> "Port scan 192.168.1.1"
> "Check that web server for vulnerabilities"
> "Triage this Linux host for suspicious persistence"

### CLI

If installed as a package (`pip install ./minor`):

```bash
ursa mcp serve    # Start the MCP server
```

### Standalone Scripts

Each tool can be run directly as a Python script:

```bash
sudo python3 minor/discover.py                    # ARP network discovery
sudo python3 minor/portscan.py 192.168.1.1        # Port scan a target
sudo python3 minor/recon.py                        # Full network recon
sudo python3 minor/sniff.py                        # Packet capture
sudo python3 minor/subenum.py example.com          # Subdomain enumeration
sudo python3 minor/dirbust.py http://target.com    # Directory brute-force
sudo python3 minor/vulnscan.py http://target.com   # Vulnerability scan
sudo python3 minor/credspray.py ssh 192.168.1.1    # Credential spray
sudo python3 minor/osfinger.py 192.168.1.1         # OS fingerprint
sudo python3 minor/smbenum.py 192.168.1.1          # SMB enumeration
sudo python3 minor/snmpscan.py 192.168.1.1         # SNMP scan
python3 minor/hashcrack.py <hash>                  # Crack a hash
python3 minor/revshell.py                          # Generate reverse shells
```

## Permissions

Most tools require `sudo` because they use raw sockets (ARP, ICMP, TCP SYN probes). Tools that only make standard TCP connections or HTTP requests (hash cracking, reverse shell generation, directory busting) do not require elevated privileges.

The defensive triage tools do not require `sudo` when scanning an offline filesystem root. On a live host, elevated privileges may improve visibility into listening ports and system-wide persistence locations.

## Policy Gates and Audit

Ursa Minor keeps normal read-only enumeration available, but high-risk MCP
actions require explicit approval metadata before execution. Gated actions
include packet capture, full network reconnaissance, full port sweeps,
authenticated directory discovery, active injection scans, API schema probing,
reverse-shell payload generation, credential spraying, SNMP brute-force/walk,
and ARP spoofing.

Pass `policy_actor`, `policy_reason`, and `policy_approval_id` to proceed with
an approval-gated tool. Destructive tools also respect the active engagement's
`allow_destructive` setting when an engagement is active. Each policy decision
is appended to `~/.ursa/audit/minor_policy.jsonl` with actor, target,
justification, risk level, and policy result. Use `ursa_tool_policies` to list
the machine-readable risk metadata exposed by the MCP server.

## Dependencies

- `scapy` — packet crafting and network scanning
- `mcp[cli]` — Model Context Protocol server
- `paramiko` — SSH client for credential testing
- `click` — CLI framework

## File Structure

```
minor/
├── server.py         # Standalone launcher for the packaged MCP server
├── discover.py       # ARP network discovery
├── portscan.py       # TCP port scanner
├── sniff.py          # Packet capture
├── recon.py          # Full reconnaissance orchestrator
├── osfinger.py       # OS fingerprinting
├── subenum.py        # Subdomain enumeration
├── dirbust.py        # Directory brute-forcing
├── vulnscan.py       # Web vulnerability scanner
├── credspray.py      # Credential spraying
├── smbenum.py        # SMB enumeration
├── snmpscan.py       # SNMP scanning
├── arpspoof.py       # ARP spoofing (standalone only)
├── hashcrack.py      # Hash cracking
├── revshell.py       # Reverse shell generator
├── pyproject.toml    # Package config
└── src/ursa_minor/   # Installable package
    ├── cli.py        # Click CLI entry point
    ├── defense.py    # Defensive host triage and baseline helpers
    └── server.py     # MCP server (package version)
```
