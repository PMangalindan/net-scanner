"""Simple network discovery and fingerprinting proof of concept.

This script scans one CIDR range, pings each usable host once, and adds
best-effort fingerprinting data for online hosts.
"""

from __future__ import annotations

import argparse
import asyncio
import http.client
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )

    PYSNMP_AVAILABLE = True
    PYSNMP_ASYNC_API = False
except ImportError:
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )

        PYSNMP_AVAILABLE = True
        PYSNMP_ASYNC_API = True
    except ImportError:
        PYSNMP_AVAILABLE = False
        PYSNMP_ASYNC_API = False


MAX_USABLE_HOSTS = 256
DEFAULT_WORKERS = 32
DEFAULT_TIMEOUT = 1.0
DEFAULT_PORT_TIMEOUT = 0.5
DEFAULT_HTTP_TIMEOUT = 1.0
DEFAULT_PORTS = [22, 23, 53, 80, 443, 445, 3389, 9100]
DEFAULT_SNMP_TIMEOUT = 1.0

SNMP_OIDS = {
    "snmp_sys_descr": "1.3.6.1.2.1.1.1.0",
    "snmp_sys_object_id": "1.3.6.1.2.1.1.2.0",
    "snmp_sys_contact": "1.3.6.1.2.1.1.4.0",
    "snmp_sys_name": "1.3.6.1.2.1.1.5.0",
    "snmp_sys_location": "1.3.6.1.2.1.1.6.0",
}


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated list of TCP ports."""

    raw_items = [item.strip() for item in value.split(",") if item.strip()]
    if not raw_items:
        raise argparse.ArgumentTypeError("Ports list cannot be empty.")

    ports: list[int] = []
    for raw in raw_items:
        if not raw.isdigit():
            raise argparse.ArgumentTypeError(f"Invalid port value: {raw}")
        port = int(raw)
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {raw}")
        ports.append(port)

    return sorted(set(ports))


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Scan a CIDR range and ping each usable host once."
    )
    parser.add_argument("cidr", help="CIDR range to scan, for example 192.168.1.0/24")
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Maximum number of worker threads to use (default: 32).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Ping timeout in seconds (default: 1).",
    )
    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        help="Comma-separated TCP ports to check for online hosts.",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=DEFAULT_PORT_TIMEOUT,
        help="TCP connect timeout in seconds (default: 0.5).",
    )
    parser.add_argument(
        "--json-out",
        help="Optional output file path for JSON results.",
    )
    parser.add_argument(
        "--snmp",
        action="store_true",
        help="Enable best-effort SNMP polling on UDP/161 for online hosts.",
    )
    parser.add_argument(
        "--snmp-community",
        default="public",
        help="SNMP v2c community string (default: public).",
    )
    parser.add_argument(
        "--snmp-timeout",
        type=float,
        default=DEFAULT_SNMP_TIMEOUT,
        help="SNMP request timeout in seconds (default: 1).",
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--show-offline",
        dest="show_offline",
        action="store_true",
        default=True,
        help="Print offline hosts as well as online hosts.",
    )
    output_group.add_argument(
        "--online-only",
        dest="show_offline",
        action="store_false",
        help="Only print online hosts.",
    )

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if args.port_timeout <= 0:
        parser.error("--port-timeout must be > 0")
    if args.snmp_timeout <= 0:
        parser.error("--snmp-timeout must be > 0")
    if args.snmp and not PYSNMP_AVAILABLE:
        parser.error("--snmp requested but pysnmp is not installed. Install pysnmp first.")

    return args


def validate_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate CIDR input and reject scans that are too large."""

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR range: {cidr}") from exc

    if network.num_addresses > MAX_USABLE_HOSTS:
        raise ValueError(
            f"Refusing to scan {network}: more than {MAX_USABLE_HOSTS} addresses."
        )

    return network


def build_ping_command(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, timeout: float) -> list[str]:
    """Build a platform-specific ping command."""

    timeout_seconds = max(1, int(timeout))
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), str(ip)]

    return ["ping", "-c", "1", "-W", str(timeout_seconds), str(ip)]


def parse_latency(output: str) -> int | float | None:
    """Parse latency from ping output in milliseconds."""

    match = re.search(r"time\s*[=<]?\s*([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.IGNORECASE)
    if not match:
        return None

    value = float(match.group(1))
    if value.is_integer():
        return int(value)
    return value


def parse_ttl(output: str) -> int | None:
    """Parse TTL from ping output for Windows and Linux/macOS."""

    match = re.search(r"\bttl\s*=\s*(\d+)\b", output, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def lookup_hostname(ip: str) -> str | None:
    """Best-effort reverse DNS lookup for an IP address."""

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (OSError, socket.herror, socket.gaierror):
        return None


def get_arp_table() -> str:
    """Fetch ARP table output as plain text."""

    if platform.system().lower() == "windows":
        command = ["arp", "-a"]
    else:
        command = ["arp", "-n"]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    return (completed.stdout or "") + "\n" + (completed.stderr or "")


def lookup_mac(ip: str, arp_output: str) -> str | None:
    """Find a MAC address for one IP in ARP output."""

    escaped_ip = re.escape(ip)
    pattern = re.compile(
        rf"{escaped_ip}[^\n]*?((?:[0-9a-f]{{2}}[-:]){{5}}[0-9a-f]{{2}})",
        re.IGNORECASE,
    )
    match = pattern.search(arp_output)
    if not match:
        return None
    return match.group(1).lower().replace("-", ":")


def check_tcp_port(ip: str, port: int, timeout: float) -> bool:
    """Check if a TCP port is reachable using a short connect attempt."""

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_common_ports(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Return open ports from a short list of common TCP ports."""

    open_ports: list[int] = []
    for port in ports:
        if check_tcp_port(ip, port, timeout):
            open_ports.append(port)
    return open_ports


def parse_html_title(html: str) -> str | None:
    """Extract a short HTML title from a response body."""

    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return None

    title = re.sub(r"\s+", " ", match.group(1)).strip()
    if not title:
        return None
    return title[:120]


def probe_http(ip: str, port: int, timeout: float) -> dict[str, Any]:
    """Make a short HTTP or HTTPS request and return basic metadata."""

    connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    try:
        if port == 443:
            context = ssl._create_unverified_context()
            connection = http.client.HTTPSConnection(ip, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(ip, port, timeout=timeout)

        connection.request("GET", "/", headers={"Host": ip, "User-Agent": "network-scan-poc/1.0"})
        response = connection.getresponse()
        body = response.read(8192).decode("utf-8", errors="ignore")
        return {
            "http_title": parse_html_title(body),
            "http_server": response.getheader("Server"),
            "http_status": response.status,
        }
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return {"http_title": None, "http_server": None, "http_status": None}
    finally:
        if connection is not None:
            connection.close()


def merge_http_probe_result(
    current: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Merge HTTP probe data, preferring non-empty values from the candidate."""

    merged = current.copy()
    for key in ("http_title", "http_server", "http_status"):
        if candidate.get(key) is not None:
            merged[key] = candidate[key]
    return merged


def probe_ssh_banner(ip: str, timeout: float) -> str | None:
    """Read the SSH service banner without authenticating."""

    try:
        with socket.create_connection((ip, 22), timeout=timeout) as connection:
            connection.settimeout(timeout)
            banner = connection.recv(256).decode("utf-8", errors="ignore").strip()
    except OSError:
        return None

    return banner or None


def snmp_get(ip: str, community: str, oid: str, timeout: float) -> str | None:
    """Perform one SNMP GET request using pysnmp."""

    if not PYSNMP_AVAILABLE:
        return None

    if not PYSNMP_ASYNC_API:
        timeout_units = max(1, int(round(timeout)))
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=timeout_units, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        try:
            error_indication, error_status, _, var_binds = next(iterator)
        except Exception:
            return None
    else:
        async def _run_get_cmd() -> tuple[Any, Any, Any, Any]:
            target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
            return await get_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

        try:
            error_indication, error_status, _, var_binds = asyncio.run(_run_get_cmd())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                error_indication, error_status, _, var_binds = loop.run_until_complete(_run_get_cmd())
            finally:
                loop.close()
        except Exception:
            return None

    if error_indication or error_status or not var_binds:
        return None

    value = var_binds[0][1]
    return str(value) if value is not None else None


def snmp_poll_basic(ip: str, community: str, timeout: float) -> dict[str, Any]:
    """Poll a small set of SNMP system OIDs; failures remain best-effort."""

    data: dict[str, Any] = {
        "snmp_enabled": False,
        "snmp_sys_descr": None,
        "snmp_sys_object_id": None,
        "snmp_sys_contact": None,
        "snmp_sys_name": None,
        "snmp_sys_location": None,
    }

    for field, oid in SNMP_OIDS.items():
        data[field] = snmp_get(ip, community, oid, timeout)

    # Consider SNMP enabled when any requested OID produced a value.
    data["snmp_enabled"] = any(
        data[field] is not None
        for field in (
            "snmp_sys_descr",
            "snmp_sys_object_id",
            "snmp_sys_contact",
            "snmp_sys_name",
            "snmp_sys_location",
        )
    )
    return data


def add_snmp_hints(device_hints: list[str], snmp_data: dict[str, Any]) -> list[str]:
    """Append SNMP-based hints from sysDescr when available."""

    hints = list(device_hints)
    sys_descr = (snmp_data.get("snmp_sys_descr") or "").lower()

    if "cisco" in sys_descr:
        hints.append("possible Cisco network device")
    if "mikrotik" in sys_descr:
        hints.append("possible MikroTik network device")
    if "ubiquiti" in sys_descr:
        hints.append("possible Ubiquiti network device")
    if "linux" in sys_descr:
        hints.append("possible Linux device")
    if "windows" in sys_descr:
        hints.append("possible Windows device")

    return list(dict.fromkeys(hints))


def build_device_hints(
    ttl: int | None,
    open_ports: list[int],
    http_title: str | None,
    http_server: str | None,
    ssh_banner: str | None,
) -> list[str]:
    """Build lightweight, best-effort hints from service and TTL data."""

    hints: list[str] = []
    ports = set(open_ports)

    if 53 in ports:
        hints.append("possible DNS server")
    if 3389 in ports:
        hints.append("possible Windows/RDP host")
    if 445 in ports:
        hints.append("possible Windows/SMB host")
    if 22 in ports:
        hints.append("possible Linux/network device")
    if ssh_banner:
        hints.append("SSH service detected")
    if 9100 in ports:
        hints.append("possible printer")
    if 80 in ports or 443 in ports:
        hints.append("has web interface")

    server_text = (http_server or "").lower()
    title_text = (http_title or "").lower()
    if "microsoft-iis" in server_text:
        hints.append("possible Windows/IIS server")
    if "nginx" in server_text:
        hints.append("possible Linux/nginx web service")
    if "apache" in server_text:
        hints.append("possible Linux/Apache web service")
    if any(keyword in title_text for keyword in ["router", "gateway", "firewall", "modem", "switch"]):
        hints.append("possible network appliance")

    if ttl is not None:
        if ttl >= 200:
            hints.append("possible network device (high TTL)")
        elif 110 <= ttl <= 140:
            hints.append("possible Windows device (TTL near 128)")
        elif 50 <= ttl <= 80:
            hints.append("possible Linux/Unix device (TTL near 64)")

    # Preserve order and remove duplicates.
    return list(dict.fromkeys(hints))


def ping_host(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    timeout: float,
    ports: list[int],
    port_timeout: float,
    use_snmp: bool,
    snmp_community: str,
    snmp_timeout: float,
) -> dict[str, Any]:
    """Ping one host and collect best-effort fingerprint details."""

    ip_text = str(ip)
    result: dict[str, Any] = {
        "ip": ip_text,
        "online": False,
        "status": "offline",
        "latency_ms": None,
        "ttl": None,
        "hostname": None,
        "mac_address": None,
        "open_ports": [],
        "http_title": None,
        "http_server": None,
        "http_status": None,
        "ssh_banner": None,
        "snmp_enabled": False,
        "snmp_sys_descr": None,
        "snmp_sys_object_id": None,
        "snmp_sys_contact": None,
        "snmp_sys_name": None,
        "snmp_sys_location": None,
        "device_hints": [],
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }

    command = build_ping_command(ip, timeout)
    run_timeout = max(1.0, timeout) + 1.0

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=run_timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return result

    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    if completed.returncode != 0:
        return result

    result["online"] = True
    result["status"] = "online"
    result["latency_ms"] = parse_latency(output)
    result["ttl"] = parse_ttl(output)
    result["hostname"] = lookup_hostname(ip_text)

    # ARP lookup is best-effort and may fail on some systems or networks.
    arp_output = get_arp_table()
    result["mac_address"] = lookup_mac(ip_text, arp_output)

    result["open_ports"] = check_common_ports(ip_text, ports, port_timeout)

    if 80 in result["open_ports"]:
        http_data = probe_http(ip_text, 80, DEFAULT_HTTP_TIMEOUT)
        result.update(http_data)

    if 443 in result["open_ports"]:
        https_data = probe_http(ip_text, 443, DEFAULT_HTTP_TIMEOUT)
        result.update(merge_http_probe_result(result, https_data))

    if 22 in result["open_ports"]:
        result["ssh_banner"] = probe_ssh_banner(ip_text, DEFAULT_HTTP_TIMEOUT)

    if use_snmp:
        snmp_data = snmp_poll_basic(ip_text, snmp_community, snmp_timeout)
        result.update(snmp_data)

    result["device_hints"] = build_device_hints(
        result["ttl"],
        result["open_ports"],
        result["http_title"],
        result["http_server"],
        result["ssh_banner"],
    )
    if use_snmp:
        result["device_hints"] = add_snmp_hints(result["device_hints"], result)
    return result


def format_latency(latency_ms: int | float | None) -> str:
    """Format numeric latency for console output."""

    if latency_ms is None:
        return "unknown"
    if isinstance(latency_ms, float) and not latency_ms.is_integer():
        return f"{latency_ms:g}"
    return str(int(latency_ms))


def print_result(result: dict[str, Any], show_offline: bool) -> None:
    """Print one host result in a compact single-line format."""

    ip_text = result["ip"]
    if not result["online"]:
        if show_offline:
            print(f"{ip_text} offline")
        return

    latency_text = format_latency(result["latency_ms"])
    ttl_text = result["ttl"] if result["ttl"] is not None else "unknown"
    hostname_text = result["hostname"] if result["hostname"] else "unknown"
    mac_text = result["mac_address"] if result["mac_address"] else "unknown"
    ports_text = result["open_ports"] if result["open_ports"] else []
    title_text = result["http_title"] if result["http_title"] else "unknown"
    server_text = result["http_server"] if result["http_server"] else "unknown"
    hints_text = result["device_hints"] if result["device_hints"] else []

    print(
        f"{ip_text} online {latency_text}ms ttl={ttl_text} "
        f"hostname={hostname_text} mac={mac_text} ports={ports_text} "
        f"http_title={title_text} server={server_text} hints={hints_text}"
    )


def scan_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    max_workers: int,
    timeout: float,
    show_offline: bool,
    ports: list[int],
    port_timeout: float,
    use_snmp: bool,
    snmp_community: str,
    snmp_timeout: float,
) -> list[dict[str, Any]]:
    """Scan all usable hosts and print each result as it completes."""

    hosts = list(network.hosts())
    if not hosts:
        return []

    worker_count = max(1, min(max_workers, len(hosts)))
    results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(
                ping_host,
                ip,
                timeout,
                ports,
                port_timeout,
                use_snmp,
                snmp_community,
                snmp_timeout,
            ): ip
            for ip in hosts
        }
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            print_result(result, show_offline)

    return results


def results_for_output(results: list[dict[str, Any]], show_offline: bool) -> list[dict[str, Any]]:
    """Filter results for output modes like --online-only."""

    if show_offline:
        return results
    return [item for item in results if item["online"]]


def write_json(path: str, results: list[dict[str, Any]]) -> None:
    """Write scan results to a JSON file."""

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)


def print_summary(cidr: str, results: list[dict[str, Any]]) -> None:
    """Print a short scan summary."""

    online_count = sum(1 for result in results if result["online"])
    offline_count = len(results) - online_count

    print(f"Scan completed at: {datetime.now().isoformat(timespec='seconds')}")
    print(f"CIDR: {cidr}")
    print(f"Scanned: {len(results)}")
    print(f"Online: {online_count}")
    print(f"Offline: {offline_count}")


def main() -> int:
    """Run the scanner."""

    args = parse_args()

    try:
        network = validate_network(args.cidr)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    results = scan_network(
        network,
        args.workers,
        args.timeout,
        args.show_offline,
        args.ports,
        args.port_timeout,
        args.snmp,
        args.snmp_community,
        args.snmp_timeout,
    )
    print_summary(args.cidr, results)

    if args.json_out:
        output_results = results_for_output(results, args.show_offline)
        write_json(args.json_out, output_results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())