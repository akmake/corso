"""
Network Scanner Module
----------------------
Two scan modes:
  1. scan_local_network()  — discovers all live hosts on the local /24 subnet (ping sweep)
  2. scan_host(host, ports) — deep port + service scan on a specific target

Requires: nmap binary installed on the system + python-nmap
"""

import asyncio
import json
import socket
from typing import Any

from core.tool_runner import is_available, run_tool

log = __import__("logging").getLogger(__name__)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


def _nmap_unavailable() -> dict:
    return {
        "error": "nmap is not available. Install nmap binary + 'pip install python-nmap'."
    }


class NetworkScanner:

    # ------------------------------------------------------------------ #
    #  LAN Discovery (ping sweep)
    # ------------------------------------------------------------------ #
    @staticmethod
    async def scan_local_network() -> dict:
        """Ping-sweep the local /24 subnet. Returns all live hosts."""
        if not NMAP_AVAILABLE:
            return _nmap_unavailable()

        loop = asyncio.get_event_loop()

        def _scan() -> dict:
            nm = nmap.PortScanner()

            # Detect local IP and build the /24 subnet
            hostname   = socket.gethostname()
            local_ip   = socket.gethostbyname(hostname)
            subnet     = ".".join(local_ip.split(".")[:3]) + ".0/24"

            # -sn = ping sweep (no port scan), fast
            nm.scan(hosts=subnet, arguments="-sn --host-timeout 3s")

            hosts: list[dict] = []
            for host in nm.all_hosts():
                info: dict[str, Any] = {
                    "ip":       host,
                    "status":   nm[host].state(),
                    "hostname": nm[host].hostname() or "",
                    "mac":      nm[host]["addresses"].get("mac", ""),
                    "vendor":   "",
                }
                vendor_map = nm[host].get("vendor", {})
                if vendor_map:
                    info["vendor"] = next(iter(vendor_map.values()), "")
                hosts.append(info)

            return {
                "scanner_ip": local_ip,
                "subnet":     subnet,
                "total":      len(hosts),
                "hosts":      hosts,
            }

        return await loop.run_in_executor(None, _scan)

    # ------------------------------------------------------------------ #
    #  Deep Port Scan on a specific host
    # ------------------------------------------------------------------ #
    @staticmethod
    async def scan_host(host: str, ports: str = "1-1024", stealth: bool = False) -> dict:
        """
        Full port + service-version scan on a single host.
        ports:   nmap port range string, e.g. "1-1024", "22,80,443", "1-65535"
        stealth: True = passive-friendly flags (T2, no version probing) to
                 reduce noise on the wire. Slower but far less detectable.
        """
        if not NMAP_AVAILABLE:
            return _nmap_unavailable()

        loop = asyncio.get_event_loop()

        def _scan() -> dict:
            nm = nmap.PortScanner()
            if stealth:
                # -sS SYN scan, -T2 polite timing, no version detection,
                # --host-timeout prevents hanging on filtered hosts
                args = "-sS -T2 --host-timeout 60s --open"
            else:
                # Standard active scan: service + version detection, faster timing
                args = "-sV -T4 --host-timeout 120s --open"
            nm.scan(
                hosts=host,
                ports=ports,
                arguments=args,
            )

            open_ports: list[dict] = []
            for scanned_host in nm.all_hosts():
                for proto in nm[scanned_host].all_protocols():
                    for port, port_info in nm[scanned_host][proto].items():
                        if port_info["state"] == "open":
                            open_ports.append({
                                "port":     port,
                                "protocol": proto,
                                "service":  port_info.get("name", ""),
                                "product":  port_info.get("product", ""),
                                "version":  port_info.get("version", ""),
                                "extra":    port_info.get("extrainfo", ""),
                                "cpe":      port_info.get("cpe", ""),
                            })

            # Sort by port number
            open_ports.sort(key=lambda p: p["port"])

            return {
                "host":       host,
                "ports_range": ports,
                "open_ports": open_ports,
                "total_open": len(open_ports),
            }

        return await loop.run_in_executor(None, _scan)

    # ------------------------------------------------------------------ #
    #  Quick TCP connect check (no nmap required)
    # ------------------------------------------------------------------ #
    @staticmethod
    async def quick_check(host: str, ports: list[int] | None = None) -> dict:
        """
        Lightweight async TCP connect check — no nmap needed.
        Useful for a fast sanity check on common ports.
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     3306, 3389, 5432, 6379, 8080, 8443, 27017]

        COMMON_SERVICES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB",
        }

        async def _try_port(port: int) -> dict | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=1.5
                )
                writer.close()
                await writer.wait_closed()
                return {
                    "port":    port,
                    "state":   "open",
                    "service": COMMON_SERVICES.get(port, "unknown"),
                }
            except Exception:
                return None

        tasks   = [_try_port(p) for p in ports]
        results = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r is not None]
        open_ports.sort(key=lambda p: p["port"])

        return {
            "host":       host,
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "method":     "tcp_connect",
        }

    # ------------------------------------------------------------------ #
    #  RustScan — ultra-fast full port scan (Docker)
    # ------------------------------------------------------------------ #
    @staticmethod
    async def rustscan(host: str, ports: str = "1-65535") -> dict:
        """
        Ultra-fast port scan using RustScan.
        Falls back to quick_check if unavailable.
        """
        if not is_available("rustscan"):
            return await NetworkScanner.quick_check(host)

        try:
            code, stdout, stderr = await run_tool("rustscan", [
                "-a", host,
                "-r", ports,
                "--ulimit", "5000",
                "-g",  # greppable output
                "--timeout", "3000",
            ], timeout=120)

            open_ports = []
            for line in stdout.strip().splitlines():
                line = line.strip()
                # RustScan greppable: host -> [ports]
                if "->" in line:
                    ports_part = line.split("->")[-1].strip().strip("[]")
                    for p in ports_part.split(","):
                        p = p.strip()
                        if p.isdigit():
                            open_ports.append({
                                "port": int(p),
                                "state": "open",
                                "service": "",
                            })
                elif line.isdigit():
                    open_ports.append({"port": int(line), "state": "open", "service": ""})

            open_ports.sort(key=lambda x: x["port"])
            return {
                "host": host,
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "method": "rustscan",
            }
        except Exception as e:
            log.debug("RustScan error: %s", e)
            return await NetworkScanner.quick_check(host)

    # ------------------------------------------------------------------ #
    #  Masscan — mass IP/port scanning
    # ------------------------------------------------------------------ #
    @staticmethod
    async def masscan(host: str, ports: str = "1-65535", rate: int = 10000) -> dict:
        """
        Fast network scanning using Masscan.
        Falls back to quick_check if unavailable.
        """
        if not is_available("masscan"):
            return await NetworkScanner.quick_check(host)

        try:
            code, stdout, stderr = await run_tool("masscan", [
                host,
                "-p", ports,
                "--rate", str(rate),
                "--open-only",
                "-oJ", "/dev/stdout",
            ], timeout=180)

            open_ports = []
            if stdout.strip():
                try:
                    # Masscan JSON output has leading/trailing artifacts
                    clean = stdout.strip().rstrip(",").strip()
                    if not clean.startswith("["):
                        clean = "[" + clean + "]"
                    data = json.loads(clean)
                    for entry in data:
                        if isinstance(entry, dict) and "ports" in entry:
                            for p in entry["ports"]:
                                open_ports.append({
                                    "port": p.get("port", 0),
                                    "state": p.get("status", "open"),
                                    "service": p.get("service", {}).get("name", ""),
                                })
                except json.JSONDecodeError:
                    for line in stdout.splitlines():
                        if "open" in line and "tcp" in line:
                            parts = line.split()
                            for part in parts:
                                if part.isdigit():
                                    open_ports.append({"port": int(part), "state": "open", "service": ""})
                                    break

            open_ports.sort(key=lambda x: x["port"])
            return {
                "host": host,
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "method": "masscan",
                "rate": rate,
            }
        except Exception as e:
            log.debug("Masscan error: %s", e)
            return await NetworkScanner.quick_check(host)
