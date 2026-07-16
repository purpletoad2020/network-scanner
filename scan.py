#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner and Topology Mapper
====================================

A self-contained Python application that:
  1. Auto-detects the local network interface and subnet.
  2. Discovers live hosts via ARP (L2) and ICMP ping sweep (L3).
  3. Collects per-host details: IP, MAC, hostname, open ports, OS hint.
  4. Identifies the gateway/router.
  5. Generates an interactive HTML topology map using PyVis (vis.js engine).

Prerequisites:
  - Python 3.7+
  - Administrator / root privileges (required for raw ARP/ICMP sockets)
  - pip install -r requirements.txt

Usage:
    sudo python scan.py          # Linux / macOS
    python scan.py               # Windows (run as Administrator recommended)

Output:
    network_map.html  -- single-file interactive topology map (no CDN deps)
"""

import json
import os
import sys
import socket
import struct
import ipaddress
import subprocess
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# Optional dependencies -- graceful fallback
# ---------------------------------------------------------------------------
try:
    from scapy.all import ARP, Ether, IP, ICMP, sr, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Bundled OUI (MAC-vendor) lookup table
# Compact hex-prefix -> (vendor, device-type hint)
# ---------------------------------------------------------------------------
_OUI_RAW = (
    "000C29|VMware|Virtual Machine\n"
    "005056|VMware|Virtual Machine\n"
    "080027|Oracle VirtualBox|Virtual Machine\n"
    "525400|QEMU/KVM|Virtual Machine\n"
    "001B21|Intel|Workstation / Server\n"
    "0003FF|Cisco Systems|Router / Switch\n"
    "001A2B|HP|Printer / Server\n"
    "001E58|Dell|Server\n"
    "00215D|Apple|Mobile / Workstation\n"
    "00241D|Apple|Mobile / Workstation\n"
    "00265D|Apple|Mobile / Workstation\n"
    "00E04C|Intel|Workstation / Server\n"
    "080027|Sun Microsystems|Server\n"
    "001C42|Apple|Mobile / Workstation\n"
    "ACBC5C|Apple|Mobile / Workstation\n"
    "F0725A|Apple|Mobile / Workstation\n"
    "B0C706|Apple|Mobile / Workstation\n"
    "D85CF9|Apple|Mobile / Workstation\n"
    "001636|Synology|NAS / Server\n"
    "001132|Netgear|Router / Switch\n"
    "001FD6|Ubiquiti|Router / AP\n"
    "04B332|Google|Mobile / IoT\n"
    "D00A8D|Samsung|Mobile / IoT\n"
    "001788|Xiaomi|Mobile / IoT\n"
    "001075|TP-Link|Router / AP\n"
    "001310|Lenovo|Workstation\n"
    "002324|Microsoft|Workstation\n"
    "000D3A|Broadcom|Network Adapter\n"
    "001EC2|ASUS|Router / AP\n"
    "002596|Huawei|Mobile / Router\n"
    "0026F5|Raspberry Pi Foundation|IoT / SBC\n"
    "04F974|Raspberry Pi Foundation|IoT / SBC\n"
    "D83A9A|Raspberry Pi Foundation|IoT / SBC\n"
    "000000|Unknown|Unknown\n"
)

# Parse the OUI table once at module level
OUI_DB: dict[str, tuple[str, str]] = {}
for line in _OUI_RAW.strip().splitlines():
    prefix_hex, vendor, dev_hint = line.split("|")
    OUI_DB[prefix_hex.upper()] = (vendor, dev_hint)


def oui_lookup(mac: str) -> tuple[str, str]:
    """Return (vendor, device_type_hint) for a MAC address."""
    if not mac or mac.lower() in ("unknown", "00:00:00:00:00:00"):
        return ("Unknown", "Unknown")
    # Normalise: remove colons/dashes, take first 6 hex chars
    clean = mac.replace(":", "").replace("-", "").upper()[:6]
    if clean in OUI_DB:
        return OUI_DB[clean]
    # Try shorter prefixes (first 3 bytes -> 6 hex chars, already done)
    return ("Unknown", "Unknown")


# ---------------------------------------------------------------------------
# Common ports to probe
# ---------------------------------------------------------------------------
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443,
]

# Port-to-service mapping for display
PORT_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


# ===================================================================
#  1. Auto-detect interface & subnet
# ===================================================================
def detect_interfaces() -> list[dict]:
    """
    Return a list of dicts describing active, non-loopback interfaces:
      [{ 'name', 'ip', 'netmask', 'network', 'mac' }, ...]
    """
    results = []

    if SCAPY_AVAILABLE:
        # Use scapy's interface table
        for ifname, info in conf.ifaces.items():
            # Handle both dict-style and object-style interfaces (Windows vs Linux)
            if hasattr(info, "ips"):
                # Object-style (e.g., Windows NetworkInterface_Win)
                ips = list(info.ips) if info.ips else []
                mac = getattr(info, "mac", "Unknown")
            elif isinstance(info, dict):
                # Dict-style (e.g., Linux)
                ips = info.get("ips", [])
                mac = info.get("mac", "Unknown")
            else:
                continue
            
            if not ips:
                continue
            for addr in ips:
                try:
                    iface = ipaddress.ip_interface(addr)
                except ValueError:
                    continue
                if iface.ip.is_loopback or iface.ip.is_link_local:
                    continue
                network = iface.network
                results.append({
                    "name": ifname,
                    "ip": str(iface.ip),
                    "netmask": str(network.netmask),
                    "network": network,
                    "mac": mac,
                })
        if results:
            return results

    # ---- Pure-Python fallback ----
    # Try to find the default-route interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        local_ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()

    # Determine netmask via subnet mask query (platform-dependent)
    try:
        if sys.platform == "win32":
            # Windows: use netsh
            out = subprocess.check_output(
                ["netsh", "interface", "ipv4", "show", "addresses"],
                stderr=subprocess.DEVNULL,
            ).decode()
        else:
            out = subprocess.check_output(
                ["ip", "-j", "addr"],
                stderr=subprocess.DEVNULL,
            ).decode()
    except Exception:
        out = ""

    # Simple heuristic: assume /24 for most home networks
    network = ipaddress.ip_interface(f"{local_ip}/24").network
    results.append({
        "name": "default",
        "ip": local_ip,
        "netmask": str(network.netmask),
        "network": network,
        "mac": "Unknown",
    })
    return results


def pick_primary_interface(interfaces: list[dict]) -> dict:
    """Pick the best candidate for scanning (prefer non-wifi, non-loopback)."""
    for iface in interfaces:
        name = iface["name"].lower()
        if "loopback" in name or "lo:" in name:
            continue
        if "wifi" in name or "wlan" in name:
            continue
        return iface
    # Fallback
    for iface in interfaces:
        if not iface["name"].lower().startswith("lo"):
            return iface
    return interfaces[0]


def select_interface(interfaces: list[dict]) -> dict:
    """Let the user select which interface/subnet to scan."""
    print("\nAvailable network interfaces:")
    print("-" * 60)
    
    filtered = []
    for i, iface in enumerate(interfaces):
        name = iface["name"]
        ip = iface["ip"]
        network = iface["network"]
        mac = iface["mac"]
        # Skip loopback
        if "loopback" in name.lower() or name.startswith("lo"):
            continue
        filtered.append((i, iface))
        print(f"  [{i}] {name}")
        print(f"      IP: {ip}")
        print(f"      Network: {network}")
        print(f"      MAC: {mac}")
        print()
    
    if not filtered:
        print("[!] No usable network interfaces found.")
        sys.exit(1)
    
    # Default to first interface
    print(f"Default: interface [{filtered[0][0]}] ({filtered[0][1]['name']})")
    choice = input(f"\nSelect interface number (or press Enter for default): ").strip()
    
    if choice == "":
        idx = filtered[0][0]
    else:
        try:
            idx = int(choice)
            if idx not in [f[0] for f in filtered]:
                print(f"[!] Invalid selection. Using default.")
                idx = filtered[0][0]
        except ValueError:
            print(f"[!] Invalid input. Using default.")
            idx = filtered[0][0]
    
    selected = next(f[1] for f in filtered if f[0] == idx)
    print(f"\nSelected: {selected['name']} ({selected['ip']}/{selected['network'].prefixlen})")
    return selected


def select_subnet(interface: dict) -> ipaddress.IPv4Network:
    """Let the user confirm or change the subnet to scan."""
    default_network = interface["network"]
    print(f"\nDefault subnet: {default_network}")
    
    choice = input("Enter custom subnet (e.g., 192.168.1.0/24, or Enter for default): ").strip()
    
    if choice == "":
        return default_network
    
    try:
        network = ipaddress.ip_network(choice, strict=False)
        # Ensure it's IPv4
        if isinstance(network, ipaddress.IPv6Network):
            print("[!] IPv6 networks are not supported. Using default.")
            return default_network
        print(f"Using custom subnet: {network}")
        return network
    except ValueError as e:
        print(f"[!] Invalid subnet: {e}. Using default.")
        return default_network


# ===================================================================
#  2. Host discovery -- ARP + ICMP
# ===================================================================
def arp_scan(network: ipaddress.IPv4Network, interface_name: str = None) -> list[dict]:
    """
    Layer-2 ARP sweep.  Returns [{ip, mac}] for every alive host.
    Requires root / admin on most platforms.
    Tries scapy first, falls back to socket-based scanning if scapy fails.
    """
    if not SCAPY_AVAILABLE:
        return socket_arp_scan(network)

    discovered: list[dict] = []
    try:
        # Force scapy to use the correct interface
        if interface_name:
            conf.iface = interface_name
        
        # Broadcast ARP request to entire /24
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        ans, _ = srp(pkt, timeout=3, verbose=False, iface=conf.iface)
        for _, rcv in ans:
            discovered.append({
                "ip": rcv[ARP].psrc,
                "mac": rcv[Ether].src,
            })
    except PermissionError:
        print("[!] ARP scan requires root/admin privileges.")
    except Exception as exc:
        print(f"[!] Scapy ARP scan failed: {exc}")
        print("    Falling back to socket-based scanning...")
        return socket_arp_scan(network)
    
    return discovered


def nmap_arp_scan(network: ipaddress.IPv4Network, interface_name: str = None) -> list[dict]:
    """
    Use nmap for fast, reliable host discovery via ARP/ICMP.
    Falls back to socket_arp_scan if nmap is not available.
    """
    discovered: list[dict] = []
    try:
        import subprocess
        cmd = [
            "nmap", "-sn", "-n", "--send-ip",
            "-oG", "-",  # greppable output to stdout
            str(network)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"    nmap scan failed: {result.stderr.strip()}")
            return socket_arp_scan(network)
        
        for line in result.stdout.splitlines():
            if line.startswith("#") and "Host:" in line:
                parts = line.split()
                # Format: #Host: 192.168.1.1 () Status: Up
                try:
                    ip_idx = parts.index("#Host:") + 1
                    ip = parts[ip_idx]
                    status_idx = parts.index("Status:") + 1
                    status = parts[status_idx]
                    if status == "Up":
                        discovered.append({"ip": ip, "mac": "Unknown", "via": "Nmap"})
                except (ValueError, IndexError):
                    pass
    except FileNotFoundError:
        print("    nmap not found, falling back to socket-based scanning...")
        return socket_arp_scan(network)
    except subprocess.TimeoutExpired:
        print("    nmap scan timed out, falling back to socket-based scanning...")
        return socket_arp_scan(network)
    except Exception as exc:
        print(f"    nmap scan error: {exc}, falling back to socket-based scanning...")
        return socket_arp_scan(network)
    
    return discovered


def socket_arp_scan(network: ipaddress.IPv4Network) -> list[dict]:
    """
    Socket-based ARP/ICMP scan as a fallback when scapy fails.
    Uses TCP connect to common ports as a proxy for host discovery.
    """
    discovered: list[dict] = []
    print(f"    Using socket-based scan on {network}...")
    
    # Try TCP connect to common ports as host discovery
    test_ports = [80, 443, 22, 53]
    
    def _probe_host(ip: str) -> dict | None:
        try:
            # Try connecting to common ports
            for port in test_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return {"ip": ip, "mac": "Unknown", "via": "TCP-Socket"}
            
            # If no TCP connection succeeded, try ICMP ping
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                s.settimeout(1)
                ident = os.getpid() & 0xFFFF
                pkt = _build_icmp(ident, 1)
                s.sendto(pkt, (ip, 0))
                _, _ = s.recvfrom(1024)
                s.close()
                return {"ip": ip, "mac": "Unknown", "via": "ICMP-Socket"}
            except Exception:
                pass
                
            return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=64) as pool:
        target_ips = [str(h) for h in network.hosts()]
        futures = {pool.submit(_probe_host, ip): ip for ip in target_ips}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                if r:
                    discovered.append(r)
            except Exception:
                pass
    
    return discovered


def icmp_ping_sweep(network: ipaddress.IPv4Network,
                    skip_ips: set[str]) -> list[dict]:
    """
    Layer-3 ICMP ping sweep for hosts missed by ARP.
    Falls back to socket-based scanning if scapy fails.
    """
    discovered: list[dict] = []
    target_ips = [str(h) for h in network.hosts()
                  if str(h) not in skip_ips]

    def _ping_one(ip: str) -> dict | None:
        try:
            if SCAPY_AVAILABLE:
                ans, _ = sr(
                    IP(dst=ip) / ICMP(type=8, code=0),
                    timeout=1, verbose=False,
                )
                if ans:
                    return {"ip": ip, "mac": "Unknown", "via": "ICMP"}
            else:
                # Pure-socket ping
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_ICMP)
                sock.settimeout(1)
                ident = os.getpid() & 0xFFFF
                seq = 1
                pkt = _build_icmp(ident, seq)
                sock.sendto(pkt, (ip, 0))
                _, _ = sock.recvfrom(1024)
                return {"ip": ip, "mac": "Unknown", "via": "ICMP"}
        except Exception:
            return None
        finally:
            if not SCAPY_AVAILABLE:
                sock.close()

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_ping_one, ip): ip for ip in target_ips}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                if r:
                    discovered.append(r)
            except Exception:
                pass
    return discovered


def _build_icmp(ident: int, seq: int) -> bytes:
    """Build a minimal ICMP echo-request packet."""
    checksum = _icmp_checksum(b"\x08\x00" + struct.pack("!HH", ident, seq) + b"\x00" * 32)
    return struct.pack("!BBHHH", 8, 0, checksum, ident, seq) + b"\x00" * 32


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s & 0xFFFF)


# ===================================================================
#  3. Port scanning (TCP connect)
# ===================================================================
def scan_ports(ip: str, ports: list[int],
               timeout: float = 0.5) -> dict[int, str]:
    """Return {port: service_name} for every open port."""
    open_ports: dict[int, str] = {}
    lock = threading.Lock()

    def _probe(port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports[port] = PORT_SERVICES.get(port, f"port-{port}")
            s.close()
        except Exception:
            pass

    threads = [threading.Thread(target=_probe, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return open_ports


# ===================================================================
#  4. Reverse DNS / hostname resolution
# ===================================================================
def resolve_hostname(ip: str, timeout: float = 2.0) -> str | None:
    """Reverse-DNS lookup with timeout."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


# ===================================================================
#  5. Gateway / router identification
# ===================================================================
def find_gateway(interfaces: list[dict]) -> str | None:
    """Return the default gateway IP, or None."""
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["route", "print"],
                stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.splitlines():
                if "0.0.0.0" in line and "0.0.0.0" in line.split()[-1:]:
                    parts = line.split()
                    for p in parts:
                        try:
                            ipaddress.ip_address(p)
                            return p
                        except ValueError:
                            continue
        else:
            out = subprocess.check_output(
                ["ip", "route"],
                stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.splitlines():
                if "default via" in line:
                    parts = line.split()
                    idx = parts.index("via")
                    return parts[idx + 1]
    except Exception as exc:
        print(f"[!] Could not find gateway: {exc}")
    return None


# ===================================================================
#  6. Device-type inference
# ===================================================================
def infer_device_type(open_ports: dict[int, str],
                      vendor: str,
                      dev_hint: str,
                      is_gateway: bool) -> str:
    """Heuristic classification."""
    if is_gateway:
        return "Router / Gateway"

    # MAC-vendor hints
    if "Virtual" in dev_hint:
        return "Virtual Machine"
    if "Raspberry" in vendor or "Pi" in dev_hint:
        return "Single-Board Computer"
    if "NAS" in dev_hint:
        return "NAS / Storage"
    if "Printer" in dev_hint:
        return "Printer"
    if "IoT" in dev_hint:
        return "IoT Device"
    if "Mobile" in dev_hint and vendor in ("Apple", "Samsung", "Xiaomi"):
        return "Mobile Device"

    # Port-based hints
    if 3389 in open_ports:
        return "Remote Desktop Server"
    if 22 in open_ports and 80 in open_ports:
        return "Web Server"
    if 80 in open_ports or 443 in open_ports:
        return "Server"
    if 53 in open_ports and 445 in open_ports:
        return "Domain Controller"
    if 3306 in open_ports or 5432 in open_ports:
        return "Database Server"

    return "Workstation / Client"


def node_icon(device_type: str) -> str:
    """Return an emoji icon for the device type."""
    icons = {
        "Router / Gateway":     "\U0001f4e1",   # 📡
        "Server":               "\U0001f5a5",   # 🖥
        "Virtual Machine":      "\U0001f4bb",   # 💻
        "Mobile Device":        "\U0001f4f1",   # 📱
        "Single-Board Computer":"\U0001f353",   # 🍓
        "NAS / Storage":        "\U0001f4be",   # 💾
        "Printer":              "\U0001f5a8",   # 🖨
        "IoT Device":           "\U0001f4df",   # 📟
        "Domain Controller":    "\U0001f3db",   # 🏛
        "Database Server":      "\U0001f5c4",   # 🗄
        "Web Server":           "\U0001f310",   # 🌐
        "Remote Desktop Server":"\U0001f5a7",   # 🖧
        "Workstation / Client": "\U0001f4bb",   # 💻
    }
    return icons.get(device_type, "\U0001f4bb")  # default 💻


# ===================================================================
#  7. Build the PyVis topology map
# ===================================================================
def build_topology(hosts: list[dict], gateway_ip: str | None,
                   output_path: str) -> None:
    """Generate a self-contained interactive HTML topology map."""
    if not PYVIS_AVAILABLE:
        print("[!] PyVis is not installed. Skipping HTML generation.")
        return

    net = Network(
        height="800px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#e0e0e0",
        directed=False,
        notebook=False,
    )

    # Enable physics for a nice force-directed layout
    options = {
        "nodes": {
            "shape": "dot",
            "size": 18,
            "font": {"size": 13, "face": "Segoe UI, Arial"},
            "shadow": {"enabled": True, "color": "rgba(0,0,0,0.4)", "size": 8},
            "borderWidth": 2
        },
        "edges": {
            "smooth": {"type": "continuous", "roundness": 0.3},
            "width": 1.5,
            "color": {"color": "#555577", "highlight": "#8888cc"},
            "arrows": {"to": {"enabled": False}}
        },
        "physics": {
            "enabled": True,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
                "gravitationalConstant": -80,
                "centralGravity": 0.01,
                "springLength": 150,
                "springConstant": 0.05
            },
            "maxVelocity": 75,
            "timestep": 0.4,
            "stabilization": {"iterations": 200, "fit": True}
        }
    }
    net.set_options(json.dumps(options))

    # Colour palette by category
    COLOURS = {
        "Router / Gateway":   {"bg": "#ff6b35", "border": "#ffffff"},
        "Server":             {"bg": "#4ecdc4", "border": "#ffffff"},
        "Virtual Machine":    {"bg": "#a855f7", "border": "#ffffff"},
        "Mobile Device":      {"bg": "#3b82f6", "border": "#ffffff"},
        "Single-Board Computer":{"bg": "#f59e0b", "border": "#ffffff"},
        "NAS / Storage":      {"bg": "#10b981", "border": "#ffffff"},
        "Printer":            {"bg": "#ec4899", "border": "#ffffff"},
        "IoT Device":         {"bg": "#6b7280", "border": "#ffffff"},
        "Domain Controller":  {"bg": "#ef4444", "border": "#ffffff"},
        "Database Server":    {"bg": "#06b6d4", "border": "#ffffff"},
        "Web Server":         {"bg": "#84cc16", "border": "#ffffff"},
        "Remote Desktop Server":{"bg": "#f97316", "border": "#ffffff"},
        "Workstation / Client":{"bg": "#6366f1", "border": "#ffffff"},
    }

    # Add gateway node
    if gateway_ip:
        gw = next((h for h in hosts if h["ip"] == gateway_ip), None)
        icon = node_icon("Router / Gateway")
        gw_hostname = gw["hostname"] if gw and gw["hostname"] else ""
        gw_mac = gw["mac"] if gw else "Unknown"
        label = icon
        c = COLOURS.get("Router / Gateway", COLOURS["Server"])
        title_parts = [
            f"<b>Gateway</b>",
        ]
        if gw_hostname:
            title_parts.append(f"Hostname: {gw_hostname}")
        title_parts.extend([
            f"IP: {gateway_ip}",
            f"MAC: {gw_mac}",
            f"Type: Router / Gateway",
        ])
        net.add_node(
            gateway_ip,
            label=label,
            color={"background": c["bg"], "border": c["border"]},
            size=30,
            shape="dot",
            font={"size": 28, "face": "Segoe UI Emoji, Apple Color Emoji, Noto Color Emoji, Arial", "color": "#e0e0e0"},
            title="<br>".join(title_parts),
        )

    # Add host nodes
    for h in hosts:
        ip = h["ip"]
        hostname = h["hostname"] or ""
        mac = h["mac"]
        dtype = h["device_type"]
        icon = node_icon(dtype)
        label = icon
        c = COLOURS.get(dtype, {"bg": "#6366f1", "border": "#ffffff"})

        ports_str = ", ".join(
            f"{p} ({s})" for p, s in sorted(h["open_ports"].items())
        ) or "No open ports"

        title_lines = [
            f"<b>{ip}</b>",
        ]
        if hostname:
            title_lines.append(f"Hostname: {hostname}")
        title_lines.extend([
            f"MAC: {mac}",
            f"Type: {dtype}",
            f"Vendor: {h['vendor']}",
            f"Ports: {ports_str}",
            f"Discovered: {h['discovered_via']}",
        ])

        net.add_node(
            ip,
            label=label,
            color={"background": c["bg"], "border": c["border"]},
            size=20,
            shape="dot",
            font={"size": 24, "face": "Segoe UI Emoji, Apple Color Emoji, Noto Color Emoji, Arial", "color": "#e0e0e0"},
            title="<br>".join(title_lines),
        )

        # Edge to gateway
        if gateway_ip:
            net.add_edge(
                ip, gateway_ip,
                color={"color": "#555577"},
                width=1,
            )

    # Save
    net.save_graph(output_path)
    print(f"\n[+] Topology map saved -> {os.path.abspath(output_path)}")


# ===================================================================
#  MAIN
# ===================================================================
def main() -> None:
    print("=" * 60)
    print("  Network Scanner & Topology Mapper")
    print("=" * 60)

    # --- Dependencies check ---
    missing = []
    if not SCAPY_AVAILABLE:
        missing.append("scapy")
    if not PYVIS_AVAILABLE:
        missing.append("pyvis")
    if missing:
        print(f"\n[!] Missing packages: {', '.join(missing)}")
        print("    Run: pip install -r requirements.txt")
        sys.exit(1)

    # --- Step 1: Interface detection ---
    print("\n[*] Step 1: Detecting network interfaces...")
    interfaces = detect_interfaces()
    if not interfaces:
        print("[!] No active network interfaces found.")
        sys.exit(1)

    # Let user select interface
    primary = select_interface(interfaces)
    
    # Let user select subnet
    target_network = select_subnet(primary)
    
    print(f"\n    Selected interface: {primary['name']}")
    print(f"    IP: {primary['ip']}")
    print(f"    Subnet: {target_network}")

    # --- Step 2: Discover hosts ---
    print(f"\n[*] Step 2: Scanning {target_network} for live hosts...")
    print(f"    Interface: {primary['name']}")

    # ARP scan first (fast, layer-2)
    arp_results = arp_scan(target_network, primary["name"])
    print(f"    ARP scan found {len(arp_results)} hosts.")

    # Collect IPs already found
    found_ips = {r["ip"] for r in arp_results}

    # If ARP found nothing, try ICMP
    if not arp_results:
        print("    ARP found nothing. Falling back to ICMP ping sweep...")
        icmp_results = icmp_ping_sweep(target_network, found_ips)
        for r in icmp_results:
            if r["ip"] not in found_ips:
                r["mac"] = "Unknown"
                arp_results.append(r)
                found_ips.add(r["ip"])
        print(f"    ICMP sweep found {len(icmp_results)} hosts.")
    else:
        # Enrich ARP results with 'via' marker
        for r in arp_results:
            r.setdefault("via", "ARP")

    print(f"    Total unique hosts: {len(arp_results)}")

    if not arp_results:
        print("\n[!] No hosts discovered. Exiting.")
        sys.exit(0)

    # --- Step 3: Identify gateway ---
    print(f"\n[*] Step 3: Identifying gateway...")
    gateway_ip = find_gateway(interfaces)
    # Also check if any ARP result matches the gateway
    if not gateway_ip:
        # Try to get from ARP results (often the first IP in the subnet)
        first_host = next(iter(target_network.hosts()))
        if str(first_host) in found_ips:
            gateway_ip = str(first_host)
            print(f"    Guessing gateway: {gateway_ip}")
    print(f"    Gateway: {gateway_ip or 'Not identified'}")

    # --- Step 4: Collect per-host details ---
    print(f"\n[*] Step 4: Collecting host details...")
    hosts_data: list[dict] = []

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {}
        for host in arp_results:
            ip = host["ip"]
            mac = host.get("mac", "Unknown")
            via = host.get("via", "ARP")

            # Submit port scan
            fut_ports = pool.submit(scan_ports, ip, COMMON_PORTS)
            # Submit hostname resolution
            fut_host = pool.submit(resolve_hostname, ip)

            futures[ip] = {
                "ip": ip,
                "mac": mac,
                "via": via,
                "fut_ports": fut_ports,
                "fut_host": fut_host,
            }

        for ip, info in futures.items():
            print(f"    Scanning {ip}...")
            open_ports = info["fut_ports"].result()
            hostname = info["fut_host"].result()
            vendor, dev_hint = oui_lookup(info["mac"])
            is_gw = (ip == gateway_ip)
            device_type = infer_device_type(open_ports, vendor, dev_hint, is_gw)

            # Only include hosts that responded meaningfully during detail collection
            # Exclude hosts with no hostname, no open ports, and no MAC (silent responders)
            has_meaningful_response = (
                hostname is not None or
                len(open_ports) > 0 or
                info["mac"] != "Unknown"
            )
            
            if has_meaningful_response:
                hosts_data.append({
                    "ip": ip,
                    "mac": info["mac"],
                    "hostname": hostname,
                    "open_ports": open_ports,
                    "vendor": vendor,
                    "device_type": device_type,
                    "is_gateway": is_gw,
                    "discovered_via": info["via"],
                })
                print(f"      Hostname: {hostname or 'N/A'}")
                print(f"      Type: {device_type}")
                print(f"      Open Ports: {open_ports}")
                print(f"      -> Included in topology")
            else:
                print(f"      Hostname: N/A, Ports: none, MAC: unknown")
                print(f"      -> Excluded from topology (no meaningful response)")

    # --- Step 5: Generate topology map ---
    print(f"\n[*] Step 5: Generating topology map...")
    output_file = "network_map.html"
    build_topology(hosts_data, gateway_ip, output_file)

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  Scan Complete!")
    print("=" * 60)
    print(f"  Total hosts discovered: {len(hosts_data)}")
    print(f"  Gateway: {gateway_ip or 'N/A'}")
    print(f"  Output:  {os.path.abspath(output_file)}")
    print("\nOpen 'network_map.html' in a web browser to view the topology.")


if __name__ == "__main__":
    main()
