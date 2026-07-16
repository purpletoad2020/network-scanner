#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner — Web GUI
=========================
Flask web application that wraps scan.py to provide a browser-based
interface for selecting the network interface, defining the subnet,
triggering scans, and viewing the interactive topology map.
"""

import json
import os
import sys
import threading
import uuid
from pathlib import Path

# Add current directory to path so we can import scan
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template, request, jsonify, send_from_directory,
)

# ---------------------------------------------------------------------------
# Import scanner functions from scan.py
# ---------------------------------------------------------------------------
from scan import (
    detect_interfaces,
    arp_scan,
    socket_arp_scan,
    icmp_ping_sweep,
    scan_ports,
    resolve_hostname,
    find_gateway,
    infer_device_type,
    oui_lookup,
    build_topology,
    COMMON_PORTS,
    SCAPY_AVAILABLE,
    PYVIS_AVAILABLE,
)

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()

# Store scan results / status in memory (simple key-value)
SCANS: dict[str, dict] = {}
SCANS_LOCK = threading.Lock()

OUTPUT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Serve the main web GUI."""
    return render_template("index.html")


@app.route("/api/interfaces")
def api_interfaces():
    """Return a list of detected network interfaces as JSON."""
    try:
        interfaces = detect_interfaces()
        # Filter out loopback, keep only relevant fields
        result = []
        for i, iface in enumerate(interfaces):
            net = iface["network"]
            if "loopback" in iface["name"].lower() or iface["name"].startswith("lo"):
                continue
            result.append({
                "index": i,
                "name": iface["name"],
                "ip": iface["ip"],
                "netmask": iface["netmask"],
                "network": str(net),
                "prefixlen": net.prefixlen,
                "mac": iface["mac"],
            })
        return jsonify({"status": "ok", "interfaces": result})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Start a scan job.  Returns a job ID to poll for status."""
    data = request.get_json(force=True)
    interface_name = data.get("interface", "")
    subnet_str = data.get("subnet", "")
    custom_ports_str = data.get("ports", "")

    import ipaddress

    # Parse subnet
    try:
        subnet = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as exc:
        return jsonify({"status": "error", "message": f"Invalid subnet: {exc}"}), 400

    # Parse custom ports
    ports = COMMON_PORTS
    if custom_ports_str.strip():
        try:
            ports = [int(p.strip()) for p in custom_ports_str.split(",") if p.strip()]
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid port list"}), 400

    # Create job and start background thread
    job_id = uuid.uuid4().hex[:12]
    with SCANS_LOCK:
        SCANS[job_id] = {
            "status": "starting",
            "progress": 0,
            "message": "Initialising scan...",
            "result": None,
            "map_file": None,
            "job_id": job_id,
            "total_hosts": 0,
        }

    thread = threading.Thread(
        target=_run_scan,
        args=(job_id, interface_name, subnet, ports),
        daemon=True,
    )
    thread.start()

    return jsonify({"status": "ok", "job_id": job_id})


@app.route("/api/scan/<job_id>")
def api_scan_status(job_id):
    """Poll scan job progress."""
    with SCANS_LOCK:
        job = SCANS.get(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Unknown job ID"}), 404
    return jsonify(job)


@app.route("/map/<job_id>")
def serve_map(job_id):
    """Serve the generated topology map for a completed scan."""
    map_file = f"network_map_{job_id}.html"
    return send_from_directory(OUTPUT_DIR, map_file)


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------
def _run_scan(job_id: str, interface_name: str,
              subnet, ports: list[int]):
    """Run the full scan pipeline in a background thread."""
    def _update(status: str, progress: int, message: str, **kwargs):
        with SCANS_LOCK:
            SCANS[job_id].update({
                "status": status,
                "progress": progress,
                "message": message,
                "job_id": job_id,
                **kwargs,
            })

    try:
        # Step 1: Interface info
        _update("running", 5, "Detecting network interfaces...")
        interfaces = detect_interfaces()
        if not interfaces:
            _update("failed", 0, "No network interfaces found.")
            return

        # Step 2: Host discovery
        _update("running", 15, f"Scanning {subnet} for live hosts...")

        # ARP scan
        arp_results = arp_scan(subnet, interface_name)
        found_ips = {r["ip"] for r in arp_results}

        if not arp_results:
            _update("running", 25, "ARP found nothing. Falling back to socket scan...")
            arp_results = socket_arp_scan(subnet)
            for r in arp_results:
                r.setdefault("via", "TCP-Socket")
            found_ips = {r["ip"] for r in arp_results}
        else:
            for r in arp_results:
                r.setdefault("via", "ARP")

        total_discovered = len(arp_results)
        _update("running", 30, f"Discovered {total_discovered} hosts. Collecting details...")

        if total_discovered == 0:
            _update("completed", 100, "No hosts discovered.", total_hosts=0)
            return

        # Step 3: Gateway detection
        _update("running", 35, "Identifying gateway...")
        gateway_ip = find_gateway(interfaces)

        # Step 4: Port scan + hostname (sequential to avoid overwhelming)
        hosts_data = []
        processed = 0

        for host in arp_results:
            ip = host["ip"]
            mac = host.get("mac", "Unknown")
            via = host.get("via", "ARP")

            _update("running", 35 + int(50 * processed / total_discovered),
                    f"Scanning {ip} ({processed + 1}/{total_discovered})...")

            open_ports = scan_ports(ip, ports)
            hostname = resolve_hostname(ip)
            vendor, dev_hint = oui_lookup(mac)
            is_gw = (ip == gateway_ip)
            device_type = infer_device_type(open_ports, vendor, dev_hint, is_gw)

            has_meaningful_response = True  # Always include ARP-discovered hosts

            hosts_data.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname if hostname else "",
                "open_ports": open_ports,
                "vendor": vendor,
                "device_type": device_type,
                "is_gateway": is_gw,
                "discovered_via": via,
            })

            processed += 1

        _update("running", 90, f"Generating topology map ({len(hosts_data)} hosts)...")

        # Step 5: Build topology map
        map_file = f"network_map_{job_id}.html"
        build_topology(hosts_data, gateway_ip, map_file)

        # Build result summary
        summary = []
        for h in hosts_data:
            ports_str = ", ".join(
                f"{p}" for p in sorted(h["open_ports"].keys())
            ) or "none"
            summary.append({
                "ip": h["ip"],
                "hostname": h["hostname"] or "—",
                "mac": h["mac"],
                "type": h["device_type"],
                "vendor": h["vendor"],
                "ports": ports_str,
                "gateway": h["is_gateway"],
            })

        _update("completed", 100,
                f"Scan complete: {len(hosts_data)} hosts mapped.",
                result=summary,
                map_file=map_file,
                total_hosts=len(hosts_data),
                gateway=gateway_ip)

    except Exception as exc:
        _update("failed", 0, f"Scan error: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  Network Scanner — Web GUI")
    print("=" * 50)
    print(f"  Open http://localhost:5000 in your browser")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=False)