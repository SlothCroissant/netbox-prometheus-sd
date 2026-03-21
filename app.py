import os
import logging
from flask import Flask, jsonify
import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NETBOX_URL = os.environ.get("NETBOX_URL") or os.environ["netbox_url"]
NETBOX_API_KEY = os.environ.get("NETBOX_API_KEY") or os.environ.get("netbox_api_key", "")
NETBOX_API_TOKEN = os.environ.get("NETBOX_API_TOKEN") or os.environ.get("netbox_api_token", "")
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() == "true"

# Build auth header: v2 uses "Bearer nbt_<key>.<token>", v1 uses "Token <key>"
if NETBOX_API_KEY and NETBOX_API_TOKEN:
    AUTH_HEADER = f"Bearer nbt_{NETBOX_API_KEY}.{NETBOX_API_TOKEN}"
else:
    AUTH_HEADER = f"Token {NETBOX_API_KEY or NETBOX_API_TOKEN}"

logger.info("Configured for NetBox at %s (SSL verify: %s)", NETBOX_URL, VERIFY_SSL)


@app.errorhandler(RequestException)
def handle_netbox_error(e):
    """Return a clear error when NetBox API calls fail."""
    status = getattr(e.response, "status_code", 502) if hasattr(e, "response") else 502
    detail = getattr(e.response, "text", str(e))[:200] if hasattr(e, "response") and e.response is not None else str(e)
    logger.error("NetBox API error: %s", detail)
    return jsonify({"error": "NetBox API request failed", "detail": detail}), status


def fetch_all_ip_addresses():
    """Fetch all IP addresses from NetBox, handling pagination."""
    headers = {"Authorization": AUTH_HEADER, "Accept": "application/json"}
    url = urljoin(NETBOX_URL.rstrip("/") + "/", "api/ipam/ip-addresses/")
    results = []
    params = {"limit": 1000}

    while url:
        resp = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("results", []))
        url = data.get("next")
        params = None  # next URL already includes params

    return results


def build_labels(ip_entry):
    """Build common Prometheus labels from a NetBox IP address entry."""
    address = ip_entry.get("address", "").split("/")[0]  # strip CIDR notation
    labels = {"__address__": address}

    if ip_entry.get("dns_name"):
        labels["dns_name"] = ip_entry["dns_name"]

    if ip_entry.get("description"):
        labels["description"] = ip_entry["description"]

    assigned = ip_entry.get("assigned_object")
    if assigned:
        if assigned.get("display"):
            labels["interface"] = assigned["display"]
        device = assigned.get("device") or assigned.get("virtual_machine")
        if device and device.get("display"):
            labels["device"] = device["display"]

    status = ip_entry.get("status")
    if status:
        labels["status"] = status.get("value", str(status)) if isinstance(status, dict) else str(status)

    return labels


@app.route("/icmp")
def icmp_targets():
    """Return targets for ICMP (ping) probing."""
    ip_addresses = fetch_all_ip_addresses()
    targets = []

    for entry in ip_addresses:
        cf = entry.get("custom_fields", {})
        if cf.get("blackbox_icmp") is True:
            labels = build_labels(entry)
            targets.append({"targets": [labels["__address__"]], "labels": labels})

    return jsonify(targets)


@app.route("/dns")
def dns_targets():
    """Return targets for DNS probing."""
    ip_addresses = fetch_all_ip_addresses()
    targets = []

    for entry in ip_addresses:
        cf = entry.get("custom_fields", {})
        if cf.get("blackbox_dns") is True:
            labels = build_labels(entry)
            targets.append({"targets": [labels["__address__"]], "labels": labels})

    return jsonify(targets)


@app.route("/tcp")
def tcp_targets():
    """Return targets for TCP probing — one target per IP:port combination."""
    ip_addresses = fetch_all_ip_addresses()
    targets = []

    for entry in ip_addresses:
        cf = entry.get("custom_fields", {})
        raw_ports = cf.get("blackbox_tcp_ports")
        if not raw_ports:
            continue
        if isinstance(raw_ports, str):
            ports = [p.strip() for p in raw_ports.split(",") if p.strip()]
        elif isinstance(raw_ports, list):
            ports = [str(p).strip() for p in raw_ports if str(p).strip()]
        else:
            continue
        if ports:
            base_labels = build_labels(entry)
            address = base_labels["__address__"]
            for port in ports:
                labels = dict(base_labels)
                labels["__address__"] = f"{address}:{port}"
                labels["port"] = str(port)
                targets.append({"targets": [f"{address}:{port}"], "labels": labels})

    return jsonify(targets)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)  # nosec B104
