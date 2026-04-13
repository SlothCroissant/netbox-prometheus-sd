import os
import logging
import time
from flask import Flask, jsonify, request, g
import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin

app = Flask(__name__)
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

NETBOX_URL = os.environ.get("NETBOX_URL") or os.environ["netbox_url"]
NETBOX_API_KEY = os.environ.get("NETBOX_API_KEY") or os.environ.get("netbox_api_key", "")
NETBOX_API_TOKEN = os.environ.get("NETBOX_API_TOKEN") or os.environ.get("netbox_api_token", "")
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() == "true"

# Build auth header: v2 uses "Bearer nbt_<key>.<token>", v1 uses "Token <key>"
if NETBOX_API_KEY and NETBOX_API_TOKEN:
    AUTH_HEADER = f"Bearer nbt_{NETBOX_API_KEY}.{NETBOX_API_TOKEN}"
    logger.info("Using v2 Bearer token authentication")
else:
    AUTH_HEADER = f"Token {NETBOX_API_KEY or NETBOX_API_TOKEN}"
    logger.info("Using v1 Token authentication")

logger.info("Configured for NetBox at %s (SSL verify: %s)", NETBOX_URL, VERIFY_SSL)


@app.before_request
def log_request_start():
    g.start_time = time.time()
    logger.info("Request started: %s %s (args: %s)", request.method, request.path, dict(request.args))


@app.after_request
def log_request_end(response):
    duration = time.time() - getattr(g, "start_time", time.time())
    logger.info(
        "Request completed: %s %s -> %s (%.3fs)",
        request.method, request.path, response.status_code, duration,
    )
    return response


@app.errorhandler(RequestException)
def handle_netbox_error(e):
    """Return a clear error when NetBox API calls fail."""
    status = getattr(e.response, "status_code", 502) if hasattr(e, "response") else 502
    detail = getattr(e.response, "text", str(e))[:200] if hasattr(e, "response") and e.response is not None else str(e)
    logger.error("NetBox API error (status=%s): %s", status, detail)
    logger.debug("Full exception: %r", e)
    return jsonify({"error": "NetBox API request failed", "detail": detail}), status


def _netbox_request(method, url, params=None, timeout=30):
    """Make an authenticated request to NetBox with request/response logging."""
    headers = {"Authorization": AUTH_HEADER, "Accept": "application/json"}
    logger.info("NetBox API request: %s %s params=%s", method.upper(), url, params)
    resp = requests.request(method, url, headers=headers, params=params, verify=VERIFY_SSL, timeout=timeout)
    logger.info(
        "NetBox API response: %s %s -> %d (%d bytes)",
        method.upper(), url, resp.status_code, len(resp.content),
    )
    logger.debug("NetBox API response body: %.2000s", resp.text)
    return resp


def fetch_all_ip_addresses():
    """Fetch all IP addresses from NetBox, handling pagination."""
    url = urljoin(NETBOX_URL.rstrip("/") + "/", "api/ipam/ip-addresses/")
    results = []
    params = {"limit": 1000}
    page = 1

    logger.info("Fetching all IP addresses from NetBox")
    while url:
        resp = _netbox_request("GET", url, params=params)
        resp.raise_for_status()
        data = resp.json()
        page_results = data.get("results", [])
        results.extend(page_results)
        logger.debug("Page %d returned %d results (total so far: %d)", page, len(page_results), len(results))
        url = data.get("next")
        params = None  # next URL already includes params
        page += 1

    logger.info("Fetched %d total IP addresses from NetBox", len(results))
    return results


def build_labels(ip_entry):
    """Build common Prometheus labels from a NetBox IP address entry."""
    address = ip_entry.get("address", "").split("/")[0]  # strip CIDR notation
    labels = {"__address__": address}
    logger.debug("Building labels for IP %s (id=%s)", address, ip_entry.get("id"))

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
    else:
        logger.debug("IP %s has no assigned object", address)

    status = ip_entry.get("status")
    if status:
        labels["status"] = status.get("value", str(status)) if isinstance(status, dict) else str(status)

    logger.debug("Labels for IP %s: %s", address, labels)
    return labels


@app.route("/icmp")
def icmp_targets():
    """Return targets for ICMP (ping) probing."""
    logger.info("Processing /icmp request")
    ip_addresses = fetch_all_ip_addresses()
    targets = []
    skipped = 0

    for entry in ip_addresses:
        cf = entry.get("custom_fields", {})
        if cf.get("blackbox_icmp") is True:
            labels = build_labels(entry)
            targets.append({"targets": [labels["__address__"]], "labels": labels})
            logger.debug("ICMP target added: %s", labels["__address__"])
        else:
            skipped += 1

    logger.info("/icmp returning %d targets (%d IPs skipped)", len(targets), skipped)
    return jsonify(targets)


@app.route("/dns")
def dns_targets():
    """Return targets for DNS probing."""
    logger.info("Processing /dns request")
    ip_addresses = fetch_all_ip_addresses()
    targets = []
    skipped = 0

    for entry in ip_addresses:
        cf = entry.get("custom_fields", {})
        if cf.get("blackbox_dns") is True:
            labels = build_labels(entry)
            targets.append({"targets": [labels["__address__"]], "labels": labels})
            logger.debug("DNS target added: %s", labels["__address__"])
        else:
            skipped += 1

    logger.info("/dns returning %d targets (%d IPs skipped)", len(targets), skipped)
    return jsonify(targets)


@app.route("/tcp")
def tcp_targets():
    """Return targets for TCP probing — one target per IP:port combination."""
    logger.info("Processing /tcp request")
    ip_addresses = fetch_all_ip_addresses()
    targets = []
    skipped = 0

    for entry in ip_addresses:
        cf = entry.get("custom_fields", {})
        raw_ports = cf.get("blackbox_tcp_ports")
        if not raw_ports:
            skipped += 1
            continue
        logger.debug("IP %s has blackbox_tcp_ports: %r", entry.get("address"), raw_ports)
        if isinstance(raw_ports, str):
            ports = [p.strip() for p in raw_ports.split(",") if p.strip()]
        elif isinstance(raw_ports, list):
            ports = [str(p).strip() for p in raw_ports if str(p).strip()]
        else:
            logger.warning("Unexpected type for blackbox_tcp_ports on IP %s: %s", entry.get("address"), type(raw_ports).__name__)
            continue
        if ports:
            base_labels = build_labels(entry)
            address = base_labels["__address__"]
            logger.debug("TCP target %s: ports %s", address, ports)
            for port in ports:
                labels = dict(base_labels)
                labels["__address__"] = f"{address}:{port}"
                labels["port"] = str(port)
                targets.append({"targets": [f"{address}:{port}"], "labels": labels})

    logger.info("/tcp returning %d targets (%d IPs skipped)", len(targets), skipped)
    return jsonify(targets)


def fetch_devices(params=None):
    """Fetch devices from NetBox, handling pagination."""
    url = urljoin(NETBOX_URL.rstrip("/") + "/", "api/dcim/devices/")
    results = []
    query_params = {"limit": 1000}
    if params:
        query_params.update(params)
    page = 1

    logger.info("Fetching devices from NetBox (filters: %s)", params)
    while url:
        resp = _netbox_request("GET", url, params=query_params)
        resp.raise_for_status()
        data = resp.json()
        page_results = data.get("results", [])
        results.extend(page_results)
        logger.debug("Page %d returned %d devices (total so far: %d)", page, len(page_results), len(results))
        url = data.get("next")
        query_params = None
        page += 1

    logger.info("Fetched %d total devices from NetBox", len(results))
    return results


def fetch_device_type_ids(manufacturer=None, model=None):
    """Search device types by manufacturer and/or model keyword, return matching IDs."""
    url = urljoin(NETBOX_URL.rstrip("/") + "/", "api/dcim/device-types/")
    params = {"limit": 1000}
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["q"] = model
    page = 1

    logger.info("Fetching device type IDs (manufacturer=%s, model=%s)", manufacturer, model)
    results = []
    while url:
        resp = _netbox_request("GET", url, params=params)
        resp.raise_for_status()
        data = resp.json()
        page_results = data.get("results", [])
        results.extend(page_results)
        logger.debug("Page %d returned %d device types (total so far: %d)", page, len(page_results), len(results))
        url = data.get("next")
        params = None
        page += 1

    ids = [dt["id"] for dt in results]
    logger.info("Found %d matching device type IDs: %s", len(ids), ids)
    return ids


def build_device_labels(device):
    """Build Prometheus labels from a NetBox device entry."""
    primary_ip = device.get("primary_ip") or device.get("primary_ip4") or device.get("primary_ip6")
    address = primary_ip["address"].split("/")[0] if primary_ip else device.get("name", "")
    if not primary_ip:
        logger.warning("Device %s (id=%s) has no primary IP, using name as address", device.get("name"), device.get("id"))

    labels = {"__address__": address}
    logger.debug("Building labels for device %s (id=%s, address=%s)", device.get("name"), device.get("id"), address)

    if device.get("name"):
        labels["device"] = device["name"]

    dt = device.get("device_type") or {}
    if dt.get("model"):
        labels["model"] = dt["model"]
    mfr = dt.get("manufacturer") or {}
    if mfr.get("name"):
        labels["manufacturer"] = mfr["name"]

    site = device.get("site") or {}
    if site.get("name"):
        labels["site"] = site["name"]

    role = device.get("role") or {}
    if role.get("name"):
        labels["role"] = role["name"]

    status = device.get("status")
    if status:
        labels["status"] = status.get("value", str(status)) if isinstance(status, dict) else str(status)

    if device.get("serial"):
        labels["serial"] = device["serial"]

    logger.debug("Labels for device %s: %s", device.get("name"), labels)
    return labels


@app.route("/devices")
def device_targets():
    """Return Prometheus SD targets for devices.

    Query parameters:
      manufacturer  – manufacturer slug (e.g. "cisco")
      device_type   – exact device-type slug (e.g. "cisco-ws-c3850-48p")
      model         – keyword search across device-type models (e.g. "3850")
    """
    manufacturer = request.args.get("manufacturer")
    device_type = request.args.get("device_type")
    model = request.args.get("model")

    logger.info("Processing /devices request (manufacturer=%s, device_type=%s, model=%s)", manufacturer, device_type, model)

    params = {}
    if manufacturer:
        params["manufacturer"] = manufacturer

    if device_type:
        params["device_type"] = device_type
    elif model:
        dt_ids = fetch_device_type_ids(manufacturer=manufacturer, model=model)
        if not dt_ids:
            logger.info("/devices returning 0 targets (no matching device types found)")
            return jsonify([])
        params["device_type_id"] = dt_ids

    devices = fetch_devices(params)
    targets = []

    for device in devices:
        labels = build_device_labels(device)
        targets.append({"targets": [labels["__address__"]], "labels": labels})

    logger.info("/devices returning %d targets", len(targets))
    return jsonify(targets)


@app.route("/health")
def health():
    """Ping NetBox API to validate connectivity."""
    logger.info("Processing /health request")
    url = urljoin(NETBOX_URL.rstrip("/") + "/", "api/status/")
    try:
        resp = _netbox_request("GET", url, timeout=10)
        resp.raise_for_status()
        logger.info("Health check passed: NetBox reachable")
        return jsonify({"status": "ok", "netbox": "reachable"}), 200
    except RequestException as e:
        detail = str(e)[:200]
        logger.error("Health check failed: %s", detail)
        logger.debug("Health check full exception: %r", e)
        return jsonify({"status": "error", "netbox": "unreachable", "detail": detail}), 503


if __name__ == "__main__":
    logger.info("Starting netbox-prometheus-sd on 0.0.0.0:9099")
    app.run(host="0.0.0.0", port=9099)  # nosec B104
