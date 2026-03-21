# NetBox Prometheus Service Discovery

A lightweight HTTP service discovery provider for [Prometheus](https://prometheus.io/) that sources targets from [NetBox](https://netbox.dev/). Designed to feed [Blackbox Exporter](https://github.com/prometheus/blackbox_exporter) with ICMP, DNS, and TCP probe targets based on NetBox IP address custom fields.

## How It Works

The app queries the NetBox IPAM API for all IP addresses and exposes them as Prometheus HTTP SD-compatible JSON endpoints. Each IP address is included on an endpoint based on its custom fields:

| Endpoint | NetBox Custom Field | Description |
|----------|---------------------|-------------|
| `/icmp`  | `blackbox_icmp` (boolean) | IP addresses to ping |
| `/dns`   | `blackbox_dns` (boolean) | IP addresses for DNS probing |
| `/tcp`   | `blackbox_tcp_ports` (string/list) | IP addresses for TCP probing, one target per port |
| `/health` | — | Health check endpoint |

Each target includes labels for `dns_name`, `description`, `interface`, `device`, and `status` when available in NetBox.

## NetBox Custom Fields

Create the following custom fields on the **IP Address** object type in NetBox:

| Name | Type | Description |
|------|------|-------------|
| `blackbox_icmp` | Boolean | Enable ICMP ping monitoring |
| `blackbox_dns` | Boolean | Enable DNS probe monitoring |
| `blackbox_tcp_ports` | Text / List | Comma-separated TCP ports to monitor (e.g. `80,443`) |

## Configuration

The app is configured via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NETBOX_URL` | Yes | — | Base URL of your NetBox instance |
| `NETBOX_API_KEY` | Yes* | — | NetBox API key (v1: token, v2: key portion of `nbt_<key>.<token>`) |
| `NETBOX_API_TOKEN` | No* | — | NetBox API token (v2 only: token portion of `nbt_<key>.<token>`) |
| `VERIFY_SSL` | No | `true` | Set to `false` to skip SSL certificate verification |

\* For NetBox v2+ API tokens (`nbt_` prefix), provide both `NETBOX_API_KEY` and `NETBOX_API_TOKEN`. For legacy v1 tokens, only `NETBOX_API_KEY` is needed.

## Running with Docker

### Docker Compose (recommended)

1. Create a `.env` file with your NetBox credentials:

   ```env
   NETBOX_URL=https://netbox.example.com
   NETBOX_API_KEY=your_api_key
   NETBOX_API_TOKEN=your_api_token
   ```

2. Create a `docker-compose.yml`:

   ```yaml
   services:
     netbox-prometheus-sd:
       image: ghcr.io/slothcroissant/netbox-prometheus-sd:latest
       ports:
         - "8080:8080"
       env_file:
         - .env
       environment:
         VERIFY_SSL: "true"
       restart: unless-stopped
   ```

3. Start the container:

   ```bash
   docker compose up -d
   ```

### Docker Run

```bash
docker run -d \
  -p 8080:8080 \
  -e NETBOX_URL=https://netbox.example.com \
  -e NETBOX_API_KEY=your_api_key \
  -e NETBOX_API_TOKEN=your_api_token \
  -e VERIFY_SSL=true \
  --restart unless-stopped \
  ghcr.io/slothcroissant/netbox-prometheus-sd:latest
```

## Prometheus Configuration

Add HTTP service discovery targets to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: blackbox_icmp
    metrics_path: /probe
    params:
      module: [icmp]
    http_sd_configs:
      - url: http://netbox-prometheus-sd:8080/icmp
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

  - job_name: blackbox_dns
    metrics_path: /probe
    params:
      module: [dns]
    http_sd_configs:
      - url: http://netbox-prometheus-sd:8080/dns
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

  - job_name: blackbox_tcp
    metrics_path: /probe
    params:
      module: [tcp_connect]
    http_sd_configs:
      - url: http://netbox-prometheus-sd:8080/tcp
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

## Building from Source

```bash
git clone https://github.com/SlothCroissant/netbox-prometheus-sd.git
cd netbox-prometheus-sd
docker build -t netbox-prometheus-sd .
```

## License

See repository for license details.
