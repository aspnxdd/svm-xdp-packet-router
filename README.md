# svm-xdp-packet-router

Rust + eBPF/XDP prototype for inspecting and routing UDP packets sent to port `8001`.

The XDP program runs in the kernel, parses packet headers, logs Shred packet data through BPF maps, tracks per-IP telemetry, and drops malformed Shred packets with reason counters.

<img width="1522" height="753" alt="image" src="https://github.com/user-attachments/assets/46eb2257-6619-4ea3-a20a-f60e6c1263a0" />


## What It Does

- Attaches an XDP program to `lo`.
- Parses Ethernet, IPv4, UDP, and `Shred`.
- Ignores packets that are not UDP destination port `8001`.
- Drops malformed or invalid pshred packets.
- Logs packet metadata and the first 128 raw packet bytes through a BPF map.
- Tracks per-IP packets, bytes, drops, redirects, and last-seen time in an eBPF map.
- Tracks reason-specific drop counters.
- Reads and prints a per-CPU drop counter from userspace.

## Project Layout

| Path                            | Purpose                           |
| ------------------------------- | --------------------------------- |
| `svm-xdp-packet-router/`        | Userspace loader                  |
| `svm-xdp-packet-router-ebpf/`   | XDP/eBPF program                  |
| `svm-xdp-packet-router-common/` | Shared structs used by both sides |

## Requirements

- Linux.
- Rust stable.
- Rust nightly with `rust-src`.
- `bpf-linker`.
- Root or the required BPF/network capabilities.

## Setup

```bash
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

## Run

```bash
cargo run
```

The project currently runs through `sudo -E` from `.cargo/config.toml`.

To expose Prometheus metrics while the XDP program is attached:

```bash
cargo run -- metrics :9090
```

Then scrape:

```bash
curl http://127.0.0.1:9090/metrics
```

## Local Grafana

Run the XDP exporter on the host:

```bash
cargo run -- metrics :9090
```

In another terminal, start Prometheus and Grafana:

```bash
docker compose up -d
```

Open:

- Grafana: http://127.0.0.1:3000
- Prometheus: http://127.0.0.1:9091

Grafana is provisioned automatically with a Prometheus datasource and the `SVM XDP Packet Router` dashboard.

Prometheus scrapes the host exporter through `host.docker.internal:9090`. The Compose file maps this name to Docker's host gateway for Linux.

Stop the UI stack with:

```bash
docker compose down
```

## Send A Test Packet

This sends malformed pshred data and should be logged as `DROP`:

```bash
./send_udp.sh 127.0.0.1 8001 "01 00 00 00 11 11 11 11"
```

This sends a valid padded `Shred` payload to UDP port `8001`:

```bash
./send_udp.sh 127.0.0.1 8001 "$(npx tsx scripts/src/send_random_shreds.ts)"
```

## Logs

The userspace loader prints packet log events for UDP destination port `8001` only.

Each packet log includes:

- XDP action.
- Source IP and UDP port.
- Destination UDP port.
- Drop reason.
- Parsed pshred fields.
- Source ID.
- First 128 raw packet bytes.

It also prints `DROP_COUNTER` every 5 seconds.

## Metrics

The `metrics` command exposes Prometheus text format metrics:

- `svm_xdp_packets_total`
- `svm_xdp_bytes_total`
- `svm_xdp_redirects_total`
- `svm_xdp_drops_total{reason="missing_shred"}`
- `svm_xdp_per_ip_packets{ip="127.0.0.1"}`
- `svm_xdp_per_ip_bytes{ip="127.0.0.1"}`
- `svm_xdp_per_ip_drops{ip="127.0.0.1"}`
- `svm_xdp_per_ip_redirects{ip="127.0.0.1"}`
- `svm_xdp_per_ip_last_seen_ns{ip="127.0.0.1"}`

## Articles about EBPF/XDP:

- https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust
- https://www.kernel.org/doc/html/latest/networking/af_xdp.html
- https://medium.com/@stevelatif/aya-rust-tutorial-part-5-using-maps-4d26c4a2fff8
- https://docs.cilium.io/en/latest/reference-guides/bpf/architecture/
