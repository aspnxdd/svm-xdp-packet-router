# svm-xdp-packet-router

Rust + eBPF/XDP prototype for inspecting UDP packets sent to port `8001`.

The XDP program runs in the kernel, parses packet headers, logs pshred packet data through BPF maps, and drops malformed pshred packets.

## What It Does

- Attaches an XDP program to `lo`.
- Parses Ethernet, IPv4, UDP, and `PshredHeader`.
- Ignores packets that are not UDP destination port `8001`.
- Drops malformed or invalid pshred packets.
- Logs packet metadata and the first 128 raw packet bytes through a BPF map.
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

## Send A Test Packet

This sends a valid padded `PshredHeader` payload to UDP port `8001`:

```bash
./send_udp.sh 127.0.0.1 8001 "01 00 00 00 11 11 11 11"
```

```bash
printf '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11' | nc -u -w1 127.0.0.1 8001
```

This sends malformed pshred data and should be logged as `DROP`:

```bash
echo "hello" | nc -u -w1 127.0.0.1 8001
```

## Logs

The userspace loader prints packet log events for UDP destination port `8001` only.

Each packet log includes:

- XDP action.
- Source IP and UDP port.
- Destination UDP port.
- Parsed pshred fields.
- Source ID.
- First 128 raw packet bytes.

It also prints `DROP_COUNTER` every 5 seconds.
