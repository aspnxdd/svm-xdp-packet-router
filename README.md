# svm-xdp-packet-router

Rust + eBPF/XDP prototype for inspecting UDP packets sent to port `8001`.

The XDP program runs in the kernel, parses packet headers, logs pshred packet data through BPF maps, and drops malformed pshred packets.

<img width="1522" height="753" alt="image" src="https://github.com/user-attachments/assets/46eb2257-6619-4ea3-a20a-f60e6c1263a0" />


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
- Parsed pshred fields.
- Source ID.
- First 128 raw packet bytes.

It also prints `DROP_COUNTER` every 5 seconds.
