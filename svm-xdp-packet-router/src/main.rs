use anyhow::Context;
use aya::{
    Ebpf,
    maps::{HashMap as AyaHashMap, MapData, PerCpuArray, PerfEventArray, perf::PerfEvent},
    programs::{Xdp, XdpMode},
    util::online_cpus,
};
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::{
    fmt::Write as _,
    mem::size_of,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use svm_xdp_packet_router_common::{IpStats, PacketLogEntry, action, drop_reason};
use tokio::{io::AsyncWriteExt, net::TcpListener, signal};

#[derive(Parser, Debug)]
#[command(about = "SVM XDP packet router")]
struct Cli {
    #[arg(long, default_value = "lo")]
    iface: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Metrics {
        #[arg(default_value = ":9090")]
        addr: String,
    },
}

struct MetricsMaps {
    drop_counter: PerCpuArray<MapData, u64>,
    drop_reasons: PerCpuArray<MapData, u64>,
    ip_stats: AyaHashMap<MapData, u32, IpStats>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    remove_memlock_limit();

    let ebpf = load_ebpf()?;

    match cli.command {
        Some(Command::Metrics { addr }) => run_metrics(ebpf, &cli.iface, &addr).await,
        None => run_default(ebpf, &cli.iface).await,
    }
}

fn remove_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!(
            "failed to remove locked-memory limit: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn load_ebpf() -> anyhow::Result<Ebpf> {
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/svm-xdp-packet-router"
    )))?)
}

async fn run_default(mut ebpf: Ebpf, iface: &str) -> anyhow::Result<()> {
    spawn_packet_log_reader(&mut ebpf)?;
    spawn_drop_counter_reader(&mut ebpf)?;
    load_and_attach(&mut ebpf, iface)?;

    info!("XDP attached to {iface}; listening on UDP port 8001");

    signal::ctrl_c().await?;
    info!("Detaching...");
    Ok(())
}

async fn run_metrics(mut ebpf: Ebpf, iface: &str, addr: &str) -> anyhow::Result<()> {
    spawn_packet_log_reader(&mut ebpf)?;
    let metrics = take_metrics_maps(&mut ebpf)?;
    load_and_attach(&mut ebpf, iface)?;

    let addr = parse_metrics_addr(addr)?;
    info!("XDP attached to {iface}; serving Prometheus metrics on http://{addr}/metrics");

    tokio::select! {
        result = serve_metrics(addr, metrics) => result,
        signal = signal::ctrl_c() => {
            signal?;
            info!("Detaching...");
            Ok(())
        }
    }
}

fn load_and_attach(ebpf: &mut Ebpf, iface: &str) -> anyhow::Result<()> {
    let program: &mut Xdp = ebpf
        .program_mut("svm_xdp_packet_router")
        .unwrap()
        .try_into()?;

    program.load().context("failed to load XDP program")?;
    program
        .attach(iface, XdpMode::default())
        .with_context(|| format!("failed to attach XDP program to {iface}"))?;

    Ok(())
}

fn take_metrics_maps(ebpf: &mut Ebpf) -> anyhow::Result<MetricsMaps> {
    let drop_counter_map = ebpf
        .take_map("DROP_COUNTER")
        .ok_or_else(|| anyhow::anyhow!("DROP_COUNTER map not found"))?;
    let drop_counter = PerCpuArray::<MapData, u64>::try_from(drop_counter_map)?;

    let drop_reasons_map = ebpf
        .take_map("DROP_REASONS")
        .ok_or_else(|| anyhow::anyhow!("DROP_REASONS map not found"))?;
    let drop_reasons = PerCpuArray::<MapData, u64>::try_from(drop_reasons_map)?;

    let ip_stats_map = ebpf
        .take_map("IP_STATS")
        .ok_or_else(|| anyhow::anyhow!("IP_STATS map not found"))?;
    let ip_stats = AyaHashMap::<MapData, u32, IpStats>::try_from(ip_stats_map)?;

    Ok(MetricsMaps {
        drop_counter,
        drop_reasons,
        ip_stats,
    })
}

fn spawn_packet_log_reader(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let packet_log_map = ebpf
        .take_map("PACKET_LOG")
        .ok_or_else(|| anyhow::anyhow!("PACKET_LOG map not found"))?;
    let mut packet_logs = PerfEventArray::try_from(packet_log_map)?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let packet_log_buffer = packet_logs.open(cpu_id, None)?;
        let mut packet_log_buffer = tokio::io::unix::AsyncFd::with_interest(
            packet_log_buffer,
            tokio::io::Interest::READABLE,
        )?;

        tokio::task::spawn(async move {
            loop {
                let Ok(mut guard) = packet_log_buffer.readable_mut().await else {
                    break;
                };

                guard.get_inner_mut().for_each(|event| match event {
                    PerfEvent::Sample { head, tail } => log_packet_sample(head, tail),
                    PerfEvent::Lost { count } => {
                        warn!("lost {count} PACKET_LOG events on cpu {cpu_id}");
                    }
                });

                guard.clear_ready();
            }
        });
    }

    Ok(())
}

fn spawn_drop_counter_reader(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let drop_counter_map = ebpf
        .take_map("DROP_COUNTER")
        .ok_or_else(|| anyhow::anyhow!("DROP_COUNTER map not found"))?;
    let drop_counter = PerCpuArray::<_, u64>::try_from(drop_counter_map)?;

    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            match drop_counter.get(&0, 0) {
                Ok(values) => {
                    let total: u64 = values.iter().copied().sum();
                    info!("drop_counter total={} per_cpu={:?}", total, values);
                }
                Err(error) => warn!("failed to read DROP_COUNTER: {error}"),
            }
        }
    });

    Ok(())
}

fn log_packet_sample(head: &[u8], tail: &[u8]) {
    if tail.is_empty() {
        if let Some(entry) = parse_packet_log(head) {
            log_packet_entry(&entry);
        }
        return;
    }

    let mut sample = Vec::with_capacity(head.len() + tail.len());
    sample.extend_from_slice(head);
    sample.extend_from_slice(tail);
    if let Some(entry) = parse_packet_log(&sample) {
        log_packet_entry(&entry);
    }
}

fn parse_packet_log(sample: &[u8]) -> Option<PacketLogEntry> {
    if sample.len() < size_of::<PacketLogEntry>() {
        warn!(
            "PACKET_LOG sample too short: got {} bytes, expected at least {}",
            sample.len(),
            size_of::<PacketLogEntry>()
        );
        return None;
    }

    Some(unsafe { sample.as_ptr().cast::<PacketLogEntry>().read_unaligned() })
}

fn log_packet_entry(entry: &PacketLogEntry) {
    let src_ip = Ipv4Addr::from(u32::from_be(entry.src_ip));
    let raw_len = usize::from(entry.raw_len).min(entry.raw.len());

    info!(
        "packet action={} drop_reason={} cpu={} src={}:{} dst_port={} len={} raw_len={} queue_id={} slot={} proposer_index={} shred_index={} witness_len={} commitment={} proposer_sig={} raw={}",
        action_name(entry.action),
        drop_reason_name(entry.drop_reason),
        entry.cpu,
        src_ip,
        entry.src_port,
        entry.dst_port,
        entry.packet_len,
        entry.raw_len,
        entry.queue_id,
        entry.slot,
        entry.proposer_index,
        entry.shred_index,
        entry.witness_len,
        hex_string(&entry.commitment),
        hex_string(&entry.proposer_sig),
        hex_string(&entry.raw[..raw_len]),
    );
}

fn action_name(value: u32) -> &'static str {
    match value {
        action::ABORTED => "ABORTED",
        action::DROP => "DROP",
        action::PASS => "PASS",
        action::TX => "TX",
        action::REDIRECT => "REDIRECT",
        _ => "UNKNOWN",
    }
}

fn drop_reason_name(value: u32) -> &'static str {
    match value {
        drop_reason::NONE => "none",
        drop_reason::MISSING_SHRED => "missing_shred",
        drop_reason::BAD_WITNESS_LEN => "bad_witness_len",
        drop_reason::BAD_SLOT => "bad_slot",
        _ => "unknown",
    }
}

fn parse_metrics_addr(value: &str) -> anyhow::Result<SocketAddr> {
    let normalized = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else if value.chars().all(|c| c.is_ascii_digit()) {
        format!("0.0.0.0:{value}")
    } else {
        value.to_owned()
    };

    normalized
        .parse()
        .with_context(|| format!("invalid metrics address: {value}"))
}

async fn serve_metrics(addr: SocketAddr, metrics: MetricsMaps) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics listener on {addr}"))?;

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let response = match render_metrics(&metrics) {
            Ok(body) => http_response("200 OK", "text/plain; version=0.0.4", &body),
            Err(error) => {
                warn!("failed to render metrics for {peer}: {error}");
                http_response(
                    "500 Internal Server Error",
                    "text/plain; charset=utf-8",
                    "failed to render metrics\n",
                )
            }
        };

        if let Err(error) = stream.write_all(response.as_bytes()).await {
            warn!("failed to write metrics response to {peer}: {error}");
        }
    }
}

fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn render_metrics(metrics: &MetricsMaps) -> anyhow::Result<String> {
    let drop_total = per_cpu_total(&metrics.drop_counter, 0)?;
    let mut packet_total = 0u64;
    let mut byte_total = 0u64;
    let mut redirect_total = 0u64;
    let mut ip_entries = Vec::new();

    for entry in metrics.ip_stats.iter() {
        let (src_ip, stats) = entry?;
        packet_total += stats.packets;
        byte_total += stats.bytes;
        redirect_total += stats.redirects;
        ip_entries.push((src_ip, stats));
    }

    let mut out = String::new();
    write_metric_header(
        &mut out,
        "svm_xdp_packets_total",
        "Total UDP 8001 packets observed by XDP.",
        "counter",
    );
    let _ = writeln!(out, "svm_xdp_packets_total {packet_total}");

    write_metric_header(
        &mut out,
        "svm_xdp_bytes_total",
        "Total bytes observed for UDP 8001 packets by XDP.",
        "counter",
    );
    let _ = writeln!(out, "svm_xdp_bytes_total {byte_total}");

    write_metric_header(
        &mut out,
        "svm_xdp_redirects_total",
        "Total successful XSK redirects.",
        "counter",
    );
    let _ = writeln!(out, "svm_xdp_redirects_total {redirect_total}");

    write_metric_header(
        &mut out,
        "svm_xdp_drops_total",
        "Total XDP drops, with optional reason labels.",
        "counter",
    );
    let _ = writeln!(out, "svm_xdp_drops_total {drop_total}");
    for reason in 1..drop_reason::COUNT {
        let value = per_cpu_total(&metrics.drop_reasons, reason)?;
        let _ = writeln!(
            out,
            "svm_xdp_drops_total{{reason=\"{}\"}} {value}",
            drop_reason_name(reason)
        );
    }

    write_metric_header(
        &mut out,
        "svm_xdp_per_ip_packets",
        "Per-source-IP UDP 8001 packet count.",
        "counter",
    );
    for (src_ip, stats) in &ip_entries {
        let ip = Ipv4Addr::from(u32::from_be(*src_ip));
        let _ = writeln!(
            out,
            "svm_xdp_per_ip_packets{{ip=\"{ip}\"}} {}",
            stats.packets
        );
    }

    write_metric_header(
        &mut out,
        "svm_xdp_per_ip_bytes",
        "Per-source-IP UDP 8001 byte count.",
        "counter",
    );
    for (src_ip, stats) in &ip_entries {
        let ip = Ipv4Addr::from(u32::from_be(*src_ip));
        let _ = writeln!(out, "svm_xdp_per_ip_bytes{{ip=\"{ip}\"}} {}", stats.bytes);
    }

    write_metric_header(
        &mut out,
        "svm_xdp_per_ip_drops",
        "Per-source-IP UDP 8001 drop count.",
        "counter",
    );
    for (src_ip, stats) in &ip_entries {
        let ip = Ipv4Addr::from(u32::from_be(*src_ip));
        let _ = writeln!(out, "svm_xdp_per_ip_drops{{ip=\"{ip}\"}} {}", stats.drops);
    }

    write_metric_header(
        &mut out,
        "svm_xdp_per_ip_redirects",
        "Per-source-IP successful XSK redirect count.",
        "counter",
    );
    for (src_ip, stats) in &ip_entries {
        let ip = Ipv4Addr::from(u32::from_be(*src_ip));
        let _ = writeln!(
            out,
            "svm_xdp_per_ip_redirects{{ip=\"{ip}\"}} {}",
            stats.redirects
        );
    }

    write_metric_header(
        &mut out,
        "svm_xdp_per_ip_last_seen_ns",
        "Last kernel monotonic timestamp observed for each source IP.",
        "gauge",
    );
    for (src_ip, stats) in &ip_entries {
        let ip = Ipv4Addr::from(u32::from_be(*src_ip));
        let _ = writeln!(
            out,
            "svm_xdp_per_ip_last_seen_ns{{ip=\"{ip}\"}} {}",
            stats.last_seen_ns
        );
    }

    Ok(out)
}

fn write_metric_header(out: &mut String, name: &str, help: &str, metric_type: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
}

fn per_cpu_total(map: &PerCpuArray<MapData, u64>, index: u32) -> anyhow::Result<u64> {
    let values = map.get(&index, 0)?;
    Ok(values.iter().copied().sum())
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}
