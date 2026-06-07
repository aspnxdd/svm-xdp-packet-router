use anyhow::Context;
use aya::{
    Ebpf,
    maps::{PerCpuArray, PerfEventArray, perf::PerfEvent},
    programs::{Xdp, XdpMode},
    util::online_cpus,
};
use log::{info, warn};
use std::{mem::size_of, net::Ipv4Addr, time::Duration};
use svm_xdp_packet_router_common::{PacketLogEntry, action};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/svm-xdp-packet-router"
    )))?;
    spawn_packet_log_reader(&mut ebpf)?;
    spawn_drop_counter_reader(&mut ebpf)?;

    let program: &mut Xdp = ebpf
        .program_mut("svm_xdp_packet_router")
        .unwrap()
        .try_into()?;

    program.load().context("failed to load XDP program")?;
    program
        .attach("lo", XdpMode::default())
        .context("failed to attach XDP program to lo")?;

    info!("XDP attached to lo — listening on UDP port 8001");

    signal::ctrl_c().await?;
    info!("Detaching...");
    Ok(())
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
        "packet action={} cpu={} src={}:{} dst_port={} len={} raw_len={} slot={} proposer_index={} shred_index={} witness_len={} commitment={} proposer_sig={} raw={}",
        action_name(entry.action),
        entry.cpu,
        src_ip,
        entry.src_port,
        entry.dst_port,
        entry.packet_len,
        entry.raw_len,
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

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
