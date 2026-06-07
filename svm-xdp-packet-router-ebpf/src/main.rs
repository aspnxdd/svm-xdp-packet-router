#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_func_id::BPF_FUNC_xdp_load_bytes, xdp_action, xdp_md},
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray, XskMap},
    programs::XdpContext,
};
use core::{ffi::c_void, mem};
use svm_xdp_packet_router_common::{PacketLogEntry, PshredHeader, SourceKey, SourceRoute};

#[repr(C)]
struct EthHdr {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}
impl EthHdr {
    const LEN: usize = mem::size_of::<Self>();
}

const ETH_P_IP: u16 = 0x0800u16.to_be();

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    dscp_ecn: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    src_addr: u32,
    dst_addr: u32,
}
const IPPROTO_UDP: u8 = 17;

#[repr(C)]
struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    check: u16,
}
impl UdpHdr {
    const LEN: usize = mem::size_of::<Self>();
}

const SHRED_PORT: u16 = 8001u16.to_be();

#[map]
static SOURCE_ROUTING_TABLE: HashMap<SourceKey, SourceRoute> = HashMap::with_max_entries(1024, 0);

#[map]
static XSK_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[map]
static PACKET_LOG: PerfEventArray<PacketLogEntry> = PerfEventArray::new(0);

#[map]
static DROP_COUNTER: aya_ebpf::maps::PerCpuArray<u64> =
    aya_ebpf::maps::PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[xdp]
pub fn svm_xdp_packet_router(ctx: XdpContext) -> u32 {
    match try_pshred_router(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_pshred_router(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = match unsafe { ptr_at::<EthHdr>(ctx, 0) } {
        Some(eth) => eth,
        None => return Err(()),
    };

    if unsafe { (*eth).ether_type } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = EthHdr::LEN;
    let ip = match unsafe { ptr_at::<Ipv4Hdr>(ctx, ip_offset) } {
        Some(ip) => ip,
        None => return Err(()),
    };
    let src_ip = unsafe { (*ip).src_addr };

    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = unsafe { ((*ip).version_ihl & 0x0F) as usize * 4 };

    let udp_offset = ip_offset + ihl;
    let udp = match unsafe { ptr_at::<UdpHdr>(ctx, udp_offset) } {
        Some(udp) => udp,
        None => return Ok(xdp_action::XDP_PASS),
    };

    let dst_port = unsafe { (*udp).dst_port };
    let src_port = unsafe { (*udp).src_port };

    if dst_port != SHRED_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let pshred_offset = udp_offset + UdpHdr::LEN;
    let pshred = match unsafe { ptr_at::<PshredHeader>(ctx, pshred_offset) } {
        Some(pshred) => pshred,
        None => {
            increment_drop_counter();
            log_packet(
                ctx,
                xdp_action::XDP_DROP,
                src_ip,
                u16::from_be(src_port),
                u16::from_be(dst_port),
                0,
                0,
                0,
                0,
                0,
                [0; 32],
            );
            return Ok(xdp_action::XDP_DROP);
        }
    };

    let version = unsafe { (*pshred).version };
    let flags = unsafe { (*pshred).flags };
    let slot = u64::from_be(unsafe { (*pshred).slot });
    let shred_index = u32::from_be(unsafe { (*pshred).shred_index });
    let shred_count = u32::from_be(unsafe { (*pshred).shred_count });
    let source_id = unsafe { (*pshred).source_id };

    if version != PshredHeader::MAGIC_VERSION {
        increment_drop_counter();
        log_packet(
            ctx,
            xdp_action::XDP_DROP,
            src_ip,
            u16::from_be(src_port),
            u16::from_be(dst_port),
            version,
            flags,
            slot,
            shred_index,
            shred_count,
            source_id,
        );
        return Ok(xdp_action::XDP_DROP);
    }

    let key = SourceKey { source_id };

    let queue_id = if let Some(route) = SOURCE_ROUTING_TABLE.get_ptr_mut(&key) {
        unsafe { (*route).packet_count += 1 };
        unsafe { (*route).queue_id }
    } else {
        0u32
    };

    match XSK_MAP.redirect(queue_id, 0) {
        Ok(action) => {
            log_packet(
                ctx,
                action,
                src_ip,
                u16::from_be(src_port),
                u16::from_be(dst_port),
                version,
                flags,
                slot,
                shred_index,
                shred_count,
                source_id,
            );
            Ok(action)
        }
        Err(_) => {
            log_packet(
                ctx,
                xdp_action::XDP_PASS,
                src_ip,
                u16::from_be(src_port),
                u16::from_be(dst_port),
                version,
                flags,
                slot,
                shred_index,
                shred_count,
                source_id,
            );
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[inline(always)]
fn log_packet(
    ctx: &XdpContext,
    action: u32,
    src_ip: u32,
    src_port: u16,
    dst_port: u16,
    version: u8,
    flags: u8,
    slot: u64,
    shred_index: u32,
    shred_count: u32,
    source_id: [u8; 32],
) {
    let mut entry: PacketLogEntry = unsafe { mem::zeroed() };
    entry.action = action;
    entry.cpu = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };
    entry.src_ip = src_ip;
    entry.packet_len = (ctx.data_end() - ctx.data()) as u32;
    entry.src_port = src_port;
    entry.dst_port = dst_port;
    entry.version = version;
    entry.flags = flags;
    entry.slot = slot;
    entry.shred_index = shred_index;
    entry.shred_count = shred_count;
    entry.source_id = source_id;

    let raw_len = copy_raw_packet(ctx, &mut entry.raw);
    entry.raw_len = raw_len as u16;

    PACKET_LOG.output(ctx, &entry, 0);
}

#[inline(always)]
fn copy_raw_packet(ctx: &XdpContext, raw: &mut [u8; PacketLogEntry::RAW_LEN]) -> usize {
    let start = ctx.data();
    let end = ctx.data_end();
    let packet_len = end - start;
    let raw_len = if packet_len > PacketLogEntry::RAW_LEN {
        PacketLogEntry::RAW_LEN
    } else {
        packet_len
    };

    if raw_len == 0 || start + raw_len > end {
        return 0;
    }

    let ret = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            0,
            raw.as_mut_ptr().cast::<c_void>(),
            raw_len as u32,
        )
    };
    if ret < 0 {
        return 0;
    }

    raw_len
}

#[inline(always)]
unsafe fn bpf_xdp_load_bytes(ctx: *mut xdp_md, offset: u32, buf: *mut c_void, len: u32) -> i64 {
    let fun: unsafe extern "C" fn(*mut xdp_md, u32, *mut c_void, u32) -> i64 =
        unsafe { mem::transmute(BPF_FUNC_xdp_load_bytes as usize) };
    unsafe { fun(ctx, offset, buf, len) }
}

#[inline(always)]
fn increment_drop_counter() {
    if let Some(counter) = DROP_COUNTER.get_ptr_mut(0) {
        unsafe { *counter += 1 };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
