// Shared between eBPF kernel program and userspace loader
// Compiles for both targets
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PshredHeader {
    pub version: u8,
    pub flags: u8,
    pub payload_len: u16,
    pub slot: u64,
    pub shred_index: u32,
    pub shred_count: u32,
    pub source_id: [u8; 32],
}

impl PshredHeader {
    pub const SIZE: usize = core::mem::size_of::<PshredHeader>();
    pub const MAGIC_VERSION: u8 = 0x01;
    pub const FLAG_CODING: u8 = 0b0000_0001;
    pub const FLAG_LAST: u8 = 0b0000_0010;
    pub const FLAG_SIGNED: u8 = 0b0000_0100;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketLogEntry {
    pub action: u32,
    pub cpu: u32,
    pub src_ip: u32,
    pub packet_len: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub raw_len: u16,
    pub version: u8,
    pub flags: u8,
    pub slot: u64,
    pub shred_index: u32,
    pub shred_count: u32,
    pub source_id: [u8; 32],
    pub raw: [u8; Self::RAW_LEN],
}

impl PacketLogEntry {
    pub const RAW_LEN: usize = 128;
}

pub mod action {
    pub const ABORTED: u32 = 0;
    pub const DROP: u32 = 1;
    pub const PASS: u32 = 2;
    pub const TX: u32 = 3;
    pub const REDIRECT: u32 = 4;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SourceKey {
    pub source_id: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SourceRoute {
    pub queue_id: u32,
    pub packet_count: u64,
}

// needed for userspace HashMap usage
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLogEntry {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SourceRoute {}

/**
 * +-----------------+------------------------------+
| Field           | Size (bytes)                 |
+-----------------+------------------------------+
| slot            | 8                            |
| proposer_index  | 4                            | (source id?)
| shred_index     | 4                            |
| commitment      | 32                           |
| shred_data      | SHRED_DATA_BYTES             |
| witness_len     | 1                            |
| witness         | 32 * witness_len             |
| proposer_sig    | 64                           |
+-----------------+------------------------------+
 */

const SHRED_DATA_BYTES: usize = 1024;
const MAX_WITNESS_LEN: usize = 8; // The expected witness length is ceil(log2(NUM_RELAYS)); NUM_RELAYS=200 (recommended)

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Shred {
    pub slot: u64,
    pub proposer_index: u32,
    pub shred_index: u32,
    pub commitment: [u8; 32],
    pub shred_data: [u8; SHRED_DATA_BYTES],
    pub witness_len: u8,
    pub witness: [[u8; 32]; MAX_WITNESS_LEN],
    pub proposer_sig: [u8; 64],
}
