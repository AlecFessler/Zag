const lib = @import("lib");

const udp_proxy = lib.udp_proxy;

pub const protocol_id = lib.Protocol.nfs_client;

// Re-export base UDP proxy tags
pub const CMD_UDP_SEND = udp_proxy.CMD_UDP_SEND;
pub const CMD_UDP_BIND = udp_proxy.CMD_UDP_BIND;
pub const RESP_UDP_RECV = udp_proxy.RESP_UDP_RECV;

// ── NFS-specific A→B extension tags ─────────────────────────────────
pub const CMD_LOG_WRITE: u8 = 0x10;
