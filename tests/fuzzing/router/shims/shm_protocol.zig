const sync = @import("sync.zig");

pub const MAX_CONNECTIONS: u32 = 8;
pub const COMMAND_SHM_SIZE: u32 = 4096;

pub const ConnectionStatus = enum(u32) {
    available = 0,
    requested = 1,
    connected = 2,
};

pub const ConnectionEntry = extern struct {
    service_id: u32,
    status: u32,
    shm_handle: u64,
    shm_size: u64,
    _reserved: u64,
};

pub const CommandChannel = extern struct {
    cmd_mutex: sync.Mutex,
    wake_flag: u64 align(8),
    reply_flag: u64 align(8),
    num_connections: u32,
    _pad: u32,
    connections: [MAX_CONNECTIONS]ConnectionEntry,
};

pub const ServiceId = struct {
    pub const SERIAL: u32 = 1;
    pub const NIC: u32 = 2;
    pub const NIC_WAN: u32 = 2;
    pub const NIC_LAN: u32 = 5;
    pub const ROUTER: u32 = 3;
    pub const CONSOLE: u32 = 4;
    pub const NFS_CLIENT: u32 = 6;
    pub const NTP_CLIENT: u32 = 7;
    pub const HTTP_SERVER: u32 = 8;
};
