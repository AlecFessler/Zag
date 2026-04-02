pub const arena = @import("arena.zig");
pub const channel = @import("channel.zig");
pub const crc32 = @import("crc32.zig");
pub const perm_view = @import("perm_view.zig");
pub const perms = @import("perms.zig");
pub const sync = @import("sync.zig");
pub const syscall = @import("syscall.zig");
pub const testing = @import("test.zig");

pub const Protocol = enum(u8) {
    serial = 1,
    nic = 2,
    router = 3,
    console = 4,
    nic_lan = 5,
    nfs_client = 6,
    ntp_client = 7,
    http_server = 8,
};
