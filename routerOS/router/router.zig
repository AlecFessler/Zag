pub const ipv4 = @import("ipv4/ipv4.zig");
pub const ipv6 = @import("ipv6/ipv6.zig");
pub const log = @import("log.zig");
pub const net = @import("net/net.zig");
pub const services = @import("services/services.zig");
pub const util = @import("util.zig");

// Entry point — delegates to main.zig
const entry = @import("main.zig");
pub const main = entry.main;

// Re-export global state from main.zig so sub-modules can access it
// via @import("router").state.*
pub const state = @import("main.zig");
