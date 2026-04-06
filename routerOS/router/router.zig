pub const console = @import("console.zig");
pub const hal = @import("hal/hal.zig");
pub const http_handler = @import("http_handler.zig");
pub const log = @import("log.zig");
pub const packet = @import("packet.zig");
pub const protocols = @import("protocols/protocols.zig");
pub const service = @import("service.zig");
pub const util = @import("util.zig");

// Entry point — delegates to main.zig
const entry = @import("main.zig");
pub const main = entry.main;

// Re-export global state from main.zig so sub-modules can access it
// via @import("router").state.*
pub const state = @import("main.zig");
