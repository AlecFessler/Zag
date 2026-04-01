pub const channel = @import("ipc/channel.zig");
pub const display = @import("protocols/display.zig");
pub const filesystem = @import("protocols/filesystem.zig");
pub const font = @import("font8x16.zig");
pub const keyboard = @import("protocols/keyboard.zig");
pub const mouse = @import("protocols/mouse.zig");
pub const perm_view = @import("perm_view.zig");
pub const perms = @import("perms.zig");
pub const sync = @import("sync.zig");
pub const syscall = @import("syscall.zig");
pub const ui = @import("ui.zig");

/// Well-known service protocol identifiers for discovery.
pub const Protocol = enum(u8) {
    compositor = 1,
    usb_keyboard = 2,
    usb_mouse = 3,
    input_control = 4,
    filesystem = 5,
};
