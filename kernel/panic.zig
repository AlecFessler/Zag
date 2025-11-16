const std = @import("std");
const zag = @import("zag.zig");

const arch = zag.arch.dispatch;
const builtin = std.builtin;
const debug = zag.debug;

pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, ret_addr: ?u64) noreturn {
    @branchHint(.cold);
    _ = trace;

    if (ret_addr) |ra| {
        const sym_name = debug.info.global_ptr.getSymbolName(ra);
        if (sym_name) |sym| {
            arch.print("KERNEL PANIC: {s} @ {s}\n", .{ msg, sym });
        } else {
            arch.print("KERNEL PANIC: {s}\n", .{msg});
        }
    } else {
        arch.print("KERNEL PANIC: {s}\n", .{msg});
    }

    const first = @returnAddress();
    var it = std.debug.StackIterator.init(first, null);
    var last_pc: u64 = 0;
    var frames: u64 = 0;

    while (frames < 64) : (frames += 1) {
        const pc = it.next() orelse break;
        const sym_name = debug.info.global_ptr.getSymbolName(pc);
        if (sym_name) |sym| {
            arch.print("{s}\n", .{sym});
        } else {
            arch.print("PC: 0x{X} (no symbol)\n", .{pc});
        }
        if (pc == 0) break;
        last_pc = pc;
    }

    arch.halt();
}
