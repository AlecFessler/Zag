const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug_info = zag.utils.debug_info;

pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, ret_addr: ?u64) noreturn {
    @branchHint(.cold);
    _ = trace;

    if (ret_addr) |ra| {
        if (debug_info.global_ptr) |dbg_info| {
            const sym_name = dbg_info.getSymbolName(ra - debug_info.kaslr_slide);
            if (sym_name) |sym| {
                arch.boot.print("KERNEL PANIC: {s} @ {s}\n", .{ msg, sym });
            }
        } else {
            arch.boot.print("KERNEL PANIC: {s}\n", .{msg});
        }
    } else {
        arch.boot.print("KERNEL PANIC: {s}\n", .{msg});
    }

    const first = @returnAddress();
    var it = std.debug.StackIterator.init(first, null);
    var last_pc: u64 = 0;
    var frames: u64 = 0;

    while (frames < 64) : (frames += 1) {
        const pc = it.next() orelse break;

        if (debug_info.global_ptr) |dbg_info| {
            const sym_name = dbg_info.getSymbolName(pc - debug_info.kaslr_slide);
            if (sym_name) |sym| {
                arch.boot.print("{s}\n", .{sym});
            }
        } else {
            arch.boot.print("PC: 0x{X} (no symbol)\n", .{pc});
        }
        if (pc == 0) break;
        last_pc = pc;
    }

    arch.cpu.halt();
}
