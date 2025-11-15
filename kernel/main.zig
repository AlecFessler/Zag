const zag = @import("zag");

const arch = zag.arch.dispatch;

const BootInfo = zag.boot.protocol.BootInfo;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

export fn kEntry(boot_info: BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn {
    arch.swapStack(boot_info.stack_top);
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

fn kMain(boot_info: BootInfo) !void {
    _ = boot_info;
    arch.init();
}
