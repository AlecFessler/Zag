const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug = zag.debug;
const device_registry = zag.devices.registry;
const memory = zag.memory.init;
const sched = zag.sched.scheduler;

const BootInfo = zag.boot.protocol.BootInfo;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

export fn kEntry(boot_info: *BootInfo) callconv(arch.cc()) noreturn {
    arch.kEntry(boot_info, &kTrampoline);
}

export fn kTrampoline(boot_info: *BootInfo) callconv(arch.cc()) noreturn {
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

fn kMain(boot_info: *BootInfo) !void {
    arch.init();
    try memory.init(boot_info.mmap);
    try memory.initHeap();
    debug.info.init(boot_info.elf_blob, boot_info.kaslr_slide, memory.heap_allocator);
    try arch.parseFirmwareTables(boot_info.xsdp_phys);
    arch.vmInit();
    arch.pmuInit();
    arch.sysInfoInit();
    device_registry.registerDisplayDevice(boot_info.framebuffer);
    const rs_phys = PAddr.fromInt(@intFromPtr(boot_info.root_service.ptr));
    const rs_virt = VAddr.fromPAddr(rs_phys, null);
    const rs_ptr: [*]const u8 = @ptrFromInt(rs_virt.addr);
    try sched.globalInit(rs_ptr[0..boot_info.root_service.len]);
    try arch.smpInit();
    sched.perCoreInit();
    arch.halt();
}
