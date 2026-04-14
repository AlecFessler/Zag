const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug_info = zag.utils.debug_info;
const device_registry = zag.devices.registry;
const kprof_log = zag.kprof.log;
const memory = zag.memory.init;
const sched = zag.sched.scheduler;
const syscall = zag.syscall;
const userspace_init = zag.boot.userspace_init;

const BootInfo = zag.boot.protocol.BootInfo;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

comptime {
    // aarch64 `-Ddirect_kernel=true` builds: force-reference the Zig
    // entry helper that start.S branches to. Without this, Zig's lazy
    // compilation skips the module and `ld.lld` fails with "undefined
    // symbol: directKernelEntry". Gated to aarch64 so x86 builds don't
    // try to compile it. We can't gate on `direct_kernel` itself (no
    // build option plumbed to Zig here), but the UEFI aarch64 path
    // just keeps an unused ~500-byte function around, which is fine.
    if (@import("builtin").cpu.arch == .aarch64) {
        _ = &@import("arch/aarch64/boot/direct_kernel.zig").directKernelEntry;
    }
}

pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

export fn kEntry(boot_info: *BootInfo) callconv(arch.cc()) noreturn {
    arch.earlyDebugChar('K');
    arch.kEntry(boot_info, &kTrampoline);
}

export fn kTrampoline(boot_info: *BootInfo) callconv(arch.cc()) noreturn {
    arch.earlyDebugChar('T');
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

fn kMain(boot_info: *BootInfo) !void {
    arch.earlyDebugChar('M');
    arch.init();
    arch.earlyDebugChar('m');
    // DEBUG: print boot_info.mmap.num_descriptors as seen from kMain
    // to detect a compiler spill corrupting the boot_info.mmap read.
    {
        const n = boot_info.mmap.num_descriptors;
        var shift: u6 = 12;
        while (true) {
            const nibble: u8 = @intCast((n >> shift) & 0xF);
            const ch: u8 = if (nibble < 10) '0' + nibble else 'A' + (nibble - 10);
            arch.earlyDebugChar(ch);
            if (shift == 0) break;
            shift -= 4;
        }
        arch.earlyDebugChar('|');
    }
    try memory.init(boot_info.mmap);
    arch.earlyDebugChar('h');
    try memory.initHeap();
    arch.earlyDebugChar('H');
    debug_info.init(boot_info.elf_blob.ptr, boot_info.elf_blob.len, boot_info.kaslr_slide, memory.heap_allocator);
    arch.earlyDebugChar('I');
    try arch.parseFirmwareTables(boot_info.xsdp_phys);
    arch.earlyDebugChar('J');
    arch.vmInit();
    // On aarch64, propagate the UEFI bootloader's "I arrived at EL2"
    // flag into the arch-layer hyp stub gate. The bootloader is the
    // only code path that can observe CurrentEL under UEFI (firmware
    // drops privilege as it likes once we're past ExitBootServices)
    // and was the one that installed the minimal hyp vector table at
    // VBAR_EL2 before its ERET-to-EL1, so it already ensured the
    // invariant vmSupported() checks. See bootloader/aarch64_el2_drop.zig.
    if (@import("builtin").cpu.arch == .aarch64 and boot_info.arrived_at_el2 != 0) {
        zag.arch.aarch64.vm.hyp_stub_installed = true;
    }
    arch.earlyDebugChar('K');
    arch.pmuInit();
    arch.earlyDebugChar('L');
    arch.sysInfoInit();
    arch.earlyDebugChar('N');
    // Wall clock offset init: read RTC once at boot (systems.md §wall-clock).
    const rtc_nanos = arch.readRtc();
    const monotonic_now = arch.getMonotonicClock().now();
    syscall.clock.wall_offset = @as(i64, @bitCast(rtc_nanos)) -% @as(i64, @bitCast(monotonic_now));
    arch.earlyDebugChar('O');
    device_registry.registerDisplayDevice(boot_info.framebuffer);
    arch.earlyDebugChar('P');
    try sched.globalInit();
    arch.earlyDebugChar('Q');
    const rs_phys = PAddr.fromInt(@intFromPtr(boot_info.root_service.ptr));
    const rs_virt = VAddr.fromPAddr(rs_phys, null);
    const rs_ptr: [*]const u8 = @ptrFromInt(rs_virt.addr);
    try userspace_init.init(rs_ptr[0..boot_info.root_service.len]);
    arch.earlyDebugChar('R');
    try arch.smpInit();
    arch.earlyDebugChar('S');
    sched.perCoreInit();
    arch.earlyDebugChar('U');
    // aarch64 world-switch smoke test. Only runnable under the
    // direct-kernel boot path today, because that is the one mode
    // where the kernel owns VBAR_EL2 (installed from boot/start.S
    // before the EL2→EL1 ERET). The UEFI-at-EL2 path leaves VBAR_EL2
    // pointing at the bootloader's minimal hyp stub (see
    // `bootloader/aarch64_el2_drop.zig`), which only knows how to
    // bare-eret a lower-EL sync exception — so `hvc #1` for VCPU_RUN
    // would return to the caller without performing a world switch
    // and the smoke test would hang in `vmResume` waiting for an
    // exit reason that never gets written. Gate on direct_kernel
    // until the UEFI path also installs a full kernel hyp dispatcher
    // at VBAR_EL2 (tracked separately).
    if (@import("builtin").cpu.arch == .aarch64 and zag.build_options.direct_kernel) {
        @import("arch/aarch64/kvm/smoke.zig").runVcpuNopSmoke();
    }
    try kprof_log.init();
    kprof_log.start();
    arch.halt();
}
