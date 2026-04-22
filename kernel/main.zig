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
    debug_info.init(boot_info.elf_blob.ptr, boot_info.elf_blob.len, boot_info.kaslr_slide);
    try arch.parseFirmwareTables(boot_info.xsdp_phys);
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
        // Install the kernel's EL2 vector table on the boot CPU now,
        // before `smpInit` brings up secondaries. The install path does
        // an HVC to the bootloader's stub at VBAR_EL2 (which recognizes
        // `HVC_IMM_INSTALL_VBAR_EL2`) — that stub is only present on the
        // BSP (UEFI firmware handed it to us). Secondaries come up via
        // PSCI with no bootloader stub on their EL2, so their own EL2
        // drop in `smp.secondaryEntry` writes VBAR_EL2 with the PA of
        // this same table directly. Running this here guarantees the
        // global `hyp_vectors_installed` is set before secondaries call
        // `perCoreInit`, which would otherwise either (a) early-return
        // on the already-true flag and leave the BSP's VBAR_EL2 at the
        // bootloader stub, or (b) fire the install HVC into the kernel
        // vectors and fail silently.
        zag.arch.aarch64.vm.installHypVectors();
    }
    arch.pmuInit();
    arch.sysInfoInit();
    // Wall clock offset init: read RTC once at boot (systems.md §wall-clock).
    const rtc_nanos = arch.readRtc();
    const monotonic_now = arch.getMonotonicClock().now();
    syscall.clock.wall_offset = @as(i64, @bitCast(rtc_nanos)) -% @as(i64, @bitCast(monotonic_now));
    device_registry.registerDisplayDevice(boot_info.framebuffer);
    try sched.globalInit();
    const rs_phys = PAddr.fromInt(@intFromPtr(boot_info.root_service.ptr));
    const rs_virt = VAddr.fromPAddr(rs_phys, null);
    const rs_ptr: [*]const u8 = @ptrFromInt(rs_virt.addr);
    try userspace_init.init(rs_ptr[0..boot_info.root_service.len]);
    try arch.smpInit();
    sched.perCoreInit();
    try kprof_log.init();
    kprof_log.start();
    arch.halt();
}
