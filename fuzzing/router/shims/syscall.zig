const std = @import("std");

pub const PAGE4K: u64 = 4096;

pub const SyscallResult2 = struct {
    val: i64,
    val2: u64,
};

pub const SyscallNum = enum(u64) {
    write,
    vm_reserve,
    vm_perms,
    shm_create,
    shm_map,
    shm_unmap,
    mmio_map,
    mmio_unmap,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    set_affinity,
    grant_perm,
    revoke_perm,
    disable_restart,
    futex_wait,
    futex_wake,
    clock_gettime,
    shutdown,
    ioport_read,
    ioport_write,
    dma_map,
    dma_unmap,
    pci_enable_bus_master,
    pin_exclusive,
};

/// Controlled by the fuzzer harness for deterministic time.
pub var fuzzer_clock_ns: i64 = 0;

pub fn write(msg: []const u8) void {
    const stderr = std.posix.STDERR_FILENO;
    _ = std.posix.write(stderr, msg) catch {};
}

pub fn clock_gettime() i64 {
    return fuzzer_clock_ns;
}

// ── Stubs (never called by processPacket path) ──

pub fn vm_reserve(_: u64, _: u64, _: u64) SyscallResult2 {
    return .{ .val = -1, .val2 = 0 };
}

pub fn vm_perms(_: u64, _: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn shm_create(_: u64) i64 {
    return -1;
}

pub fn shm_create_with_rights(_: u64, _: u64) i64 {
    return -1;
}

pub fn shm_map(_: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn shm_unmap(_: u64, _: u64) i64 {
    return -1;
}

pub fn mmio_map(_: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn mmio_unmap(_: u64, _: u64) i64 {
    return -1;
}

pub fn proc_create(_: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn thread_create(_: *const fn () void, _: u64, _: u64) i64 {
    return -1;
}

pub fn thread_exit() noreturn {
    unreachable;
}

pub fn thread_yield() void {}

pub fn set_affinity(_: u64) i64 {
    return -1;
}

pub fn grant_perm(_: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn revoke_perm(_: u64) i64 {
    return -1;
}

pub fn disable_restart() i64 {
    return -1;
}

pub fn futex_wait(_: *const u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn futex_wake(_: *const u64, _: u64) i64 {
    return -1;
}

pub fn shutdown() noreturn {
    std.process.exit(0);
}

pub fn ioport_read(_: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn ioport_write(_: u64, _: u64, _: u64, _: u64) i64 {
    return -1;
}

pub fn dma_map(_: u64, _: u64) i64 {
    return -1;
}

pub fn pci_enable_bus_master(_: u64) i64 {
    return -1;
}

pub fn dma_unmap(_: u64, _: u64) i64 {
    return -1;
}

pub fn pin_exclusive() i64 {
    return -1;
}
