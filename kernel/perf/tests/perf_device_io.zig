const lib = @import("lib");

const bench = lib.bench;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// Device I/O hot-path microbenchmarks. Complements `perf_syscall_micro`'s
/// `*_badh` variants which measure only the capability-lookup floor: those
/// short-circuit at `getPermByHandle` before reaching any device code. The
/// three benches here drive real device handles from the root service's
/// permission view, exercising the full rights check + device entry
/// validation + the actual `inb`/`outb` instruction or MMIO page-table
/// mutation.
///
///   ioport_read      — `inb` on AHCI PIO BAR at offset 0 (always safe to
///                      observe: reads have no side effects in QEMU and on
///                      real AHCI legacy PIO this is the data-read port,
///                      which is harmless without a pending command).
///   ioport_write     — `outb` on AHCI PIO BAR at offset 2 with value 0.
///                      This is the device-control range on the AHCI
///                      legacy-IDE PIO BAR; writing zero toggles nothing
///                      observable without a command in flight.
///   mmio_map_unmap   — `mem_mmio_map` + `mem_mmio_unmap` pair on the AHCI
///                      MMIO BAR. Reuses one VM reservation across iters
///                      (same pattern as `perf_shm_cycle`'s map/unmap pair)
///                      so we measure page-table mutation + TLB shootdown
///                      cost, not VA-allocator churn.
///
/// The first two bodies use `runBench` with module-level handle caches
/// (see `perf_pmu_self.zig`). The third uses a manual `rdtscp` loop
/// because it sequences two syscalls per iteration and the cached-handle
/// pattern there matches `perf_shm_cycle.zig` more naturally.

// --- Module-level handle caches (populated once in main) ---

var pio_handle: u64 = 0;
var mmio_handle: u64 = 0;

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const pio_dev = t.requirePioDevice(view, "perf_device_io.pio");
    const mmio_dev = t.requireMmioDevice(view, "perf_device_io.mmio");
    pio_handle = pio_dev.handle;
    mmio_handle = mmio_dev.handle;

    // --- ioport_read / ioport_write: single-call bodies via runBench ---
    _ = bench.runBench(.{
        .name = "ioport_read",
        .warmup = 1000,
        .iterations = 10000,
    }, benchIoportRead);

    _ = bench.runBench(.{
        .name = "ioport_write",
        .warmup = 1000,
        .iterations = 10000,
    }, benchIoportWrite);

    // --- mmio_map_unmap: manual rdtscp pair loop ---
    const ITERATIONS: u32 = 2000;
    const dev_size = mmio_dev.deviceSizeOrPortCount();
    const page_size: u64 = syscall.PAGE4K;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .mmio = true,
    }).bits();

    const vm = syscall.mem_reserve(0, size, vm_rights);
    if (vm.val < 0) {
        syscall.write("[PERF] mmio_map_unmap SKIP mem_reserve failed\n");
        syscall.shutdown();
    }
    const vm_handle: u64 = @bitCast(vm.val);

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] mmio_map_unmap SKIP alloc failed\n");
        _ = syscall.revoke_perm(vm_handle);
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    // Pin to core 0 at realtime priority, same as runBench does internally.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    // mem_mmio_unmap was removed; unmapping requires revoking the VM.
    // Each iteration: reserve → mmio_map → revoke.
    var w: u32 = 0;
    while (w < 200) {
        const vm2 = syscall.mem_reserve(0, size, vm_rights);
        if (vm2.val >= 0) {
            _ = syscall.mem_mmio_map(mmio_handle, @bitCast(vm2.val), 0);
            _ = syscall.revoke_perm(@bitCast(vm2.val));
        }
        w += 1;
    }

    var i: u32 = 0;
    while (i < ITERATIONS) {
        const vm2 = syscall.mem_reserve(0, size, vm_rights);
        if (vm2.val < 0) break;
        const vm2_h: u64 = @bitCast(vm2.val);
        const t0 = bench.rdtscp();
        const map_rc = syscall.mem_mmio_map(mmio_handle, vm2_h, 0);
        const t1 = bench.rdtscp();
        _ = syscall.revoke_perm(vm2_h);
        if (map_rc != 0) break;
        buf[i] = t1 -% t0;
        i += 1;
    }
    if (i > 0) {
        bench.report("mmio_map", bench.computeStats(buf[0..i], @intCast(i)));
    }
    syscall.shutdown();
}

// --- Bench bodies ---

fn benchIoportRead() void {
    _ = syscall.ioport_read(pio_handle, 0, 1);
}

fn benchIoportWrite() void {
    _ = syscall.ioport_write(pio_handle, 2, 1, 0);
}
