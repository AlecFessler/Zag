const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

/// mem_perms benchmark. Measures the cost of changing page permissions
/// on an already-mapped region. This is the TLB-shootdown hot path — a
/// JIT compiler toggling W→X, a garbage collector protecting pages, or
/// mprotect-style tracing all go through mem_perms and incur a
/// per-thread flush.
///
/// Variants:
///   mem_perms_toggle   — RW → RX → RW on a 1-page region (common JIT)
///   mem_perms_wide_4k  — RW → RX on a 4-page region (larger shootdown)
pub fn main(_: u64) void {
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const rw = (perms.VmReservationRights{ .read = true, .write = true, .execute = true }).bits();
    const rx = (perms.VmReservationRights{ .read = true, .execute = true }).bits();

    // --- 1-page bench: W↔X toggle ---
    {
        const vm = syscall.mem_reserve(0, syscall.PAGE4K, rw);
        if (vm.val < 0) {
            syscall.write("[PERF] mem_perms_toggle SKIP mem_reserve failed\n");
            syscall.shutdown();
        }
        const vm_h: u64 = @bitCast(vm.val);
        // Prefault the page so measurements exclude demand-paging cost.
        const ptr: *volatile u8 = @ptrFromInt(vm.val2);
        ptr.* = 0;

        cached_vm_h_1 = vm_h;
        _ = bench.runBench(.{
            .name = "mem_perms_toggle_1page",
            .warmup = 500,
            .iterations = 5000,
        }, benchToggle1);

        _ = syscall.revoke_perm(vm_h);
    }

    // --- 4-page bench: wider shootdown ---
    {
        const vm = syscall.mem_reserve(0, 4 * syscall.PAGE4K, rw);
        if (vm.val < 0) {
            syscall.write("[PERF] mem_perms_wide SKIP mem_reserve failed\n");
            syscall.shutdown();
        }
        const vm_h: u64 = @bitCast(vm.val);
        // Prefault all 4 pages.
        const base: [*]volatile u8 = @ptrFromInt(vm.val2);
        base[0] = 0;
        base[4096] = 0;
        base[8192] = 0;
        base[12288] = 0;

        cached_vm_h_4 = vm_h;
        _ = bench.runBench(.{
            .name = "mem_perms_wide_4page",
            .warmup = 200,
            .iterations = 2000,
        }, benchToggle4);

        _ = syscall.revoke_perm(vm_h);
    }

    _ = rx; // silence unused when toggles below capture it via module state
    syscall.shutdown();
}

var cached_vm_h_1: u64 = 0;
var cached_vm_h_4: u64 = 0;

fn benchToggle1() void {
    const rw = (perms.VmReservationRights{ .read = true, .write = true, .execute = true }).bits();
    const rx = (perms.VmReservationRights{ .read = true, .execute = true }).bits();
    _ = syscall.mem_perms(cached_vm_h_1, 0, syscall.PAGE4K, rx);
    _ = syscall.mem_perms(cached_vm_h_1, 0, syscall.PAGE4K, rw);
}

fn benchToggle4() void {
    const rw = (perms.VmReservationRights{ .read = true, .write = true, .execute = true }).bits();
    const rx = (perms.VmReservationRights{ .read = true, .execute = true }).bits();
    _ = syscall.mem_perms(cached_vm_h_4, 0, 4 * syscall.PAGE4K, rx);
    _ = syscall.mem_perms(cached_vm_h_4, 0, 4 * syscall.PAGE4K, rw);
}
