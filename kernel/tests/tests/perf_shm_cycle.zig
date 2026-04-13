const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

/// Shared-memory setup cost. Zero-copy IPC buffers are the hot path for
/// data-plane workloads (NIC rings, video pipelines) — each connection
/// pays this cost once but it sets the floor for how cheap a short-lived
/// connection can be.
///
/// Four benchmarks isolate different parts of the cycle:
///   shm_create     — shm object allocation
///   shm_map        — attach to an existing VM reservation
///   shm_unmap      — detach
///   shm_full_cycle — create + reserve + map + unmap + revoke_shm
pub fn main(_: u64) void {
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const ITERATIONS: u32 = 2000;

    // --- Per-step benches: reuse a single long-lived VM reservation and a
    // single long-lived shm object so each iteration hits exactly the
    // step being measured. ---
    const shm_size: u64 = syscall.PAGE4K;
    const shm_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();

    // --- shm_create bench (allocate + free each iter) ---
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] shm_cycle SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var w: u32 = 0;
    while (w < 500) {
        const rc = syscall.shm_create_with_rights(shm_size, shm_rights);
        if (rc >= 0) _ = syscall.revoke_perm(@bitCast(rc));
        w += 1;
    }

    var i: u32 = 0;
    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        const rc = syscall.shm_create_with_rights(shm_size, shm_rights);
        const t1 = bench.rdtscp();
        if (rc < 0) break;
        buf[i] = t1 -% t0;
        _ = syscall.revoke_perm(@bitCast(rc));
        i += 1;
    }
    if (i > 0) {
        bench.report("shm_create", bench.computeStats(buf[0..i], @intCast(i)));
    }

    // --- shm_map / shm_unmap bench: steady-state shm + VM ---
    const shm_rc = syscall.shm_create_with_rights(shm_size, shm_rights);
    if (shm_rc < 0) {
        syscall.write("[PERF] shm_map SKIP create failed\n");
        syscall.shutdown();
    }
    const shm_handle: u64 = @bitCast(shm_rc);

    // Measure map+unmap as a pair on a stable VM reservation. Reusing
    // one VM slot keeps the kernel's VA allocator state fixed across
    // iterations so we measure the shm_map/unmap fast path, not the
    // mem_reserve steady-state churn.
    const stable_vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (stable_vm.val < 0) {
        syscall.write("[PERF] shm_map SKIP mem_reserve failed\n");
        _ = syscall.revoke_perm(shm_handle);
        syscall.shutdown();
    }
    const stable_vm_h: u64 = @bitCast(stable_vm.val);

    w = 0;
    while (w < 100) {
        _ = syscall.mem_shm_map(shm_handle, stable_vm_h, 0);
        _ = syscall.mem_shm_unmap(shm_handle, stable_vm_h);
        w += 1;
    }

    i = 0;
    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        const map_rc = syscall.mem_shm_map(shm_handle, stable_vm_h, 0);
        const unmap_rc = syscall.mem_shm_unmap(shm_handle, stable_vm_h);
        const t1 = bench.rdtscp();
        if (map_rc != 0 or unmap_rc != 0) break;
        buf[i] = t1 -% t0;
        i += 1;
    }
    if (i > 0) {
        bench.report("shm_map_unmap_pair", bench.computeStats(buf[0..i], @intCast(i)));
    }

    _ = syscall.revoke_perm(stable_vm_h);
    _ = syscall.revoke_perm(shm_handle);

    // --- Full cycle: what a transient zero-copy channel costs ---
    i = 0;
    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        const c_rc = syscall.shm_create_with_rights(shm_size, shm_rights);
        if (c_rc < 0) break;
        const c_h: u64 = @bitCast(c_rc);
        const vm = syscall.mem_reserve(0, shm_size, vm_rights);
        if (vm.val < 0) {
            _ = syscall.revoke_perm(c_h);
            break;
        }
        const vm_h: u64 = @bitCast(vm.val);
        _ = syscall.mem_shm_map(c_h, vm_h, 0);
        _ = syscall.mem_shm_unmap(c_h, vm_h);
        _ = syscall.revoke_perm(vm_h);
        _ = syscall.revoke_perm(c_h);
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }
    if (i > 0) {
        bench.report("shm_full_cycle", bench.computeStats(buf[0..i], @intCast(i)));
    }

    syscall.shutdown();
}
