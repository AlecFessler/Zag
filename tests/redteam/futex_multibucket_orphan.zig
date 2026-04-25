// PoC for futex multi-bucket cross-pollination → waiter orphan + latent UAF.
//
// Bug surface
// -----------
// kernel/proc/futex.zig wires multi-address futex waits (sysFutexWaitVal /
// sysFutexWaitChange with count > 1) by calling pushWaiter() once per bucket:
//
//     for (0..count) |i| {
//         pushWaiter(&buckets[bucketIdx(addrs[i])], thread);
//     }
//
// Each pushWaiter is `bucket.pq.enqueue(thread)`. The PriorityQueue
// (kernel/utils/containers/priority_queue.zig) is intrusive: it threads the
// list through `Thread.next`, a single per-thread `?SlabRef(Thread)` field.
// Its design comment is explicit about the assumption it relies on:
//
//   // items sitting in a run queue / wait queue are live by construction,
//   // since the queue owns them across yields
//
// That assumption holds when a thread is in *one* queue. Multi-address futex
// waits violate it: the same Thread node is linked into N different bucket
// chains, all sharing one `next` slot.
//
// While each bucket has only the multi-waiter T enqueued, this is invisible:
// every pushWaiter resets `T.next = null` at the end of enqueue, so each
// bucket's chain looks like a clean [T] with T.next = null. The corruption
// becomes structural the moment a SECOND waiter Y is enqueued onto one of
// those buckets — say bucket A:
//
//     A:  head=T, tail=Y, T.next=Y, Y.next=null   ← real
//     B:  head=T, tail=T, T.next=Y                ← phantom: Y reachable
//                                                   from B.head though it was
//                                                   never pushed onto B
//
// PriorityQueue.dequeue is the corruption sink. wake(addrB) calls dequeue
// on bucket B:
//
//     level.head = Helpers.getNext(head);   // B.head = T.next = Y
//     ...
//     Helpers.setNext(head, null);          // T.next = null  ← clobbers A!
//
// After dequeue: A.head=T, A.tail=Y, T.next=null, Y.next=null. Y is
// unreachable from A.head — A's chain is broken. Then wake's per-thread
// removeFromOtherBuckets(T, addrB) → remove(A, T) sets A.head =
// getNext(T) = null and leaves A.tail = Y dangling. End state:
//
//     A:  head=null, tail=Y                  ← Y orphaned, unwakeable on A
//     B:  head=Y,    tail=T                  ← phantom Y on B, stale T tail
//
// Two consequences
// ----------------
// 1. Liveness: a thread waiting on bucket A is permanently unwakeable —
//    sysFutexWake(addrA) walks an empty list and returns 0 even though Y
//    is blocked on A. This PoC observes (1) directly.
//
// 2. Latent UAF: if Y is later killed and its slab slot recycled (futex
//    bucket scrub via removeBlockedThread iterates thread.futex_paddrs and
//    calls bucket.pq.remove(Y) — a no-op since A.head=null, so A.tail is
//    NOT cleared), the next pushWaiter to bucket A reads stale A.tail = Y
//    and writes `Y.next = SlabRef(new_thread, gen)` into the freed (or
//    re-allocated) slot. Either scratch into a freed slot or corruption of
//    the live tenant of that slab slot — including its own `Thread.next`,
//    poisoning whatever queue the new tenant belongs to (run queue,
//    wait queue, IPC waiter list).
//
// PoC design
// ----------
// Three threads in the root_service process:
//   * main  — spawns helpers, drives the wakes, prints the verdict.
//   * H1    — multi-address waiter on [addrA, addrB] (different buckets).
//   * H2    — single-address waiter on addrA2 (same bucket as addrA).
//
// All three futex words live in the same demand-paged user page. Within a
// page the kernel's bucketIdx(paddr) = (paddr >> 3) & 0xff depends only on
// the low 11 bits of paddr (= the low 11 bits of vaddr inside the page),
// so we control the bucket assignments precisely:
//
//     addrA  = page + 0x000   bucketIdx = 0
//     addrA2 = page + 0x800   bucketIdx = 0   (same bucket as addrA)
//     addrB  = page + 0x008   bucketIdx = 1   (different bucket)
//
// Sequencing: main creates H1 → waits for H1's pre-syscall flag → yields
// long enough for H1 to actually block → repeats for H2. This guarantees
// H1's two pushWaiter calls happen before H2's one, which is what produces
// the cross-pollution shape described above.
//
// Then main:
//   step 1.  wake(addrB, 1)  — dequeue path corrupts A.
//   step 2.  wake(addrA2, 1) — under the bug, returns 0 (A.head=null);
//                              under a patched kernel, returns 1.
//
// We also have H2 set `h2_woke` after returning from futex_wait, so the
// two signals (wake return value + observable thread progress) confirm
// each other.
//
// Differential
// ------------
//   PATCHED    — wake(addrA2) returns 1 AND h2_woke == 1.
//   VULNERABLE — wake(addrA2) returns 0 AND h2_woke == 0.

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;
const t = lib.testing;

const PAGE4K: u64 = 4096;
const FUTEX_FOREVER: u64 = ~@as(u64, 0);

// Static handshake / observation flags. All addressed atomically; in
// static memory so addresses stay stable across context switches.
var ready_h1: u64 align(8) = 0;
var ready_h2: u64 align(8) = 0;
var h1_woke: u64 align(8) = 0;
var h2_woke: u64 align(8) = 0;

// The page that holds the three futex words. Resolved at runtime by
// mem_reserve so it sits in user partition with a real PTE.
var page_va: u64 = 0;

inline fn addrA() *u64 {
    return @ptrFromInt(page_va + 0x000);
}
inline fn addrA2() *u64 {
    return @ptrFromInt(page_va + 0x800);
}
inline fn addrB() *u64 {
    return @ptrFromInt(page_va + 0x008);
}

fn yieldFor(n: u64) void {
    var i: u64 = 0;
    while (i < n) {
        _ = syscall.thread_yield_raw();
        i += 1;
    }
}

fn h1Entry() void {
    @atomicStore(u64, &ready_h1, 1, .release);

    // Multi-address wait on [addrA, addrB]. count=2 routes through
    // futex.waitVal, which calls pushWaiter once per bucket using the
    // single shared Thread.next field — the setup the bug needs.
    var addrs: [2]u64 = .{ @intFromPtr(addrA()), @intFromPtr(addrB()) };
    var expected: [2]u64 = .{ 0, 0 };
    _ = syscall.futex_wait_val(
        @intFromPtr(&addrs),
        @intFromPtr(&expected),
        2,
        FUTEX_FOREVER,
    );

    @atomicStore(u64, &h1_woke, 1, .release);
    syscall.thread_exit();
}

fn h2Entry() void {
    @atomicStore(u64, &ready_h2, 1, .release);

    // Single-address wait on addrA2. Same bucket as addrA but a
    // different word, so it's a real waiter that the buggy bucket
    // structure can lose.
    _ = syscall.futex_wait(addrA2(), 0, FUTEX_FOREVER);

    @atomicStore(u64, &h2_woke, 1, .release);
    syscall.thread_exit();
}

pub fn main(_: u64) void {
    // Reserve one private RW page for the three futex words.
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const r = syscall.mem_reserve(0, PAGE4K, rights);
    if (r.val < 0) {
        syscall.write("POC-futex-mb-orphan: SETUP_FAIL mem_reserve ret=");
        t.printI64(r.val);
        syscall.write("\n");
        syscall.shutdown();
    }
    page_va = r.val2;

    // Pre-fault the page so the helper threads' demandPage path inside
    // futex_wait_val doesn't add unnecessary noise to the sequencing.
    @as(*volatile u64, @ptrCast(addrA())).* = 0;
    @as(*volatile u64, @ptrCast(addrA2())).* = 0;
    @as(*volatile u64, @ptrCast(addrB())).* = 0;

    // Spawn H1 first. We need H1's two pushWaiter calls (bucket A and
    // bucket B) to happen BEFORE H2's pushWaiter onto bucket A — that
    // ordering is what extends bucket A past T and exposes the cross-
    // pollution. We can't directly observe "thread blocked", so the
    // protocol is: helper sets ready_X just before its blocking syscall;
    // main spins on the flag and then yields enough times that the
    // scheduler has had ample chance to run the helper, enter the
    // syscall, and put the thread on its bucket(s).
    const h1 = syscall.thread_create(h1Entry, 0, 4);
    if (h1 < 0) {
        syscall.write("POC-futex-mb-orphan: SETUP_FAIL thread_create h1\n");
        syscall.shutdown();
    }
    while (@atomicLoad(u64, &ready_h1, .acquire) == 0) _ = syscall.thread_yield_raw();
    yieldFor(500);

    const h2 = syscall.thread_create(h2Entry, 0, 4);
    if (h2 < 0) {
        syscall.write("POC-futex-mb-orphan: SETUP_FAIL thread_create h2\n");
        syscall.shutdown();
    }
    while (@atomicLoad(u64, &ready_h2, .acquire) == 0) _ = syscall.thread_yield_raw();
    yieldFor(500);

    // Step 1: wake addrB. Under the bug, this dequeue corrupts bucket A;
    // under a patched kernel, it just wakes H1 cleanly. Either way wake
    // should return 1 (woke H1).
    const woken_b = syscall.futex_wake(addrB(), 1);
    if (woken_b != 1) {
        syscall.write("POC-futex-mb-orphan: SETUP_FAIL wake(addrB) returned ");
        t.printI64(woken_b);
        syscall.write("\n");
        syscall.shutdown();
    }

    // Give H1 time to run its post-wait code so we can confirm it
    // actually saw the wake (rules out a false negative on H2's side).
    yieldFor(200);
    if (@atomicLoad(u64, &h1_woke, .acquire) != 1) {
        syscall.write("POC-futex-mb-orphan: SETUP_FAIL h1 didn't observe wake\n");
        syscall.shutdown();
    }

    // Step 2: wake addrA2. Under the bug, bucket A.head is now null
    // because the wake-from-B path silently emptied A while leaving
    // A.tail dangling at H2; the dequeue here finds nothing and returns
    // 0. Under a patched kernel, H2 is still on A and gets woken.
    const woken_a = syscall.futex_wake(addrA2(), 1);

    yieldFor(200);
    const h2_observed_wake = @atomicLoad(u64, &h2_woke, .acquire) == 1;

    if (woken_a == 1 and h2_observed_wake) {
        syscall.write("POC-futex-mb-orphan: PATCHED (multi-bucket wait kept bucket A intact; wake(addrA2)=1, H2 woke)\n");
    } else if (woken_a == 0 and !h2_observed_wake) {
        syscall.write("POC-futex-mb-orphan: VULNERABLE (multi-bucket wait orphaned H2 in bucket A; wake(addrA2)=0, H2 still blocked)\n");
    } else {
        syscall.write("POC-futex-mb-orphan: UNEXPECTED woken_a=");
        t.printI64(woken_a);
        syscall.write(" h2_woke=");
        t.printDec(if (h2_observed_wake) 1 else 0);
        syscall.write("\n");
    }

    syscall.shutdown();
}
