//! Test driver for the per-core timer wheel min-heap. Mirrors the
//! in-file `test "..."` blocks in `timer.zig` but runs against a
//! standalone `zig test` invocation that wires up the `zag` module.
//!
//! Usage:
//!   zig test --dep zag -Mtest=kernel/sched/timer_heap_test.zig \
//!            --dep zag -Mzag=kernel/zag.zig
//!
//! This file exists only because `timer.zig` lives inside the kernel
//! `zag` module — the same .zig file can't be both a `zig test` root
//! and a member of the `zag` module. The driver references the
//! published `TimerHeap` surface through `zag.sched.timer.*` and
//! re-derives the assertions in tests so the heap impl gets exercised
//! without re-doing the kernel build pipeline.

const std = @import("std");
const zag = @import("zag");

const timer = zag.sched.timer;
const Timer = timer.Timer;
const TimerHeap = timer.TimerHeap;
const WHEEL_NOT_QUEUED: u32 = timer.WHEEL_NOT_QUEUED;
const MAX_TIMERS_PER_CORE: u32 = timer.MAX_TIMERS_PER_CORE;

fn freshTimer(deadline: u64) Timer {
    var t: Timer = .{};
    // Mark slot live (odd gen) so `SlabRef(Timer).init` (called inside
    // `TimerHeap.insert`) accepts it. Real allocs go through the slab
    // which sets this; the unit-test driver builds Timers in-line so
    // we have to seed the gen by hand.
    t._gen_lock.setGenRelease(1);
    t.deadline_ns = deadline;
    return t;
}

fn assertHeapInvariant(heap: *const TimerHeap) !void {
    var i: u32 = 0;
    while (i < heap.len) : (i += 1) {
        const left = 2 * i + 1;
        const right = 2 * i + 2;
        if (left < heap.len)
            try std.testing.expect(heap.entries[i].deadline_ns <= heap.entries[left].deadline_ns);
        if (right < heap.len)
            try std.testing.expect(heap.entries[i].deadline_ns <= heap.entries[right].deadline_ns);
        try std.testing.expectEqual(i, heap.entries[i].timer.ptr.wheel_idx); // self-alive
    }
}

test "min-heap insert maintains heap property" {
    var heap: TimerHeap = .{};

    const deadlines = [_]u64{ 50, 10, 30, 5, 100, 20, 40, 1, 75 };
    var timers: [deadlines.len]Timer = undefined;
    for (deadlines, 0..) |d, i| {
        timers[i] = freshTimer(d);
        const slot = heap.insert(&timers[i], d) orelse return error.HeapFull;
        try std.testing.expect(slot < deadlines.len);
        try assertHeapInvariant(&heap);
    }

    try std.testing.expectEqual(@as(u32, deadlines.len), heap.len);
    try std.testing.expectEqual(@as(u64, 1), heap.peekMin().?.deadline_ns);
}

test "pop returns min then re-heapifies" {
    var heap: TimerHeap = .{};

    const deadlines = [_]u64{ 50, 10, 30, 5, 100, 20, 40, 1, 75 };
    var timers: [deadlines.len]Timer = undefined;
    for (deadlines, 0..) |d, i| {
        timers[i] = freshTimer(d);
        _ = heap.insert(&timers[i], d) orelse return error.HeapFull;
    }

    var sorted = deadlines;
    std.mem.sort(u64, &sorted, {}, std.sort.asc(u64));

    for (sorted) |expected| {
        const popped = heap.popMin() orelse return error.UnexpectedEmpty;
        try std.testing.expectEqual(expected, popped.deadline_ns);
        try std.testing.expectEqual(WHEEL_NOT_QUEUED, popped.timer.ptr.wheel_idx); // self-alive
        try assertHeapInvariant(&heap);
    }

    try std.testing.expect(heap.isEmpty());
    try std.testing.expectEqual(@as(?@TypeOf(heap.peekMin().?), null), heap.popMin());
}

test "cancel by handle removes correct entry" {
    var heap: TimerHeap = .{};

    const deadlines = [_]u64{ 100, 50, 200, 25, 75, 150, 250, 10, 60 };
    var timers: [deadlines.len]Timer = undefined;
    for (deadlines, 0..) |d, i| {
        timers[i] = freshTimer(d);
        _ = heap.insert(&timers[i], d) orelse return error.HeapFull;
    }

    const victim_deadline: u64 = 75;
    const victim = &timers[4];
    try std.testing.expectEqual(victim_deadline, victim.deadline_ns);
    try std.testing.expect(victim.wheel_idx != WHEEL_NOT_QUEUED);

    heap.removeAt(victim.wheel_idx);

    try std.testing.expectEqual(WHEEL_NOT_QUEUED, victim.wheel_idx);
    try std.testing.expectEqual(@as(u32, deadlines.len - 1), heap.len);
    try assertHeapInvariant(&heap);

    var seen_victim: bool = false;
    while (heap.popMin()) |e| {
        if (e.deadline_ns == victim_deadline) seen_victim = true;
        try assertHeapInvariant(&heap);
    }
    try std.testing.expect(!seen_victim);

    // Cancelling the root.
    heap.len = 0;
    for (deadlines, 0..) |d, i| {
        timers[i] = freshTimer(d);
        _ = heap.insert(&timers[i], d) orelse return error.HeapFull;
    }
    const root_before = heap.peekMin().?.deadline_ns;
    heap.removeAt(0);
    try assertHeapInvariant(&heap);
    const root_after = heap.peekMin().?.deadline_ns;
    try std.testing.expect(root_after >= root_before);
    try std.testing.expect(root_after != root_before);
}

test "fill+drain N entries" {
    var heap: TimerHeap = .{};

    const N: u32 = MAX_TIMERS_PER_CORE;
    var timers: [MAX_TIMERS_PER_CORE]Timer = undefined;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        const deadline: u64 = @as(u64, N - i) * 100;
        timers[i] = freshTimer(deadline);
        _ = heap.insert(&timers[i], deadline) orelse return error.HeapFull;
    }
    try std.testing.expectEqual(N, heap.len);

    var overflow_timer = freshTimer(1);
    const result = heap.insert(&overflow_timer, 1);
    try std.testing.expectEqual(@as(?u32, null), result);
    try std.testing.expectEqual(N, heap.len);
    try std.testing.expectEqual(WHEEL_NOT_QUEUED, overflow_timer.wheel_idx);

    var prev: u64 = 0;
    while (heap.popMin()) |e| {
        try std.testing.expect(e.deadline_ns >= prev);
        prev = e.deadline_ns;
    }
    try std.testing.expect(heap.isEmpty());
}

test "cancel preserves invariant when victim sits below root" {
    var heap: TimerHeap = .{};
    const deadlines = [_]u64{ 5, 10, 100, 20, 30, 200, 300, 50, 60 };
    var timers: [deadlines.len]Timer = undefined;
    for (deadlines, 0..) |d, i| {
        timers[i] = freshTimer(d);
        _ = heap.insert(&timers[i], d) orelse return error.HeapFull;
    }

    var victim_idx: ?u32 = null;
    var k: u32 = 0;
    while (k < heap.len) : (k += 1) {
        if (heap.entries[k].deadline_ns == 200) {
            victim_idx = k;
            break;
        }
    }
    try std.testing.expect(victim_idx != null);
    heap.removeAt(victim_idx.?);
    try assertHeapInvariant(&heap);
}
