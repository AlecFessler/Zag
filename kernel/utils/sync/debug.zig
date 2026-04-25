// Lockdep-style runtime deadlock detector.
//
// Limitations:
//   - Per-core held stack (no global view); cross-core migration between
//     acquire and release is silently tolerated by release().
//   - Recursive-acquire detection still catches the same-core same-lock
//     case, which is what matters for kernel deadlock prevention.
//   - Pair registry has fixed capacity; on overflow new edges are
//     silently dropped.
//   - Panic path uses serial.printRaw to avoid recursing through
//     print_lock (which itself is detector-instrumented).

const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;

pub const SrcLoc = std.builtin.SourceLocation;

const active = builtin.mode == .Debug and !builtin.is_test;

const HELD_STACK_DEPTH: u8 = 8;
const MAX_CORES: usize = 8;
const PAIR_REGISTRY_CAPACITY: usize = 64;

pub const Entry = struct {
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    ordered_group: u32,
    src: SrcLoc,
};

pub const HeldStack = struct {
    entries: [HELD_STACK_DEPTH]Entry = undefined,
    depth: u8 = 0,
};

pub const CheckResult = enum {
    ok,
    panic_recursive,
    panic_same_class,
    panic_cycle,
};

pub const CheckOutcome = struct {
    result: CheckResult = .ok,
    /// For recursive / same-class: the prior held entry that conflicted.
    prior: ?Entry = null,
    /// For cycle: the prior pair-registry entry whose order was reversed.
    cycle_outer: [*:0]const u8 = "",
    cycle_inner: [*:0]const u8 = "",
    cycle_prior_outer_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
    cycle_prior_inner_src: SrcLoc = .{ .file = "", .fn_name = "", .line = 0, .column = 0, .module = "" },
};

const PairEntry = struct {
    outer: ?[*:0]const u8 = null,
    inner: [*:0]const u8 = undefined,
    outer_src: SrcLoc = undefined,
    inner_src: SrcLoc = undefined,
};

const PairRegistry = struct {
    entries: [PAIR_REGISTRY_CAPACITY]PairEntry = [_]PairEntry{.{}} ** PAIR_REGISTRY_CAPACITY,
    lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn acquireLock(self: *PairRegistry) void {
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn releaseLock(self: *PairRegistry) void {
        self.lock.store(0, .release);
    }

    fn hash(outer: [*:0]const u8, inner: [*:0]const u8) usize {
        const a: usize = @intFromPtr(outer);
        const b: usize = @intFromPtr(inner);
        // Mix the two pointers; rotate one to avoid trivial collisions
        // when (A,B) vs (B,A) are queried.
        const rot = (b << 17) | (b >> @as(u6, @intCast((@bitSizeOf(usize) - 17) & 0x3f)));
        return (a ^ rot) % PAIR_REGISTRY_CAPACITY;
    }

    /// Returns true if the pair (outer,inner) is already present.
    fn contains(self: *PairRegistry, outer: [*:0]const u8, inner: [*:0]const u8) bool {
        var idx = hash(outer, inner);
        var probes: usize = 0;
        while (probes < PAIR_REGISTRY_CAPACITY) {
            const e = self.entries[idx];
            if (e.outer == null) return false;
            if (e.outer.? == outer and e.inner == inner) return true;
            idx = (idx + 1) % PAIR_REGISTRY_CAPACITY;
            probes += 1;
        }
        return false;
    }

    /// Look up an entry's source locations. Returns null if absent.
    fn lookup(self: *PairRegistry, outer: [*:0]const u8, inner: [*:0]const u8) ?PairEntry {
        var idx = hash(outer, inner);
        var probes: usize = 0;
        while (probes < PAIR_REGISTRY_CAPACITY) {
            const e = self.entries[idx];
            if (e.outer == null) return null;
            if (e.outer.? == outer and e.inner == inner) return e;
            idx = (idx + 1) % PAIR_REGISTRY_CAPACITY;
            probes += 1;
        }
        return null;
    }

    /// Insert if absent. Silently drops on table overflow.
    fn insert(
        self: *PairRegistry,
        outer: [*:0]const u8,
        inner: [*:0]const u8,
        outer_src: SrcLoc,
        inner_src: SrcLoc,
    ) void {
        var idx = hash(outer, inner);
        var probes: usize = 0;
        while (probes < PAIR_REGISTRY_CAPACITY) {
            const e = self.entries[idx];
            if (e.outer == null) {
                self.entries[idx] = .{
                    .outer = outer,
                    .inner = inner,
                    .outer_src = outer_src,
                    .inner_src = inner_src,
                };
                return;
            }
            if (e.outer.? == outer and e.inner == inner) return;
            idx = (idx + 1) % PAIR_REGISTRY_CAPACITY;
            probes += 1;
        }
    }

    fn clear(self: *PairRegistry) void {
        var i: usize = 0;
        while (i < PAIR_REGISTRY_CAPACITY) {
            self.entries[i] = .{};
            i += 1;
        }
    }
};

var held_stacks: [MAX_CORES]HeldStack align(64) = [_]HeldStack{.{}} ** MAX_CORES;
var pair_registry: PairRegistry = .{};

/// Pure check + mutate. Returns the outcome rather than panicking so that
/// tests can drive the logic without a real arch.smp.coreID().
pub fn acquireOn(
    stack: *HeldStack,
    registry: *PairRegistry,
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    ordered_group: u32,
    src: SrcLoc,
) CheckOutcome {
    var i: u8 = 0;
    while (i < stack.depth) {
        const held = stack.entries[i];
        if (held.lock_ptr == lock_ptr) {
            return .{ .result = .panic_recursive, .prior = held };
        }
        if (held.class == class and (ordered_group == 0 or held.ordered_group != ordered_group)) {
            return .{ .result = .panic_same_class, .prior = held };
        }
        i += 1;
    }

    registry.acquireLock();
    defer registry.releaseLock();

    var j: u8 = 0;
    while (j < stack.depth) {
        const held = stack.entries[j];
        if (held.class != class) {
            if (registry.contains(class, held.class)) {
                const prior = registry.lookup(class, held.class) orelse PairEntry{};
                return .{
                    .result = .panic_cycle,
                    .cycle_outer = class,
                    .cycle_inner = held.class,
                    .cycle_prior_outer_src = prior.outer_src,
                    .cycle_prior_inner_src = prior.inner_src,
                };
            }
            registry.insert(held.class, class, held.src, src);
        }
        j += 1;
    }

    if (stack.depth < HELD_STACK_DEPTH) {
        stack.entries[stack.depth] = .{
            .lock_ptr = lock_ptr,
            .class = class,
            .ordered_group = ordered_group,
            .src = src,
        };
        stack.depth += 1;
    }

    return .{};
}

/// Pure release. Pops the matching entry; returns false if not found
/// (caller may have migrated cores between acquire and release).
pub fn releaseOn(stack: *HeldStack, lock_ptr: *const anyopaque) bool {
    var i: u8 = 0;
    while (i < stack.depth) {
        if (stack.entries[i].lock_ptr == lock_ptr) {
            var j: u8 = i;
            while (j + 1 < stack.depth) {
                stack.entries[j] = stack.entries[j + 1];
                j += 1;
            }
            stack.depth -= 1;
            return true;
        }
        i += 1;
    }
    return false;
}

/// Set by the kernel boot path once `arch.smp.coreID()` is safe to call
/// (after APIC/GIC init). Until then, acquire/release are no-ops — early
/// boot uses SpinLocks for serial print and PMM init, before any SMP
/// machinery is up.
var smp_ready: u32 align(64) = 0;

pub fn markSmpReady() void {
    @atomicStore(u32, &smp_ready, 1, .release);
}

pub fn acquire(
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    ordered_group: u32,
    src: SrcLoc,
) void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    const core_id = arch.smp.coreID();
    if (core_id >= MAX_CORES) return;
    const stack = &held_stacks[@intCast(core_id)];
    const outcome = acquireOn(stack, &pair_registry, lock_ptr, class, ordered_group, src);
    handleOutcome(outcome, core_id, lock_ptr, class, src);
}

pub fn release(lock_ptr: *const anyopaque) void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    const core_id = arch.smp.coreID();
    if (core_id >= MAX_CORES) return;
    const stack = &held_stacks[@intCast(core_id)];
    _ = releaseOn(stack, lock_ptr);
}

fn handleOutcome(
    outcome: CheckOutcome,
    core_id: u64,
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    src: SrcLoc,
) void {
    switch (outcome.result) {
        .ok => return,
        .panic_recursive => {
            const prior = outcome.prior.?;
            printDecimal("lockdep: recursive acquire core=", core_id);
            arch.boot.printRaw(" lock_ptr=0x");
            printHex(@intFromPtr(lock_ptr));
            arch.boot.printRaw(" class=\"");
            printCStr(class);
            arch.boot.printRaw("\"\n  prior at ");
            arch.boot.printRaw(prior.src.file);
            arch.boot.printRaw(":");
            printDecimal("", prior.src.line);
            arch.boot.printRaw(" in ");
            arch.boot.printRaw(prior.src.fn_name);
            arch.boot.printRaw("\n  this at ");
            arch.boot.printRaw(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw(" in ");
            arch.boot.printRaw(src.fn_name);
            arch.boot.printRaw("\n");
            @panic("lockdep: recursive acquire");
        },
        .panic_same_class => {
            const prior = outcome.prior.?;
            printDecimal("lockdep: same-class overlap core=", core_id);
            arch.boot.printRaw(" class=\"");
            printCStr(class);
            arch.boot.printRaw("\"\n  outer at ");
            arch.boot.printRaw(prior.src.file);
            arch.boot.printRaw(":");
            printDecimal("", prior.src.line);
            arch.boot.printRaw("\n  inner at ");
            arch.boot.printRaw(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw("\n  fix: use lockPair / unlockPair to acquire same-class instances atomically\n");
            @panic("lockdep: same-class overlap");
        },
        .panic_cycle => {
            arch.boot.printRaw("lockdep: AB-BA cycle ");
            printCStr(outcome.cycle_inner);
            arch.boot.printRaw(" -> ");
            printCStr(outcome.cycle_outer);
            arch.boot.printRaw("\n  prior A->B at ");
            arch.boot.printRaw(outcome.cycle_prior_inner_src.file);
            arch.boot.printRaw(":");
            printDecimal("", outcome.cycle_prior_inner_src.line);
            arch.boot.printRaw("\n  this B->A at ");
            arch.boot.printRaw(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw("\n");
            @panic("lockdep: AB-BA cycle");
        },
    }
}

fn printCStr(s: [*:0]const u8) void {
    arch.boot.printRaw(std.mem.span(s));
}

fn printDecimal(prefix: []const u8, n: u64) void {
    arch.boot.printRaw(prefix);
    var buf: [20]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            buf[i] = @as(u8, @intCast(v % 10)) + '0';
            v /= 10;
        }
    }
    arch.boot.printRaw(buf[i..]);
}

fn printHex(n: u64) void {
    var buf: [16]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            const d = @as(u8, @intCast(v & 0xF));
            buf[i] = if (d < 10) d + '0' else d - 10 + 'a';
            v >>= 4;
        }
    }
    arch.boot.printRaw(buf[i..]);
}

// ---------- Tests ----------

const testing = std.testing;

fn makeSrc(comptime file: [:0]const u8, line: u32) SrcLoc {
    return .{
        .file = file,
        .fn_name = "test",
        .line = line,
        .column = 0,
        .module = "debug",
    };
}

test "acquireOn: simple acquire pushes entry" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    const out = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    try testing.expectEqual(CheckResult.ok, out.result);
    try testing.expectEqual(@as(u8, 1), stack.depth);
}

test "acquireOn: recursive acquire same lock_ptr panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    const out = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.panic_recursive, out.result);
}

test "acquireOn: same-class overlap with ordered_group=0 panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    const out = acquireOn(&stack, &reg, &lock_b, class_a, 0, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.panic_same_class, out.result);
}

test "acquireOn: same-class overlap with matching ordered_group succeeds" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    const out1 = acquireOn(&stack, &reg, &lock_a, class_a, 7, makeSrc("a.zig", 10));
    try testing.expectEqual(CheckResult.ok, out1.result);
    const out2 = acquireOn(&stack, &reg, &lock_b, class_a, 7, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.ok, out2.result);
    try testing.expectEqual(@as(u8, 2), stack.depth);
}

test "acquireOn: same-class overlap with mismatched ordered_group panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 7, makeSrc("a.zig", 10));
    const out = acquireOn(&stack, &reg, &lock_b, class_a, 9, makeSrc("a.zig", 20));
    try testing.expectEqual(CheckResult.panic_same_class, out.result);
}

test "acquireOn: AB then release A then BA succeeds (no overlap)" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    const class_b: [*:0]const u8 = "ClassB";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    _ = acquireOn(&stack, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 20));
    try testing.expect(releaseOn(&stack, &lock_b));
    try testing.expect(releaseOn(&stack, &lock_a));

    // Now BA in isolation: the registry has A->B, but no overlap means
    // the cycle check (which only fires against currently-held entries)
    // does not trigger.
    _ = acquireOn(&stack, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 30));
    const out = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 40));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

test "acquireOn: AB-BA cycle detected" {
    var stack_a: HeldStack = .{};
    var stack_b: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    const class_b: [*:0]const u8 = "ClassB";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;

    // Core 0 acquires A then B.
    _ = acquireOn(&stack_a, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    _ = acquireOn(&stack_a, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 20));

    // Core 1 acquires B then A — should detect cycle.
    _ = acquireOn(&stack_b, &reg, &lock_b, class_b, 0, makeSrc("b.zig", 10));
    const out = acquireOn(&stack_b, &reg, &lock_a, class_a, 0, makeSrc("b.zig", 20));
    try testing.expectEqual(CheckResult.panic_cycle, out.result);
}

test "releaseOn: pops matching entry" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    var lock_a: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    try testing.expectEqual(@as(u8, 1), stack.depth);
    try testing.expect(releaseOn(&stack, &lock_a));
    try testing.expectEqual(@as(u8, 0), stack.depth);
}

test "releaseOn: tolerates unknown lock_ptr" {
    var stack: HeldStack = .{};
    var unknown: u32 = 0;
    try testing.expect(!releaseOn(&stack, &unknown));
}

test "releaseOn: pops middle entry preserving order" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    const class_a: [*:0]const u8 = "ClassA";
    const class_b: [*:0]const u8 = "ClassB";
    const class_c: [*:0]const u8 = "ClassC";
    var lock_a: u32 = 0;
    var lock_b: u32 = 0;
    var lock_c: u32 = 0;

    _ = acquireOn(&stack, &reg, &lock_a, class_a, 0, makeSrc("a.zig", 10));
    _ = acquireOn(&stack, &reg, &lock_b, class_b, 0, makeSrc("a.zig", 20));
    _ = acquireOn(&stack, &reg, &lock_c, class_c, 0, makeSrc("a.zig", 30));

    try testing.expect(releaseOn(&stack, &lock_b));
    try testing.expectEqual(@as(u8, 2), stack.depth);
    try testing.expectEqual(@as(*const anyopaque, &lock_a), stack.entries[0].lock_ptr);
    try testing.expectEqual(@as(*const anyopaque, &lock_c), stack.entries[1].lock_ptr);
}

test "acquireOn: stack overflow degrades but still checks panics" {
    var stack: HeldStack = .{};
    var reg: PairRegistry = .{};
    reg.clear();

    // Fill the stack with HELD_STACK_DEPTH distinct same-group locks so
    // that the same-class-overlap check stays quiet.
    var locks: [HELD_STACK_DEPTH + 1]u32 = undefined;
    const class_a: [*:0]const u8 = "ClassA";
    var i: usize = 0;
    while (i < HELD_STACK_DEPTH) {
        locks[i] = 0;
        const out = acquireOn(&stack, &reg, &locks[i], class_a, 1, makeSrc("a.zig", @intCast(i)));
        try testing.expectEqual(CheckResult.ok, out.result);
        i += 1;
    }
    try testing.expectEqual(@as(u8, HELD_STACK_DEPTH), stack.depth);

    // 17th acquire: not pushed (stack full) but recursive check still fires
    // when re-acquiring an existing lock_ptr.
    const out_recursive = acquireOn(&stack, &reg, &locks[0], class_a, 1, makeSrc("a.zig", 99));
    try testing.expectEqual(CheckResult.panic_recursive, out_recursive.result);

    // Fresh 17th: ok-result but does not push (depth stays at HELD_STACK_DEPTH).
    locks[HELD_STACK_DEPTH] = 0;
    const out_overflow = acquireOn(&stack, &reg, &locks[HELD_STACK_DEPTH], class_a, 1, makeSrc("a.zig", 100));
    try testing.expectEqual(CheckResult.ok, out_overflow.result);
    try testing.expectEqual(@as(u8, HELD_STACK_DEPTH), stack.depth);
}

test "PairRegistry: insert + contains + lookup" {
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const src_a = makeSrc("x.zig", 1);
    const src_b = makeSrc("x.zig", 2);

    try testing.expect(!reg.contains(a, b));
    reg.insert(a, b, src_a, src_b);
    try testing.expect(reg.contains(a, b));
    try testing.expect(!reg.contains(b, a));

    const got = reg.lookup(a, b) orelse return error.MissingEntry;
    try testing.expectEqual(@as(u32, 1), got.outer_src.line);
    try testing.expectEqual(@as(u32, 2), got.inner_src.line);
}

test "PairRegistry: idempotent insert" {
    var reg: PairRegistry = .{};
    reg.clear();

    const a: [*:0]const u8 = "A";
    const b: [*:0]const u8 = "B";
    const src1 = makeSrc("x.zig", 1);
    const src2 = makeSrc("x.zig", 2);
    const src3 = makeSrc("x.zig", 3);
    const src4 = makeSrc("x.zig", 4);

    reg.insert(a, b, src1, src2);
    reg.insert(a, b, src3, src4);
    const got = reg.lookup(a, b) orelse return error.MissingEntry;
    // First insert wins.
    try testing.expectEqual(@as(u32, 1), got.outer_src.line);
}
