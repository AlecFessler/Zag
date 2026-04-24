const std = @import("std");
const builtin = @import("builtin");
const zag = @import("zag");

const bump = zag.memory.allocators.bump;

const arch = zag.arch.dispatch;

const Range = zag.utils.range.Range;
const SpinLock = zag.utils.sync.SpinLock;

const INVALID_INDEX: u32 = std.math.maxInt(u32);
const DEFAULT_WALK_BOUND: u32 = 256;

pub const AllocError = error{
    SlabFull,
};

pub const AccessError = error{
    StaleHandle,
};

/// Per-object gen+lock word. First field of every slab-backed T. Encodes:
///   word = (gen << 1) | lock_bit
///   gen even  → slot is freed
///   gen odd   → slot is live
///   lock_bit  → 1 while a critical section is in progress
///
/// Replaces the object-level `SpinLock` that slab-backed types used to
/// carry as a separate field: same mutual-exclusion semantics, plus
/// structural UAF detection on every acquire (stale expected_gen → the
/// slot was freed since the handle was issued).
///
/// Callers that have a handle and a snapshotted `expected_gen` use
/// `lockWithGen` to verify + lock in one atomic instruction. Callers
/// holding a *T from a live internal reference chain use the plain
/// `lock()` which acquires whatever gen is current.
pub const GenLock = extern struct {
    word: std.atomic.Value(u64) align(8) = .{ .raw = 0 },

    /// Plain spin-acquire of the lock bit, regardless of generation.
    /// Used by internal kernel paths that already have a live *T from a
    /// pinned reference chain (no handle, no staleness concern).
    pub fn lock(self: *GenLock) void {
        while (true) {
            const cur = self.word.load(.monotonic);
            if (cur & 1 == 0) {
                if (self.word.cmpxchgWeak(cur, cur | 1, .acquire, .monotonic) == null) return;
            }
            std.atomic.spinLoopHint();
        }
    }

    /// Release a lock acquired via `lock` or `lockWithGen`. Clears the
    /// lock bit without touching the generation counter.
    pub fn unlock(self: *GenLock) void {
        const prev = self.word.fetchAnd(~@as(u64, 1), .release);
        std.debug.assert(prev & 1 == 1);
    }

    /// Spin-CAS-acquire the lock bit while atomically verifying the
    /// caller's `expected_gen` snapshot matches the slot's current gen.
    /// Returns `StaleHandle` if the slot has been freed (and possibly
    /// reallocated) since the handle was issued.
    pub fn lockWithGen(self: *GenLock, expected_gen: u63) AccessError!void {
        // Parity invariant: a live-handle gen is always odd. An even
        // expected_gen means the caller is holding a reference to a
        // freed slot — a bug at the issuance site, not a stale handle.
        std.debug.assert(expected_gen % 2 == 1);
        const unlocked: u64 = (@as(u64, expected_gen) << 1) | 0;
        const locked: u64 = (@as(u64, expected_gen) << 1) | 1;
        while (true) {
            if (self.word.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
            const cur = self.word.load(.monotonic);
            if ((cur >> 1) != expected_gen) return error.StaleHandle;
            std.atomic.spinLoopHint();
        }
    }

    /// Read the current generation. Callers issuing a handle snapshot
    /// this alongside the *T; callers on refcount-zero destroy paths
    /// read it to hand back to `SecureSlab.destroy`.
    pub fn currentGen(self: *const GenLock) u63 {
        return @intCast(self.word.load(.monotonic) >> 1);
    }

    /// Replace the word with `(new_gen << 1) | 0` — clears the lock bit
    /// and installs a new gen in one release store. Used by the slab
    /// allocator on alloc (freed→live) and destroy (live→freed).
    pub fn setGenRelease(self: *GenLock, new_gen: u63) void {
        const new_word: u64 = (@as(u64, new_gen) << 1) | 0;
        self.word.store(new_word, .release);
    }
};

/// Fat pointer to a slab-backed object. Pairs the pointer with the
/// generation captured at issuance; every access goes through `lock` /
/// `unlock`, which internally calls `GenLock.lockWithGen(self.gen)`.
///
/// This is the ONLY sanctioned form for kernel storage of a pointer to
/// a slab-backed object. Bare `*T` for slab-backed T is banned at the
/// type-system level (enforced by the static analyzer — see
/// `tools/check_gen_lock.py`). Wherever such a pointer would be stored
/// — struct field, array element, function parameter, local variable —
/// the slot is `SlabRef(T)` instead.
///
/// Semantics:
///  * `init(ptr, gen)` — construct a fat pointer; gen is the snapshot
///    taken when the reference was minted (perm-table insertion,
///    fresh-alloc return, etc.).
///  * `lock()` returns a guarded pointer to T on success, or
///    `StaleHandle` if the slot has been freed since the ref was
///    minted. Caller must pair with `unlock()`.
///  * `unlock()` releases the lock bit. The gen carried by the ref is
///    untouched — the ref remains valid for subsequent locks until the
///    slot is actually freed.
///  * `eql(other)` — identity compare. Fat refs to the same slot with
///    the same gen are the same reference.
pub fn SlabRef(comptime T: type) type {
    // NOTE: `validateT` is intentionally deferred to the method bodies
    // below (via `ptr._gen_lock` field syntax) rather than called at
    // the outer `fn SlabRef` scope. Otherwise embedding `SlabRef(T)` in
    // a struct field of T itself (e.g. `KernelObject.process:
    // SlabRef(Process)` inside `Process.perm_table`) creates a
    // self-referential comptime cycle — Zig's `@hasField` requires the
    // struct to be fully resolved, which cannot happen while T is
    // still being declared. Field-syntax access inside `lock`/`unlock`
    // still produces the same `@hasField("_gen_lock")` guarantee, just
    // at method-call time instead of at type-instantiation time.
    return extern struct {
        const Self = @This();

        ptr: *T,
        gen: u32,
        _pad: u32 = 0,

        pub fn init(ptr: *T, gen: u63) Self {
            std.debug.assert(gen % 2 == 1);
            return .{ .ptr = ptr, .gen = @intCast(gen) };
        }

        /// Verify-and-acquire. On success the caller has exclusive
        /// access to `self.ptr` until `unlock()`. On `StaleHandle` the
        /// slot was freed since this ref was minted — the caller must
        /// NOT touch `self.ptr`.
        pub fn lock(self: Self) AccessError!*T {
            try self.ptr._gen_lock.lockWithGen(@intCast(self.gen));
            return self.ptr;
        }

        pub fn unlock(self: Self) void {
            self.ptr._gen_lock.unlock();
        }

        pub fn eql(self: Self, other: Self) bool {
            return self.ptr == other.ptr and self.gen == other.gen;
        }
    };
}

/// Out-of-band doubly-linked list entry. Sits in its own vaddr region
/// separate from the slot pointers so a single OOB write from a T instance
/// cannot corrupt both the address table and the freelist topology.
pub const LinkPair = extern struct {
    prev: u32,
    next: u32,
};

/// Secure slab allocator.
///
/// Memory model: three comptime-reserved kernel vaddr regions per class,
/// each demand-paged via the kernel page-fault handler. Regions:
///   data  — dense array of T slots (T embeds its own GenLock at offset 0)
///   ptrs  — parallel array of `*T` (one per slot index)
///   links — parallel array of `LinkPair` (prev/next indices into the free list)
///
/// Freelist: circular doubly-linked by u32 index. Two cursors (pop_cursor,
/// push_cursor) each walk by a hardware-random `[-N, N]` modulo free-list
/// size, every alloc *and* free. Intent: break deterministic heap grooming
/// so an attacker cannot pin which slot their next free-then-alloc will
/// reclaim.
///
/// Per-object gen+lock word: T declares `_gen_lock: GenLock` as its first
/// field. Capability handles store the expected gen alongside *T; deref
/// goes through `GenLock.lockWithGen` which CAS-verifies gen + acquires
/// the lock bit in one instruction.
pub fn SecureSlab(
    comptime T: type,
    comptime walk_bound: u32,
) type {
    comptime validateT(T);

    return struct {
        const Self = @This();

        const slot_align: u64 = @alignOf(T);
        const slot_stride: u64 = std.mem.alignForward(u64, @sizeOf(T), slot_align);

        data_bump: bump.BumpAllocator,
        ptrs_bump: bump.BumpAllocator,
        links_bump: bump.BumpAllocator,

        data_base: u64,
        ptrs_base: u64,
        links_base: u64,

        pop_cursor: u32,
        push_cursor: u32,
        count_free: u32,
        count_total: u32,
        max_slots: u32,

        rng_state: u64,

        /// Allocator-internal lock guarding the freelist / cursors /
        /// bump pointers. Orthogonal to per-slot GenLocks.
        lock: SpinLock = .{},

        pub const Ref = SlabRef(T);

        pub fn init(
            data_range: Range,
            ptrs_range: Range,
            links_range: Range,
        ) Self {
            std.debug.assert(data_range.start < data_range.end);
            std.debug.assert(ptrs_range.start < ptrs_range.end);
            std.debug.assert(links_range.start < links_range.end);
            std.debug.assert(!data_range.overlapsWith(ptrs_range));
            std.debug.assert(!data_range.overlapsWith(links_range));
            std.debug.assert(!ptrs_range.overlapsWith(links_range));

            const max_by_data: u64 = (data_range.end - data_range.start) / slot_stride;
            const max_by_ptrs: u64 = (ptrs_range.end - ptrs_range.start) / @sizeOf(*T);
            const max_by_links: u64 = (links_range.end - links_range.start) / @sizeOf(LinkPair);
            const max_index_space: u64 = INVALID_INDEX;
            const max_slots: u32 = @intCast(@min(
                @min(max_by_data, max_by_ptrs),
                @min(max_by_links, max_index_space),
            ));

            // Mix a timestamp into the seed even when RDRAND / RNDR is
            // available, and use it as sole entropy if hardware RNG is not.
            // Prevents a deterministic cursor walk in the narrow window
            // before any hardware RNG has been observed.
            const ts = arch.time.readTimestamp(false);
            const hw = arch.cpu.getRandom() orelse 0x9E3779B97F4A7C15;
            const seed: u64 = hw ^ ts;

            return .{
                .data_bump = bump.BumpAllocator.init(data_range.start, data_range.end),
                .ptrs_bump = bump.BumpAllocator.init(ptrs_range.start, ptrs_range.end),
                .links_bump = bump.BumpAllocator.init(links_range.start, links_range.end),
                .data_base = data_range.start,
                .ptrs_base = ptrs_range.start,
                .links_base = links_range.start,
                .pop_cursor = INVALID_INDEX,
                .push_cursor = INVALID_INDEX,
                .count_free = 0,
                .count_total = 0,
                .max_slots = max_slots,
                .rng_state = seed,
            };
        }

        /// Allocate a fresh slot. Returns a `SlabRef(T)` — a fat
        /// pointer pairing the slot pointer with its just-advanced
        /// generation. The caller must initialize all non-`_gen_lock`
        /// fields of T via `ref.ptr.field = …` before any concurrent
        /// observer can see the ref; this path writes the gen-lock
        /// word (live, unlocked) but nothing else. While no other
        /// observer holds the ref, field access during init is
        /// self-alive and does not need lock/unlock bracketing.
        pub fn create(self: *Self) AllocError!Ref {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.count_free == 0) {
                try self.growOne();
            }

            const draw_pop = self.randStep();
            const draw_push = self.randStep();
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);

            const popped = self.pop_cursor;
            const link = self.linkAt(popped);
            const next_after_pop = link.next;

            self.unlinkLocked(popped);
            self.pop_cursor = if (self.count_free == 0) INVALID_INDEX else next_after_pop;
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);

            const slot_ptr = self.ptrAt(popped);
            const prev_gen = slot_ptr._gen_lock.currentGen();
            std.debug.assert(prev_gen % 2 == 0); // was freed (gen even)
            const new_gen: u63 = prev_gen + 1;
            slot_ptr._gen_lock.setGenRelease(new_gen);

            return Ref.init(slot_ptr, new_gen);
        }

        /// Atomically verify the caller's carried gen, acquire the
        /// lock, bump gen to the next even (freed) value, and re-link
        /// the slot. Returns `StaleHandle` if the gen no longer matches
        /// — a concurrent destroy already ran (or the ref predates a
        /// reallocation and is a bug). A racing double-free is rejected
        /// cleanly rather than panicking.
        ///
        /// Prefer `SlabRef(T).destroy(slab)` at call sites that already
        /// hold a fat pointer; this underlying form exists for sites
        /// that only know `(*T, gen)` and haven't migrated yet.
        pub fn destroy(
            self: *Self,
            ptr: *T,
            expected_gen: u63,
        ) AccessError!void {
            // Parity invariant: expected_gen must be odd (live slot).
            // lockWithGen asserts this too; stating it here makes the
            // destroy-side contract explicit for readers.
            std.debug.assert(expected_gen % 2 == 1);
            try ptr._gen_lock.lockWithGen(expected_gen);

            self.lock.lock();
            defer self.lock.unlock();

            // Gen-lock currently held. Bump to (expected_gen+1)<<1 | 0 and
            // release in one store: the new gen is even (freed) and the
            // lock bit is clear.
            ptr._gen_lock.setGenRelease(expected_gen + 1);

            const idx = self.indexOf(ptr);

            const draw_push = self.randStep();
            const draw_pop = self.randStep();

            self.linkInLocked(idx);
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);
        }

        // ---- internals ----

        fn growOne(self: *Self) AllocError!void {
            if (self.count_total >= self.max_slots) return error.SlabFull;

            const slot_base = bumpBytes(&self.data_bump, slot_stride, slot_align) orelse
                return error.SlabFull;
            // Freshly demand-paged memory is already zero (fault handler
            // zeroes new pages); be explicit under second-touch reuse.
            @memset(slot_base[0..slot_stride], 0);
            const slot_ptr: *T = @ptrCast(@alignCast(slot_base));

            const ptr_cell = bumpOne(&self.ptrs_bump, *T) orelse return error.SlabFull;
            ptr_cell.* = slot_ptr;

            const link_cell = bumpOne(&self.links_bump, LinkPair) orelse return error.SlabFull;
            link_cell.* = .{ .prev = INVALID_INDEX, .next = INVALID_INDEX };

            const new_idx: u32 = self.count_total;
            self.count_total += 1;

            self.linkInLocked(new_idx);
        }

        fn randStep(self: *Self) i32 {
            const r = self.nextRandom();
            const span: u64 = 2 * @as(u64, walk_bound) + 1;
            const unsigned_step: u32 = @intCast(r % span);
            return @as(i32, @intCast(unsigned_step)) - @as(i32, walk_bound);
        }

        fn nextRandom(self: *Self) u64 {
            if (arch.cpu.getRandom()) |r| {
                self.rng_state ^= r;
                return r;
            }
            var s = self.rng_state;
            if (s == 0) s = 0x9E3779B97F4A7C15;
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            self.rng_state = s;
            return s *% 0x2545F4914F6CDD1D;
        }

        fn walkCursorLocked(self: *Self, start: u32, raw_steps: i32) u32 {
            if (self.count_free == 0) return INVALID_INDEX;

            const size_i: i32 = @intCast(self.count_free);
            const effective: u32 = @intCast(@mod(raw_steps, size_i));

            var cursor = if (start == INVALID_INDEX) self.anyFreeSlotLocked() else start;
            var i: u32 = 0;
            while (i < effective) {
                cursor = self.linkAt(cursor).next;
                i += 1;
            }
            return cursor;
        }

        fn anyFreeSlotLocked(self: *Self) u32 {
            if (self.push_cursor != INVALID_INDEX) return self.push_cursor;
            if (self.pop_cursor != INVALID_INDEX) return self.pop_cursor;
            @panic("anyFreeSlotLocked called on empty list");
        }

        fn linkInLocked(self: *Self, idx: u32) void {
            // Parity invariant: slots on the freelist have even gen.
            // linkIn is called from growOne (slot fresh at gen=0) and
            // from destroy (slot just bumped to the next even gen).
            std.debug.assert(self.ptrAt(idx)._gen_lock.currentGen() % 2 == 0);
            const link = self.linkAt(idx);
            if (self.count_free == 0) {
                link.* = .{ .prev = idx, .next = idx };
                self.pop_cursor = idx;
                self.push_cursor = idx;
            } else {
                const anchor = if (self.push_cursor == INVALID_INDEX)
                    self.anyFreeSlotLocked()
                else
                    self.push_cursor;
                const anchor_link = self.linkAt(anchor);
                const after = anchor_link.next;
                link.* = .{ .prev = anchor, .next = after };
                anchor_link.next = idx;
                self.linkAt(after).prev = idx;
            }
            self.count_free += 1;
        }

        fn unlinkLocked(self: *Self, idx: u32) void {
            std.debug.assert(self.count_free > 0);
            // Parity invariant: slots on the freelist have even gen.
            // unlink is called from create() before the gen is bumped
            // to odd, so the slot must still be even here.
            std.debug.assert(self.ptrAt(idx)._gen_lock.currentGen() % 2 == 0);
            const link = self.linkAt(idx);
            const saved_prev = link.prev;
            if (self.count_free == 1) {
                std.debug.assert(link.prev == idx and link.next == idx);
            } else {
                self.linkAt(link.prev).next = link.next;
                self.linkAt(link.next).prev = link.prev;
            }
            link.* = .{ .prev = INVALID_INDEX, .next = INVALID_INDEX };
            self.count_free -= 1;

            if (self.push_cursor == idx) {
                self.push_cursor = if (self.count_free == 0) INVALID_INDEX else saved_prev;
            }
        }

        fn linkAt(self: *Self, idx: u32) *LinkPair {
            std.debug.assert(idx < self.count_total);
            const addr = self.links_base + @as(u64, idx) * @sizeOf(LinkPair);
            return @ptrFromInt(addr);
        }

        fn ptrAt(self: *Self, idx: u32) *T {
            std.debug.assert(idx < self.count_total);
            const addr = self.ptrs_base + @as(u64, idx) * @sizeOf(*T);
            const cell: *const *T = @ptrFromInt(addr);
            return cell.*;
        }

        fn indexOf(self: *Self, ptr: *T) u32 {
            // Slots are laid out at `data_base + i * slot_stride` by
            // growOne; the pointer's offset from data_base divides by
            // stride to give its index. O(1), no ptrs-array walk.
            const addr = @intFromPtr(ptr);
            std.debug.assert(addr >= self.data_base);
            const offset = addr - self.data_base;
            std.debug.assert(offset % slot_stride == 0);
            const idx: u32 = @intCast(offset / slot_stride);
            std.debug.assert(idx < self.count_total);
            // Defensive: ptrs-array must still agree. This is a
            // debug-only cross-check that catches corruption of the
            // ptrs region independent of the stride math.
            std.debug.assert(self.ptrAt(idx) == ptr);
            return idx;
        }
    };
}

// ---- shared helpers ----

fn validateT(comptime T: type) void {
    const info = @typeInfo(T);
    if (info != .@"struct") {
        @compileError("SecureSlab requires a struct T; got " ++ @typeName(T));
    }
    if (!@hasField(T, "_gen_lock")) {
        @compileError(@typeName(T) ++ " must declare a `_gen_lock: GenLock` field");
    }
    // Offset-0 is the design ideal ("the first word of every slab-backed
    // object is the lock, stable even when inserted into the freelist").
    // Enforcing it at comptime would require every slab T — including
    // Thread/Process and their many sub-structs — to be `extern struct`,
    // a cascading refactor that touches ?u64 / ?Stack / tagged-union
    // fields. For now we validate only that `_gen_lock` exists; access
    // goes through `ptr._gen_lock` (field syntax), so Zig's struct
    // layout still resolves the gen-lock correctly at any offset. The
    // UAF-detection invariant holds regardless — the word is part of T's
    // own storage, so it persists across the free→alloc cycle on the
    // freelist, and `lockWithGen` CAS-catches stale expected_gen. The
    // offset-0 convention should be restored as each slab T is converted
    // to extern struct; until then, comptime enforcement would gate the
    // build on the full refactor.
}

fn bumpOne(ba: *bump.BumpAllocator, comptime R: type) ?*R {
    const aligned = std.mem.alignForward(u64, ba.free_addr, @alignOf(R));
    const next_free = aligned + @sizeOf(R);
    if (next_free > ba.end_addr) return null;
    ba.free_addr = next_free;
    return @ptrFromInt(aligned);
}

fn bumpBytes(ba: *bump.BumpAllocator, size: u64, alignment: u64) ?[*]u8 {
    const aligned = std.mem.alignForward(u64, ba.free_addr, alignment);
    const next_free = aligned + size;
    if (next_free > ba.end_addr) return null;
    ba.free_addr = next_free;
    return @ptrFromInt(aligned);
}

// ---- tests ----

const testing = std.testing;

const TestT = extern struct {
    _gen_lock: GenLock = .{},
    value: u64 = 0,
    pad: u64 = 0,
};

test "validateT accepts well-formed extern struct" {
    _ = SecureSlab(TestT, DEFAULT_WALK_BOUND);
}

test "randStep stays in [-N, N]" {
    const S = SecureSlab(TestT, 16);
    var dummy: S = undefined;
    dummy.rng_state = 0xDEADBEEFCAFEBABE;
    var i: usize = 0;
    while (i < 1000) {
        const step = dummy.randStep();
        try testing.expect(step >= -16 and step <= 16);
        i += 1;
    }
}

test "genlock lock/unlock sequencing" {
    var gl: GenLock = .{};
    gl.setGenRelease(5); // pretend we just allocated gen=5
    gl.lock();
    try testing.expect(gl.word.load(.monotonic) & 1 == 1);
    gl.unlock();
    try testing.expect(gl.word.load(.monotonic) & 1 == 0);
    try testing.expectEqual(@as(u63, 5), gl.currentGen());
}

test "genlock lockWithGen rejects stale" {
    var gl: GenLock = .{};
    gl.setGenRelease(5);
    // Stale gen must still be odd — an even expected_gen would trip
    // the parity assert, not return StaleHandle (that's a caller bug,
    // not an ordinary stale-handle miss).
    try testing.expectError(error.StaleHandle, gl.lockWithGen(3));
}

test "SlabRef lock / unlock round-trip on live slot" {
    var t: TestT = .{};
    t._gen_lock.setGenRelease(3); // pretend live at gen=3
    const ref = SlabRef(TestT).init(&t, 3);
    const got = try ref.lock();
    try testing.expectEqual(&t, got);
    try testing.expect(t._gen_lock.word.load(.monotonic) & 1 == 1);
    ref.unlock();
    try testing.expect(t._gen_lock.word.load(.monotonic) & 1 == 0);
}

test "SlabRef.lock rejects a stale ref" {
    var t: TestT = .{};
    t._gen_lock.setGenRelease(5); // slot has advanced to 5
    const stale = SlabRef(TestT).init(&t, 3); // caller captured gen=3
    try testing.expectError(error.StaleHandle, stale.lock());
}
