const std = @import("std");
const builtin = @import("builtin");
const zag = @import("zag");

const bump = zag.memory.allocators.bump;

const arch = zag.arch.dispatch;

const Range = zag.utils.range.Range;
const SpinLock = zag.utils.sync.SpinLock;

const INVALID_INDEX: u32 = std.math.maxInt(u32);
const DEFAULT_WALK_BOUND: u32 = 256;

/// Out-of-band doubly-linked list entry. Sits in its own vaddr region
/// separate from the slot pointers so a single OOB write from a T instance
/// cannot corrupt both the address table and the freelist topology.
pub const LinkPair = extern struct {
    prev: u32,
    next: u32,
};

pub const AllocError = error{
    SlabFull,
};

pub const AccessError = error{
    StaleHandle,
};

/// Secure slab allocator.
///
/// Memory model: three comptime-reserved kernel vaddr regions per class,
/// each demand-paged via the kernel page-fault handler. Regions:
///   data  — dense array of T slots
///   ptrs  — parallel array of `*T` (one per slot index)
///   links — parallel array of `LinkPair` (prev/next indices into the free list)
///
/// Freelist: circular doubly-linked by u32 index. Two cursors (pop_cursor,
/// push_cursor) each walk by a hardware-random `[-N, N]` modulo free-list
/// size, every alloc *and* free. Intent: break deterministic heap grooming
/// so an attacker cannot pin which slot their next free-then-alloc will
/// reclaim.
///
/// Per-object gen+lock word: every slab-allocated T must be `extern struct`
/// with `_gen_lock: u64` as its first field. Bit 0 of that word is the
/// per-object lock bit; bits 1..63 hold the monotonically-increasing
/// generation counter. Encoding:
///   word = (gen << 1) | lock_bit
///   gen even  → slot is freed
///   gen odd   → slot is live
///   lock_bit  → 1 while a safeAccess / destroy is in progress
///
/// Capability handles store the expected gen alongside `*T`; on deref,
/// `safeAccess` performs a CAS that simultaneously verifies the gen and
/// acquires the object lock, making stale-handle use a clean error rather
/// than silent corruption.
pub fn SecureSlab(
    comptime T: type,
    comptime walk_bound: u32,
) type {
    comptime validateT(T);

    return struct {
        const Self = @This();

        data_bump: bump.BumpAllocator,
        ptrs_bump: bump.BumpAllocator,
        links_bump: bump.BumpAllocator,

        ptrs_base: u64,
        links_base: u64,

        pop_cursor: u32,
        push_cursor: u32,
        count_free: u32,
        count_total: u32,
        max_slots: u32,

        rng_state: u64,

        lock: SpinLock = .{},

        pub const AllocResult = struct {
            ptr: *T,
            gen: u63,
        };

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

            const max_by_data: u64 = (data_range.end - data_range.start) / @sizeOf(T);
            const max_by_ptrs: u64 = (ptrs_range.end - ptrs_range.start) / @sizeOf(*T);
            const max_by_links: u64 = (links_range.end - links_range.start) / @sizeOf(LinkPair);
            const max_index_space: u64 = INVALID_INDEX;
            const max_slots: u32 = @intCast(@min(
                @min(max_by_data, max_by_ptrs),
                @min(max_by_links, max_index_space),
            ));

            const seed: u64 = arch.cpu.getRandom() orelse 0x9E3779B97F4A7C15;

            return .{
                .data_bump = bump.BumpAllocator.init(data_range.start, data_range.end),
                .ptrs_bump = bump.BumpAllocator.init(ptrs_range.start, ptrs_range.end),
                .links_bump = bump.BumpAllocator.init(links_range.start, links_range.end),
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

        /// Allocate a fresh slot. Returns the object pointer and its new
        /// generation; the caller must stash `gen` in whatever capability
        /// handle it issues, then pass it back to `safeAccess` / `destroy`.
        ///
        /// Caller must not touch any `T` fields before receiving both values
        /// — the gen-lock word is written by this path.
        pub fn create(self: *Self) AllocError!AllocResult {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.count_free == 0) {
                try self.growOne();
            }

            // Pop cursor walks, then the slot at the cursor is extracted.
            const draw_pop = self.randStep();
            const draw_push = self.randStep();
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);

            const popped = self.pop_cursor;
            const link = self.linkAt(popped);
            const next_after_pop = link.next;

            self.unlinkLocked(popped);

            // Keep pop cursor valid after the unlink.
            self.pop_cursor = if (self.count_free == 0) INVALID_INDEX else next_after_pop;

            // Push cursor walk happens on the (now-shrunken) free list.
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);

            const slot_ptr = self.ptrAt(popped);
            const word = genLockWord(slot_ptr);
            const prev_word = word.load(.monotonic);
            std.debug.assert(prev_word & 1 == 0); // was not locked
            std.debug.assert((prev_word >> 1) % 2 == 0); // was freed (gen even)
            const new_gen: u63 = @intCast((prev_word >> 1) + 1);
            const new_word: u64 = (@as(u64, new_gen) << 1) | 0; // live, unlocked
            word.store(new_word, .release);

            return .{ .ptr = slot_ptr, .gen = new_gen };
        }

        /// Atomically verify the caller's expected gen matches, acquire the
        /// object lock, bump the gen to the next even (freed) value, and
        /// link the slot back into the free list. Returns `StaleHandle` if
        /// the handle's gen no longer matches — that means the object was
        /// already freed (possibly reallocated) by a concurrent path.
        pub fn destroy(
            self: *Self,
            ptr: *T,
            expected_gen: u63,
        ) AccessError!void {
            const word = genLockWord(ptr);
            const unlocked: u64 = (@as(u64, expected_gen) << 1) | 0;
            const locked: u64 = (@as(u64, expected_gen) << 1) | 1;

            while (true) {
                if (word.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) break;
                const cur = word.load(.monotonic);
                if ((cur >> 1) != expected_gen) return error.StaleHandle;
                std.atomic.spinLoopHint();
            }

            self.lock.lock();
            defer self.lock.unlock();

            // Gen-lock currently held. Bump to (expected_gen+1)<<1 | 0 and
            // release in one store: the new gen is even (freed) and the
            // lock bit is clear.
            const new_word: u64 = (@as(u64, expected_gen + 1) << 1) | 0;
            word.store(new_word, .release);

            const idx = self.indexOf(ptr);

            const draw_push = self.randStep();
            const draw_pop = self.randStep();

            self.linkInLocked(idx);
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);
        }

        /// Destroy a slot whose caller has independently established
        /// exclusive ownership (typically via a refcount transition to
        /// zero). Skips the gen-lock CAS that `destroy` requires — the
        /// caller is asserting no other CPU can possibly be in a
        /// `safeAccess` body on this slot. Bumps gen to the next even
        /// value and links back into the free list.
        ///
        /// If you have a capability handle with an expected_gen, use
        /// `destroy` instead. Misuse turns UAF-protection into a silent
        /// corruption window.
        pub fn destroyUnchecked(self: *Self, ptr: *T) void {
            const word = genLockWord(ptr);
            const cur = word.load(.monotonic);
            const cur_gen = cur >> 1;
            std.debug.assert(cur_gen % 2 == 1); // was live (gen odd)
            std.debug.assert(cur & 1 == 0); // was unlocked

            self.lock.lock();
            defer self.lock.unlock();

            const new_word: u64 = (@as(u64, cur_gen + 1) << 1) | 0;
            word.store(new_word, .release);

            const idx = self.indexOf(ptr);

            const draw_push = self.randStep();
            const draw_pop = self.randStep();

            self.linkInLocked(idx);
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);
        }

        /// The only door to a real `*T`. Spin-CAS-acquires the gen-lock while
        /// verifying the handle's expected gen, runs `body(ctx, ptr)`, and
        /// releases the lock. Returns `StaleHandle` if the gen no longer
        /// matches; propagates any error returned by `body`.
        pub fn safeAccess(
            self: *Self,
            ptr: *T,
            expected_gen: u63,
            ctx: anytype,
            comptime body: anytype,
        ) SafeAccessReturn(@TypeOf(body)) {
            _ = self;
            const word = genLockWord(ptr);
            const unlocked: u64 = (@as(u64, expected_gen) << 1) | 0;
            const locked: u64 = (@as(u64, expected_gen) << 1) | 1;

            while (true) {
                if (word.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) break;
                const cur = word.load(.monotonic);
                if ((cur >> 1) != expected_gen) return error.StaleHandle;
                std.atomic.spinLoopHint();
            }
            defer word.store(unlocked, .release);

            return body(ctx, ptr);
        }

        // ---- internals ----

        fn growOne(self: *Self) AllocError!void {
            if (self.count_total >= self.max_slots) return error.SlabFull;

            const slot_ptr = bumpOne(&self.data_bump, T) orelse return error.SlabFull;
            // Freshly demand-paged memory is already zero (fault handler
            // zeroes new pages), but be explicit for correctness under
            // second-touch reuse.
            @memset(std.mem.asBytes(slot_ptr), 0);

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
            // Used only to re-seed a cursor after it was invalidated. The
            // push_cursor (if valid) is the canonical seed; otherwise fall
            // back to the pop_cursor; otherwise the list is empty.
            if (self.push_cursor != INVALID_INDEX) return self.push_cursor;
            if (self.pop_cursor != INVALID_INDEX) return self.pop_cursor;
            @panic("anyFreeSlotLocked called on empty list");
        }

        fn linkInLocked(self: *Self, idx: u32) void {
            const link = self.linkAt(idx);
            if (self.count_free == 0) {
                link.* = .{ .prev = idx, .next = idx };
                self.pop_cursor = idx;
                self.push_cursor = idx;
            } else {
                // Insert after push_cursor (or after an arbitrary node if
                // push_cursor was invalidated).
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
            // Walk the ptrs array to find the matching index. This is O(n)
            // but only on the destroy path; the alternative — reverse-mapping
            // via `(ptr - data_base) / sizeof(T)` — skips the ptrs-table
            // indirection that the separation-of-metadata property relies on.
            var i: u32 = 0;
            while (i < self.count_total) {
                if (self.ptrAt(i) == ptr) return i;
                i += 1;
            }
            @panic("indexOf: pointer not in this slab");
        }
    };
}

// ---- shared helpers ----

fn validateT(comptime T: type) void {
    const info = @typeInfo(T);
    if (info != .@"struct") {
        @compileError("SecureSlab requires a struct T; got " ++ @typeName(T));
    }
    if (info.@"struct".layout != .@"extern") {
        @compileError("SecureSlab requires T to be `extern struct` for stable layout; got " ++ @typeName(T));
    }

    const fields = info.@"struct".fields;
    if (fields.len == 0) {
        @compileError(@typeName(T) ++ " must have `_gen_lock: u64` as its first field");
    }
    if (!std.mem.eql(u8, fields[0].name, "_gen_lock")) {
        @compileError(@typeName(T) ++ ": first field must be `_gen_lock`, got `" ++ fields[0].name ++ "`");
    }
    if (fields[0].type != u64) {
        @compileError(@typeName(T) ++ ": `_gen_lock` must be u64");
    }

    // Any other top-level SpinLock field means the caller is double-locking.
    // Fine-grained sub-locks on *sub*-structs are fine; this only fires on
    // SpinLock sitting directly on T.
    for (fields[1..]) |f| {
        if (f.type == SpinLock) {
            @compileError(@typeName(T) ++ " has top-level SpinLock `" ++ f.name ++
                "`; remove it (the `_gen_lock` word replaces the coarse object lock)");
        }
    }
}

fn genLockWord(ptr: anytype) *std.atomic.Value(u64) {
    return @ptrCast(@alignCast(ptr));
}

fn bumpOne(ba: *bump.BumpAllocator, comptime R: type) ?*R {
    const aligned = std.mem.alignForward(u64, ba.free_addr, @alignOf(R));
    const next_free = aligned + @sizeOf(R);
    if (next_free > ba.end_addr) return null;
    ba.free_addr = next_free;
    return @ptrFromInt(aligned);
}

fn SafeAccessReturn(comptime BodyType: type) type {
    const body_info = @typeInfo(BodyType).@"fn";
    const body_ret = body_info.return_type.?;
    const ret_info = @typeInfo(body_ret);
    return switch (ret_info) {
        .error_union => |eu| (eu.error_set || AccessError)!eu.payload,
        else => AccessError!body_ret,
    };
}

// ---- tests ----

const testing = std.testing;

const TestT = extern struct {
    _gen_lock: u64,
    value: u64,
    pad: u64,
};

test "validateT accepts well-formed extern struct" {
    // Just instantiating the type triggers the comptime check.
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
