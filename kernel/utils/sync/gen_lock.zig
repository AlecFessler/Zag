const std = @import("std");
const zag = @import("zag");

const debug = zag.utils.sync.debug;

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
    class: [*:0]const u8 = "@unclassified",

    /// Plain spin-acquire of the lock bit, regardless of generation.
    /// Used by internal kernel paths that already have a live *T from a
    /// pinned reference chain (no handle, no staleness concern).
    pub fn lock(self: *GenLock) void {
        debug.acquire(self, self.class, 0, @src());
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
        debug.release(self);
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
        debug.acquire(self, self.class, 0, @src());
        const unlocked: u64 = (@as(u64, expected_gen) << 1) | 0;
        const locked: u64 = (@as(u64, expected_gen) << 1) | 1;
        while (true) {
            if (self.word.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
            const cur = self.word.load(.monotonic);
            if ((cur >> 1) != expected_gen) {
                debug.release(self);
                return error.StaleHandle;
            }
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
/// `tools/check_gen_lock/`). Wherever such a pointer would be stored
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

/// Lock-guarded cell for a `?SlabRef(T)`. Native 128-bit atomics would
/// want `cmpxchg16b` on x86_64, which our kernel's CPU baseline does
/// not mandate; a per-cell `SpinLock` gives the same observable
// ---- tests ----

const testing = std.testing;

const TestT = extern struct {
    _gen_lock: GenLock = .{},
    value: u64 = 0,
};

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
