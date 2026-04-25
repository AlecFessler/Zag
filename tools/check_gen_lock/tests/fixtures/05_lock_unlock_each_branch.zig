// EXPECT: clean
// Lock + explicit unlock on every if/else branch → OK.

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn SlabRef(comptime T: type) type {
    return extern struct {
        ptr: *T,
        gen: u64 = 0,
        pub fn lock(_: @This()) ?*T { return null; }
        pub fn unlock(_: @This()) void {}
    };
}

pub fn sysBranchUnlock(ref: SlabRef(Foo), cond: u64) i64 {
    _ = ref.lock() orelse return -2;
    if (cond != 0) {
        ref.unlock();
        return -1;
    }
    ref.unlock();
    return 0;
}
