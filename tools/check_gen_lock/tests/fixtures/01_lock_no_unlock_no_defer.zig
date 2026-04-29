// EXPECT: errors=1
// Lock + early return without unlock or defer → leak.

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

pub fn sysLeak(ref: SlabRef(Foo), cond: u64) i64 {
    _ = ref.lock() orelse return -2;
    if (cond != 0) return -1; // <- LEAK: no unlock, no defer
    _ = ref;
    ref.unlock();
    return 0;
}
